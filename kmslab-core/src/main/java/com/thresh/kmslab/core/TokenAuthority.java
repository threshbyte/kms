package com.thresh.kmslab.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mints and verifies capability tokens.
 *
 * <p><b>There is deliberately no HTTP endpoint that issues tokens.</b> Issuance requires the root
 * key, so it belongs to a trusted operator process; exposing it over the same API that consumes
 * tokens would let any authenticated caller mint authority for itself. Wiring workload identity
 * (mTLS/SPIFFE, OIDC) into an issuance service is the next step, not a shortcut to take here.
 *
 * @author threshbyte
 */
public final class TokenAuthority {

    private static final int ROOT_KEY_LEN = 32;
    private static final String HMAC = "HmacSHA256";

    private final byte[] rootKey;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public TokenAuthority(byte[] rootKey, Clock clock) {
        if (rootKey == null || rootKey.length < ROOT_KEY_LEN) {
            throw new IllegalArgumentException("root key must be at least 32 bytes");
        }
        this.rootKey = rootKey.clone();
        this.clock = clock;
    }

    /** Generates a random root key. Development only: production loads it from the KMS/HSM. */
    public static TokenAuthority withRandomKey(Clock clock) {
        byte[] key = new byte[ROOT_KEY_LEN];
        new SecureRandom().nextBytes(key);
        return new TokenAuthority(key, clock);
    }

    /** Issues a token. {@code ttl} is capped at 5 minutes by design. */
    public CapabilityToken issue(String subject, String tenant, Duration ttl, List<String> extraCaveats) {
        if (ttl.isNegative() || ttl.isZero()) {
            throw new TokenException(TokenException.Reason.MALFORMED, "ttl must be positive");
        }
        if (ttl.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new TokenException(TokenException.Reason.MALFORMED,
                    "ttl above 5 minutes defeats revocation; shorten it");
        }
        byte[] idBytes = new byte[16];
        random.nextBytes(idBytes);
        String identifier = HexFormat.of().formatHex(idBytes);

        List<String> caveats = new ArrayList<>();
        caveats.add("subject=" + subject);
        caveats.add("tenant=" + tenant);
        caveats.add("expires=" + clock.instant().plus(ttl).getEpochSecond());
        caveats.addAll(extraCaveats == null ? List.of() : extraCaveats);

        byte[] tag = hmac(rootKey, identifier.getBytes(StandardCharsets.UTF_8));
        for (String caveat : caveats) {
            tag = fold(tag, caveat);
        }
        return new CapabilityToken(identifier, caveats, tag);
    }

    /**
     * Verifies signature and expiry.
     *
     * @return the verified identity plus every caveat, grouped by name
     */
    public VerifiedIdentity verify(String encoded) {
        CapabilityToken token = CapabilityToken.decode(encoded);

        byte[] expected = hmac(rootKey, token.identifier().getBytes(StandardCharsets.UTF_8));
        for (String caveat : token.caveats()) {
            expected = fold(expected, caveat);
        }
        if (!MessageDigest.isEqual(expected, token.tag())) {
            throw new TokenException(TokenException.Reason.BAD_SIGNATURE,
                    "token signature mismatch");
        }

        Map<String, List<String>> byName = new LinkedHashMap<>();
        for (String caveat : token.caveats()) {
            int eq = caveat.indexOf('=');
            String name = eq < 0 ? caveat : caveat.substring(0, eq);
            String value = eq < 0 ? "" : caveat.substring(eq + 1);
            byName.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }

        String subject = single(byName, "subject");
        String tenant = single(byName, "tenant");
        String expires = single(byName, "expires");
        if (subject == null || tenant == null || expires == null) {
            throw new TokenException(TokenException.Reason.MISSING_CLAIM,
                    "token must carry subject, tenant and expires");
        }
        long expiry;
        try {
            expiry = Long.parseLong(expires);
        } catch (NumberFormatException e) {
            throw new TokenException(TokenException.Reason.MALFORMED, "expires is not a number");
        }
        if (Instant.ofEpochSecond(expiry).isBefore(clock.instant())) {
            throw new TokenException(TokenException.Reason.EXPIRED, "token expired");
        }
        return new VerifiedIdentity(subject, tenant, Instant.ofEpochSecond(expiry), byName);
    }

    /** One chained tag step. Package visible so {@link CapabilityToken} can attenuate. */
    static byte[] fold(byte[] previousTag, String caveat) {
        return hmac(previousTag, caveat.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hmac(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static String single(Map<String, List<String>> byName, String name) {
        List<String> values = byName.get(name);
        return values == null || values.size() != 1 ? null : values.get(0);
    }

    /**
     * What a verified token proves about the caller.
     *
     * @param caveats every caveat grouped by name; empty lists never appear
     */
    public record VerifiedIdentity(String subject, String tenant, Instant expires,
                                   Map<String, List<String>> caveats) {

        public VerifiedIdentity {
            caveats = Map.copyOf(caveats);
        }

        /** All values for one caveat name, empty when absent. */
        public List<String> caveat(String name) {
            return caveats.getOrDefault(name, List.of());
        }

        public boolean hasCaveat(String name) {
            return caveats.containsKey(name);
        }
    }
}
