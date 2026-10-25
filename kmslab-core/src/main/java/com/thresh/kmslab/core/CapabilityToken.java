package com.thresh.kmslab.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * A macaroon-style capability token: an identifier, an ordered caveat list and a chained tag.
 *
 * <p>The chaining is what makes delegation possible without the root key. The holder can append a
 * caveat and compute the next tag from the current one, because
 * {@code tag(n) = HMAC(tag(n-1), caveat(n))}. Removing or reordering a caveat requires recomputing
 * every later tag, which is impossible without the root key — so a token can only ever be
 * narrowed, never widened.
 *
 * <p>Caveats are {@code name=value} lines. Recognised names, enforced by the service:
 * {@code subject}, {@code tenant}, {@code expires}, {@code action}, {@code key},
 * {@code column}, {@code purpose}. Unknown caveats are preserved and ignored, which keeps
 * attenuation forward compatible.
 *
 * @author threshbyte
 */
public final class CapabilityToken {

    private final String identifier;
    private final List<String> caveats;
    private final byte[] tag;

    CapabilityToken(String identifier, List<String> caveats, byte[] tag) {
        this.identifier = identifier;
        this.caveats = List.copyOf(caveats);
        this.tag = tag.clone();
    }

    public String identifier() {
        return identifier;
    }

    public List<String> caveats() {
        return caveats;
    }

    byte[] tag() {
        return tag.clone();
    }

    /**
     * Narrows this token by appending one caveat.
     *
     * <p>Callable by the token holder: no root key is needed, which is the point. The result is
     * safe to hand to a downstream service with less authority than this one.
     */
    public CapabilityToken attenuate(String caveat) {
        if (caveat == null || caveat.isBlank() || caveat.contains("\n")) {
            throw new TokenException(TokenException.Reason.MALFORMED, "invalid caveat");
        }
        List<String> next = new ArrayList<>(caveats);
        next.add(caveat);
        byte[] nextTag = TokenAuthority.fold(tag, caveat);
        return new CapabilityToken(identifier, next, nextTag);
    }

    /** Encodes as {@code base64url(payload) + "." + base64url(tag)}. */
    public String encode() {
        String payload = identifier + "\n" + String.join("\n", caveats);
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return enc.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + "." + enc.encodeToString(tag);
    }

    static CapabilityToken decode(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new TokenException(TokenException.Reason.MALFORMED, "token is empty");
        }
        int dot = encoded.indexOf('.');
        if (dot <= 0 || dot == encoded.length() - 1 || encoded.indexOf('.', dot + 1) >= 0) {
            throw new TokenException(TokenException.Reason.MALFORMED, "token must have 2 segments");
        }
        Base64.Decoder dec = Base64.getUrlDecoder();
        String payload;
        byte[] tag;
        try {
            payload = new String(dec.decode(encoded.substring(0, dot)), StandardCharsets.UTF_8);
            tag = dec.decode(encoded.substring(dot + 1));
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenException.Reason.MALFORMED, "token is not base64url");
        }
        String[] lines = payload.split("\n", -1);
        if (lines.length == 0 || lines[0].isBlank()) {
            throw new TokenException(TokenException.Reason.MALFORMED, "token has no identifier");
        }
        List<String> caveats = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (!lines[i].isBlank()) {
                caveats.add(lines[i]);
            }
        }
        return new CapabilityToken(lines[0], caveats, tag);
    }
}
