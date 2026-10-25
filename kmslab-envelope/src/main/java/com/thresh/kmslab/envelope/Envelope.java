package com.thresh.kmslab.envelope;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * A single kms1 envelope. It <b>retains the raw header and payload bytes</b>, so the AEAD
 * additional data {@code header || canonical(ctx)} is always byte-exact: there is no chance of
 * drift from re-serializing fields.
 *
 * <p>Format: docs/envelope-v1.md §2/§3.
 *
 * @author threshbyte
 */
public final class Envelope {

    static final String PREFIX = "kms1.";
    private static final Base64.Encoder B64E = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final byte[] header;   // 95 bytes
    private final byte[] payload;  // 12 + L + 16 bytes

    private final byte version;
    private final byte alg;
    private final UUID keyId;
    private final long keyVer;
    private final byte wrap;
    private final byte[] dekWrap;
    private final byte[] ctxHash;
    private final byte[] nonce;
    private final byte[] ciphertext;
    private final byte[] tag;

    private Envelope(byte[] header, byte[] payload) {
        this.header = header;
        this.payload = payload;

        ByteBuffer h = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN);
        this.version = h.get();
        this.alg = h.get();
        byte[] idBytes = new byte[16];
        h.get(idBytes);
        this.keyId = Crypto.bytesToUuid(idBytes, 0);
        this.keyVer = Integer.toUnsignedLong(h.getInt());
        this.wrap = h.get();
        this.dekWrap = new byte[Algorithms.DEK_WRAP_LEN];
        h.get(this.dekWrap);
        this.ctxHash = new byte[32];
        h.get(this.ctxHash);

        ByteBuffer p = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        this.nonce = new byte[Algorithms.NONCE_LEN];
        p.get(this.nonce);
        this.tag = new byte[Algorithms.TAG_LEN];
        System.arraycopy(payload, payload.length - Algorithms.TAG_LEN, this.tag, 0, Algorithms.TAG_LEN);
        this.ciphertext = new byte[payload.length - Algorithms.NONCE_LEN - Algorithms.TAG_LEN];
        p.get(this.ciphertext);

        if (!Algorithms.isSupportedVersion(version)) {
            throw new EnvelopeException(EnvelopeErrorCode.UNSUPPORTED,
                    "unsupported envelope version: 0x" + Integer.toHexString(version & 0xff));
        }
        if (!Algorithms.isSupportedAlg(alg)) {
            throw new EnvelopeException(EnvelopeErrorCode.UNSUPPORTED,
                    "unsupported AEAD alg: 0x" + Integer.toHexString(alg & 0xff));
        }
        if (!Algorithms.isSupportedWrap(wrap)) {
            throw new EnvelopeException(EnvelopeErrorCode.UNSUPPORTED,
                    "unsupported DEK wrap: 0x" + Integer.toHexString(wrap & 0xff));
        }
    }

    /** Builds from raw header and payload bytes (internal/test use). Applies structural checks. */
    static Envelope of(byte[] header, byte[] payload) {
        if (header == null || header.length != Algorithms.HEADER_LEN) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT,
                    "header must be exactly " + Algorithms.HEADER_LEN + " bytes");
        }
        if (payload == null || payload.length < Algorithms.PAYLOAD_MIN_LEN) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT,
                    "payload must be at least " + Algorithms.PAYLOAD_MIN_LEN + " bytes");
        }
        return new Envelope(header.clone(), payload.clone());
    }

    /**
     * Parses an envelope string. Structural violations yield {@code FORMAT}; unknown
     * version/algorithm yields {@code UNSUPPORTED}. No repair-and-retry is attempted.
     */
    public static Envelope decode(String text) {
        if (text == null) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "envelope is null");
        }
        if (!text.startsWith(PREFIX)) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "missing 'kms1.' prefix");
        }
        String rest = text.substring(PREFIX.length());
        int dot = rest.indexOf('.');
        if (dot < 0) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "expected 3 segments, got 2");
        }
        if (rest.indexOf('.', dot + 1) >= 0) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "expected 3 segments, got more");
        }
        String hPart = rest.substring(0, dot);
        String pPart = rest.substring(dot + 1);

        requireUrlSafeBase64(hPart, "header");
        requireUrlSafeBase64(pPart, "payload");

        byte[] header = decodeBase64(hPart, "header");
        byte[] payload = decodeBase64(pPart, "payload");
        return of(header, payload);
    }

    private static void requireUrlSafeBase64(String s, String what) {
        if (s.isEmpty()) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, what + " segment is empty");
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                // '=', '+' and '/' are the usual mistakes: padding, or standard base64
                throw new EnvelopeException(EnvelopeErrorCode.FORMAT,
                        what + " segment contains illegal character '" + c
                                + "' at " + i + " (URL-safe base64 without padding required)");
            }
        }
    }

    private static byte[] decodeBase64(String s, String what) {
        try {
            return B64D.decode(s);
        } catch (IllegalArgumentException e) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, what + " is not valid base64url", e);
        }
    }

    /** Encodes to a string that can be stored in a single column. */
    public String encode() {
        return PREFIX + B64E.encodeToString(header) + "." + B64E.encodeToString(payload);
    }

    /** First half of the AEAD additional data: the raw header bytes. */
    byte[] headerBytes() {
        return header.clone();
    }

    byte[] payloadBytes() {
        return payload.clone();
    }

    public byte version() {
        return version;
    }

    public byte alg() {
        return alg;
    }

    public UUID keyId() {
        return keyId;
    }

    public long keyVer() {
        return keyVer;
    }

    public byte wrap() {
        return wrap;
    }

    public byte[] dekWrap() {
        return dekWrap.clone();
    }

    public byte[] ctxHash() {
        return ctxHash.clone();
    }

    public byte[] nonce() {
        return nonce.clone();
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    public byte[] tag() {
        return tag.clone();
    }

    /** Plaintext length; GCM ciphertext has the same length as the plaintext. */
    public int plaintextLength() {
        return ciphertext.length;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Envelope other
                && Arrays.equals(header, other.header)
                && Arrays.equals(payload, other.payload);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(header) + Arrays.hashCode(payload);
    }

    @Override
    public String toString() {
        return "Envelope{ver=" + version + ", alg=" + alg
                + ", keyId=" + keyId + ", keyVer=" + keyVer
                + ", wrap=" + wrap + ", ctLen=" + ciphertext.length + "}";
    }
}
