package com.thresh.kmslab.envelope;

/**
 * Algorithm identifiers and fixed sizes for the kms1 format. See docs/envelope-v1.md §3/§3.1.
 *
 * @author threshbyte
 */
public final class Algorithms {

    /** Format version. Only 0x01 is accepted. */
    public static final byte VER_1 = 0x01;

    /** AEAD: AES-256-GCM (12-byte nonce, 16-byte tag). */
    public static final byte ALG_AES_256_GCM = 0x01;

    /** DEK wrapping: AES-256-KW (RFC 3394). */
    public static final byte WRAP_AES_256_KW = 0x01;

    /** Fixed header length. */
    public static final int HEADER_LEN = 95;
    /** DEK length. */
    public static final int DEK_LEN = 32;
    /** AES-KW output length: 32-byte plaintext plus an 8-byte integrity check value. */
    public static final int DEK_WRAP_LEN = 40;
    /** GCM nonce length. */
    public static final int NONCE_LEN = 12;
    /** GCM tag length. */
    public static final int TAG_LEN = 16;
    /** Minimum payload length, i.e. nonce plus tag. */
    public static final int PAYLOAD_MIN_LEN = NONCE_LEN + TAG_LEN;
    /** Upper bound on the canonical context, to bound memory use. */
    public static final int MAX_CTX_CANONICAL_LEN = 4096;

    /** HKDF domain separation string. Changing it changes the format. */
    static final byte[] HKDF_INFO_DATA = "kms1/data".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private Algorithms() {
    }

    static boolean isSupportedVersion(byte v) {
        return v == VER_1;
    }

    static boolean isSupportedAlg(byte a) {
        return a == ALG_AES_256_GCM;
    }

    static boolean isSupportedWrap(byte w) {
        return w == WRAP_AES_256_KW;
    }
}
