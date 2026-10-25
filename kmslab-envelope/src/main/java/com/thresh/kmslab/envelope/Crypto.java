package com.thresh.kmslab.envelope;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;

/**
 * Internal helpers: SHA-256, zeroization, UUID encoding.
 *
 * @author threshbyte
 */
final class Crypto {

    private Crypto() {
    }

    static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Best-effort zeroization. The JVM cannot guarantee cryptographic erasure because the
     * garbage collector relocates objects; this only shortens the exposure window.
     */
    static void zero(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }

    static byte[] uuidToBytes(UUID id) {
        byte[] out = new byte[16];
        long msb = id.getMostSignificantBits();
        long lsb = id.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (msb >>> (8 * (7 - i)));
            out[8 + i] = (byte) (lsb >>> (8 * (7 - i)));
        }
        return out;
    }

    static UUID bytesToUuid(byte[] b, int off) {
        long msb = 0;
        long lsb = 0;
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (b[off + i] & 0xffL);
            lsb = (lsb << 8) | (b[off + 8 + i] & 0xffL);
        }
        return new UUID(msb, lsb);
    }
}
