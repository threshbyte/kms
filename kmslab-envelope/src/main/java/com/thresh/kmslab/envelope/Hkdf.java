package com.thresh.kmslab.envelope;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * HKDF-SHA256 (RFC 5869), see docs/envelope-v1.md §5.
 *
 * <p>The format only needs a 32-byte output (a single block), but this is implemented for the
 * full RFC so that changing the length later cannot break it.
 *
 * @author threshbyte
 */
final class Hkdf {

    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32;

    private Hkdf() {
    }

    static byte[] sha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length <= 0 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("invalid HKDF output length: " + length);
        }
        byte[] prk = hmac(salt.length == 0 ? new byte[HASH_LEN] : salt, ikm);

        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        for (int i = 1; offset < length; i++) {
            Mac mac = newMac(prk);
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            int n = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, okm, offset, n);
            offset += n;
        }
        Crypto.zero(prk);
        return okm;
    }

    private static byte[] hmac(byte[] key, byte[] msg) {
        return newMac(key).doFinal(msg);
    }

    private static Mac newMac(byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
