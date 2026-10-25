package com.thresh.kmslab.envelope;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Software KEK wrapping (AES-256-KW). This is tier C1 of the architecture: <b>development,
 * test and staging only</b>.
 *
 * <p>Production must replace it with a CryptoBackend backed by a cloud KMS or a PKCS#11 HSM.
 * See the architecture document, decision C and §17.7. The existence of this class must never be
 * read as permission to run it in production: the root key lives in process memory, so whoever
 * owns the host owns every key.
 *
 * @author threshbyte
 */
public final class SoftKeyWrapper implements KeyWrapper {

    private final Map<UUID, Map<Long, byte[]>> keys = new HashMap<>();

    /** Registers a KEK (32 bytes). Not safe for concurrent mutation with reads. */
    public synchronized SoftKeyWrapper put(UUID keyId, long keyVer, byte[] kek) {
        if (kek == null || kek.length != Algorithms.DEK_LEN) {
            throw new IllegalArgumentException("KEK must be 32 bytes (AES-256)");
        }
        keys.computeIfAbsent(keyId, k -> new HashMap<>()).put(keyVer, kek.clone());
        return this;
    }

    /**
     * Destroys the KEK for one version. Every ciphertext bound to it becomes unreadable, which is
     * exactly what a key purge must achieve.
     *
     * @return true if material was present
     */
    public synchronized boolean remove(UUID keyId, long keyVer) {
        Map<Long, byte[]> versions = keys.get(keyId);
        if (versions == null) {
            return false;
        }
        boolean removed = versions.remove(keyVer) != null;
        if (versions.isEmpty()) {
            keys.remove(keyId);
        }
        return removed;
    }

    /** Registers a random KEK. Development and test convenience only. */
    public static SoftKeyWrapper dev(UUID keyId, long keyVer) {
        byte[] kek = new byte[Algorithms.DEK_LEN];
        new SecureRandom().nextBytes(kek);
        return new SoftKeyWrapper().put(keyId, keyVer, kek);
    }

    @Override
    public byte[] wrap(UUID keyId, long keyVer, byte[] dek) {
        if (dek == null || dek.length != Algorithms.DEK_LEN) {
            throw new IllegalArgumentException("DEK must be 32 bytes");
        }
        try {
            Cipher c = Cipher.getInstance("AESWrap");
            c.init(Cipher.WRAP_MODE, kek(keyId, keyVer));
            byte[] wrapped = c.wrap(new SecretKeySpec(dek, "AES"));
            if (wrapped.length != Algorithms.DEK_WRAP_LEN) {
                throw new IllegalStateException("unexpected AES-KW output length: " + wrapped.length);
            }
            return wrapped;
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException(EnvelopeErrorCode.AUTH, "DEK wrap failed", e);
        }
    }

    @Override
    public byte[] unwrap(UUID keyId, long keyVer, byte[] dekWrap) {
        try {
            Cipher c = Cipher.getInstance("AESWrap");
            c.init(Cipher.UNWRAP_MODE, kek(keyId, keyVer));
            SecretKey k = (SecretKey) c.unwrap(dekWrap, "AES", Cipher.SECRET_KEY);
            byte[] dek = k.getEncoded();
            if (dek == null || dek.length != Algorithms.DEK_LEN) {
                throw new EnvelopeException(EnvelopeErrorCode.AUTH, "unwrapped DEK has wrong length");
            }
            return dek;
        } catch (GeneralSecurityException e) {
            // A failed AES-KW integrity check lands here too
            throw new EnvelopeException(EnvelopeErrorCode.AUTH, "DEK unwrap failed", e);
        }
    }

    private SecretKeySpec kek(UUID keyId, long keyVer) {
        Map<Long, byte[]> versions = keys.get(keyId);
        byte[] kek = versions == null ? null : versions.get(keyVer);
        if (kek == null) {
            throw new EnvelopeException(EnvelopeErrorCode.AUTH,
                    "no KEK for keyId=" + keyId + " keyVer=" + keyVer);
        }
        return new SecretKeySpec(kek, "AES");
    }
}
