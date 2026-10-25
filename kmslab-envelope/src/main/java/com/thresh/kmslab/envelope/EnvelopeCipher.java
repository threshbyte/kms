package com.thresh.kmslab.envelope;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Encryption and decryption entry point for kms1 envelopes.
 *
 * <p>Encryption follows docs/envelope-v1.md §7, decryption §8. Core invariants:
 * <ul>
 *   <li>All 95 header bytes go into the AAD, so any mutation fails — this blocks algorithm
 *       downgrade and key substitution.</li>
 *   <li>{@code subkey = HKDF(DEK, salt=ctx_hash)}, so every record uses a distinct key.</li>
 *   <li>{@code ctx} is part of the AAD, so a ciphertext cannot be relocated to another
 *       column or row.</li>
 * </ul>
 *
 * @author threshbyte
 */
public final class EnvelopeCipher {

    private static final String GCM = "AES/GCM/NoPadding";
    private static final int TAG_BITS = Algorithms.TAG_LEN * 8;

    private final KeyWrapper wrapper;
    private final UUID defaultKeyId;
    private final long defaultKeyVer;
    private final SecureRandom random;

    public EnvelopeCipher(KeyWrapper wrapper, UUID keyId, long keyVer) {
        this(wrapper, keyId, keyVer, new SecureRandom());
    }

    public EnvelopeCipher(KeyWrapper wrapper, UUID keyId, long keyVer, SecureRandom random) {
        this.wrapper = wrapper;
        this.defaultKeyId = keyId;
        this.defaultKeyVer = keyVer;
        this.random = random;
    }

    /** Normal encryption: a fresh DEK and a fresh nonce every time. */
    public Envelope encrypt(Ctx ctx, byte[] plaintext) {
        byte[] dek = new byte[Algorithms.DEK_LEN];
        byte[] nonce = new byte[Algorithms.NONCE_LEN];
        random.nextBytes(dek);
        random.nextBytes(nonce);
        try {
            return doEncrypt(ctx, plaintext, dek, nonce, defaultKeyId, defaultKeyVer);
        } finally {
            Crypto.zero(dek);
            Crypto.zero(nonce);
        }
    }

    /**
     * Encrypts with caller-supplied key material. <b>Test vectors and cross-implementation
     * conformance only</b>; the production path must not call this.
     *
     * <p>The supplied arrays are copied and never modified.
     */
    public Envelope encryptWithMaterial(Ctx ctx, byte[] plaintext,
                                        UUID keyId, long keyVer, byte[] dek, byte[] nonce) {
        return doEncrypt(ctx, plaintext, dek.clone(), nonce.clone(), keyId, keyVer);
    }

    private Envelope doEncrypt(Ctx ctx, byte[] plaintext, byte[] dek, byte[] nonce,
                               UUID keyId, long keyVer) {
        if (ctx == null) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "ctx is required");
        }
        if (plaintext == null) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "plaintext is null");
        }
        if (dek.length != Algorithms.DEK_LEN) {
            throw new IllegalArgumentException("DEK must be 32 bytes");
        }
        if (nonce.length != Algorithms.NONCE_LEN) {
            throw new IllegalArgumentException("nonce must be 12 bytes");
        }

        byte[] subkey = null;
        try {
            byte[] ctxHash = ctx.hash();
            byte[] canonicalCtx = ctx.canonical();

            // 1) Wrap the DEK first: dek_wrap is an input to the header, not a function of it
            byte[] dekWrap = wrapper.wrap(keyId, keyVer, dek);
            if (dekWrap.length != Algorithms.DEK_WRAP_LEN) {
                throw new IllegalStateException("wrapper returned " + dekWrap.length + " bytes, expected 40");
            }

            // 2) Header
            byte[] header = buildHeader(keyId, keyVer, dekWrap, ctxHash);

            // 3) Derive the subkey and run the AEAD
            subkey = Hkdf.sha256(dek, ctxHash, Algorithms.HKDF_INFO_DATA, 32);
            byte[] aad = concat(header, canonicalCtx);
            byte[] ctAndTag = gcm(true, subkey, nonce, aad, plaintext);

            byte[] payload = new byte[Algorithms.NONCE_LEN + ctAndTag.length];
            System.arraycopy(nonce, 0, payload, 0, Algorithms.NONCE_LEN);
            System.arraycopy(ctAndTag, 0, payload, Algorithms.NONCE_LEN, ctAndTag.length);

            return Envelope.of(header, payload);
        } finally {
            Crypto.zero(dek);
            if (subkey != null) {
                Crypto.zero(subkey);
            }
        }
    }

    public byte[] decrypt(Ctx ctx, String text) {
        return decrypt(ctx, Envelope.decode(text));
    }

    public byte[] decrypt(Ctx ctx, Envelope env) {
        if (ctx == null) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "ctx is required");
        }
        byte[] ctxHash = ctx.hash();

        // A ctx that does not match the header is its own error class: it is the signature of a
        // ciphertext moved to a different row or column.
        if (!MessageDigest.isEqual(ctxHash, env.ctxHash())) {
            throw new EnvelopeException(EnvelopeErrorCode.CONTEXT_MISMATCH,
                    "ctx does not match envelope ctx_hash (ciphertext moved or wrong ctx supplied)");
        }

        byte[] dek = null;
        byte[] subkey = null;
        try {
            dek = wrapper.unwrap(env.keyId(), env.keyVer(), env.dekWrap());
            if (dek.length != Algorithms.DEK_LEN) {
                throw new EnvelopeException(EnvelopeErrorCode.AUTH, "unwrapped DEK has wrong length");
            }
            subkey = Hkdf.sha256(dek, ctxHash, Algorithms.HKDF_INFO_DATA, 32);

            byte[] aad = concat(env.headerBytes(), ctx.canonical());
            return gcm(false, subkey, env.nonce(), aad, concat(env.ciphertext(), env.tag()));
        } finally {
            Crypto.zero(dek);
            Crypto.zero(subkey);
        }
    }

    private static byte[] buildHeader(UUID keyId, long keyVer, byte[] dekWrap, byte[] ctxHash) {
        if (keyVer < 0 || keyVer > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("keyVer out of uint32 range: " + keyVer);
        }
        ByteBuffer h = ByteBuffer.allocate(Algorithms.HEADER_LEN).order(ByteOrder.BIG_ENDIAN);
        h.put(Algorithms.VER_1);
        h.put(Algorithms.ALG_AES_256_GCM);
        h.put(Crypto.uuidToBytes(keyId));
        h.putInt((int) keyVer);
        h.put(Algorithms.WRAP_AES_256_KW);
        h.put(dekWrap, 0, Algorithms.DEK_WRAP_LEN);
        h.put(ctxHash, 0, 32);
        return h.array();
    }

    private static byte[] gcm(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input) {
        try {
            Cipher c = Cipher.getInstance(GCM);
            c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            c.updateAAD(aad);
            return c.doFinal(input);
        } catch (GeneralSecurityException e) {
            if (encrypt) {
                throw new EnvelopeException(EnvelopeErrorCode.AUTH, "AEAD encryption failed", e);
            }
            throw new EnvelopeException(EnvelopeErrorCode.AUTH, "AEAD authentication failed", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
