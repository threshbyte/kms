package com.thresh.kmslab.store;

import com.thresh.kmslab.core.KekRegistry;
import com.thresh.kmslab.envelope.KeyWrapper;
import com.thresh.kmslab.envelope.SoftKeyWrapper;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Stores KEK material wrapped under a storage root key (SRK), and journals every change.
 *
 * <p><b>The SRK is the trust anchor and this class never invents it.</b> The caller supplies 32
 * bytes from wherever it can actually protect them: an environment variable injected by the
 * orchestrator, a TPM-sealed secret, or a cloud KMS. If the SRK sits on the same disk as the
 * journal, persistence buys availability and nothing else — which is still C1, and must be stated
 * that way rather than implied to be encryption.
 *
 * <p>Wrapping is AES-256-KW, so the stored form is authenticated: a flipped bit in the journal
 * makes the KEK unloadable instead of loading a wrong one.
 *
 * @author threshbyte
 */
public final class WrappedKekVault implements KekRegistry {

    /** Journal record for a new wrapped KEK. */
    static final String KEK_WRAPPED = "KEK_WRAPPED";
    /** Journal record for destroyed material. */
    static final String KEK_DESTROYED = "KEK_DESTROYED";

    private static final int KEK_LEN = 32;
    private static final int SRK_LEN = 32;
    private static final byte[] KW_IV = {
            (byte) 0xA6, (byte) 0xA6, (byte) 0xA6, (byte) 0xA6,
            (byte) 0xA6, (byte) 0xA6, (byte) 0xA6, (byte) 0xA6};

    private final byte[] srk;
    private final Journal journal;
    private final SoftKeyWrapper wrapper = new SoftKeyWrapper();
    private final SecureRandom random = new SecureRandom();

    public WrappedKekVault(byte[] storageRootKey, Journal journal) {
        Objects.requireNonNull(storageRootKey, "storageRootKey");
        if (storageRootKey.length != SRK_LEN) {
            throw new IllegalArgumentException("storage root key must be 32 bytes");
        }
        this.srk = storageRootKey.clone();
        this.journal = Objects.requireNonNull(journal, "journal");
    }

    @Override
    public void provision(UUID keyId, int version) {
        byte[] kek = new byte[KEK_LEN];
        random.nextBytes(kek);
        try {
            // Journal first: a crash after this line leaves recoverable material, never a key
            // whose material was silently dropped.
            journal.append(KEK_WRAPPED, Map.of(
                    "keyId", keyId.toString(),
                    "version", version,
                    "wrapped", Base64.getEncoder().encodeToString(wrap(kek))));
            wrapper.put(keyId, version, kek);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
    }

    @Override
    public void destroy(UUID keyId, int version) {
        wrapper.remove(keyId, version);
        journal.append(KEK_DESTROYED, Map.of(
                "keyId", keyId.toString(),
                "version", version));
    }

    @Override
    public KeyWrapper wrapper() {
        return wrapper;
    }

    /** Drops material during a replay, without journaling what is already journaled. */
    void forget(UUID keyId, int version) {
        wrapper.remove(keyId, version);
    }

    /** Restores material during a replay. Fails loudly if the SRK is wrong. */
    void restore(UUID keyId, int version, String wrappedBase64) {
        byte[] wrapped = Base64.getDecoder().decode(wrappedBase64);
        wrapper.put(keyId, version, unwrap(wrapped));
    }

    private byte[] wrap(byte[] kek) {
        try {
            Cipher cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.WRAP_MODE, new SecretKeySpec(srk, "AES"));
            return cipher.wrap(new SecretKeySpec(kek, "AES"));
        } catch (GeneralSecurityException e) {
            throw new Journal.JournalException("cannot wrap KEK", e);
        }
    }

    private byte[] unwrap(byte[] wrapped) {
        try {
            Cipher cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(srk, "AES"));
            return cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded();
        } catch (GeneralSecurityException e) {
            // AES-KW integrity failure lands here: wrong SRK, or a tampered journal line.
            throw new Journal.JournalException(
                    "cannot unwrap a KEK: wrong storage root key, or the journal was modified", e);
        }
    }
}
