package com.thresh.kmslab.envelope;

import java.util.UUID;

/**
 * Wraps and unwraps a DEK. A production implementation is backed by an HSM or a cloud KMS
 * {@code CryptoBackend}; this interface only covers the AES-256-KW step.
 *
 * @author threshbyte
 */
public interface KeyWrapper {

    /** @return the 40-byte wrapped DEK */
    byte[] wrap(UUID keyId, long keyVer, byte[] dek);

    /** @return the 32-byte DEK; must throw {@link EnvelopeErrorCode#AUTH} if the integrity check fails */
    byte[] unwrap(UUID keyId, long keyVer, byte[] dekWrap);
}
