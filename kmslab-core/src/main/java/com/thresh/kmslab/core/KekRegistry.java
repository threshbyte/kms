package com.thresh.kmslab.core;

import com.thresh.kmslab.envelope.KeyWrapper;

import java.util.UUID;

/**
 * Owns KEK material per (key, version).
 *
 * <p>In production this is backed by an HSM or a cloud KMS: provisioning generates material
 * inside the boundary and destroying makes it unrecoverable. The in-memory implementation is the
 * C1 tier and is development only.
 *
 * @author threshbyte
 */
public interface KekRegistry {

    /** Generates fresh KEK material for the given version. */
    void provision(UUID keyId, int version);

    /** Destroys the material. After this, ciphertext under that version is unreadable forever. */
    void destroy(UUID keyId, int version);

    /** The wrapper the cipher uses. */
    KeyWrapper wrapper();
}
