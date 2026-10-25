package com.thresh.kmslab.core;

/**
 * Authorisable operations. DECRYPT is intentionally not implied by ENCRYPT.
 *
 * @author threshbyte
 */
public enum Action {
    ENCRYPT,
    DECRYPT,
    /** Hands the plaintext DEK to the caller; only for keys with exportAllowed. */
    GENERATE_DATA_KEY,
    ROTATE,
    DISABLE,
    ENABLE,
    SCHEDULE_DELETION,
    CANCEL_DELETION,
    PURGE,
    DESCRIBE
}
