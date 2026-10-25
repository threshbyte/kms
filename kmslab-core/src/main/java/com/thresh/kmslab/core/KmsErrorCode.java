package com.thresh.kmslab.core;

/**
 * Stable error codes for the service layer, mirroring the four envelope codes.
 *
 * @author threshbyte
 */
public enum KmsErrorCode {
    /** Key, alias or grant does not exist. */
    NOT_FOUND,
    /** The operation is not valid in the current key state. */
    INVALID_STATE,
    /** Uniqueness violation, e.g. duplicate alias. */
    CONFLICT,
    /** The caller is not authorised. */
    FORBIDDEN,
    /** A destructive operation needs a second, different approver. */
    APPROVAL_REQUIRED,
    /** Ciphertexts still reference this key version. */
    REFERENCES_EXIST,
    /** The deletion cooling period has not elapsed yet. */
    COOLING_PERIOD_ACTIVE,
    /** Malformed request. */
    BAD_REQUEST
}
