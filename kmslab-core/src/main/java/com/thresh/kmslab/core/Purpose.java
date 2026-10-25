package com.thresh.kmslab.core;

/**
 * Why a caller wants plaintext. A decrypt request without a purpose is rejected: "I need the data"
 * is not a purpose, and the purpose is what makes the audit trail answerable.
 *
 * @author threshbyte
 */
public enum Purpose {
    /** Rendering a value back to the owning user. */
    USER_VIEW,
    /** Bulk export, typically requiring dual approval. */
    EXPORT,
    /** Re-encryption during a rotation or migration job. */
    MIGRATION
}
