package com.thresh.kmslab.envelope;

/**
 * Error codes that every implementation must agree on. See docs/envelope-v1.md §8/§9.
 *
 * <p>These four codes must stay distinct. Collapsing them into a single "decryption failed"
 * would destroy the ability to tell "the ciphertext was moved to another row" apart from
 * "the key is wrong" — two completely different incidents.
 *
 * @author threshbyte
 */
public enum EnvelopeErrorCode {
    /** Structural or encoding violation: prefix, segment count, base64 alphabet, lengths. */
    FORMAT,
    /** Unknown version, algorithm or wrap mode. No downgrade guessing is allowed. */
    UNSUPPORTED,
    /** Supplied ctx does not match the header ctx_hash; usually a moved ciphertext. */
    CONTEXT_MISMATCH,
    /** DEK unwrap failed or AEAD tag verification failed. */
    AUTH
}
