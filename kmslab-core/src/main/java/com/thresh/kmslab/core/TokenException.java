package com.thresh.kmslab.core;

/**
 * Capability token failure. Kept separate from {@link KmsException} because token problems are
 * authentication failures (401) while KMS errors are authorisation or state failures (403/409).
 *
 * @author threshbyte
 */
public class TokenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Why the token was rejected. Never leaks token contents. */
    public enum Reason {
        /** Not parseable as a token. */
        MALFORMED,
        /** Signature does not match: the token was edited or forged. */
        BAD_SIGNATURE,
        /** The {@code expires} caveat is in the past. */
        EXPIRED,
        /** A required caveat is absent. */
        MISSING_CLAIM
    }

    private final Reason reason;

    public TokenException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }

    @Override
    public String toString() {
        return "TokenException[" + reason + "]: " + getMessage();
    }
}
