package com.thresh.kmslab.sdk;

/**
 * A failed API call, carrying the server's machine-readable error.
 *
 * <p>Callers branch on {@link #code()} (the category, e.g. {@code INVALID_STATE}) and may inspect
 * {@link #reason()} for the specific cause (e.g. {@code KEY_STATE_DISABLED}). Neither field ever
 * contains a token or plaintext: the server does not send them and the client does not add them.
 *
 * @author threshbyte
 */
public class KmsClientException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int status;
    private final String code;
    private final String reason;

    public KmsClientException(int status, String code, String reason, String message) {
        super(message);
        this.status = status;
        this.code = code;
        this.reason = reason;
    }

    /** HTTP status. */
    public int status() {
        return status;
    }

    /** Error category from the server, e.g. {@code FORBIDDEN}. */
    public String code() {
        return code;
    }

    /** Specific cause from the server, or null when the category is enough. */
    public String reason() {
        return reason;
    }

    /** True when the token was missing, expired or forged; a retry after refreshing may work. */
    public boolean isAuthenticationFailure() {
        return status == 401;
    }

    @Override
    public String toString() {
        return "KmsClientException[" + status + " " + code
                + (reason == null ? "" : "/" + reason) + "]: " + getMessage();
    }
}
