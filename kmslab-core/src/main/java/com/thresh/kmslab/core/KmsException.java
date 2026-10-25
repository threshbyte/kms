package com.thresh.kmslab.core;

/**
 * Service layer failure. Never carries key material or plaintext fragments.
 *
 * @author threshbyte
 */
public class KmsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final KmsErrorCode code;
    private final String reason;

    public KmsException(KmsErrorCode code, String message) {
        this(code, message, null);
    }

    /**
     * @param reason machine-readable reason, e.g. {@code KEY_NOT_IN_TOKEN}; null when the code
     *               alone is enough. Exposed over the API so clients do not parse prose.
     */
    public KmsException(KmsErrorCode code, String message, String reason) {
        super(message);
        this.code = code;
        this.reason = reason;
    }

    public KmsErrorCode code() {
        return code;
    }

    public String reason() {
        return reason;
    }

    @Override
    public String toString() {
        return "KmsException[" + code + "]: " + getMessage();
    }
}
