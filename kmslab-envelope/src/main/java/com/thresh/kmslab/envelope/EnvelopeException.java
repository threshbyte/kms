package com.thresh.kmslab.envelope;

/**
 * Raised when an envelope cannot be parsed, encrypted or decrypted.
 *
 * @author threshbyte
 */
public class EnvelopeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final EnvelopeErrorCode code;

    public EnvelopeException(EnvelopeErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public EnvelopeException(EnvelopeErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public EnvelopeErrorCode code() {
        return code;
    }

    @Override
    public String toString() {
        return "EnvelopeException[" + code + "]: " + getMessage();
    }
}
