package com.thresh.kmslab.server;

/**
 * An error that maps directly onto an HTTP status. Used for transport-level problems; domain
 * problems travel as {@link com.thresh.kmslab.core.KmsException} and are mapped centrally.
 *
 * @author threshbyte
 */
public class ApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int status;
    private final String code;

    public ApiException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }
}
