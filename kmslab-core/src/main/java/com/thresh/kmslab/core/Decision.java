package com.thresh.kmslab.core;

/**
 * The outcome of a policy evaluation.
 *
 * <p>A deny always carries a reason code: "access denied" with no reason is unoperable, and the
 * reason is safe to log because it describes the rule that fired, never the data.
 *
 * @author threshbyte
 */
public record Decision(boolean allowed, String reason) {

    public static Decision allow() {
        return new Decision(true, "ALLOW");
    }

    public static Decision deny(String reason) {
        return new Decision(false, reason);
    }

    public static final String NO_GRANT = "NO_GRANT";
    public static final String ACTION_NOT_GRANTED = "ACTION_NOT_GRANTED";
    public static final String PURPOSE_REQUIRED = "PURPOSE_REQUIRED";
    public static final String PURPOSE_NOT_ALLOWED = "PURPOSE_NOT_ALLOWED";
    public static final String COLUMN_NOT_ALLOWED = "COLUMN_NOT_ALLOWED";
    public static final String TENANT_MISMATCH = "TENANT_MISMATCH";
}
