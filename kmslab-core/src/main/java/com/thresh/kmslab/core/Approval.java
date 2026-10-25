package com.thresh.kmslab.core;

/**
 * Two-person rule for destructive operations.
 *
 * <p>Same-person approval is rejected rather than quietly accepted: a control that one person can
 * satisfy alone is not a control.
 *
 * @author threshbyte
 */
public record Approval(String requester, String approver) {

    public Approval {
        if (requester == null || requester.isBlank()) {
            throw new KmsException(KmsErrorCode.APPROVAL_REQUIRED, "requester is required");
        }
        if (approver == null || approver.isBlank()) {
            throw new KmsException(KmsErrorCode.APPROVAL_REQUIRED, "approver is required");
        }
        if (requester.equals(approver)) {
            throw new KmsException(KmsErrorCode.APPROVAL_REQUIRED,
                    "requester and approver must be different people");
        }
    }
}
