package com.thresh.kmslab.core;

/**
 * Key lifecycle state. Design: architecture document §6.1.
 *
 * <p>{@link #DISABLED} and deletion are deliberately separate: an incident responder needs a
 * fast, reversible break-glass switch, and deletion is irreversible.
 *
 * @author threshbyte
 */
public enum KeyState {
    /** Normal. Encrypt and decrypt are allowed. */
    ENABLED,
    /** Break-glass. Neither encrypt nor decrypt is allowed, but {@code enable} restores service. */
    DISABLED,
    /** Deletion requested. Waiting out the cooling period; {@code cancelDeletion} still works. */
    PENDING_DELETION,
    /** Key material destroyed. Terminal, and every ciphertext under this key is unreadable. */
    DELETED;

    public boolean canEncrypt() {
        return this == ENABLED;
    }

    public boolean canDecrypt() {
        return this == ENABLED;
    }
}
