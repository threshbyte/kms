package com.thresh.kmslab.core;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A customer master key. The key material itself never lives here: only the identity, the
 * lifecycle timestamps and where the KEK versions are held.
 *
 * @author threshbyte
 */
public final class ManagedKey {

    private final UUID keyId;
    private final String alias;
    private final String tenant;
    private final boolean exportAllowed;
    private final Instant createdAt;

    private KeyState state;
    private int currentVersion;
    private Instant stateChangedAt;
    private Instant deleteAfter;

    ManagedKey(UUID keyId, String alias, String tenant, boolean exportAllowed, Instant createdAt) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.alias = Objects.requireNonNull(alias, "alias");
        this.tenant = Objects.requireNonNull(tenant, "tenant");
        this.exportAllowed = exportAllowed;
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
        this.state = KeyState.ENABLED;
        this.currentVersion = 1;
        this.stateChangedAt = createdAt;
    }

    public UUID keyId() {
        return keyId;
    }

    public String alias() {
        return alias;
    }

    public String tenant() {
        return tenant;
    }

    /** Whether the plaintext DEK may ever leave the service (envelope mode B). */
    public boolean exportAllowed() {
        return exportAllowed;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public KeyState state() {
        return state;
    }

    public int currentVersion() {
        return currentVersion;
    }

    public Instant stateChangedAt() {
        return stateChangedAt;
    }

    /** Set only while {@link KeyState#PENDING_DELETION}. */
    public Instant deleteAfter() {
        return deleteAfter;
    }

    /**
     * Rebuilds a key from persisted state.
     *
     * <p>Restoring bypasses the normal transitions on purpose: the journal already validated them
     * when they happened, and re-running them would emit duplicate events and audit entries.
     *
     * <p>Public for the persistence layer only. Nothing else should construct a key this way.
     */
    public static ManagedKey restore(UUID keyId, String alias, String tenant, boolean exportAllowed,
                              Instant createdAt, KeyState state, int currentVersion,
                              Instant stateChangedAt, Instant deleteAfter) {
        ManagedKey key = new ManagedKey(keyId, alias, tenant, exportAllowed, createdAt);
        key.state = state;
        key.currentVersion = currentVersion;
        key.stateChangedAt = stateChangedAt;
        key.deleteAfter = deleteAfter;
        return key;
    }

    void transitionTo(KeyState next, Instant now) {
        this.state = Objects.requireNonNull(next, "next");
        this.stateChangedAt = Objects.requireNonNull(now, "now");
        if (next != KeyState.PENDING_DELETION) {
            this.deleteAfter = null;
        }
    }

    void scheduleDeletion(Instant deleteAfter, Instant now) {
        this.deleteAfter = Objects.requireNonNull(deleteAfter, "deleteAfter");
        transitionTo(KeyState.PENDING_DELETION, now);
        this.deleteAfter = deleteAfter;
    }

    void bumpVersion() {
        this.currentVersion++;
    }

    @Override
    public String toString() {
        return "ManagedKey{" + alias + ", state=" + state + ", v=" + currentVersion + '}';
    }
}
