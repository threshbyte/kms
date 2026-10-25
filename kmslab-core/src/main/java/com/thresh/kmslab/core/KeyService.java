package com.thresh.kmslab.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Key lifecycle. Implements the state machine from the architecture document §6.1.
 *
 * <p>Three properties are load bearing:
 * <ul>
 *   <li><b>Rotation adds a version, never a new key.</b> The {@code key_id} in the ciphertext
 *       header therefore stays stable across rotations, which is what lets old ciphertexts keep
 *       decrypting without a field-to-key mapping table.</li>
 *   <li><b>Disable and delete are different.</b> Disable is the reversible break-glass switch;
 *       delete destroys material and is irreversible.</li>
 *   <li><b>Deletion needs two people and a cooling period</b>, and refuses while ciphertexts
 *       still reference the key.</li>
 * </ul>
 *
 * @author threshbyte
 */
public final class KeyService {

    /** Default minimum cooling period before a scheduled deletion can be executed. */
    public static final Duration MIN_COOLING = Duration.ofDays(7);
    /** Default maximum cooling period. */
    public static final Duration MAX_COOLING = Duration.ofDays(30);

    /**
     * Actions a key creator receives automatically. Deliberately excludes ENCRYPT/DECRYPT:
     * administration and data access are separate duties.
     */
    public static final Set<Action> ADMIN_ACTIONS = Set.of(
            Action.ROTATE, Action.DISABLE, Action.ENABLE,
            Action.SCHEDULE_DELETION, Action.CANCEL_DELETION, Action.PURGE, Action.DESCRIBE);

    private final Map<UUID, ManagedKey> keysById = new ConcurrentHashMap<>();
    private final Map<String, UUID> idsByAlias = new ConcurrentHashMap<>();
    private final KekRegistry keks;
    private final PolicyEngine policy;
    private final AuditLog audit;
    private final Clock clock;
    private KeyEventListener listener = KeyEventListener.NONE;

    public KeyService(KekRegistry keks, PolicyEngine policy, AuditLog audit, Clock clock) {
        this.keks = keks;
        this.policy = policy;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Registers the durability hook. Call before the first mutation, and the listener must be
     * durable before the operation returns: an acknowledged create that vanishes on restart is
     * worse than a failed create.
     */
    public void setEventListener(KeyEventListener listener) {
        this.listener = Objects.requireNonNull(listener, "listener");
    }

    /**
     * Creates a key and makes the creator its administrator.
     *
     * <p>Any authenticated principal may create a key inside its own tenant; authority over the
     * new key is then explicit, so there is no ambient "everyone can use every key" state.
     */
    public ManagedKey create(Principal creator, String alias, String tenant, boolean exportAllowed) {
        if (alias == null || alias.isBlank()) {
            throw new KmsException(KmsErrorCode.BAD_REQUEST, "alias is required");
        }
        if (!creator.tenant().equals(tenant)) {
            throw new KmsException(KmsErrorCode.FORBIDDEN,
                    "cannot create a key in another tenant");
        }
        UUID keyId = UUID.randomUUID();
        if (idsByAlias.putIfAbsent(aliasKey(tenant, alias), keyId) != null) {
            throw new KmsException(KmsErrorCode.CONFLICT, "alias already exists: " + alias);
        }

        ManagedKey key = new ManagedKey(keyId, alias, tenant, exportAllowed, clock.instant());
        keysById.put(keyId, key);
        keks.provision(keyId, key.currentVersion());

        // The creator becomes the key administrator, not a data reader. Administration and data
        // access are separate: a key admin who can also decrypt is a single point of compromise,
        // and the whole point of an encrypt-only ingest identity is lost if admin implies read.
        policy.grant(new Grant(creator.subject(), keyId, ADMIN_ACTIONS, Set.of(), Set.of()));

        audit.append(creator.subject(), "CREATE_KEY", keyId, (long) key.currentVersion(),
                "ALLOW", "alias=" + alias, null);
        listener.onKeyEvent("KEY_CREATED", Map.of("keyId", keyId.toString(), "alias", alias, "tenant", tenant, "exportAllowed", exportAllowed, "createdAt", key.createdAt().toString()));
        return key;
    }

    public ManagedKey get(UUID keyId) {
        ManagedKey key = keysById.get(keyId);
        if (key == null) {
            throw new KmsException(KmsErrorCode.NOT_FOUND, "no such key: " + keyId);
        }
        return key;
    }

    public List<ManagedKey> list() {
        return List.copyOf(keysById.values());
    }

    /**
     * Re-inserts a key during a journal replay: no events, no audit, no KEK provisioning, because
     * the journal already recorded all of it.
     */
    public void restoreKey(ManagedKey key) {
        keysById.put(key.keyId(), key);
        idsByAlias.put(aliasKey(key.tenant(), key.alias()), key.keyId());
    }

    /** Adds a key version. Old versions stay readable. */
    public ManagedKey rotate(Principal actor, UUID keyId) {
        ManagedKey key = require(actor, Action.ROTATE, keyId);
        requireState(key, KeyState.ENABLED, "rotate");
        key.bumpVersion();
        keks.provision(keyId, key.currentVersion());
        audit.append(actor.subject(), "ROTATE", keyId, (long) key.currentVersion(), "ALLOW",
                "now at version " + key.currentVersion(), null);
        listener.onKeyEvent("KEY_ROTATED", Map.of("keyId", keyId.toString(), "version", key.currentVersion()));
        return key;
    }

    public ManagedKey disable(Principal actor, UUID keyId) {
        ManagedKey key = require(actor, Action.DISABLE, keyId);
        requireState(key, KeyState.ENABLED, "disable");
        key.transitionTo(KeyState.DISABLED, clock.instant());
        audit.append(actor.subject(), "DISABLE", keyId, (long) key.currentVersion(), "ALLOW", null, null);
        listener.onKeyEvent("KEY_STATE_CHANGED", Map.of("keyId", keyId.toString(), "state", "DISABLED", "changedAt", key.stateChangedAt().toString()));
        return key;
    }

    public ManagedKey enable(Principal actor, UUID keyId) {
        ManagedKey key = require(actor, Action.ENABLE, keyId);
        if (key.state() != KeyState.DISABLED) {
            throw new KmsException(KmsErrorCode.INVALID_STATE,
                    "only a DISABLED key can be enabled, current state is " + key.state());
        }
        key.transitionTo(KeyState.ENABLED, clock.instant());
        audit.append(actor.subject(), "ENABLE", keyId, (long) key.currentVersion(), "ALLOW", null, null);
        listener.onKeyEvent("KEY_STATE_CHANGED", Map.of("keyId", keyId.toString(), "state", "ENABLED", "changedAt", key.stateChangedAt().toString()));
        return key;
    }

    /**
     * Schedules deletion.
     *
     * @param referencingCiphertexts how many stored ciphertexts still reference this key, from an
     *                               actual scan, not from the requester's belief
     * @param force                  override the reference check; recorded in the audit chain
     */
    public ManagedKey scheduleDeletion(Principal actor, UUID keyId, Duration cooling,
                                       Approval approval, long referencingCiphertexts, boolean force) {
        ManagedKey key = require(actor, Action.SCHEDULE_DELETION, keyId);
        if (key.state() == KeyState.PENDING_DELETION || key.state() == KeyState.DELETED) {
            throw new KmsException(KmsErrorCode.INVALID_STATE,
                    "cannot schedule deletion from state " + key.state());
        }
        if (cooling.compareTo(MIN_COOLING) < 0 || cooling.compareTo(MAX_COOLING) > 0) {
            throw new KmsException(KmsErrorCode.BAD_REQUEST,
                    "cooling period must be between " + MIN_COOLING.toDays()
                            + " and " + MAX_COOLING.toDays() + " days");
        }
        if (!approval.requester().equals(actor.subject())) {
            throw new KmsException(KmsErrorCode.APPROVAL_REQUIRED,
                    "the approval must be requested by the caller");
        }
        if (referencingCiphertexts > 0 && !force) {
            throw new KmsException(KmsErrorCode.REFERENCES_EXIST,
                    referencingCiphertexts + " ciphertexts still reference this key");
        }
        Instant now = clock.instant();
        key.scheduleDeletion(now.plus(cooling), now);
        audit.append(actor.subject(), "SCHEDULE_DELETION", keyId, (long) key.currentVersion(), "ALLOW",
                "cooling=" + cooling.toDays() + "d, approver=" + approval.approver()
                        + ", referencing=" + referencingCiphertexts + ", force=" + force, null);
        listener.onKeyEvent("KEY_STATE_CHANGED", Map.of("keyId", keyId.toString(), "state", "PENDING_DELETION", "changedAt", key.stateChangedAt().toString(), "deleteAfter", key.deleteAfter().toString()));
        return key;
    }

    public ManagedKey cancelDeletion(Principal actor, UUID keyId) {
        ManagedKey key = require(actor, Action.CANCEL_DELETION, keyId);
        if (key.state() != KeyState.PENDING_DELETION) {
            throw new KmsException(KmsErrorCode.INVALID_STATE,
                    "not pending deletion, current state is " + key.state());
        }
        key.transitionTo(KeyState.ENABLED, clock.instant());
        audit.append(actor.subject(), "CANCEL_DELETION", keyId, (long) key.currentVersion(), "ALLOW",
                null, null);
        listener.onKeyEvent("KEY_STATE_CHANGED", Map.of("keyId", keyId.toString(), "state", "ENABLED", "changedAt", key.stateChangedAt().toString()));
        return key;
    }

    /**
     * Destroys the key material. Irreversible: every ciphertext under this key becomes unreadable.
     *
     * <p>Refuses before the cooling period elapses so that a mistaken schedule can still be
     * cancelled.
     */
    public void purge(Principal actor, UUID keyId) {
        ManagedKey key = require(actor, Action.PURGE, keyId);
        if (key.state() != KeyState.PENDING_DELETION) {
            throw new KmsException(KmsErrorCode.INVALID_STATE,
                    "only a PENDING_DELETION key can be purged, current state is " + key.state());
        }
        Instant now = clock.instant();
        if (key.deleteAfter() != null && now.isBefore(key.deleteAfter())) {
            throw new KmsException(KmsErrorCode.COOLING_PERIOD_ACTIVE,
                    "cooling period ends at " + key.deleteAfter());
        }
        int lastVersion = key.currentVersion();
        for (int v = 1; v <= lastVersion; v++) {
            keks.destroy(keyId, v);
        }
        key.transitionTo(KeyState.DELETED, now);
        audit.append(actor.subject(), "PURGE", keyId, (long) lastVersion, "ALLOW",
                "destroyed versions 1.." + lastVersion, null);
        listener.onKeyEvent("KEY_STATE_CHANGED", Map.of("keyId", keyId.toString(), "state", "DELETED", "changedAt", key.stateChangedAt().toString()));
    }

    /** Fetches the key and checks the admin policy for it. */
    private ManagedKey require(Principal actor, Action action, UUID keyId) {
        ManagedKey key = get(keyId);
        Decision d = policy.decide(actor, action, keyId, key.tenant(), null, null);
        if (!d.allowed()) {
            audit.append(actor.subject(), action.name(), keyId, (long) key.currentVersion(),
                    "DENY", d.reason(), null);
            throw new KmsException(KmsErrorCode.FORBIDDEN, "denied: " + d.reason(), d.reason());
        }
        return key;
    }

    private static String aliasKey(String tenant, String alias) {
        return tenant + "/" + alias;
    }

    private static void requireState(ManagedKey key, KeyState expected, String operation) {
        if (key.state() != expected) {
            throw new KmsException(KmsErrorCode.INVALID_STATE,
                    "cannot " + operation + " a key in state " + key.state());
        }
    }


}
