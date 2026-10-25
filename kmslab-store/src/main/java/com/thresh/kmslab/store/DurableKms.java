package com.thresh.kmslab.store;

import com.thresh.kmslab.core.Action;
import com.thresh.kmslab.core.AuditEntry;
import com.thresh.kmslab.core.AuditLog;
import com.thresh.kmslab.core.EnvelopeBroker;
import com.thresh.kmslab.core.Grant;
import com.thresh.kmslab.core.KeyService;
import com.thresh.kmslab.core.KeyState;
import com.thresh.kmslab.core.ManagedKey;
import com.thresh.kmslab.core.PolicyEngine;
import com.thresh.kmslab.core.Purpose;
import com.thresh.kmslab.store.Journal.Record;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Restart-safe assembly of the whole service.
 *
 * <p>Opening replays one journal into keys, grants, KEK material and the audit chain, then wires
 * every mutation back to the journal. Replay happens <b>before</b> the listeners are attached, so
 * rebuilding state never writes to the journal again.
 *
 * <p>What durability costs: an acknowledged operation is on disk, but a crash between the audit
 * line and the state line leaves an audit entry with no matching state change. Replay tolerates
 * that — state replay is idempotent and an orphan audit entry is harmless — and it is strictly
 * better than the alternative of writing state first and losing the evidence.
 *
 * @author threshbyte
 */
public final class DurableKms implements Closeable {

    static final String AUDIT_ENTRY = "AUDIT_ENTRY";
    static final String GRANT_SET = "GRANT_SET";
    static final String GRANT_REVOKED = "GRANT_REVOKED";

    private final Journal journal;
    private final AuditLog audit;
    private final PolicyEngine policy;
    private final KeyService keys;
    private final EnvelopeBroker broker;
    private final WrappedKekVault vault;
    private final Map<UUID, ManagedKey> keyCache = new LinkedHashMap<>();

    private DurableKms(Journal journal, AuditLog audit, PolicyEngine policy, KeyService keys,
                       EnvelopeBroker broker, WrappedKekVault vault) {
        this.journal = journal;
        this.audit = audit;
        this.policy = policy;
        this.keys = keys;
        this.broker = broker;
        this.vault = vault;
    }

    /**
     * Opens (or creates) the store in {@code directory}.
     *
     * @param storageRootKey 32 bytes protecting KEK material at rest; the caller owns its source
     */
    public static DurableKms open(Path directory, byte[] storageRootKey, Clock clock)
            throws IOException {
        Journal journal = Journal.open(directory.resolve("journal.jsonl"));
        List<Record> records = journal.readAll();

        List<AuditEntry> auditEntries = new ArrayList<>();
        for (Record record : records) {
            if (record.type().equals(AUDIT_ENTRY)) {
                auditEntries.add(toAuditEntry(record));
            }
        }

        // Resuming verifies the chain: adopting a tampered file would let the forgery become the
        // new head, and every later entry would then vouch for it.
        AuditLog audit = new AuditLog(clock, auditEntries);
        PolicyEngine policy = new PolicyEngine();
        WrappedKekVault vault = new WrappedKekVault(storageRootKey, journal);
        KeyService keys = new KeyService(vault, policy, audit, clock);

        Map<UUID, ManagedKey> current = new LinkedHashMap<>();
        for (Record record : records) {
            switch (record.type()) {
                case AUDIT_ENTRY -> {
                    // already loaded above
                }
                case "KEY_CREATED" -> applyCreated(keys, current, record);
                case "KEY_ROTATED" -> applyRotated(keys, current, record);
                case "KEY_STATE_CHANGED" -> applyStateChange(keys, current, record);
                case WrappedKekVault.KEK_WRAPPED -> vault.restore(
                        UUID.fromString(record.string("keyId")),
                        record.integer("version"),
                        record.string("wrapped"));
                case WrappedKekVault.KEK_DESTROYED -> vault.forget(
                        UUID.fromString(record.string("keyId")),
                        record.integer("version"));
                case GRANT_SET -> policy.grant(toGrant(record));
                case GRANT_REVOKED -> policy.revoke(
                        record.string("subject"),
                        UUID.fromString(record.string("keyId")));
                default -> throw new Journal.JournalException(
                        "unknown journal record type: " + record.type(), null);
            }
        }

        // Only now attach the durability hooks, so the replay itself cannot append.
        audit.setAppender(entry -> journal.append(AUDIT_ENTRY, toPayload(entry)));
        keys.setEventListener((type, payload) -> journal.append(type, payload));
        policy.setListener(new com.thresh.kmslab.core.GrantListener() {
            @Override
            public void onGrant(Grant grant) {
                journal.append(GRANT_SET, grantPayload(grant));
            }

            @Override
            public void onRevoke(String subject, UUID keyId) {
                journal.append(GRANT_REVOKED, Map.of("subject", subject,
                        "keyId", keyId.toString()));
            }
        });

        EnvelopeBroker broker = new EnvelopeBroker(keys, policy, audit, vault);
        DurableKms kms = new DurableKms(journal, audit, policy, keys, broker, vault);
        kms.keyCache.putAll(current);
        return kms;
    }

    /* ------------------------------------------------------------------ replay */

    private static void applyCreated(KeyService keys, Map<UUID, ManagedKey> current, Record r) {
        UUID keyId = UUID.fromString(r.string("keyId"));
        Instant createdAt = Instant.parse(r.string("createdAt"));
        ManagedKey key = ManagedKey.restore(keyId, r.string("alias"), r.string("tenant"),
                r.bool("exportAllowed"), createdAt, KeyState.ENABLED, 1, createdAt, null);
        keys.restoreKey(key);
        current.put(keyId, key);
    }

    private static void applyRotated(KeyService keys, Map<UUID, ManagedKey> current, Record r) {
        ManagedKey previous = require(current, r);
        ManagedKey rotated = ManagedKey.restore(previous.keyId(), previous.alias(),
                previous.tenant(), previous.exportAllowed(), previous.createdAt(),
                previous.state(), r.integer("version"), previous.stateChangedAt(),
                previous.deleteAfter());
        keys.restoreKey(rotated);
        current.put(rotated.keyId(), rotated);
    }

    private static void applyStateChange(KeyService keys, Map<UUID, ManagedKey> current, Record r) {
        ManagedKey previous = require(current, r);
        KeyState state = KeyState.valueOf(r.string("state"));
        Instant changedAt = Instant.parse(r.string("changedAt"));
        Instant deleteAfter = r.has("deleteAfter") ? Instant.parse(r.string("deleteAfter")) : null;
        ManagedKey updated = ManagedKey.restore(previous.keyId(), previous.alias(),
                previous.tenant(), previous.exportAllowed(), previous.createdAt(),
                state, previous.currentVersion(), changedAt, deleteAfter);
        keys.restoreKey(updated);
        current.put(updated.keyId(), updated);
    }

    private static ManagedKey require(Map<UUID, ManagedKey> current, Record r) {
        UUID keyId = UUID.fromString(r.string("keyId"));
        ManagedKey key = current.get(keyId);
        if (key == null) {
            throw new Journal.JournalException(
                    "journal refers to key " + keyId + " before it was created", null);
        }
        return key;
    }

    private static Grant toGrant(Record r) {
        Set<Action> actions = EnumSet.noneOf(Action.class);
        r.payload().path("actions").forEach(n -> actions.add(Action.valueOf(n.asText())));
        Set<String> columns = new LinkedHashSet<>();
        r.payload().path("columns").forEach(n -> columns.add(n.asText()));
        Set<Purpose> purposes = EnumSet.noneOf(Purpose.class);
        r.payload().path("purposes").forEach(n -> purposes.add(Purpose.valueOf(n.asText())));
        return new Grant(r.string("subject"), UUID.fromString(r.string("keyId")),
                actions, columns, purposes);
    }

    private static Map<String, Object> grantPayload(Grant grant) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("subject", grant.subject());
        payload.put("keyId", grant.keyId().toString());
        payload.put("actions", grant.actions().stream().map(Enum::name).toList());
        payload.put("columns", List.copyOf(grant.allowedColumns()));
        payload.put("purposes", grant.allowedPurposes().stream().map(Enum::name).toList());
        return payload;
    }

    private static Map<String, Object> toPayload(AuditEntry e) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sequence", e.sequence());
        payload.put("at", e.at().toString());
        payload.put("actor", e.actor());
        payload.put("action", e.action());
        payload.put("keyId", e.keyId() == null ? null : e.keyId().toString());
        payload.put("keyVersion", e.keyVersion());
        payload.put("outcome", e.outcome());
        payload.put("detail", e.detail());
        payload.put("ctxHashHex", e.ctxHashHex());
        payload.put("prevHash", e.prevHash());
        payload.put("hash", e.hash());
        return payload;
    }

    private static AuditEntry toAuditEntry(Record r) {
        return new AuditEntry(
                r.payload().path("sequence").asLong(),
                Instant.parse(r.string("at")),
                r.string("actor"),
                r.string("action"),
                r.has("keyId") ? UUID.fromString(r.string("keyId")) : null,
                r.has("keyVersion") ? r.payload().path("keyVersion").asLong() : null,
                r.string("outcome"),
                r.has("detail") ? r.string("detail") : null,
                r.has("ctxHashHex") ? r.string("ctxHashHex") : null,
                r.string("prevHash"),
                r.string("hash"));
    }

    /* ------------------------------------------------------------------ accessors */

    public KeyService keys() {
        return keys;
    }

    public PolicyEngine policy() {
        return policy;
    }

    public AuditLog audit() {
        return audit;
    }

    public EnvelopeBroker broker() {
        return broker;
    }

    public Path journalPath() {
        return journal.path();
    }

    @Override
    public void close() {
        journal.close();
    }
}
