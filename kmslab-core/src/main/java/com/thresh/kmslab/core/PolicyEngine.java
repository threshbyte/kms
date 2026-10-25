package com.thresh.kmslab.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authorisation engine. Deny by default; a grant is the only way in.
 *
 * <p>Two rules carry most of the weight:
 * <ul>
 *   <li><b>Encrypt does not imply decrypt.</b> A service that only writes encrypted data never
 *       receives {@link Action#DECRYPT}. This is the single largest difference from a
 *       "one token opens everything" design.</li>
 *   <li><b>Decrypt requires a purpose.</b> The purpose is recorded in the audit chain, so the
 *       question "why was this plaintext read" has an answer.</li>
 * </ul>
 *
 * @author threshbyte
 */
public final class PolicyEngine {

    private final Map<UUID, List<Grant>> grantsByKey = new ConcurrentHashMap<>();
    private GrantListener listener = GrantListener.NONE;

    /**
     * Registers the durability hook. Call before the first mutation; a grant that is not durable
     * by the time the call returns is a lock-out on the next restart.
     */
    public void setListener(GrantListener listener) {
        this.listener = Objects.requireNonNull(listener, "listener");
    }

    public void grant(Grant grant) {
        Objects.requireNonNull(grant, "grant");
        grantsByKey.compute(grant.keyId(), (k, v) -> {
            List<Grant> list = v == null ? new ArrayList<>() : new ArrayList<>(v);
            list.removeIf(g -> g.subject().equals(grant.subject()));
            list.add(grant);
            return List.copyOf(list);
        });
        listener.onGrant(grant);
    }

    public void revoke(String subject, UUID keyId) {
        grantsByKey.computeIfPresent(keyId, (k, v) -> {
            List<Grant> list = new ArrayList<>(v);
            list.removeIf(g -> g.subject().equals(subject));
            return List.copyOf(list);
        });
        listener.onRevoke(subject, keyId);
    }

    public List<Grant> grantsFor(UUID keyId) {
        return grantsByKey.getOrDefault(keyId, List.of());
    }

    /**
     * Decides one action.
     *
     * @param column  the {@code ctx.column} value, may be null
     * @param purpose required for DECRYPT, ignored otherwise
     */
    public Decision decide(Principal principal, Action action, UUID keyId,
                           String tenant, String column, Purpose purpose) {
        Grant grant = grantsFor(keyId).stream()
                .filter(g -> g.subject().equals(principal.subject()))
                .findFirst()
                .orElse(null);
        if (grant == null) {
            return Decision.deny(Decision.NO_GRANT);
        }
        if (!grant.actions().contains(action)) {
            return Decision.deny(Decision.ACTION_NOT_GRANTED);
        }
        if (!principal.tenant().equals(tenant)) {
            return Decision.deny(Decision.TENANT_MISMATCH);
        }
        if (action == Action.DECRYPT) {
            if (purpose == null) {
                return Decision.deny(Decision.PURPOSE_REQUIRED);
            }
            if (!grant.allowedPurposes().contains(purpose)) {
                return Decision.deny(Decision.PURPOSE_NOT_ALLOWED);
            }
        }
        Set<String> columns = grant.allowedColumns();
        if (!columns.isEmpty() && (column == null || !columns.contains(column))) {
            return Decision.deny(Decision.COLUMN_NOT_ALLOWED);
        }
        return Decision.allow();
    }
}
