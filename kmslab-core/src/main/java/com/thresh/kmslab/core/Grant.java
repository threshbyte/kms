package com.thresh.kmslab.core;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * An authorisation grant: which subject may perform which actions on one key.
 *
 * <p>An empty {@code allowedColumns} means "no column restriction". A non-empty set restricts the
 * operation to those {@code ctx.column} values, which is what keeps a reporting service away from
 * the columns it has no business reading.
 *
 * @author threshbyte
 * @param allowedPurposes required for DECRYPT; empty means no purpose is acceptable
 */
public record Grant(
        String subject,
        UUID keyId,
        Set<Action> actions,
        Set<String> allowedColumns,
        Set<Purpose> allowedPurposes) {

    public Grant {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(keyId, "keyId");
        actions = Set.copyOf(Objects.requireNonNull(actions, "actions"));
        allowedColumns = Set.copyOf(Objects.requireNonNull(allowedColumns, "allowedColumns"));
        allowedPurposes = Set.copyOf(Objects.requireNonNull(allowedPurposes, "allowedPurposes"));
    }

    /** Convenience factory for the common "encrypt only, all columns" grant. */
    public static Grant encryptOnly(String subject, UUID keyId) {
        return new Grant(subject, keyId, Set.of(Action.ENCRYPT), Set.of(), Set.of());
    }

    /** Convenience factory for "encrypt and decrypt these columns, for these purposes". */
    public static Grant readWrite(String subject, UUID keyId,
                                 Set<String> columns, Set<Purpose> purposes) {
        return new Grant(subject, keyId, Set.of(Action.ENCRYPT, Action.DECRYPT), columns, purposes);
    }
}
