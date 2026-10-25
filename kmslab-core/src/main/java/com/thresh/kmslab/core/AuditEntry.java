package com.thresh.kmslab.core;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One link in the append-only audit chain.
 *
 * <p>The chain is what turns "we logged it" into "we can prove it was not edited": each entry
 * commits to its predecessor, so removing or altering one breaks every hash after it.
 *
 * @author threshbyte
 * @param sequence        monotonic, starting at 1
 * @param at              event time
 * @param actor           authenticated subject
 * @param action          the attempted operation
 * @param keyId           target key, may be null for non-key events
 * @param keyVersion      target key version, may be null
 * @param outcome         {@code ALLOW}, {@code DENY} or {@code ERROR}
 * @param detail          deny reason or error code; never contains plaintext
 * @param ctxHashHex      hex of SHA-256(canonical(ctx)), may be null
 * @param prevHash        hash of the previous entry, or 64 zeros for the first one
 * @param hash            hash of this entry
 */
public record AuditEntry(
        long sequence,
        Instant at,
        String actor,
        String action,
        UUID keyId,
        Long keyVersion,
        String outcome,
        String detail,
        String ctxHashHex,
        String prevHash,
        String hash) {

    public AuditEntry {
        Objects.requireNonNull(at, "at");
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(prevHash, "prevHash");
        Objects.requireNonNull(hash, "hash");
    }
}
