package com.thresh.kmslab.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Append-only, hash-chained audit log.
 *
 * <p>Not a "better log file": the chain is verifiable offline. Anyone holding a copy of the entries
 * can recompute the hashes and detect an insertion, deletion or edit in the middle. Merkle
 * checkpoints and per-operation receipts are a later stage; the chain is the prerequisite.
 *
 * <p>In-memory here. Production writes to WORM storage and publishes signed checkpoints.
 *
 * @author threshbyte
 */
public final class AuditLog {

    /** Hash of the imaginary entry before the first one. */
    static final String GENESIS = "0".repeat(64);

    private final List<AuditEntry> entries = new ArrayList<>();
    private final Clock clock;
    private String lastHash = GENESIS;
    private java.util.function.Consumer<AuditEntry> appender = e -> {
    };

    public AuditLog(Clock clock) {
        this.clock = clock;
    }

    /**
     * Resumes an existing chain.
     *
     * <p>The chain is verified before it is adopted. Loading an unverified chain would let a
     * tampered file become the new head, and every later entry would then "prove" the forgery.
     *
     * @throws IllegalStateException when the loaded chain does not verify
     */
    public AuditLog(Clock clock, List<AuditEntry> existing) {
        this.clock = clock;
        String problem = verify(existing);
        if (problem != null) {
            throw new IllegalStateException("refusing to resume a broken audit chain: " + problem);
        }
        this.entries.addAll(existing);
        if (!existing.isEmpty()) {
            this.lastHash = existing.get(existing.size() - 1).hash();
        }
    }

    /**
     * Appends an entry and returns it.
     *
     * @param ctxHash raw SHA-256 of the canonical context, or null when not applicable
     */
    public synchronized AuditEntry append(String actor, String action, UUID keyId, Long keyVersion,
                                          String outcome, String detail, byte[] ctxHash) {
        long seq = entries.size() + 1L;
        Instant at = clock.instant();
        String ctxHashHex = ctxHash == null ? null : HexFormat.of().formatHex(ctxHash);
        AuditEntry draft = new AuditEntry(seq, at, actor, action, keyId, keyVersion,
                outcome, detail, ctxHashHex, lastHash, "");
        String hash = hashOf(draft);
        AuditEntry entry = new AuditEntry(seq, at, actor, action, keyId, keyVersion,
                outcome, detail, ctxHashHex, lastHash, hash);
        appender.accept(entry);
        entries.add(entry);
        lastHash = hash;
        return entry;
    }

    /**
     * Registers the durability sink, called <b>before</b> the entry is accepted.
     *
     * <p>If the sink throws, the entry is not added and the operation that caused it fails. That
     * ordering is deliberate: an audit entry that was acknowledged but not persisted is a hole in
     * the only evidence trail this system has.
     */
    public synchronized void setAppender(java.util.function.Consumer<AuditEntry> appender) {
        this.appender = java.util.Objects.requireNonNull(appender, "appender");
    }

    public synchronized List<AuditEntry> entries() {
        return List.copyOf(entries);
    }

    public synchronized AuditEntry last() {
        return entries.isEmpty() ? null : entries.get(entries.size() - 1);
    }

    /**
     * Recomputes every hash and checks the backward links.
     *
     * @return null when the chain is intact, otherwise a description of the first broken link
     */
    public static String verify(List<AuditEntry> chain) {
        String expectedPrev = GENESIS;
        long expectedSeq = 1;
        for (AuditEntry e : chain) {
            if (e.sequence() != expectedSeq) {
                return "sequence gap: expected " + expectedSeq + " but found " + e.sequence();
            }
            if (!e.prevHash().equals(expectedPrev)) {
                return "broken link at seq " + e.sequence() + ": prevHash does not match";
            }
            String recomputed = hashOf(e);
            if (!recomputed.equals(e.hash())) {
                return "hash mismatch at seq " + e.sequence() + ": entry was modified";
            }
            expectedPrev = e.hash();
            expectedSeq++;
        }
        return null;
    }

    /**
     * Canonical byte layout of an entry. Field order is part of the format: changing it
     * invalidates every historical hash, so treat it as frozen.
     */
    static String hashOf(AuditEntry e) {
        String canonical = String.join("\u001f",
                Long.toString(e.sequence()),
                e.at().toString(),
                e.actor(),
                e.action(),
                e.keyId() == null ? "" : e.keyId().toString(),
                e.keyVersion() == null ? "" : e.keyVersion().toString(),
                e.outcome(),
                e.detail() == null ? "" : e.detail(),
                e.ctxHashHex() == null ? "" : e.ctxHashHex(),
                e.prevHash());
        return sha256Hex(canonical);
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
