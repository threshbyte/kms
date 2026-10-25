package com.thresh.kmslab.envelope;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Encryption context: binds a ciphertext to its position in the business data
 * (tenant / table / column / row_pk).
 *
 * <p>Canonical form per docs/envelope-v1.md §4.2: entries sorted by the unsigned
 * lexicographic order of the key's UTF-8 bytes, each written as
 * {@code u32be(len)||bytes} for key then value.
 *
 * <p>Sorting must use <b>UTF-8 bytes</b>, never {@link String#compareTo}. The latter compares
 * UTF-16 code units, which orders supplementary-plane characters differently and would make two
 * "correct" implementations disagree on the canonical bytes.
 *
 * @author threshbyte
 */
public final class Ctx {

    private final Map<String, String> entries;
    private final byte[] canonical;
    private final byte[] hash;

    private Ctx(Map<String, String> sortedEntries) {
        this.entries = sortedEntries;
        this.canonical = encode(sortedEntries);
        this.hash = Crypto.sha256().digest(this.canonical);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Convenience factory for a single-entry context. */
    public static Ctx of(String key, String value) {
        return builder().put(key, value).build();
    }

    public Map<String, String> asMap() {
        return entries;
    }

    /** Canonical bytes (defensive copy). */
    public byte[] canonical() {
        return canonical.clone();
    }

    /** SHA-256 of the canonical form (defensive copy). */
    public byte[] hash() {
        return hash.clone();
    }

    int canonicalLength() {
        return canonical.length;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Ctx other && entries.equals(other.entries);
    }

    @Override
    public int hashCode() {
        return entries.hashCode();
    }

    @Override
    public String toString() {
        return "Ctx" + entries;
    }

    private static byte[] encode(Map<String, String> sorted) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            byte[] k = e.getKey().getBytes(StandardCharsets.UTF_8);
            byte[] v = e.getValue().getBytes(StandardCharsets.UTF_8);
            writeU32(out, k.length);
            out.writeBytes(k);
            writeU32(out, v.length);
            out.writeBytes(v);
        }
        return out.toByteArray();
    }

    private static void writeU32(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xff);
        out.write((value >>> 16) & 0xff);
        out.write((value >>> 8) & 0xff);
        out.write(value & 0xff);
    }

    /** Unsigned lexicographic comparison of UTF-8 bytes. */
    private static int compareUtf8(String a, String b) {
        return Arrays.compareUnsigned(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    private static void checkSize(int len, String lastKey) {
        if (len > Algorithms.MAX_CTX_CANONICAL_LEN) {
            throw new EnvelopeException(EnvelopeErrorCode.FORMAT,
                    "ctx canonical length " + len + " exceeds " + Algorithms.MAX_CTX_CANONICAL_LEN
                            + " (last key: " + lastKey + ")");
        }
    }

    public static final class Builder {

        private final Map<String, String> raw = new LinkedHashMap<>();

        private Builder() {
        }

        public Builder put(String key, String value) {
            Objects.requireNonNull(key, "ctx key");
            Objects.requireNonNull(value, "ctx value");
            if (key.isEmpty()) {
                throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "ctx key must not be empty");
            }
            if (raw.containsKey(key)) {
                throw new EnvelopeException(EnvelopeErrorCode.FORMAT, "duplicate ctx key: " + key);
            }
            raw.put(key, value);
            return this;
        }

        public Builder putAll(Map<String, String> map) {
            map.forEach(this::put);
            return this;
        }

        public Ctx build() {
            if (raw.isEmpty()) {
                throw new EnvelopeException(EnvelopeErrorCode.FORMAT,
                        "ctx must have at least one entry; an empty ctx provides no binding");
            }
            List<Map.Entry<String, String>> list = new ArrayList<>(raw.entrySet());
            list.sort((x, y) -> compareUtf8(x.getKey(), y.getKey()));

            Map<String, String> sorted = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : list) {
                sorted.put(e.getKey(), e.getValue());
            }
            Map<String, String> immutable = Collections.unmodifiableMap(sorted);

            Ctx built = new Ctx(immutable);
            checkSize(built.canonicalLength(), list.get(list.size() - 1).getKey());
            return built;
        }
    }
}
