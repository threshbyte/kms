package com.thresh.kmslab.sdk;

/**
 * A data key exported to the caller in envelope (mode B) form.
 *
 * <p>The caller encrypts bulk data locally with {@code plaintextDek}, stores {@code wrappedDek}
 * beside it, and owns wiping the plaintext array. This only works for keys created with
 * {@code exportAllowed}, which is off by default.
 *
 * @author threshbyte
 */
public record ExportedDataKey(byte[] plaintextDek, String wrappedDek) {
}
