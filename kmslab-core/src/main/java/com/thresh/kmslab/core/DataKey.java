package com.thresh.kmslab.core;

import com.thresh.kmslab.envelope.Envelope;

/**
 * A data key handed to the caller in envelope (mode B) form.
 *
 * <p>The caller encrypts bulk data locally with {@code plaintextDek}, stores {@code wrappedDek}
 * alongside it, and never contacts the KMS again while the DEK is cached. That is the performance
 * argument for mode B — and the security cost, which is why it is off by default.
 *
 * @author threshbyte
 * @param plaintextDek the raw 32-byte DEK; the caller owns wiping it
 * @param wrappedDek   the DEK sealed under the key, safe to store next to the data
 */
public record DataKey(byte[] plaintextDek, Envelope wrappedDek) {
}
