package com.thresh.kmslab.core;

import com.thresh.kmslab.envelope.KeyWrapper;
import com.thresh.kmslab.envelope.SoftKeyWrapper;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Development implementation of {@link KekRegistry}: random KEKs in process memory.
 *
 * <p>This is tier C1 and must never run in production. The root material sits in the heap, so a
 * heap dump or a host compromise yields every key.
 *
 * @author threshbyte
 */
public final class InMemoryKekRegistry implements KekRegistry {

    private final SoftKeyWrapper wrapper = new SoftKeyWrapper();
    private final SecureRandom random = new SecureRandom();

    @Override
    public void provision(UUID keyId, int version) {
        byte[] kek = new byte[32];
        random.nextBytes(kek);
        wrapper.put(keyId, version, kek);
        java.util.Arrays.fill(kek, (byte) 0);
    }

    @Override
    public void destroy(UUID keyId, int version) {
        wrapper.remove(keyId, version);
    }

    @Override
    public KeyWrapper wrapper() {
        return wrapper;
    }
}
