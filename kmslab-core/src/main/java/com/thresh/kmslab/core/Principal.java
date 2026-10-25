package com.thresh.kmslab.core;

import java.util.Objects;

/**
 * The authenticated caller.
 *
 * <p>In production this is derived from a workload identity (mTLS/SPIFFE, OIDC) and carried in a
 * short-lived capability token; it must never come from a static token on disk. This record is
 * only the identity, never the authority: authority always comes from {@link PolicyEngine}.
 *
 * @author threshbyte
 */
public record Principal(String subject, String tenant) {

    public Principal {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(tenant, "tenant");
        if (subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
    }
}
