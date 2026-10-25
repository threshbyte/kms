package com.thresh.kmslab.core;

import java.util.UUID;

/**
 * Receives grant changes so authorisation survives a restart.
 *
 * <p>Without persisting grants, a restart would leave every key with no accessor — the keys would
 * exist and nothing could use them. That is why this is a listener and not an afterthought.
 *
 * @author threshbyte
 */
public interface GrantListener {

    /** No-op listener, for callers that do not persist. */
    GrantListener NONE = new GrantListener() {
        @Override
        public void onGrant(Grant grant) {
        }

        @Override
        public void onRevoke(String subject, UUID keyId) {
        }
    };

    void onGrant(Grant grant);

    void onRevoke(String subject, UUID keyId);
}
