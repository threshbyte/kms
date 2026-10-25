package com.thresh.kmslab.core;

import java.util.Map;

/**
 * Receives key lifecycle events so a store can persist them.
 *
 * <p>Deliberately a listener rather than inheritance: a subclass that forgets to override one
 * operation would lose that event silently, and "silently lost durability" is the worst possible
 * failure mode for a key service.
 *
 * <p>Payloads carry identity and version only. Key material never travels through this interface;
 * the KEK vault persists wrapped material on its own path.
 *
 * @author threshbyte
 */
@FunctionalInterface
public interface KeyEventListener {

    /** No-op listener, for callers that do not persist. */
    KeyEventListener NONE = (type, payload) -> {
    };

    void onKeyEvent(String type, Map<String, Object> payload);
}
