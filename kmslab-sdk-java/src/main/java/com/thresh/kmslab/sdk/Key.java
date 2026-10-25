package com.thresh.kmslab.sdk;

/**
 * A key as the server reports it. Plain data: no key material ever appears here.
 *
 * @param deleteAfter ISO-8601 instant while deletion is scheduled, otherwise null
 * @author threshbyte
 */
public record Key(String keyId, String alias, String tenant, String state,
                  int currentVersion, boolean exportAllowed, String deleteAfter) {
}
