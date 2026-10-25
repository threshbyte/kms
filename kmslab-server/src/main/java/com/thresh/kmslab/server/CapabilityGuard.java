package com.thresh.kmslab.server;

import com.thresh.kmslab.core.Action;
import com.thresh.kmslab.core.Purpose;
import com.thresh.kmslab.core.TokenAuthority;

import java.util.UUID;

/**
 * Applies the coarse constraints carried inside the token, before the fine-grained
 * {@link com.thresh.kmslab.core.PolicyEngine} runs.
 *
 * <p>Both layers are needed. The token narrows what a caller may attempt at all and can be handed
 * downstream already narrowed; the policy engine decides what that identity is actually entitled
 * to on this key. Neither alone is sufficient: policy cannot express "this delegated token", and a
 * token cannot express per-key grants granted after issuance.
 *
 * @author threshbyte
 */
final class CapabilityGuard {

    private CapabilityGuard() {
    }

    static void check(TokenAuthority.VerifiedIdentity id, Action action, UUID keyId,
                      String column, Purpose purpose) {
        if (!allowed(id, "action", action.name())) {
            throw new ApiException(403, "ACTION_NOT_IN_TOKEN",
                    "token does not carry action " + action.name());
        }
        if (keyId != null && !allowed(id, "key", keyId.toString())) {
            throw new ApiException(403, "KEY_NOT_IN_TOKEN",
                    "token does not carry this key");
        }
        if (!allowed(id, "column", column)) {
            throw new ApiException(403, "COLUMN_NOT_IN_TOKEN",
                    "token does not carry this column");
        }
        if (purpose != null && !allowed(id, "purpose", purpose.name())) {
            throw new ApiException(403, "PURPOSE_NOT_IN_TOKEN",
                    "token does not carry purpose " + purpose.name());
        }
    }

    /**
     * The single key id this token is narrowed to, or null when unrestricted.
     *
     * @throws ApiException when the token carries several key caveats: a token that names two keys
     *                      is ambiguous, and guessing which one was meant is not acceptable
     */
    static UUID restrictedKey(TokenAuthority.VerifiedIdentity id) {
        var values = id.caveat("key");
        if (values.isEmpty()) {
            return null;
        }
        if (values.size() > 1) {
            throw new ApiException(403, "AMBIGUOUS_TOKEN",
                    "token carries more than one key caveat");
        }
        try {
            return UUID.fromString(values.get(0));
        } catch (IllegalArgumentException e) {
            throw new ApiException(403, "MALFORMED_TOKEN", "token key caveat is not a UUID");
        }
    }

    /**
     * A caveat name that is absent imposes no restriction. When present, the value must match.
     * A present caveat plus a null request value is a mismatch, never a free pass.
     */
    private static boolean allowed(TokenAuthority.VerifiedIdentity id, String name, String value) {
        if (!id.hasCaveat(name)) {
            return true;
        }
        return value != null && id.caveat(name).contains(value);
    }
}
