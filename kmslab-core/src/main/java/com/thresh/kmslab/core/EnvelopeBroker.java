package com.thresh.kmslab.core;

import com.thresh.kmslab.envelope.Ctx;
import com.thresh.kmslab.envelope.Envelope;
import com.thresh.kmslab.envelope.EnvelopeCipher;
import com.thresh.kmslab.envelope.EnvelopeException;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;

/**
 * The data plane: authorise, check state, encrypt or decrypt, audit.
 *
 * <p>Order matters. Authorisation runs before any cryptographic work, and the audit entry is
 * written for denied attempts too — a log that only records successes cannot answer "who tried".
 *
 * @author threshbyte
 */
public final class EnvelopeBroker {

    private final KeyService keys;
    private final PolicyEngine policy;
    private final AuditLog audit;
    private final KekRegistry keks;
    private final SecureRandom random = new SecureRandom();

    public EnvelopeBroker(KeyService keys, PolicyEngine policy, AuditLog audit, KekRegistry keks) {
        this.keys = keys;
        this.policy = policy;
        this.audit = audit;
        this.keks = keks;
    }

    /** Encrypts under the key's current version. */
    public String encrypt(Principal actor, UUID keyId, Ctx ctx, byte[] plaintext) {
        ManagedKey key = keys.get(keyId);
        String column = column(ctx);
        Decision d = policy.decide(actor, Action.ENCRYPT, keyId, key.tenant(), column, null);
        if (!d.allowed()) {
            deny(actor, Action.ENCRYPT, keyId, key, ctx, d.reason(), KmsErrorCode.FORBIDDEN);
        }
        if (!key.state().canEncrypt()) {
            deny(actor, Action.ENCRYPT, keyId, key, ctx, "KEY_STATE_" + key.state().name(),
                    KmsErrorCode.INVALID_STATE);
        }
        Envelope cipherText = cipherFor(key).encrypt(ctx, plaintext);
        audit.append(actor.subject(), "ENCRYPT", keyId, (long) key.currentVersion(), "ALLOW", null,
                ctx.hash());
        return cipherText.encode();
    }

    /**
     * Decrypts an envelope. The key is taken from the ciphertext header, never from a caller
     * parameter: trusting a caller-supplied key id would create an implicit lookup path.
     */
    public byte[] decrypt(Principal actor, Purpose purpose, Ctx ctx, String envelopeString) {
        return decrypt(actor, purpose, ctx, envelopeString, null);
    }

    /**
     * Decrypts, but only when the envelope belongs to {@code restrictToKeyId}.
     *
     * <p>This is how a narrowed capability is enforced: the token says "this key only", the
     * envelope header says which key it actually is, and the two must agree. The check lives here
     * rather than in the HTTP layer so a rejected attempt still lands in the audit chain.
     *
     * @param restrictToKeyId null means no constraint
     */
    public byte[] decrypt(Principal actor, Purpose purpose, Ctx ctx, String envelopeString,
                          UUID restrictToKeyId) {
        Envelope envelope;
        try {
            envelope = Envelope.decode(envelopeString);
        } catch (EnvelopeException e) {
            audit.append(actor.subject(), "DECRYPT", null, null, "ERROR", e.code().name(),
                    ctx == null ? null : ctx.hash());
            throw e;
        }
        UUID keyId = envelope.keyId();
        ManagedKey key = keys.get(keyId);
        String column = column(ctx);

        if (restrictToKeyId != null && !restrictToKeyId.equals(keyId)) {
            deny(actor, Action.DECRYPT, keyId, key, ctx, "KEY_NOT_IN_TOKEN", KmsErrorCode.FORBIDDEN);
        }

        Decision d = policy.decide(actor, Action.DECRYPT, keyId, key.tenant(), column, purpose);
        if (!d.allowed()) {
            deny(actor, Action.DECRYPT, keyId, key, ctx, d.reason(), KmsErrorCode.FORBIDDEN);
        }
        if (!key.state().canDecrypt()) {
            deny(actor, Action.DECRYPT, keyId, key, ctx, "KEY_STATE_" + key.state().name(),
                    KmsErrorCode.INVALID_STATE);
        }

        byte[] plaintext = cipherFor(key).decrypt(ctx, envelope);
        audit.append(actor.subject(), "DECRYPT", keyId, envelope.keyVer(),
                "ALLOW", purpose.name(), ctx.hash());
        return plaintext;
    }

    /**
     * Hands out a data key in mode B. Refused unless the key was created with export allowed:
     * exporting key material is a deliberate, per-key decision, not a runtime one.
     */
    public DataKey generateDataKey(Principal actor, UUID keyId, Ctx ctx) {
        ManagedKey key = keys.get(keyId);
        String column = column(ctx);
        Decision d = policy.decide(actor, Action.GENERATE_DATA_KEY, keyId, key.tenant(), column, null);
        if (!d.allowed()) {
            deny(actor, Action.GENERATE_DATA_KEY, keyId, key, ctx, d.reason(), KmsErrorCode.FORBIDDEN);
        }
        if (!key.exportAllowed()) {
            deny(actor, Action.GENERATE_DATA_KEY, keyId, key, ctx, "EXPORT_NOT_ALLOWED",
                    KmsErrorCode.FORBIDDEN);
        }
        if (!key.state().canEncrypt()) {
            deny(actor, Action.GENERATE_DATA_KEY, keyId, key, ctx,
                    "KEY_STATE_" + key.state().name(), KmsErrorCode.INVALID_STATE);
        }
        byte[] dek = new byte[32];
        random.nextBytes(dek);
        Envelope wrapped = cipherFor(key).encrypt(ctx, dek);
        audit.append(actor.subject(), "GENERATE_DATA_KEY", keyId, (long) key.currentVersion(), "ALLOW",
                null, ctx.hash());
        return new DataKey(dek, wrapped);
    }

    private EnvelopeCipher cipherFor(ManagedKey key) {
        return new EnvelopeCipher(keks.wrapper(), key.keyId(), key.currentVersion());
    }

    private void deny(Principal actor, Action action, UUID keyId, ManagedKey key,
                      Ctx ctx, String reason, KmsErrorCode code) {
        audit.append(actor.subject(), action.name(), keyId, (long) key.currentVersion(),
                "DENY", reason, ctx == null ? null : ctx.hash());
        throw new KmsException(code, "denied: " + reason, reason);
    }

    private static String column(Ctx ctx) {
        Map<String, String> map = ctx.asMap();
        return map.get("column");
    }
}
