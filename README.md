# KMSLab

A self-hosted key management service for teams that need to encrypt sensitive database fields and
hold their own keys.

Most "KMS SDKs" in the wild are key *distribution* services: they hand the application a plaintext
data key and let it encrypt locally. That puts the trust boundary at the application process, not
at the key store — a heap dump or a debug port yields every key, and a leaked token decrypts the
whole database. KMSLab takes the other position: keys stay inside the service, ciphertext is
self-describing, and every key use is recorded in a chain anyone can verify.

## What it does

- **Field-level encryption with authenticated ciphertext.** Values are sealed with AES-256-GCM in a
  versioned envelope. The encryption context (tenant, table, column, primary key) is bound into the
  AAD, so a ciphertext copied from one row to another fails to decrypt instead of silently
  revealing someone else's data.
- **Key lifecycle you can operate.** Create, rotate, disable, schedule deletion, cancel, purge.
  Rotation adds a version rather than a new key, so old ciphertext keeps working without a mapping
  table.
- **Authorisation that separates duties.** An ingest service can be granted `ENCRYPT` and nothing
  else: it writes ciphertext it can never read back. Key administration is a different grant from
  data access.
- **Capability tokens that can only narrow.** Short-lived, signed, and attenuable by the holder, so
  a service can hand a downstream a strictly weaker token without calling the issuer.
- **A verifiable audit trail.** Every key operation appends to a hash chain; resume verifies the
  chain before continuing it.
- **Durable state.** One append-only journal, fsync'd before acknowledgement, replayed on restart.

## How it works

Envelope encryption, three layers:

```
KEK  (per tenant x purpose, versioned, wrapped under a storage root key)
 └── DEK  (32 random bytes per encryption)
      └── subkey = HKDF-SHA256(DEK, salt = SHA-256(canonical(ctx)))
```

The ciphertext carries everything needed to route decryption:

```
kms1.<base64url(header)>.<base64url(nonce || ciphertext || tag)>

header = ver | alg | key_id(16B) | key_ver(4B) | wrap | dek_wrap(40B) | ctx_hash(32B)
```

The whole 95-byte header is part of the AAD. Changing the algorithm byte, the key version or the
context breaks decryption rather than downgrading it. The format is specified byte for byte in
[docs/envelope-v1.md](https://github.com/threshbyte/kms/blob/dev/java/docs/envelope-v1.md) and ships with conformance vectors, so an implementation
in another language can interoperate.

## Modules

| Module | Responsibility |
|---|---|
| `kmslab-envelope` | The `kms1` format: AEAD, key derivation, DEK wrapping. Zero runtime dependencies so it can be audited in one sitting. |
| `kmslab-core` | Domain: key lifecycle, policy, audit chain, capability tokens, encryption broker. No framework. |
| `kmslab-server` | HTTP API on the JDK server with virtual threads. |
| `kmslab-sdk-java` | Typed client, integration-tested against a real server. |
| `kmslab-store` | Append-only journal and the KEK vault that keeps key material wrapped at rest. |

## Getting started

Requires JDK 21. The build pins it for you — the system `java` on many machines is older, so use
the wrapper rather than `mvn` directly.

```bash
./build.sh test      # unit and integration tests
./verify.sh          # tests plus the cross-language conformance check
./build.sh package   # build the jars
```

Encrypting a field through the SDK:

```java
try (KmsClient kms = KmsClient.builder("https://kms.internal")
        .token(() -> identity.currentToken())
        .build()) {

    Key key = kms.createKey("user-phone", false);
    UUID keyId = UUID.fromString(key.keyId());

    Map<String, String> ctx = Map.of(
            "tenant", "pay", "table", "user", "column", "phone", "row_pk", "10086");

    String envelope = kms.encrypt(keyId, ctx, phoneBytes);
    byte[] plain   = kms.decrypt(ctx, envelope, Purpose.USER_VIEW);
}
```

The same over HTTP:

```bash
curl -sX POST https://kms.internal/v1/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"keyId":"...","ctx":{"tenant":"pay","table":"user","column":"phone","row_pk":"10086"},
       "plaintextBase64":"MTM4MDAxMzgwMDA="}'
```

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/health` | Liveness, no auth |
| `POST` | `/v1/keys` | Create a key |
| `POST` | `/v1/keys/{id}/rotate` `.../disable` `.../enable` | Lifecycle |
| `POST` | `/v1/keys/{id}/schedule-deletion` `.../cancel-deletion` `.../purge` | Destructive operations, gated |
| `POST` | `/v1/encrypt` | Seal a value |
| `POST` | `/v1/decrypt` | Open a value; requires a purpose |
| `POST` | `/v1/datakeys` | Export a data key (only for keys created for it) |

Errors carry a category and a specific reason:

```json
{"error": {"code": "INVALID_STATE", "reason": "KEY_STATE_DISABLED", "message": "denied: ..."}}
```

## Security model

Honest boundaries, because a key service that overstates itself is worse than none:

- **Key material stays inside the service.** Only keys explicitly created with `exportAllowed` can
  hand out a data key, and that is the mode to avoid for the most sensitive data.
- **The storage root key is yours to protect.** At rest, KEK material is wrapped under a 32-byte
  root key the caller supplies. If that key lives on the same disk as the journal, durability is
  what you gained — not confidentiality.
- **In-memory KEKs are development only.** `SoftKeyWrapper` exists for tests and local runs.
  Production needs a cloud KMS or an HSM as root; the interface is already in place.
- **The audit chain proves the log was not edited.** It does not prove the service never disclosed
  plaintext to an authorised caller — that is what narrow grants and the purpose field are for.

## Documentation

- [docs/envelope-v1.md](https://github.com/threshbyte/kms/blob/dev/java/docs/envelope-v1.md) — the ciphertext format, byte level
- [docs/conventions.md](https://github.com/threshbyte/kms/blob/dev/java/docs/conventions.md) — serialization policy, dependency policy, naming rules

## Status

Usable on a single node: envelope format, key lifecycle, policy, audit chain, capability tokens,
HTTP API, Java SDK and durable storage work end to end. Not done yet: a production root of trust
(cloud KMS or PKCS#11), multi-node replication, and a JDBC/JPA adapter for transparent field
encryption.
