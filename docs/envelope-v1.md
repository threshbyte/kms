# kms1 Envelope Format Specification v1

> Status: **normative, with a reference implementation in `kmslab-envelope/`**
> Goal: any language, any crypto library can implement it and interoperate. Every byte is
> defined here; there is no "as the SDK does it".
> Related design: `../KMS-架构设计.md` §5.

---

## 1. Scope

This specification defines a **self-describing ciphertext** (an "envelope"):

- string encoding (directly storable in a `VARCHAR`/`TEXT` column)
- binary header layout
- canonical serialization of the encryption context (`ctx`)
- exact parameters for key derivation, DEK wrapping and the AEAD
- encryption and decryption procedures, and the inputs that must be rejected
- error codes every implementation must agree on

**Out of scope**: how keys are stored, how KEKs rotate, authentication, auditing. Those belong
to the service layer and do not affect wire compatibility.

### 1.1 Three constraints that shape the design

1. **The key travels with the ciphertext, wrapped.** The DEK is wrapped by a KEK and embedded in
   the envelope, so the holder of the KEK can decrypt without calling the KMS.
2. **Context must be bound.** A ciphertext must not decrypt after being moved to another
   column or row.
3. **The format must evolve.** Algorithms must be replaceable (including SM and post-quantum)
   while old ciphertexts stay readable forever.

---

## 2. Overall format

```
kms1.<base64url(header)>.<base64url(payload)>
```

| Item | Requirement |
|---|---|
| Literal prefix | ASCII `kms1` followed by a single ASCII `.` |
| Segment count | Exactly 3, separated by `.` |
| Base64 variant | **URL-safe** (`A-Za-z0-9-_`), **no padding** (`=` forbidden) |
| Whitespace/newlines | Forbidden inside the envelope string |
| Case | Significant |

`header` is exactly **95 bytes** (§3). `payload` is `nonce(12) || ciphertext(L) || tag(16)`,
i.e. `L + 28` bytes.

> **Note**: an early draft said "CBOR fixed-length layout". CBOR adds a type/length header per
> field, which contradicts the 95-byte total. This specification uses **fixed-width
> big-endian byte concatenation**, which is exactly where 95 = 1+1+16+4+1+40+32 comes from.

---

## 3. Header layout (95 bytes, big-endian)

| Offset | Length | Field | Value |
|---:|---:|---|---|
| 0 | 1 | `ver` | `0x01`. Format version |
| 1 | 1 | `alg` | `0x01` = AES-256-GCM. Others reserved, see §3.1 |
| 2 | 16 | `key_id` | KEK identifier. 128-bit network order UUID (RFC 4122: `mostSigBits` first) |
| 18 | 4 | `key_ver` | KEK version, unsigned 32-bit |
| 22 | 1 | `wrap` | `0x01` = AES-256-KW (RFC 3394). Others reserved |
| 23 | 40 | `dek_wrap` | Wrapped DEK, always 40 bytes (32-byte DEK plus 8-byte integrity check value) |
| 63 | 32 | `ctx_hash` | `SHA-256(canonical(ctx))` |

Total: 95 bytes. **Every header byte is part of the AEAD additional data** (§8), so mutating any
of them makes decryption fail. The header therefore needs no separate signature or MAC.

### 3.1 Reserved values

| Field | Value | Meaning | v1 requirement |
|---|---|---|---|
| `ver` | `0x02+` | Future format version | Must reject; must not attempt a v1 parse |
| `alg` | `0x02` | SM4-GCM (reserved) | Reject |
| `alg` | `0x03` | XChaCha20-Poly1305 (reserved) | Reject |
| `wrap` | `0x02` | RSA-OAEP-2048 (reserved, asymmetric KEK) | Reject |
| Other unlisted values | — | Undefined | Reject |

**Unknown values always yield `UNSUPPORTED`; guessing is forbidden.** This is the only defence
against algorithm downgrade.

---

## 4. Encryption context `ctx`

`ctx` is a `string -> string` map that binds a ciphertext to its position in the data.

### 4.1 Reserved keys

The specification does not mandate particular keys, but reserves these names (implementations
may require their presence):

| Key | Meaning | Example |
|---|---|---|
| `tenant` | Tenant or business line | `pay` |
| `table` | Logical table name | `user` |
| `column` | Column or field name | `phone` |
| `row_pk` | Row primary key | `10086` |

**Implementation contract**: at least one entry; keys must not be empty; keys and values are
UTF-8; a value may be empty. Implementations should cap `len(canonical(ctx))` at 4096.

### 4.2 Canonical form — the core of cross-implementation agreement

```
canonical(ctx) = entries sorted ascending by the unsigned UTF-8 byte order of the key,
                 then concatenated as:
                   u32be(len(key_bytes))   || key_bytes
                || u32be(len(value_bytes)) || value_bytes
```

- Ordering is by **unsigned lexicographic order of the key's UTF-8 bytes** — not locale order,
  not `String.compareTo`. Java's UTF-16 comparison disagrees with byte order on
  supplementary-plane characters.
- No separators, no nesting, no type tags. The length prefixes are unambiguous on their own.
- An empty map yields an empty byte string, but §4.1 requires at least one entry, so
  implementations must reject an empty ctx.

**Why length-prefixed TLV rather than JSON**: JSON key order, escaping, number/string
ambiguity and Unicode normalization all let two correct implementations produce different
bytes. A length-prefixed TLV is the only safe choice.

`ctx_hash = SHA-256(canonical(ctx))`.

---

## 5. Key derivation

```
subkey = HKDF-SHA256(IKM  = DEK (32B),
                     salt = ctx_hash (32B),
                     info = UTF-8("kms1/data") (9B),
                     L    = 32)
```

HKDF per RFC 5869:

```
PRK  = HMAC-SHA256(key = salt, msg = IKM)          // 32B
T(1) = HMAC-SHA256(key = PRK,  msg = info || 0x01) // 32B
OKM  = first 32 bytes of T(1)                      // L = 32 <= HashLen, one block
```

**Why derive instead of using the DEK directly**: `salt = ctx_hash` gives every record a
distinct subkey under the same DEK, and the domain separation string `kms1/data` prevents the
key from being reused for signing or wrapping.

---

## 6. DEK wrapping

```
dek_wrap = AES-256-KW(KEK[key_id][key_ver], DEK)
```

- RFC 3394, algorithm identifier `AES256KW`, default IV `A6A6A6A6A6A6A6A6`.
- 32-byte input yields **40 bytes**.
- An unwrap failure (integrity check mismatch) must yield `AUTH` and **must not** return any
  partial result.

> **Why AES-KW rather than "AES-GCM with a fixed nonce" for deterministic wrapping**: GCM fails
> catastrophically when a key/nonce pair is reused (keystream leak plus tag forgery). If the KEK
> version and `ctx_hash` are unchanged — exactly the case when re-encrypting the same row — a
> deterministic encapsulation necessarily reuses `(key, nonce)`. AES-KW is a deterministic mode
> designed for key wrapping, has no nonce, and removes the risk at its root.

---

## 7. Encryption

Inputs: `ctx`, `plaintext`, `KEK(key_id, key_ver)`, and optionally an injected `DEK` and `nonce`
(test use only).

```
1. Validate ctx is non-empty and keys are non-empty
2. ctx_hash  <- SHA-256(canonical(ctx))
3. DEK       <- 32 bytes from a CSPRNG (unless injected)
4. dek_wrap  <- AES-256-KW(KEK, DEK)                            // 40B
5. header    <- ver||alg||key_id||key_ver||wrap||dek_wrap||ctx_hash   // 95B
6. subkey    <- HKDF-SHA256(DEK, ctx_hash, "kms1/data", 32)
7. nonce     <- 12 bytes from a CSPRNG (unless injected)
8. aad       <- header || canonical(ctx)
9. ct||tag   <- AES-256-GCM(subkey, nonce, plaintext, aad)       // tag 16B
10. payload  <- nonce || ct || tag
11. output   <- "kms1." || b64url(header) || "." || b64url(payload)
12. zero DEK and subkey immediately
```

Step 5 depends on the output of step 4: **`dek_wrap` is an input to the header, not a function
of it.** Any design that derives the wrapping key from the header creates a circular dependency.

---

## 8. Decryption

Inputs: envelope string, `ctx`, a KEK resolver.

```
1. Strict parse (§9) -> header, payload          // failure -> FORMAT / UNSUPPORTED
2. ctx_hash' <- SHA-256(canonical(ctx))
3. if header.ctx_hash != ctx_hash'               -> CONTEXT_MISMATCH
4. DEK <- AES-256-KW.unwrap(KEK[key_id][key_ver], dek_wrap)   // failure -> AUTH
5. subkey <- HKDF-SHA256(DEK, ctx_hash, "kms1/data", 32)
6. aad <- header || canonical(ctx)               // recomputed canonical, same as above
7. plaintext <- AES-256-GCM.decrypt(subkey, nonce, ct, tag, aad)  // failure -> AUTH
8. zero DEK and subkey
```

**Error semantics must stay distinct**, but no error message may echo plaintext or key material:

| Situation | Code |
|---|---|
| Structure or encoding invalid | `FORMAT` |
| Unknown version / algorithm / wrap mode | `UNSUPPORTED` |
| `ctx` does not match the header `ctx_hash` | `CONTEXT_MISMATCH` |
| DEK unwrap failed or AEAD tag verification failed | `AUTH` |

> `CONTEXT_MISMATCH` is separate from `AUTH` for diagnosability: "I moved the ciphertext to
> another row" and "the key is wrong" are different incidents. This is not an exploitable
> oracle — neither code reveals anything about the key or the plaintext.

---

## 9. Parser strictness (inputs that must be rejected)

An implementation **must** reject the following and must not attempt repair-and-retry:

| # | Input | Code |
|---|---|---|
| P1 | Does not start with `kms1.` | `FORMAT` |
| P2 | Segment count != 3 | `FORMAT` |
| P3 | Contains `=`, `+`, `/`, whitespace or newline | `FORMAT` |
| P4 | Base64 decoding fails | `FORMAT` |
| P5 | `header` length != 95 | `FORMAT` |
| P6 | `payload` length < 28 | `FORMAT` |
| P7 | `ver != 0x01` | `UNSUPPORTED` |
| P8 | Unknown `alg` / `wrap` | `UNSUPPORTED` |
| P9 | Trailing characters after the payload segment | `FORMAT` |
| P10 | Empty `ctx` | `FORMAT` (may be enforced at the encrypt/decrypt entry rather than during parsing) |

Parsing does **not** verify `ctx_hash` (no `ctx` is available yet); only structure is checked.

---

## 10. Security invariants

Each of these should become a negative test:

| ID | Invariant | Attack blocked |
|---|---|---|
| I1 | Any change to any part of `ctx` breaks decryption | Context forgery |
| I2 | Changing the header (`key_id`/`key_ver`/`alg`, re-encoded) breaks decryption | Algorithm downgrade, key substitution |
| I3 | Moving a ciphertext to another row (`row_pk` differs) breaks decryption | Ciphertext relocation |
| I4 | Encrypting the same plaintext twice yields different ciphertext | Equality probing, frequency analysis |
| I5 | Unknown `ver`/`alg` raises an error rather than downgrading | Downgrade attack |
| I6 | No implicit key lookup: `key_id` must match explicitly | Unauthorized key access |
| I7 | Truncating or appending any byte breaks decryption | Length extension, truncation |
| I8 | A nonce must never repeat under the same `(DEK, ctx)` (implementations must use a CSPRNG) | GCM nonce reuse |

---

## 11. Test vector file

Path: `kmslab-envelope/src/test/resources/vectors/envelope-v1.json`

```json
{
  "spec": "kms1",
  "version": 1,
  "positive": [
    {
      "name": "...",
      "key_id": "...", "key_ver": 1,
      "kek_hex": "...", "dek_hex": "...", "nonce_hex": "...",
      "ctx": { "tenant": "pay", "table": "user", "column": "phone", "row_pk": "10086" },
      "plaintext_utf8": "...",
      "plaintext_hex": "...",
      "envelope": "kms1...."
    }
  ],
  "negative": [
    { "name": "...", "envelope": "kms1....", "ctx": { }, "kek_hex": "...", "expect": "AUTH" }
  ]
}
```

Acceptance criteria: any implementation that reads this file **must** be able to
(a) recompute a **byte-identical** `envelope` from the given `kek/dek/nonce/ctx/plaintext`;
(b) decrypt `envelope` with `kek` and obtain `plaintext_hex`;
(c) make every entry in `negative` fail with its declared code.

---

## 12. Versioning rules

- The `kms1` prefix permanently means this specification. Any breaking change requires `kms2`.
- Adding a new `alg` / `wrap` value is a **compatible extension**: an old implementation simply
  reports `UNSUPPORTED` and can still read old ciphertexts without upgrading.
- Rollout order for a new algorithm: make every reader support it (deploy) **then** enable it on
  writers (config). Never switch writers first, or old readers break immediately.

---

## 13. Deliberate non-goals

| Not done | Reason |
|---|---|
| A separate header signature field | The header is already fully covered by the AAD; a second MAC adds inconsistency risk |
| Plaintext `ctx` embedded in the ciphertext | Leaks field names and primary keys; only `ctx_hash` is stored, the caller supplies `ctx` |
| A short string `kid` | The 8-character id in the reference implementation is exactly the trap: fixed length, collision-prone, not evolvable. Use a UUID plus an explicit version |
| Automatic key discovery | See I6 |
| Plaintext compression | Introduces CRIME-class risk and makes length probeable; `kms1` does not compress |
| A timestamp inside the format | Clocks are untrustworthy and it leaks write time; auditing belongs to the service layer |
