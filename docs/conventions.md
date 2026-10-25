# Conventions

Project-wide rules that are cheaper to enforce than to remember. Each one has a reason and, where
possible, a test that fails when it is broken.

## Serialization

**JSON is the default. Kryo is allowed in exactly one lane. Formats that already have a byte-level
specification keep their own encoding.**

Decide in this order, and stop at the first match:

1. **Does the data cross a trust boundary, or must it survive an upgrade?** -> JSON
2. **Does it hold key material, a credential, or a hash that must be reproducible?** -> the
   hand-written canonical encoding already used for that path
3. **Neither** (in-process cache, rebuildable on loss)? -> Kryo

### What "safe" means here

Safety is a property of the *position*, not the library. Three properties decide it, and a format
that fails one of them must not be used there:

| Property | Meaning | Failure mode it prevents |
|---|---|---|
| Schema locked | A parse can only produce types declared in advance | A crafted payload instantiating something unexpected |
| Constructors not bypassed | Validation in the constructor actually runs | A half-built object with violated invariants is used as real data |
| Bytes reproducible | The same value yields the same bytes across versions and languages | A silent format break invalidates stored hashes, tokens or ciphertext |

### Why Kryo is confined to ephemeral, trusted payloads

Kryo's real problem in this codebase is not gadget chains — registration handles those. It is the
second property: Kryo is an object-graph serialiser and will instantiate objects through Objenesis
to bypass constructors when a no-argument path is unavailable. `ManagedKey`, `Grant` and
`Principal` all validate in the constructor. A deserialised instance may therefore violate its own
invariants, and nothing downstream would notice.

That is acceptable for a cache, where a wrong value is discarded and rebuilt. It is not acceptable
for authoritative state.

| Use | Format | Why |
|---|---|---|
| HTTP request and response bodies | **JSON** (Jackson) | Peer is untrusted; unknown fields are rejected |
| Persistence: key metadata, grants, audit records (P2) | **JSON** | Must survive upgrades and stay readable by other tools |
| Audit segments on WORM storage | **JSON** | Must remain verifiable by a party that does not run our code |
| In-process cache: wrapped DEK, key metadata snapshot | **Kryo** | Trusted, rebuildable, never authoritative |
| Internal RPC between our own services | **JSON** | Both ends are ours, and readability is worth more than bytes |
| Ciphertext envelope `kms1.` | **Custom binary** | Published spec with cross-language test vectors |
| Capability token | **Custom (payload + HMAC tag)** | Handed to third parties; the tag must be reproducible |
| Audit entry hash | **Hand-written canonical string** | Any library change would silently invalidate every historical hash |

Note the audit row: an earlier draft allowed Kryo for audit segments. That was wrong. Audit bytes
must remain verifiable long after this code stops being built with this dependency set, so they are
JSON, and the hash is computed from a canonical field join rather than from a serialiser.

### Native Java serialization is banned

`ObjectOutputStream` / `ObjectInputStream` / `Externalizable` are forbidden. A `readObject` on
attacker-influenced bytes is remote code execution waiting for a gadget chain, and the format has
no schema, no version negotiation and no way to constrain what gets instantiated.

`SerializationGuardTest` fails the build if any of them appears in any module.

The `serialVersionUID` fields on our exceptions are not an exception to this: they exist so the
standard library behaves correctly if someone serialises one by accident. We never call
`ObjectOutputStream` ourselves.

### If Kryo is introduced, configure it defensively

It is not a dependency yet: nothing needs it until persistence lands in P2. When it is added:

- `setRegistrationRequired(true)` — no unregistered class may be instantiated.
- `setReferences(false)` unless a graph genuinely needs them; reference tracking is a
  deserialization gadget vector.
- Prefer a custom `InstantiatorStrategy` that calls real constructors over Objenesis, so
  invariants hold even for cache objects.
- Pin the version and treat an upgrade as a format change: round-trip a golden fixture in tests.
- Keep it out of `kmslab-envelope`, which must stay dependency-free.

## Third-party dependencies

- `kmslab-envelope`: **zero** runtime dependencies. It is the format and the crypto; it must be
  auditable in one sitting.
- `kmslab-core`: no runtime dependencies either. It is the domain model.
- `kmslab-server`: JSON only (Jackson). A hand-rolled JSON parser in a security service is a worse
  trade than one well-audited library.

## Naming

No type may reuse a type name from the reference KMS SDK documents. See
`kmslab-envelope/src/test/resources/reference-reserved-names.txt` and `ClassNamingGuardTest`.

## Author

Every type carries `@author threshbyte`.
