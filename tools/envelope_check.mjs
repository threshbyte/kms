#!/usr/bin/env node
/**
 * Independent implementation of the kms1 envelope format (Node / OpenSSL), used for
 * cross-implementation conformance.
 *
 * It shares no code with the Java implementation, and the cryptographic primitives come from a
 * different library (OpenSSL rather than SunJCE). That is what lets it expose spec ambiguities
 * where "both sides implemented their own reading" of the same sentence.
 *
 * Usage:
 *   node tools/envelope_check.mjs [vectors.json]
 * Exit code: 0 = all checks passed, 1 = at least one failure.
 */
import { createCipheriv, createDecipheriv, createHash, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

const HEADER_LEN = 95;
const DEK_LEN = 32;
const DEK_WRAP_LEN = 40;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const KW_IV = Buffer.alloc(8, 0xa6);
const HKDF_INFO = Buffer.from('kms1/data', 'utf8');

class EnvelopeError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/* ------------------------------------------------------------------ spec §4.2 */

function canonicalCtx(ctx) {
  const entries = Object.entries(ctx).map(([k, v]) => [
    Buffer.from(k, 'utf8'),
    Buffer.from(v, 'utf8'),
  ]);
  if (entries.length === 0) {
    throw new EnvelopeError('FORMAT', 'ctx must have at least one entry');
  }
  // Unsigned lexicographic order of the key's UTF-8 bytes; Buffer.compare is exactly that
  entries.sort((a, b) => Buffer.compare(a[0], b[0]));

  const parts = [];
  for (const [k, v] of entries) {
    const lenK = Buffer.alloc(4);
    lenK.writeUInt32BE(k.length, 0);
    const lenV = Buffer.alloc(4);
    lenV.writeUInt32BE(v.length, 0);
    parts.push(lenK, k, lenV, v);
  }
  return Buffer.concat(parts);
}

/* ------------------------------------------------------------------ spec §9 */

function parseEnvelope(text) {
  if (typeof text !== 'string') {
    throw new EnvelopeError('FORMAT', 'envelope is not a string');
  }
  if (!text.startsWith('kms1.')) {
    throw new EnvelopeError('FORMAT', "missing 'kms1.' prefix");
  }
  const segs = text.slice(5).split('.');
  if (segs.length !== 2) {
    throw new EnvelopeError('FORMAT', `expected 3 segments, got ${segs.length + 1}`);
  }
  for (const [name, seg] of [['header', segs[0]], ['payload', segs[1]]]) {
    if (seg.length === 0) {
      throw new EnvelopeError('FORMAT', `${name} segment is empty`);
    }
    if (!/^[A-Za-z0-9_-]+$/.test(seg)) {
      throw new EnvelopeError('FORMAT', `${name} contains an illegal base64url character`);
    }
  }
  const header = Buffer.from(segs[0], 'base64url');
  const payload = Buffer.from(segs[1], 'base64url');
  if (header.length !== HEADER_LEN) {
    throw new EnvelopeError('FORMAT', `header must be ${HEADER_LEN} bytes, got ${header.length}`);
  }
  if (payload.length < NONCE_LEN + TAG_LEN) {
    throw new EnvelopeError('FORMAT', 'payload too short');
  }
  return { header, payload };
}

function fields(header, payload) {
  const ver = header[0];
  const alg = header[1];
  const keyId = header.subarray(2, 18);
  const keyVer = header.readUInt32BE(18);
  const wrap = header[22];
  const dekWrap = header.subarray(23, 63);
  const ctxHash = header.subarray(63, 95);

  if (ver !== 0x01) {
    throw new EnvelopeError('UNSUPPORTED', `unsupported version 0x${ver.toString(16)}`);
  }
  if (alg !== 0x01) {
    throw new EnvelopeError('UNSUPPORTED', `unsupported alg 0x${alg.toString(16)}`);
  }
  if (wrap !== 0x01) {
    throw new EnvelopeError('UNSUPPORTED', `unsupported wrap 0x${wrap.toString(16)}`);
  }

  return {
    ver,
    alg,
    keyId,
    keyVer,
    wrap,
    dekWrap,
    ctxHash,
    nonce: payload.subarray(0, NONCE_LEN),
    ciphertext: payload.subarray(NONCE_LEN, payload.length - TAG_LEN),
    tag: payload.subarray(payload.length - TAG_LEN),
  };
}

/* ------------------------------------------------------------------ spec §5/§6 */

function deriveSubkey(dek, ctxHash) {
  return Buffer.from(hkdfSync('sha256', dek, ctxHash, HKDF_INFO, 32));
}

function unwrapDek(kek, dekWrap) {
  if (kek.length !== DEK_LEN) {
    throw new EnvelopeError('AUTH', 'KEK must be 32 bytes');
  }
  try {
    const d = createDecipheriv('id-aes256-wrap', kek, KW_IV);
    return Buffer.concat([d.update(dekWrap), d.final()]);
  } catch {
    throw new EnvelopeError('AUTH', 'DEK unwrap failed');
  }
}

function wrapDek(kek, dek) {
  const c = createCipheriv('id-aes256-wrap', kek, KW_IV);
  const out = Buffer.concat([c.update(dek), c.final()]);
  if (out.length !== DEK_WRAP_LEN) {
    throw new Error(`AES-KW produced ${out.length} bytes`);
  }
  return out;
}

/* ------------------------------------------------------------------ spec §7 */

function buildHeader(keyIdHex, keyVer, dekWrap, ctxHash) {
  const h = Buffer.alloc(HEADER_LEN);
  h[0] = 0x01;
  h[1] = 0x01;
  Buffer.from(keyIdHex.replaceAll('-', ''), 'hex').copy(h, 2);
  h.writeUInt32BE(keyVer >>> 0, 18);
  h[22] = 0x01;
  dekWrap.copy(h, 23);
  ctxHash.copy(h, 63);
  return h;
}

function encryptEnvelope({ kek, keyIdHex, keyVer, dek, nonce, ctx, plaintext }) {
  const canonical = canonicalCtx(ctx);
  const ctxHash = createHash('sha256').update(canonical).digest();
  const dekWrap = wrapDek(kek, dek);
  const header = buildHeader(keyIdHex, keyVer, dekWrap, ctxHash);
  const subkey = deriveSubkey(dek, ctxHash);
  const aad = Buffer.concat([header, canonical]);

  const c = createCipheriv('aes-256-gcm', subkey, nonce);
  c.setAAD(aad, { plaintextLength: plaintext.length });
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const tag = c.getAuthTag();
  const payload = Buffer.concat([nonce, ct, tag]);

  return `kms1.${header.toString('base64url')}.${payload.toString('base64url')}`;
}

/* ------------------------------------------------------------------ spec §8 */

function decryptEnvelope(kek, text, ctx) {
  const { header, payload } = parseEnvelope(text);
  const f = fields(header, payload);

  const canonical = canonicalCtx(ctx);
  const ctxHash = createHash('sha256').update(canonical).digest();
  if (!ctxHash.equals(f.ctxHash)) {
    throw new EnvelopeError('CONTEXT_MISMATCH', 'ctx does not match header ctx_hash');
  }

  const dek = unwrapDek(kek, f.dekWrap);
  const subkey = deriveSubkey(dek, ctxHash);
  const aad = Buffer.concat([header, canonical]);

  try {
    const d = createDecipheriv('aes-256-gcm', subkey, f.nonce);
    d.setAAD(aad, { plaintextLength: f.ciphertext.length });
    d.setAuthTag(f.tag);
    return Buffer.concat([d.update(f.ciphertext), d.final()]);
  } catch {
    throw new EnvelopeError('AUTH', 'AEAD authentication failed');
  }
}

/* ------------------------------------------------------------------ conformance */

function hex(b) {
  return b.toString('hex');
}

function run() {
  const path = process.argv[2] ?? 'kmslab-envelope/src/test/resources/vectors/envelope-v1.json';
  const data = JSON.parse(readFileSync(path, 'utf8'));

  if (data.spec !== 'kms1' || data.version !== 1) {
    console.error(`unexpected spec header: ${data.spec} v${data.version}`);
    process.exit(1);
  }

  const failures = [];
  let checks = 0;

  for (const v of data.positive) {
    const kek = Buffer.from(v.kek_hex, 'hex');
    const dek = Buffer.from(v.dek_hex, 'hex');
    const nonce = Buffer.from(v.nonce_hex, 'hex');
    const plaintext = Buffer.from(v.plaintext_hex, 'hex');

    const material = {
      kek,
      keyIdHex: v.key_id,
      keyVer: v.key_ver,
      dek,
      nonce,
      ctx: v.ctx,
      plaintext,
    };

    // (a) Re-encrypting from the primitive inputs must reproduce the envelope byte for byte
    checks++;
    try {
      const rebuilt = encryptEnvelope(material);
      if (rebuilt !== v.envelope) {
        failures.push(`[${v.name}] rebuilt envelope differs\n  java: ${v.envelope}\n  node: ${rebuilt}`);
      }
    } catch (e) {
      failures.push(`[${v.name}] re-encrypt threw: ${e.code ?? ''} ${e.message}`);
    }

    // (b) The committed envelope must decrypt to the expected plaintext
    checks++;
    try {
      const got = decryptEnvelope(kek, v.envelope, v.ctx);
      if (hex(got) !== v.plaintext_hex) {
        failures.push(`[${v.name}] plaintext differs: node=${hex(got)} want=${v.plaintext_hex}`);
      }
    } catch (e) {
      failures.push(`[${v.name}] decrypt threw: ${e.code ?? ''} ${e.message}`);
    }

    // (c) This implementation must also round-trip its own output
    checks++;
    try {
      const rebuilt = encryptEnvelope(material);
      if (hex(decryptEnvelope(kek, rebuilt, v.ctx)) !== v.plaintext_hex) {
        failures.push(`[${v.name}] self round-trip failed`);
      }
    } catch (e) {
      failures.push(`[${v.name}] self round-trip threw: ${e.code ?? ''} ${e.message}`);
    }
  }

  for (const n of data.negative) {
    checks++;
    try {
      decryptEnvelope(Buffer.from(n.kek_hex, 'hex'), n.envelope, n.ctx);
      failures.push(`[${n.name}] expected ${n.expect} but decryption succeeded`);
    } catch (e) {
      if (!(e instanceof EnvelopeError)) {
        failures.push(`[${n.name}] threw a non-spec error: ${e.message}`);
      } else if (e.code !== n.expect) {
        failures.push(`[${n.name}] expected ${n.expect}, got ${e.code} (${e.message})`);
      }
    }
  }

  if (failures.length > 0) {
    console.error(`\nFAILED: ${failures.length}/${checks} checks\n`);
    for (const f of failures) {
      console.error('  ' + f);
    }
    process.exit(1);
  }

  console.log(`PASS kms1 cross-implementation conformance: ${checks} checks`);
  console.log(`  positive vectors: ${data.positive.length} (rebuild + decrypt + self round-trip)`);
  console.log(`  negative vectors: ${data.negative.length} (error code matched one by one)`);
  console.log(`  implementation: Node ${process.version} / OpenSSL, zero shared code with Java/SunJCE`);
}

run();
