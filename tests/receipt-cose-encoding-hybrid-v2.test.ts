// SPDX-License-Identifier: Apache-2.0
//
// EP-COSE-ENCODING-v0.2 hybrid transport pair: hostile matrix.
//
// Reuses the frozen receipt and key seeds from
// conformance/encoding-equivalence/vectors.json so the classical half is
// directly comparable to the v0.1 suite. The PQ leg runs for real -- this file
// fails loudly if @noble/post-quantum is missing rather than skipping.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  COSE_ALG_EDDSA,
  COSE_ALG_ML_DSA_65,
  COSE_HYBRID_ENCODING_PROFILE,
  COSE_HYBRID_REQUIRED_ALGORITHMS,
  COSE_HEADER_EP_REQUIRED_ALGS,
  coseHybridProtectedHeader,
  buildReceiptCoseHybrid,
  verifyReceiptCoseHybrid,
  verifyReceiptCoseSign1,
  decodeDeterministicCbor8949,
  encodeDeterministicCbor8949,
} from '../packages/verify/src/receipt-cose-encoding.ts';
// The RFC 9964 ML-DSA-65 COSE algorithm identifier is not invented in the
// hybrid profile: it is the same value the McGraw budget adapter already
// verifies foreign COSE_Sign1 objects under. This import IS the trace.
import { MCGRAW_BUDGET_COSE_ALGORITHM } from '../packages/verify/src/aeb-mcgraw-delegation-adapter.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ROOT = path.join(__dirname, '..');
const suite = JSON.parse(
  readFileSync(path.join(ROOT, 'conformance', 'encoding-equivalence', 'vectors.json'), 'utf8'),
);

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const privateKeyFromSeedHex = (seedHex: string) => crypto.createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
  format: 'der',
  type: 'pkcs8',
});

const envelopeKey = privateKeyFromSeedHex(suite.keys.envelope.seed_hex);
const envelopePub = suite.keys.envelope.public_key_spki_b64u as string;
const issuerPub = suite.keys.issuer.public_key_spki_b64u as string;
const receipt = suite.receipt;

const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const KID = 'envelope-key-1';

const BUILD_OPTS = {
  envelopePrivateKey: envelopeKey,
  envelopePqSecretKey: pq.secretKey,
  kid: KID,
};

const VERIFY_OPTS = {
  envelopePublicKeyBase64url: envelopePub,
  envelopePqPublicKeyBase64url: pqPubB64u,
  receiptIssuerPublicKeyBase64url: issuerPub,
  expectedKid: KID,
};

async function buildPair() {
  const built = await buildReceiptCoseHybrid(receipt, BUILD_OPTS);
  expect(built.ok, built.ok ? '' : (built as { reason: string }).reason).toBe(true);
  return (built as { ok: true; value: any }).value;
}

/** Rebuild one half with a caller-chosen protected header map (attacker tooling). */
function reencodeHalf(protectedMap: Map<unknown, unknown>, payload: Uint8Array, signature: Uint8Array) {
  const protectedEncoded = encodeDeterministicCbor8949(protectedMap);
  expect(protectedEncoded.ok).toBe(true);
  const body = encodeDeterministicCbor8949([
    (protectedEncoded as { ok: true; value: Uint8Array }).value, new Map(), payload, signature,
  ]);
  expect(body.ok).toBe(true);
  const bodyBytes = (body as { ok: true; value: Uint8Array }).value;
  const out = new Uint8Array(bodyBytes.length + 1);
  out[0] = 0xd2;
  out.set(bodyBytes, 1);
  return out;
}

function halfParts(cose: Uint8Array) {
  const decoded = decodeDeterministicCbor8949(cose.subarray(1), { textKeysOnly: false });
  expect(decoded.ok).toBe(true);
  const [protectedBytes, , payload, signature] = (decoded as { ok: true; value: any[] }).value;
  return { protectedBytes, payload, signature } as {
    protectedBytes: Uint8Array; payload: Uint8Array; signature: Uint8Array;
  };
}

describe('the ML-DSA-65 COSE algorithm identifier is traced, not invented', () => {
  it('equals the value the McGraw RFC 9964 adapter already verifies under', () => {
    expect(COSE_ALG_ML_DSA_65).toBe(MCGRAW_BUDGET_COSE_ALGORITHM);
    expect(COSE_HYBRID_REQUIRED_ALGORITHMS).toEqual([COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65]);
  });

  it('the real ML-DSA-65 backend is present (this suite never silently skips)', () => {
    expect(pq.publicKey.length).toBe(1952);
    expect(COSE_HYBRID_ENCODING_PROFILE).toBe('EP-COSE-ENCODING-v0.2');
  });
});

describe('EP-COSE-ENCODING-v0.2 happy path', () => {
  it('round-trips a hybrid pair under all three pinned keys', async () => {
    const pair = await buildPair();
    const result = await verifyReceiptCoseHybrid(pair, VERIFY_OPTS);
    expect(result.reason).toBeUndefined();
    expect(result.valid).toBe(true);
    expect(result.checks.envelope_signatures).toBe(true);
    expect(result.checks.receipt_signature).toBe(true);
  });

  it('both halves carry byte-identical payloads and the ML-DSA half is 3309 bytes', async () => {
    const pair = await buildPair();
    const c = halfParts(pair.classical);
    const p = halfParts(pair.pq);
    expect(Buffer.from(c.payload).equals(Buffer.from(p.payload))).toBe(true);
    expect(c.signature.length).toBe(64);
    expect(p.signature.length).toBe(3309);
  });

  it('the required set is a PROTECTED (signed) header in both halves', async () => {
    const pair = await buildPair();
    for (const half of [pair.classical, pair.pq]) {
      const { protectedBytes } = halfParts(half);
      const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
        { ok: true; value: Map<unknown, unknown> }).value;
      expect(headers.get(COSE_HEADER_EP_REQUIRED_ALGS))
        .toEqual([...COSE_HYBRID_REQUIRED_ALGORITHMS]);
    }
  });
});

describe('EP-COSE-ENCODING-v0.2 hostile matrix', () => {
  it('refuses a stripped ML-DSA half', async () => {
    const pair = await buildPair();
    const result = await verifyReceiptCoseHybrid({ classical: pair.classical }, VERIFY_OPTS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('hybrid_pair_incomplete');
  });

  it('refuses the classical half presented as BOTH halves', async () => {
    const pair = await buildPair();
    const result = await verifyReceiptCoseHybrid(
      { classical: pair.classical, pq: pair.classical }, VERIFY_OPTS,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('unsupported_envelope_alg');
  });

  it('refuses a narrowed required_algorithms set, and the surviving signature no longer verifies', async () => {
    const pair = await buildPair();
    const { payload, signature } = halfParts(pair.classical);
    // The attacker rewrites the classical half to claim only Ed25519 is required.
    const narrowed = new Map<unknown, unknown>([
      [1, COSE_ALG_EDDSA],
      [3, 'application/emilia-receipt+json'],
      [4, new TextEncoder().encode(KID)],
      ['ep.caid', pair.caid],
      [COSE_HEADER_EP_REQUIRED_ALGS, [COSE_ALG_EDDSA]],
    ]);
    const forged = reencodeHalf(narrowed, payload, signature);
    const result = await verifyReceiptCoseHybrid({ classical: forged, pq: pair.pq }, VERIFY_OPTS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('algorithm_set_mismatch');
    // And even if the structural check were bypassed, the bytes changed: the
    // original signature does not cover the rewritten protected header.
    const original = halfParts(pair.classical);
    expect(Buffer.from(original.protectedBytes).equals(
      Buffer.from(halfParts(forged).protectedBytes),
    )).toBe(false);
  });

  it('refuses a widened required_algorithms set', async () => {
    const pair = await buildPair();
    const { payload, signature } = halfParts(pair.classical);
    const widened = new Map<unknown, unknown>([
      [1, COSE_ALG_EDDSA],
      [3, 'application/emilia-receipt+json'],
      [4, new TextEncoder().encode(KID)],
      ['ep.caid', pair.caid],
      [COSE_HEADER_EP_REQUIRED_ALGS, [COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65, -50]],
    ]);
    const forged = reencodeHalf(widened, payload, signature);
    const result = await verifyReceiptCoseHybrid({ classical: forged, pq: pair.pq }, VERIFY_OPTS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('algorithm_set_mismatch');
  });

  it('refuses a wrong-length ML-DSA-65 signature', async () => {
    const pair = await buildPair();
    const { protectedBytes, payload } = halfParts(pair.pq);
    const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
      { ok: true; value: Map<unknown, unknown> }).value;
    const forged = reencodeHalf(headers, payload, new Uint8Array(3308));
    const result = await verifyReceiptCoseHybrid({ classical: pair.classical, pq: forged }, VERIFY_OPTS);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed_signature');
  });

  it('refuses a wrong-length Ed25519 signature', async () => {
    const pair = await buildPair();
    const { protectedBytes, payload } = halfParts(pair.classical);
    const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
      { ok: true; value: Map<unknown, unknown> }).value;
    const forged = reencodeHalf(headers, payload, new Uint8Array(63));
    const result = await verifyReceiptCoseHybrid({ classical: forged, pq: pair.pq }, VERIFY_OPTS);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed_signature');
  });

  it('refuses an Ed448 SPKI pinned as the Ed25519 envelope key', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const pair = await buildPair();
    const result = await verifyReceiptCoseHybrid(pair, {
      ...VERIFY_OPTS,
      envelopePublicKeyBase64url: ed448.publicKey
        .export({ format: 'der', type: 'spki' }).toString('base64url'),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed_key');
  });

  it('refuses pq_backend_unavailable rather than passing on the EdDSA half', async () => {
    const pair = await buildPair();
    const result = await verifyReceiptCoseHybrid(pair, {
      ...VERIFY_OPTS,
      agility: { mldsaBackendLoader: () => null },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('pq_backend_unavailable');
  });

  it('refuses a kid that does not match the pin', async () => {
    const pair = await buildPair();
    const result = await verifyReceiptCoseHybrid(pair, { ...VERIFY_OPTS, expectedKid: 'other-kid' });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('kid_mismatch');
  });

  it('never throws on hostile caller input', async () => {
    for (const bad of [null, undefined, 'x', 7, [], { classical: 1, pq: 2 }]) {
      const result = await verifyReceiptCoseHybrid(bad as any, VERIFY_OPTS);
      expect(result.valid).toBe(false);
    }
  });

  it('the protected-header builder refuses a non-registered algorithm set', () => {
    expect(() => coseHybridProtectedHeader(COSE_ALG_EDDSA, KID, 'caid:1:a.b.1:jcs-sha256:x', [COSE_ALG_EDDSA]))
      .toThrow(/registered EP-COSE-ENCODING-v0.2 set/);
  });

  it('the builder refuses rather than emitting a one-legged pair without a PQ backend', async () => {
    const built = await buildReceiptCoseHybrid(receipt, BUILD_OPTS, { mldsaBackendLoader: () => null });
    expect(built.ok).toBe(false);
    expect((built as { reason: string }).reason).toBe('pq_backend_unavailable');
  });
});

describe('the unchanged v0.1 verifier refuses either half of a v0.2 pair', () => {
  it('refuses on the unknown protected label BEFORE any signature check', async () => {
    const pair = await buildPair();
    for (const half of [pair.classical, pair.pq]) {
      const result = verifyReceiptCoseSign1(half, {
        envelopePublicKeyBase64url: envelopePub,
        receiptIssuerPublicKeyBase64url: issuerPub,
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('unexpected_protected_header');
      expect(result.checks.envelope_signature).toBe(false);
    }
  });
});
