// SPDX-License-Identifier: Apache-2.0
//
// EP-SCITT-STATEMENT-v2 hybrid Signed Statement pair: hostile matrix.
// The PQ leg runs for real; this file fails loudly if @noble/post-quantum is
// missing rather than skipping.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  EP_SCITT_STATEMENT_HYBRID_PROFILE,
  EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS,
  epScittV2ProtectedHeader,
  buildEpScittHybridSignedStatement,
  verifyEpScittSignedStatementHybrid,
  verifyEpScittSignedStatement,
} from '../packages/verify/src/scitt-statement.ts';
import {
  COSE_ALG_EDDSA,
  COSE_ALG_ML_DSA_65,
  COSE_HEADER_EP_REQUIRED_ALGS,
  decodeDeterministicCbor8949,
  encodeDeterministicCbor8949,
} from '../packages/verify/src/receipt-cose-encoding.ts';

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

const statementKey = privateKeyFromSeedHex(suite.keys.envelope.seed_hex);
const statementPub = suite.keys.envelope.public_key_spki_b64u as string;
const issuerPub = suite.keys.issuer.public_key_spki_b64u as string;
const receipt = suite.receipt;

const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const KID = 'scitt-issuer-key-1';
const ISS = 'ep:issuer:test-transparency';

const BUILD_OPTS = {
  statementPrivateKey: statementKey,
  statementPqSecretKey: pq.secretKey,
  kid: KID,
  iss: ISS,
};

const VERIFY_OPTS = {
  statementPublicKeyBase64url: statementPub,
  statementPqPublicKeyBase64url: pqPubB64u,
  receiptIssuerPublicKeyBase64url: issuerPub,
  expectedIss: ISS,
  expectedKid: KID,
};

async function buildPair() {
  const built = await buildEpScittHybridSignedStatement(receipt, BUILD_OPTS);
  expect(built.ok, built.ok ? '' : (built as { reason: string }).reason).toBe(true);
  return (built as { ok: true; value: any }).value;
}

function halfParts(cose: Uint8Array) {
  const decoded = decodeDeterministicCbor8949(cose.subarray(1), { textKeysOnly: false });
  expect(decoded.ok).toBe(true);
  const [protectedBytes, , payload, signature] = (decoded as { ok: true; value: any[] }).value;
  return { protectedBytes, payload, signature } as {
    protectedBytes: Uint8Array; payload: Uint8Array; signature: Uint8Array;
  };
}

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

describe('EP-SCITT-STATEMENT-v2 happy path', () => {
  it('the real ML-DSA-65 backend is present (never a silent skip)', () => {
    expect(pq.publicKey.length).toBe(1952);
    expect(EP_SCITT_STATEMENT_HYBRID_PROFILE).toBe('EP-SCITT-STATEMENT-v2');
    expect(EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS).toEqual([COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65]);
  });

  it('round-trips a hybrid pair, and reports VERIFIED without ever reporting REGISTERED', async () => {
    const pair = await buildPair();
    const result = await verifyEpScittSignedStatementHybrid(pair, VERIFY_OPTS);
    expect(result.reason).toBeUndefined();
    expect(result.valid).toBe(true);
    expect(result.registered).toBe(false);
    expect(result.iss).toBe(ISS);
    expect(result.sub).toBe(pair.sub);
  });

  it('both halves carry the CWT claims, identical payloads, and the signed required set', async () => {
    const pair = await buildPair();
    const c = halfParts(pair.classical);
    const p = halfParts(pair.pq);
    expect(Buffer.from(c.payload).equals(Buffer.from(p.payload))).toBe(true);
    expect(c.signature.length).toBe(64);
    expect(p.signature.length).toBe(3309);
    for (const protectedBytes of [c.protectedBytes, p.protectedBytes]) {
      const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
        { ok: true; value: Map<unknown, unknown> }).value;
      expect(headers.get(COSE_HEADER_EP_REQUIRED_ALGS))
        .toEqual([...EP_SCITT_STATEMENT_V2_REQUIRED_ALGORITHMS]);
      expect(headers.get(15) instanceof Map).toBe(true);
    }
  });
});

describe('EP-SCITT-STATEMENT-v2 hostile matrix', () => {
  it('refuses a stripped ML-DSA half', async () => {
    const pair = await buildPair();
    const result = await verifyEpScittSignedStatementHybrid({ classical: pair.classical }, VERIFY_OPTS);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('hybrid_pair_incomplete');
  });

  it('refuses the classical half presented as both halves', async () => {
    const pair = await buildPair();
    const result = await verifyEpScittSignedStatementHybrid(
      { classical: pair.classical, pq: pair.classical }, VERIFY_OPTS,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('unsupported_statement_alg');
  });

  it('refuses a narrowed required_algorithms set', async () => {
    const pair = await buildPair();
    const { protectedBytes, payload, signature } = halfParts(pair.classical);
    const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
      { ok: true; value: Map<unknown, unknown> }).value;
    headers.set(COSE_HEADER_EP_REQUIRED_ALGS, [COSE_ALG_EDDSA]);
    const forged = reencodeHalf(headers, payload, signature);
    const result = await verifyEpScittSignedStatementHybrid(
      { classical: forged, pq: pair.pq }, VERIFY_OPTS,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('algorithm_set_mismatch');
  });

  it('refuses a widened required_algorithms set', async () => {
    const pair = await buildPair();
    const { protectedBytes, payload, signature } = halfParts(pair.pq);
    const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
      { ok: true; value: Map<unknown, unknown> }).value;
    headers.set(COSE_HEADER_EP_REQUIRED_ALGS, [COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65, -50]);
    const forged = reencodeHalf(headers, payload, signature);
    const result = await verifyEpScittSignedStatementHybrid(
      { classical: pair.classical, pq: forged }, VERIFY_OPTS,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('algorithm_set_mismatch');
  });

  it('refuses a wrong-length ML-DSA-65 signature', async () => {
    const pair = await buildPair();
    const { protectedBytes, payload } = halfParts(pair.pq);
    const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
      { ok: true; value: Map<unknown, unknown> }).value;
    const forged = reencodeHalf(headers, payload, new Uint8Array(3310));
    const result = await verifyEpScittSignedStatementHybrid(
      { classical: pair.classical, pq: forged }, VERIFY_OPTS,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed_signature');
  });

  it('refuses a wrong-length Ed25519 signature', async () => {
    const pair = await buildPair();
    const { protectedBytes, payload } = halfParts(pair.classical);
    const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
      { ok: true; value: Map<unknown, unknown> }).value;
    const forged = reencodeHalf(headers, payload, new Uint8Array(65));
    const result = await verifyEpScittSignedStatementHybrid(
      { classical: forged, pq: pair.pq }, VERIFY_OPTS,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed_signature');
  });

  it('refuses an Ed448 SPKI pinned as the Ed25519 statement key', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const pair = await buildPair();
    const result = await verifyEpScittSignedStatementHybrid(pair, {
      ...VERIFY_OPTS,
      statementPublicKeyBase64url: ed448.publicKey
        .export({ format: 'der', type: 'spki' }).toString('base64url'),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed_key');
  });

  it('refuses pq_backend_unavailable rather than passing on the EdDSA half', async () => {
    const pair = await buildPair();
    const result = await verifyEpScittSignedStatementHybrid(pair, {
      ...VERIFY_OPTS,
      agility: { mldsaBackendLoader: () => null },
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('pq_backend_unavailable');
  });

  it('refuses an iss that does not match the pin', async () => {
    const pair = await buildPair();
    const result = await verifyEpScittSignedStatementHybrid(
      pair, { ...VERIFY_OPTS, expectedIss: 'ep:issuer:other' },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('iss_mismatch');
  });

  it('refuses a sub rewritten away from the payload it must recompute from', async () => {
    const pair = await buildPair();
    const { protectedBytes, payload, signature } = halfParts(pair.classical);
    const headers = (decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false }) as
      { ok: true; value: Map<unknown, unknown> }).value;
    const cwt = headers.get(15) as Map<unknown, unknown>;
    cwt.set(2, `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`);
    const forged = reencodeHalf(headers, payload, signature);
    const result = await verifyEpScittSignedStatementHybrid(
      { classical: forged, pq: pair.pq }, VERIFY_OPTS,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('hybrid_payload_mismatch');
  });

  it('never throws on hostile caller input', async () => {
    for (const bad of [null, undefined, 'x', 7, [], { classical: 1, pq: 2 }]) {
      const result = await verifyEpScittSignedStatementHybrid(bad as any, VERIFY_OPTS);
      expect(result.valid).toBe(false);
      expect(result.registered).toBe(false);
    }
  });

  it('the protected-header builder refuses a non-registered algorithm set', () => {
    expect(() => epScittV2ProtectedHeader(
      COSE_ALG_EDDSA, KID, ISS, 'caid:1:a.b.1:jcs-sha256:x', [COSE_ALG_ML_DSA_65],
    )).toThrow(/registered EP-SCITT-STATEMENT-v2 set/);
  });

  it('the builder refuses rather than emitting a one-legged pair without a PQ backend', async () => {
    const built = await buildEpScittHybridSignedStatement(
      receipt, BUILD_OPTS, { mldsaBackendLoader: () => null },
    );
    expect(built.ok).toBe(false);
    expect((built as { reason: string }).reason).toBe('pq_backend_unavailable');
  });
});

describe('the unchanged v1 verifier refuses either half of a v2 pair', () => {
  it('refuses on the unknown protected label BEFORE any signature check', async () => {
    const pair = await buildPair();
    for (const half of [pair.classical, pair.pq]) {
      const result = verifyEpScittSignedStatement(half, {
        statementPublicKeyBase64url: statementPub,
        receiptIssuerPublicKeyBase64url: issuerPub,
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('unexpected_protected_header');
      expect(result.checks.statement_signature).toBe(false);
      expect(result.registered).toBe(false);
    }
  });
});
