// SPDX-License-Identifier: Apache-2.0
//
// EP-GATE-QUALIFICATION-DSSE-HYBRID-v2 is REGISTRATION-GATED. These tests pin
// the gate itself: the named refusal fires on every path including the one
// where both real signatures verify, the structural work still happens so the
// eventual un-gating is a one-line change, and the unchanged v1 pipeline is
// untouched. The PQ leg runs for real.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  GATE_QUALIFICATION_HYBRID_PROFILE,
  GATE_QUALIFICATION_HYBRID_REQUIRED_ALGORITHMS,
  GATE_QUALIFICATION_HYBRID_GATE_REASON,
  verifyHybridDsseEnvelope,
  dsseSigningBytes,
  IN_TOTO_PAYLOAD_TYPE,
  IN_TOTO_STATEMENT_V1,
  TEST_RESULT_PREDICATE,
} from '../packages/verify/src/gate-qualification.ts';
import { canonicalizeStrictJson } from '../packages/verify/src/strict-json.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const STATEMENT = {
  _type: IN_TOTO_STATEMENT_V1,
  predicate: { result: 'PASSED' },
  predicateType: TEST_RESULT_PREDICATE,
  subject: [{ digest: { sha256: 'a'.repeat(64) }, name: 'candidate' }],
};

const payloadText = canonicalizeStrictJson(STATEMENT);
const payloadBytes = Buffer.from(payloadText, 'utf8');
const payloadB64 = payloadBytes.toString('base64');
const pae = dsseSigningBytes(IN_TOTO_PAYLOAD_TYPE, payloadBytes);

const edSig = crypto.sign(null, pae, ed.privateKey).toString('base64');
const pqSig = Buffer.from(ml_dsa65.sign(new Uint8Array(pae), pq.secretKey)).toString('base64');

const TRUST = {
  keys: {
    'ed-1': { alg: 'Ed25519', public_key: edPubB64u },
    'pq-1': { alg: 'ML-DSA-65', public_key: pqPubB64u },
  },
  accepted_keyids: ['ed-1', 'pq-1'],
  threshold: 2,
};

const ENVELOPE = {
  payloadType: IN_TOTO_PAYLOAD_TYPE,
  payload: payloadB64,
  signatures: [
    { keyid: 'ed-1', sig: edSig },
    { keyid: 'pq-1', sig: pqSig },
  ],
};

describe('the registration gate is the deliverable, and it never opens', () => {
  it('refuses alg_registration_pending even when BOTH real signatures verify', async () => {
    const result = await verifyHybridDsseEnvelope(ENVELOPE, IN_TOTO_PAYLOAD_TYPE, TRUST);
    // The structural work happened and both legs really did check out...
    expect(result.checks.structure).toBe(true);
    expect(result.checks.legs_present).toBe(true);
    expect(result.checks.signature_lengths).toBe(true);
    expect(result.checks.signatures_would_verify).toBe(true);
    expect(result.checks.threshold_met).toBe(true);
    // ...and it is STILL refused, because DSSE carries no algorithm identifier
    // and the in-toto Statement has no signed field for the required set.
    expect(result.checks.algorithm_registered).toBe(false);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe(GATE_QUALIFICATION_HYBRID_GATE_REASON);
    expect(result.errors).toContain('alg_registration_pending');
  });

  it('exposes the profile name and the registered set without accepting anything', () => {
    expect(GATE_QUALIFICATION_HYBRID_PROFILE).toBe('EP-GATE-QUALIFICATION-DSSE-HYBRID-v2');
    expect(GATE_QUALIFICATION_HYBRID_REQUIRED_ALGORITHMS).toEqual(['Ed25519', 'ML-DSA-65']);
    expect(GATE_QUALIFICATION_HYBRID_GATE_REASON).toBe('alg_registration_pending');
  });
});

describe('the structural v2 still does its work behind the gate', () => {
  it('reports a stripped ML-DSA leg as missing, never as a pass', async () => {
    const result = await verifyHybridDsseEnvelope(
      { ...ENVELOPE, signatures: [ENVELOPE.signatures[0]] },
      IN_TOTO_PAYLOAD_TYPE,
      TRUST,
    );
    expect(result.checks.legs_present).toBe(false);
    expect(result.errors).toContain('missing_required_algorithm:ML-DSA-65');
    expect(result.accepted).toBe(false);
  });

  it('never narrows the required set to what the envelope presented', async () => {
    // A trust policy naming ONLY an Ed25519 key still requires ML-DSA-65.
    const result = await verifyHybridDsseEnvelope(
      { ...ENVELOPE, signatures: [ENVELOPE.signatures[0]] },
      IN_TOTO_PAYLOAD_TYPE,
      { keys: { 'ed-1': TRUST.keys['ed-1'] }, accepted_keyids: ['ed-1'], threshold: 1 },
    );
    expect(result.checks.algorithm_set).toBe(true);
    expect(result.checks.legs_present).toBe(false);
    expect(result.accepted).toBe(false);
  });

  it('pins the ML-DSA-65 signature length at 3309 bytes', async () => {
    const short = Buffer.from(pqSig, 'base64').subarray(0, 3308).toString('base64');
    const result = await verifyHybridDsseEnvelope(
      { ...ENVELOPE, signatures: [ENVELOPE.signatures[0], { keyid: 'pq-1', sig: short }] },
      IN_TOTO_PAYLOAD_TYPE,
      TRUST,
    );
    expect(result.checks.signature_lengths).toBe(false);
    expect(result.errors).toContain('malformed_signature:ML-DSA-65');
  });

  it('pins the Ed25519 signature length at 64 bytes', async () => {
    const short = Buffer.from(edSig, 'base64').subarray(0, 63).toString('base64');
    const result = await verifyHybridDsseEnvelope(
      { ...ENVELOPE, signatures: [{ keyid: 'ed-1', sig: short }, ENVELOPE.signatures[1]] },
      IN_TOTO_PAYLOAD_TYPE,
      TRUST,
    );
    expect(result.checks.signature_lengths).toBe(false);
    expect(result.errors).toContain('malformed_signature:Ed25519');
  });

  it('refuses an Ed448 key filed under the Ed25519 algorithm tag', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const result = await verifyHybridDsseEnvelope(ENVELOPE, IN_TOTO_PAYLOAD_TYPE, {
      ...TRUST,
      keys: {
        ...TRUST.keys,
        'ed-1': {
          alg: 'Ed25519',
          public_key: ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
        },
      },
    });
    expect(result.checks.signatures_would_verify).toBe(false);
    expect(result.errors.join(' ')).toContain('malformed_key');
  });

  it('refuses a tampered payload', async () => {
    const tamperedText = canonicalizeStrictJson({ ...STATEMENT, predicate: { result: 'FAILED' } });
    const result = await verifyHybridDsseEnvelope(
      { ...ENVELOPE, payload: Buffer.from(tamperedText, 'utf8').toString('base64') },
      IN_TOTO_PAYLOAD_TYPE,
      TRUST,
    );
    expect(result.checks.signatures_would_verify).toBe(false);
    expect(result.accepted).toBe(false);
  });

  it('reports pq_backend_unavailable rather than a pass on the Ed25519 leg', async () => {
    const result = await verifyHybridDsseEnvelope(
      ENVELOPE, IN_TOTO_PAYLOAD_TYPE, TRUST, { mldsaBackendLoader: () => null },
    );
    expect(result.checks.signatures_would_verify).toBe(false);
    expect(result.errors.join(' ')).toContain('pq_backend_unavailable');
    expect(result.accepted).toBe(false);
  });

  it('refuses an unknown keyid rather than inferring an algorithm for it', async () => {
    const result = await verifyHybridDsseEnvelope(
      { ...ENVELOPE, signatures: [{ keyid: 'unknown', sig: edSig }, ENVELOPE.signatures[1]] },
      IN_TOTO_PAYLOAD_TYPE,
      TRUST,
    );
    expect(result.errors).toContain('untrusted_verification_key');
    expect(result.accepted).toBe(false);
  });

  it('never throws on hostile caller input', async () => {
    for (const bad of [null, undefined, 'x', 7, [], { payloadType: 1 }]) {
      const result = await verifyHybridDsseEnvelope(bad, IN_TOTO_PAYLOAD_TYPE, TRUST);
      expect(result.accepted).toBe(false);
      expect(result.reason).toBe(GATE_QUALIFICATION_HYBRID_GATE_REASON);
    }
    for (const badTrust of [null, undefined, {}, { keys: {} }]) {
      const result = await verifyHybridDsseEnvelope(ENVELOPE, IN_TOTO_PAYLOAD_TYPE, badTrust as any);
      expect(result.accepted).toBe(false);
    }
  });
});
