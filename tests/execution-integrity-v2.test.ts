// SPDX-License-Identifier: Apache-2.0
//
// EP-EXECUTION-INTEGRITY-v2 hybrid verifier test.
//
// Builds a REAL Ed25519 + ML-DSA-65 signed execution-integrity attestation, then
// asserts the fail-closed predicate: drift binding plus the hybrid hostile
// matrix (leg stripping both ways, set narrowing structural + independent
// crypto.verify, widening, duplicate/relabelled/swapped legs, Ed448 masquerade,
// key substitution, tamper-after-signing), the v1 verifier refusing a v2
// attestation, and a v1 byte-identity regression.
//
// The PQ leg runs for real: this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize, actionHash } from '../packages/issue/index.js';
import {
  bindExecution,
  verifyExecutionIntegrity,
  EXECUTION_INTEGRITY_V2_VERSION,
  EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS,
  buildExecutionIntegrityV2,
  executionV2SignedPayload,
  verifyExecutionIntegrityV2,
} from '../lib/execution/integrity.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const APPROVED_ACTION = {
  action_type: 'payment.release',
  policy_id: 'policy.wires',
  initiator: 'ep:agent:worker',
  target_resource_id: 'wire/8841',
  amount: 2_400_000,
  currency: 'USD',
};
const APPROVED_HASH = actionHash(APPROVED_ACTION);
const DRIFTED_ACTION = { ...APPROVED_ACTION, target_resource_id: 'wire/9999', amount: 4_000_000 };
const RECEIPT = { action_hash: APPROVED_HASH };
const EXECUTOR_ID = 'ep:executor:emilia-primary';

const ed = crypto.generateKeyPairSync('ed25519');
const edSpki = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');

const clone = <T>(v: T): T => structuredClone(v);

async function buildV2(executedAction: any = APPROVED_ACTION) {
  return buildExecutionIntegrityV2({
    approvedActionHash: APPROVED_HASH,
    executedAction,
    executor: { executor_key_id: EXECUTOR_ID, privateKey: ed.privateKey, pqSecretKey: pqSecretB64u, pqPublicKey: pqPubB64u },
  });
}
function pins(att: any) {
  return { executorKeys: { [att.proof.executor_key_id]: { public_key: att.proof.public_key, pq_public_key: att.proof.pq_public_key } } };
}

describe('EP-EXECUTION-INTEGRITY-v2 hybrid', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid attestation verifies under both pinned keys', async () => {
    const att = await buildV2();
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(true);
    expect(res.checks.legs_present).toBe(true);
    expect(res.checks.executor_signature_valid).toBe(true);
    expect(res.checks.executed_hash_matches_approved).toBe(true);
  });

  it('the committed bytes carry the required algorithm set + v2 marker', async () => {
    const att = await buildV2();
    const bytes = canonicalize({
      '@version': EXECUTION_INTEGRITY_V2_VERSION,
      approved_action_hash: att.approved_action_hash,
      binding_status: att.binding_status ?? 'match',
      executed_action: att.executed_action ?? null,
      executed_action_hash: att.executed_action_hash,
      executed_at: att.executed_at ?? null,
      execution_id: att.execution_id ?? null,
      executor_id: att.executor_id ?? att.proof?.executor_key_id ?? null,
      required_algorithms: [...EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS],
    });
    expect(bytes).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
  });

  it('the object-arg calling convention also verifies', async () => {
    const att = await buildV2();
    const res = await verifyExecutionIntegrityV2({ approvedActionHash: APPROVED_HASH, attestation: att }, pins(att));
    expect(res.valid).toBe(true);
  });

  // --- v1 / v2 compatibility --------------------------------------------------

  it('the v1 verifier refuses a v2 attestation on the version marker', async () => {
    const att = await buildV2();
    const res = verifyExecutionIntegrity(att, RECEIPT, pins(att) as any);
    expect(res.valid).toBe(false);
    expect(res.checks.version).toBe(false);
    expect(res.errors.some((e) => /unsupported version: EP-EXECUTION-INTEGRITY-v2/.test(e))).toBe(true);
  });

  it('the v1 verifier still accepts a v1 attestation, unchanged (byte-identity regression)', async () => {
    const v1 = await bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: false,
      signer: {
        executorId: EXECUTOR_ID,
        publicKeyB64u: edSpki,
        sign: (bytes: Buffer) => crypto.sign(null, bytes, ed.privateKey).toString('base64url'),
      },
    });
    const res = verifyExecutionIntegrity(v1, RECEIPT, { executorKeys: { [EXECUTOR_ID]: { public_key: edSpki } } });
    expect(res.valid).toBe(true);
  });

  it('the v2 verifier refuses a v1 attestation on the version marker', async () => {
    const v1 = await bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: false,
      signer: {
        executorId: EXECUTOR_ID,
        publicKeyB64u: edSpki,
        sign: (bytes: Buffer) => crypto.sign(null, bytes, ed.privateKey).toString('base64url'),
      },
    });
    const res = await verifyExecutionIntegrityV2(v1, RECEIPT, { executorKeys: { [EXECUTOR_ID]: { public_key: edSpki, pq_public_key: pqPubB64u } } });
    expect(res.valid).toBe(false);
    expect(res.checks.version).toBe(false);
  });

  // --- drift binding ----------------------------------------------------------

  it('EXECUTION DRIFT: an executed action != approved action_hash refuses', async () => {
    const att = await buildV2(DRIFTED_ACTION);
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.executed_hash_matches_approved).toBe(false);
  });

  // --- anti-stripping ---------------------------------------------------------

  it('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const att = clone(await buildV2());
    att.proof!.signatures = att.proof!.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
    expect(res.checks.executor_signature_valid).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const att = clone(await buildV2());
    att.proof!.signatures = att.proof!.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('SET NARROWING fails BOTH structurally and cryptographically', async () => {
    const att = clone(await buildV2());
    att.proof!.required_algorithms = ['Ed25519'];
    att.proof!.signatures = att.proof!.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);

    const narrowedBytes = Buffer.from(canonicalize({
      '@version': EXECUTION_INTEGRITY_V2_VERSION,
      approved_action_hash: att.approved_action_hash,
      binding_status: att.binding_status ?? 'match',
      executed_action: att.executed_action ?? null,
      executed_action_hash: att.executed_action_hash,
      executed_at: att.executed_at ?? null,
      execution_id: att.execution_id ?? null,
      executor_id: att.executor_id ?? att.proof?.executor_key_id ?? null,
      required_algorithms: ['Ed25519'],
    }), 'utf8');
    const edPub = crypto.createPublicKey({ key: Buffer.from(att.proof!.public_key, 'base64url'), format: 'der', type: 'spki' });
    const survivingSig = Buffer.from(att.proof!.signatures[0].sig, 'base64url');
    expect(crypto.verify(null, narrowedBytes, edPub, survivingSig)).toBe(false);
  });

  it('SET WIDENING: an extra algorithm refuses', async () => {
    const att = clone(await buildV2());
    att.proof!.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
  });

  it('DUPLICATE ALGORITHM refuses', async () => {
    const att = clone(await buildV2());
    att.proof!.signatures = [att.proof!.signatures[0], att.proof!.signatures[0]];
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('ALGORITHM RELABELLING: Ed25519 leg called Ed448 refuses', async () => {
    const att = clone(await buildV2());
    att.proof!.signatures = att.proof!.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.legs_present).toBe(false);
  });

  it('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
    const att = clone(await buildV2());
    const pqLeg = att.proof!.signatures.find((s: any) => s.alg === 'ML-DSA-65');
    att.proof!.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg] as any;
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.executor_signature_valid).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const att = clone(await buildV2());
    att.proof!.public_key = ed448Pub;
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, {
      executorKeys: { [EXECUTOR_ID]: { public_key: ed448Pub, pq_public_key: att.proof!.pq_public_key } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.executor_signature_valid).toBe(false);
  });

  // --- pinning ----------------------------------------------------------------

  it('an unpinned executor confers nothing', async () => {
    const att = await buildV2();
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, { executorKeys: {} });
    expect(res.valid).toBe(false);
    expect(res.checks.executor_key_pinned).toBe(false);
  });

  it('pinning only the Ed25519 half refuses (both halves required)', async () => {
    const att = await buildV2();
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, {
      executorKeys: { [EXECUTOR_ID]: { public_key: att.proof!.public_key, pq_public_key: '' } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.executor_key_pinned).toBe(false);
  });

  it('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const att = await buildV2();
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, {
      executorKeys: { [EXECUTOR_ID]: { public_key: att.proof!.public_key, pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.executor_key_pinned).toBe(false);
  });

  // --- binding ----------------------------------------------------------------

  it('TAMPERED AFTER SIGNING: editing executed_at breaks the binding of BOTH legs', async () => {
    const att = clone(await buildV2());
    att.executed_at = '2030-01-01T00:00:00.000Z';
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.executor_signature_valid).toBe(false);
    expect(res.checks.signature_binds_attestation).toBe(false);
  });

  // --- defensive edge contracts ---------------------------------------------

  it('missing evidence stays fail-closed unless reversibility is independently asserted', async () => {
    const absent = await verifyExecutionIntegrityV2(null, RECEIPT, {});
    expect(absent.valid).toBe(false);
    expect(absent.checks.attestation_present).toBe(false);

    const explicit = await verifyExecutionIntegrityV2(null, RECEIPT, { reversibilityAsserted: true });
    expect(explicit.valid).toBe(true);

    const callback = await verifyExecutionIntegrityV2(null, RECEIPT, { reversibilityAsserted: () => true });
    expect(callback.valid).toBe(true);

    const throwingCallback = await verifyExecutionIntegrityV2(null, RECEIPT, {
      reversibilityAsserted: () => { throw new Error('independent check unavailable'); },
    });
    expect(throwingCallback.valid).toBe(false);
    expect(throwingCallback.checks.attestation_present).toBe(false);
  });

  it('refuses a valid attestation when the receipt supplies no approved action hash', async () => {
    const att = await buildV2();
    const res = await verifyExecutionIntegrityV2(att, {}, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.executed_hash_matches_approved).toBe(false);
  });

  it('refuses missing and malformed hybrid proof structures without throwing', async () => {
    const missing = clone(await buildV2());
    delete missing.proof;
    const missingRes = await verifyExecutionIntegrityV2(missing, RECEIPT, {});
    expect(missingRes.valid).toBe(false);
    expect(missingRes.checks.legs_present).toBe(false);

    const malformed = clone(await buildV2());
    const trusted = pins(malformed);
    malformed.proof!.signatures = [null] as any;
    malformed.proof!.public_key = '';
    malformed.proof!.pq_key_id = 42 as any;
    const malformedRes = await verifyExecutionIntegrityV2(malformed, RECEIPT, trusted);
    expect(malformedRes.valid).toBe(false);
    expect(malformedRes.checks.legs_present).toBe(false);
    expect(malformedRes.checks.executor_key_pinned).toBe(false);
  });

  it('refuses an attestation whose signed field set cannot be canonicalized', async () => {
    const att = clone(await buildV2()) as any;
    const circular: any = {};
    circular.self = circular;
    att.execution_id = circular;
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, pins(att));
    expect(res.valid).toBe(false);
    expect(res.checks.signature_binds_attestation).toBe(false);
    expect(res.checks.executor_signature_valid).toBe(false);
  });

  it('issuer helpers reject incomplete keys and unregistered algorithm sets', async () => {
    await expect(buildExecutionIntegrityV2()).rejects.toThrow(/requires executor/);
    await expect(buildExecutionIntegrityV2({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      executor: {
        executor_key_id: EXECUTOR_ID,
        privateKey: ed.privateKey,
        pqSecretKey: pqSecretB64u,
        pqPublicKey: '!',
      },
    })).rejects.toThrow(/pqPublicKey/);
    expect(() => executionV2SignedPayload({} as any, ['Ed25519'])).toThrow(/algorithm set/);

    const complete = await buildExecutionIntegrityV2({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      executionId: 'execution-42',
      executedAt: '2026-08-02T20:01:00.000Z',
      deterministic: true,
      executor: {
        executor_key_id: EXECUTOR_ID,
        privateKey: ed.privateKey,
        pqSecretKey: pq.secretKey,
        pqPublicKey: pq.publicKey,
      },
    });
    expect(complete.execution_id).toBe('execution-42');
    expect(complete.executed_at).toBe('2026-08-02T20:01:00.000Z');
  });

  // --- fail-closed backend ----------------------------------------------------

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const att = await buildV2();
    const res = await verifyExecutionIntegrityV2(att, RECEIPT, { ...pins(att), mldsaBackendLoader: async () => null });
    expect(res.valid).toBe(false);
    expect(res.checks.executor_signature_valid).toBe(false);
    expect(res.errors.some((e) => /pq_backend_unavailable/.test(e))).toBe(true);
  });

  // --- fail-closed on junk ----------------------------------------------------

  it('malformed input refuses without throwing', async () => {
    for (const junk of ['x', 42, []]) {
      const res = await verifyExecutionIntegrityV2(junk, RECEIPT, pins(await buildV2()));
      expect(res.valid).toBe(false);
    }
  });
});
