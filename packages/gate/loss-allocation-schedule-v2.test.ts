// SPDX-License-Identifier: Apache-2.0
//
// EP-LOSS-ALLOCATION-SCHEDULE-v2 hybrid adoption test: signRiskBodyV2 /
// verifyRiskBodyV2 (EP-RISK-HYBRID-v2) wired in additively via
// signLossAllocationScheduleV2 / verifyLossAllocationScheduleV2. Hostile
// matrix per docs/protocol/pq-hybrid-program.md: stripped leg, narrowed set,
// wrong-length signature, Ed448 masquerade, v1-refuses-v2, valid v2
// roundtrip.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
  LOSS_ALLOCATION_SCHEDULE_V2_VERSION,
  lossAllocationScheduleDigest,
  signLossAllocationSchedule,
  signLossAllocationScheduleV2,
  verifyLossAllocationSchedule,
  verifyLossAllocationScheduleV2,
} from './loss-allocation-schedule.js';
import { riskDigest } from './reliance-risk-crypto.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (character: string) => `sha256:${character.repeat(64)}`;
const NOW = '2026-07-28T13:00:00Z';

function program() {
  return {
    program_id: 'rp.payer.pas-adverse-determination.1',
    version: 1,
    source_digest: D('1'),
    program_digest: D('2'),
  };
}

function schedule() {
  return {
    schedule_id: 'loss-allocation:payer-program-v2',
    relying_party_id: 'payer:example-health-plan',
    program: program(),
    issued_at: '2026-07-28T12:00:00Z',
    valid_from: '2026-07-28T12:00:00Z',
    expires_at: '2026-07-29T12:00:00Z',
    status_target: { type: 'loss-allocation-schedule', usage: 'reliance' },
    rules: [{
      failure_class: 'issuer_artifact_invalid',
      responsible_party_id: 'issuer:allocation-committee',
      allocation: { currency: 'USD', max_amount_minor: '25000000' },
      terms_digest: D('a'),
      dispute_endpoint: null,
    }],
    claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
  };
}

function material() {
  const pair = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(5));
  return {
    signer: {
      issuer_id: 'issuer:allocation-committee',
      key_id: 'loss-allocation-key-v2',
      private_key: pair.privateKey,
      pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
    },
    trusted_keys: {
      'loss-allocation-key-v2': {
        issuer_id: 'issuer:allocation-committee',
        public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
      },
    },
  };
}

async function verifyContext(m: ReturnType<typeof material>, artifact: any) {
  return {
    trusted_keys: m.trusted_keys,
    expected_relying_party_id: 'payer:example-health-plan',
    expected_program: program(),
    status: { outcome: 'current_not_revoked', target_digest: riskDigest(artifact) },
    now: NOW,
  };
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

test('a real hybrid schedule verifies under both pinned keys', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  assert.equal(artifact['@version'], LOSS_ALLOCATION_SCHEDULE_V2_VERSION);
  const verified: any = await verifyLossAllocationScheduleV2(artifact, await verifyContext(m, artifact));
  assert.equal(verified.accepted, true, verified.reason ?? '');
  assert.equal(verified.verified, true);
});

test('the v1 verifier refuses a v2 schedule cleanly on the version marker', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  const verified: any = verifyLossAllocationSchedule(artifact, await verifyContext(m, artifact) as any);
  assert.equal(verified.accepted, false);
});

test('the v1 verifier still accepts a v1 schedule, unchanged', () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const artifact = signLossAllocationSchedule(schedule(), v1Signer);
  const verified: any = verifyLossAllocationSchedule(artifact, {
    trusted_keys: { [v1Signer.key_id]: { issuer_id: v1Signer.issuer_id, public_key: m.trusted_keys[m.signer.key_id].public_key } },
    expected_relying_party_id: 'payer:example-health-plan',
    expected_program: program(),
    status: { outcome: 'current_not_revoked', target_digest: lossAllocationScheduleDigest(artifact) },
    now: NOW,
  });
  assert.equal(verified.accepted, true, verified.reason ?? '');
});

test('the v2 verifier refuses a v1 schedule on the version marker', async () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const artifact = signLossAllocationSchedule(schedule(), v1Signer);
  const verified: any = await verifyLossAllocationScheduleV2(artifact, await verifyContext(m, artifact));
  assert.equal(verified.accepted, false);
});

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'Ed25519') } };
  const verified: any = await verifyLossAllocationScheduleV2(stripped, await verifyContext(m, artifact));
  assert.equal(verified.accepted, false);
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65') } };
  const verified: any = await verifyLossAllocationScheduleV2(stripped, await verifyContext(m, artifact));
  assert.equal(verified.accepted, false);
});

test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  const narrowed = {
    ...artifact,
    proof: {
      ...artifact.proof,
      required_algorithms: ['Ed25519'],
      signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'Ed25519'),
    },
  };
  const verified: any = await verifyLossAllocationScheduleV2(narrowed, await verifyContext(m, artifact));
  assert.equal(verified.accepted, false);
});

test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 signature refuses', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  const tampered = {
    ...artifact,
    proof: {
      ...artifact.proof,
      signatures: artifact.proof.signatures.map((s: any) => (
        s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, -4) } : s
      )),
    },
  };
  const verified: any = await verifyLossAllocationScheduleV2(tampered, await verifyContext(m, artifact));
  assert.equal(verified.accepted, false);
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  const ed448 = generateKeyPairSync('ed448');
  const ctx = await verifyContext(m, artifact);
  const verified: any = await verifyLossAllocationScheduleV2(artifact, {
    ...ctx,
    trusted_keys: {
      [m.signer.key_id]: {
        issuer_id: m.signer.issuer_id,
        public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: m.trusted_keys[m.signer.key_id].pq_public_key,
      },
    },
  });
  assert.equal(verified.accepted, false);
});

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const m = material();
  const artifact: any = await signLossAllocationScheduleV2(schedule(), m.signer);
  const ctx = await verifyContext(m, artifact);
  const verified: any = await verifyLossAllocationScheduleV2(artifact, { ...ctx, mldsaBackendLoader: async () => null } as any);
  assert.equal(verified.accepted, false);
});
