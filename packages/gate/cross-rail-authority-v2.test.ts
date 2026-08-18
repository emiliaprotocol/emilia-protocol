// SPDX-License-Identifier: Apache-2.0
//
// EP-HUMAN-INTERRUPTION-DECISION-v2 and EP-RAIL-ENTRY-PERMIT-v2 hybrid
// adoption test: signRiskBodyV2 / verifyRiskBodyV2 (EP-RISK-HYBRID-v2) wired
// in additively. Hostile matrix per docs/protocol/pq-hybrid-program.md:
// stripped leg, narrowed set, wrong-length signature, Ed448 masquerade,
// v1-refuses-v2, valid v2 roundtrip.
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY,
  HUMAN_INTERRUPTION_DECISION_V2_VERSION,
  RAIL_ENTRY_PERMIT_V2_VERSION,
  signHumanInterruptionDecision,
  signHumanInterruptionDecisionV2,
  signRailEntryPermitV2,
  verifyHumanInterruptionDecision,
  verifyHumanInterruptionDecisionV2,
  verifyRailEntryPermitV2,
} from './src/cross-rail-authority.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (label: string) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const CAID = `caid:1:commerce.payment.1:jcs-sha256:${Buffer.alloc(32, 7).toString('base64url')}`;
const NOW = Date.parse('2026-08-03T18:00:00.000Z');

function material() {
  const pair = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(13));
  return {
    signer: {
      issuer_id: 'customer:security',
      key_id: 'key:authority-v2',
      private_key: pair.privateKey,
      pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
    },
    trusted_keys: {
      'key:authority-v2': {
        issuer_id: 'customer:security',
        public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
      },
    },
  };
}

function decisionInput() {
  return {
    decision_id: 'decision:rail-entry:v2',
    tenant_id: 'tenant:example',
    subject_id: 'agent:finance:01',
    connector_id: 'connector:stripe:01',
    caid: CAID,
    action_digest: D('action'),
    provider_request_digest: D('request'),
    policy_digest: D('policy'),
    configuration_digest: D('configuration'),
    mode: 'standing_policy' as const,
    reason_codes: ['within_standing_policy'],
    issued_at: '2026-08-03T17:59:00.000Z',
    expires_at: '2026-08-03T18:05:00.000Z',
  };
}

function decisionExpected() {
  const i = decisionInput();
  return {
    decision_id: i.decision_id,
    tenant_id: i.tenant_id,
    subject_id: i.subject_id,
    connector_id: i.connector_id,
    caid: i.caid,
    action_digest: i.action_digest,
    provider_request_digest: i.provider_request_digest,
    policy_digest: i.policy_digest,
    configuration_digest: i.configuration_digest,
    mode: i.mode,
    issued_at: i.issued_at,
    expires_at: i.expires_at,
  };
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

// --- EP-HUMAN-INTERRUPTION-DECISION-v2 --------------------------------------

test('a real hybrid interruption decision verifies under both pinned keys', async () => {
  const m = material();
  const artifact: any = await signHumanInterruptionDecisionV2(decisionInput(), m.signer);
  assert.equal(artifact['@version'], HUMAN_INTERRUPTION_DECISION_V2_VERSION);
  const verified: any = await verifyHumanInterruptionDecisionV2(artifact, {
    trusted_keys: m.trusted_keys, now: NOW, expected: decisionExpected(),
  });
  assert.equal(verified.accepted, true, verified.reason ?? '');
});

test('the v1 verifier refuses a v2 decision cleanly on the version marker', async () => {
  const m = material();
  const artifact: any = await signHumanInterruptionDecisionV2(decisionInput(), m.signer);
  const verified: any = verifyHumanInterruptionDecision(artifact, {
    trusted_keys: { [m.signer.key_id]: { issuer_id: m.signer.issuer_id, public_key: m.trusted_keys[m.signer.key_id].public_key } },
    now: NOW,
    expected: decisionExpected(),
  });
  assert.equal(verified.accepted, false);
});

test('the v1 verifier still accepts a v1 decision, unchanged', () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const artifact = signHumanInterruptionDecision(decisionInput(), v1Signer);
  const verified: any = verifyHumanInterruptionDecision(artifact, {
    trusted_keys: { [m.signer.key_id]: { issuer_id: m.signer.issuer_id, public_key: m.trusted_keys[m.signer.key_id].public_key } },
    now: NOW,
    expected: decisionExpected(),
  });
  assert.equal(verified.accepted, true, verified.reason ?? '');
});

test('the v2 verifier refuses a v1 decision on the version marker', async () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const artifact = signHumanInterruptionDecision(decisionInput(), v1Signer);
  const verified: any = await verifyHumanInterruptionDecisionV2(artifact, {
    trusted_keys: m.trusted_keys, now: NOW, expected: decisionExpected(),
  });
  assert.equal(verified.accepted, false);
});

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const m = material();
  const artifact: any = await signHumanInterruptionDecisionV2(decisionInput(), m.signer);
  const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'Ed25519') } };
  const verified: any = await verifyHumanInterruptionDecisionV2(stripped, {
    trusted_keys: m.trusted_keys, now: NOW, expected: decisionExpected(),
  });
  assert.equal(verified.accepted, false);
});

test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails', async () => {
  const m = material();
  const artifact: any = await signHumanInterruptionDecisionV2(decisionInput(), m.signer);
  const narrowed = {
    ...artifact,
    proof: {
      ...artifact.proof,
      required_algorithms: ['Ed25519'],
      signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'Ed25519'),
    },
  };
  const verified: any = await verifyHumanInterruptionDecisionV2(narrowed, {
    trusted_keys: m.trusted_keys, now: NOW, expected: decisionExpected(),
  });
  assert.equal(verified.accepted, false);
});

test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 signature refuses', async () => {
  const m = material();
  const artifact: any = await signHumanInterruptionDecisionV2(decisionInput(), m.signer);
  const tampered = {
    ...artifact,
    proof: {
      ...artifact.proof,
      signatures: artifact.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, -4) } : s)),
    },
  };
  const verified: any = await verifyHumanInterruptionDecisionV2(tampered, {
    trusted_keys: m.trusted_keys, now: NOW, expected: decisionExpected(),
  });
  assert.equal(verified.accepted, false);
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
  const m = material();
  const artifact = await signHumanInterruptionDecisionV2(decisionInput(), m.signer);
  const ed448 = generateKeyPairSync('ed448');
  const verified: any = await verifyHumanInterruptionDecisionV2(artifact, {
    trusted_keys: {
      [m.signer.key_id]: {
        issuer_id: m.signer.issuer_id,
        public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: m.trusted_keys[m.signer.key_id].pq_public_key,
      },
    },
    now: NOW,
    expected: decisionExpected(),
  });
  assert.equal(verified.accepted, false);
});

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const m = material();
  const artifact = await signHumanInterruptionDecisionV2(decisionInput(), m.signer);
  const verified: any = await verifyHumanInterruptionDecisionV2(artifact, {
    trusted_keys: m.trusted_keys, now: NOW, expected: decisionExpected(), mldsaBackendLoader: async () => null,
  } as any);
  assert.equal(verified.accepted, false);
});

// --- EP-RAIL-ENTRY-PERMIT-v2 -------------------------------------------------

function permitBody() {
  return {
    permit_id: 'permit:rail-entry:v2',
    tenant_id: 'tenant:example',
    subject_id: 'agent:finance:01',
    connector_id: 'connector:stripe:01',
    caid: CAID,
    action_digest: D('action'),
    provider_request_digest: D('request'),
    operation_id: 'operation:01',
    authorization_receipt_digest: D('receipt'),
    allowance_digest: D('allowance'),
    interruption_decision_digest: D('decision'),
    human_authorization_digest: null,
    mode: 'standing_policy',
    issued_at: '2026-08-03T17:59:00.000Z',
    expires_at: '2026-08-03T18:05:00.000Z',
    single_use: true,
    claim_boundary: CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.rail_entry_permit,
  };
}

test('a real hybrid rail-entry permit verifies under both pinned keys', async () => {
  const m = material();
  const artifact: any = await signRailEntryPermitV2(permitBody(), m.signer);
  assert.equal(artifact['@version'], RAIL_ENTRY_PERMIT_V2_VERSION);
  const verified: any = await verifyRailEntryPermitV2(artifact, m.trusted_keys);
  assert.equal(verified.valid, true, verified.reason ?? '');
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const m = material();
  const artifact: any = await signRailEntryPermitV2(permitBody(), m.signer);
  const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65') } };
  const verified: any = await verifyRailEntryPermitV2(stripped, m.trusted_keys);
  assert.equal(verified.valid, false);
});

test('SET NARROWING on a rail-entry permit fails both structurally and cryptographically', async () => {
  const m = material();
  const artifact: any = await signRailEntryPermitV2(permitBody(), m.signer);
  const narrowed = {
    ...artifact,
    proof: {
      ...artifact.proof,
      required_algorithms: ['Ed25519'],
      signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'Ed25519'),
    },
  };
  const verified: any = await verifyRailEntryPermitV2(narrowed, m.trusted_keys);
  assert.equal(verified.valid, false);
});

test('ED448 MASQUERADE on a rail-entry permit refuses', async () => {
  const m = material();
  const artifact = await signRailEntryPermitV2(permitBody(), m.signer);
  const ed448 = generateKeyPairSync('ed448');
  const verified: any = await verifyRailEntryPermitV2(artifact, {
    [m.signer.key_id]: {
      issuer_id: m.signer.issuer_id,
      public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      pq_public_key: m.trusted_keys[m.signer.key_id].pq_public_key,
    },
  });
  assert.equal(verified.valid, false);
});

test('NO ML-DSA BACKEND on a rail-entry permit is a refusal, never a pass', async () => {
  const m = material();
  const artifact = await signRailEntryPermitV2(permitBody(), m.signer);
  const verified: any = await verifyRailEntryPermitV2(artifact, m.trusted_keys, { mldsaBackendLoader: async () => null });
  assert.equal(verified.valid, false);
});
