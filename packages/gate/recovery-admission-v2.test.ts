// SPDX-License-Identifier: Apache-2.0
//
// EP-RECOVERY-CAPABILITY-v2 hybrid adoption test: signRiskBodyV2 /
// verifyRiskBodyV2 (EP-RISK-HYBRID-v2) wired in additively via
// signRecoveryCapabilityV2 / verifyRecoveryCapabilityV2. Hostile matrix per
// docs/protocol/pq-hybrid-program.md: stripped leg, narrowed set,
// wrong-length signature, Ed448 masquerade, v1-refuses-v2, valid v2
// roundtrip.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  RECOVERY_CAPABILITY_V2_VERSION,
  signRecoveryCapability,
  signRecoveryCapabilityV2,
  verifyRecoveryCapability,
  verifyRecoveryCapabilityV2,
} from './src/recovery-admission.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (character: string) => `sha256:${character.repeat(64)}`;
const C = (character: string) => `caid:1:operations.recovery.1:jcs-sha256:${character.repeat(43)}`;
const NOW = '2026-08-03T20:00:00.000Z';
const ACTION_EXPIRES = '2026-08-03T20:30:00.000Z';
const CAPABILITY_EXPIRES = '2026-08-03T21:00:00.000Z';

function material() {
  const pair = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(11));
  return {
    signer: {
      issuer_id: 'rp:example-operations',
      key_id: 'key:rp:recovery-capability:v2',
      private_key: pair.privateKey,
      pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
    },
    trusted_keys: {
      'key:rp:recovery-capability:v2': {
        issuer_id: 'rp:example-operations',
        public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
      },
    },
  };
}

function localInput() {
  return {
    capability_id: 'recovery-capability:operation:v2',
    admission_id: 'admission:operation:v2',
    admission_snapshot_digest: D('0'),
    tenant_id: 'tenant:example',
    audience: 'gate:production:01',
    action_caid: C('A'),
    action_digest: D('a'),
    action_capability_expires_at: ACTION_EXPIRES,
    provider_id: 'provider:payments:01',
    account_digest: D('2'),
    environment_digest: D('3'),
    operation_id: 'operation:payment:01',
    issuer_digest: D('4'),
    trust_epoch_digest: D('5'),
    config_epoch_digest: D('6'),
    adapter_id: 'adapter:payments:primary',
    adapter_digest: D('7'),
    resource_set_digest: D('8'),
    issued_at: '2026-08-03T19:55:00.000Z',
    valid_from: NOW,
    expires_at: CAPABILITY_EXPIRES,
    mode: 'LOCAL_ATOMIC' as const,
    recovery: {
      scope: 'INTRA_TRANSACTION_ONLY' as const,
      state_domain_digest: D('b'),
      adapter_id: 'adapter:payments:primary',
      adapter_digest: D('7'),
      max_transaction_ms: 5_000,
    },
  };
}

function verificationContext(m: ReturnType<typeof material>, input = localInput()) {
  return {
    trusted_keys: m.trusted_keys,
    expected_policy: {
      capability_id: input.capability_id,
      admission_id: input.admission_id,
      admission_snapshot_digest: input.admission_snapshot_digest,
      mode: input.mode,
      recovery: structuredClone(input.recovery),
      tenant_id: input.tenant_id,
      audience: input.audience,
      action_caid: input.action_caid,
      action_digest: input.action_digest,
      action_capability_expires_at: input.action_capability_expires_at,
      provider_id: input.provider_id,
      account_digest: input.account_digest,
      environment_digest: input.environment_digest,
      operation_id: input.operation_id,
      issuer_id: m.signer.issuer_id,
      issuer_digest: input.issuer_digest,
      trust_epoch_digest: input.trust_epoch_digest,
      config_epoch_digest: input.config_epoch_digest,
      adapter_id: input.adapter_id,
      adapter_digest: input.adapter_digest,
      resource_set_digest: input.resource_set_digest,
    },
    now: NOW,
  };
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

test('a real hybrid capability verifies under both pinned keys', async () => {
  const m = material();
  const artifact: any = await signRecoveryCapabilityV2(localInput(), m.signer);
  assert.equal(artifact['@version'], RECOVERY_CAPABILITY_V2_VERSION);
  const verified: any = await verifyRecoveryCapabilityV2(artifact, verificationContext(m) as any);
  assert.equal(verified.accepted, true, verified.reason ?? '');
  assert.equal(verified.verified, true);
});

test('the v1 verifier refuses a v2 capability cleanly on the version marker', async () => {
  const m = material();
  const artifact: any = await signRecoveryCapabilityV2(localInput(), m.signer);
  const v1Context = {
    trusted_keys: { [m.signer.key_id]: { issuer_id: m.signer.issuer_id, public_key: m.trusted_keys[m.signer.key_id].public_key } },
    expected_policy: verificationContext(m).expected_policy,
    now: NOW,
  };
  const verified: any = verifyRecoveryCapability(artifact, v1Context as any);
  assert.equal(verified.accepted, false);
});

test('the v1 verifier still accepts a v1 capability, unchanged', () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const artifact = signRecoveryCapability(localInput(), v1Signer);
  const v1Context = {
    trusted_keys: { [m.signer.key_id]: { issuer_id: m.signer.issuer_id, public_key: m.trusted_keys[m.signer.key_id].public_key } },
    expected_policy: verificationContext(m).expected_policy,
    now: NOW,
  };
  const verified: any = verifyRecoveryCapability(artifact, v1Context as any);
  assert.equal(verified.accepted, true, verified.reason ?? '');
});

test('the v2 verifier refuses a v1 capability on the version marker', async () => {
  const m = material();
  const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
  const artifact = signRecoveryCapability(localInput(), v1Signer);
  const verified: any = await verifyRecoveryCapabilityV2(artifact, verificationContext(m) as any);
  assert.equal(verified.accepted, false);
});

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const m = material();
  const artifact: any = await signRecoveryCapabilityV2(localInput(), m.signer);
  const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'Ed25519') } };
  const verified: any = await verifyRecoveryCapabilityV2(stripped, verificationContext(m) as any);
  assert.equal(verified.accepted, false);
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const m = material();
  const artifact: any = await signRecoveryCapabilityV2(localInput(), m.signer);
  const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65') } };
  const verified: any = await verifyRecoveryCapabilityV2(stripped, verificationContext(m) as any);
  assert.equal(verified.accepted, false);
});

test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails', async () => {
  const m = material();
  const artifact: any = await signRecoveryCapabilityV2(localInput(), m.signer);
  const narrowed = {
    ...artifact,
    proof: {
      ...artifact.proof,
      required_algorithms: ['Ed25519'],
      signatures: artifact.proof.signatures.filter((s: any) => s.alg === 'Ed25519'),
    },
  };
  const verified: any = await verifyRecoveryCapabilityV2(narrowed, verificationContext(m) as any);
  assert.equal(verified.accepted, false);
});

test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 signature refuses', async () => {
  const m = material();
  const artifact: any = await signRecoveryCapabilityV2(localInput(), m.signer);
  const tampered = {
    ...artifact,
    proof: {
      ...artifact.proof,
      signatures: artifact.proof.signatures.map((s: any) => (
        s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, -4) } : s
      )),
    },
  };
  const verified: any = await verifyRecoveryCapabilityV2(tampered, verificationContext(m) as any);
  assert.equal(verified.accepted, false);
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
  const m = material();
  const artifact = await signRecoveryCapabilityV2(localInput(), m.signer);
  const ed448 = generateKeyPairSync('ed448');
  const ctx = verificationContext(m);
  const verified: any = await verifyRecoveryCapabilityV2(artifact, {
    ...ctx,
    trusted_keys: {
      [m.signer.key_id]: {
        issuer_id: m.signer.issuer_id,
        public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: m.trusted_keys[m.signer.key_id].pq_public_key,
      },
    },
  } as any);
  assert.equal(verified.accepted, false);
});

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const m = material();
  const artifact = await signRecoveryCapabilityV2(localInput(), m.signer);
  const verified: any = await verifyRecoveryCapabilityV2(artifact, { ...verificationContext(m), mldsaBackendLoader: async () => null } as any);
  assert.equal(verified.accepted, false);
});
