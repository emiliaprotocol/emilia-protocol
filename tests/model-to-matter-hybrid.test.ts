// SPDX-License-Identifier: Apache-2.0
//
// EP-MODEL-TO-MATTER-EVIDENCE-v2 / EP-MODEL-TO-MATTER-EFFECT-v2: hostile
// matrix for the hybrid (Ed25519 + ML-DSA-65) evidence and effect artifacts.
// Builds REAL Ed25519 + ML-DSA-65 signed artifacts via the exported
// signModelToMatterEvidenceV2 / signModelToMatterEffectV2, then asserts the
// fail-closed predicate: leg stripping, set narrowing, a wrong-length
// signature, an Ed448 key masquerading as the Ed25519 leg, and a v1
// verifier refusing a v2 artifact (and vice versa). The PQ leg runs for
// real; this suite fails loudly, not silently, if @noble/post-quantum is
// unavailable.
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  M2M_EVIDENCE_VERSION,
  M2M_EVIDENCE_V2_VERSION,
  M2M_EFFECT_VERSION,
  M2M_EFFECT_V2_VERSION,
  M2M_V2_REQUIRED_ALGORITHMS,
  M2M_CLEARANCE_VERSION,
  createModelToMatterAction,
  modelToMatterActionDigest,
  modelToMatterCaid,
  signModelToMatterEvidence,
  signModelToMatterEvidenceV2,
  verifyModelToMatterEvidence,
  verifyModelToMatterEvidenceV2,
  verifyModelToMatterEvidenceAny,
  signModelToMatterEffect,
  signModelToMatterEffectV2,
  verifyModelToMatterEffect,
  verifyModelToMatterEffectV2,
  verifyModelToMatterEffectAny,
} from '../lib/frontier/model-to-matter.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

function digest(label: string): string {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

const ACTION_INPUT = Object.freeze({
  action_type: 'science.bio.experiment.execute.1',
  model: {
    provider: 'example-frontier-lab',
    model_id: 'frontier-bio-model-2026-08',
    manifest_digest: digest('model-manifest'),
    harness_digest: digest('agent-harness'),
    safeguards_digest: digest('deployment-safeguards'),
  },
  experiment: {
    protocol_digest: digest('benign-cfps-protocol'),
    materials_commitment: digest('opaque-benign-materials'),
    expected_effects_digest: digest('approved-effect-criteria'),
  },
  principal: { organization_id: 'org:example-university', principal_id: 'researcher:alice' },
  executor: { executor_id: 'cloud-lab:example', facility_id: 'facility:safe-demo-01' },
  purpose: { code: 'defensive-research', jurisdiction: 'US' },
  destination_digest: digest('approved-destination'),
  requested_at: '2026-08-11T15:58:00Z',
  max_executions: 1,
});
const A = createModelToMatterAction(structuredClone(ACTION_INPUT));

const ed = crypto.generateKeyPairSync('ed25519');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPublicKeyB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretKeyB64u = Buffer.from(pq.secretKey).toString('base64url');
const HYBRID_KEYS = {
  ed25519: ed.privateKey,
  mldsa65: { public_key: pqPublicKeyB64u, private_key: pqSecretKeyB64u, key_id: 'm2m:pq:test' },
};
const PINNED_ISSUER = {
  issuer_id: 'issuer:model_attestation',
  public_key: ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  pq_public_key: pqPublicKeyB64u,
};

function evidenceInput(overrides: Record<string, unknown> = {}) {
  return {
    evidence_type: 'model_attestation',
    action_digest: modelToMatterActionDigest(A),
    issuer_id: 'issuer:model_attestation',
    issued_at: '2026-08-11T15:59:00Z',
    expires_at: '2026-08-11T16:10:00Z',
    claims: {
      provider: A.model.provider,
      model_id: A.model.model_id,
      manifest_digest: A.model.manifest_digest,
      harness_digest: A.model.harness_digest,
      safeguards_digest: A.model.safeguards_digest,
    },
    ...overrides,
  };
}

describe('Model-to-Matter evidence -- hybrid v2', () => {
  it('valid v2 roundtrip: real Ed25519 + ML-DSA-65 signatures verify and the artifact is accepted', async () => {
    const artifact = await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS);
    expect(artifact['@version']).toBe(M2M_EVIDENCE_V2_VERSION);
    expect(artifact.signature.required_algorithms).toEqual([...M2M_V2_REQUIRED_ALGORITHMS]);
    const result = await verifyModelToMatterEvidenceV2(artifact, {
      expectedAction: A,
      as_of: '2026-08-11T16:00:00Z',
      pinnedIssuerKeys: [PINNED_ISSUER],
    });
    expect(result).toMatchObject({ verified: true, accepted: true, reason: null });
  });

  it('routes a v2 artifact to the hybrid verifier via verifyModelToMatterEvidenceAny', async () => {
    const artifact = await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS);
    const opts = { expectedAction: A, as_of: '2026-08-11T16:00:00Z', pinnedIssuerKeys: [PINNED_ISSUER] };
    expect(await verifyModelToMatterEvidenceAny(artifact, opts)).toEqual(await verifyModelToMatterEvidenceV2(artifact, opts));
  });

  it('v1 verifier refuses a v2 artifact on the version marker before inspecting any signature', async () => {
    const artifact = await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS);
    const result = verifyModelToMatterEvidence(artifact, { expectedAction: A, as_of: '2026-08-11T16:00:00Z' });
    expect(result).toMatchObject({ verified: false, reason: 'unsupported_version' });
  });

  it('v2 verifier refuses a v1 artifact on the version marker', async () => {
    const v1 = signModelToMatterEvidence(evidenceInput(), ed.privateKey);
    expect(v1['@version']).toBe(M2M_EVIDENCE_VERSION);
    const result = await verifyModelToMatterEvidenceV2(v1, { expectedAction: A, as_of: '2026-08-11T16:00:00Z' });
    expect(result).toMatchObject({ verified: false, reason: 'unsupported_version' });
  });

  it('stripped leg: dropping the ML-DSA-65 signature refuses', async () => {
    const artifact: any = structuredClone(await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS));
    artifact.signature.signatures = artifact.signature.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
    const result = await verifyModelToMatterEvidenceV2(artifact, { expectedAction: A, as_of: '2026-08-11T16:00:00Z' });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('signature_missing_or_malformed');
  });

  it('narrowed set: an artifact re-labelled with required_algorithms=[Ed25519] fails the digest binding (bytes changed)', async () => {
    const artifact: any = structuredClone(await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS));
    artifact.signature.required_algorithms = ['Ed25519'];
    artifact.signature.signatures = artifact.signature.signatures.filter((s: any) => s.alg === 'Ed25519');
    const result = await verifyModelToMatterEvidenceV2(artifact, { expectedAction: A, as_of: '2026-08-11T16:00:00Z' });
    expect(result.verified).toBe(false);
    expect(['signature_missing_or_malformed', 'digest_mismatch']).toContain(result.reason);
  });

  it('wrong-length signature: a truncated Ed25519 leg refuses as a signature failure, not a crash', async () => {
    const artifact: any = structuredClone(await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS));
    artifact.signature.signatures = artifact.signature.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, 8) } : s
    ));
    const result = await verifyModelToMatterEvidenceV2(artifact, { expectedAction: A, as_of: '2026-08-11T16:00:00Z' });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('signature_invalid');
  });

  it('Ed448-masquerade: an Ed448 public_key presented as the Ed25519 half is refused', async () => {
    const artifact: any = structuredClone(await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS));
    const ed448 = crypto.generateKeyPairSync('ed448');
    artifact.signature.public_key = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const result = await verifyModelToMatterEvidenceV2(artifact, { expectedAction: A, as_of: '2026-08-11T16:00:00Z' });
    expect(result.verified).toBe(false);
    expect(['digest_mismatch', 'key_id_mismatch', 'signature_invalid']).toContain(result.reason);
  });

  it('pinned-issuer acceptance requires BOTH signed public halves to match the pin, not just the classical one', async () => {
    const artifact = await signModelToMatterEvidenceV2(evidenceInput(), HYBRID_KEYS);
    const otherPq = ml_dsa65.keygen(crypto.randomBytes(32));
    const wrongPin = { ...PINNED_ISSUER, pq_public_key: Buffer.from(otherPq.publicKey).toString('base64url') };
    const result = await verifyModelToMatterEvidenceV2(artifact, {
      expectedAction: A, as_of: '2026-08-11T16:00:00Z', pinnedIssuerKeys: [wrongPin],
    });
    expect(result).toMatchObject({ verified: true, accepted: false, reason: 'issuer_key_not_pinned' });
  });
});

function clearanceFor(a: ReturnType<typeof createModelToMatterAction>) {
  return {
    '@version': M2M_CLEARANCE_VERSION,
    verdict: 'clear_to_execute',
    action_digest: modelToMatterActionDigest(a),
    action_caid: modelToMatterCaid(a).caid,
    replay_digest: digest('effect-hybrid-clearance-replay'),
  };
}

describe('Model-to-Matter effect -- hybrid v2', () => {
  it('valid v2 roundtrip: real Ed25519 + ML-DSA-65 signatures verify and the receipt is accepted', async () => {
    const clearance = clearanceFor(A);
    const artifact = await signModelToMatterEffectV2({
      action: A,
      clearance,
      executor_id: A.executor.executor_id,
      executed_at: '2026-08-11T16:01:00Z',
      status: 'completed',
      observed_effect_digest: digest('observed-effect'),
    }, HYBRID_KEYS);
    expect(artifact['@version']).toBe(M2M_EFFECT_V2_VERSION);
    const executorEd25519PublicKey = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const result = await verifyModelToMatterEffectV2(artifact, {
      expectedAction: A,
      expectedClearanceReplayDigest: clearance.replay_digest,
      pinnedExecutorKeys: [{
        executor_id: A.executor.executor_id,
        public_key: executorEd25519PublicKey,
        pq_public_key: pqPublicKeyB64u,
      }],
    });
    expect(result).toMatchObject({ verified: true, accepted: true, reason: null });
  });

  it('routes a v2 effect to the hybrid verifier via verifyModelToMatterEffectAny', async () => {
    const clearance = clearanceFor(A);
    const artifact = await signModelToMatterEffectV2({
      action: A, clearance, executor_id: A.executor.executor_id,
      executed_at: '2026-08-11T16:01:00Z', status: 'completed',
      observed_effect_digest: digest('observed-effect-2'),
    }, HYBRID_KEYS);
    const opts = { expectedAction: A, expectedClearanceReplayDigest: clearance.replay_digest };
    expect(await verifyModelToMatterEffectAny(artifact, opts)).toEqual(await verifyModelToMatterEffectV2(artifact, opts));
  });

  it('v1 verifier refuses a v2 effect on the version marker', async () => {
    const clearance = clearanceFor(A);
    const artifact = await signModelToMatterEffectV2({
      action: A, clearance, executor_id: A.executor.executor_id,
      executed_at: '2026-08-11T16:01:00Z', status: 'completed',
      observed_effect_digest: digest('observed-effect-3'),
    }, HYBRID_KEYS);
    const result = verifyModelToMatterEffect(artifact, { expectedAction: A, expectedClearanceReplayDigest: clearance.replay_digest });
    expect(result).toMatchObject({ verified: false, reason: 'unsupported_version' });
  });

  it('v2 verifier refuses a v1 effect on the version marker', async () => {
    const clearance = clearanceFor(A);
    const v1 = signModelToMatterEffect({
      action: A, clearance, executor_id: A.executor.executor_id,
      executed_at: '2026-08-11T16:01:00Z', status: 'completed',
      observed_effect_digest: digest('observed-effect-4'),
    }, ed.privateKey);
    expect(v1['@version']).toBe(M2M_EFFECT_VERSION);
    const result = await verifyModelToMatterEffectV2(v1, { expectedAction: A, expectedClearanceReplayDigest: clearance.replay_digest });
    expect(result).toMatchObject({ verified: false, reason: 'unsupported_version' });
  });

  it('stripped leg: dropping the Ed25519 signature refuses', async () => {
    const clearance = clearanceFor(A);
    const artifact: any = structuredClone(await signModelToMatterEffectV2({
      action: A, clearance, executor_id: A.executor.executor_id,
      executed_at: '2026-08-11T16:01:00Z', status: 'completed',
      observed_effect_digest: digest('observed-effect-5'),
    }, HYBRID_KEYS));
    artifact.signature.signatures = artifact.signature.signatures.filter((s: any) => s.alg !== 'Ed25519');
    const result = await verifyModelToMatterEffectV2(artifact, { expectedAction: A, expectedClearanceReplayDigest: clearance.replay_digest });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('signature_missing_or_malformed');
  });

  it('wrong-length signature: a truncated ML-DSA-65 leg refuses as a signature failure', async () => {
    const clearance = clearanceFor(A);
    const artifact: any = structuredClone(await signModelToMatterEffectV2({
      action: A, clearance, executor_id: A.executor.executor_id,
      executed_at: '2026-08-11T16:01:00Z', status: 'completed',
      observed_effect_digest: digest('observed-effect-6'),
    }, HYBRID_KEYS));
    artifact.signature.signatures = artifact.signature.signatures.map((s: any) => (
      s.alg === 'ML-DSA-65' ? { ...s, sig: s.sig.slice(0, 20) } : s
    ));
    const result = await verifyModelToMatterEffectV2(artifact, { expectedAction: A, expectedClearanceReplayDigest: clearance.replay_digest });
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('signature_invalid');
  });
});
