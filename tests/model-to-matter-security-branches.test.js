// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../packages/verify/index.js';
import {
  M2M_CLEARANCE_VERSION,
  M2M_EFFECT_VERSION,
  M2M_EVIDENCE_TYPES,
  M2M_EVIDENCE_VERSION,
  buildModelToMatterGraph,
  createModelToMatterAction,
  createModelToMatterProfile,
  createRegisteredModelToMatterChallenge,
  evaluateRegisteredModelToMatterPresentation,
  modelToMatterActionDigest,
  signModelToMatterEffect,
  signModelToMatterEvidence,
  verifyModelToMatterEffect,
  verifyModelToMatterEvidence,
} from '../lib/frontier/model-to-matter.js';
import { artifactDigest } from '../lib/evidence/evidence-graph.js';
import { createDurableChallengeStore } from '../packages/gate/challenge-store.js';
import { createDurableConsumptionStore, createMemoryBackend } from '../packages/gate/store.js';

const NOW = '2026-07-11T16:00:00Z';
const ISSUED_AT = '2026-07-11T15:59:00Z';
const EXPIRES_AT = '2026-07-11T16:10:00Z';
const CHALLENGE_EXPIRES = '2026-07-11T16:05:00Z';
const evidenceKey = crypto.generateKeyPairSync('ed25519').privateKey;
const executorKey = crypto.generateKeyPairSync('ed25519').privateKey;

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function digest(label) {
  return `sha256:${sha256(label)}`;
}

function publicKey(privateKey) {
  return crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
}

function keyId(publicKeyB64u) {
  return `ep:m2m:key:sha256:${sha256(Buffer.from(publicKeyB64u, 'base64url')).slice(0, 16)}`;
}

function rawSigned(body, privateKey, domain, digestField) {
  const bytes = Buffer.from(domain + canonicalize(body), 'utf8');
  const publicKeyB64u = publicKey(privateKey);
  return {
    ...structuredClone(body),
    signature: {
      algorithm: 'Ed25519',
      key_id: keyId(publicKeyB64u),
      public_key: publicKeyB64u,
      [digestField]: `sha256:${sha256(bytes)}`,
      signature_b64u: crypto.sign(null, bytes, privateKey).toString('base64url'),
    },
  };
}

const ACTION_INPUT = {
  action_type: 'science.bio.experiment.execute',
  model: {
    provider: 'example-frontier-lab',
    model_id: 'frontier-bio-model-2026-07',
    manifest_digest: digest('model-manifest'),
    harness_digest: digest('agent-harness'),
    safeguards_digest: digest('deployment-safeguards'),
  },
  experiment: {
    protocol_digest: digest('benign-cfps-protocol'),
    materials_commitment: digest('opaque-benign-materials'),
    expected_effects_digest: digest('approved-effect-criteria'),
  },
  principal: {
    organization_id: 'org:example-university',
    principal_id: 'researcher:alice',
  },
  executor: {
    executor_id: 'cloud-lab:example',
    facility_id: 'facility:safe-demo-01',
  },
  purpose: {
    code: 'defensive-research',
    jurisdiction: 'US',
  },
  destination_digest: digest('approved-destination'),
  requested_at: '2026-07-11T15:58:00Z',
  max_executions: 1,
};

function action(overrides = {}) {
  return createModelToMatterAction({
    ...structuredClone(ACTION_INPUT),
    ...structuredClone(overrides),
  });
}

const acceptedIssuers = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, [{
  issuer_id: `issuer:${type}`,
  public_key: publicKey(evidenceKey),
}]]));

function profile(overrides = {}) {
  return createModelToMatterProfile({
    profile_id: 'ep:m2m:security-branches:v1',
    accepted_issuers: acceptedIssuers,
    ...structuredClone(overrides),
  });
}

function claimsFor(type, a) {
  const claims = {
    model_attestation: {
      provider: a.model.provider,
      model_id: a.model.model_id,
      manifest_digest: a.model.manifest_digest,
      harness_digest: a.model.harness_digest,
      safeguards_digest: a.model.safeguards_digest,
    },
    safety_case_attestation: {
      manifest_digest: a.model.manifest_digest,
      harness_digest: a.model.harness_digest,
      safeguards_digest: a.model.safeguards_digest,
      safety_case_digest: digest('safety-case'),
      assessment: 'acceptable',
    },
    institutional_authority: {
      organization_id: a.principal.organization_id,
      principal_id: a.principal.principal_id,
      action_type: a.action_type,
      purpose_code: a.purpose.code,
      decision: 'allow',
    },
    biosafety_review: {
      protocol_digest: a.experiment.protocol_digest,
      materials_commitment: a.experiment.materials_commitment,
      facility_id: a.executor.facility_id,
      decision: 'approve',
    },
    domain_screening: {
      materials_commitment: a.experiment.materials_commitment,
      destination_digest: a.destination_digest,
      screening_profile_digest: digest('screening-profile'),
      decision: 'pass',
    },
    human_authorization: {
      approver_id: 'person:responsible-investigator',
      decision: 'approve',
      assurance_class: 'class_a',
    },
  };
  return structuredClone(claims[type]);
}

function signedEvidence(a, type, overrides = {}) {
  return signModelToMatterEvidence({
    evidence_type: type,
    action_digest: modelToMatterActionDigest(a),
    issuer_id: `issuer:${type}`,
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    claims: { ...claimsFor(type, a), ...(overrides.claims || {}) },
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => key !== 'claims')),
  }, evidenceKey);
}

function evidenceSet(a) {
  return M2M_EVIDENCE_TYPES.map((type) => signedEvidence(a, type));
}

function challengeStore(backend = createMemoryBackend()) {
  return createDurableChallengeStore(backend);
}

function clearanceStore(backend = createMemoryBackend()) {
  return createDurableConsumptionStore(backend);
}

async function registered(a, p, nonce) {
  const store = challengeStore();
  const challenge = await createRegisteredModelToMatterChallenge(a, p, {
    challengeStore: store,
    expires_at: CHALLENGE_EXPIRES,
    nonce,
  });
  return { challenge, store };
}

function evidenceOptions(a, type, overrides = {}) {
  return {
    expectedType: type,
    expectedAction: a,
    as_of: NOW,
    pinnedIssuerKeys: acceptedIssuers[type],
    ...overrides,
  };
}

function validClearance(a) {
  return {
    '@version': M2M_CLEARANCE_VERSION,
    verdict: 'clear_to_execute',
    action_digest: modelToMatterActionDigest(a),
    replay_digest: digest('clearance-replay'),
  };
}

function effectBody(a, overrides = {}) {
  return {
    '@version': M2M_EFFECT_VERSION,
    action_digest: modelToMatterActionDigest(a),
    clearance_replay_digest: digest('clearance-replay'),
    executor_id: a.executor.executor_id,
    executed_at: '2026-07-11T16:01:00Z',
    status: 'completed',
    observed_effect_digest: digest('observed-effect'),
    ...overrides,
  };
}

function effectOptions(a, overrides = {}) {
  return {
    expectedAction: a,
    expectedClearanceReplayDigest: digest('clearance-replay'),
    pinnedExecutorKeys: [{ executor_id: a.executor.executor_id, public_key: publicKey(executorKey) }],
    ...overrides,
  };
}

describe('Model-to-Matter defensive branch contract', () => {
  it('rejects malformed action containers, nested values, and strict timestamp edge cases', () => {
    expect(() => createModelToMatterAction(null)).toThrow(/object/i);
    expect(() => action({ action_type: 'science.experiment.execute' })).toThrow(/unsupported action_type/i);
    expect(() => action({ model: null })).toThrow(/model must be an object/i);
    expect(() => action({ principal: { ...ACTION_INPUT.principal, principal_id: ' ' } })).toThrow(/non-empty/i);
    expect(() => action({ requested_at: null })).toThrow(/RFC 3339/i);
    expect(() => action({ requested_at: 'not-an-instant' })).toThrow(/RFC 3339/i);
    expect(() => action({ requested_at: '2026-07-11T15:58:00+24:00' })).toThrow(/RFC 3339/i);
    expect(() => action({ requested_at: '2026-07-11T15:58:00+00:60' })).toThrow(/RFC 3339/i);
    expect(() => action({ experiment: [{ sequence: 'forbidden' }] })).toThrow(/commitments and digests/i);

    expect(action({ requested_at: '2026-07-11T08:58:00-07:00' }).requested_at)
      .toBe('2026-07-11T08:58:00-07:00');
  });

  it('rejects malformed profiles, issuer pins, freshness, and incomplete revocation policy', async () => {
    expect(() => createModelToMatterProfile(null)).toThrow(/object/i);
    expect(() => profile({ allowed_action_types: [] })).toThrow(/allowed_action_types/i);
    expect(() => profile({ freshness_sec: { domain_screening: -1 } })).toThrow(/freshness/i);
    expect(() => profile({ revocation_required: M2M_EVIDENCE_TYPES.slice(1) })).toThrow(/revocation/i);

    const nullPin = structuredClone(acceptedIssuers);
    nullPin.domain_screening = [null];
    expect(() => profile({ accepted_issuers: nullPin })).toThrow(/pin must be an object/i);

    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const wrongKeyPins = structuredClone(acceptedIssuers);
    wrongKeyPins.domain_screening = [{
      issuer_id: 'issuer:domain_screening',
      public_key: publicKey(rsa),
    }];
    expect(() => profile({ accepted_issuers: wrongKeyPins })).toThrow(/Ed25519 SPKI/i);

    for (const [label, mutate] of [
      ['policy id', (candidate) => { candidate.policy_id = 'other-policy'; }],
      ['purpose', (candidate) => { candidate.reliance_purpose = 'other-purpose'; }],
      ['requirement', (candidate) => { candidate.requirement = 'human_authorization'; }],
      ['issuer map', (candidate) => { candidate.accepted_issuers.extra = []; }],
    ]) {
      const candidate = structuredClone(profile());
      mutate(candidate);
      await expect(createRegisteredModelToMatterChallenge(action(), candidate, {
        challengeStore: challengeStore(),
        expires_at: CHALLENGE_EXPIRES,
      }), label).rejects.toThrow();
    }
  });

  it('rejects malformed evidence inputs, outcomes, claims, and signing keys', () => {
    const a = action();
    expect(() => signModelToMatterEvidence(null, evidenceKey)).toThrow(/object/i);
    expect(() => signModelToMatterEvidence({
      evidence_type: 'unknown',
      action_digest: modelToMatterActionDigest(a),
      issuer_id: 'issuer:unknown',
      issued_at: ISSUED_AT,
      expires_at: EXPIRES_AT,
      claims: {},
    }, evidenceKey)).toThrow(/unsupported evidence_type/i);
    expect(() => signModelToMatterEvidence({
      evidence_type: 'domain_screening',
      action_digest: modelToMatterActionDigest(a),
      issuer_id: 'issuer:domain_screening',
      issued_at: ISSUED_AT,
      expires_at: EXPIRES_AT,
      claims: null,
    }, evidenceKey)).toThrow(/claims must be an object/i);
    expect(() => signedEvidence(a, 'domain_screening', { outcome: 'maybe' })).toThrow(/outcome/i);

    const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    expect(() => signModelToMatterEvidence({
      evidence_type: 'domain_screening',
      action_digest: modelToMatterActionDigest(a),
      issuer_id: 'issuer:domain_screening',
      issued_at: ISSUED_AT,
      expires_at: EXPIRES_AT,
      claims: claimsFor('domain_screening', a),
    }, p256)).toThrow(/Ed25519/i);
  });

  it('separates malformed cryptographic envelopes from malformed signed semantics', () => {
    const a = action();
    const artifact = signedEvidence(a, 'domain_screening');
    const opts = evidenceOptions(a, 'domain_screening');

    expect(verifyModelToMatterEvidence(null, opts).reason).toBe('unsupported_version');
    expect(verifyModelToMatterEvidence({ ...artifact, signature: undefined }, opts).reason)
      .toBe('signature_missing_or_malformed');
    expect(verifyModelToMatterEvidence({
      ...artifact,
      signature: { ...artifact.signature, evidence_digest: digest('wrong-body') },
    }, opts).reason).toBe('digest_mismatch');
    expect(verifyModelToMatterEvidence({
      ...artifact,
      signature: { ...artifact.signature, key_id: 'wrong-key-id' },
    }, opts).reason).toBe('key_id_mismatch');
    expect(verifyModelToMatterEvidence({
      ...artifact,
      signature: { ...artifact.signature, signature_b64u: 'AA' },
    }, opts).reason).toBe('signature_invalid');

    const invalidPublicKey = 'not-an-spki';
    expect(verifyModelToMatterEvidence({
      ...artifact,
      signature: {
        ...artifact.signature,
        public_key: invalidPublicKey,
        key_id: keyId(invalidPublicKey),
      },
    }, opts).reason).toBe('signature_invalid');

    const malformedBody = rawSigned({
      ...Object.fromEntries(Object.entries(artifact).filter(([key]) => key !== 'signature')),
      claims: { ...artifact.claims, ignored_decision: 'allow' },
    }, evidenceKey, `${M2M_EVIDENCE_VERSION}\0`, 'evidence_digest');
    expect(verifyModelToMatterEvidence(malformedBody, opts).reason).toBe('evidence_body_invalid');
  });

  it('refuses wrong type, invalid action, future evidence, issuer aliasing, and weak assurance', () => {
    const a = action();
    const screening = signedEvidence(a, 'domain_screening');

    expect(verifyModelToMatterEvidence(screening, evidenceOptions(a, 'biosafety_review')).reason)
      .toBe('wrong_type');
    expect(verifyModelToMatterEvidence(screening, evidenceOptions(a, 'domain_screening', {
      expectedAction: null,
    })).reason).toBe('expected_action_invalid');

    const future = signedEvidence(a, 'domain_screening', {
      issued_at: '2026-07-11T16:01:00Z',
      expires_at: '2026-07-11T16:11:00Z',
    });
    expect(verifyModelToMatterEvidence(future, evidenceOptions(a, 'domain_screening')).reason)
      .toBe('not_yet_valid');

    const aliasedIssuer = signedEvidence(a, 'domain_screening', { issuer_id: 'issuer:other' });
    expect(verifyModelToMatterEvidence(aliasedIssuer, evidenceOptions(a, 'domain_screening')).reason)
      .toBe('pin_missing_or_mismatched_issuer_id');
    expect(verifyModelToMatterEvidence(screening, evidenceOptions(a, 'domain_screening', {
      pinnedIssuerKeys: null,
    })).reason).toBe('issuer_key_not_pinned');

    const weakerHuman = signedEvidence(a, 'human_authorization', {
      claims: { assurance_class: 'class_b' },
    });
    expect(verifyModelToMatterEvidence(weakerHuman, evidenceOptions(a, 'human_authorization', {
      requiredHumanAssurance: 'quorum',
    })).reason).toBe('claims_do_not_match_action');
  });

  it('rejects non-arrays, unsupported types, duplicates, and unsafe graph internals', async () => {
    const a = action();
    const p = profile();
    expect(() => buildModelToMatterGraph(a, null)).toThrow(/array/i);
    expect(() => buildModelToMatterGraph(a, [{ evidence_type: 'unknown' }])).toThrow(/unsupported/i);
    expect(() => buildModelToMatterGraph(a, [
      signedEvidence(a, 'domain_screening'),
      signedEvidence(a, 'domain_screening'),
    ])).toThrow(/duplicate/i);

    const base = buildModelToMatterGraph(a, evidenceSet(a));
    const malformedArtifact = {};
    const unsafeGraphs = [
      { ...structuredClone(base), extra: true },
      { ...structuredClone(base), edges: [{ from: 'a', to: 'b' }] },
      {
        ...structuredClone(base),
        nodes: base.nodes.map((node, index) => index === 0 ? { ...node, id: digest('wrong-node') } : node),
      },
      {
        ...structuredClone(base),
        nodes: base.nodes.map((node, index) => index === 1 ? { ...node, type: base.nodes[0].type } : node),
      },
      {
        ...structuredClone(base),
        nodes: base.nodes.map((node, index) => index === 0
          ? { ...node, id: artifactDigest(malformedArtifact), artifact: malformedArtifact }
          : node),
      },
    ];

    for (const [index, graph] of unsafeGraphs.entries()) {
      const registration = await registered(a, p, `m2m-unsafe-graph-${index}`);
      const result = await evaluateRegisteredModelToMatterPresentation({
        action: a,
        profile: p,
        challenge: registration.challenge,
        graph,
        as_of: NOW,
        challengeStore: registration.store,
        clearanceStore: clearanceStore(),
        revokedEvidenceDigests: new Set(),
      });
      expect(result.verdict).not.toBe('clear_to_execute');
    }
  });

  it('fails closed on malformed presentations, unavailable stores, and malformed revocation state', async () => {
    expect((await evaluateRegisteredModelToMatterPresentation(null)).verdict)
      .toBe('do_not_execute_malformed');

    const a = action();
    const p = profile();
    const graph = buildModelToMatterGraph(a, evidenceSet(a));

    const missingStore = await registered(a, p, 'm2m-missing-clearance-store');
    const withoutStore = await evaluateRegisteredModelToMatterPresentation({
      action: a,
      profile: p,
      challenge: missingStore.challenge,
      graph,
      as_of: NOW,
      challengeStore: missingStore.store,
      revokedEvidenceDigests: new Set(),
    });
    expect(withoutStore.verdict).toBe('do_not_execute_refused');
    expect(withoutStore.reasons.join(' ')).toMatch(/clearanceStore/i);

    const malformedRevocation = await registered(a, p, 'm2m-malformed-revocation');
    const malformed = await evaluateRegisteredModelToMatterPresentation({
      action: a,
      profile: p,
      challenge: malformedRevocation.challenge,
      graph,
      as_of: NOW,
      challengeStore: malformedRevocation.store,
      clearanceStore: clearanceStore(),
      revokedEvidenceDigests: new Set(['not-a-digest']),
    });
    expect(malformed.verdict).toBe('do_not_execute_malformed');
    expect(malformed.reasons.join(' ')).toMatch(/revocation state/i);

    const unavailable = await registered(a, p, 'm2m-unavailable-clearance-store');
    await expect(evaluateRegisteredModelToMatterPresentation({
      action: a,
      profile: p,
      challenge: unavailable.challenge,
      graph,
      as_of: NOW,
      challengeStore: unavailable.store,
      clearanceStore: { consume: async () => { throw new Error('storage unavailable'); } },
      revokedEvidenceDigests: new Set(),
    })).rejects.toThrow(/storage unavailable/i);
  });

  it('rejects invalid effect inputs, bindings, status, time, executor, and key type', () => {
    const a = action();
    const clearance = validClearance(a);
    const base = {
      action: a,
      clearance,
      executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T16:01:00Z',
      status: 'completed',
      observed_effect_digest: digest('observed-effect'),
    };

    expect(() => signModelToMatterEffect(null, executorKey)).toThrow(/object/i);
    expect(() => signModelToMatterEffect({
      ...base,
      clearance: { ...clearance, action_digest: digest('different-action') },
    }, executorKey)).toThrow(/different action/i);
    expect(() => signModelToMatterEffect({ ...base, executor_id: 'cloud-lab:other' }, executorKey))
      .toThrow(/executor_id/i);
    expect(() => signModelToMatterEffect({ ...base, executed_at: null }, executorKey))
      .toThrow(/RFC 3339/i);
    expect(() => signModelToMatterEffect({ ...base, status: 'unknown' }, executorKey))
      .toThrow(/status/i);
    expect(() => signModelToMatterEffect({ ...base, observed_effect_digest: 'bad' }, executorKey))
      .toThrow(/observed_effect_digest/i);

    const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    expect(() => signModelToMatterEffect(base, p256)).toThrow(/Ed25519/i);
  });

  it('verifies every effect binding independently and refuses missing executor trust', () => {
    const a = action();
    const effect = signModelToMatterEffect({
      action: a,
      clearance: validClearance(a),
      executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T16:01:00Z',
      status: 'completed',
      observed_effect_digest: digest('observed-effect'),
    }, executorKey);

    expect(verifyModelToMatterEffect(null, effectOptions(a)).reason).toBe('unsupported_version');
    expect(verifyModelToMatterEffect({ ...effect, signature: undefined }, effectOptions(a)).reason)
      .toBe('signature_missing_or_malformed');
    expect(verifyModelToMatterEffect(effect, effectOptions(a, { expectedAction: null })).reason)
      .toBe('expected_action_invalid');
    expect(verifyModelToMatterEffect(effect, effectOptions(a, {
      expectedClearanceReplayDigest: digest('other-clearance'),
    })).reason).toBe('clearance_binding_mismatch');
    expect(verifyModelToMatterEffect(effect, effectOptions(a, { pinnedExecutorKeys: null })).reason)
      .toBe('executor_key_not_pinned');

    const otherAction = action({ destination_digest: digest('other-destination') });
    expect(verifyModelToMatterEffect(effect, effectOptions(otherAction)).reason)
      .toBe('action_binding_mismatch');

    const wrongExecutor = rawSigned(effectBody(a, { executor_id: 'cloud-lab:other' }), executorKey,
      `${M2M_EFFECT_VERSION}\0`, 'effect_digest');
    expect(verifyModelToMatterEffect(wrongExecutor, effectOptions(a)).reason).toBe('executor_mismatch');

    const tooEarly = rawSigned(effectBody(a, { executed_at: '2026-07-11T15:57:00Z' }), executorKey,
      `${M2M_EFFECT_VERSION}\0`, 'effect_digest');
    expect(verifyModelToMatterEffect(tooEarly, effectOptions(a)).reason).toBe('execution_before_action');

    const malformedBody = rawSigned(effectBody(a, { status: 'unknown' }), executorKey,
      `${M2M_EFFECT_VERSION}\0`, 'effect_digest');
    expect(verifyModelToMatterEffect(malformedBody, effectOptions(a)).reason).toBe('effect_body_invalid');
  });
});
