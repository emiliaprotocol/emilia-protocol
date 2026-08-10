// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  M2M_ACTION_VERSION,
  M2M_CAID_ACTION_TYPE,
  M2M_CAID_DEFINITION,
  M2M_CLEARANCE_VERSION,
  M2M_EFFECT_VERSION,
  M2M_EVIDENCE_TYPES,
  M2M_PROFILE_VERSION,
  buildModelToMatterGraph,
  createModelToMatterEvidenceRequirement,
  createModelToMatterExecutor,
  createModelToMatterAction,
  createModelToMatterProfile,
  createRegisteredModelToMatterChallenge,
  evaluateRegisteredModelToMatterPresentation,
  modelToMatterActionDigest,
  modelToMatterCaid,
  signModelToMatterEffect,
  signModelToMatterEvidence,
  verifyModelToMatterEffect,
  verifyModelToMatterOutcome,
  verifyModelToMatterEvidence,
  verifyModelToMatterCaid,
} from '../lib/frontier/model-to-matter.js';
import {
  RELIANCE_PROGRAM_SOURCE_VERSION,
  compileRelianceProgram,
  signRelianceProgram,
} from '../packages/gate/reliance-program.js';
import {
  buildOutcomeObservation,
  observedEffectsDigest,
} from '../packages/verify/index.js';
import { predictedEffectsDigest } from '../packages/verify/effect-predicates.js';
import { createDurableChallengeStore } from '../packages/gate/challenge-store.js';
import { createDurableConsumptionStore, createMemoryBackend } from '../packages/gate/store.js';
import { artifactDigest } from '../lib/evidence/evidence-graph.js';

const NOW = '2026-07-11T16:00:00Z';
const ISSUED_AT = '2026-07-11T15:59:00Z';
const EVIDENCE_EXPIRES = '2026-07-11T16:10:00Z';
const PHYSICAL_STATE_EXPIRES = '2026-07-11T16:14:00Z';
const CHALLENGE_EXPIRES = '2026-07-11T16:05:00Z';

const keys = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [
  type,
  crypto.generateKeyPairSync('ed25519').privateKey,
]));
const executorKey = crypto.generateKeyPairSync('ed25519').privateKey;
const relianceProgramKey = crypto.generateKeyPairSync('ed25519');

function publicKey(privateKey) {
  return crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
}

function digest(label) {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function challengeNonce(label) {
  return crypto.createHash('sha256').update(label).digest('base64url');
}

const ACTION_INPUT = Object.freeze({
  action_type: 'science.bio.experiment.execute.1',
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
});

function action(overrides = {}) {
  return createModelToMatterAction({
    ...structuredClone(ACTION_INPUT),
    ...structuredClone(overrides),
  });
}

const PHYSICAL_STATE_POLICY = Object.freeze({
  required_precondition_digest: digest('required-physical-preconditions'),
  max_measurement_age_sec: 120,
  max_validity_duration_sec: 900,
  executor_control_domain: 'control:cloud-lab:example',
  executor_public_keys: [publicKey(executorKey)],
});

const issuerPins = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, [{
  issuer_id: `issuer:${type}`,
  public_key: publicKey(keys[type]),
  ...(type === 'physical_state_attestation' ? {
    sensor_network_id: 'sensor-network:facility-safe-demo-01',
    control_domain: 'control:independent-facility-sensors',
  } : {}),
}]]));

function profile(overrides = {}) {
  return createModelToMatterProfile({
    profile_id: 'ep:m2m:bio-research:v1',
    accepted_issuers: issuerPins,
    physical_state_policy: PHYSICAL_STATE_POLICY,
    ...structuredClone(overrides),
  });
}

function claimsFor(type, a) {
  if (type === 'model_attestation') {
    return {
      provider: a.model.provider,
      model_id: a.model.model_id,
      manifest_digest: a.model.manifest_digest,
      harness_digest: a.model.harness_digest,
      safeguards_digest: a.model.safeguards_digest,
    };
  }
  if (type === 'safety_case_attestation') {
    return {
      manifest_digest: a.model.manifest_digest,
      harness_digest: a.model.harness_digest,
      safeguards_digest: a.model.safeguards_digest,
      safety_case_digest: digest('frontier-safety-case'),
      assessment: 'acceptable',
    };
  }
  if (type === 'institutional_authority') {
    return {
      organization_id: a.principal.organization_id,
      principal_id: a.principal.principal_id,
      action_type: a.action_type,
      purpose_code: a.purpose.code,
      decision: 'allow',
    };
  }
  if (type === 'biosafety_review') {
    return {
      protocol_digest: a.experiment.protocol_digest,
      materials_commitment: a.experiment.materials_commitment,
      facility_id: a.executor.facility_id,
      decision: 'approve',
    };
  }
  if (type === 'domain_screening') {
    return {
      materials_commitment: a.experiment.materials_commitment,
      destination_digest: a.destination_digest,
      screening_profile_digest: digest('screening-profile'),
      decision: 'pass',
    };
  }
  if (type === 'human_authorization') {
    return {
      approver_id: 'person:responsible-investigator',
      decision: 'approve',
      assurance_class: 'class_a',
    };
  }
  if (type === 'physical_state_attestation') {
    return {
      sensor_network_id: issuerPins.physical_state_attestation[0].sensor_network_id,
      required_precondition_digest: PHYSICAL_STATE_POLICY.required_precondition_digest,
      measured_state_digest: digest('measured-room-state'),
      measured_at: ISSUED_AT,
      match: true,
    };
  }
  throw new Error(`unknown evidence type ${type}`);
}

function signedEvidence(a, type, overrides = {}, privateKey = keys[type]) {
  return signModelToMatterEvidence({
    evidence_type: type,
    action_digest: modelToMatterActionDigest(a),
    issuer_id: overrides.issuer_id ?? `issuer:${type}`,
    issued_at: overrides.issued_at ?? ISSUED_AT,
    expires_at: overrides.expires_at
      ?? (type === 'physical_state_attestation' ? PHYSICAL_STATE_EXPIRES : EVIDENCE_EXPIRES),
    claims: { ...claimsFor(type, a), ...(overrides.claims || {}) },
    ...(overrides.outcome ? { outcome: overrides.outcome } : {}),
  }, privateKey);
}

function evidenceSet(a, omit = []) {
  return M2M_EVIDENCE_TYPES
    .filter((type) => !omit.includes(type))
    .map((type) => signedEvidence(a, type));
}

function store() {
  return createDurableChallengeStore(createMemoryBackend());
}

function actionStore(backend = createMemoryBackend()) {
  return createDurableConsumptionStore(backend);
}

function relianceProgram(a, p, sourceOverrides = {}) {
  const requirement = createModelToMatterEvidenceRequirement(p);
  const source = {
    '@version': RELIANCE_PROGRAM_SOURCE_VERSION,
    program_id: 'rp.m2m.example-research:v1',
    version: 1,
    relying_party: { id: 'org:example-university', key_id: 'rp-key-1' },
    root_caid: modelToMatterCaid(a).caid,
    action_digest: modelToMatterActionDigest(a),
    valid_from: '2026-07-11T15:00:00Z',
    expires_at: '2026-07-12T15:00:00Z',
    stages: [{
      stage_id: 'model-to-matter-evidence',
      depends_on: [],
      rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
      profiles: [{
        profile_id: requirement.id,
        profile_hash: requirement.profile_hash,
        evaluation_max_age_sec: 300,
        revocation_required: true,
      }],
    }],
    execution: {
      depends_on: ['model-to-matter-evidence'],
      consequence_mode: 'action-escrow',
      capability_template_digest: null,
      escrow_profile_digest: digest('m2m-action-escrow-profile'),
    },
    ...structuredClone(sourceOverrides),
  };
  const envelope = signRelianceProgram(source, relianceProgramKey.privateKey);
  const compiled = compileRelianceProgram(envelope, {
    trustedKeys: {
      'rp-key-1': {
        relying_party_id: source.relying_party.id,
        public_key: publicKey(relianceProgramKey.privateKey),
      },
    },
    profiles: [requirement],
  });
  return { requirement, compiled };
}

describe('EP Model-to-Matter action and profile', () => {
  it('creates a digest-only, single-execution action without raw biological content', () => {
    const a = action();
    expect(a['@version']).toBe(M2M_ACTION_VERSION);
    expect(a.max_executions).toBe(1);
    expect(modelToMatterActionDigest(a)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(a)).not.toContain('fasta');
    expect(Object.isFrozen(a)).toBe(true);
  });

  it('uses one registered CAID over the exact bytes every evidence leg binds', () => {
    const a = action();
    const computed = modelToMatterCaid(a);
    expect(a.action_type).toBe(M2M_CAID_ACTION_TYPE);
    expect(computed.caid).toMatch(/^caid:1:science\.bio\.experiment\.execute\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
    expect(computed.digest).toBe(modelToMatterActionDigest(a));
    expect(verifyModelToMatterCaid(a, computed.caid)).toEqual({ valid: true, reasons: [] });
    expect(verifyModelToMatterCaid({ ...a, destination_digest: digest('other') }, computed.caid).valid).toBe(false);

    const registry = JSON.parse(readFileSync(new URL('../caid/registry/action-types.json', import.meta.url), 'utf8'));
    expect(registry.types.find((entry) => entry.action_type === M2M_CAID_ACTION_TYPE))
      .toEqual(M2M_CAID_DEFINITION);
  });

  it('rejects raw sequence, raw protocol, prompt, and chain-of-thought fields at any depth', () => {
    for (const forbidden of ['sequence', 'fasta', 'raw_protocol', 'prompt', 'chain_of_thought']) {
      expect(() => action({ experiment: { ...ACTION_INPUT.experiment, nested: { [forbidden]: 'raw-sensitive-value' } } }))
        .toThrow(/commitments and digests/i);
    }
  });

  it('rejects reusable, malformed, and impossible-time actions', () => {
    expect(() => action({ max_executions: 2 })).toThrow(/max_executions/);
    expect(() => action({ requested_at: '2026-02-30T12:00:00Z' })).toThrow(/requested_at/);
    expect(() => action({ destination_digest: 'not-a-digest' })).toThrow(/destination_digest/);
  });

  it('builds the relying-party-owned evidence requirement and issuer pins', () => {
    const p = profile();
    expect(p['@version']).toBe(M2M_PROFILE_VERSION);
    for (const type of M2M_EVIDENCE_TYPES) {
      expect(p.requirement).toContain(type);
      expect(p.accepted_issuers[type]).toHaveLength(1);
    }
    expect(p.required_human_assurance).toBe('class_a');

    const requirement = createModelToMatterEvidenceRequirement(p);
    expect(requirement.id).toBe(p.profile_id);
    expect(requirement.profile_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(requirement.required_evidence.map((item) => item.evidence_type))
      .toEqual(M2M_EVIDENCE_TYPES);
    expect(Object.isFrozen(requirement)).toBe(true);
  });

  it('refuses profile weakening and prototype-inherited assurance labels', async () => {
    const p = structuredClone(profile());
    p.require_action_agreement = false;
    await expect(createRegisteredModelToMatterChallenge(action(), p, {
      challengeStore: store(), expires_at: CHALLENGE_EXPIRES,
    })).rejects.toThrow(/action agreement/i);
    expect(() => profile({ required_human_assurance: 'toString' })).toThrow(/assurance/i);
    expect(() => profile({ required_human_assurance: 'class_b' })).toThrow(/assurance/i);
  });
});

describe('EP Model-to-Matter signed evidence', () => {
  it('separates cryptographic verification from relying-party acceptance', () => {
    const a = action();
    const artifact = signedEvidence(a, 'domain_screening');
    const verifiedOnly = verifyModelToMatterEvidence(artifact, {
      expectedType: 'domain_screening', expectedAction: a, as_of: NOW, pinnedIssuerKeys: [],
    });
    expect(verifiedOnly.verified).toBe(true);
    expect(verifiedOnly.accepted).toBe(false);
    expect(verifiedOnly.reason).toBe('issuer_key_not_pinned');

    const accepted = verifyModelToMatterEvidence(artifact, {
      expectedType: 'domain_screening', expectedAction: a, as_of: NOW,
      pinnedIssuerKeys: issuerPins.domain_screening,
    });
    expect(accepted.verified).toBe(true);
    expect(accepted.accepted).toBe(true);
  });

  it('deep-copies claims so mutation after signing cannot rewrite the artifact', () => {
    const a = action();
    const body = {
      evidence_type: 'domain_screening', action_digest: modelToMatterActionDigest(a),
      issuer_id: 'issuer:domain_screening', issued_at: ISSUED_AT, expires_at: EVIDENCE_EXPIRES,
      claims: claimsFor('domain_screening', a),
    };
    const artifact = signModelToMatterEvidence(body, keys.domain_screening);
    body.claims.decision = 'fail';
    expect(artifact.claims.decision).toBe('pass');
  });

  it('rejects unknown adapter claims instead of signing ignored or sensitive content', () => {
    const a = action();
    expect(() => signModelToMatterEvidence({
      evidence_type: 'domain_screening', action_digest: modelToMatterActionDigest(a),
      issuer_id: 'issuer:domain_screening', issued_at: ISSUED_AT, expires_at: EVIDENCE_EXPIRES,
      claims: { ...claimsFor('domain_screening', a), dna: 'opaque-but-forbidden-here' },
    }, keys.domain_screening)).toThrow(/not allowed/i);
    expect(() => signedEvidence(a, 'human_authorization', {
      claims: { assurance_class: 'toString' },
    })).toThrow(/assurance/i);
  });

  it('refuses tampering, issuer laundering, cross-action replay, and impossible timestamps', () => {
    const a = action();
    const artifact = signedEvidence(a, 'biosafety_review');
    const opts = {
      expectedType: 'biosafety_review', expectedAction: a, as_of: NOW,
      pinnedIssuerKeys: issuerPins.biosafety_review,
    };
    expect(verifyModelToMatterEvidence({ ...artifact, claims: { ...artifact.claims, decision: 'approve-anything' } }, opts).accepted).toBe(false);

    const attackerKey = crypto.generateKeyPairSync('ed25519').privateKey;
    const laundered = signedEvidence(a, 'biosafety_review', {}, attackerKey);
    expect(verifyModelToMatterEvidence(laundered, opts).reason).toBe('issuer_key_not_pinned');

    const other = action({ destination_digest: digest('other-destination') });
    expect(verifyModelToMatterEvidence(artifact, { ...opts, expectedAction: other }).reason).toBe('action_binding_mismatch');

    const impossible = signModelToMatterEvidence({
      evidence_type: 'biosafety_review', action_digest: modelToMatterActionDigest(a),
      issuer_id: 'issuer:biosafety_review', issued_at: '2026-02-30T12:00:00Z',
      expires_at: EVIDENCE_EXPIRES, claims: claimsFor('biosafety_review', a),
    }, keys.biosafety_review);
    expect(verifyModelToMatterEvidence(impossible, opts).reason).toBe('invalid_time_window');
  });

  it('refuses valid signatures whose domain claims do not match the exact action', () => {
    const a = action();
    const wrongModel = signedEvidence(a, 'model_attestation', {
      claims: { manifest_digest: digest('different-model') },
    });
    const result = verifyModelToMatterEvidence(wrongModel, {
      expectedType: 'model_attestation', expectedAction: a, as_of: NOW,
      pinnedIssuerKeys: issuerPins.model_attestation,
    });
    expect(result.verified).toBe(true);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe('claims_do_not_match_action');
  });

  it('treats expired and revoked evidence as unusable without weakening signature verification', () => {
    const a = action();
    const artifact = signedEvidence(a, 'domain_screening');
    const expired = verifyModelToMatterEvidence(artifact, {
      expectedType: 'domain_screening', expectedAction: a, as_of: '2026-07-11T16:11:00Z',
      pinnedIssuerKeys: issuerPins.domain_screening,
    });
    expect(expired.verified).toBe(true);
    expect(expired.accepted).toBe(false);
    expect(expired.reason).toBe('expired');

    const revoked = verifyModelToMatterEvidence(artifact, {
      expectedType: 'domain_screening', expectedAction: a, as_of: NOW,
      pinnedIssuerKeys: issuerPins.domain_screening,
      revokedEvidenceDigests: new Set([artifact.signature.evidence_digest]),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    expect(revoked.verified).toBe(true);
    expect(revoked.accepted).toBe(false);
    expect(revoked.reason).toBe('revoked');
  });
});

describe('EP Model-to-Matter clearance lifecycle', () => {
  it('challenges for the complete model-to-matter evidence set', async () => {
    const a = action();
    const challenge = await createRegisteredModelToMatterChallenge(a, profile(), {
      challengeStore: store(), expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce('m2m-required-evidence'),
    });
    expect(challenge.required_evidence.map((item) => item.type)).toEqual(M2M_EVIDENCE_TYPES);
    expect(challenge.action_digest).toBe(modelToMatterActionDigest(a));
  });

  it('clears a complete pinned evidence graph on first presentation and refuses replay', async () => {
    const backend = createMemoryBackend();
    const issueStore = createDurableChallengeStore(backend);
    const a = action();
    const p = profile();
    const challenge = await createRegisteredModelToMatterChallenge(a, p, {
      challengeStore: issueStore, expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce('m2m-once-00000001'),
    });
    const graph = buildModelToMatterGraph(a, evidenceSet(a));
    const results = await Promise.all([
      evaluateRegisteredModelToMatterPresentation({
        action: a, challenge, graph, profile: p, as_of: NOW,
        challengeStore: createDurableChallengeStore(backend),
        clearanceStore: actionStore(),
        revokedEvidenceDigests: new Set(),
        retiredPhysicalMeasurementDigests: new Set(),
      }),
      evaluateRegisteredModelToMatterPresentation({
        action: a, challenge, graph, profile: p, as_of: NOW,
        challengeStore: createDurableChallengeStore(backend),
        clearanceStore: actionStore(),
        revokedEvidenceDigests: new Set(),
        retiredPhysicalMeasurementDigests: new Set(),
      }),
    ]);
    expect(results.filter((result) => result.verdict === 'clear_to_execute')).toHaveLength(1);
    expect(results.filter((result) => result.verdict === 'do_not_execute_refused')).toHaveLength(1);
    expect(results[0]['@version']).toBe(M2M_CLEARANCE_VERSION);
    expect(new Set(results.map((result) => result.action_caid)))
      .toEqual(new Set([modelToMatterCaid(a).caid]));
  });

  it('admits at most one clearance across distinct challenges for the same action', async () => {
    const a = action();
    const p = profile();
    const challengeBackend = createMemoryBackend();
    const issueStore = createDurableChallengeStore(challengeBackend);
    const [first, second] = await Promise.all([
      createRegisteredModelToMatterChallenge(a, p, {
        challengeStore: issueStore, expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce('m2m-action-once-a'),
      }),
      createRegisteredModelToMatterChallenge(a, p, {
        challengeStore: issueStore, expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce('m2m-action-once-b'),
      }),
    ]);
    const graph = buildModelToMatterGraph(a, evidenceSet(a));
    const clearanceBackend = createMemoryBackend();
    const results = await Promise.all([first, second].map((challenge) => (
      evaluateRegisteredModelToMatterPresentation({
        action: a,
        challenge,
        graph,
        profile: p,
        as_of: NOW,
        challengeStore: createDurableChallengeStore(challengeBackend),
        clearanceStore: actionStore(clearanceBackend),
        revokedEvidenceDigests: new Set(),
        retiredPhysicalMeasurementDigests: new Set(),
      })
    )));
    expect(results.filter((result) => result.verdict === 'clear_to_execute')).toHaveLength(1);
    expect(results.filter((result) => result.verdict === 'do_not_execute_refused')).toHaveLength(1);
  });

  it('snapshots the action, profile, and graph before awaiting durable consumption', async () => {
    const a = action();
    const p = structuredClone(profile());
    const graph = structuredClone(buildModelToMatterGraph(a, evidenceSet(a)));
    const registeredStore = store();
    const challenge = await createRegisteredModelToMatterChallenge(a, p, {
      challengeStore: registeredStore,
      expires_at: CHALLENGE_EXPIRES,
      nonce: challengeNonce('m2m-snapshot-before-await'),
    });
    let releaseConsume;
    const consumeBarrier = new Promise((resolve) => { releaseConsume = resolve; });
    const delayedStore = {
      async register(value) {
        return registeredStore.register(value);
      },
      async consume(value) {
        await consumeBarrier;
        return registeredStore.consume(value);
      },
    };
    const pending = evaluateRegisteredModelToMatterPresentation({
      action: a,
      challenge,
      graph,
      profile: p,
      as_of: NOW,
      challengeStore: delayedStore,
      clearanceStore: actionStore(),
      revokedEvidenceDigests: new Set(),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    p.requirement = 'model_attestation';
    graph.nodes = graph.nodes.filter((node) => node.type === 'model_attestation');
    releaseConsume();

    const result = await pending;
    expect(result.verdict).toBe('clear_to_execute');
    expect(result.graph.nodes).toBe(M2M_EVIDENCE_TYPES.length);
  });

  it('fails before challenge consumption when explicit revocation state is absent', async () => {
    const a = action();
    const p = profile();
    const challengeStore = store();
    const challenge = await createRegisteredModelToMatterChallenge(a, p, {
      challengeStore, expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce('m2m-revocation-state'),
    });
    const graph = buildModelToMatterGraph(a, evidenceSet(a));
    const clearanceStore = actionStore();
    const absent = await evaluateRegisteredModelToMatterPresentation({
      action: a, challenge, graph, profile: p, as_of: NOW, challengeStore, clearanceStore,
    });
    expect(absent.verdict).toBe('do_not_execute_refused');
    expect(absent.reasons.join(' ')).toMatch(/revocation state/i);

    const retried = await evaluateRegisteredModelToMatterPresentation({
      action: a, challenge, graph, profile: p, as_of: NOW, challengeStore, clearanceStore,
      revokedEvidenceDigests: new Set(),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    expect(retried.verdict).toBe('clear_to_execute');
  });

  it('returns a machine-readable follow-up challenge for only missing evidence', async () => {
    const a = action();
    const p = profile();
    const challengeStore = store();
    const challenge = await createRegisteredModelToMatterChallenge(a, p, {
      challengeStore, expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce('m2m-partial-00001'),
    });
    const graph = buildModelToMatterGraph(a, evidenceSet(a, ['biosafety_review', 'domain_screening']));
    const result = await evaluateRegisteredModelToMatterPresentation({
      action: a, challenge, graph, profile: p, as_of: NOW, challengeStore,
      next_nonce: challengeNonce('m2m-followup-0001'),
      clearanceStore: actionStore(),
      revokedEvidenceDigests: new Set(),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    expect(result.verdict).toBe('do_not_execute_missing_evidence');
    expect(result.next_challenge.required_evidence.map((item) => item.type))
      .toEqual(['biosafety_review', 'domain_screening']);
  });

  it('refuses action mutation before consuming the registered challenge', async () => {
    const a = action();
    const p = profile();
    const challengeStore = store();
    const challenge = await createRegisteredModelToMatterChallenge(a, p, {
      challengeStore, expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce('m2m-action-swap-1'),
    });
    const graph = buildModelToMatterGraph(a, evidenceSet(a));
    const changed = action({ model: { ...ACTION_INPUT.model, harness_digest: digest('changed-harness') } });
    const swapped = await evaluateRegisteredModelToMatterPresentation({
      action: changed, challenge, graph, profile: p, as_of: NOW, challengeStore,
      clearanceStore: actionStore(),
      revokedEvidenceDigests: new Set(),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    expect(swapped.verdict).toBe('do_not_execute_action_mismatch');

    const original = await evaluateRegisteredModelToMatterPresentation({
      action: a, challenge, graph, profile: p, as_of: NOW, challengeStore,
      clearanceStore: actionStore(),
      revokedEvidenceDigests: new Set(),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    expect(original.verdict).toBe('clear_to_execute');
  });

  it('refuses signed but unpinned, stale, denied, and claim-mismatched evidence', async () => {
    const cases = [
      {
        label: 'unpinned',
        evidence(a) {
          const attackerKey = crypto.generateKeyPairSync('ed25519').privateKey;
          return evidenceSet(a).map((artifact) => artifact.evidence_type === 'domain_screening'
            ? signedEvidence(a, 'domain_screening', {}, attackerKey) : artifact);
        },
        verdict: 'do_not_execute_unverifiable',
      },
      {
        label: 'stale',
        profile: { freshness_sec: { domain_screening: 10 } },
        evidence(a) { return evidenceSet(a); },
        verdict: 'do_not_execute_stale_evidence',
      },
      {
        label: 'denied',
        evidence(a) {
          return evidenceSet(a).map((artifact) => artifact.evidence_type === 'biosafety_review'
            ? signedEvidence(a, 'biosafety_review', { outcome: 'deny' }) : artifact);
        },
        verdict: 'do_not_execute_conflicted',
      },
      {
        label: 'wrong-claims',
        evidence(a) {
          return evidenceSet(a).map((artifact) => artifact.evidence_type === 'safety_case_attestation'
            ? signedEvidence(a, 'safety_case_attestation', { claims: { assessment: 'unknown' } }) : artifact);
        },
        verdict: 'do_not_execute_unverifiable',
      },
    ];

    for (const testCase of cases) {
      const a = action();
      const p = profile(testCase.profile || {});
      const challengeStore = store();
      const challenge = await createRegisteredModelToMatterChallenge(a, p, {
        challengeStore, expires_at: CHALLENGE_EXPIRES, nonce: challengeNonce(`m2m-${testCase.label}-evidence`),
      });
      const result = await evaluateRegisteredModelToMatterPresentation({
        action: a, challenge, graph: buildModelToMatterGraph(a, testCase.evidence(a)),
        profile: p, as_of: NOW, challengeStore,
        clearanceStore: actionStore(),
        revokedEvidenceDigests: new Set(),
        retiredPhysicalMeasurementDigests: new Set(),
      });
      expect(result.verdict, testCase.label).toBe(testCase.verdict);
    }
  });

  it('never throws on hostile presentation shapes', async () => {
    const actionDigest = modelToMatterActionDigest(action());
    const hostile = [
      null,
      undefined,
      0,
      '',
      [],
      {},
      { '@version': 'wrong' },
      { '@version': 'EP-AEG-v1', action_digest: actionDigest, nodes: {}, edges: [] },
      { '@version': 'EP-AEG-v1', action_digest: actionDigest, nodes: [null], edges: [] },
      { '@version': 'EP-AEG-v1', action_digest: actionDigest, nodes: [], edges: {} },
    ];
    for (const graph of hostile) {
      const a = action();
      const p = profile();
      const challengeStore = store();
      const challenge = await createRegisteredModelToMatterChallenge(a, p, {
        challengeStore, expires_at: CHALLENGE_EXPIRES,
      });
      const result = await evaluateRegisteredModelToMatterPresentation({
        action: a, challenge, graph, profile: p, as_of: NOW, challengeStore,
        clearanceStore: actionStore(),
        revokedEvidenceDigests: new Set(),
        retiredPhysicalMeasurementDigests: new Set(),
      });
      expect(result.verdict).not.toBe('clear_to_execute');
    }
  });
});

describe('EP Model-to-Matter pinned executor boundary', () => {
  function executor(overrides = {}, a = null) {
    const p = profile();
    return createModelToMatterExecutor({
      profile: p,
      challengeStore: store(),
      clearanceStore: actionStore(),
      revocationProvider: async () => new Set(),
      physicalMeasurementProvider: async () => new Set(),
      allowEphemeralState: true,
      now: () => Date.parse(NOW),
      ...(a ? { relianceProgram: relianceProgram(a, p).compiled } : {}),
      ...overrides,
    });
  }

  it('binds the signed Reliance Program and exact evidence requirement into clearance', async () => {
    const a = action();
    const p = profile();
    const { requirement, compiled } = relianceProgram(a, p);
    const gate = executor({ profile: p, relianceProgram: compiled });
    const challenge = await gate.issueChallenge(a, { nonce: challengeNonce('m2m-reliance-binding') });
    const result = await gate.evaluate({
      action: a,
      challenge,
      graph: buildModelToMatterGraph(a, evidenceSet(a)),
    });

    expect(result).toMatchObject({
      verdict: 'clear_to_execute',
      reliance_program_id: compiled.program.program_id,
      reliance_program_version: compiled.program.version,
      reliance_program_source_digest: compiled.source_digest,
      reliance_program_digest: compiled.program_digest,
      evidence_requirement_digest: requirement.profile_hash,
    });
  });

  it('refuses missing roles, cross-role substitution, and mismatched program pins', async () => {
    const a = action();
    const p = profile();
    const { compiled } = relianceProgram(a, p);

    const missingGate = executor({ profile: p, relianceProgram: compiled });
    const missingChallenge = await missingGate.issueChallenge(a, { nonce: challengeNonce('m2m-program-missing-role') });
    const missing = await missingGate.evaluate({
      action: a,
      challenge: missingChallenge,
      graph: buildModelToMatterGraph(a, evidenceSet(a, ['biosafety_review'])),
    });
    expect(missing.verdict).toBe('do_not_execute_missing_evidence');
    expect(missing.evidence_requirement_digest).toBe(createModelToMatterEvidenceRequirement(p).profile_hash);

    const missingPhysicalGate = executor({ profile: p, relianceProgram: compiled });
    const missingPhysicalChallenge = await missingPhysicalGate.issueChallenge(a, {
      nonce: challengeNonce('m2m-program-missing-physical-state'),
    });
    const missingPhysical = await missingPhysicalGate.evaluate({
      action: a,
      challenge: missingPhysicalChallenge,
      graph: buildModelToMatterGraph(a, evidenceSet(a, ['physical_state_attestation'])),
    });
    expect(missingPhysical.verdict).toBe('do_not_execute_missing_evidence');

    const substitutionGate = executor({ profile: p, relianceProgram: compiled });
    const substitutionChallenge = await substitutionGate.issueChallenge(a, { nonce: challengeNonce('m2m-program-role-swap') });
    const substitute = signedEvidence(a, 'model_attestation', { issued_at: '2026-07-11T15:59:01Z' });
    const substitutedGraph = structuredClone(buildModelToMatterGraph(a, evidenceSet(a, ['biosafety_review'])));
    substitutedGraph.nodes.push({
      id: artifactDigest(substitute),
      type: 'biosafety_review',
      artifact: substitute,
    });
    const substituted = await substitutionGate.evaluate({
      action: a,
      challenge: substitutionChallenge,
      graph: substitutedGraph,
    });
    expect(substituted.verdict).not.toBe('clear_to_execute');
    expect(substituted.reasons.join(' ')).toMatch(/biosafety_review/i);

    const physicalSubstitutionGate = executor({ profile: p, relianceProgram: compiled });
    const physicalSubstitutionChallenge = await physicalSubstitutionGate.issueChallenge(a, {
      nonce: challengeNonce('m2m-program-physical-role-swap'),
    });
    const screeningSubstitute = signedEvidence(a, 'domain_screening', {
      issued_at: '2026-07-11T15:59:02Z',
    });
    const physicalSubstitutionGraph = structuredClone(buildModelToMatterGraph(
      a,
      evidenceSet(a, ['physical_state_attestation']),
    ));
    physicalSubstitutionGraph.nodes.push({
      id: artifactDigest(screeningSubstitute),
      type: 'physical_state_attestation',
      artifact: screeningSubstitute,
    });
    const physicalSubstitution = await physicalSubstitutionGate.evaluate({
      action: a,
      challenge: physicalSubstitutionChallenge,
      graph: physicalSubstitutionGraph,
    });
    expect(physicalSubstitution.verdict).toBe('do_not_execute_unverifiable');
    expect(physicalSubstitution.reasons.join(' ')).toMatch(/physical_state_attestation/i);

    const stricterProfile = profile({ freshness_sec: { domain_screening: 299 } });
    const mismatched = relianceProgram(a, stricterProfile).compiled;
    expect(() => executor({ profile: p, relianceProgram: mismatched }))
      .toThrow(/evidence requirement digest/i);

    const otherAction = action({ destination_digest: digest('other-program-action') });
    const otherGate = executor({ profile: p, relianceProgram: compiled });
    await expect(otherGate.issueChallenge(otherAction)).rejects.toThrow(/Reliance Program.*action/i);

    const expiredProgram = relianceProgram(a, p, {
      valid_from: '2026-07-10T15:00:00Z',
      expires_at: '2026-07-11T15:30:00Z',
    }).compiled;
    const expiredGate = executor({ profile: p, relianceProgram: expiredProgram });
    await expect(expiredGate.issueChallenge(a)).rejects.toThrow(/Reliance Program is not active/i);
  });

  it('refuses corrupted compiled-program structure before challenge issuance', () => {
    const a = action();
    const p = profile();
    const { compiled } = relianceProgram(a, p);
    const cases = [
      {
        label: 'wrapper version',
        mutate(program) { program.version = 'EP-RELIANCE-PROGRAM-v0'; },
        reason: /relianceProgram\.version/i,
      },
      {
        label: 'compiled digest',
        mutate(program) { program.program_digest = digest('wrong-compiled-program'); },
        reason: /program_digest/i,
      },
      {
        label: 'CAID family',
        build() {
          return relianceProgram(a, p, {
            root_caid: `caid:1:health.prior-authorization-determination.1:jcs-sha256:${'A'.repeat(43)}`,
          }).compiled;
        },
        reason: /Model-to-Matter CAID/i,
      },
      {
        label: 'empty trace',
        mutate(program) { program.trace = []; },
        reason: /trace/i,
      },
      {
        label: 'trace mapping',
        mutate(program) { program.trace[0].requirement_id = 'different-requirement'; },
        reason: /trace/i,
      },
    ];

    for (const testCase of cases) {
      const candidate = testCase.build ? testCase.build() : structuredClone(compiled);
      testCase.mutate?.(candidate);
      expect(() => executor({ profile: p, relianceProgram: candidate }), testCase.label)
        .toThrow(testCase.reason);
    }
  });

  it('refuses invalid or inactive Reliance Programs at the low-level evaluator boundary', async () => {
    const a = action();
    const p = profile();
    const challengeStore = store();
    const challenge = await createRegisteredModelToMatterChallenge(a, p, {
      challengeStore,
      expires_at: CHALLENGE_EXPIRES,
      nonce: challengeNonce('m2m-low-level-program-refusal'),
    });
    const graph = buildModelToMatterGraph(a, evidenceSet(a));
    const invalid = structuredClone(relianceProgram(a, p).compiled);
    invalid.version = 'EP-RELIANCE-PROGRAM-v0';
    const malformedProgram = await evaluateRegisteredModelToMatterPresentation({
      action: a,
      challenge,
      graph,
      profile: p,
      relianceProgram: invalid,
      as_of: NOW,
      challengeStore,
      clearanceStore: actionStore(),
      revokedEvidenceDigests: new Set(),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    expect(malformedProgram).toMatchObject({
      verdict: 'do_not_execute_refused',
      clear_to_execute: false,
    });
    expect(malformedProgram.reasons.join(' ')).toMatch(/pinned Reliance Program refused/i);

    const expired = relianceProgram(a, p, {
      valid_from: '2026-07-10T15:00:00Z',
      expires_at: '2026-07-11T15:30:00Z',
    }).compiled;
    const inactive = await evaluateRegisteredModelToMatterPresentation({
      action: a,
      challenge,
      graph,
      profile: p,
      relianceProgram: expired,
      as_of: NOW,
      challengeStore,
      clearanceStore: actionStore(),
      revokedEvidenceDigests: new Set(),
      retiredPhysicalMeasurementDigests: new Set(),
    });
    expect(inactive).toMatchObject({
      verdict: 'do_not_execute_refused',
      base_verdict: 'refused',
      clear_to_execute: false,
    });
    expect(inactive.reasons).toEqual(['pinned Reliance Program is not active at the evaluation time']);
  });

  it('pins all trust configuration and invokes the effect adapter only after one successful clearance', async () => {
    const a = action();
    const challengeStore = store();
    const clearanceStore = actionStore();
    const gate = executor({ challengeStore, clearanceStore });
    const challenge = await gate.issueChallenge(a, { nonce: challengeNonce('m2m-pinned-executor') });
    const graph = buildModelToMatterGraph(a, evidenceSet(a));
    const presentation = { action: structuredClone(a), challenge, graph };
    let effects = 0;
    let seenAction;

    const injected = await gate.run({ ...presentation, profile: profile() }, async () => { effects++; });
    expect(injected).toMatchObject({
      ok: false,
      allow: false,
      clearance: { verdict: 'do_not_execute_refused', clear_to_execute: false },
    });

    challengeStore.consume = async () => true;
    clearanceStore.consume = async () => true;
    const firstPending = gate.run(presentation, async ({ action: executedAction }) => {
      effects++;
      seenAction = executedAction;
      return 'executed';
    });
    presentation.action.destination_digest = digest('mutated-after-run');
    const first = await firstPending;
    const replay = await gate.run({ action: a, challenge, graph }, async () => { effects++; });

    expect(first).toMatchObject({ ok: true, allow: true, value: 'executed' });
    expect(replay).toMatchObject({ ok: false, allow: false });
    expect(effects).toBe(1);
    expect(seenAction.destination_digest).toBe(a.destination_digest);
    expect(Object.isFrozen(seenAction)).toBe(true);
    expect(Object.isFrozen(seenAction.experiment)).toBe(true);
  });

  it('refuses every transaction-scoped trust field before challenge consumption', async () => {
    const a = action();
    for (const field of [
      'profile', 'challengeStore', 'clearanceStore', 'revokedEvidenceDigests',
      'revocationProvider', 'relianceProgram', 'requirementBinding',
      'physicalMeasurementProvider', 'retiredPhysicalMeasurementDigests',
      'as_of', 'next_expires_at', 'next_nonce',
    ]) {
      const gate = executor();
      const challenge = await gate.issueChallenge(a, { nonce: challengeNonce(`m2m-injected-${field}`) });
      const result = await gate.evaluate({
        action: a,
        challenge,
        graph: buildModelToMatterGraph(a, evidenceSet(a)),
        [field]: {},
      });
      expect(result.verdict, field).toBe('do_not_execute_refused');
      expect(result.reasons.join('; '), field).toContain('transaction-scoped trust configuration refused');
    }
  });

  it('fails closed when its pinned clock, revocation, or measurement-retirement provider is unavailable', async () => {
    const a = action();
    const badClock = executor({ now: () => { throw new Error('clock unavailable'); } });
    await expect(badClock.issueChallenge(a)).rejects.toThrow(/clock/i);

    const badRevocation = executor({ revocationProvider: async () => null });
    const challenge = await badRevocation.issueChallenge(a, { nonce: challengeNonce('m2m-bad-revocation-provider') });
    const result = await badRevocation.evaluate({
      action: a,
      challenge,
      graph: buildModelToMatterGraph(a, evidenceSet(a)),
    });
    expect(result).toMatchObject({
      verdict: 'do_not_execute_refused',
      clear_to_execute: false,
      reasons: ['revocation state is unavailable or malformed'],
    });

    const badMeasurements = executor({ physicalMeasurementProvider: async () => null });
    const measurementChallenge = await badMeasurements.issueChallenge(a, {
      nonce: challengeNonce('m2m-bad-physical-measurement-provider'),
    });
    const measurementResult = await badMeasurements.evaluate({
      action: a,
      challenge: measurementChallenge,
      graph: buildModelToMatterGraph(a, evidenceSet(a)),
    });
    expect(measurementResult).toMatchObject({
      verdict: 'do_not_execute_refused',
      clear_to_execute: false,
      reasons: ['physical measurement retirement state is unavailable or malformed'],
    });
  });

  it('latches the executor closed after an indeterminate storage outcome', async () => {
    const a = action();
    const challengeStore = store();
    const gate = executor({
      challengeStore,
      clearanceStore: { consume: async () => { throw new Error('response lost'); } },
    });
    const challenge = await gate.issueChallenge(a, { nonce: challengeNonce('m2m-storage-freeze') });
    let effects = 0;
    const result = await gate.run({
      action: a,
      challenge,
      graph: buildModelToMatterGraph(a, evidenceSet(a)),
    }, async () => { effects++; });

    expect(result).toMatchObject({
      ok: false,
      allow: false,
      clearance: {
        verdict: 'do_not_execute_refused',
        clear_to_execute: false,
        reconciliation_required: true,
      },
    });
    expect(effects).toBe(0);
    expect(gate.status()).toMatchObject({ frozen: true, reconciliation_required: true });

    const frozen = await gate.evaluate({ action: a, challenge, graph: buildModelToMatterGraph(a, evidenceSet(a)) });
    expect(frozen).toMatchObject({
      verdict: 'do_not_execute_refused',
      clear_to_execute: false,
      reconciliation_required: true,
    });
    await expect(gate.issueChallenge(a, { nonce: challengeNonce('m2m-after-freeze') })).rejects.toThrow(/frozen/i);
  });

  it('requires explicit durable custody in production mode', () => {
    const p = profile();
    const revocationProvider = async () => new Set();
    const physicalMeasurementProvider = async () => new Set();
    expect(() => createModelToMatterExecutor({
      profile: p,
      challengeStore: store(),
      clearanceStore: actionStore(),
      revocationProvider,
      physicalMeasurementProvider,
    })).toThrow(/durable body-bound atomic challenge custody/);

    const challengeBackend = Object.assign(createMemoryBackend(), { durable: true });
    const clearanceBackend = Object.assign(createMemoryBackend(), { durable: true });
    expect(() => createModelToMatterExecutor({
      profile: p,
      challengeStore: createDurableChallengeStore(challengeBackend),
      clearanceStore: createDurableConsumptionStore(clearanceBackend),
      revocationProvider,
      physicalMeasurementProvider,
    })).not.toThrow();

    for (const config of [
      { profile: null },
      { challengeStore: null },
      { clearanceStore: null },
      { revocationProvider: null },
      { physicalMeasurementProvider: null },
      { challengeTtlSec: 0 },
      { challengeTtlSec: 86401 },
    ]) {
      expect(() => executor(config)).toThrow();
    }
  });
});

describe('EP Model-to-Matter post-execution effect receipt', () => {
  it('requires executor and independent observations before outcome reconciliation', () => {
    const predictions = [
      {
        effect_type: 'executor_status', target: 'facility:safe-demo-01',
        required_source_role: 'executor', required_source_class: 'cloud_lab',
        predicate: { op: 'eq', value: 'completed' },
      },
      {
        effect_type: 'sensor_result', target: 'facility:safe-demo-01',
        required_source_role: 'independent_observer', required_source_class: 'facility_sensor',
        predicate: { op: 'eq', value: 'within_approved_bounds' },
      },
    ];
    const a = action({
      experiment: {
        ...ACTION_INPUT.experiment,
        expected_effects_digest: predictedEffectsDigest(predictions),
      },
    });
    const clearance = {
      '@version': M2M_CLEARANCE_VERSION,
      verdict: 'clear_to_execute',
      action_digest: modelToMatterActionDigest(a),
      action_caid: modelToMatterCaid(a).caid,
      replay_digest: digest('outcome-clearance-replay'),
    };
    const observerKey = crypto.generateKeyPairSync('ed25519').privateKey;
    const receiptId = `ep:m2m:clearance:${clearance.replay_digest.slice('sha256:'.length)}`;
    const common = {
      receipt_id: receiptId,
      receipt_digest: clearance.replay_digest,
      action_hash: modelToMatterActionDigest(a),
      action_caid: modelToMatterCaid(a).caid,
      consumption_nonce: clearance.replay_digest,
      operation_id: 'm2m:operation:001',
    };
    const executorEffects = [
      { effect_type: 'executor_status', target: a.executor.facility_id, value: 'completed' },
    ];
    const observations = [
      buildOutcomeObservation({
        ...common,
        source: {
          role: 'executor', source_id: a.executor.executor_id,
          source_class: 'cloud_lab', facility_id: a.executor.facility_id,
        },
        observed_from: '2026-07-11T16:01:00Z',
        observed_until: '2026-07-11T16:01:00Z',
        attested_at: '2026-07-11T16:01:01Z',
        observed_effects: executorEffects,
        signer: { privateKey: executorKey },
      }),
      buildOutcomeObservation({
        ...common,
        source: {
          role: 'independent_observer', source_id: 'sensor:facility-safe-demo-01',
          source_class: 'facility_sensor', facility_id: a.executor.facility_id,
        },
        observed_from: '2026-07-11T16:01:00Z',
        observed_until: '2026-07-11T16:02:00Z',
        attested_at: '2026-07-11T16:02:01Z',
        observed_effects: [
          { effect_type: 'sensor_result', target: a.executor.facility_id, value: 'within_approved_bounds' },
        ],
        signer: { privateKey: observerKey },
      }),
    ];
    const effect = signModelToMatterEffect({
      action: a,
      clearance,
      executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T16:01:00Z',
      status: 'completed',
      observed_effect_digest: observedEffectsDigest(executorEffects),
    }, executorKey);
    const opts = {
      expectedOperationId: common.operation_id,
      now: '2026-07-11T16:03:00Z',
      pinnedExecutorKeys: [{ executor_id: a.executor.executor_id, public_key: publicKey(executorKey) }],
      sourceKeys: {
        [a.executor.executor_id]: {
          public_key: publicKey(executorKey), role: 'executor',
          source_class: 'cloud_lab', facility_id: a.executor.facility_id,
          control_domain_id: 'control-domain:cloud-lab', status: 'active',
          valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z',
        },
        'sensor:facility-safe-demo-01': {
          public_key: publicKey(observerKey), role: 'independent_observer',
          source_class: 'facility_sensor', facility_id: a.executor.facility_id,
          control_domain_id: 'control-domain:facility-sensor', status: 'active',
          valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z',
        },
      },
      sourceRequirements: [
        { role: 'executor', source_class: 'cloud_lab', min_distinct_sources: 1, distinct_by: ['key', 'control_domain'] },
        { role: 'independent_observer', source_class: 'facility_sensor', min_distinct_sources: 1, distinct_by: ['key', 'control_domain'] },
      ],
      observationWindows: [
        {
          role: 'executor', source_class: 'cloud_lab', relation: 'exact',
          not_before: '2026-07-11T16:01:00Z', not_after: '2026-07-11T16:01:00Z',
          max_attestation_delay_ms: 5_000,
        },
        {
          role: 'independent_observer', source_class: 'facility_sensor', relation: 'exact',
          not_before: '2026-07-11T16:01:00Z', not_after: '2026-07-11T16:02:00Z',
          max_attestation_delay_ms: 5_000,
        },
      ],
    };
    const result = verifyModelToMatterOutcome({
      action: a, clearance, effect, predicted_effects: predictions, observations,
    }, opts);
    expect(result).toMatchObject({ accepted: true, lifecycle_state: 'reconciled', outcome: 'in_bounds' });
    expect(result.establishes_physical_truth).toBe(false);

    const clearanceMismatch = verifyModelToMatterOutcome({
      action: a,
      clearance: { ...clearance, action_digest: digest('different-action') },
      effect,
      predicted_effects: predictions,
      observations,
    }, opts);
    expect(clearanceMismatch).toMatchObject({
      accepted: false,
      lifecycle_state: 'indeterminate',
      reason: 'clearance_binding_mismatch',
    });

    const predictionMismatch = verifyModelToMatterOutcome({
      action: a, clearance, effect, predicted_effects: [], observations,
    }, opts);
    expect(predictionMismatch).toMatchObject({
      accepted: false,
      lifecycle_state: 'indeterminate',
      reason: 'predicted_effects_not_bound_to_action',
    });

    const executorObservationMismatch = verifyModelToMatterOutcome({
      action: a,
      clearance,
      effect,
      predicted_effects: predictions,
      observations: [
        { ...observations[0], observed_effects_digest: digest('different-observed-effects') },
        observations[1],
      ],
    }, opts);
    expect(executorObservationMismatch).toMatchObject({
      accepted: false,
      lifecycle_state: 'indeterminate',
      reason: 'executor_effect_not_bound_to_executor_observation',
    });

    const missingObserver = verifyModelToMatterOutcome({
      action: a, clearance, effect, predicted_effects: predictions, observations: observations.slice(0, 1),
    }, opts);
    expect(missingObserver).toMatchObject({ accepted: false, lifecycle_state: 'indeterminate', outcome: null });
  });

  it('signs and verifies the executor statement against the clearance and pinned executor', () => {
    const a = action();
    const clearance = {
      '@version': M2M_CLEARANCE_VERSION,
      verdict: 'clear_to_execute',
      action_digest: modelToMatterActionDigest(a),
      action_caid: modelToMatterCaid(a).caid,
      replay_digest: digest('clearance-replay'),
    };
    const effect = signModelToMatterEffect({
      action: a,
      clearance,
      executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T16:01:00Z',
      status: 'completed',
      observed_effect_digest: digest('opaque-observed-result'),
    }, executorKey);
    expect(effect['@version']).toBe(M2M_EFFECT_VERSION);

    const result = verifyModelToMatterEffect(effect, {
      expectedAction: a,
      expectedClearanceReplayDigest: clearance.replay_digest,
      pinnedExecutorKeys: [{ executor_id: a.executor.executor_id, public_key: publicKey(executorKey) }],
    });
    expect(result.verified).toBe(true);
    expect(result.accepted).toBe(true);
    expect(result.establishes_physical_truth).toBe(false);
  });

  it('will not mint an effect receipt from a refusal and rejects executor or payload substitution', () => {
    const a = action();
    const refused = {
      '@version': M2M_CLEARANCE_VERSION,
      verdict: 'do_not_execute_missing_evidence',
      action_digest: modelToMatterActionDigest(a),
      action_caid: modelToMatterCaid(a).caid,
      replay_digest: digest('refusal-replay'),
    };
    expect(() => signModelToMatterEffect({
      action: a, clearance: refused, executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T16:01:00Z', status: 'completed',
      observed_effect_digest: digest('result'),
    }, executorKey)).toThrow(/clear_to_execute/);

    expect(() => signModelToMatterEffect({
      action: a,
      clearance: { ...refused, verdict: 'clear_to_execute' },
      executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T15:57:00Z',
      status: 'completed',
      observed_effect_digest: digest('result'),
    }, executorKey)).toThrow(/before the action/i);

    expect(() => signModelToMatterEffect({
      action: a,
      clearance: {
        ...refused,
        verdict: 'clear_to_execute',
        action_caid: modelToMatterCaid(action({ destination_digest: digest('other') })).caid,
      },
      executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T16:01:00Z',
      status: 'completed',
      observed_effect_digest: digest('result'),
    }, executorKey)).toThrow(/different CAID/i);

    const clearance = { ...refused, verdict: 'clear_to_execute' };
    const effect = signModelToMatterEffect({
      action: a, clearance, executor_id: a.executor.executor_id,
      executed_at: '2026-07-11T16:01:00Z', status: 'completed',
      observed_effect_digest: digest('result'),
    }, executorKey);
    const opts = {
      expectedAction: a,
      expectedClearanceReplayDigest: clearance.replay_digest,
      pinnedExecutorKeys: [{ executor_id: a.executor.executor_id, public_key: publicKey(executorKey) }],
    };
    expect(verifyModelToMatterEffect({ ...effect, status: 'failed' }, opts).accepted).toBe(false);
    expect(verifyModelToMatterEffect(effect, {
      ...opts,
      pinnedExecutorKeys: [{ executor_id: 'cloud-lab:attacker', public_key: publicKey(executorKey) }],
    }).reason).toBe('executor_key_not_pinned');
  });
});
