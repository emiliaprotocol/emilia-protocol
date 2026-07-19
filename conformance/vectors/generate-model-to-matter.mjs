// SPDX-License-Identifier: Apache-2.0
// Generate deterministic EP-MODEL-TO-MATTER-v1 public vectors.

import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  M2M_CLEARANCE_VERSION,
  M2M_CAID_ACTION_TYPE,
  M2M_EVIDENCE_TYPES,
  createModelToMatterAction,
  createModelToMatterProfile,
  modelToMatterActionDigest,
  modelToMatterCaid,
  signModelToMatterEffect,
  signModelToMatterEvidence,
} from '../../lib/frontier/model-to-matter.js';

const ISSUED_AT = '2026-07-19T11:59:00Z';
const AS_OF = '2026-07-19T12:00:00Z';
const EXPIRES_AT = '2026-07-19T12:10:00Z';
const CHALLENGE_EXPIRES_AT = '2026-07-19T12:05:00Z';
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function digest(label) {
  return `sha256:${sha256(label)}`;
}

function testPrivateKey(label) {
  const seed = crypto.createHash('sha256').update(`EP-M2M-v1 deterministic test key: ${label}`).digest();
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

function publicKey(privateKey) {
  return crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
}

const action = createModelToMatterAction({
  action_type: M2M_CAID_ACTION_TYPE,
  model: {
    provider: 'example-frontier-model-provider',
    model_id: 'defensive-science-model-1',
    manifest_digest: digest('model-manifest'),
    harness_digest: digest('executor-harness'),
    safeguards_digest: digest('deployment-safeguards'),
  },
  experiment: {
    protocol_digest: digest('opaque-benign-protocol'),
    materials_commitment: digest('opaque-benign-materials'),
    expected_effects_digest: digest('approved-effect-criteria'),
  },
  principal: {
    organization_id: 'org:example-research-institute',
    principal_id: 'researcher:alice',
  },
  executor: {
    executor_id: 'cloud-lab:example',
    facility_id: 'facility:demo-01',
  },
  purpose: {
    code: 'defensive-research',
    jurisdiction: 'US',
  },
  destination_digest: digest('approved-destination'),
  requested_at: '2026-07-19T11:58:00Z',
  max_executions: 1,
});

const issuerKeys = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, testPrivateKey(type)]));
const acceptedIssuers = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, [{
  issuer_id: `issuer:${type}`,
  public_key: publicKey(issuerKeys[type]),
}]]));
const profile = createModelToMatterProfile({
  profile_id: 'ep:m2m:conformance:v1',
  accepted_issuers: acceptedIssuers,
});

function claimsFor(type, overrides = {}) {
  const claims = {
    model_attestation: {
      provider: action.model.provider,
      model_id: action.model.model_id,
      manifest_digest: action.model.manifest_digest,
      harness_digest: action.model.harness_digest,
      safeguards_digest: action.model.safeguards_digest,
    },
    safety_case_attestation: {
      manifest_digest: action.model.manifest_digest,
      harness_digest: action.model.harness_digest,
      safeguards_digest: action.model.safeguards_digest,
      safety_case_digest: digest('safety-case'),
      assessment: 'acceptable',
    },
    institutional_authority: {
      organization_id: action.principal.organization_id,
      principal_id: action.principal.principal_id,
      action_type: action.action_type,
      purpose_code: action.purpose.code,
      decision: 'allow',
    },
    biosafety_review: {
      protocol_digest: action.experiment.protocol_digest,
      materials_commitment: action.experiment.materials_commitment,
      facility_id: action.executor.facility_id,
      decision: 'approve',
    },
    domain_screening: {
      materials_commitment: action.experiment.materials_commitment,
      destination_digest: action.destination_digest,
      screening_profile_digest: digest('screening-profile'),
      decision: 'pass',
    },
    human_authorization: {
      approver_id: 'person:responsible-investigator',
      decision: 'approve',
      assurance_class: 'class_a',
    },
  };
  return { ...claims[type], ...overrides };
}

function signEvidence(type, {
  privateKey = issuerKeys[type],
  issuerId = `issuer:${type}`,
  issuedAt = ISSUED_AT,
  expiresAt = EXPIRES_AT,
  outcome,
  claims = {},
} = {}) {
  return signModelToMatterEvidence({
    evidence_type: type,
    action_digest: modelToMatterActionDigest(action),
    issuer_id: issuerId,
    issued_at: issuedAt,
    expires_at: expiresAt,
    claims: claimsFor(type, claims),
    ...(outcome === undefined ? {} : { outcome }),
  }, privateKey);
}

const valid = M2M_EVIDENCE_TYPES.map((type) => signEvidence(type));
function replace(type, artifact) {
  return valid.map((candidate) => candidate.evidence_type === type ? artifact : candidate);
}

const evidenceSets = {
  valid,
  missing_domain_screening: valid.filter((artifact) => artifact.evidence_type !== 'domain_screening'),
  unpinned_domain_screening: replace('domain_screening', signEvidence('domain_screening', {
    privateKey: testPrivateKey('attacker'),
  })),
  expired_domain_screening: replace('domain_screening', signEvidence('domain_screening', {
    issuedAt: '2026-07-19T11:40:00Z',
    expiresAt: '2026-07-19T11:50:00Z',
  })),
  denied_biosafety: replace('biosafety_review', signEvidence('biosafety_review', {
    outcome: 'deny',
    claims: { decision: 'deny' },
  })),
  weak_human: replace('human_authorization', signEvidence('human_authorization', {
    claims: { assurance_class: 'software' },
  })),
};

const humanEvidence = valid.find((artifact) => artifact.evidence_type === 'human_authorization');
const executorKey = testPrivateKey('executor');
const effect = signModelToMatterEffect({
  action,
  clearance: {
    '@version': M2M_CLEARANCE_VERSION,
    verdict: 'clear_to_execute',
    action_digest: modelToMatterActionDigest(action),
    action_caid: modelToMatterCaid(action).caid,
    replay_digest: digest('clearance-replay'),
  },
  executor_id: action.executor.executor_id,
  executed_at: '2026-07-19T12:01:00Z',
  status: 'completed',
  observed_effect_digest: digest('opaque-observed-effect'),
}, executorKey);

const suite = {
  suite: 'EP-MODEL-TO-MATTER-v1',
  vectors_version: '2026-07-19',
  note: 'Deterministic public test material only. These vectors test executor-side authorization-evidence clearance; they do not screen biological content or establish scientific safety or physical truth.',
  as_of: AS_OF,
  challenge_expires_at: CHALLENGE_EXPIRES_AT,
  action,
  caid: modelToMatterCaid(action),
  profile,
  evidence_sets: evidenceSets,
  effect_fixture: {
    effect,
    expected_clearance_replay_digest: digest('clearance-replay'),
    executor_pin: {
      executor_id: action.executor.executor_id,
      public_key: publicKey(executorKey),
    },
  },
  vectors: [
    { id: 'accept_registered_caid', kind: 'caid', expect: { valid: true } },
    { id: 'refuse_caid_action_substitution', kind: 'caid', action_overrides: { destination_digest: digest('other-caid-destination') }, expect: { valid: false } },
    { id: 'accept_complete_evidence', kind: 'presentation', evidence_set: 'valid', expect: { verdict: 'clear_to_execute' } },
    { id: 'refuse_missing_domain_screening', kind: 'presentation', evidence_set: 'missing_domain_screening', expect: { verdict: 'do_not_execute_missing_evidence' } },
    { id: 'refuse_unpinned_domain_screening', kind: 'presentation', evidence_set: 'unpinned_domain_screening', expect: { verdict: 'do_not_execute_unverifiable' } },
    { id: 'refuse_expired_domain_screening', kind: 'presentation', evidence_set: 'expired_domain_screening', expect: { verdict: 'do_not_execute_unverifiable' } },
    { id: 'refuse_revoked_human_authorization', kind: 'presentation', evidence_set: 'valid', revoked_evidence_digests: [humanEvidence.signature.evidence_digest], expect: { verdict: 'do_not_execute_stale_evidence' } },
    { id: 'refuse_denied_biosafety_review', kind: 'presentation', evidence_set: 'denied_biosafety', expect: { verdict: 'do_not_execute_unverifiable' } },
    { id: 'refuse_weak_human_authorization', kind: 'presentation', evidence_set: 'weak_human', expect: { verdict: 'do_not_execute_unverifiable' } },
    { id: 'refuse_action_mutation_after_challenge', kind: 'presentation', evidence_set: 'valid', action_overrides: { destination_digest: digest('mutated-destination') }, expect: { verdict: 'do_not_execute_action_mismatch' } },
    { id: 'refuse_indeterminate_clearance_storage', kind: 'presentation', evidence_set: 'valid', clearance_store: 'throw', expect: { verdict: 'do_not_execute_refused', reconciliation_required: true } },
    { id: 'refuse_same_challenge_replay', kind: 'same_challenge_replay', evidence_set: 'valid', expect: { verdicts: ['clear_to_execute', 'do_not_execute_refused'] } },
    { id: 'admit_at_most_one_of_two_challenges', kind: 'two_challenge_race', evidence_set: 'valid', expect: { verdicts: ['clear_to_execute', 'do_not_execute_refused'] } },
    { id: 'accept_pinned_executor_effect', kind: 'effect', expect: { accepted: true } },
    { id: 'refuse_tampered_executor_effect', kind: 'effect', tamper: { status: 'failed' }, expect: { accepted: false } },
  ],
};

const output = fileURLToPath(new URL('./model-to-matter.v1.json', import.meta.url));
writeFileSync(output, `${JSON.stringify(suite, null, 2)}\n`);
console.log(`wrote ${suite.vectors.length} Model-to-Matter vectors to ${output}`);
