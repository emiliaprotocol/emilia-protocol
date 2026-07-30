#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Deterministic public vectors for EP-BOUNDED-EXECUTION-PROGRAM-v1.
// Run with: node --import ./scripts/ts-loader/register.mjs \
//   conformance/vectors/generate-bounded-execution-program.mjs [--check]

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  BOUNDED_EXECUTION_PROGRAM_VERSION,
  EXECUTION_PROGRAM_CLAIM_BOUNDARY,
  executionProgramDigest,
  signBoundedExecutionProgram,
  verifyBoundedExecutionProgram,
} from '../../packages/gate/bounded-execution-program.js';
import {
  ADMISSION_CURRENTNESS_VERSION,
  EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION,
  EXECUTION_PROGRAM_STATUS_VERSION,
  createAdmissionSnapshot,
  createMemoryAdmissionStore,
  createExecutionProgramAdmissionBinding as createReferenceExecutionProgramAdmissionBinding,
} from '../../packages/gate/src/admission-store.ts';
import { canonicalize } from '../../packages/gate/execution-binding.js';

const OUTPUT = fileURLToPath(new URL('./bounded-execution-program.v1.json', import.meta.url));
const VECTOR_VERSION = '1.2.0';
const NOW = '2026-07-29T20:15:00.000Z';
const ADMISSION_EXPIRES_AT = '2026-07-29T20:45:00.000Z';
const ED25519_PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const clone = (value) => structuredClone(value);
const byteOrder = (left, right) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
/**
 * @param {string} label
 * @returns {import('../../packages/gate/src/admission-store.ts').AdmissionDigest}
 */
const digest = (label) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const caid = (label) => (
  `caid:1:devops.infrastructure-change.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`
);

function executionProgramAdmissionBinding(input) {
  const bindingBody = {
    '@version': EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION,
    tenant_id: input.tenant_id,
    program_digest: input.program_digest,
    node_id: input.node_id,
    occurrence_id: input.occurrence_id,
    expires_at: new Date(Date.parse(input.expires_at)).toISOString(),
  };
  const identityTuple = [
    bindingBody.tenant_id,
    bindingBody.program_digest,
    bindingBody.node_id,
    bindingBody.occurrence_id,
  ];
  const identityDomain = `${EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION}:IDENTITY`;
  const identityDigest = `sha256:${crypto.createHash('sha256')
    .update(identityDomain)
    .update('\0')
    .update(canonicalize(identityTuple))
    .digest('hex')}`;
  const digestDomain = `${EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION}:DIGEST`;
  const resource = {
    kind: 'execution_program',
    resource_id: `execution-program:${identityDigest}`,
    reservation_id: `execution-program-reservation:${identityDigest}`,
    digest: `sha256:${crypto.createHash('sha256')
      .update(digestDomain)
      .update('\0')
      .update(canonicalize(bindingBody))
      .digest('hex')}`,
    expires_at: bindingBody.expires_at,
  };
  assert.deepEqual(
    resource,
    createReferenceExecutionProgramAdmissionBinding(input),
    'language-neutral admission binding disagrees with current AdmissionStore source',
  );
  return {
    identity_tuple: identityTuple,
    identity_domain: identityDomain,
    identity_digest: identityDigest,
    binding_body: bindingBody,
    digest_domain: digestDomain,
    resource,
  };
}

function deterministicEd25519(label) {
  const seed = crypto.createHash('sha256')
    .update(`EP-BOUNDED-EXECUTION-PROGRAM-v1 public conformance key\0${label}`)
    .digest();
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

const PROGRAM_KEY = deterministicEd25519('program-authorizer');
const PROGRAM_PUBLIC_KEY = crypto.createPublicKey(
  PROGRAM_KEY.export({ type: 'pkcs8', format: 'pem' }),
)
  .export({ type: 'spki', format: 'der' }).toString('base64url');
const SIGNER = {
  issuer_id: 'customer:example-security',
  key_id: 'key:bounded-program-authorizer',
  private_key: PROGRAM_KEY,
};

const BASE_INPUT = {
  program_id: 'program:production-remediation:01',
  tenant_id: 'tenant:example',
  version: 1,
  subject_id: 'agent:operations:01',
  audience: 'gate:production:01',
  objective_digest: digest('objective:production-remediation'),
  authorization_digest: digest('authorization:production-remediation'),
  presentation_digest: digest('presentation:production-remediation'),
  supersedes_program_digest: null,
  issued_at: '2026-07-29T19:55:00Z',
  valid_from: '2026-07-29T20:00:00Z',
  expires_at: '2026-07-29T21:00:00Z',
  max_total_occurrences: 3,
  // Intentionally unsorted. Canonical signing sorts budget_id bytewise.
  budgets: [
    { budget_id: 'change-risk', unit: 'risk-point', limit: 5 },
    { budget_id: 'attempts', unit: 'attempt', limit: 3 },
  ],
  // Intentionally unsorted. Canonical signing sorts node_id bytewise.
  nodes: [
    {
      node_id: 'verify',
      action: {
        mode: 'exact',
        caid: caid('action:verify'),
        action_digest: digest('action:verify'),
      },
      trust_program_digest: digest('trust-program:verify'),
      depends_on: [{
        node_id: 'remediate',
        // Intentionally unsorted. Canonical signing sorts terminal outcomes.
        outcomes: ['PROVEN_NOT_COMMITTED', 'COMMITTED'],
      }],
      max_occurrences: 1,
      charges: [
        { budget_id: 'change-risk', amount: 1 },
        { budget_id: 'attempts', amount: 1 },
      ],
    },
    {
      node_id: 'inspect',
      action: {
        mode: 'exact',
        caid: caid('action:inspect'),
        action_digest: digest('action:inspect'),
      },
      trust_program_digest: digest('trust-program:inspect'),
      depends_on: [],
      max_occurrences: 1,
      charges: [
        { budget_id: 'change-risk', amount: 1 },
        { budget_id: 'attempts', amount: 1 },
      ],
    },
    {
      node_id: 'rollback',
      action: {
        mode: 'exact',
        caid: caid('action:rollback'),
        action_digest: digest('action:rollback'),
      },
      trust_program_digest: digest('trust-program:rollback'),
      depends_on: [],
      max_occurrences: 1,
      charges: [
        { budget_id: 'change-risk', amount: 5 },
        { budget_id: 'attempts', amount: 1 },
      ],
    },
    {
      node_id: 'remediate',
      action: {
        mode: 'profile',
        profile_id: 'profile:terraform-reviewed-plan',
        profile_digest: digest('profile:terraform-reviewed-plan'),
      },
      trust_program_digest: digest('trust-program:remediate'),
      depends_on: [{ node_id: 'inspect', outcomes: ['COMMITTED'] }],
      max_occurrences: 1,
      charges: [
        { budget_id: 'change-risk', amount: 3 },
        { budget_id: 'attempts', amount: 1 },
      ],
    },
  ],
};

const BASE_ARTIFACT = signBoundedExecutionProgram(BASE_INPUT, SIGNER);
const BASE_PROGRAM_DIGEST = executionProgramDigest(BASE_ARTIFACT);
const SUCCESSOR_INPUT = {
  ...clone(BASE_INPUT),
  version: 2,
  authorization_digest: digest('authorization:production-remediation:v2'),
  supersedes_program_digest: BASE_PROGRAM_DIGEST,
};
const SUCCESSOR_ARTIFACT = signBoundedExecutionProgram(SUCCESSOR_INPUT, SIGNER);
const SKIPPED_SUCCESSOR_INPUT = {
  ...clone(BASE_INPUT),
  version: 3,
  authorization_digest: digest('authorization:production-remediation:v3'),
  supersedes_program_digest: BASE_PROGRAM_DIGEST,
};
const SKIPPED_SUCCESSOR_ARTIFACT = signBoundedExecutionProgram(SKIPPED_SUCCESSOR_INPUT, SIGNER);

const REUSED_AUTHORIZATION_SUCCESSOR_INPUT = {
  ...clone(SUCCESSOR_INPUT),
  authorization_digest: BASE_INPUT.authorization_digest,
};
const REUSED_AUTHORIZATION_SUCCESSOR_ARTIFACT = signBoundedExecutionProgram(
  REUSED_AUTHORIZATION_SUCCESSOR_INPUT,
  SIGNER,
);

const FROZEN_SUBJECT_SUCCESSOR_INPUT = {
  ...clone(SUCCESSOR_INPUT),
  subject_id: 'agent:substituted',
};
const FROZEN_SUBJECT_SUCCESSOR_ARTIFACT = signBoundedExecutionProgram(
  FROZEN_SUBJECT_SUCCESSOR_INPUT,
  SIGNER,
);

const TOTAL_OCCURRENCE_INPUT = {
  ...clone(BASE_INPUT),
  program_id: 'program:total-occurrence-ceiling:01',
  objective_digest: digest('objective:total-occurrence-ceiling'),
  authorization_digest: digest('authorization:total-occurrence-ceiling'),
  presentation_digest: digest('presentation:total-occurrence-ceiling'),
  max_total_occurrences: 2,
  budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 10 }],
  nodes: [{
    ...clone(BASE_INPUT.nodes.find((node) => node.node_id === 'inspect')),
    max_occurrences: 3,
    charges: [{ budget_id: 'attempts', amount: 1 }],
  }],
};
const TOTAL_OCCURRENCE_ARTIFACT = signBoundedExecutionProgram(TOTAL_OCCURRENCE_INPUT, SIGNER);

const DUPLICATE_UNIT_INPUT = {
  ...clone(BASE_INPUT),
  program_id: 'program:duplicate-unit-budgets:01',
  objective_digest: digest('objective:duplicate-unit-budgets'),
  authorization_digest: digest('authorization:duplicate-unit-budgets'),
  presentation_digest: digest('presentation:duplicate-unit-budgets'),
  max_total_occurrences: 1,
  budgets: [
    { budget_id: 'attempts+foreground', unit: 'attempt', limit: 1 },
    { budget_id: 'attempts+background', unit: 'attempt', limit: 2 },
  ],
  nodes: [{
    ...clone(BASE_INPUT.nodes.find((node) => node.node_id === 'inspect')),
    charges: [{ budget_id: 'attempts+foreground', amount: 1 }],
  }],
};
const DUPLICATE_UNIT_ARTIFACT = signBoundedExecutionProgram(DUPLICATE_UNIT_INPUT, SIGNER);

function unsignedPayload(artifact) {
  const { issuer: _issuer, proof: _proof, ...payload } = clone(artifact);
  return payload;
}

/** Sign exact payload bytes without running the bounded-program normalizer. */
function signRawPayload(payload) {
  const body = JSON.parse(canonicalize({
    ...clone(payload),
    issuer: { id: SIGNER.issuer_id, key_id: SIGNER.key_id },
  }));
  const bodyJcs = canonicalize(body);
  return {
    ...body,
    proof: {
      algorithm: 'Ed25519',
      key_id: SIGNER.key_id,
      body_digest: `sha256:${crypto.createHash('sha256').update(bodyJcs, 'utf8').digest('hex')}`,
      signature_b64u: crypto.sign(
        null,
        Buffer.from(`${BOUNDED_EXECUTION_PROGRAM_VERSION}\0${bodyJcs}`, 'utf8'),
        PROGRAM_KEY,
      ).toString('base64url'),
    },
  };
}

function mutatePayload(mutator) {
  const payload = unsignedPayload(BASE_ARTIFACT);
  mutator(payload);
  return signRawPayload(payload);
}

const tamperedCharge = clone(BASE_ARTIFACT);
tamperedCharge.nodes.find((node) => node.node_id === 'remediate')
  .charges.find((charge) => charge.budget_id === 'change-risk').amount = 2;

const hostileArtifacts = {
  tampered_charge_after_signature: tamperedCharge,
  signed_unknown_field: mutatePayload((payload) => { payload.unrecognized = true; }),
  signed_noncanonical_budget_order: mutatePayload((payload) => { payload.budgets.reverse(); }),
  signed_cycle: mutatePayload((payload) => {
    payload.nodes.find((node) => node.node_id === 'inspect').depends_on = [
      { node_id: 'verify', outcomes: ['COMMITTED'] },
    ];
  }),
  signed_claim_boundary_substitution: mutatePayload((payload) => {
    payload.claim_boundary = 'intent_and_safety_verified';
  }),
  signed_successor_without_predecessor: (() => {
    const payload = unsignedPayload(SUCCESSOR_ARTIFACT);
    payload.supersedes_program_digest = null;
    return signRawPayload(payload);
  })(),
  signed_charge_above_budget: mutatePayload((payload) => {
    payload.nodes.find((node) => node.node_id === 'rollback')
      .charges.find((charge) => charge.budget_id === 'change-risk').amount = 6;
  }),
  signed_profile_without_digest: mutatePayload((payload) => {
    const action = payload.nodes.find((node) => node.node_id === 'remediate').action;
    delete action.profile_digest;
  }),
  signed_duplicate_dependency_outcome: mutatePayload((payload) => {
    payload.nodes.find((node) => node.node_id === 'verify')
      .depends_on[0].outcomes = ['COMMITTED', 'COMMITTED'];
  }),
  signed_indeterminate_dependency: mutatePayload((payload) => {
    payload.nodes.find((node) => node.node_id === 'verify')
      .depends_on[0].outcomes = ['INDETERMINATE'];
  }),
  signed_missing_total_occurrence_ceiling: mutatePayload((payload) => {
    delete payload.max_total_occurrences;
  }),
  signed_excessive_total_occurrence_ceiling: mutatePayload((payload) => {
    payload.max_total_occurrences = 1_000_001;
  }),
};

const ARTIFACTS = {
  base: BASE_ARTIFACT,
  successor: SUCCESSOR_ARTIFACT,
  skipped_successor: SKIPPED_SUCCESSOR_ARTIFACT,
  reused_authorization_successor: REUSED_AUTHORIZATION_SUCCESSOR_ARTIFACT,
  frozen_subject_successor: FROZEN_SUBJECT_SUCCESSOR_ARTIFACT,
  total_occurrence_limit: TOTAL_OCCURRENCE_ARTIFACT,
  duplicate_unit_budgets: DUPLICATE_UNIT_ARTIFACT,
  ...hostileArtifacts,
};

const TRUSTED_KEYS = {
  [SIGNER.key_id]: {
    issuer_id: SIGNER.issuer_id,
    public_key: PROGRAM_PUBLIC_KEY,
  },
};
const STORE_VERIFICATION_POLICY = {
  trusted_keys: {
    [SIGNER.key_id]: {
      issuer_id: SIGNER.issuer_id,
      public_key: PROGRAM_PUBLIC_KEY,
      role: 'program_authorizer',
      status: 'ACTIVE',
    },
  },
};
const DEFAULT_STORE_CONFIGURATION = {
  clock: NOW,
  execution_program_verification_policy: STORE_VERIFICATION_POLICY,
  max_execution_program_status_age_ms: 5_000,
  status_oracle: 'mutable_authenticated_status_fixture',
  action_match_verifier: 'authenticated_exact_projection',
};
const STORE_CONFIGURATIONS = {
  active: DEFAULT_STORE_CONFIGURATION,
  suspended_authorizer: {
    ...clone(DEFAULT_STORE_CONFIGURATION),
    execution_program_verification_policy: {
      trusted_keys: {
        [SIGNER.key_id]: {
          ...clone(STORE_VERIFICATION_POLICY.trusted_keys[SIGNER.key_id]),
          status: 'SUSPENDED',
        },
      },
    },
  },
  revoked_authorizer: {
    ...clone(DEFAULT_STORE_CONFIGURATION),
    execution_program_verification_policy: {
      trusted_keys: {
        [SIGNER.key_id]: {
          ...clone(STORE_VERIFICATION_POLICY.trusted_keys[SIGNER.key_id]),
          status: 'REVOKED',
        },
      },
    },
  },
  expired_clock: {
    ...clone(DEFAULT_STORE_CONFIGURATION),
    clock: '2026-07-29T21:00:00.000Z',
  },
  status_oracle: {
    ...clone(DEFAULT_STORE_CONFIGURATION),
    status_oracle: 'mutable_authenticated_status_fixture',
  },
};
const VERIFICATION_CONTEXT = {
  now: NOW,
  expected_program_id: BASE_INPUT.program_id,
  expected_tenant_id: BASE_INPUT.tenant_id,
  expected_authorizer_id: SIGNER.issuer_id,
  expected_authorization_digest: BASE_INPUT.authorization_digest,
  expected_audience: BASE_INPUT.audience,
};

function verificationOptions(common, entry) {
  const options = {
    trusted_keys: entry.trusted_key_set === 'none' ? {} : clone(common.trusted_keys),
    ...clone(common.verification_context),
  };
  if (entry.omit_relying_party_context) {
    delete options.expected_program_id;
    delete options.expected_tenant_id;
    delete options.expected_authorizer_id;
    delete options.expected_authorization_digest;
    delete options.expected_audience;
  }
  return { ...options, ...(entry.verification_overrides ?? {}) };
}

function verificationProjection(result) {
  return {
    accepted: result.accepted,
    verified: result.verified,
    reason: result.reason,
    program_digest: result.program_digest,
    authorizer_id: result.authorizer_id ?? null,
    claim_boundary: result.claim_boundary,
  };
}

const syntaxDefinitions = [
  {
    id: 'accept_canonical_exact_and_profile_dag_at_valid_from',
    classification: 'positive', artifact: 'base',
    verification_overrides: { now: '2026-07-29T20:00:00.000Z' },
    must: { accepted: true, verified: true, reason: null },
  },
  {
    id: 'accept_canonical_exact_and_profile_dag_inside_window',
    classification: 'positive', artifact: 'base',
    must: { accepted: true, verified: true, reason: null },
  },
  {
    id: 'accept_successor_with_exact_predecessor_digest',
    classification: 'positive', artifact: 'successor',
    verification_overrides: {
      expected_authorization_digest: SUCCESSOR_INPUT.authorization_digest,
    },
    must: { accepted: true, verified: true, reason: null },
  },
  {
    id: 'accept_signed_version_gap_as_syntax_before_runtime_supersession_check',
    classification: 'positive', artifact: 'skipped_successor',
    verification_overrides: {
      expected_authorization_digest: SKIPPED_SUCCESSOR_INPUT.authorization_digest,
    },
    must: { accepted: true, verified: true, reason: null },
  },
  {
    id: 'accept_independent_budget_ids_with_duplicate_unit_labels',
    classification: 'positive', artifact: 'duplicate_unit_budgets',
    verification_overrides: {
      expected_program_id: DUPLICATE_UNIT_INPUT.program_id,
      expected_authorization_digest: DUPLICATE_UNIT_INPUT.authorization_digest,
    },
    must: { accepted: true, verified: true, reason: null },
  },
  {
    id: 'refuse_post_signature_charge_tamper',
    classification: 'hostile', artifact: 'tampered_charge_after_signature',
    must: { accepted: false, verified: false, reason: 'program_signature_invalid' },
  },
  {
    id: 'refuse_untrusted_authorizer_key',
    classification: 'hostile', artifact: 'base', trusted_key_set: 'none',
    must: { accepted: false, verified: false, reason: 'program_issuer_untrusted' },
  },
  {
    id: 'refuse_valid_signature_over_unknown_payload_field',
    classification: 'hostile', artifact: 'signed_unknown_field',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_valid_signature_over_noncanonical_budget_order',
    classification: 'hostile', artifact: 'signed_noncanonical_budget_order',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_valid_signature_over_cycle',
    classification: 'hostile', artifact: 'signed_cycle',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_valid_signature_over_claim_boundary_substitution',
    classification: 'hostile', artifact: 'signed_claim_boundary_substitution',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_successor_without_predecessor_digest',
    classification: 'hostile', artifact: 'signed_successor_without_predecessor',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_node_charge_above_program_budget',
    classification: 'hostile', artifact: 'signed_charge_above_budget',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_profile_action_without_digest_pin',
    classification: 'hostile', artifact: 'signed_profile_without_digest',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_duplicate_terminal_dependency_outcome',
    classification: 'hostile', artifact: 'signed_duplicate_dependency_outcome',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_indeterminate_as_dependency_outcome',
    classification: 'hostile', artifact: 'signed_indeterminate_dependency',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_missing_mandatory_total_occurrence_ceiling',
    classification: 'hostile', artifact: 'signed_missing_total_occurrence_ceiling',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_total_occurrence_ceiling_above_protocol_limit',
    classification: 'hostile', artifact: 'signed_excessive_total_occurrence_ceiling',
    must: { accepted: false, verified: true, reason: 'program_schema_invalid' },
  },
  {
    id: 'refuse_missing_relying_party_context',
    classification: 'hostile', artifact: 'base', omit_relying_party_context: true,
    must: { accepted: false, verified: true, reason: 'context_binding_required' },
  },
  {
    id: 'refuse_authorizer_substitution',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { expected_authorizer_id: 'customer:attacker' },
    must: { accepted: false, verified: true, reason: 'authorizer_mismatch' },
  },
  {
    id: 'refuse_program_id_substitution',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { expected_program_id: 'program:other' },
    must: { accepted: false, verified: true, reason: 'program_id_mismatch' },
  },
  {
    id: 'refuse_tenant_substitution',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { expected_tenant_id: 'tenant:other' },
    must: { accepted: false, verified: true, reason: 'tenant_mismatch' },
  },
  {
    id: 'refuse_authorization_substitution',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { expected_authorization_digest: digest('authorization:other') },
    must: { accepted: false, verified: true, reason: 'authorization_mismatch' },
  },
  {
    id: 'refuse_audience_substitution',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { expected_audience: 'gate:other' },
    must: { accepted: false, verified: true, reason: 'audience_mismatch' },
  },
  {
    id: 'refuse_before_inclusive_activation',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { now: '2026-07-29T19:59:59.999Z' },
    must: { accepted: false, verified: true, reason: 'program_not_active' },
  },
  {
    id: 'refuse_at_exclusive_expiry',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { now: '2026-07-29T21:00:00.000Z' },
    must: { accepted: false, verified: true, reason: 'program_expired' },
  },
  {
    id: 'refuse_invalid_verification_time',
    classification: 'hostile', artifact: 'base',
    verification_overrides: { now: 'not-a-time' },
    must: { accepted: false, verified: true, reason: 'verification_time_invalid' },
  },
];

function compileSyntaxCases(common) {
  return syntaxDefinitions.map(({ must, ...entry }) => {
    const result = verifyBoundedExecutionProgram(
      ARTIFACTS[entry.artifact],
      verificationOptions(common, entry),
    );
    assert.deepEqual(
      { accepted: result.accepted, verified: result.verified, reason: result.reason },
      must,
      `${entry.id}: reference syntax result changed`,
    );
    return { ...entry, expect: verificationProjection(result) };
  });
}

function nodeById(program, nodeId) {
  return program.nodes.find((node) => node.node_id === nodeId);
}

/**
 * @typedef {object} RuntimeSealedEvidence
 * @property {string} role
 * @property {string} subject_id
 * @property {string} payload_digest
 * @property {string} profile_digest
 * @property {string} verifier_id
 * @property {string} trust_configuration_digest
 */

/**
 * Language-neutral admission projection used only by the abstract trace model.
 * The authenticated verifier result is optional because hostile cases omit or
 * substitute it; arbitrary caller assertions remain separately representable.
 *
 * @typedef {object} RuntimeAdmission
 * @property {'input' | 'snapshot'} admission_form
 * @property {string} tenant_id
 * @property {string} subject_id
 * @property {string} authorization_digest
 * @property {string} caid
 * @property {string} action_digest
 * @property {string} authorization_policy_digest
 * @property {string} operation_id
 * @property {number} trust_epoch
 * @property {string} trust_configuration_digest
 * @property {string} expires_at
 * @property {Array<import('../../packages/gate/src/admission-store.ts').AdmissionResourceReservationInput>} execution_program_resources
 * @property {unknown} [action_match_evidence]
 * @property {Record<string, unknown>} [action_match_verification]
 * @property {Record<string, unknown>} [action_match]
 * @property {RuntimeSealedEvidence[]} [sealed_evidence]
 */

/**
 * @param {import('../../packages/gate/src/bounded-execution-program.ts').VerifiedBoundedExecutionProgram} program
 * @param {string} nodeId
 * @param {Partial<RuntimeAdmission>} [overrides]
 * @returns {RuntimeAdmission}
 */
function exactAdmission(program, nodeId, overrides = {}) {
  const node = nodeById(program, nodeId);
  assert.equal(node.action.mode, 'exact');
  return {
    admission_form: 'input',
    tenant_id: program.tenant_id,
    subject_id: program.subject_id,
    authorization_digest: program.authorization_digest,
    caid: node.action.caid,
    action_digest: node.action.action_digest,
    authorization_policy_digest: node.trust_program_digest,
    operation_id: `operation:vector:${nodeId}`,
    trust_epoch: 1,
    trust_configuration_digest: digest('trust-configuration:vector'),
    expires_at: ADMISSION_EXPIRES_AT,
    execution_program_resources: [],
    ...overrides,
  };
}

/**
 * @param {import('../../packages/gate/src/bounded-execution-program.ts').VerifiedBoundedExecutionProgram} program
 * @param {string} nodeId
 * @param {Partial<RuntimeAdmission>} [overrides]
 * @returns {RuntimeAdmission}
 */
function profileAdmission(program, nodeId, overrides = {}) {
  const node = nodeById(program, nodeId);
  assert.equal(node.action.mode, 'profile');
  const evidencePayloadDigest = digest('evidence:profile-action-match');
  /** @type {RuntimeAdmission} */
  const admission = {
    admission_form: 'input',
    tenant_id: program.tenant_id,
    subject_id: program.subject_id,
    authorization_digest: program.authorization_digest,
    caid: caid('action:reviewed-remediation-plan'),
    action_digest: digest('action:reviewed-remediation-plan'),
    authorization_policy_digest: node.trust_program_digest,
    operation_id: `operation:vector:${nodeId}`,
    trust_epoch: 1,
    trust_configuration_digest: digest('trust-configuration:vector'),
    expires_at: ADMISSION_EXPIRES_AT,
    execution_program_resources: [],
    action_match_evidence: { signed_match: 'opaque-verifier-input' },
    sealed_evidence: [{
      role: 'aeb',
      subject_id: program.subject_id,
      payload_digest: evidencePayloadDigest,
      profile_digest: node.action.profile_digest,
      verifier_id: 'verifier:profile-action-match',
      trust_configuration_digest: digest('trust-config:profile-action-match'),
    }],
    ...overrides,
  };
  const evidence = admission.sealed_evidence?.find((entry) => entry.role === 'aeb');
  if (!Object.hasOwn(overrides, 'action_match_verification') && evidence) {
    admission.action_match_verification = {
      valid: true,
      result: 'MATCH',
      tenant_id: admission.tenant_id,
      profile_id: node.action.profile_id,
      profile_digest: node.action.profile_digest,
      subject_id: program.subject_id,
      operation_id: admission.operation_id,
      caid: admission.caid,
      action_digest: admission.action_digest,
      verifier_id: evidence.verifier_id,
      evidence_payload_digest: evidence.payload_digest,
      evidence_trust_configuration_digest: evidence.trust_configuration_digest,
      trust_epoch: admission.trust_epoch,
      trust_configuration_digest: admission.trust_configuration_digest,
    };
  }
  return admission;
}

function runtimeState(storeConfiguration = DEFAULT_STORE_CONFIGURATION) {
  return {
    store_configuration: clone(storeConfiguration),
    initial_clock: storeConfiguration.clock,
    programs: new Map(),
    program_heads: new Map(),
    occurrences: new Map(),
    authorization_claims: new Map(),
    ordinary_admissions: new Map(),
    status_observations: new Map(),
    explicit_status_observations: new Set(),
  };
}

function newProgramRuntime(definition) {
  return {
    status: 'ACTIVE',
    status_sequence: 0,
    definition,
    total_occurrences: 0,
    node_occurrence_counts: new Map(
      definition.program.nodes.map((node) => [node.node_id, 0]),
    ),
    budgets: new Map(definition.program.budgets.map((budget) => [budget.budget_id, {
      budget_id: budget.budget_id,
      unit: budget.unit,
      limit: budget.limit,
      reserved: 0,
      consumed: 0,
    }])),
  };
}

function occurrenceKey(programRef, occurrenceId) {
  return `${programRef}\0${occurrenceId}`;
}

function authorizationClaimKey(tenantId, authorizationDigest) {
  return `${tenantId}\0${authorizationDigest}`;
}

function expectedProfileActionMatch(program, node, admission) {
  const evidence = admission.sealed_evidence?.find((entry) => entry.role === 'aeb');
  if (!evidence || node.action.mode !== 'profile') return null;
  return {
    tenant_id: program.tenant_id,
    profile_id: node.action.profile_id,
    profile_digest: node.action.profile_digest,
    subject_id: program.subject_id,
    operation_id: admission.operation_id,
    caid: admission.caid,
    action_digest: admission.action_digest,
    verifier_id: evidence.verifier_id,
    evidence_payload_digest: evidence.payload_digest,
    evidence_trust_configuration_digest: evidence.trust_configuration_digest,
    trust_epoch: admission.trust_epoch,
    trust_configuration_digest: admission.trust_configuration_digest,
  };
}

function bindingMatches(program, node, admission) {
  if (admission?.tenant_id !== program.tenant_id
      || admission.subject_id !== program.subject_id
      || admission.authorization_digest !== program.authorization_digest
      || admission.authorization_policy_digest !== node.trust_program_digest) return false;
  if (node.action.mode === 'exact') {
    return admission.caid === node.action.caid
      && admission.action_digest === node.action.action_digest
      && admission.action_match_evidence === undefined;
  }
  const evidence = admission.sealed_evidence?.find((entry) => entry.role === 'aeb');
  const expected = expectedProfileActionMatch(program, node, admission);
  if (admission.action_match_evidence === undefined || !evidence || !expected
      || evidence.subject_id !== program.subject_id
      || evidence.profile_digest !== node.action.profile_digest) return false;
  const verification = admission.action_match_verification;
  return verification?.valid === true
    && verification.result === 'MATCH'
    && Reflect.ownKeys(verification).length === Reflect.ownKeys(expected).length + 2
    && Object.entries(expected).every(([key, value]) => verification[key] === value);
}

function dependencySatisfied(state, programRef, dependency) {
  return [...state.occurrences.values()].some((occurrence) => (
    occurrence.program_ref === programRef
    && occurrence.node_id === dependency.node_id
    && dependency.outcomes.includes(occurrence.state)
  ));
}

function registrationContext(definition) {
  return {
    expected_program_id: definition.program.program_id,
    expected_tenant_id: definition.program.tenant_id,
    expected_authorization_digest: definition.program.authorization_digest,
    expected_audience: definition.program.audience,
  };
}

function registrationRefusal(state, definition, context) {
  const contextKeys = [
    'expected_program_id',
    'expected_tenant_id',
    'expected_authorization_digest',
    'expected_audience',
  ];
  if (!context || Reflect.ownKeys(context).length !== contextKeys.length
      || !contextKeys.every((key) => Object.hasOwn(context, key))) {
    return 'context_binding_required';
  }
  const policyEntry = state.store_configuration.execution_program_verification_policy
    ?.trusted_keys?.[definition.key_id];
  if (!policyEntry || policyEntry.role !== 'program_authorizer'
      || policyEntry.status !== 'ACTIVE'
      || policyEntry.issuer_id !== definition.authorizer_id) {
    return 'program_issuer_untrusted';
  }
  if (context.expected_program_id !== definition.program.program_id) return 'program_id_mismatch';
  if (context.expected_tenant_id !== definition.program.tenant_id) return 'tenant_mismatch';
  if (context.expected_authorization_digest !== definition.program.authorization_digest) {
    return 'authorization_mismatch';
  }
  if (context.expected_audience !== definition.program.audience) return 'audience_mismatch';
  const now = Date.parse(state.store_configuration.clock);
  if (!Number.isFinite(now)) return 'verification_time_invalid';
  if (now < Date.parse(definition.program.valid_from)) return 'program_not_active';
  if (now >= Date.parse(definition.program.expires_at)) return 'program_expired';
  return null;
}

function refreshProgramStatus(state, programRef, runtime) {
  if (runtime.status === 'SUPERSEDED') return 'program_superseded';
  if (runtime.status === 'REVOKED') return 'program_revoked';
  if (state.store_configuration.status_oracle === 'none') {
    return 'program_status_indeterminate';
  }
  if (!state.explicit_status_observations.has(programRef)) {
    const previous = state.status_observations.get(programRef);
    const observedAt = state.store_configuration.clock;
    if (previous?.observed_at !== observedAt) {
      state.status_observations.set(programRef, {
        '@version': EXECUTION_PROGRAM_STATUS_VERSION,
        tenant_id: runtime.definition.program.tenant_id,
        program_id: runtime.definition.program.program_id,
        program_digest: runtime.definition.program_digest,
        version: runtime.definition.program.version,
        status: 'ACTIVE',
        sequence: previous ? previous.sequence + 1 : 0,
        observed_at: observedAt,
        expires_at: observedAt === state.initial_clock
          ? runtime.definition.program.expires_at
          : new Date(Date.parse(observedAt) + 3_600_000).toISOString(),
      });
    }
  }
  {
    const observation = state.status_observations.get(programRef);
    const now = Date.parse(state.store_configuration.clock);
    const observedAt = Date.parse(observation?.observed_at);
    const expiresAt = Date.parse(observation?.expires_at);
    if (!observation
        || observation['@version'] !== EXECUTION_PROGRAM_STATUS_VERSION
        || observation.tenant_id !== runtime.definition.program.tenant_id
        || observation.program_id !== runtime.definition.program.program_id
        || observation.program_digest !== runtime.definition.program_digest
        || observation.version !== runtime.definition.program.version
        || !Number.isSafeInteger(observation.sequence)
        || !Number.isFinite(observedAt) || !Number.isFinite(expiresAt)
        || observedAt > now
        || now - observedAt > state.store_configuration.max_execution_program_status_age_ms
        || expiresAt <= now
        || observation.sequence < runtime.status_sequence
        || !['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(observation.status)) {
      return 'program_status_indeterminate';
    }
    runtime.status = observation.status;
    runtime.status_sequence = observation.sequence;
  }
  if (runtime.status === 'SUSPENDED') return 'program_suspended';
  if (runtime.status === 'REVOKED') return 'program_revoked';
  const now = Date.parse(state.store_configuration.clock);
  if (now < Date.parse(runtime.definition.program.valid_from)) return 'program_not_active';
  if (now >= Date.parse(runtime.definition.program.expires_at)) return 'program_expired';
  return null;
}

function releaseOccurrence(runtime, occurrence) {
  for (const charge of occurrence.charges) {
    runtime.budgets.get(charge.budget_id).reserved -= charge.amount;
  }
  runtime.node_occurrence_counts.set(
    occurrence.node_id,
    runtime.node_occurrence_counts.get(occurrence.node_id) - 1,
  );
  occurrence.state = 'RELEASED';
}

function reserveRuntime(state, operation) {
  const runtime = state.programs.get(operation.program_ref);
  if (!runtime) return { ok: false, reason: 'program_not_found' };
  const statusRefusal = refreshProgramStatus(state, operation.program_ref, runtime);
  if (statusRefusal) return { ok: false, reason: statusRefusal };
  const key = occurrenceKey(operation.program_ref, operation.occurrence_id);
  if (state.occurrences.has(key)) return { ok: false, reason: 'program_occurrence_conflict' };
  const node = nodeById(runtime.definition.program, operation.node_id);
  if (!node || !bindingMatches(runtime.definition.program, node, operation.admission)) {
    return { ok: false, reason: 'program_binding_mismatch' };
  }
  if (Date.parse(operation.admission.expires_at)
      > Date.parse(runtime.definition.program.expires_at)) {
    return { ok: false, reason: 'program_expiration_mismatch' };
  }
  const expectedBinding = executionProgramAdmissionBinding({
    tenant_id: operation.admission.tenant_id,
    program_digest: runtime.definition.program_digest,
    node_id: node.node_id,
    occurrence_id: operation.occurrence_id,
    expires_at: operation.admission.expires_at,
  }).resource;
  const existingBindings = operation.admission.execution_program_resources ?? [];
  if (existingBindings.length > 1
      || (existingBindings.length === 1
        && canonicalize(existingBindings[0]) !== canonicalize(expectedBinding))
      || (existingBindings.length === 0 && operation.admission.admission_form === 'snapshot')) {
    return { ok: false, reason: 'program_binding_mismatch' };
  }
  if (!node.depends_on.every((dependency) => (
    dependencySatisfied(state, operation.program_ref, dependency)
  ))) return { ok: false, reason: 'program_node_unreachable' };
  if (runtime.total_occurrences >= runtime.definition.program.max_total_occurrences) {
    return { ok: false, reason: 'program_total_occurrence_exhausted' };
  }
  if (runtime.node_occurrence_counts.get(node.node_id) >= node.max_occurrences) {
    return { ok: false, reason: 'program_occurrence_exhausted' };
  }
  if (node.charges.some((charge) => {
    const budget = runtime.budgets.get(charge.budget_id);
    return budget.reserved + budget.consumed + charge.amount > budget.limit;
  })) return { ok: false, reason: 'program_budget_exhausted' };
  for (const charge of node.charges) runtime.budgets.get(charge.budget_id).reserved += charge.amount;
  runtime.total_occurrences += 1;
  runtime.node_occurrence_counts.set(
    node.node_id,
    runtime.node_occurrence_counts.get(node.node_id) + 1,
  );
  state.occurrences.set(key, {
    program_ref: operation.program_ref,
    node_id: node.node_id,
    occurrence_id: operation.occurrence_id,
    state: 'RESERVED',
    charges: clone(node.charges),
    effect_relation: null,
    admission_binding: clone(expectedBinding),
  });
  return { ok: true, execution_program_binding: clone(expectedBinding) };
}

function selectOccurrence(state, operation) {
  return state.occurrences.get(occurrenceKey(operation.program_ref, operation.occurrence_id));
}

function applyRuntimeOperation(state, operation, definitions) {
  if (operation.op === 'set_store_clock') {
    state.store_configuration.clock = new Date(Date.parse(operation.now)).toISOString();
    return { ok: true };
  }
  if (operation.op === 'set_status_observation') {
    state.status_observations.set(operation.program_ref, clone(operation.observation));
    state.explicit_status_observations.add(operation.program_ref);
    return { ok: true };
  }
  if (operation.op === 'register') {
    const definition = definitions[operation.program_ref];
    if (!definition) return { ok: false, reason: 'program_not_found' };
    const registrationFailure = registrationRefusal(state, definition, operation.context);
    if (registrationFailure) return { ok: false, reason: registrationFailure };
    if (definition.program.version !== 1
        || definition.program.supersedes_program_digest !== null) {
      return { ok: false, reason: 'program_supersession_invalid' };
    }
    const headKey = `${definition.program.tenant_id}\0${definition.program.program_id}`;
    if (state.programs.has(operation.program_ref) || state.program_heads.has(headKey)) {
      return { ok: false, reason: 'program_exists' };
    }
    const claimKey = authorizationClaimKey(
      definition.program.tenant_id,
      definition.program.authorization_digest,
    );
    if (state.authorization_claims.has(claimKey)
        || [...state.ordinary_admissions.values()].some((admission) => (
          admission.tenant_id === definition.program.tenant_id
          && admission.authorization_digest === definition.program.authorization_digest
          && admission.execution_right === 'RESERVED'
        ))) return { ok: false, reason: 'program_binding_mismatch' };
    const runtime = newProgramRuntime(definition);
    const statusFailure = refreshProgramStatus(state, operation.program_ref, runtime);
    if (statusFailure) return { ok: false, reason: statusFailure };
    state.programs.set(operation.program_ref, runtime);
    state.program_heads.set(headKey, operation.program_ref);
    state.authorization_claims.set(claimKey, {
      tenant_id: definition.program.tenant_id,
      authorization_digest: definition.program.authorization_digest,
      program_ref: operation.program_ref,
    });
    return { ok: true };
  }
  if (operation.op === 'ordinary_reserve') {
    const claimKey = authorizationClaimKey(operation.tenant_id, operation.authorization_digest);
    if (state.authorization_claims.has(claimKey)) {
      return { ok: false, reason: 'program_required' };
    }
    if (state.ordinary_admissions.has(operation.admission_id)) {
      return { ok: false, reason: 'admission_exists' };
    }
    state.ordinary_admissions.set(operation.admission_id, {
      admission_id: operation.admission_id,
      tenant_id: operation.tenant_id,
      authorization_digest: operation.authorization_digest,
      execution_right: 'RESERVED',
    });
    return { ok: true };
  }
  if (operation.op === 'ordinary_release') {
    const admission = state.ordinary_admissions.get(operation.admission_id);
    if (!admission) return { ok: false, reason: 'admission_not_found' };
    if (admission.execution_right !== 'RESERVED') {
      return { ok: false, reason: 'state_conflict' };
    }
    admission.execution_right = 'RELEASED';
    return { ok: true };
  }
  if (operation.op === 'reserve') return reserveRuntime(state, operation);
  if (operation.op === 'ordinary_begin') {
    const occurrence = selectOccurrence(state, operation);
    if (!occurrence) return { ok: false, reason: 'program_not_found' };
    return { ok: false, reason: 'program_required' };
  }
  if (operation.op === 'begin') {
    const occurrence = selectOccurrence(state, operation);
    if (!occurrence) return { ok: false, reason: 'program_not_found' };
    if (occurrence.state !== 'RESERVED') {
      return {
        ok: false,
        reason: ['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED']
          .includes(occurrence.state) ? 'execution_right_consumed' : 'state_conflict',
      };
    }
    const runtime = state.programs.get(operation.program_ref);
    const statusRefusal = refreshProgramStatus(state, operation.program_ref, runtime);
    if (statusRefusal) {
      releaseOccurrence(runtime, occurrence);
      return { ok: false, reason: statusRefusal };
    }
    for (const charge of occurrence.charges) {
      const budget = runtime.budgets.get(charge.budget_id);
      budget.reserved -= charge.amount;
      budget.consumed += charge.amount;
    }
    occurrence.state = 'INVOKING';
    return { ok: true };
  }
  if (operation.op === 'release') {
    const occurrence = selectOccurrence(state, operation);
    if (!occurrence) return { ok: false, reason: 'program_not_found' };
    if (occurrence.state !== 'RESERVED') {
      return {
        ok: false,
        reason: ['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED']
          .includes(occurrence.state) ? 'execution_right_consumed' : 'state_conflict',
      };
    }
    const runtime = state.programs.get(operation.program_ref);
    releaseOccurrence(runtime, occurrence);
    return { ok: true };
  }
  if (operation.op === 'provider_outcome') {
    const occurrence = selectOccurrence(state, operation);
    if (!occurrence) return { ok: false, reason: 'program_not_found' };
    if (!['INVOKING', 'INDETERMINATE'].includes(occurrence.state)) {
      return { ok: false, reason: 'state_conflict' };
    }
    if (!['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(operation.outcome)) {
      return { ok: false, reason: 'state_conflict' };
    }
    if (occurrence.state === 'INDETERMINATE' && operation.outcome === 'INDETERMINATE') {
      return { ok: false, reason: 'state_conflict' };
    }
    occurrence.state = operation.outcome;
    return { ok: true };
  }
  if (operation.op === 'effect_relation') {
    const occurrence = selectOccurrence(state, operation);
    if (!occurrence) return { ok: false, reason: 'program_not_found' };
    if (!['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED']
      .includes(occurrence.state)) return { ok: false, reason: 'state_conflict' };
    if (!['OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'].includes(operation.value)) {
      return { ok: false, reason: 'state_conflict' };
    }
    occurrence.effect_relation = operation.value;
    return { ok: true };
  }
  if (operation.op === 'supersede') {
    const successor = definitions[operation.successor_program_ref];
    if (!successor) return { ok: false, reason: 'program_not_found' };
    const registrationFailure = registrationRefusal(state, successor, operation.context);
    if (registrationFailure) return { ok: false, reason: registrationFailure };
    if (successor.program.version < 2 || successor.program.supersedes_program_digest === null) {
      return { ok: false, reason: 'program_supersession_invalid' };
    }
    const predecessorEntry = [...state.programs.entries()].find(([, runtime]) => (
      runtime.definition.program_digest === successor.program.supersedes_program_digest
      && runtime.definition.program.tenant_id === successor.program.tenant_id
    ));
    if (!predecessorEntry) return { ok: false, reason: 'program_not_found' };
    const [predecessorRef, predecessor] = predecessorEntry;
    const headKey = `${successor.program.tenant_id}\0${successor.program.program_id}`;
    if (predecessor.status !== 'ACTIVE'
        || state.program_heads.get(headKey) !== predecessorRef
        || successor.program.program_id !== predecessor.definition.program.program_id
        || successor.program.tenant_id !== predecessor.definition.program.tenant_id
        || successor.program.version !== predecessor.definition.program.version + 1
        || successor.authorizer_id !== predecessor.definition.authorizer_id
        || successor.program.subject_id !== predecessor.definition.program.subject_id
        || successor.program.audience !== predecessor.definition.program.audience
        || successor.program.objective_digest !== predecessor.definition.program.objective_digest
        || successor.program.presentation_digest !== predecessor.definition.program.presentation_digest
        || successor.program.authorization_digest === predecessor.definition.program.authorization_digest) {
      return { ok: false, reason: 'program_supersession_invalid' };
    }
    if ([...state.occurrences.values()].some((occurrence) => (
      occurrence.program_ref === predecessorRef
      && occurrence.state === 'RESERVED'
    ))) return { ok: false, reason: 'program_reserved_work_exists' };
    const successorClaimKey = authorizationClaimKey(
      successor.program.tenant_id,
      successor.program.authorization_digest,
    );
    const authorizationOwner = state.authorization_claims.get(successorClaimKey);
    if (authorizationOwner !== undefined) {
      return { ok: false, reason: 'program_binding_mismatch' };
    }
    predecessor.status = 'SUPERSEDED';
    predecessor.status_sequence += 1;
    state.programs.set(operation.successor_program_ref, newProgramRuntime(successor));
    state.program_heads.set(headKey, operation.successor_program_ref);
    state.authorization_claims.set(successorClaimKey, {
      tenant_id: successor.program.tenant_id,
      authorization_digest: successor.program.authorization_digest,
      program_ref: operation.successor_program_ref,
    });
    return { ok: true };
  }
  throw new Error(`unknown runtime operation: ${operation.op}`);
}

function runtimeSnapshot(state) {
  return {
    programs: [...state.programs.entries()]
      .sort(([left], [right]) => byteOrder(left, right))
      .map(([programRef, runtime]) => ({
        program_ref: programRef,
        status: runtime.status,
        status_sequence: runtime.status_sequence,
        total_occurrences: runtime.total_occurrences,
        node_occurrence_counts: [...runtime.node_occurrence_counts.entries()]
          .sort(([left], [right]) => byteOrder(left, right))
          .map(([nodeId, count]) => ({ node_id: nodeId, count })),
        budgets: [...runtime.budgets.values()]
          .sort((left, right) => byteOrder(left.budget_id, right.budget_id))
          .map((budget) => clone(budget)),
      })),
    occurrences: [...state.occurrences.values()]
      .sort((left, right) => byteOrder(
        `${left.program_ref}\0${left.occurrence_id}`,
        `${right.program_ref}\0${right.occurrence_id}`,
      ))
      .map((occurrence) => ({
        program_ref: occurrence.program_ref,
        node_id: occurrence.node_id,
        occurrence_id: occurrence.occurrence_id,
        state: occurrence.state,
        effect_relation: occurrence.effect_relation,
        admission_binding: clone(occurrence.admission_binding),
      })),
    authorization_claims: [...state.authorization_claims.values()]
      .sort((left, right) => byteOrder(
        `${left.tenant_id}\0${left.authorization_digest}`,
        `${right.tenant_id}\0${right.authorization_digest}`,
      ))
      .map((claim) => clone(claim)),
    ordinary_admissions: [...state.ordinary_admissions.values()]
      .sort((left, right) => byteOrder(left.admission_id, right.admission_id))
      .map((admission) => clone(admission)),
  };
}

function traceStep(operation, must) {
  return { operation, must };
}

function compileTrace(definition, programDefinitions, storeConfigurations) {
  const state = runtimeState(storeConfigurations[definition.store_configuration_ref ?? 'active']);
  return {
    id: definition.id,
    classification: definition.classification,
    purpose: definition.purpose,
    store_configuration_ref: definition.store_configuration_ref ?? 'active',
    steps: definition.steps.map(({ operation, must }, index) => {
      const result = applyRuntimeOperation(state, operation, programDefinitions);
      assert.equal(result.ok, must.ok, `${definition.id} step ${index + 1}: runtime success changed`);
      if (!must.ok) {
        assert.deepEqual(result, must, `${definition.id} step ${index + 1}: runtime refusal changed`);
      }
      return { operation, expect: { result, state: runtimeSnapshot(state) } };
    }),
  };
}

function runtimeDefinitions(programs) {
  const baseProgram = programs.base;
  const successorProgram = programs.successor;
  const exact = (nodeId, overrides) => exactAdmission(baseProgram.program, nodeId, overrides);
  const profile = (nodeId, overrides) => profileAdmission(baseProgram.program, nodeId, overrides);
  const successorExact = (nodeId, overrides) => exactAdmission(successorProgram.program, nodeId, overrides);
  const totalExact = (overrides) => exactAdmission(
    programs.total_occurrence_limit.program,
    'inspect',
    overrides,
  );
  const duplicateUnitExact = (overrides) => exactAdmission(
    programs.duplicate_unit_budgets.program,
    'inspect',
    overrides,
  );
  const register = (programRef, context = registrationContext(programs[programRef])) => ({
    op: 'register', program_ref: programRef, context,
  });
  const supersede = (successorProgramRef) => ({
    op: 'supersede',
    successor_program_ref: successorProgramRef,
    context: registrationContext(programs[successorProgramRef]),
  });
  const statusObservation = (status, sequence, observedAt = NOW) => ({
    '@version': EXECUTION_PROGRAM_STATUS_VERSION,
    tenant_id: baseProgram.program.tenant_id,
    program_id: baseProgram.program.program_id,
    program_digest: baseProgram.program_digest,
    version: baseProgram.program.version,
    status,
    sequence,
    observed_at: observedAt,
    expires_at: '2026-07-29T20:55:00.000Z',
  });
  const prebuilt = (admission, executionProgramResources) => ({
    ...clone(admission),
    admission_form: 'snapshot',
    execution_program_resources: executionProgramResources.map((resource) => clone(resource)),
  });
  const bindingResource = ({
    program = baseProgram,
    tenantId = baseProgram.program.tenant_id,
    nodeId = 'inspect',
    occurrenceId,
    expiresAt = ADMISSION_EXPIRES_AT,
  }) => executionProgramAdmissionBinding({
    tenant_id: tenantId,
    program_digest: program.program_digest,
    node_id: nodeId,
    occurrence_id: occurrenceId,
    expires_at: expiresAt,
  }).resource;
  const ok = { ok: true };
  const refuse = (reason) => ({ ok: false, reason });
  return [
    {
      id: 'positive_terminal_path_with_exact_and_profile_actions',
      classification: 'positive',
      purpose: 'Consumes each attempt once and accepts only the terminal outcomes named by dependencies.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:01', admission: exact('inspect') }, ok),
        traceStep({ op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:inspect:01' }, ok),
        traceStep({ op: 'provider_outcome', program_ref: 'base', occurrence_id: 'occurrence:inspect:01', outcome: 'COMMITTED' }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'remediate', occurrence_id: 'occurrence:remediate:01', admission: profile('remediate') }, ok),
        traceStep({ op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:remediate:01' }, ok),
        traceStep({ op: 'provider_outcome', program_ref: 'base', occurrence_id: 'occurrence:remediate:01', outcome: 'PROVEN_NOT_COMMITTED' }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'verify', occurrence_id: 'occurrence:verify:01', admission: exact('verify') }, ok),
        traceStep({ op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:verify:01' }, ok),
        traceStep({ op: 'provider_outcome', program_ref: 'base', occurrence_id: 'occurrence:verify:01', outcome: 'COMMITTED' }, ok),
      ],
    },
    {
      id: 'hostile_unreachable_indeterminate_and_diverged_effect',
      classification: 'hostile',
      purpose: 'INDETERMINATE consumes budget and DIVERGED remains an effect relation; neither unlocks a dependent node.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:ambiguous', admission: exact('inspect') }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'remediate', occurrence_id: 'occurrence:remediate:early', admission: profile('remediate') }, refuse('program_node_unreachable')),
        traceStep({ op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:inspect:ambiguous' }, ok),
        traceStep({ op: 'provider_outcome', program_ref: 'base', occurrence_id: 'occurrence:inspect:ambiguous', outcome: 'INDETERMINATE' }, ok),
        traceStep({ op: 'effect_relation', program_ref: 'base', occurrence_id: 'occurrence:inspect:ambiguous', value: 'DIVERGED' }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'remediate', occurrence_id: 'occurrence:remediate:still-locked', admission: profile('remediate') }, refuse('program_node_unreachable')),
        traceStep({ op: 'provider_outcome', program_ref: 'base', occurrence_id: 'occurrence:inspect:ambiguous', outcome: 'COMMITTED' }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'remediate', occurrence_id: 'occurrence:remediate:after-reconciliation', admission: profile('remediate') }, ok),
      ],
    },
    {
      id: 'hostile_bypass_release_replay_and_occurrence_ceiling',
      classification: 'hostile',
      purpose: 'Program-linked work cannot use ordinary begin, release keeps the occurrence ID fenced, and an invoked occurrence cannot be released.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:released', admission: exact('inspect') }, ok),
        traceStep({ op: 'ordinary_begin', program_ref: 'base', occurrence_id: 'occurrence:inspect:released' }, refuse('program_required')),
        traceStep({ op: 'release', program_ref: 'base', occurrence_id: 'occurrence:inspect:released' }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:released', admission: exact('inspect') }, refuse('program_occurrence_conflict')),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:replacement', admission: exact('inspect') }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:over-ceiling', admission: exact('inspect') }, refuse('program_occurrence_exhausted')),
        traceStep({ op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:inspect:replacement' }, ok),
        traceStep({ op: 'release', program_ref: 'base', occurrence_id: 'occurrence:inspect:replacement' }, refuse('execution_right_consumed')),
      ],
    },
    {
      id: 'hostile_binding_profile_and_budget_fail_closed',
      classification: 'hostile',
      purpose: 'Substituted exact actions, legacy caller MATCH assertions, missing or substituted authenticated profile evidence, and aggregate budget overflow refuse without mutation.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:substituted', admission: exact('inspect', { action_digest: digest('action:substituted') }) }, refuse('program_binding_mismatch')),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:valid', admission: exact('inspect') }, ok),
        traceStep({ op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:inspect:valid' }, ok),
        traceStep({ op: 'provider_outcome', program_ref: 'base', occurrence_id: 'occurrence:inspect:valid', outcome: 'COMMITTED' }, ok),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'remediate',
          occurrence_id: 'occurrence:remediate:legacy-caller-assertion',
          admission: profile('remediate', {
            action_match_evidence: undefined,
            action_match_verification: undefined,
            action_match: {
              result: 'MATCH',
              profile_id: 'profile:terraform-reviewed-plan',
              profile_digest: nodeById(baseProgram.program, 'remediate').action.profile_digest,
              evidence_payload_digest: digest('evidence:legacy-caller-assertion'),
            },
          }),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'remediate',
          occurrence_id: 'occurrence:remediate:no-profile-evidence',
          admission: profile('remediate', {
            action_match_evidence: undefined,
            action_match_verification: undefined,
          }),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'remediate',
          occurrence_id: 'occurrence:remediate:substituted-evidence',
          admission: profile('remediate', {
            action_match_verification: {
              ...profile('remediate').action_match_verification,
              trust_epoch: 2,
            },
          }),
        }, refuse('program_binding_mismatch')),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'rollback', occurrence_id: 'occurrence:rollback:over-budget', admission: exact('rollback') }, refuse('program_budget_exhausted')),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'remediate', occurrence_id: 'occurrence:remediate:valid', admission: profile('remediate') }, ok),
      ],
    },
    {
      id: 'positive_release_then_signed_supersession_starts_fresh',
      classification: 'positive',
      purpose: 'Reserved predecessor work blocks supersession; exact version plus one, a fresh authorization digest, and frozen identity/intent context are mandatory before fresh successor state starts.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:predecessor', admission: exact('inspect') }, ok),
        traceStep(supersede('successor'), refuse('program_reserved_work_exists')),
        traceStep({ op: 'release', program_ref: 'base', occurrence_id: 'occurrence:inspect:predecessor' }, ok),
        traceStep(supersede('skipped_successor'), refuse('program_supersession_invalid')),
        traceStep(supersede('reused_authorization_successor'), refuse('program_supersession_invalid')),
        traceStep(supersede('frozen_subject_successor'), refuse('program_supersession_invalid')),
        traceStep(supersede('successor'), ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:old-program', admission: exact('inspect') }, refuse('program_superseded')),
        traceStep({ op: 'reserve', program_ref: 'successor', node_id: 'inspect', occurrence_id: 'occurrence:inspect:successor', admission: successorExact('inspect') }, ok),
      ],
    },
    {
      id: 'hostile_terminal_outcome_not_named_by_dependency',
      classification: 'hostile',
      purpose: 'PROVEN_NOT_COMMITTED is terminal but does not satisfy a dependency that names only COMMITTED.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'inspect', occurrence_id: 'occurrence:inspect:not-committed', admission: exact('inspect') }, ok),
        traceStep({ op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:inspect:not-committed' }, ok),
        traceStep({ op: 'provider_outcome', program_ref: 'base', occurrence_id: 'occurrence:inspect:not-committed', outcome: 'PROVEN_NOT_COMMITTED' }, ok),
        traceStep({ op: 'reserve', program_ref: 'base', node_id: 'remediate', occurrence_id: 'occurrence:remediate:not-unlocked', admission: profile('remediate') }, refuse('program_node_unreachable')),
      ],
    },
    {
      id: 'hostile_prebuilt_unbound_and_admission_binding_relink',
      classification: 'hostile',
      purpose: 'A prebuilt snapshot must carry exactly one deterministic execution_program resource for the requested tenant, program, node, occurrence, and snapshot expiry.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:binding:unbound',
          admission: prebuilt(exact('inspect'), []),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:binding:relinked',
          admission: prebuilt(exact('inspect'), [bindingResource({
            occurrenceId: 'occurrence:binding:original',
          })]),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'rollback',
          occurrence_id: 'occurrence:binding:node',
          admission: prebuilt(exact('rollback'), [bindingResource({
            nodeId: 'inspect', occurrenceId: 'occurrence:binding:node',
          })]),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:binding:program',
          admission: prebuilt(exact('inspect'), [bindingResource({
            program: successorProgram, occurrenceId: 'occurrence:binding:program',
          })]),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:binding:tenant',
          admission: prebuilt(exact('inspect'), [bindingResource({
            tenantId: 'tenant:other', occurrenceId: 'occurrence:binding:tenant',
          })]),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:binding:expiry',
          admission: prebuilt(exact('inspect'), [bindingResource({
            occurrenceId: 'occurrence:binding:expiry',
            expiresAt: '2026-07-29T20:44:00.000Z',
          })]),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:binding:multiple',
          admission: prebuilt(exact('inspect'), [
            bindingResource({ occurrenceId: 'occurrence:binding:multiple' }),
            bindingResource({ occurrenceId: 'occurrence:binding:extra' }),
          ]),
        }, refuse('program_binding_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:binding:exact',
          admission: prebuilt(exact('inspect'), [bindingResource({
            occurrenceId: 'occurrence:binding:exact',
          })]),
        }, ok),
      ],
    },
    {
      id: 'hostile_authorization_claim_registration_and_ordinary_reserve',
      classification: 'hostile',
      purpose: 'Program registration cannot strand an ordinary RESERVED admission and, once registered, exclusively claims its tenant plus authorization digest for program-aware reserve.',
      steps: [
        traceStep({
          op: 'ordinary_reserve', admission_id: 'admission:ordinary:before-program',
          tenant_id: baseProgram.program.tenant_id,
          authorization_digest: baseProgram.program.authorization_digest,
        }, ok),
        traceStep(register('base'), refuse('program_binding_mismatch')),
        traceStep({ op: 'ordinary_release', admission_id: 'admission:ordinary:before-program' }, ok),
        traceStep(register('base'), ok),
        traceStep({
          op: 'ordinary_reserve', admission_id: 'admission:ordinary:claimed-auth',
          tenant_id: baseProgram.program.tenant_id,
          authorization_digest: baseProgram.program.authorization_digest,
        }, refuse('program_required')),
        traceStep({
          op: 'ordinary_reserve', admission_id: 'admission:ordinary:other-auth',
          tenant_id: baseProgram.program.tenant_id,
          authorization_digest: digest('authorization:ordinary-other'),
        }, ok),
        traceStep({
          op: 'ordinary_reserve', admission_id: 'admission:ordinary:other-tenant',
          tenant_id: 'tenant:other',
          authorization_digest: baseProgram.program.authorization_digest,
        }, ok),
      ],
    },
    {
      id: 'positive_store_owned_registration_policy_and_clock',
      classification: 'positive',
      purpose: 'Registration receives only four relying-party bindings; trust pins, key role/status, authorizer resolution, and verification time come from the store.',
      steps: [traceStep(register('base'), ok)],
    },
    {
      id: 'hostile_suspended_authorizer_key_is_not_trusted',
      classification: 'hostile',
      store_configuration_ref: 'suspended_authorizer',
      purpose: 'A store-owned program_authorizer pin with SUSPENDED status is excluded from trusted verification keys.',
      steps: [traceStep(register('base'), refuse('program_issuer_untrusted'))],
    },
    {
      id: 'hostile_revoked_authorizer_key_is_not_trusted',
      classification: 'hostile',
      store_configuration_ref: 'revoked_authorizer',
      purpose: 'A store-owned program_authorizer pin with REVOKED status is excluded from trusted verification keys.',
      steps: [traceStep(register('base'), refuse('program_issuer_untrusted'))],
    },
    {
      id: 'hostile_store_clock_at_program_expiry_refuses_registration',
      classification: 'hostile',
      store_configuration_ref: 'expired_clock',
      purpose: 'Caller context cannot replace the store clock; the exclusive program expiry refuses registration.',
      steps: [traceStep(register('base'), refuse('program_expired'))],
    },
    {
      id: 'hostile_status_suspension_and_revocation_fail_closed_before_entry',
      classification: 'hostile',
      store_configuration_ref: 'status_oracle',
      purpose: 'Authenticated SUSPENDED and REVOKED observations refuse reserve, and a SUSPENDED observation discovered immediately before invocation atomically releases reserved work before provider entry.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({
          op: 'set_status_observation', program_ref: 'base',
          observation: statusObservation('SUSPENDED', 1),
        }, ok),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:status:suspended', admission: exact('inspect'),
        }, refuse('program_suspended')),
        traceStep({
          op: 'set_status_observation', program_ref: 'base',
          observation: statusObservation('ACTIVE', 2),
        }, ok),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:status:before-begin', admission: exact('inspect'),
        }, ok),
        traceStep({
          op: 'set_status_observation', program_ref: 'base',
          observation: statusObservation('SUSPENDED', 3),
        }, ok),
        traceStep({
          op: 'begin', program_ref: 'base',
          occurrence_id: 'occurrence:status:before-begin',
        }, refuse('program_suspended')),
        traceStep({
          op: 'set_status_observation', program_ref: 'base',
          observation: statusObservation('ACTIVE', 4),
        }, ok),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:status:invoking', admission: exact('inspect'),
        }, ok),
        traceStep({
          op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:status:invoking',
        }, ok),
        traceStep({
          op: 'set_status_observation', program_ref: 'base',
          observation: statusObservation('REVOKED', 5),
        }, ok),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'rollback',
          occurrence_id: 'occurrence:status:revoked', admission: exact('rollback'),
        }, refuse('program_revoked')),
        traceStep({
          op: 'provider_outcome', program_ref: 'base',
          occurrence_id: 'occurrence:status:invoking', outcome: 'PROVEN_NOT_COMMITTED',
        }, ok),
      ],
    },
    {
      id: 'hostile_admission_expiry_cap_and_program_expiry_before_begin',
      classification: 'hostile',
      purpose: 'Admission expiry may equal but never exceed program expiry; reaching the shared exclusive deadline before begin releases reserved work and refuses provider entry.',
      steps: [
        traceStep(register('base'), ok),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:expiry:too-long',
          admission: exact('inspect', { expires_at: '2026-07-29T21:00:00.001Z' }),
        }, refuse('program_expiration_mismatch')),
        traceStep({
          op: 'reserve', program_ref: 'base', node_id: 'inspect',
          occurrence_id: 'occurrence:expiry:at-limit',
          admission: exact('inspect', { expires_at: '2026-07-29T21:00:00.000Z' }),
        }, ok),
        traceStep({ op: 'set_store_clock', now: '2026-07-29T21:00:00.000Z' }, ok),
        traceStep({
          op: 'begin', program_ref: 'base', occurrence_id: 'occurrence:expiry:at-limit',
        }, refuse('program_expired')),
      ],
    },
    {
      id: 'hostile_total_occurrence_ceiling_counts_released_attempts',
      classification: 'hostile',
      purpose: 'The per-node index decrements on release, but total_occurrences counts retained RELEASED records and refuses work at the mandatory program-wide ceiling.',
      steps: [
        traceStep(register('total_occurrence_limit'), ok),
        traceStep({
          op: 'reserve', program_ref: 'total_occurrence_limit', node_id: 'inspect',
          occurrence_id: 'occurrence:total:0', admission: totalExact(),
        }, ok),
        traceStep({
          op: 'release', program_ref: 'total_occurrence_limit', occurrence_id: 'occurrence:total:0',
        }, ok),
        traceStep({
          op: 'reserve', program_ref: 'total_occurrence_limit', node_id: 'inspect',
          occurrence_id: 'occurrence:total:1', admission: totalExact(),
        }, ok),
        traceStep({
          op: 'release', program_ref: 'total_occurrence_limit', occurrence_id: 'occurrence:total:1',
        }, ok),
        traceStep({
          op: 'reserve', program_ref: 'total_occurrence_limit', node_id: 'inspect',
          occurrence_id: 'occurrence:total:2', admission: totalExact(),
        }, refuse('program_total_occurrence_exhausted')),
      ],
    },
    {
      id: 'positive_duplicate_unit_labels_use_independent_budget_ids',
      classification: 'positive',
      purpose: 'Budget accounting keys by budget_id; charging one dimension does not charge another dimension carrying the same human-readable unit label.',
      steps: [
        traceStep(register('duplicate_unit_budgets'), ok),
        traceStep({
          op: 'reserve', program_ref: 'duplicate_unit_budgets', node_id: 'inspect',
          occurrence_id: 'occurrence:duplicate-unit:1', admission: duplicateUnitExact(),
        }, ok),
        traceStep({
          op: 'begin', program_ref: 'duplicate_unit_budgets',
          occurrence_id: 'occurrence:duplicate-unit:1',
        }, ok),
      ],
    },
  ];
}

function validateRuntimeTraces(runtime) {
  for (const trace of runtime.traces) {
    const state = runtimeState(runtime.store_configurations[trace.store_configuration_ref]);
    trace.steps.forEach((step, index) => {
      const result = applyRuntimeOperation(state, step.operation, runtime.programs);
      assert.deepEqual(
        { result, state: runtimeSnapshot(state) },
        step.expect,
        `${trace.id} step ${index + 1}: runtime vector mismatch`,
      );
    });
  }
}

function validateAdmissionBindingVectors(profile) {
  assert.equal(profile['@version'], EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION);
  assert.equal(
    profile.identity_formula,
    'SHA-256(UTF8("EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1:IDENTITY") || 0x00 || JCS([tenant_id, program_digest, node_id, occurrence_id]))',
  );
  assert.equal(
    profile.digest_formula,
    'SHA-256(UTF8("EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1:DIGEST") || 0x00 || JCS(binding_body))',
  );
  for (const fixture of profile.fixtures) {
    const expected = executionProgramAdmissionBinding(fixture.input);
    assert.deepEqual(fixture.identity_tuple, expected.identity_tuple, `${fixture.id}: identity tuple mismatch`);
    assert.equal(fixture.identity_domain, expected.identity_domain, `${fixture.id}: identity domain mismatch`);
    assert.equal(fixture.identity_digest, expected.identity_digest, `${fixture.id}: identity digest mismatch`);
    assert.deepEqual(fixture.binding_body, expected.binding_body, `${fixture.id}: binding body mismatch`);
    assert.equal(fixture.digest_domain, expected.digest_domain, `${fixture.id}: digest domain mismatch`);
    assert.deepEqual(fixture.resource, expected.resource, `${fixture.id}: resource mismatch`);
  }
  assert.notEqual(
    profile.fixtures.find((fixture) => fixture.id === 'structured_alias_left').resource.resource_id,
    profile.fixtures.find((fixture) => fixture.id === 'structured_alias_right').resource.resource_id,
    'structured tuple aliases must not collide',
  );
}

function validateStoreConfigurationCases(cases) {
  for (const entry of cases) {
    /** @type {{ accepted: boolean; error_code: string | null }} */
    let actual = { accepted: true, error_code: null };
    try {
      createMemoryAdmissionStore({
        now: NOW,
        executionProgramVerificationPolicy: entry.verification_policy,
      });
    } catch (error) {
      actual = {
        accepted: false,
        error_code: error && typeof error === 'object' && 'code' in error
          ? String(error.code) : 'unknown',
      };
    }
    assert.deepEqual(actual, entry.expect, `${entry.id}: store policy validation changed`);
  }
}

function concreteOwnerToken(index) {
  return `admission-owner:v2:${Buffer.alloc(32, index).toString('base64url')}`;
}

function concreteInvocationToken(index) {
  return `admission-invocation:v2:${Buffer.alloc(32, index).toString('base64url')}`;
}

/**
 * @returns {import('../../packages/gate/src/admission-store.ts').AdmissionCurrentnessObservation}
 */
function concreteCurrentness(body, now) {
  return {
    '@version': ADMISSION_CURRENTNESS_VERSION,
    observed_at: new Date(now).toISOString(),
    qualification_status_authority_id: body.qualification_status.authority_id,
    qualification_status_sequence: body.qualification_status.sequence,
    qualification_status_head_digest: body.qualification_status.head_payload_digest,
    qualification_status_expires_at: body.qualification_status.expires_at,
    trust_epoch: body.trust_epoch,
    trust_configuration_digest: body.trust_configuration_digest,
    configuration_epoch: body.configuration_epoch,
    configuration_digest: body.configuration_digest,
    runtime_measurement_digest: body.runtime_measurement_digest,
    candidate_match: 'EXACT_MATCH',
    external_leases: [],
  };
}

function materializeConcreteAdmission(traceId, stepIndex, definition, abstract) {
  const sequence = stepIndex + 1;
  const unique = `${traceId}:${sequence}`;
  const evidenceDeadline = '2026-07-29T21:30:00.000Z';
  const admissionId = `admission:trace:${unique}`;
  const operationId = `operation:trace:${unique}`;
  const requestedExpiresAt = abstract.expires_at;
  const programResources = abstract.execution_program_resources ?? [];
  let expiresAt = requestedExpiresAt;
  if (abstract.admission_form === 'snapshot' && programResources.length > 0) {
    const earliest = Math.min(...programResources.map((resource) => Date.parse(resource.expires_at)));
    if (earliest < Date.parse(expiresAt)) expiresAt = new Date(earliest - 1).toISOString();
  }
  const candidateDigest = digest(`candidate:${unique}`);
  const runtimeDigest = digest(`runtime:${unique}`);
  const testResultDigest = digest(`test-result:${unique}`);
  const agentEvidenceDigest = digest(`agent-evidence:${unique}`);
  const statementDigest = digest(`qualification-statement:${unique}`);
  const statusDigest = digest(`qualification-status:${unique}`);
  const sealedAeb = abstract.sealed_evidence?.find((entry) => entry.role === 'aeb');
  /** @type {import('../../packages/gate/src/admission-store.ts').AdmissionSnapshotInput['inputs']} */
  const roles = [
    {
      role: 'candidate_manifest', artifact_type: 'artifact.candidate_manifest',
      subject: abstract.subject_id, payload_digest: candidateDigest,
      profile_digest: digest('profile:candidate-manifest'), verifier_id: 'verifier:candidate-manifest',
      trust_configuration_digest: digest('trust-config:candidate-manifest'), valid_until: evidenceDeadline,
    },
    {
      role: 'runtime_measurement', artifact_type: 'artifact.runtime_measurement',
      subject: 'runtime:trace', payload_digest: runtimeDigest,
      profile_digest: digest('profile:runtime-measurement'), verifier_id: 'verifier:runtime-measurement',
      trust_configuration_digest: digest('trust-config:runtime-measurement'), valid_until: evidenceDeadline,
    },
    {
      role: 'test_result', artifact_type: 'artifact.test_result', subject: 'test:trace',
      payload_digest: testResultDigest, profile_digest: digest('profile:test-result'),
      verifier_id: 'verifier:test-result', trust_configuration_digest: digest('trust-config:test-result'),
      valid_until: evidenceDeadline,
    },
    {
      role: 'agent_evaluation_evidence', artifact_type: 'artifact.agent_evaluation_evidence',
      subject: 'agent:trace', payload_digest: agentEvidenceDigest,
      profile_digest: digest('profile:agent-evidence'), verifier_id: 'verifier:agent-evidence',
      trust_configuration_digest: digest('trust-config:agent-evidence'), valid_until: evidenceDeadline,
    },
    {
      role: 'qualification_statement', artifact_type: 'artifact.qualification_statement',
      subject: 'qualification:trace', payload_digest: statementDigest,
      profile_digest: digest('profile:qualification-statement'), verifier_id: 'verifier:qualification-statement',
      trust_configuration_digest: digest('trust-config:qualification-statement'), valid_until: evidenceDeadline,
    },
    {
      role: 'qualification_status', artifact_type: 'artifact.qualification_status',
      subject: 'qualification-status:trace', payload_digest: statusDigest,
      profile_digest: digest('profile:qualification-status'), verifier_id: 'verifier:qualification-status',
      trust_configuration_digest: digest('trust-config:qualification-status'), valid_until: evidenceDeadline,
    },
    {
      role: 'aeb', artifact_type: 'artifact.aeb',
      subject: sealedAeb?.subject_id ?? definition.program.subject_id,
      payload_digest: sealedAeb?.payload_digest ?? digest(`aeb:${unique}`),
      profile_digest: sealedAeb?.profile_digest ?? digest('profile:aeb'),
      verifier_id: sealedAeb?.verifier_id ?? 'verifier:aeb',
      trust_configuration_digest: sealedAeb?.trust_configuration_digest ?? digest('trust-config:aeb'),
      valid_until: evidenceDeadline,
    },
    {
      role: 'aec', artifact_type: 'artifact.aec', subject: 'aec:trace',
      payload_digest: digest(`aec:${unique}`), profile_digest: digest('profile:aec'),
      verifier_id: 'verifier:aec', trust_configuration_digest: digest('trust-config:aec'),
      valid_until: evidenceDeadline,
    },
    {
      role: 'local_policy', artifact_type: 'artifact.local_policy', subject: 'policy:trace',
      payload_digest: digest(`local-policy:${unique}`), profile_digest: digest('profile:local-policy'),
      verifier_id: 'verifier:local-policy', trust_configuration_digest: digest('trust-config:local-policy'),
      valid_until: evidenceDeadline,
    },
    {
      role: 'authorization', artifact_type: 'artifact.authorization', subject: 'authorization:trace',
      payload_digest: abstract.authorization_digest, profile_digest: digest('profile:authorization'),
      verifier_id: 'verifier:authorization', trust_configuration_digest: digest('trust-config:authorization'),
      valid_until: evidenceDeadline,
    },
  ];
  /** @type {import('../../packages/gate/src/admission-store.ts').AdmissionSnapshotInput} */
  const input = {
    tenant_id: abstract.tenant_id,
    admission_id: admissionId,
    operation_id: operationId,
    candidate_manifest_digest: candidateDigest,
    runtime_measurement_digest: runtimeDigest,
    candidate_custody: {
      request_construction: 'GATE', mutation_credential_custody: 'GATE',
      enforcement_placement: 'ACTUATOR', evidence_digest: digest(`custody:${unique}`),
    },
    assignment_digest: digest(`assignment:${unique}`),
    qualification_policy_digest: digest(`qualification-policy:${unique}`),
    test_result_payload_digests: [testResultDigest],
    agent_evaluation_evidence_payload_digests: [agentEvidenceDigest],
    qualification_statement_payload_digest: statementDigest,
    qualification_status: {
      authority_id: 'qualification-authority:trace', sequence,
      head_payload_digest: statusDigest, observed_at: NOW, expires_at: evidenceDeadline,
    },
    caid: abstract.caid,
    action_digest: abstract.action_digest,
    effect_request_digest: digest(`effect-request:${unique}`),
    provider: { provider_id: 'provider:trace', account_id: 'account:trace', environment: 'production' },
    executor_adapter_digest: digest('executor-adapter:trace'),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: abstract.authorization_policy_digest,
    trust_epoch: abstract.trust_epoch,
    trust_configuration_digest: abstract.trust_configuration_digest,
    configuration_epoch: 1,
    configuration_digest: digest('configuration:trace'),
    inputs: roles,
    resource_reservations: [
      {
        kind: 'replay', resource_id: `receipt:${unique}`, reservation_id: `replay:${unique}`,
        digest: digest(`replay:${unique}`), expires_at: evidenceDeadline,
      },
      {
        kind: 'provider_operation', resource_id: operationId,
        reservation_id: `provider-operation:${unique}`,
        digest: digest(`provider-operation:${unique}`), expires_at: evidenceDeadline,
      },
      ...programResources,
    ],
    admitted_at: NOW,
    expires_at: expiresAt,
    supersedes_admission_id: null,
    remedy_for: null,
  };
  return {
    input,
    admission: abstract.admission_form === 'snapshot' ? createAdmissionSnapshot(input) : input,
  };
}

function materializeConcreteOrdinaryAdmission(traceId, stepIndex, operation, programs) {
  const base = programs.base;
  const exactNode = base.program.nodes.find((node) => node.action.mode === 'exact');
  assert.ok(exactNode?.action.mode === 'exact');
  const materialized = materializeConcreteAdmission(traceId, stepIndex, base, exactAdmission(
    base.program,
    exactNode.node_id,
    {
      tenant_id: operation.tenant_id,
      authorization_digest: operation.authorization_digest,
    },
  ));
  return {
    ...materialized.input,
    admission_id: operation.admission_id,
    operation_id: `operation:${operation.admission_id}`,
    idempotency_key: `idempotency:${operation.admission_id}`,
  };
}

function concreteActionMatchPlan(program, node, admission) {
  if (node.action.mode !== 'profile' || admission.action_match_evidence === undefined) return null;
  const expected = expectedProfileActionMatch(program, node, admission);
  const projection = admission.action_match_verification;
  if (!expected || !projection) return null;
  const overrides = {};
  for (const [key, value] of Object.entries(expected)) {
    if (projection[key] !== value) overrides[key] = projection[key];
  }
  return { evidence: clone(admission.action_match_evidence), overrides };
}

function projectConcreteResult(raw, expected, binding) {
  if (!raw.ok) return { ok: false, reason: raw.reason };
  if (Object.hasOwn(expected, 'execution_program_binding')) {
    return { ok: true, execution_program_binding: clone(binding) };
  }
  return { ok: true };
}

async function replayConcreteRuntimeTraces(runtime, syntaxFixtures) {
  for (const trace of runtime.traces) {
    const configuration = runtime.store_configurations[trace.store_configuration_ref];
    let now = Date.parse(configuration.clock);
    let statusObservation = null;
    const generatedStatus = new Map();
    let actionMatchPlan = null;
    let ownerIndex = 1;
    let invocationIndex = 1;
    /** @type {import('../../packages/gate/src/admission-store.ts').CreateMemoryAdmissionStoreOptions} */
    const storeOptions = {
      now: () => now,
      ownerTokenFactory: () => concreteOwnerToken(ownerIndex++),
      invocationTokenFactory: () => concreteInvocationToken(invocationIndex++),
      currentnessOracle: {
        read: async (snapshot) => concreteCurrentness(snapshot.body, now),
      },
      executionProgramVerificationPolicy: configuration.execution_program_verification_policy,
      maxExecutionProgramStatusAgeMs: configuration.max_execution_program_status_age_ms,
      executionProgramActionMatchVerifier: {
        verify: async ({ evidence, expected }) => {
          if (!actionMatchPlan
              || canonicalize(evidence) !== canonicalize(actionMatchPlan.evidence)) return null;
          return { valid: true, result: 'MATCH', ...expected, ...actionMatchPlan.overrides };
        },
      },
    };
    if (configuration.status_oracle !== 'none') {
      storeOptions.executionProgramStatusOracle = {
        read: async (reference) => {
          if (statusObservation !== null) return clone(statusObservation);
          const key = reference.program_digest;
          const previous = generatedStatus.get(key);
          const observedAt = new Date(now).toISOString();
          if (previous?.observed_at === observedAt) return clone(previous);
          const definition = Object.values(runtime.programs).find(
            (entry) => entry.program_digest === reference.program_digest,
          );
          if (!definition) return null;
          const initial = now === Date.parse(configuration.clock);
          const next = {
            '@version': 'EP-BOUNDED-EXECUTION-PROGRAM-STATUS-v1',
            ...reference,
            status: 'ACTIVE',
            sequence: previous ? previous.sequence + 1 : 0,
            observed_at: observedAt,
            expires_at: initial
              ? definition.program.expires_at
              : new Date(now + 3_600_000).toISOString(),
          };
          generatedStatus.set(key, next);
          return clone(next);
        },
      };
    }
    const store = createMemoryAdmissionStore(storeOptions);
    const handles = new Map();
    const attemptedOccurrences = new Map();
    const attemptedOrdinaryAdmissions = new Map();
    const authorizationClaimRefs = new Set();

    const readOccurrence = async (operation) => {
      const definition = runtime.programs[operation.program_ref];
      const occurrence = await store.readExecutionProgramOccurrence({
        tenant_id: definition.program.tenant_id,
        program_digest: definition.program_digest,
        occurrence_id: operation.occurrence_id,
      });
      if (!occurrence) return null;
      const record = await store.read({
        tenant_id: occurrence.tenant_id,
        admission_id: occurrence.admission_id,
      });
      const handle = handles.get(occurrence.admission_id);
      assert.ok(record && handle);
      return { occurrence, record, handle };
    };

    const execute = async (operation, stepIndex) => {
      if (operation.op === 'set_store_clock') {
        now = Date.parse(operation.now);
        return { raw: { ok: true } };
      }
      if (operation.op === 'set_status_observation') {
        statusObservation = clone(operation.observation);
        return { raw: { ok: true } };
      }
      if (operation.op === 'register') {
        const raw = await store.registerExecutionProgram(
          syntaxFixtures[operation.program_ref],
          operation.context,
        );
        if (raw.ok) authorizationClaimRefs.add(operation.program_ref);
        return { raw };
      }
      if (operation.op === 'reserve') {
        const definition = runtime.programs[operation.program_ref];
        attemptedOccurrences.set(
          occurrenceKey(operation.program_ref, operation.occurrence_id),
          { program_ref: operation.program_ref, occurrence_id: operation.occurrence_id },
        );
        const materialized = materializeConcreteAdmission(
          trace.id,
          stepIndex,
          definition,
          operation.admission,
        );
        const node = nodeById(definition.program, operation.node_id);
        actionMatchPlan = concreteActionMatchPlan(definition.program, node, operation.admission);
        const raw = await store.reserveExecutionProgramAdmission({
          program_digest: definition.program_digest,
          node_id: operation.node_id,
          occurrence_id: operation.occurrence_id,
          admission: materialized.admission,
          action_match_evidence: operation.admission.action_match_evidence,
        });
        actionMatchPlan = null;
        if (!raw.ok) return { raw };
        handles.set(raw.snapshot.body.admission_id, { owner_token: raw.owner_token });
        const binding = createReferenceExecutionProgramAdmissionBinding({
          tenant_id: materialized.input.tenant_id,
          program_digest: definition.program_digest,
          node_id: operation.node_id,
          occurrence_id: operation.occurrence_id,
          expires_at: materialized.input.expires_at,
        });
        return { raw, binding };
      }
      if (operation.op === 'ordinary_reserve') {
        const input = materializeConcreteOrdinaryAdmission(
          trace.id,
          stepIndex,
          operation,
          runtime.programs,
        );
        attemptedOrdinaryAdmissions.set(input.admission_id, {
          tenant_id: input.tenant_id,
          authorization_digest: operation.authorization_digest,
        });
        const raw = await store.reserve(input);
        if (raw.ok) handles.set(input.admission_id, { owner_token: raw.owner_token });
        return { raw };
      }
      if (operation.op === 'ordinary_release') {
        const attempted = attemptedOrdinaryAdmissions.get(operation.admission_id);
        const handle = handles.get(operation.admission_id);
        const record = attempted && await store.read({
          tenant_id: attempted.tenant_id,
          admission_id: operation.admission_id,
        });
        if (!attempted || !handle || !record) {
          return { raw: { ok: false, reason: 'admission_not_found' } };
        }
        return {
          raw: await store.release({
            tenant_id: attempted.tenant_id,
            admission_id: operation.admission_id,
            expected_revision: record.revision,
            owner_token: handle.owner_token,
          }),
        };
      }
      if (operation.op === 'begin' || operation.op === 'ordinary_begin') {
        const selected = await readOccurrence(operation);
        if (!selected) return { raw: { ok: false, reason: 'program_not_found' } };
        const cas = {
          tenant_id: selected.occurrence.tenant_id,
          admission_id: selected.occurrence.admission_id,
          expected_revision: selected.record.revision,
          owner_token: selected.handle.owner_token,
        };
        const raw = operation.op === 'begin'
          ? await store.beginExecutionProgramInvocation(cas)
          : await store.beginInvocation(cas);
        if (raw.ok) selected.handle.invocation_token = raw.invocation_token;
        return { raw };
      }
      if (operation.op === 'release') {
        const selected = await readOccurrence(operation);
        if (!selected) return { raw: { ok: false, reason: 'program_not_found' } };
        return {
          raw: await store.releaseExecutionProgramAdmission({
            tenant_id: selected.occurrence.tenant_id,
            admission_id: selected.occurrence.admission_id,
            expected_revision: selected.record.revision,
            owner_token: selected.handle.owner_token,
          }),
        };
      }
      if (operation.op === 'provider_outcome') {
        const selected = await readOccurrence(operation);
        if (!selected) return { raw: { ok: false, reason: 'program_not_found' } };
        return {
          raw: await store.recordProviderOutcome({
            tenant_id: selected.occurrence.tenant_id,
            admission_id: selected.occurrence.admission_id,
            expected_revision: selected.record.revision,
            owner_token: selected.handle.owner_token,
            invocation_token: selected.handle.invocation_token,
            value: operation.outcome,
            evidence_digest: operation.outcome === 'INDETERMINATE'
              ? null : digest(`${trace.id}:${stepIndex}:provider:${operation.outcome}`),
            observed_at: new Date(now).toISOString(),
          }),
        };
      }
      if (operation.op === 'effect_relation') {
        const selected = await readOccurrence(operation);
        if (!selected) return { raw: { ok: false, reason: 'program_not_found' } };
        return {
          raw: await store.recordEffectRelation({
            tenant_id: selected.occurrence.tenant_id,
            admission_id: selected.occurrence.admission_id,
            expected_revision: selected.record.revision,
            owner_token: selected.handle.owner_token,
            invocation_token: selected.handle.invocation_token,
            value: operation.value,
            evidence_digest: operation.value === 'INDETERMINATE'
              ? null : digest(`${trace.id}:${stepIndex}:effect:${operation.value}`),
            observed_at: new Date(now).toISOString(),
          }),
        };
      }
      if (operation.op === 'supersede') {
        const raw = await store.supersedeExecutionProgram(
          syntaxFixtures[operation.successor_program_ref],
          operation.context,
        );
        if (raw.ok) authorizationClaimRefs.add(operation.successor_program_ref);
        return { raw };
      }
      throw new Error(`unsupported concrete runtime operation: ${operation.op}`);
    };

    const projectState = async () => {
      const occurrences = [];
      const indexedCounts = new Map();
      for (const attempt of [...attemptedOccurrences.values()].sort((left, right) => byteOrder(
        occurrenceKey(left.program_ref, left.occurrence_id),
        occurrenceKey(right.program_ref, right.occurrence_id),
      ))) {
        const definition = runtime.programs[attempt.program_ref];
        const occurrence = await store.readExecutionProgramOccurrence({
          tenant_id: definition.program.tenant_id,
          program_digest: definition.program_digest,
          occurrence_id: attempt.occurrence_id,
        });
        if (!occurrence) continue;
        const record = await store.read({
          tenant_id: occurrence.tenant_id,
          admission_id: occurrence.admission_id,
        });
        const snapshot = await store.readSnapshot(occurrence.snapshot_digest);
        assert.ok(record && snapshot);
        const binding = snapshot.body.resource_reservations.find(
          (resource) => resource.kind === 'execution_program',
        );
        assert.ok(binding);
        occurrences.push({
          program_ref: attempt.program_ref,
          node_id: occurrence.node_id,
          occurrence_id: occurrence.occurrence_id,
          state: occurrence.state,
          effect_relation: record.effect_relation?.value ?? null,
          admission_binding: clone(binding),
        });
        if (occurrence.state !== 'RELEASED') {
          const key = `${attempt.program_ref}\0${occurrence.node_id}`;
          indexedCounts.set(key, (indexedCounts.get(key) ?? 0) + 1);
        }
      }
      const programs = [];
      for (const programRef of Object.keys(runtime.programs).sort(byteOrder)) {
        const definition = runtime.programs[programRef];
        const state = await store.readExecutionProgram({
          tenant_id: definition.program.tenant_id,
          program_digest: definition.program_digest,
        });
        if (!state) continue;
        programs.push({
          program_ref: programRef,
          status: state.status,
          status_sequence: state.status_sequence,
          total_occurrences: state.total_occurrences,
          node_occurrence_counts: state.program.nodes.map((node) => ({
            node_id: node.node_id,
            count: indexedCounts.get(`${programRef}\0${node.node_id}`) ?? 0,
          })).sort((left, right) => byteOrder(left.node_id, right.node_id)),
          budgets: state.budgets.map((budget) => clone(budget))
            .sort((left, right) => byteOrder(left.budget_id, right.budget_id)),
        });
      }
      const authorizationClaims = [...authorizationClaimRefs]
        .map((programRef) => ({
          tenant_id: runtime.programs[programRef].program.tenant_id,
          authorization_digest: runtime.programs[programRef].program.authorization_digest,
          program_ref: programRef,
        }))
        .sort((left, right) => byteOrder(
          `${left.tenant_id}\0${left.authorization_digest}`,
          `${right.tenant_id}\0${right.authorization_digest}`,
        ));
      const ordinaryAdmissions = [];
      for (const [admissionId, attempted] of [...attemptedOrdinaryAdmissions.entries()]
        .sort(([left], [right]) => byteOrder(left, right))) {
        const record = await store.read({
          tenant_id: attempted.tenant_id,
          admission_id: admissionId,
        });
        if (!record) continue;
        ordinaryAdmissions.push({
          admission_id: admissionId,
          tenant_id: attempted.tenant_id,
          authorization_digest: attempted.authorization_digest,
          execution_right: record.execution_right,
        });
      }
      return {
        programs,
        occurrences,
        authorization_claims: authorizationClaims,
        ordinary_admissions: ordinaryAdmissions,
      };
    };

    for (let index = 0; index < trace.steps.length; index += 1) {
      const step = trace.steps[index];
      const executed = await execute(step.operation, index);
      const actual = {
        result: projectConcreteResult(executed.raw, step.expect.result, executed.binding),
        state: await projectState(),
      };
      assert.deepEqual(
        actual,
        step.expect,
        `${trace.id} step ${index + 1} (${step.operation.op}): concrete store replay drift`,
      );
      assert.deepEqual(
        await store.checkInvariants(),
        { ok: true, violations: [] },
        `${trace.id} step ${index + 1}: concrete store invariant drift`,
      );
    }
  }
}

function validateSyntaxVectors(syntax) {
  const baseBody = clone(syntax.fixtures.base);
  delete baseBody.proof;
  assert.equal(canonicalize(baseBody), syntax.canonical.signed_body_jcs);
  assert.equal(
    Buffer.from(`${BOUNDED_EXECUTION_PROGRAM_VERSION}\0${syntax.canonical.signed_body_jcs}`, 'utf8')
      .toString('base64url'),
    syntax.canonical.signature_input_b64u,
  );
  assert.equal(executionProgramDigest(syntax.fixtures.base), syntax.canonical.program_digest);
  for (const entry of syntax.cases) {
    const actual = verificationProjection(verifyBoundedExecutionProgram(
      syntax.fixtures[entry.artifact],
      verificationOptions(syntax.common, entry),
    ));
    assert.deepEqual(actual, entry.expect, `${entry.id}: syntax vector mismatch`);
  }
}

function buildSuite() {
  const syntaxCommon = {
    trusted_keys: TRUSTED_KEYS,
    verification_context: VERIFICATION_CONTEXT,
  };
  const verifiedDefinition = (artifact, input) => {
    const verification = verifyBoundedExecutionProgram(artifact, {
      trusted_keys: TRUSTED_KEYS,
      now: NOW,
      expected_program_id: input.program_id,
      expected_tenant_id: input.tenant_id,
      expected_authorizer_id: SIGNER.issuer_id,
      expected_authorization_digest: input.authorization_digest,
      expected_audience: input.audience,
    });
    if (!verification.accepted || !verification.program || !verification.program_digest) {
      throw new Error(`runtime fixture verification failed: ${verification.reason}`);
    }
    return {
      program_digest: verification.program_digest,
      program: clone(verification.program),
      authorizer_id: verification.authorizer_id,
      key_id: SIGNER.key_id,
    };
  };
  const baseVerification = verifyBoundedExecutionProgram(BASE_ARTIFACT, {
    trusted_keys: TRUSTED_KEYS,
    ...VERIFICATION_CONTEXT,
  });
  assert.equal(baseVerification.accepted, true);
  const baseBody = clone(BASE_ARTIFACT);
  delete baseBody.proof;
  const signedBodyJcs = canonicalize(baseBody);
  const programs = {
    base: verifiedDefinition(BASE_ARTIFACT, BASE_INPUT),
    successor: verifiedDefinition(SUCCESSOR_ARTIFACT, SUCCESSOR_INPUT),
    skipped_successor: verifiedDefinition(SKIPPED_SUCCESSOR_ARTIFACT, SKIPPED_SUCCESSOR_INPUT),
    reused_authorization_successor: verifiedDefinition(
      REUSED_AUTHORIZATION_SUCCESSOR_ARTIFACT,
      REUSED_AUTHORIZATION_SUCCESSOR_INPUT,
    ),
    frozen_subject_successor: verifiedDefinition(
      FROZEN_SUBJECT_SUCCESSOR_ARTIFACT,
      FROZEN_SUBJECT_SUCCESSOR_INPUT,
    ),
    total_occurrence_limit: verifiedDefinition(
      TOTAL_OCCURRENCE_ARTIFACT,
      TOTAL_OCCURRENCE_INPUT,
    ),
    duplicate_unit_budgets: verifiedDefinition(DUPLICATE_UNIT_ARTIFACT, DUPLICATE_UNIT_INPUT),
  };
  const traces = runtimeDefinitions(programs)
    .map((definition) => compileTrace(definition, programs, STORE_CONFIGURATIONS));
  const admissionBindingFixtures = [
    {
      id: 'base_inspect_occurrence_binding',
      input: {
        tenant_id: programs.base.program.tenant_id,
        program_digest: programs.base.program_digest,
        node_id: 'inspect',
        occurrence_id: 'occurrence:binding:fixture',
        expires_at: ADMISSION_EXPIRES_AT,
      },
    },
    {
      id: 'normalizes_equivalent_offset_expiry',
      input: {
        tenant_id: programs.base.program.tenant_id,
        program_digest: programs.base.program_digest,
        node_id: 'inspect',
        occurrence_id: 'occurrence:binding:offset-expiry',
        expires_at: '2026-07-29T13:45:00-07:00',
      },
    },
    {
      id: 'structured_alias_left',
      input: {
        tenant_id: 'tenant+alpha',
        program_digest: programs.base.program_digest,
        node_id: 'node:a',
        occurrence_id: 'b:c',
        expires_at: ADMISSION_EXPIRES_AT,
      },
    },
    {
      id: 'structured_alias_right',
      input: {
        tenant_id: 'tenant+alpha',
        program_digest: programs.base.program_digest,
        node_id: 'node:a:b',
        occurrence_id: 'c',
        expires_at: ADMISSION_EXPIRES_AT,
      },
    },
  ].map((fixture) => ({ ...fixture, ...executionProgramAdmissionBinding(fixture.input) }));
  const storeConfigurationCases = [
    {
      id: 'accept_active_program_authorizer_pin',
      verification_policy: STORE_VERIFICATION_POLICY,
      expect: { accepted: true, error_code: null },
    },
    {
      id: 'accept_suspended_pin_as_configuration_but_exclude_it_from_trust',
      verification_policy: STORE_CONFIGURATIONS.suspended_authorizer
        .execution_program_verification_policy,
      expect: { accepted: true, error_code: null },
    },
    {
      id: 'accept_revoked_pin_as_configuration_but_exclude_it_from_trust',
      verification_policy: STORE_CONFIGURATIONS.revoked_authorizer
        .execution_program_verification_policy,
      expect: { accepted: true, error_code: null },
    },
    {
      id: 'refuse_non_program_authorizer_key_role',
      verification_policy: {
        trusted_keys: {
          [SIGNER.key_id]: {
            ...STORE_VERIFICATION_POLICY.trusted_keys[SIGNER.key_id],
            role: 'general_signer',
          },
        },
      },
      expect: { accepted: false, error_code: 'invalid_program_verification_policy' },
    },
  ];
  return {
    '@version': 'EP-BOUNDED-EXECUTION-PROGRAM-CONFORMANCE-v1',
    status: 'public-experimental-test-vector',
    vectors_version: VECTOR_VERSION,
    claim_boundary: {
      establishes: [
        'the syntax cases exercise deterministic Ed25519 and canonical JSON bytes against the repository reference verifier',
        'the runtime traces define expected store-owned verification, status, authenticated action-match, admission-resource binding, authorization-digest fencing, indexed and total occurrence, budget, outcome, release, and exact version-plus-one supersession transitions for one abstract linearizable state machine',
      ],
      does_not_establish: [
        'that natural-language intent was understood or correctly compiled',
        'that an authorization digest proves a human ceremony, identity, consent, comprehension, or display integrity',
        'that an action profile is sound or that a plan is safe, lawful, optimal, or free of prompt injection',
        'that provider evidence, an observed effect, or event chronology is true',
        'that every mutation path was mediated by Gate or that any production store is durable or linearizable',
        'independent implementation, cross-vendor interoperability, deployment, standardization, or certification',
        'that DIVERGED identifies why an observed effect differed',
      ],
    },
    syntax: {
      profile: 'Canonical signed program syntax and relying-party verification projection.',
      common: syntaxCommon,
      fixtures: ARTIFACTS,
      canonical: {
        signing_input: BASE_INPUT,
        normalized_program: clone(baseVerification.program),
        signed_body_jcs: signedBodyJcs,
        signature_input_b64u: Buffer.from(
          `${BOUNDED_EXECUTION_PROGRAM_VERSION}\0${signedBodyJcs}`,
          'utf8',
        ).toString('base64url'),
        program_digest: baseVerification.program_digest,
      },
      cases: compileSyntaxCases(syntaxCommon),
    },
    runtime: {
      profile: 'Language-neutral abstract transition traces with store-owned verification and time, authenticated status and profile evidence, deterministic AdmissionSnapshot resource sealing, and tenant-plus-authorization ownership. Each rejected step must leave the complete expected state unchanged.',
      store_configurations: STORE_CONFIGURATIONS,
      store_configuration_cases: storeConfigurationCases,
      admission_binding: {
        '@version': EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION,
        identity_formula: 'SHA-256(UTF8("EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1:IDENTITY") || 0x00 || JCS([tenant_id, program_digest, node_id, occurrence_id]))',
        digest_formula: 'SHA-256(UTF8("EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1:DIGEST") || 0x00 || JCS(binding_body))',
        fixtures: admissionBindingFixtures,
      },
      programs,
      traces,
    },
  };
}

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
  throw new Error('usage: generate-bounded-execution-program.mjs [--check]');
}

const generated = buildSuite();
validateSyntaxVectors(generated.syntax);
validateStoreConfigurationCases(generated.runtime.store_configuration_cases);
validateAdmissionBindingVectors(generated.runtime.admission_binding);
validateRuntimeTraces(generated.runtime);
const serialized = `${JSON.stringify(generated, null, 2)}\n`;

if (args[0] === '--check') {
  const checkedIn = readFileSync(OUTPUT, 'utf8');
  if (checkedIn !== serialized) {
    console.error('bounded-execution-program.v1.json is stale; regenerate it');
    process.exitCode = 1;
  } else {
    const parsed = JSON.parse(checkedIn);
    validateSyntaxVectors(parsed.syntax);
    validateStoreConfigurationCases(parsed.runtime.store_configuration_cases);
    validateAdmissionBindingVectors(parsed.runtime.admission_binding);
    validateRuntimeTraces(parsed.runtime);
    console.log(
      `checked bounded-execution-program.v1.json — ${generated.syntax.cases.length} syntax cases and ${generated.runtime.traces.length} runtime traces`,
    );
  }
} else {
  writeFileSync(OUTPUT, serialized);
  console.log(
    `wrote bounded-execution-program.v1.json — ${generated.syntax.cases.length} syntax cases and ${generated.runtime.traces.length} runtime traces (self-check passed)`,
  );
}
