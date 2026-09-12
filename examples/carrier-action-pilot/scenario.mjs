// SPDX-License-Identifier: Apache-2.0
//
// A fully synthetic payment-release pilot for carrier design work.
//
// This example uses the real hybrid-signed action-risk schedule, qualification
// status, Outcome Observation v2, provider binding, and Action Evidence Packet
// implementations. The native component adapters are deliberately small test
// adapters. They are caller trust inputs, not independent production verifiers.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { buildOutcomeObservationV2 } from '../../packages/verify/outcome-binding.js';
import {
  ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY,
  ACTION_RISK_DIVERGENT_HANDLING,
  ACTION_RISK_INDETERMINATE_HANDLING,
  ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY,
  actionRiskControlScheduleDigest,
  actionRiskHybridTrustPinDigest,
  actionRiskQualificationStatusDigest,
  evaluateActionRiskControlSchedule,
  signActionRiskControlSchedule,
  signActionRiskQualificationStatus,
} from '../../packages/gate/action-risk-control-schedule.js';
import {
  PROVIDER_OUTCOME_BINDING_CLAIM_BOUNDARY,
  PROVIDER_OUTCOME_BINDING_VERSION,
  PROVIDER_OUTCOME_CONTEXT_VERSION,
  buildProviderOutcomeBinding,
  providerOutcomeContextDigest,
  providerOutcomeObservationEffects,
} from '../../packages/gate/provider-outcome-binding.js';
import {
  ACTION_EVIDENCE_COMPONENT_ROLES,
  ACTION_EVIDENCE_MANIFEST_VERSION,
  ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY,
  actionEvidenceArtifactDigest,
  buildActionEvidencePacket,
  verifyActionEvidencePacket,
} from '../../packages/gate/action-evidence-packet.js';

/** @typedef {import('../../packages/gate/action-evidence-packet.js').ActionEvidenceComponentVerifier} ActionEvidenceComponentVerifier */
/** @typedef {import('../../packages/gate/action-evidence-packet.js').ActionEvidenceManifest} ActionEvidenceManifest */
/** @typedef {import('../../packages/gate/action-evidence-packet.js').ActionEvidenceScheduleVerifier} ActionEvidenceScheduleVerifier */
/** @typedef {import('../../packages/gate/action-evidence-packet.js').VerifyActionEvidencePacketOptions} VerifyActionEvidencePacketOptions */
/** @typedef {import('../../packages/gate/provider-outcome-binding.js').ProviderOutcome} ProviderOutcome */
/** @typedef {import('../../packages/gate/provider-outcome-binding.js').ProviderOutcomeContext} ProviderOutcomeContext */

const { ml_dsa65: mlDsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const NOW = '2026-09-04T12:03:00.000Z';
const PROVIDER_ENTRY_AT = '2026-09-04T12:01:00.000Z';
const PROVIDER_EVENT_AT = '2026-09-04T12:01:30.000Z';
const ASSEMBLED_AT = '2026-09-04T12:02:15.000Z';
const SCHEDULE_ID = 'schedule:carrier-pilot:payment-release:v1';
const SCHEDULE_ISSUER = 'issuer:carrier-pilot:risk-control';
const SCHEDULE_KEY_ID = 'key:carrier-pilot:schedule:1';
const STATUS_AUTHORITY = 'authority:carrier-pilot:qualification';
const STATUS_KEY_ID = 'key:carrier-pilot:qualification:1';
const RELYING_PARTY = 'enterprise:carrier-pilot';
const TENANT = 'tenant:carrier-pilot';

const REQUIRED_SURFACES = Object.freeze([
  'provider_api',
  'provider_console',
]);

const SOURCES = Object.freeze([
  Object.freeze({
    role: 'independent_observer',
    source_id: 'source:bank-settlement-feed',
    source_class: 'bank.settlement-feed',
  }),
  Object.freeze({
    role: 'system_of_record',
    source_id: 'source:erp-payment-ledger',
    source_class: 'erp.payment-ledger',
  }),
]);

const DEFAULT_STATES = Object.freeze({
  aeb: 'SATISFIED',
  admission_snapshot: 'IMMUTABLE',
  admission_decision: 'ALLOW',
  qualification_statement: 'QUALIFIED',
  qualification_status_head: 'CURRENT',
  open_exposure_ceiling: 'ACTIVE',
  open_exposure_record: 'CLOSED_COMMITTED',
  open_exposure_history: 'CLOSED_COMMITTED',
  observed_effect_relation: 'OBSERVED_AS_REQUESTED',
  coverage_surface: 'gated',
  refusal_probe: 'blocked_without_receipt',
  supplied_population_report: 'VERIFIED_SUPPLIED_POPULATION',
  loss_report: null,
  recourse: null,
  loss_allocation: null,
});

const PILOT_BOUNDARY =
  'Fully synthetic local test. The native callbacks are caller-controlled test adapters, not independent production re-performance. No carrier or provider has adopted this example. It does not establish authorization, policy, coverage, price, liability, a claim decision, or payment.';

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`,
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  const bytes = typeof value === 'string' ? value : canonicalize(value);
  return `sha256:${crypto.createHash('sha256').update(bytes, 'utf8').digest('hex')}`;
}

function caidFor(action) {
  const suffix = crypto.createHash('sha256')
    .update(canonicalize(action), 'utf8')
    .digest('base64url');
  return `caid:1:payment.release.1:jcs-sha256:${suffix}`;
}

function ed25519PrivateKey(seedByte) {
  return crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.alloc(32, seedByte),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
}

function hybridKeyMaterial(seedByte, issuerId, keyId) {
  const privateKey = ed25519PrivateKey(seedByte);
  const pq = mlDsa65.keygen(new Uint8Array(32).fill(seedByte));
  const pin = Object.freeze({
    issuer_id: issuerId,
    public_key: crypto.createPublicKey(privateKey)
      .export({ type: 'spki', format: 'der' })
      .toString('base64url'),
    pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
  });
  return Object.freeze({
    signer: Object.freeze({
      issuer_id: issuerId,
      key_id: keyId,
      private_key: privateKey,
      pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
    }),
    pin,
    pins: Object.freeze({ [keyId]: pin }),
  });
}

const scheduleKeys = hybridKeyMaterial(0x11, SCHEDULE_ISSUER, SCHEDULE_KEY_ID);
const statusKeys = hybridKeyMaterial(0x22, STATUS_AUTHORITY, STATUS_KEY_ID);
const sourceMaterials = Object.freeze([
  hybridKeyMaterial(0x33, 'authority:bank-settlement-feed', 'key:bank-settlement-feed:1'),
  hybridKeyMaterial(0x44, 'authority:erp-payment-ledger', 'key:erp-payment-ledger:1'),
]);

const sourceKeys = Object.freeze(Object.fromEntries(SOURCES.map((source, index) => [
  source.source_id,
  Object.freeze({
    public_key: sourceMaterials[index].pin.public_key,
    pq_public_key: sourceMaterials[index].pin.pq_public_key,
    role: source.role,
    source_class: source.source_class,
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_to: '2027-01-01T00:00:00.000Z',
    status: 'active',
    control_domain_id: index === 0 ? 'domain:bank-feed' : 'domain:erp-ledger',
  }),
])));

export const PAYMENT_ACTION = Object.freeze({
  action_type: 'payment.release',
  payment_instruction_id: 'payment:vendor-1042',
  amount_minor: '125000',
  currency: 'USD',
  payee_account_digest: digest('synthetic-payee:vendor-1042:account-7'),
});

/**
 * @param {Readonly<Record<string, string>>} action
 * @param {ProviderOutcome} outcome
 * @returns {Readonly<ProviderOutcomeContext>}
 */
function providerContext(action, outcome = 'COMMITTED') {
  return Object.freeze({
    '@version': PROVIDER_OUTCOME_CONTEXT_VERSION,
    tenant_id: TENANT,
    admission_id: 'admission:payment:1042',
    operation_id: 'operation:payment:1042',
    snapshot_digest: digest('snapshot:payment:1042'),
    caid: caidFor(action),
    action_digest: digest(action),
    effect_request_digest: digest({
      action,
      provider: 'provider:payment-api',
      account: 'account:merchant-production',
    }),
    provider: 'provider:payment-api',
    account: 'account:merchant-production',
    environment: 'production',
    adapter_id: 'adapter:payment-api:v1',
    idempotency_key: 'idempotency:operation:payment:1042',
    outcome,
    observed_at: PROVIDER_EVENT_AT,
  });
}

function scheduleSource() {
  return {
    schedule_id: SCHEDULE_ID,
    relying_party_id: RELYING_PARTY,
    tenant_id: TENANT,
    issued_at: '2026-09-04T12:00:00.000Z',
    valid_from: '2026-09-04T12:00:00.000Z',
    expires_at: '2026-10-04T12:00:00.000Z',
    action: {
      action_class: 'payment.release',
      caid_profile_id: 'caid-profile:payment-release:1',
      caid_profile_digest: digest('caid-profile:payment-release:1'),
    },
    provider_binding: {
      provider_id: 'provider:payment-api',
      account_id: 'account:merchant-production',
      environment: 'production',
      adapter_digest: digest('adapter:payment-api:v1'),
    },
    qualification: {
      requirements_digest: digest('qualification:payment-release:requirements:v1'),
      status_authority_id: STATUS_AUTHORITY,
      status_key_id: STATUS_KEY_ID,
      min_sequence: 12,
      max_observation_age_sec: 300,
    },
    control_bindings: {
      aeb_digest: digest('aeb:payment-release:v1'),
      aec_digest: digest('aec:payment-release:v1'),
      local_policy_digest: digest('policy:payment-release:v7'),
    },
    complete_mediation: {
      surface_inventory_digest: digest(REQUIRED_SURFACES),
      refusal_probe_evidence_digest: digest('probe:both-surfaces:block-without-receipt'),
    },
    loss_allocation: {
      program_digest: digest('loss-allocation:customer-carrier-signed-scope'),
    },
    open_exposure: {
      program_id: 'oel:carrier-pilot:finance',
      program_digest: digest('oel:carrier-pilot:finance:v1'),
      currency: 'USD',
      per_action_ceiling_minor: '1000000',
      aggregate_ceiling_minor: '5000000',
      reconciler_id: 'reconciler:carrier-pilot:finance',
      reconciliation_deadline_sec: 3600,
    },
    outcome_binding: {
      required_sources: SOURCES.map(({ role, source_class }) => ({ role, source_class })),
      quorum: 2,
      observation_window: {
        opens_before_provider_entry_sec: 0,
        closes_after_provider_entry_sec: 180,
        max_observation_age_sec: 180,
      },
      require_control_domain_independence: true,
    },
    handling: {
      indeterminate: ACTION_RISK_INDETERMINATE_HANDLING,
      divergent: ACTION_RISK_DIVERGENT_HANDLING,
    },
    trust_pin_references: [
      {
        purpose: 'QUALIFICATION_STATUS',
        authority_id: STATUS_AUTHORITY,
        key_id: STATUS_KEY_ID,
        key_digest: actionRiskHybridTrustPinDigest(STATUS_KEY_ID, statusKeys.pin),
      },
      {
        purpose: 'SCHEDULE_ISSUER',
        authority_id: SCHEDULE_ISSUER,
        key_id: SCHEDULE_KEY_ID,
        key_digest: actionRiskHybridTrustPinDigest(SCHEDULE_KEY_ID, scheduleKeys.pin),
      },
    ],
    claim_boundary: ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY,
  };
}

function observedControls(source) {
  return {
    action: structuredClone(source.action),
    provider_binding: structuredClone(source.provider_binding),
    qualification_requirements_digest: source.qualification.requirements_digest,
    control_bindings: structuredClone(source.control_bindings),
    complete_mediation: structuredClone(source.complete_mediation),
    loss_allocation: structuredClone(source.loss_allocation),
    open_exposure: structuredClone(source.open_exposure),
    outcome_binding: structuredClone(source.outcome_binding),
    handling: structuredClone(source.handling),
    trust_pin_references: structuredClone(source.trust_pin_references),
  };
}

async function qualificationStatus(schedule, input = {}) {
  return signActionRiskQualificationStatus({
    status_id: input.status_id ?? 'qualification-status:carrier-pilot:12',
    schedule_id: SCHEDULE_ID,
    schedule_digest: actionRiskControlScheduleDigest(schedule),
    tenant_id: TENANT,
    requirements_digest: digest('qualification:payment-release:requirements:v1'),
    sequence: input.sequence ?? 12,
    observed_at: input.observed_at ?? '2026-09-04T12:02:00.000Z',
    outcome: input.outcome ?? 'ELIGIBLE',
    evidence_digest: input.evidence_digest ?? digest('qualification-evidence:payment-release:12'),
    claim_boundary: ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY,
  }, statusKeys.signer, { deterministic: true });
}

function qualificationHead(schedule, status, input = {}) {
  return Object.freeze({
    schedule_id: SCHEDULE_ID,
    schedule_digest: actionRiskControlScheduleDigest(schedule),
    tenant_id: TENANT,
    status_authority_id: STATUS_AUTHORITY,
    status_key_id: STATUS_KEY_ID,
    sequence: input.sequence ?? status.sequence,
    status_digest: input.status_digest ?? actionRiskQualificationStatusDigest(status),
    recorded_at: input.recorded_at ?? '2026-09-04T12:02:10.000Z',
  });
}

function scheduleEvaluationOptions(source, status, head, now = NOW) {
  return {
    trusted_schedule_keys: scheduleKeys.pins,
    trusted_status_keys: statusKeys.pins,
    expected_schedule_id: SCHEDULE_ID,
    expected_issuer_id: SCHEDULE_ISSUER,
    expected_relying_party_id: RELYING_PARTY,
    expected_tenant_id: TENANT,
    observed_controls: observedControls(source),
    qualification_status: status,
    qualification_status_head: head,
    now,
  };
}

async function buildProviderEvidence(context) {
  const observations = await Promise.all(SOURCES.map((source, index) => (
    buildOutcomeObservationV2({
      receipt_id: `receipt:carrier-pilot:${index + 1}`,
      receipt_digest: digest(`receipt:carrier-pilot:${index + 1}`),
      action_hash: context.action_digest,
      action_caid: context.caid,
      consumption_nonce: `consumption:carrier-pilot:${index + 1}`,
      operation_id: context.operation_id,
      source,
      observed_from: index === 0
        ? PROVIDER_ENTRY_AT
        : '2026-09-04T12:01:05.000Z',
      observed_until: index === 0
        ? '2026-09-04T12:01:35.000Z'
        : '2026-09-04T12:01:40.000Z',
      attested_at: index === 0
        ? '2026-09-04T12:02:00.000Z'
        : '2026-09-04T12:02:05.000Z',
      observed_effects: providerOutcomeObservationEffects(context),
      signer: {
        privateKey: sourceMaterials[index].signer.private_key,
        pqPrivateKey: sourceMaterials[index].signer.pq_private_key,
        pqPublicKey: sourceMaterials[index].pin.pq_public_key,
      },
    })
  )));
  return {
    observations,
    bindings: observations.map((observation) => buildProviderOutcomeBinding({
      provider_context: context,
      outcome_observation: observation,
    })),
  };
}

function syntheticArtifact(role, state, subjectDigest, input = {}) {
  return Object.freeze({
    '@version': 'SYNTHETIC-CARRIER-PILOT-NATIVE-v1',
    role,
    artifact_id: `artifact:carrier-pilot:${role}`,
    subject_digest: subjectDigest,
    native_state: state,
    observed_at: '2026-09-04T12:02:10.000Z',
    ...input,
  });
}

function statesForOutcome(outcome, includeLoss) {
  const terminal = outcome === 'COMMITTED'
    ? 'CLOSED_COMMITTED'
    : outcome === 'PROVEN_NOT_COMMITTED'
      ? 'CLOSED_PROVEN_NOT_COMMITTED'
      : 'INDETERMINATE';
  return {
    ...DEFAULT_STATES,
    open_exposure_record: terminal,
    open_exposure_history: terminal,
    observed_effect_relation: outcome === 'INDETERMINATE'
      ? 'INDETERMINATE'
      : 'OBSERVED_AS_REQUESTED',
    loss_report: includeLoss ? 'LOSS_REPORTED' : null,
  };
}

/** @param {{ outcome?: ProviderOutcome, includeLoss?: boolean }} [input] */
async function buildFixture({ outcome = 'COMMITTED', includeLoss = false } = {}) {
  const source = scheduleSource();
  const schedule = await signActionRiskControlSchedule(
    source,
    scheduleKeys.signer,
    { deterministic: true },
  );
  const status = await qualificationStatus(schedule);
  const statusHead = qualificationHead(schedule, status);
  const context = providerContext(PAYMENT_ACTION, outcome);
  const subjectDigest = providerOutcomeContextDigest(context);
  const provider = await buildProviderEvidence(context);
  const states = statesForOutcome(outcome, includeLoss);
  const artifacts = {};

  for (const role of ACTION_EVIDENCE_COMPONENT_ROLES) {
    if (states[role] === null) continue;
    if (role === 'qualification_statement') {
      artifacts[role] = status;
    } else if (role === 'qualification_status_head') {
      artifacts[role] = statusHead;
    } else if (role === 'coverage_surface') {
      artifacts[role] = syntheticArtifact(role, states[role], subjectDigest, {
        required_surfaces: [...REQUIRED_SURFACES],
        covered_surfaces: [...REQUIRED_SURFACES],
      });
    } else {
      artifacts[role] = syntheticArtifact(role, states[role], subjectDigest);
    }
  }

  /** @type {ActionEvidenceManifest['components']} */
  const components = /** @type {ActionEvidenceManifest['components']} */ (Object.fromEntries(
    ACTION_EVIDENCE_COMPONENT_ROLES.map((role) => [
      role,
      states[role] === null ? null : {
        artifact_digest: actionEvidenceArtifactDigest(artifacts[role]),
        expected_state: states[role],
      },
    ]),
  ));

  /** @type {ActionEvidenceManifest} */
  const manifest = {
    '@version': ACTION_EVIDENCE_MANIFEST_VERSION,
    packet_id: `packet:carrier-pilot:${outcome.toLowerCase()}:${includeLoss ? 'loss' : 'no-loss'}`,
    assembled_at: ASSEMBLED_AT,
    subject: context,
    subject_digest: subjectDigest,
    schedule: {
      artifact_digest: actionEvidenceArtifactDigest(schedule),
      evaluation: 'ELIGIBLE',
    },
    components,
    provider_outcomes: SOURCES.map((sourceIdentity, index) => ({
      binding_artifact_digest: actionEvidenceArtifactDigest(provider.bindings[index]),
      outcome_observation_artifact_digest: actionEvidenceArtifactDigest(provider.observations[index]),
      expected_source: sourceIdentity,
    })),
    claim_boundary: ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY,
  };
  const attachments = [
    schedule,
    ...provider.bindings,
    ...provider.observations,
    ...ACTION_EVIDENCE_COMPONENT_ROLES
      .filter((role) => states[role] !== null)
      .map((role) => artifacts[role]),
  ];
  const packet = buildActionEvidencePacket({ manifest, attachments });
  return {
    source,
    schedule,
    status,
    statusHead,
    context,
    provider,
    states,
    artifacts,
    manifest,
    packet,
  };
}

function nativeState(role, artifact) {
  if (role === 'qualification_statement') return 'QUALIFIED';
  if (role === 'qualification_status_head') return 'CURRENT';
  return artifact?.native_state;
}

function makeSyntheticComponentVerifiers(fixture) {
  const trustedDigests = Object.fromEntries(ACTION_EVIDENCE_COMPONENT_ROLES
    .filter((role) => fixture.states[role] !== null)
    .map((role) => [role, actionEvidenceArtifactDigest(fixture.artifacts[role])]));
  const trustedSubjectDigest = providerOutcomeContextDigest(fixture.context);

  return Object.fromEntries(ACTION_EVIDENCE_COMPONENT_ROLES.map((role) => {
    /** @type {ActionEvidenceComponentVerifier} */
    const verifier = (request) => {
      const actualDigest = actionEvidenceArtifactDigest(request.artifact);
      /** @type {Record<string, any>} */
      const artifact = request.artifact !== null
        && typeof request.artifact === 'object'
        && !Array.isArray(request.artifact)
        ? request.artifact
        : {};
      const state = nativeState(role, artifact);
      const digestAccepted = actualDigest === trustedDigests[role];
      const stateAccepted = state === request.expected_state;
      const subjectAccepted = role === 'qualification_statement'
        || role === 'qualification_status_head'
        || artifact.subject_digest === trustedSubjectDigest;
      const surfacesAccepted = role !== 'coverage_surface'
        || artifact.required_surfaces.every(
          (surface) => artifact.covered_surfaces.includes(surface),
        );
      const verified = digestAccepted && stateAccepted && subjectAccepted && surfacesAccepted;
      return {
        verification: verified ? 'VERIFIED' : 'NOT_VERIFIED',
        currentness: 'CURRENT',
        artifact_digest: actualDigest,
        subject_digest: trustedSubjectDigest,
        state: typeof state === 'string' ? state : 'UNKNOWN',
        reason: verified
          ? null
          : surfacesAccepted
            ? 'synthetic_native_binding_failed'
            : 'surface_inventory_incomplete',
      };
    };
    return [role, verifier];
  }));
}

/** @returns {ActionEvidenceScheduleVerifier} */
function makeScheduleVerifier(fixture) {
  return async (request) => {
    const evaluation = await evaluateActionRiskControlSchedule(
      request.artifact,
      scheduleEvaluationOptions(
        fixture.source,
        fixture.status,
        fixture.statusHead,
        request.now,
      ),
    );
    const cryptographicallyVerified = evaluation.schedule_verified === true
      && evaluation.qualification_status_verified === true;
    return {
      verification: cryptographicallyVerified ? 'VERIFIED' : 'NOT_VERIFIED',
      currentness: evaluation.outcome === 'INDETERMINATE' ? 'INDETERMINATE' : 'CURRENT',
      artifact_digest: actionEvidenceArtifactDigest(request.artifact),
      subject_digest: providerOutcomeContextDigest(fixture.context),
      evaluation: evaluation.outcome,
      outcome_requirements: structuredClone(fixture.schedule.outcome_binding),
      reason: evaluation.outcome === 'ELIGIBLE' ? null : evaluation.reason,
    };
  };
}

/** @returns {VerifyActionEvidencePacketOptions} */
function verificationOptions(fixture, input = {}) {
  return {
    expected_context: input.expectedContext ?? fixture.context,
    now: NOW,
    verify_schedule: makeScheduleVerifier(fixture),
    component_verifiers: makeSyntheticComponentVerifiers(fixture),
    provider_outcome: {
      source_keys: sourceKeys,
      provider_entry_at: PROVIDER_ENTRY_AT,
      maximum_observation_age_ms: 120_000,
    },
  };
}

function replaceArtifact(fixture, oldArtifact, replacement, updateManifest) {
  const oldDigest = actionEvidenceArtifactDigest(oldArtifact);
  const attachments = Object.values(fixture.packet.attachments)
    .filter((artifact) => actionEvidenceArtifactDigest(artifact) !== oldDigest);
  attachments.push(replacement);
  const manifest = structuredClone(fixture.manifest);
  updateManifest(manifest, actionEvidenceArtifactDigest(replacement));
  return buildActionEvidencePacket({ manifest, attachments });
}

function digestOnlyProviderPacket(fixture) {
  const index = 0;
  const originalObservation = fixture.provider.observations[index];
  const originalBinding = fixture.provider.bindings[index];
  const digestOnly = {
    '@version': 'SYNTHETIC-DIGEST-ONLY-PROVIDER-SOURCE-v1',
    source_id: SOURCES[index].source_id,
    claimed_observation_digest: actionEvidenceArtifactDigest(originalObservation),
  };
  const digestOnlyBinding = {
    '@version': PROVIDER_OUTCOME_BINDING_VERSION,
    provider_context: structuredClone(fixture.context),
    provider_context_digest: providerOutcomeContextDigest(fixture.context),
    outcome_observation_digest: actionEvidenceArtifactDigest(digestOnly),
    claim_boundary: PROVIDER_OUTCOME_BINDING_CLAIM_BOUNDARY,
  };
  const removed = new Set([
    actionEvidenceArtifactDigest(originalObservation),
    actionEvidenceArtifactDigest(originalBinding),
  ]);
  const attachments = Object.values(fixture.packet.attachments)
    .filter((artifact) => !removed.has(actionEvidenceArtifactDigest(artifact)));
  attachments.push(digestOnlyBinding, digestOnly);
  const manifest = structuredClone(fixture.manifest);
  manifest.provider_outcomes[index] = {
    ...manifest.provider_outcomes[index],
    binding_artifact_digest: actionEvidenceArtifactDigest(digestOnlyBinding),
    outcome_observation_artifact_digest: actionEvidenceArtifactDigest(digestOnly),
  };
  return buildActionEvidencePacket({ manifest, attachments });
}

function omittedSurfacePacket(fixture) {
  const replacement = syntheticArtifact(
    'coverage_surface',
    'gated',
    providerOutcomeContextDigest(fixture.context),
    {
      required_surfaces: [...REQUIRED_SURFACES],
      covered_surfaces: ['provider_api'],
    },
  );
  return {
    packet: replaceArtifact(
      fixture,
      fixture.artifacts.coverage_surface,
      replacement,
      (manifest, digestValue) => {
        manifest.components.coverage_surface.artifact_digest = digestValue;
      },
    ),
    artifact: replacement,
  };
}

function fixtureWithArtifact(fixture, role, artifact, packet) {
  return {
    ...fixture,
    packet,
    artifacts: { ...fixture.artifacts, [role]: artifact },
  };
}

function expectedContextForSubstitutedPayee(baseContext) {
  const substituted = {
    ...PAYMENT_ACTION,
    payee_account_digest: digest('synthetic-payee:attacker:account-9'),
  };
  return {
    ...baseContext,
    caid: caidFor(substituted),
    action_digest: digest(substituted),
    effect_request_digest: digest({
      action: substituted,
      provider: baseContext.provider,
      account: baseContext.account,
    }),
  };
}

function resultSummary(verification) {
  return {
    packet_result: verification.result,
    reasons: [...verification.reasons],
  };
}

export async function runCarrierActionPilot() {
  const committed = await buildFixture();
  const eligibleEvaluation = await evaluateActionRiskControlSchedule(
    committed.schedule,
    scheduleEvaluationOptions(
      committed.source,
      committed.status,
      committed.statusHead,
    ),
  );
  const positiveVerification = await verifyActionEvidencePacket(
    committed.packet,
    verificationOptions(committed),
  );

  const substitutedContext = expectedContextForSubstitutedPayee(committed.context);
  const substitutionVerification = await verifyActionEvidencePacket(
    committed.packet,
    verificationOptions(committed, { expectedContext: substitutedContext }),
  );

  const suspendedStatus = await qualificationStatus(committed.schedule, {
    status_id: 'qualification-status:carrier-pilot:13:suspended',
    sequence: 13,
    observed_at: '2026-09-04T12:02:20.000Z',
    outcome: 'NOT_ELIGIBLE',
    evidence_digest: digest('qualification-evidence:payment-release:13:suspended'),
  });
  const suspendedEvaluation = await evaluateActionRiskControlSchedule(
    committed.schedule,
    scheduleEvaluationOptions(
      committed.source,
      suspendedStatus,
      qualificationHead(committed.schedule, suspendedStatus, {
        recorded_at: '2026-09-04T12:02:30.000Z',
      }),
    ),
  );

  const rollbackEvaluation = await evaluateActionRiskControlSchedule(
    committed.schedule,
    scheduleEvaluationOptions(
      committed.source,
      committed.status,
      qualificationHead(committed.schedule, suspendedStatus, {
        recorded_at: '2026-09-04T12:02:30.000Z',
      }),
    ),
  );

  const digestOnlyVerification = await verifyActionEvidencePacket(
    digestOnlyProviderPacket(committed),
    verificationOptions(committed),
  );

  const indeterminate = await buildFixture({ outcome: 'INDETERMINATE' });
  const indeterminateVerification = await verifyActionEvidencePacket(
    indeterminate.packet,
    verificationOptions(indeterminate),
  );

  const omitted = omittedSurfacePacket(committed);
  const omittedFixture = fixtureWithArtifact(
    committed,
    'coverage_surface',
    omitted.artifact,
    omitted.packet,
  );
  const omittedSurfaceVerification = await verifyActionEvidencePacket(
    omitted.packet,
    verificationOptions(omittedFixture),
  );

  const lossReported = await buildFixture({ includeLoss: true });
  const lossReportedVerification = await verifyActionEvidencePacket(
    lossReported.packet,
    verificationOptions(lossReported),
  );
  const lossScheduleEvaluation = await evaluateActionRiskControlSchedule(
    lossReported.schedule,
    scheduleEvaluationOptions(
      lossReported.source,
      lossReported.status,
      lossReported.statusHead,
    ),
  );

  assert.equal(positiveVerification.result, 'TECHNICALLY_COMPLETE');

  return Object.freeze({
    example: 'carrier-action-pilot',
    action: 'payment.release',
    native_verifier_mode: 'synthetic_test_adapters',
    claim_boundary: PILOT_BOUNDARY,
    positive: {
      ...resultSummary(positiveVerification),
      schedule_evaluation: eligibleEvaluation.outcome,
      authorizes_action: eligibleEvaluation.authorizes_action,
      establishes_coverage: eligibleEvaluation.establishes_coverage,
    },
    payee_substitution: {
      ...resultSummary(substitutionVerification),
      packet_accepted_for_substituted_action: false,
    },
    qualification_suspended: {
      schedule_evaluation: suspendedEvaluation.outcome,
      reason: suspendedEvaluation.reason,
      provider_entry_permitted: false,
    },
    qualification_rollback: {
      schedule_evaluation: rollbackEvaluation.outcome,
      reason: rollbackEvaluation.reason,
      provider_entry_permitted: false,
    },
    digest_only_provider_source: {
      ...resultSummary(digestOnlyVerification),
      source_treated_as_verified: false,
    },
    lost_or_unclear_provider_result: {
      ...resultSummary(indeterminateVerification),
      open_exposure: 'PRESERVED',
      retry_allowed: false,
      required_handling: ACTION_RISK_INDETERMINATE_HANDLING,
    },
    omitted_provider_surface: {
      ...resultSummary(omittedSurfaceVerification),
      complete_mediation_established: false,
    },
    loss_reported: {
      ...resultSummary(lossReportedVerification),
      loss_artifact_verified: lossReportedVerification.verified_components.includes('loss_report'),
      establishes_coverage: lossScheduleEvaluation.establishes_coverage,
      coverage_decision: null,
      claim_payment_decision: null,
    },
  });
}

const entry = process.argv[1] ? pathToFileURL(process.argv[1]).href : null;
if (entry === import.meta.url) {
  const result = await runCarrierActionPilot();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
