// SPDX-License-Identifier: Apache-2.0
/**
 * Public, synthetic healthcare composition over the existing EMILIA
 * Proposal-to-Effect controller.
 *
 * This module deliberately does not implement an execution state machine.
 * Reservation, provider-entry custody, replay fencing, indeterminate outcomes,
 * and authenticated reconciliation remain owned by Proposal-to-Effect, AEB,
 * and Gate. The healthcare layer contributes:
 *
 *   scanner projection -> exact hospice administrative action -> Proposal-to-
 *   Effect -> protected sandbox callback -> append-only assurance export.
 *
 * A scanner finding is not prior authorization, clinical judgment, a fraud
 * conclusion, or payment authority.
 */

import { computeCaid } from '../../caid/impl/js/caid.mjs';
import type {
  ConsequenceAttemptBinding,
  ConsequenceAttemptReference,
  ProposalToEffectProfile,
  ProposalToEffectProposal,
} from '../../packages/gate/proposal-to-effect.js';
import { hashCanonicalAction } from '../guard-policies.js';

type JsonObject = Record<string, any>;

export const HEALTHCARE_CONSEQUENCE_PROFILE_VERSION =
  'EMILIA-HEALTHCARE-CONSEQUENCE-CONTROL-v1';
export const HEALTHCARE_SCANNER_FINDING_VERSION =
  'EMILIA-HEALTHCARE-ADMINISTRATIVE-FINDING-v1';
export const PROSPECTIVE_CONTROL_PACKAGE_SCHEMA =
  'emilia.commercial.prospective-control-package.v1';
export const HEALTHCARE_CONTROL_PACKAGE_VERSION =
  PROSPECTIVE_CONTROL_PACKAGE_SCHEMA;
export const HEALTHCARE_ASSURANCE_PACKET_VERSION =
  'EMILIA-HEALTHCARE-CONSEQUENCE-ASSURANCE-PACKET-v1';
export const HOSPICE_ACTION_VERSION =
  'EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v1';
export const HOSPICE_PROFILE_ID = 'medi-cal.hospice-integrity.v1';
export const HOSPICE_ACTION_TYPE =
  'health.medi-cal.hospice-claim-payment.1';
export const HOSPICE_PROPOSAL_PROFILE_ID =
  'healthcare.hospice-payment.consequence-control.v1';
export const HOSPICE_AEB_REQUIREMENT_REF =
  'requirement:healthcare-hospice-consequence-control';

export const HOSPICE_ACTION_FIELDS = Object.freeze([
  '@version',
  'profile_id',
  'action_type',
  'organization_id',
  'provider_npi',
  'member_ref',
  'service_period_start',
  'service_period_end',
  'authorization_form_digest',
  'amount',
  'currency',
  'payment_destination_digest',
  'reviewer_id',
  'authority_proof_digest',
  'policy_id',
  'policy_version',
  'policy_hash',
] as const);

export const HOSPICE_CAID_DEFINITION = Object.freeze({
  action_type: HOSPICE_ACTION_TYPE,
  required_fields: [
    { name: '@version', type: 'string' },
    { name: 'profile_id', type: 'string' },
    { name: 'organization_id', type: 'string' },
    { name: 'provider_npi', type: 'string' },
    { name: 'member_ref', type: 'string' },
    { name: 'service_period_start', type: 'string' },
    { name: 'service_period_end', type: 'string' },
    { name: 'authorization_form_digest', type: 'digest' },
    { name: 'amount', type: 'amount-string' },
    { name: 'currency', type: 'enum', values: ['USD'] },
    { name: 'payment_destination_digest', type: 'digest' },
    { name: 'reviewer_id', type: 'string' },
    { name: 'authority_proof_digest', type: 'digest' },
    { name: 'policy_id', type: 'string' },
    { name: 'policy_version', type: 'integer' },
    { name: 'policy_hash', type: 'digest' },
  ],
  optional_fields: [],
});

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const CAID_RE =
  /^caid:1:health\.medi-cal\.hospice-claim-payment\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const MEMBER_REF_RE = /^member:sha256:[a-f0-9]{64}$/;
const MONEY_RE = /^(?:0|[1-9][0-9]*)\.[0-9]{2}$/;
const PROHIBITED_PHI_FIELDS = new Set([
  'account_number',
  'member_name',
  'patient_name',
  'beneficiary_id',
  'bic',
  'cin',
  'date_of_birth',
  'dob',
  'address',
  'telephone',
  'phone',
  'email',
  'ssn',
  'medicare_beneficiary_identifier',
  'diagnosis',
  'diagnosis_text',
  'clinical_note',
  'authorization_form',
  'bank_account',
  'routing_number',
  'raw_provider_evidence',
]);
const RUNTIME_DOWNGRADE_FIELDS = new Set([
  'action_caid',
  'authorized',
  'bypass_checks',
  'enforcement_mode',
  'fail_open',
  'permit',
]);
const EXPORTABLE_DECISIONS = new Set([
  'EXECUTED',
  'INDETERMINATE',
  'RECONCILED_EXECUTED',
  'RECONCILED_NOT_EXECUTED',
]);

export const HEALTHCARE_ASSURANCE_LIMITATIONS = Object.freeze([
  'This packet covers a synthetic, relying-party-governed hospice payment administrative action in a sandbox callback only.',
  'A scanner finding identifies a control requirement; it is not prior authorization, clinical judgment, a fraud determination, or authority to pay or withhold care.',
  'The packet does not establish medical necessity, service delivery, coding correctness, claim validity, provider or member real-world identity, or source-system truth.',
  'No live Medicare, Medi-Cal, insurer, provider, bank, or payment-rail mutation is claimed.',
  'EXECUTED means the configured protected sandbox callback completed and Proposal-to-Effect committed its exact operation; INDETERMINATE does not prove success or failure.',
  'The packet supports verification and re-performance procedures; it is not an audit opinion, certification, regulatory conclusion, or clinical conclusion.',
] as const);

function isPlainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function digest(value: unknown): string {
  return `sha256:${hashCanonicalAction(value as Record<string, unknown>)}`;
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_RE.test(value);
}

function validDateOnly(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed.getTime())
    && parsed.toISOString().slice(0, 10) === value;
}

function exactKeys(value: unknown, keys: readonly string[]): value is JsonObject {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && expected.every((key, index) => key === actual[index]);
}

function prohibitedPhi(
  value: unknown,
  depth = 0,
  budget: { entries: number } = { entries: 0 },
): string | null {
  if (depth > 10 || budget.entries > 4096) return 'input_complexity_limit';
  if (Array.isArray(value)) {
    for (const entry of value) {
      budget.entries += 1;
      const found = prohibitedPhi(entry, depth + 1, budget);
      if (found) return found;
    }
    return null;
  }
  if (!isPlainObject(value)) return null;
  for (const [key, entry] of Object.entries(value)) {
    budget.entries += 1;
    if (PROHIBITED_PHI_FIELDS.has(key)) return key;
    const found = prohibitedPhi(entry, depth + 1, budget);
    if (found) return found;
  }
  return null;
}

function refusal(reason: string, extras: JsonObject = {}): JsonObject {
  return { ok: false, decision: 'REFUSED', reason, ...extras };
}

function safeReason(error: unknown, fallback: string): string {
  const candidate = isPlainObject(error) && typeof error.message === 'string'
    ? error.message
    : error instanceof Error
      ? error.message
      : '';
  return /^[a-z0-9][a-z0-9:_-]{2,127}$/i.test(candidate)
    ? candidate.toLowerCase()
    : fallback;
}

export interface CanonicalHospiceAction {
  action: JsonObject;
  caid: string;
  action_digest: string;
}

/**
 * Relying-party-owned exact action projection used both before proposal
 * creation and again at the protected callback boundary.
 */
export function canonicalizeHospicePaymentAction(input: unknown): CanonicalHospiceAction {
  if (!exactKeys(input, HOSPICE_ACTION_FIELDS)) {
    throw new Error('healthcare_action_shape_invalid');
  }
  const phi = prohibitedPhi(input);
  if (phi) throw new Error('healthcare_prohibited_phi');
  if ([...RUNTIME_DOWNGRADE_FIELDS].some((field) => Object.hasOwn(input, field))) {
    throw new Error('healthcare_runtime_downgrade_refused');
  }
  if (input['@version'] !== HOSPICE_ACTION_VERSION
      || input.profile_id !== HOSPICE_PROFILE_ID
      || input.action_type !== HOSPICE_ACTION_TYPE) {
    throw new Error('healthcare_action_profile_mismatch');
  }
  for (const field of [
    'organization_id',
    'provider_npi',
    'member_ref',
    'service_period_start',
    'service_period_end',
    'authorization_form_digest',
    'amount',
    'currency',
    'payment_destination_digest',
    'reviewer_id',
    'authority_proof_digest',
    'policy_id',
    'policy_hash',
  ]) {
    if (typeof input[field] !== 'string' || input[field].length === 0) {
      throw new Error(`healthcare_material_field_missing:${field}`);
    }
  }
  if (!identifier(input.organization_id)
      || !/^\d{10}$/.test(input.provider_npi)
      || !MEMBER_REF_RE.test(input.member_ref)
      || !validDateOnly(input.service_period_start)
      || !validDateOnly(input.service_period_end)
      || input.service_period_start > input.service_period_end
      || !DIGEST_RE.test(input.authorization_form_digest)
      || !MONEY_RE.test(input.amount)
      || Number(input.amount) <= 0
      || input.currency !== 'USD'
      || !DIGEST_RE.test(input.payment_destination_digest)
      || !identifier(input.reviewer_id)
      || !DIGEST_RE.test(input.authority_proof_digest)
      || !identifier(input.policy_id)
      || !Number.isSafeInteger(input.policy_version)
      || input.policy_version < 1
      || !DIGEST_RE.test(input.policy_hash)) {
    throw new Error('healthcare_material_action_invalid');
  }

  const action = clone(input);
  const computed = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: [HOSPICE_CAID_DEFINITION],
  });
  if (!computed?.caid || !computed?.digest
      || !CAID_RE.test(computed.caid)
      || !DIGEST_RE.test(computed.digest)) {
    throw new Error('healthcare_action_caid_generation_failed');
  }
  return {
    action,
    caid: computed.caid,
    action_digest: computed.digest,
  };
}

export function createHospiceProposalToEffectProfile({
  authorization_endpoint,
  ttl_sec = 300,
}: {
  authorization_endpoint: string;
  ttl_sec?: number;
}): ProposalToEffectProfile {
  if (typeof authorization_endpoint !== 'string') {
    throw new Error('healthcare_authorization_endpoint_invalid');
  }
  let endpoint: URL;
  try {
    endpoint = new URL(authorization_endpoint);
  } catch {
    throw new Error('healthcare_authorization_endpoint_invalid');
  }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password
      || endpoint.hash || endpoint.origin === 'null') {
    throw new Error('healthcare_authorization_endpoint_invalid');
  }
  if (!Number.isSafeInteger(ttl_sec) || ttl_sec < 1 || ttl_sec > 900) {
    throw new Error('healthcare_proposal_ttl_invalid');
  }
  return Object.freeze({
    id: HOSPICE_PROPOSAL_PROFILE_ID,
    action_type: HOSPICE_ACTION_TYPE,
    selector: Object.freeze({
      action_type: HOSPICE_ACTION_TYPE,
      protocol: 'https',
      method: 'POST',
      path: '/synthetic/health/hospice-claim/payment',
    }),
    // Proposal-to-Effect acquisition field names use the identifier grammar
    // and therefore cannot spell JSON-LD's "@version". The canonicalizer still
    // requires and binds @version as part of the exact CAID action.
    required_fields: HOSPICE_ACTION_FIELDS.filter((field) => field !== '@version'),
    authorization: Object.freeze({
      authorization_endpoint: endpoint.toString(),
      flow: 'EP-APPROVAL-v1' as const,
    }),
    aeb_requirement_ref: HOSPICE_AEB_REQUIREMENT_REF,
    ttl_sec,
    canonicalize_action(input: unknown) {
      const canonical = canonicalizeHospicePaymentAction(input);
      return { action: canonical.action, caid: canonical.caid };
    },
  });
}

export interface ProspectiveHealthcareControlPackage {
  schema: typeof PROSPECTIVE_CONTROL_PACKAGE_SCHEMA;
  claimBoundary:
    'prospective_control_from_triage_not_historical_authorization_or_fraud_proof';
  controlPurpose: 'new_future_action_pre_effect_control';
  retroactiveAuthorization: 'none';
  tenantId: string;
  caseId: string;
  caseDigest: string;
  sourceRecordDigests: string[];
  sourceFinding: {
    code: 'MISSING_APPROVAL';
    confidence: 'deterministic';
    role: 'retrospective_triage_evidence_only';
    provesHistoricalAuthorization: false;
    provesFraud: false;
    authorizesScannedExecution: false;
  };
  profile: {
    id: typeof HOSPICE_PROFILE_ID;
    version: 1;
    proposalToEffect: 'EMILIA-PROPOSAL-TO-EFFECT-v1';
  };
  policy: {
    id: string;
    version: number;
    hash: string;
  };
  action: JsonObject;
  caid: string;
  actionDigest: string;
  requiredControl: {
    approval: {
      required: true;
      receiptProfile: 'EP-RECEIPT-v1';
      assuranceClass: 'class_a';
    };
    quorum: {
      minimumApprovals: 1;
      distinctApprovers: 1;
    };
    freshness: {
      actionMaxAgeSec: 300;
      revocationMaxStalenessSec: 900;
    };
    consumption: {
      mode: 'one_time';
      maximumUses: 1;
    };
  };
  phi: {
    rawPhiIncluded: false;
    memberReference: 'pairwise_pseudonymous_commitment';
  };
  packageDigest: string;
}

export interface HealthcareEvidenceEvent {
  event_id: string;
  sequence: number;
  tenant_id: string;
  operation_id: string;
  event_type: 'PREPARED' | 'EXECUTION' | 'RECONCILIATION';
  recorded_at: string;
  payload: JsonObject;
}

export interface HealthcareEvidenceStore {
  appendOnly: true;
  tenantBound: true;
  durable: boolean;
  append(input: Omit<HealthcareEvidenceEvent, 'event_id' | 'sequence'>):
    Promise<HealthcareEvidenceEvent>;
  list(input: { tenant_id: string; operation_id: string }):
    Promise<HealthcareEvidenceEvent[]>;
}

export interface HealthcareReconciliationHandleStore {
  serverSideOnly: true;
  durable: boolean;
  put(input: {
    tenant_id: string;
    operation_id: string;
    handle: ConsequenceAttemptReference;
  }): Promise<void>;
  get(input: {
    tenant_id: string;
    operation_id: string;
  }): Promise<ConsequenceAttemptReference | null>;
}

export interface ProposalToEffectController {
  prepare(input: {
    proposal_id: string;
    profile_id: string;
    operation_id: string;
    initiator_id: string;
    action: unknown;
  }): ProposalToEffectProposal;
  verifyProposal(input: unknown, options?: { allowExpired?: boolean }): {
    proposal: ProposalToEffectProposal;
    profile: JsonObject;
  };
  execute(
    input: { proposal: unknown; receipt: unknown; evaluation: unknown },
    effect: (input: {
      action: JsonObject;
      proposal: ProposalToEffectProposal;
      authorization: JsonObject;
      attempt: ConsequenceAttemptBinding;
    }) => unknown | Promise<unknown>,
  ): Promise<JsonObject>;
  reconcile(input: {
    proposal: unknown;
    evaluation: unknown;
    attempt: ConsequenceAttemptReference;
    provider_evidence: unknown;
  }): Promise<JsonObject>;
  getReconciliationHandle(target: object): ConsequenceAttemptReference | null;
}

function memoryKey(tenantId: string, operationId: string): string {
  return `${tenantId}\0${operationId}`;
}

/** Explicitly test/demo-only in-memory evidence and capability custody. */
export function createMemoryHealthcareControlStores(): {
  evidence_store: HealthcareEvidenceStore;
  reconciliation_handle_store: HealthcareReconciliationHandleStore;
} {
  const events = new Map<string, HealthcareEvidenceEvent[]>();
  const handles = new Map<string, ConsequenceAttemptReference>();
  const evidence_store: HealthcareEvidenceStore = {
    appendOnly: true,
    tenantBound: true,
    durable: false,
    async append(input) {
      const key = memoryKey(input.tenant_id, input.operation_id);
      const sequence = (events.get(key)?.length ?? 0) + 1;
      const unsigned = { ...clone(input), sequence };
      const event: HealthcareEvidenceEvent = {
        ...unsigned,
        event_id: digest({
          domain: HEALTHCARE_CONSEQUENCE_PROFILE_VERSION,
          ...unsigned,
        }),
      };
      events.set(key, [...(events.get(key) ?? []), clone(event)]);
      return clone(event);
    },
    async list(input) {
      return clone(events.get(memoryKey(input.tenant_id, input.operation_id)) ?? []);
    },
  };
  const reconciliation_handle_store: HealthcareReconciliationHandleStore = {
    serverSideOnly: true,
    durable: false,
    async put(input) {
      handles.set(
        memoryKey(input.tenant_id, input.operation_id),
        clone(input.handle),
      );
    },
    async get(input) {
      const handle = handles.get(memoryKey(input.tenant_id, input.operation_id));
      return handle ? clone(handle) : null;
    },
  };
  return { evidence_store, reconciliation_handle_store };
}

function normalizeProspectiveControlPackage(
  value: unknown,
  expectedTenant: string,
): {
  control_package: ProspectiveHealthcareControlPackage;
  finding: JsonObject;
  canonical: CanonicalHospiceAction;
} {
  if (!exactKeys(value, [
    'action',
    'actionDigest',
    'caid',
    'caseDigest',
    'caseId',
    'claimBoundary',
    'controlPurpose',
    'packageDigest',
    'phi',
    'policy',
    'profile',
    'requiredControl',
    'retroactiveAuthorization',
    'schema',
    'sourceFinding',
    'sourceRecordDigests',
    'tenantId',
  ]) || value.schema !== PROSPECTIVE_CONTROL_PACKAGE_SCHEMA
      || value.claimBoundary
        !== 'prospective_control_from_triage_not_historical_authorization_or_fraud_proof'
      || value.controlPurpose !== 'new_future_action_pre_effect_control'
      || value.retroactiveAuthorization !== 'none'
      || value.tenantId !== expectedTenant
      || !identifier(value.caseId)
      || !DIGEST_RE.test(value.caseDigest)
      || !DIGEST_RE.test(value.packageDigest)
      || !Array.isArray(value.sourceRecordDigests)
      || value.sourceRecordDigests.length < 1
      || value.sourceRecordDigests.length > 256) {
    throw new Error('prospective_control_package_invalid');
  }
  for (const source of value.sourceRecordDigests) {
    if (!DIGEST_RE.test(source)) {
      throw new Error('prospective_control_package_invalid');
    }
  }
  if (!exactKeys(value.sourceFinding, [
    'authorizesScannedExecution',
    'code',
    'confidence',
    'provesFraud',
    'provesHistoricalAuthorization',
    'role',
  ]) || value.sourceFinding.code !== 'MISSING_APPROVAL'
      || value.sourceFinding.confidence !== 'deterministic'
      || value.sourceFinding.role !== 'retrospective_triage_evidence_only'
      || value.sourceFinding.provesHistoricalAuthorization !== false
      || value.sourceFinding.provesFraud !== false
      || value.sourceFinding.authorizesScannedExecution !== false) {
    throw new Error('prospective_control_finding_boundary_invalid');
  }
  if (!exactKeys(value.profile, ['id', 'proposalToEffect', 'version'])
      || value.profile.id !== HOSPICE_PROFILE_ID
      || value.profile.version !== 1
      || value.profile.proposalToEffect !== 'EMILIA-PROPOSAL-TO-EFFECT-v1') {
    throw new Error('prospective_control_profile_invalid');
  }
  if (!exactKeys(value.policy, ['hash', 'id', 'version'])
      || !identifier(value.policy.id)
      || !Number.isSafeInteger(value.policy.version)
      || value.policy.version < 1
      || !DIGEST_RE.test(value.policy.hash)) {
    throw new Error('prospective_control_policy_invalid');
  }
  if (!exactKeys(value.requiredControl, [
    'approval',
    'consumption',
    'freshness',
    'quorum',
  ])
      || !exactKeys(value.requiredControl.approval, [
        'assuranceClass',
        'receiptProfile',
        'required',
      ])
      || value.requiredControl.approval.required !== true
      || value.requiredControl.approval.receiptProfile !== 'EP-RECEIPT-v1'
      || value.requiredControl.approval.assuranceClass !== 'class_a'
      || !exactKeys(value.requiredControl.quorum, [
        'distinctApprovers',
        'minimumApprovals',
      ])
      || value.requiredControl.quorum.minimumApprovals !== 1
      || value.requiredControl.quorum.distinctApprovers !== 1
      || !exactKeys(value.requiredControl.freshness, [
        'actionMaxAgeSec',
        'revocationMaxStalenessSec',
      ])
      || value.requiredControl.freshness.actionMaxAgeSec !== 300
      || value.requiredControl.freshness.revocationMaxStalenessSec !== 900
      || !exactKeys(value.requiredControl.consumption, [
        'maximumUses',
        'mode',
      ])
      || value.requiredControl.consumption.mode !== 'one_time'
      || value.requiredControl.consumption.maximumUses !== 1) {
    throw new Error('prospective_control_requirement_invalid');
  }
  if (!exactKeys(value.phi, ['memberReference', 'rawPhiIncluded'])
      || value.phi.rawPhiIncluded !== false
      || value.phi.memberReference !== 'pairwise_pseudonymous_commitment') {
    throw new Error('prospective_control_phi_boundary_invalid');
  }
  const canonical = canonicalizeHospicePaymentAction(value.action);
  if (canonical.action.organization_id !== expectedTenant
      || value.caid !== canonical.caid
      || value.actionDigest !== canonical.action_digest
      || value.policy.id !== canonical.action.policy_id
      || value.policy.version !== canonical.action.policy_version
      || value.policy.hash !== canonical.action.policy_hash) {
    throw new Error('prospective_control_action_mismatch');
  }
  const unsigned = clone(value);
  delete unsigned.packageDigest;
  if (digest(unsigned) !== value.packageDigest) {
    throw new Error('prospective_control_package_digest_invalid');
  }
  const control_package = clone(value) as ProspectiveHealthcareControlPackage;
  const finding = {
    '@version': HEALTHCARE_SCANNER_FINDING_VERSION,
    provenance_schema: PROSPECTIVE_CONTROL_PACKAGE_SCHEMA,
    case_id: control_package.caseId,
    case_digest: control_package.caseDigest,
    package_digest: control_package.packageDigest,
    source_record_digests: clone(control_package.sourceRecordDigests),
    source_finding: clone(control_package.sourceFinding),
    disposition: 'CONTROL_REQUIRED',
    scope: 'administrative_hospice_payment',
    triage_provenance_only: true,
    authorization_evidence: false,
    prior_authorization: false,
    clinical_judgment: false,
    fraud_determination: false,
    payment_authority: false,
  };
  return { control_package, finding, canonical };
}

function validateControlPackage(
  value: unknown,
  expectedTenant: string,
): { case_id: string; canonical: CanonicalHospiceAction } {
  const normalized = normalizeProspectiveControlPackage(value, expectedTenant);
  return {
    case_id: normalized.control_package.caseId,
    canonical: normalized.canonical,
  };
}

function publicAttempt(value: unknown): ConsequenceAttemptBinding | null {
  if (!isPlainObject(value)) return null;
  const fields = [
    'tenant_id',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
    'request_digest',
  ];
  if (!fields.every((field) => typeof value[field] === 'string')) return null;
  return Object.fromEntries(
    fields.map((field) => [field, value[field]]),
  ) as unknown as ConsequenceAttemptBinding;
}

function projectControllerResult(value: unknown): JsonObject {
  if (!isPlainObject(value)) return {};
  const result: JsonObject = {};
  if (typeof value.ok === 'boolean') result.ok = value.ok;
  if (identifier(value.reason)) result.reason = value.reason;
  if (identifier(value.state)) result.state = value.state;
  if (identifier(value.outcome)) result.outcome = value.outcome;
  if (DIGEST_RE.test(value.evidence_digest)) {
    result.evidence_digest = value.evidence_digest;
  }
  if (isPlainObject(value.aeb)) {
    result.aeb = {
      ...(identifier(value.aeb.state) ? { state: value.aeb.state } : {}),
      ...(typeof value.aeb.retry_allowed === 'boolean'
        ? { retry_allowed: value.aeb.retry_allowed }
        : {}),
      ...(identifier(value.aeb.reason) ? { reason: value.aeb.reason } : {}),
    };
  }
  const attempt = publicAttempt(value.consequence?.attempt);
  if (isPlainObject(value.consequence)) {
    result.consequence = {
      ...(identifier(value.consequence.state)
        ? { state: value.consequence.state }
        : {}),
      ...(attempt ? { attempt } : {}),
    };
  }
  return result;
}

function verifyPreparedContext(
  events: HealthcareEvidenceEvent[],
  proposal: ProposalToEffectProposal,
  tenantId: string,
): JsonObject | null {
  const prepared = [...events].reverse().find((event) => (
    event.event_type === 'PREPARED'
    && event.payload?.proposal_digest === digest(proposal)
  ));
  if (!prepared || prepared.tenant_id !== tenantId
      || prepared.operation_id !== proposal.operation_id
      || !isPlainObject(prepared.payload?.control_package)) {
    return null;
  }
  try {
    const control = validateControlPackage(
      prepared.payload.control_package,
      tenantId,
    );
    if (control.canonical.caid !== proposal.caid
        || control.canonical.action_digest !== proposal.aeb_action_digest
        || control.canonical.action_digest !== proposal.action_digest) {
      return null;
    }
  } catch {
    return null;
  }
  return prepared.payload;
}

export interface HealthcareConsequenceControlOptions {
  controller: ProposalToEffectController;
  evidence_store: HealthcareEvidenceStore;
  reconciliation_handle_store: HealthcareReconciliationHandleStore;
  mutate_sandbox(input: {
    tenant_id: string;
    operation_id: string;
    action: JsonObject;
    authorization: JsonObject;
    attempt: ConsequenceAttemptBinding;
  }): Promise<unknown> | unknown;
  now?: () => number;
  allow_ephemeral_stores_for_tests?: boolean;
}

export function createHealthcareConsequenceControl(
  options: HealthcareConsequenceControlOptions,
) {
  if (!options?.controller
      || typeof options.controller.prepare !== 'function'
      || typeof options.controller.verifyProposal !== 'function'
      || typeof options.controller.execute !== 'function'
      || typeof options.controller.reconcile !== 'function'
      || typeof options.controller.getReconciliationHandle !== 'function') {
    throw new Error('healthcare_proposal_to_effect_controller_required');
  }
  if (!options.evidence_store
      || options.evidence_store.appendOnly !== true
      || options.evidence_store.tenantBound !== true
      || typeof options.evidence_store.append !== 'function'
      || typeof options.evidence_store.list !== 'function') {
    throw new Error('healthcare_evidence_store_required');
  }
  if (!options.reconciliation_handle_store
      || options.reconciliation_handle_store.serverSideOnly !== true
      || typeof options.reconciliation_handle_store.put !== 'function'
      || typeof options.reconciliation_handle_store.get !== 'function') {
    throw new Error('healthcare_reconciliation_handle_store_required');
  }
  if (options.allow_ephemeral_stores_for_tests !== true
      && (options.evidence_store.durable !== true
        || options.reconciliation_handle_store.durable !== true)) {
    throw new Error('healthcare_durable_stores_required');
  }
  if (typeof options.mutate_sandbox !== 'function') {
    throw new Error('healthcare_sandbox_mutation_required');
  }
  const now = options.now ?? Date.now;

  function currentTime(): number {
    const value = now();
    if (!Number.isSafeInteger(value) || !Number.isFinite(new Date(value).getTime())) {
      throw new Error('healthcare_clock_invalid');
    }
    return value;
  }

  async function appendEvent(input: Omit<HealthcareEvidenceEvent, 'event_id' | 'sequence'>) {
    return options.evidence_store.append(clone(input));
  }

  async function prepare(input: {
    tenant_id: string;
    initiator_id: string;
    proposal_id: string;
    operation_id: string;
    prospective_control_package: unknown;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!identifier(input?.initiator_id)) return refusal('authenticated_initiator_required');
    if (!identifier(input?.proposal_id) || !identifier(input?.operation_id)) {
      return refusal('healthcare_operation_identity_invalid');
    }
    let normalized: ReturnType<typeof normalizeProspectiveControlPackage>;
    try {
      normalized = normalizeProspectiveControlPackage(
        input.prospective_control_package,
        input.tenant_id,
      );
    } catch (error) {
      return refusal(safeReason(error, 'healthcare_preparation_refused'));
    }
    const { canonical, finding, control_package: control } = normalized;

    let proposal: ProposalToEffectProposal;
    try {
      proposal = options.controller.prepare({
        proposal_id: input.proposal_id,
        profile_id: HOSPICE_PROPOSAL_PROFILE_ID,
        operation_id: input.operation_id,
        initiator_id: input.initiator_id,
        action: canonical.action,
      });
      const verified = options.controller.verifyProposal(proposal);
      if (verified.proposal.caid !== canonical.caid
          || verified.proposal.action_digest !== canonical.action_digest
          || verified.proposal.aeb_action_digest !== canonical.action_digest
          || verified.proposal.consequence.tenant_id !== input.tenant_id
          || verified.proposal.consequence.environment !== 'sandbox') {
        return refusal('healthcare_proposal_binding_mismatch');
      }
    } catch (error) {
      return refusal(safeReason(error, 'healthcare_proposal_preparation_failed'));
    }

    try {
      await appendEvent({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
        event_type: 'PREPARED',
        recorded_at: new Date(currentTime()).toISOString(),
        payload: {
          finding: clone(finding),
          control_package: clone(control),
          proposal: clone(proposal),
          proposal_digest: digest(proposal),
        },
      });
    } catch {
      return refusal('healthcare_evidence_store_unavailable');
    }
    return {
      ok: true,
      decision: 'APPROVAL_REQUIRED',
      finding,
      control_package: control,
      proposal,
      authorization: clone(proposal.authorization),
      challenge: clone(proposal.challenge),
    };
  }

  async function execute(input: {
    tenant_id: string;
    proposal: unknown;
    approval_evidence: unknown;
    evaluation: unknown;
    observed_action: unknown;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!isPlainObject(input?.approval_evidence)) {
      return refusal('approval_evidence_required');
    }
    if (!isPlainObject(input?.evaluation)) {
      return refusal('aeb_evaluation_required');
    }
    const evidencePhi = prohibitedPhi({
      approval_evidence: input.approval_evidence,
      evaluation: input.evaluation,
    });
    if (evidencePhi) return refusal('healthcare_prohibited_phi');

    let proposal: ProposalToEffectProposal;
    let observed: CanonicalHospiceAction;
    try {
      proposal = options.controller.verifyProposal(input.proposal).proposal;
      observed = canonicalizeHospicePaymentAction(input.observed_action);
    } catch (error) {
      return refusal(safeReason(error, 'healthcare_execution_input_refused'));
    }
    if (proposal.consequence.tenant_id !== input.tenant_id
        || proposal.consequence.environment !== 'sandbox') {
      return refusal('tenant_or_environment_mismatch');
    }
    if (observed.caid !== proposal.caid
        || observed.action_digest !== proposal.action_digest
        || observed.action_digest !== proposal.aeb_action_digest) {
      return refusal('execution_action_mismatch');
    }

    let events: HealthcareEvidenceEvent[];
    try {
      events = await options.evidence_store.list({
        tenant_id: input.tenant_id,
        operation_id: proposal.operation_id,
      });
    } catch {
      return refusal('healthcare_evidence_store_unavailable');
    }
    const prepared = verifyPreparedContext(events, proposal, input.tenant_id);
    if (!prepared) return refusal('healthcare_prepared_context_mismatch');

    const baseEvidence = {
      approval_evidence: clone(input.approval_evidence),
      approval_evidence_digest: digest(input.approval_evidence),
      aeb_evaluation: clone(input.evaluation),
      aeb_evaluation_digest: digest(input.evaluation),
      proposal_digest: digest(proposal),
    };
    try {
      const result = await options.controller.execute({
        proposal,
        receipt: input.approval_evidence,
        evaluation: input.evaluation,
      }, async ({ action, authorization, attempt, proposal: callbackProposal }) => {
        const callbackAction = canonicalizeHospicePaymentAction(action);
        if (callbackProposal.operation_id !== proposal.operation_id
            || callbackProposal.caid !== proposal.caid
            || callbackAction.caid !== observed.caid
            || callbackAction.action_digest !== observed.action_digest
            || attempt.tenant_id !== input.tenant_id
            || attempt.provider_id !== proposal.consequence.provider_id
            || attempt.provider_account_id
              !== proposal.consequence.provider_account_id
            || attempt.environment !== 'sandbox'
            || attempt.request_digest !== proposal.consequence.request_digest) {
          throw new Error('healthcare_protected_callback_binding_mismatch');
        }
        return options.mutate_sandbox({
          tenant_id: input.tenant_id,
          operation_id: proposal.operation_id,
          action: clone(observed.action),
          authorization: clone(authorization),
          attempt: clone(attempt),
        });
      });

      const projected = projectControllerResult(result);
      const state = projected.consequence?.state;
      const attempt = publicAttempt(projected.consequence?.attempt);
      if (state === 'COMMITTED') {
        try {
          await appendEvent({
            tenant_id: input.tenant_id,
            operation_id: proposal.operation_id,
            event_type: 'EXECUTION',
            recorded_at: new Date(currentTime()).toISOString(),
            payload: {
              ...baseEvidence,
              decision: 'EXECUTED',
              proposal_to_effect: projected,
              attempt,
            },
          });
        } catch {
          return {
            ok: false,
            decision: 'INDETERMINATE',
            reason: 'healthcare_assurance_record_unavailable',
            operation_id: proposal.operation_id,
            action_caid: proposal.caid,
            reconciliation_required: true,
            retry_safe: false,
          };
        }
        return {
          ok: true,
          decision: 'EXECUTED',
          operation_id: proposal.operation_id,
          action_caid: proposal.caid,
          attempt,
          reconciliation_required: false,
          retry_safe: false,
        };
      }

      if (state === 'INDETERMINATE') {
        const handle = options.controller.getReconciliationHandle(result);
        if (handle) {
          await options.reconciliation_handle_store.put({
            tenant_id: input.tenant_id,
            operation_id: proposal.operation_id,
            handle,
          }).catch(() => undefined);
        }
        await appendEvent({
          tenant_id: input.tenant_id,
          operation_id: proposal.operation_id,
          event_type: 'EXECUTION',
          recorded_at: new Date(currentTime()).toISOString(),
          payload: {
            ...baseEvidence,
            decision: 'INDETERMINATE',
            proposal_to_effect: projected,
            attempt,
          },
        }).catch(() => undefined);
        return {
          ok: false,
          decision: 'INDETERMINATE',
          reason: identifier(projected.reason)
            ? projected.reason
            : 'provider_outcome_indeterminate',
          operation_id: proposal.operation_id,
          action_caid: proposal.caid,
          attempt,
          reconciliation_required: true,
          retry_safe: false,
        };
      }
      return refusal(
        identifier(projected.reason) ? projected.reason : 'proposal_to_effect_refused',
        {
          operation_id: proposal.operation_id,
          action_caid: proposal.caid,
          retry_safe: state === 'RELEASED',
        },
      );
    } catch (error) {
      const metadata = isPlainObject((error as any)?.proposalToEffect)
        ? (error as any).proposalToEffect
        : {};
      const attempt = publicAttempt(metadata.attempt);
      const state = metadata.attempt_state;
      if (state !== 'INDETERMINATE') {
        return refusal(safeReason(error, 'proposal_to_effect_refused'), {
          operation_id: proposal.operation_id,
          action_caid: proposal.caid,
        });
      }
      const handle = options.controller.getReconciliationHandle(error as object);
      if (handle) {
        await options.reconciliation_handle_store.put({
          tenant_id: input.tenant_id,
          operation_id: proposal.operation_id,
          handle,
        }).catch(() => undefined);
      }
      await appendEvent({
        tenant_id: input.tenant_id,
        operation_id: proposal.operation_id,
        event_type: 'EXECUTION',
        recorded_at: new Date(currentTime()).toISOString(),
        payload: {
          ...baseEvidence,
          decision: 'INDETERMINATE',
          proposal_to_effect: {
            consequence: { state: 'INDETERMINATE', attempt },
          },
          attempt,
        },
      }).catch(() => undefined);
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'provider_outcome_indeterminate',
        operation_id: proposal.operation_id,
        action_caid: proposal.caid,
        attempt,
        reconciliation_required: true,
        retry_safe: false,
      };
    }
  }

  async function reconcile(input: {
    tenant_id: string;
    operation_id: string;
    proposal: unknown;
    evaluation: unknown;
    provider_evidence: unknown;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!identifier(input?.operation_id)) return refusal('operation_id_required');
    if (!isPlainObject(input?.evaluation)) return refusal('aeb_evaluation_required');
    if (!isPlainObject(input?.provider_evidence)) {
      return refusal('authenticated_provider_evidence_required');
    }
    if (prohibitedPhi(input.provider_evidence)) {
      return refusal('healthcare_prohibited_phi');
    }
    let proposal: ProposalToEffectProposal;
    try {
      proposal = options.controller.verifyProposal(
        input.proposal,
        { allowExpired: true },
      ).proposal;
    } catch (error) {
      return refusal(safeReason(error, 'healthcare_reconciliation_input_refused'));
    }
    if (proposal.consequence.tenant_id !== input.tenant_id
        || proposal.operation_id !== input.operation_id) {
      return refusal('reconciliation_operation_mismatch');
    }

    let events: HealthcareEvidenceEvent[];
    try {
      events = await options.evidence_store.list({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
      });
    } catch {
      return refusal('healthcare_evidence_store_unavailable');
    }
    if (!verifyPreparedContext(events, proposal, input.tenant_id)) {
      return refusal('healthcare_prepared_context_mismatch');
    }
    const indeterminate = [...events].reverse().find((event) => (
      event.event_type === 'EXECUTION'
      && event.payload?.decision === 'INDETERMINATE'
    ));
    const attempt = publicAttempt(indeterminate?.payload?.attempt);
    if (!indeterminate || !attempt) {
      return refusal('reconciliation_not_indeterminate');
    }
    if (input.provider_evidence.operation_id !== input.operation_id) {
      return refusal('provider_evidence_operation_mismatch', {
        decision: 'INDETERMINATE',
        retry_safe: false,
      });
    }
    if (input.provider_evidence.attempt_id !== attempt.attempt_id) {
      return refusal('provider_evidence_attempt_mismatch', {
        decision: 'INDETERMINATE',
        retry_safe: false,
      });
    }
    let handle: ConsequenceAttemptReference | null;
    try {
      handle = await options.reconciliation_handle_store.get({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
      });
    } catch {
      handle = null;
    }
    if (!handle || handle.tenant_id !== input.tenant_id
        || handle.attempt_id !== attempt.attempt_id) {
      return refusal('reconciliation_handle_unavailable', {
        decision: 'INDETERMINATE',
        retry_safe: false,
      });
    }

    let result: JsonObject;
    try {
      result = await options.controller.reconcile({
        proposal,
        evaluation: input.evaluation,
        attempt: handle,
        provider_evidence: input.provider_evidence,
      });
    } catch {
      return refusal('provider_evidence_unverified', {
        decision: 'INDETERMINATE',
        retry_safe: false,
      });
    }
    const projected = projectControllerResult(result);
    if (result.ok !== true) {
      return refusal(
        identifier(result.reason) ? result.reason : 'provider_evidence_unverified',
        {
          decision: 'INDETERMINATE',
          operation_id: input.operation_id,
          action_caid: proposal.caid,
          reconciliation_required: true,
          retry_safe: false,
        },
      );
    }
    const state = result.state;
    const decision = state === 'COMMITTED'
      ? 'RECONCILED_EXECUTED'
      : state === 'RELEASED'
        ? 'RECONCILED_NOT_EXECUTED'
        : 'INDETERMINATE';
    const evidenceDigest = DIGEST_RE.test(result.evidence_digest)
      ? result.evidence_digest
      : digest(input.provider_evidence);
    try {
      await appendEvent({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
        event_type: 'RECONCILIATION',
        recorded_at: new Date(currentTime()).toISOString(),
        payload: {
          decision,
          provider_evidence: clone(input.provider_evidence),
          provider_evidence_digest: evidenceDigest,
          authenticated_provider_evidence: true,
          proposal_to_effect: projected,
          attempt,
        },
      });
    } catch {
      return {
        ok: false,
        decision: 'INDETERMINATE',
        reason: 'healthcare_assurance_record_unavailable',
        operation_id: input.operation_id,
        action_caid: proposal.caid,
        reconciliation_required: true,
        retry_safe: false,
      };
    }
    return {
      ok: decision !== 'INDETERMINATE',
      decision,
      operation_id: input.operation_id,
      action_caid: proposal.caid,
      provider_evidence_digest: evidenceDigest,
      authenticated_provider_evidence: true,
      reconciliation_required: decision === 'INDETERMINATE',
      retry_safe: state === 'RELEASED',
    };
  }

  async function exportAssurancePacket(input: {
    tenant_id: string;
    operation_id: string;
  }): Promise<JsonObject> {
    if (!identifier(input?.tenant_id)) return refusal('tenant_required');
    if (!identifier(input?.operation_id)) return refusal('operation_id_required');
    let events: HealthcareEvidenceEvent[];
    try {
      events = await options.evidence_store.list({
        tenant_id: input.tenant_id,
        operation_id: input.operation_id,
      });
    } catch {
      return refusal('healthcare_evidence_store_unavailable');
    }
    const prepared = events.find((event) => event.event_type === 'PREPARED');
    const execution = [...events].reverse().find(
      (event) => event.event_type === 'EXECUTION',
    );
    const reconciliation = [...events].reverse().find(
      (event) => event.event_type === 'RECONCILIATION',
    );
    const terminal = reconciliation ?? execution;
    if (!prepared || !terminal
        || !EXPORTABLE_DECISIONS.has(terminal.payload?.decision)
        || !isPlainObject(prepared.payload?.proposal)
        || !isPlainObject(prepared.payload?.control_package)) {
      return refusal('healthcare_assurance_packet_not_available');
    }
    const proposal = prepared.payload.proposal as ProposalToEffectProposal;
    if (proposal.operation_id !== input.operation_id
        || proposal.consequence?.tenant_id !== input.tenant_id
        || !verifyPreparedContext(events, proposal, input.tenant_id)) {
      return refusal('healthcare_assurance_evidence_conflict');
    }
    const packet: JsonObject = {
      '@version': HEALTHCARE_ASSURANCE_PACKET_VERSION,
      profile: {
        id: HOSPICE_PROPOSAL_PROFILE_ID,
        action_type: HOSPICE_ACTION_TYPE,
        environment: 'sandbox',
        synthetic: true,
      },
      tenant_id: input.tenant_id,
      operation_id: input.operation_id,
      finding: clone(prepared.payload.finding),
      control_package: clone(prepared.payload.control_package),
      protocol_evidence: {
        proposal: clone(proposal),
        proposal_digest: prepared.payload.proposal_digest,
        approval_evidence: clone(execution?.payload?.approval_evidence ?? null),
        approval_evidence_digest:
          execution?.payload?.approval_evidence_digest ?? null,
        aeb_evaluation: clone(execution?.payload?.aeb_evaluation ?? null),
        aeb_evaluation_digest:
          execution?.payload?.aeb_evaluation_digest ?? null,
        proposal_to_effect: clone(terminal.payload.proposal_to_effect ?? null),
        provider_reconciliation_evidence:
          clone(reconciliation?.payload?.provider_evidence ?? null),
        provider_reconciliation_evidence_digest:
          reconciliation?.payload?.provider_evidence_digest ?? null,
      },
      outcome: {
        decision: terminal.payload.decision,
        attempt: clone(terminal.payload.attempt),
        reconciliation_required:
          terminal.payload.decision === 'INDETERMINATE',
        authenticated_reconciliation:
          reconciliation?.payload?.authenticated_provider_evidence === true,
        retry_safe:
          terminal.payload.decision === 'RECONCILED_NOT_EXECUTED',
      },
      chronology: events.map((event) => ({
        event_id: event.event_id,
        sequence: event.sequence,
        event_type: event.event_type,
        recorded_at: event.recorded_at,
      })),
      verification_scope: {
        self_digest: true,
        exact_action_caid_recomputable: true,
        signatures_must_be_reverified_under_relying_party_pins: true,
        population_completeness_established: false,
      },
      limitations: [...HEALTHCARE_ASSURANCE_LIMITATIONS],
      assembled_at: terminal.recorded_at,
    };
    if (prohibitedPhi(packet)) {
      return refusal('healthcare_assurance_packet_phi_refused');
    }
    packet.packet_digest = digest(packet);
    return packet;
  }

  return Object.freeze({
    prepare,
    execute,
    reconcile,
    exportAssurancePacket,
  });
}

export type HealthcareConsequenceControl =
  ReturnType<typeof createHealthcareConsequenceControl>;

export function verifyHealthcareAssurancePacket(packet: unknown): {
  valid: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  if (!isPlainObject(packet)
      || packet['@version'] !== HEALTHCARE_ASSURANCE_PACKET_VERSION) {
    return { valid: false, reasons: ['packet_shape_invalid'] };
  }
  if (prohibitedPhi(packet)) reasons.push('packet_contains_prohibited_phi');
  const unsigned = clone(packet);
  delete unsigned.packet_digest;
  if (!DIGEST_RE.test(packet.packet_digest)
      || packet.packet_digest !== digest(unsigned)) {
    reasons.push('packet_digest_invalid');
  }
  if (!identifier(packet.tenant_id)
      || !identifier(packet.operation_id)
      || packet.profile?.id !== HOSPICE_PROPOSAL_PROFILE_ID
      || packet.profile?.action_type !== HOSPICE_ACTION_TYPE
      || packet.profile?.environment !== 'sandbox'
      || packet.profile?.synthetic !== true) {
    reasons.push('packet_profile_invalid');
  }
  let canonical: CanonicalHospiceAction | null = null;
  let normalizedControl: ReturnType<typeof normalizeProspectiveControlPackage> | null = null;
  try {
    normalizedControl = normalizeProspectiveControlPackage(
      packet.control_package,
      packet.tenant_id,
    );
    canonical = normalizedControl.canonical;
  } catch {
    reasons.push('packet_action_invalid');
  }
  if (normalizedControl
      && digest(packet.finding) !== digest(normalizedControl.finding)) {
    reasons.push('packet_finding_binding_invalid');
  }
  if (canonical
      && (canonical.action.organization_id !== packet.tenant_id
        || canonical.caid !== packet.control_package?.caid
        || canonical.action_digest !== packet.control_package?.actionDigest
        || canonical.caid !== packet.protocol_evidence?.proposal?.caid
        || canonical.action_digest
          !== packet.protocol_evidence?.proposal?.action_digest
        || canonical.action_digest
          !== packet.protocol_evidence?.proposal?.aeb_action_digest)) {
    reasons.push('packet_action_binding_invalid');
  }
  if (!EXPORTABLE_DECISIONS.has(packet.outcome?.decision)
      || packet.outcome?.reconciliation_required
        !== (packet.outcome?.decision === 'INDETERMINATE')
      || !Array.isArray(packet.chronology)
      || packet.chronology.length < 2
      || !Array.isArray(packet.limitations)
      || digest(packet.limitations) !== digest(HEALTHCARE_ASSURANCE_LIMITATIONS)) {
    reasons.push('packet_outcome_invalid');
  }
  const packetAttempt = publicAttempt(packet.outcome?.attempt);
  if (!packetAttempt
      || packetAttempt.tenant_id !== packet.tenant_id
      || packetAttempt.provider_id
        !== packet.protocol_evidence?.proposal?.consequence?.provider_id
      || packetAttempt.provider_account_id
        !== packet.protocol_evidence?.proposal?.consequence?.provider_account_id
      || packetAttempt.environment !== 'sandbox'
      || packetAttempt.request_digest
        !== packet.protocol_evidence?.proposal?.consequence?.request_digest) {
    reasons.push('packet_attempt_binding_invalid');
  }
  if (!DIGEST_RE.test(packet.protocol_evidence?.proposal_digest)
      || packet.protocol_evidence.proposal_digest
        !== digest(packet.protocol_evidence.proposal)) {
    reasons.push('packet_proposal_digest_invalid');
  }
  if (!isPlainObject(packet.protocol_evidence?.approval_evidence)
      || !DIGEST_RE.test(packet.protocol_evidence?.approval_evidence_digest)
      || packet.protocol_evidence.approval_evidence_digest
        !== digest(packet.protocol_evidence.approval_evidence)
      || !isPlainObject(packet.protocol_evidence?.aeb_evaluation)
      || !DIGEST_RE.test(packet.protocol_evidence?.aeb_evaluation_digest)
      || packet.protocol_evidence.aeb_evaluation_digest
        !== digest(packet.protocol_evidence.aeb_evaluation)) {
    reasons.push('packet_approval_evidence_invalid');
  }
  if (packet.outcome?.authenticated_reconciliation === true) {
    const provider = packet.protocol_evidence?.provider_reconciliation_evidence;
    if (!isPlainObject(provider)
        || !DIGEST_RE.test(
          packet.protocol_evidence?.provider_reconciliation_evidence_digest,
        )
        || packet.protocol_evidence.provider_reconciliation_evidence_digest
          !== digest(provider)
        || provider.authenticated !== true
        || provider.operation_id !== packet.operation_id
        || provider.tenant_id !== packet.tenant_id
        || provider.caid !== canonical?.caid
        || provider.action_digest !== canonical?.action_digest
        || provider.attempt_id !== packetAttempt?.attempt_id
        || provider.request_digest !== packetAttempt?.request_digest
        || provider.provider_id !== packetAttempt?.provider_id
        || provider.provider_account_id !== packetAttempt?.provider_account_id
        || provider.environment !== packetAttempt?.environment) {
      reasons.push('packet_reconciliation_evidence_invalid');
    }
  }
  return { valid: reasons.length === 0, reasons: [...new Set(reasons)] };
}
