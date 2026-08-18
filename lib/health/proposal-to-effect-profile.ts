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

import crypto from 'node:crypto';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import type {
  ConsequenceAttemptBinding,
  ConsequenceAttemptReference,
  ProposalToEffectProfile,
  ProposalToEffectProposal,
} from '../../packages/gate/proposal-to-effect.js';
import { canonicalize } from '../canonical-json.js';
import { hashCanonicalAction } from '../guard-policies.js';
import {
  signAgile,
  verifyAgileSignatureSet,
  type AgileSignature,
} from '@emilia-protocol/verify/pq-signature-agility';
import { checkOperationPolicy, type FipsPosture } from '@emilia-protocol/verify/fips-mode';

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
export const HEALTHCARE_ASSURANCE_TRUST_BUNDLE_VERSION =
  'EMILIA-HEALTHCARE-ASSURANCE-TRUST-BUNDLE-v1';
export const HEALTHCARE_ASSURANCE_ASSERTION_VERSION =
  'EMILIA-HEALTHCARE-ASSURANCE-ASSERTION-v1';

/**
 * Hybrid (Ed25519 + ML-DSA-65) siblings of the assertion and packet above.
 * REFERENCE MIGRATION FOLLOWED: packages/verify/src/revocation.ts
 * EP-REVOCATION-v2. Five moves, in order:
 *   1. VERSION BUMP, NOT A FIELD BUMP -- a second signature changes the SHAPE
 *      of `proof`, so each artifact takes a new `@version`. v1's
 *      checkHealthcareAssurancePacketInternalConsistency() and
 *      verifyHealthcareAssurancePacketOffline() are left callable with their
 *      original single-argument behavior; a v2 packet fails v1's exact-version
 *      check ('packet_shape_invalid') before any proof is inspected.
 *   2. SET SHAPE -- `proof` carries `required_algorithms` plus a `signatures`
 *      array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *      ({ alg, sig, key_id? }), reused verbatim.
 *   3. ANTI-STRIPPING BYTES -- required_algorithms is INSIDE the signed bytes
 *      (see signAssuranceValueV2 below), rebuilt by the verifier from the
 *      REGISTERED set, never from what the artifact presents.
 *   4. V1 COMPATIBILITY -- v1 stays fully synchronous. V2 verification is
 *      ASYNC (ML-DSA verification is async): separate entry points
 *      (verifyHealthcareAssurancePacketOfflineV2) plus a router
 *      (verifyHealthcareAssurancePacketOfflineAny).
 *   5. NAMED REFUSALS -- every failure names a reason; nothing throws; an
 *      absent ML-DSA backend is 'pq_backend_unavailable', never a pass.
 */
export const HEALTHCARE_ASSURANCE_ASSERTION_V2_VERSION =
  'EMILIA-HEALTHCARE-ASSURANCE-ASSERTION-v2';
export const HEALTHCARE_ASSURANCE_PACKET_V2_VERSION =
  'EMILIA-HEALTHCARE-CONSEQUENCE-ASSURANCE-PACKET-v2';
export const HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS =
  Object.freeze(['Ed25519', 'ML-DSA-65'] as const);
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
const PROHIBITED_PHI_FIELD_ALIASES = new Set([
  'accountnumber',
  'membername',
  'patientname',
  'beneficiaryid',
  'bic',
  'cin',
  'dateofbirth',
  'dob',
  'address',
  'telephone',
  'phone',
  'email',
  'ssn',
  'medicarebeneficiaryidentifier',
  'diagnosis',
  'diagnosistext',
  'clinicalnote',
  'authorizationform',
  'bankaccount',
  'routingnumber',
  'rawproviderevidence',
  'freetext',
  'freeformtext',
  'freetextnote',
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
  'RECONCILED_EXECUTED',
  'RECONCILED_NOT_EXECUTED',
]);
const RECONCILED_DECISIONS = new Set([
  'RECONCILED_EXECUTED',
  'RECONCILED_NOT_EXECUTED',
]);
const ASSURANCE_SIGNATURE_DOMAIN =
  'EMILIA-HEALTHCARE-CONSEQUENCE-ASSURANCE-v1';
const ASSURANCE_ROLES = [
  'evaluator',
  'receipt',
  'aeb',
  'provider',
] as const;
type HealthcareAssuranceRole = typeof ASSURANCE_ROLES[number];

export const HEALTHCARE_ASSURANCE_LIMITATIONS = Object.freeze([
  'This packet covers a synthetic, relying-party-governed hospice payment administrative action in a sandbox callback only.',
  'A scanner finding identifies a control requirement; it is not prior authorization, clinical judgment, a fraud determination, or authority to pay or withhold care.',
  'The packet does not establish medical necessity, service delivery, coding correctness, claim validity, provider or member real-world identity, or source-system truth.',
  'No live Medicare, Medi-Cal, insurer, provider, bank, or payment-rail mutation is claimed.',
  'EXECUTED means the configured protected sandbox callback completed and Proposal-to-Effect committed its exact operation; INDETERMINATE does not prove success or failure.',
  'Field-name filtering and allowlisted projections reduce exposure but are not proof that PHI is absent; deployments must apply source-system classification, DLP, access control, and authorized privacy review.',
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

const HOSPICE_RELIANCE_PROGRAM_DIGEST = digest({
  '@version': HEALTHCARE_CONSEQUENCE_PROFILE_VERSION,
  profile_id: HOSPICE_PROPOSAL_PROFILE_ID,
  action_type: HOSPICE_ACTION_TYPE,
  action_version: HOSPICE_ACTION_VERSION,
  aeb_requirement_ref: HOSPICE_AEB_REQUIREMENT_REF,
  action_fields: HOSPICE_ACTION_FIELDS,
});

function signingBytes(domain: string, value: unknown): Buffer {
  return Buffer.from(`${ASSURANCE_SIGNATURE_DOMAIN}:${domain}\0${canonicalize(value)}`);
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

function normalizedFieldAlias(value: string): string {
  return value.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
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
    if (PROHIBITED_PHI_FIELD_ALIASES.has(normalizedFieldAlias(key))) return key;
    const found = prohibitedPhi(entry, depth + 1, budget);
    if (found) return found;
  }
  return null;
}

function canonicalBase64url(
  value: unknown,
  expectedBytes?: number,
): Buffer | null {
  if (typeof value !== 'string'
      || value.length === 0
      || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  try {
    const decoded = Buffer.from(value, 'base64url');
    if ((expectedBytes !== undefined && decoded.length !== expectedBytes)
        || decoded.toString('base64url') !== value) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function assuranceProofShape(value: unknown): value is JsonObject {
  return exactKeys(value, [
    'algorithm',
    'key_id',
    'signature_b64u',
  ])
    && value.algorithm === 'Ed25519'
    && identifier(value.key_id)
    && canonicalBase64url(value.signature_b64u, 64) !== null;
}

function signerShape(value: unknown): value is HealthcareAssuranceSigner {
  return isPlainObject(value)
    && value.algorithm === 'Ed25519'
    && identifier(value.key_id)
    && typeof value.sign === 'function';
}

/**
 * v2 hybrid signer: the SAME injected Ed25519 custody signer shape as v1
 * (there is no honest KMS/HSM ML-DSA-65 custody path today; see
 * docs/protocol/pq-hybrid-program.md), plus an ML-DSA-65 secret key used only
 * through signAgile (never reimplemented here).
 */
export interface HealthcareAssuranceHybridSigner {
  ed25519: HealthcareAssuranceSigner;
  mldsa65: {
    key_id: string;
    /** Raw ML-DSA-65 secret key (4032 bytes) or its base64url encoding. */
    private_key: Uint8Array | string;
  };
}

function hybridSignerShape(value: unknown): value is HealthcareAssuranceHybridSigner {
  return isPlainObject(value)
    && signerShape(value.ed25519)
    && isPlainObject(value.mldsa65)
    && identifier(value.mldsa65.key_id)
    && (value.mldsa65.private_key instanceof Uint8Array
      || typeof value.mldsa65.private_key === 'string');
}

export function assuranceProofV2Shape(value: unknown): value is JsonObject {
  return exactKeys(value, ['profile', 'required_algorithms', 'signatures'])
    && value.profile === HEALTHCARE_ASSURANCE_PACKET_V2_VERSION
    && Array.isArray(value.required_algorithms)
    && value.required_algorithms.length === HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS.length
    && HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS.every(
      (alg, index) => value.required_algorithms[index] === alg,
    )
    && Array.isArray(value.signatures)
    && value.signatures.length === HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS.length;
}

/**
 * The single custody call site (injected signer.sign()) this file's proof
 * primitives all fund through. Opt-in FIPS consult: `fips` is undefined for
 * every existing caller, so this branch is not taken and behavior is
 * byte-identical to before the consult existed (pinned by a regression
 * test). When `fips` is supplied and the policy denies the classical leg,
 * this refuses BEFORE calling signer.sign(), never after.
 */
async function signAssuranceValue(
  domain: string,
  value: unknown,
  signer: HealthcareAssuranceSigner,
  fips?: { posture?: FipsPosture; allow_unvalidated_mldsa?: boolean },
): Promise<JsonObject> {
  if (fips) {
    const decision = checkOperationPolicy('Ed25519', fips.posture, {
      allow_unvalidated_mldsa: fips.allow_unvalidated_mldsa,
    });
    if (!decision.permitted) {
      throw new Error(`healthcare_assurance_fips_policy_denied:${decision.reason}`);
    }
  }
  const signed = await signer.sign(signingBytes(domain, value));
  const signature = typeof signed === 'string'
    ? canonicalBase64url(signed, 64)
    : signed instanceof Uint8Array
      ? Buffer.from(signed)
      : null;
  if (!signature || signature.length !== 64) {
    throw new Error('healthcare_assurance_signature_invalid');
  }
  return {
    algorithm: 'Ed25519',
    key_id: signer.key_id,
    signature_b64u: signature.toString('base64url'),
  };
}

/**
 * v2 hybrid twin of signAssuranceValue. Signs the SAME domain-separated bytes
 * signingBytes() produces, plus the registered algorithm set committed
 * INSIDE those bytes (anti-stripping; move 3 above), under BOTH Ed25519 and
 * ML-DSA-65. The ML-DSA-65 leg goes through signAgile verbatim -- this module
 * never reimplements FIPS 204 signing.
 */
export async function signAssuranceValueV2(
  domain: string,
  value: unknown,
  signer: HealthcareAssuranceHybridSigner,
): Promise<JsonObject> {
  const bytes = Buffer.from(canonicalize({
    domain: signingBytes(domain, value).toString('base64url'),
    required_algorithms: [...HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS],
  }));
  const ed25519Sig = await signer.ed25519.sign(bytes);
  const ed25519SigB64u = typeof ed25519Sig === 'string'
    ? ed25519Sig
    : Buffer.from(ed25519Sig).toString('base64url');
  const mldsaSignature = await signAgile(new Uint8Array(bytes), {
    alg: 'ML-DSA-65',
    private_key: signer.mldsa65.private_key,
    key_id: signer.mldsa65.key_id,
  });
  const signatures: AgileSignature[] = [
    { alg: 'Ed25519', sig: ed25519SigB64u, key_id: signer.ed25519.key_id },
    mldsaSignature,
  ];
  return {
    profile: HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
    required_algorithms: [...HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS],
    signatures,
  };
}

async function signedAssuranceAssertion(
  role: Exclude<HealthcareAssuranceRole, 'evaluator'>,
  body: JsonObject,
  signer: HealthcareAssuranceSigner,
  fips?: { posture?: FipsPosture; allow_unvalidated_mldsa?: boolean },
): Promise<JsonObject> {
  const assertion = {
    '@version': HEALTHCARE_ASSURANCE_ASSERTION_VERSION,
    role,
    body: clone(body),
  };
  return {
    ...assertion,
    proof: await signAssuranceValue(`assertion:${role}`, assertion, signer, fips),
  };
}

export async function signedAssuranceAssertionV2(
  role: Exclude<HealthcareAssuranceRole, 'evaluator'>,
  body: JsonObject,
  signer: HealthcareAssuranceHybridSigner,
): Promise<JsonObject> {
  const assertion = {
    '@version': HEALTHCARE_ASSURANCE_ASSERTION_V2_VERSION,
    role,
    body: clone(body),
  };
  return {
    ...assertion,
    proof: await signAssuranceValueV2(`assertion:${role}`, assertion, signer),
  };
}

function refusal(reason: string, extras: JsonObject = {}): JsonObject {
  return {
    ok: false,
    decision: 'REFUSED',
    reason,
    ...extras,
    program_digest: HOSPICE_RELIANCE_PROGRAM_DIGEST,
  };
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

export interface HealthcareAssuranceSigner {
  algorithm: 'Ed25519';
  key_id: string;
  sign(bytes: Uint8Array): Promise<string | Uint8Array> | string | Uint8Array;
}

export interface HealthcareAssuranceKeyPin {
  key_id: string;
  public_key_spki_b64u: string;
}

export interface HealthcareAssuranceTrustBundle {
  '@version': typeof HEALTHCARE_ASSURANCE_TRUST_BUNDLE_VERSION;
  relying_party_id: string;
  evaluator: HealthcareAssuranceKeyPin;
  receipt: HealthcareAssuranceKeyPin;
  aeb: HealthcareAssuranceKeyPin;
  provider: HealthcareAssuranceKeyPin;
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

function findingProjection(value: unknown): JsonObject | null {
  if (!isPlainObject(value)
      || !identifier(value.case_id)
      || !DIGEST_RE.test(value.case_digest)
      || !DIGEST_RE.test(value.package_digest)
      || !Array.isArray(value.source_record_digests)
      || !value.source_record_digests.every((entry: unknown) => (
        typeof entry === 'string' && DIGEST_RE.test(entry)
      ))) {
    return null;
  }
  return {
    case_id: value.case_id,
    case_digest: value.case_digest,
    package_digest: value.package_digest,
    source_record_digests: clone(value.source_record_digests),
    disposition: value.disposition,
    scope: value.scope,
    triage_provenance_only: value.triage_provenance_only === true,
    authorization_evidence: value.authorization_evidence === true,
    prior_authorization: value.prior_authorization === true,
    clinical_judgment: value.clinical_judgment === true,
    fraud_determination: value.fraud_determination === true,
    payment_authority: value.payment_authority === true,
  };
}

function controlProjection(value: unknown): JsonObject | null {
  if (!isPlainObject(value)
      || value.schema !== PROSPECTIVE_CONTROL_PACKAGE_SCHEMA
      || !identifier(value.caseId)
      || !DIGEST_RE.test(value.caseDigest)
      || !DIGEST_RE.test(value.packageDigest)
      || !CAID_RE.test(value.caid)
      || !DIGEST_RE.test(value.actionDigest)
      || !isPlainObject(value.policy)
      || !identifier(value.policy.id)
      || !Number.isSafeInteger(value.policy.version)
      || !DIGEST_RE.test(value.policy.hash)) {
    return null;
  }
  return {
    schema: value.schema,
    case_id: value.caseId,
    case_digest: value.caseDigest,
    package_digest: value.packageDigest,
    caid: value.caid,
    action_digest: value.actionDigest,
    policy: {
      id: value.policy.id,
      version: value.policy.version,
      hash: value.policy.hash,
    },
    raw_phi_included: value.phi?.rawPhiIncluded === true,
  };
}

function proposalProjection(value: unknown): JsonObject | null {
  if (!isPlainObject(value)
      || !identifier(value.proposal_id)
      || value.profile_id !== HOSPICE_PROPOSAL_PROFILE_ID
      || !identifier(value.operation_id)
      || !identifier(value.initiator_id)
      || !CAID_RE.test(value.caid)
      || !DIGEST_RE.test(value.action_digest)
      || !DIGEST_RE.test(value.aeb_action_digest)
      || !isPlainObject(value.aeb)
      || value.aeb.requirement_ref !== HOSPICE_AEB_REQUIREMENT_REF
      || !DIGEST_RE.test(value.aeb.pinned_config_digest)
      || !DIGEST_RE.test(value.aeb.consumption_nonce)
      || !isPlainObject(value.consequence)
      || !identifier(value.consequence.tenant_id)
      || !identifier(value.consequence.provider_id)
      || !identifier(value.consequence.provider_account_id)
      || value.consequence.environment !== 'sandbox'
      || !identifier(value.consequence.executor_id)
      || !DIGEST_RE.test(value.consequence.request_digest)) {
    return null;
  }
  return {
    proposal_id: value.proposal_id,
    profile_id: value.profile_id,
    operation_id: value.operation_id,
    initiator_id: value.initiator_id,
    caid: value.caid,
    action_digest: value.action_digest,
    aeb_action_digest: value.aeb_action_digest,
    aeb: {
      requirement_ref: value.aeb.requirement_ref,
      pinned_config_digest: value.aeb.pinned_config_digest,
      consumption_nonce: value.aeb.consumption_nonce,
    },
    consequence: {
      tenant_id: value.consequence.tenant_id,
      provider_id: value.consequence.provider_id,
      provider_account_id: value.consequence.provider_account_id,
      environment: value.consequence.environment,
      executor_id: value.consequence.executor_id,
      request_digest: value.consequence.request_digest,
    },
  };
}

function receiptProjection(value: unknown): JsonObject | null {
  if (!isPlainObject(value)
      || value['@version'] !== 'EP-RECEIPT-v1'
      || !identifier(value.receipt_id)
      || !CAID_RE.test(value.caid)
      || !DIGEST_RE.test(value.action_digest)) {
    return null;
  }
  return {
    '@version': value['@version'],
    receipt_id: value.receipt_id,
    caid: value.caid,
    action_digest: value.action_digest,
  };
}

function aebProjection(value: unknown): JsonObject | null {
  if (!isPlainObject(value)
      || value['@type'] !== 'AEB-EVALUATION-v1'
      || !identifier(value.operation_id)
      || !DIGEST_RE.test(value.consumption_nonce)
      || !isPlainObject(value.evaluator)
      || !identifier(value.evaluator.id)
      || !identifier(value.evaluator.key_id)
      || !DIGEST_RE.test(value.evaluator.pinned_config_digest)
      || !identifier(value.requirement_ref)
      || !DIGEST_RE.test(value.requirement_digest)
      || !DIGEST_RE.test(value.registry_digest)
      || !CAID_RE.test(value.caid)
      || !isPlainObject(value.composition)
      || !DIGEST_RE.test(value.composition.action_digest)
      || value.verdict !== 'SATISFIED'
      || typeof value.evaluated_at !== 'string'
      || !DIGEST_RE.test(value.evidence_digest)) {
    return null;
  }
  return {
    '@type': value['@type'],
    operation_id: value.operation_id,
    consumption_nonce: value.consumption_nonce,
    evaluator: {
      id: value.evaluator.id,
      key_id: value.evaluator.key_id,
      pinned_config_digest: value.evaluator.pinned_config_digest,
    },
    requirement_ref: value.requirement_ref,
    requirement_digest: value.requirement_digest,
    registry_digest: value.registry_digest,
    caid: value.caid,
    composition_action_digest: value.composition.action_digest,
    verdict: value.verdict,
    evaluated_at: value.evaluated_at,
    evidence_digest: value.evidence_digest,
  };
}

function providerProjection(
  value: unknown,
  evidenceDigest: unknown,
): JsonObject | null {
  if (!isPlainObject(value)
      || value.authenticated !== true
      || !identifier(value.evidence_id)
      || typeof value.observed_at !== 'string'
      || !['COMMITTED', 'NOT_COMMITTED'].includes(value.outcome)
      || !identifier(value.operation_id)
      || !CAID_RE.test(value.caid)
      || !DIGEST_RE.test(value.action_digest)
      || !identifier(value.tenant_id)
      || !DIGEST_RE.test(value.request_digest)
      || !identifier(value.provider_id)
      || !identifier(value.provider_account_id)
      || value.environment !== 'sandbox'
      || !identifier(value.attempt_id)
      || typeof evidenceDigest !== 'string'
      || !DIGEST_RE.test(evidenceDigest)) {
    return null;
  }
  return {
    authenticated: true,
    evidence_id: value.evidence_id,
    evidence_digest: evidenceDigest,
    observed_at: value.observed_at,
    outcome: value.outcome,
    operation_id: value.operation_id,
    caid: value.caid,
    action_digest: value.action_digest,
    tenant_id: value.tenant_id,
    request_digest: value.request_digest,
    provider_id: value.provider_id,
    provider_account_id: value.provider_account_id,
    environment: value.environment,
    attempt_id: value.attempt_id,
  };
}

function assertionBody(
  role: Exclude<HealthcareAssuranceRole, 'evaluator'>,
  relyingPartyId: string,
  tenantId: string,
  operationId: string,
  caid: string,
  actionDigest: string,
  artifactDigest: string,
  projection: JsonObject,
): JsonObject {
  return {
    role,
    relying_party_id: relyingPartyId,
    tenant_id: tenantId,
    operation_id: operationId,
    caid,
    action_digest: actionDigest,
    artifact_digest: artifactDigest,
    projection: clone(projection),
  };
}

function terminalProjection(
  decision: unknown,
  proposalToEffect: unknown,
  attemptValue: unknown,
  provider: JsonObject | null,
): JsonObject | null {
  if (typeof decision !== 'string'
      || !EXPORTABLE_DECISIONS.has(decision)
      || !isPlainObject(proposalToEffect)) {
    return null;
  }
  const attempt = publicAttempt(attemptValue);
  const consequenceAttempt = publicAttempt(proposalToEffect.consequence?.attempt);
  if (!attempt || !consequenceAttempt || digest(attempt) !== digest(consequenceAttempt)) {
    return null;
  }
  const reconciled = RECONCILED_DECISIONS.has(decision);
  const expectedState = decision === 'RECONCILED_NOT_EXECUTED'
    ? 'RELEASED'
    : 'COMMITTED';
  const expectedProviderOutcome = decision === 'RECONCILED_NOT_EXECUTED'
    ? 'NOT_COMMITTED'
    : 'COMMITTED';
  if (proposalToEffect.consequence?.state !== expectedState
      || (reconciled && proposalToEffect.state !== expectedState)
      || (reconciled && proposalToEffect.outcome !== expectedProviderOutcome)
      || (reconciled && provider?.outcome !== expectedProviderOutcome)
      || (!reconciled && provider !== null)) {
    return null;
  }
  return {
    decision,
    proposal_to_effect_state: expectedState,
    provider_outcome: reconciled ? expectedProviderOutcome : null,
    attempt,
    authenticated_reconciliation: reconciled,
    retry_safe: decision === 'RECONCILED_NOT_EXECUTED',
  };
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
  assurance: {
    relying_party_id: string;
    signers: {
      evaluator: HealthcareAssuranceSigner;
      receipt: HealthcareAssuranceSigner;
      aeb: HealthcareAssuranceSigner;
      provider: HealthcareAssuranceSigner;
    };
    /**
     * Opt-in FIPS posture consult at every signAssuranceValue() custody call
     * site. Omit entirely (every existing deployment) and signing stays
     * byte-identical to before this field existed.
     */
    fips?: { posture?: FipsPosture; allow_unvalidated_mldsa?: boolean };
    /**
     * Opt-in hybrid (Ed25519 + ML-DSA-65) signer set for
     * exportAssurancePacketV2(). Omitting this leaves exportAssurancePacketV2
     * a named refusal; it never falls back to signing only the classical leg.
     */
    hybrid?: {
      evaluator: HealthcareAssuranceHybridSigner;
      receipt: HealthcareAssuranceHybridSigner;
      aeb: HealthcareAssuranceHybridSigner;
      provider: HealthcareAssuranceHybridSigner;
    };
  };
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
  if (!options.assurance
      || !identifier(options.assurance.relying_party_id)
      || !isPlainObject(options.assurance.signers)
      || !ASSURANCE_ROLES.every((role) => signerShape(
        options.assurance.signers[role],
      ))
      || new Set(
        ASSURANCE_ROLES.map((role) => options.assurance.signers[role].key_id),
      ).size !== ASSURANCE_ROLES.length) {
    throw new Error('healthcare_assurance_signers_required');
  }
  if (options.assurance.hybrid !== undefined
      && !ASSURANCE_ROLES.every((role) => hybridSignerShape(options.assurance.hybrid![role]))) {
    throw new Error('healthcare_assurance_hybrid_signers_invalid');
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
    const finding = findingProjection(prepared.payload.finding);
    const control = controlProjection(prepared.payload.control_package);
    const proposalBinding = proposalProjection(proposal);
    const receipt = receiptProjection(execution?.payload?.approval_evidence);
    const aeb = aebProjection(execution?.payload?.aeb_evaluation);
    const provider = reconciliation
      ? providerProjection(
        reconciliation.payload?.provider_evidence,
        reconciliation.payload?.provider_evidence_digest,
      )
      : null;
    const terminalProjectionValue = terminalProjection(
      terminal.payload.decision,
      terminal.payload.proposal_to_effect,
      terminal.payload.attempt,
      provider,
    );
    if (!finding || !control || !proposalBinding || !receipt || !aeb
        || !terminalProjectionValue
        || control.caid !== proposalBinding.caid
        || control.action_digest !== proposalBinding.action_digest
        || receipt.caid !== proposalBinding.caid
        || receipt.action_digest !== proposalBinding.action_digest
        || aeb.operation_id !== input.operation_id
        || aeb.caid !== proposalBinding.caid
        || aeb.requirement_ref !== proposalBinding.aeb.requirement_ref
        || aeb.consumption_nonce !== proposalBinding.aeb.consumption_nonce
        || (RECONCILED_DECISIONS.has(terminal.payload.decision) && !provider)) {
      return refusal('healthcare_assurance_evidence_conflict');
    }
    if (prohibitedPhi({
      finding: prepared.payload.finding,
      control_package: prepared.payload.control_package,
      proposal,
      approval_evidence: execution?.payload?.approval_evidence,
      aeb_evaluation: execution?.payload?.aeb_evaluation,
      provider_evidence: reconciliation?.payload?.provider_evidence,
    })) {
      return refusal('healthcare_assurance_packet_phi_refused');
    }

    let receiptAssertion: JsonObject;
    let aebAssertion: JsonObject;
    let providerAssertion: JsonObject | null = null;
    try {
      receiptAssertion = await signedAssuranceAssertion(
        'receipt',
        assertionBody(
          'receipt',
          options.assurance.relying_party_id,
          input.tenant_id,
          input.operation_id,
          proposal.caid,
          proposal.action_digest,
          execution!.payload.approval_evidence_digest,
          receipt,
        ),
        options.assurance.signers.receipt,
        options.assurance.fips,
      );
      aebAssertion = await signedAssuranceAssertion(
        'aeb',
        assertionBody(
          'aeb',
          options.assurance.relying_party_id,
          input.tenant_id,
          input.operation_id,
          proposal.caid,
          proposal.action_digest,
          execution!.payload.aeb_evaluation_digest,
          aeb,
        ),
        options.assurance.signers.aeb,
        options.assurance.fips,
      );
      if (provider) {
        providerAssertion = await signedAssuranceAssertion(
          'provider',
          assertionBody(
            'provider',
            options.assurance.relying_party_id,
            input.tenant_id,
            input.operation_id,
            proposal.caid,
            proposal.action_digest,
            provider.evidence_digest,
            provider,
          ),
          options.assurance.signers.provider,
          options.assurance.fips,
        );
      }
    } catch {
      return refusal('healthcare_assurance_signing_failed');
    }

    const packetBody: JsonObject = {
      '@version': HEALTHCARE_ASSURANCE_PACKET_VERSION,
      relying_party_id: options.assurance.relying_party_id,
      profile: {
        id: HOSPICE_PROPOSAL_PROFILE_ID,
        action_type: HOSPICE_ACTION_TYPE,
        environment: 'sandbox',
        synthetic: true,
      },
      tenant_id: input.tenant_id,
      operation_id: input.operation_id,
      finding_projection: finding,
      control_projection: control,
      protocol_evidence: {
        proposal_binding: {
          artifact_digest: prepared.payload.proposal_digest,
          projection: proposalBinding,
        },
        receipt: receiptAssertion,
        aeb: aebAssertion,
        ...(providerAssertion ? { provider: providerAssertion } : {}),
      },
      outcome: terminalProjectionValue,
      chronology: events.map((event) => ({
        event_id: event.event_id,
        sequence: event.sequence,
        event_type: event.event_type,
        recorded_at: event.recorded_at,
      })),
      verification_scope: {
        internal_consistency_digest_only: true,
        exact_action_bound_by_signed_safe_projection: true,
        offline_signatures_require_relying_party_pins: true,
        raw_evidence_intentionally_omitted: true,
        population_completeness_established: false,
      },
      limitations: [...HEALTHCARE_ASSURANCE_LIMITATIONS],
      assembled_at: terminal.recorded_at,
    };
    if (prohibitedPhi(packetBody)) {
      return refusal('healthcare_assurance_packet_phi_refused');
    }
    const packet: JsonObject = {
      ...packetBody,
      packet_digest: digest(packetBody),
    };
    try {
      packet.proof = await signAssuranceValue(
        'packet:evaluator',
        packet,
        options.assurance.signers.evaluator,
        options.assurance.fips,
      );
    } catch (error) {
      return refusal('healthcare_assurance_signing_failed', {
        detail: safeReason(error, 'healthcare_assurance_signing_failed'),
      });
    }
    const consistency = checkHealthcareAssurancePacketInternalConsistency(packet);
    if (!consistency.consistent) {
      return refusal('healthcare_assurance_evidence_conflict');
    }
    return packet;
  }

  /**
   * Hybrid (Ed25519 + ML-DSA-65) sibling of exportAssurancePacket. Opt-in:
   * refuses by name when options.assurance.hybrid is not configured, and
   * never falls back to signing only the classical leg.
   *
   * COMPOSED over exportAssurancePacket rather than re-walking proposal,
   * event, and provider discovery a second time: the v1 packet's BODY
   * (proposal binding, findings, chronology, outcome) is exactly what a v2
   * packet for the same input must also bind to, so a v2 export re-signs
   * that identical content at each level (assertions, then packet) under the
   * v2 version markers and hybrid proof shape. The v1 classical signature
   * computed along the way is discarded, never returned or reused as a v2
   * leg -- v2 legs are ALWAYS freshly signed under options.assurance.hybrid.
   */
  async function exportAssurancePacketV2(input: {
    tenant_id: string;
    operation_id: string;
  }): Promise<JsonObject> {
    if (!options.assurance.hybrid) {
      return refusal('healthcare_assurance_hybrid_signer_not_configured');
    }
    const v1 = await exportAssurancePacket(input);
    if (v1.ok === false) return v1;
    const hybrid = options.assurance.hybrid;

    async function reassertV2(
      role: Exclude<HealthcareAssuranceRole, 'evaluator'>,
    ): Promise<JsonObject | null> {
      const assertion = v1.protocol_evidence?.[role];
      if (!isPlainObject(assertion)) return null;
      return signedAssuranceAssertionV2(role, assertion.body, hybrid[role]);
    }

    let receiptAssertionV2: JsonObject | null;
    let aebAssertionV2: JsonObject | null;
    let providerAssertionV2: JsonObject | null;
    try {
      receiptAssertionV2 = await reassertV2('receipt');
      aebAssertionV2 = await reassertV2('aeb');
      providerAssertionV2 = v1.protocol_evidence?.provider !== undefined
        ? await reassertV2('provider')
        : null;
    } catch (error) {
      return refusal('healthcare_assurance_hybrid_signing_failed', {
        detail: safeReason(error, 'healthcare_assurance_hybrid_signing_failed'),
      });
    }
    if (!receiptAssertionV2 || !aebAssertionV2) {
      return refusal('healthcare_assurance_hybrid_signing_failed');
    }

    const packetBody: JsonObject = {
      ...v1,
      '@version': HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
      protocol_evidence: {
        ...v1.protocol_evidence,
        receipt: receiptAssertionV2,
        aeb: aebAssertionV2,
        ...(providerAssertionV2 ? { provider: providerAssertionV2 } : {}),
      },
    };
    delete packetBody.packet_digest;
    delete packetBody.proof;
    if (prohibitedPhi(packetBody)) {
      return refusal('healthcare_assurance_packet_phi_refused');
    }
    const packet: JsonObject = {
      ...packetBody,
      packet_digest: digest(packetBody),
    };
    try {
      packet.proof = await signAssuranceValueV2('packet:evaluator', packet, hybrid.evaluator);
    } catch (error) {
      return refusal('healthcare_assurance_hybrid_signing_failed', {
        detail: safeReason(error, 'healthcare_assurance_hybrid_signing_failed'),
      });
    }
    const consistency = checkHealthcareAssurancePacketInternalConsistency(packet, {
      version: HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
      assertionVersion: HEALTHCARE_ASSURANCE_ASSERTION_V2_VERSION,
      proofShapeCheck: assuranceProofV2Shape,
    });
    if (!consistency.consistent) {
      return refusal('healthcare_assurance_evidence_conflict');
    }
    return packet;
  }

  return Object.freeze({
    prepare,
    execute,
    reconcile,
    exportAssurancePacket,
    exportAssurancePacketV2,
  });
}

export type HealthcareConsequenceControl =
  ReturnType<typeof createHealthcareConsequenceControl>;

/**
 * The `version`/`proofShapeCheck` parameters default to the exact v1
 * constants, so every existing call site (which omits them) is
 * byte-identical to before these parameters existed. This is COMPOSITION,
 * not a v1 behavior change: v2 supplies its own version and proof-shape
 * check rather than a parallel copy of this function drifting from it.
 */
function assuranceAssertion(
  value: unknown,
  role: Exclude<HealthcareAssuranceRole, 'evaluator'>,
  version: string = HEALTHCARE_ASSURANCE_ASSERTION_VERSION,
  proofShapeCheck: (proof: unknown) => boolean = assuranceProofShape,
): JsonObject | null {
  if (!exactKeys(value, ['@version', 'body', 'proof', 'role'])
      || value['@version'] !== version
      || value.role !== role
      || !isPlainObject(value.body)
      || value.body.role !== role
      || !isPlainObject(value.body.projection)
      || !DIGEST_RE.test(value.body.artifact_digest)
      || !proofShapeCheck(value.proof)) {
    return null;
  }
  return value;
}

/**
 * Checks only packet shape, allowlisted projections, digests, and cross-field
 * consistency. It does not establish signer trust or evidence authenticity.
 *
 * `options` defaults to the exact v1 version/proof-shape constants, so the
 * single-argument v1 call sites throughout this file are byte-identical to
 * before this parameter existed. The v2 verify path (below) passes the v2
 * version and assuranceProofV2Shape explicitly.
 */
export function checkHealthcareAssurancePacketInternalConsistency(
  packet: unknown,
  options: {
    version?: string;
    assertionVersion?: string;
    proofShapeCheck?: (proof: unknown) => boolean;
  } = {},
): {
  consistent: boolean;
  reasons: string[];
} {
  const packetVersion = options.version ?? HEALTHCARE_ASSURANCE_PACKET_VERSION;
  const assertionVersion = options.assertionVersion ?? HEALTHCARE_ASSURANCE_ASSERTION_VERSION;
  const proofShapeCheck = options.proofShapeCheck ?? assuranceProofShape;
  const reasons: string[] = [];
  if (!exactKeys(packet, [
    '@version',
    'assembled_at',
    'chronology',
    'control_projection',
    'finding_projection',
    'limitations',
    'operation_id',
    'outcome',
    'packet_digest',
    'profile',
    'proof',
    'protocol_evidence',
    'relying_party_id',
    'tenant_id',
    'verification_scope',
  ]) || packet['@version'] !== packetVersion) {
    return { consistent: false, reasons: ['packet_shape_invalid'] };
  }
  if (prohibitedPhi(packet)) reasons.push('packet_contains_prohibited_phi');
  const packetBody = clone(packet);
  delete packetBody.packet_digest;
  delete packetBody.proof;
  if (!DIGEST_RE.test(packet.packet_digest)
      || packet.packet_digest !== digest(packetBody)) {
    reasons.push('packet_digest_invalid');
  }
  if (!proofShapeCheck(packet.proof)) {
    reasons.push('packet_proof_shape_invalid');
  }
  if (!identifier(packet.relying_party_id)
      || !identifier(packet.tenant_id)
      || !identifier(packet.operation_id)
      || packet.profile?.id !== HOSPICE_PROPOSAL_PROFILE_ID
      || packet.profile?.action_type !== HOSPICE_ACTION_TYPE
      || packet.profile?.environment !== 'sandbox'
      || packet.profile?.synthetic !== true) {
    reasons.push('packet_profile_invalid');
  }

  const finding = packet.finding_projection;
  const control = packet.control_projection;
  if (!isPlainObject(finding)
      || !identifier(finding.case_id)
      || !DIGEST_RE.test(finding.case_digest)
      || !DIGEST_RE.test(finding.package_digest)
      || !Array.isArray(finding.source_record_digests)
      || !finding.source_record_digests.every((entry: unknown) => (
        typeof entry === 'string' && DIGEST_RE.test(entry)
      ))
      || finding.triage_provenance_only !== true
      || finding.authorization_evidence !== false
      || finding.prior_authorization !== false
      || finding.clinical_judgment !== false
      || finding.fraud_determination !== false
      || finding.payment_authority !== false
      || !isPlainObject(control)
      || control.schema !== PROSPECTIVE_CONTROL_PACKAGE_SCHEMA
      || control.case_id !== finding.case_id
      || control.case_digest !== finding.case_digest
      || control.package_digest !== finding.package_digest
      || !CAID_RE.test(control.caid)
      || !DIGEST_RE.test(control.action_digest)
      || control.raw_phi_included !== false) {
    reasons.push('packet_safe_projection_invalid');
  }

  const proposalBinding = packet.protocol_evidence?.proposal_binding;
  const proposal = proposalProjection(proposalBinding?.projection);
  if (!isPlainObject(proposalBinding)
      || !DIGEST_RE.test(proposalBinding.artifact_digest)
      || !proposal
      || proposal.operation_id !== packet.operation_id
      || proposal.consequence?.tenant_id !== packet.tenant_id
      || proposal.caid !== control?.caid
      || proposal.action_digest !== control?.action_digest
      || proposal.aeb_action_digest !== control?.action_digest) {
    reasons.push('packet_proposal_binding_invalid');
  }

  const receipt = assuranceAssertion(
    packet.protocol_evidence?.receipt, 'receipt', assertionVersion, proofShapeCheck,
  );
  const aeb = assuranceAssertion(
    packet.protocol_evidence?.aeb, 'aeb', assertionVersion, proofShapeCheck,
  );
  const receiptBody = receipt?.body;
  const aebBody = aeb?.body;
  const receiptValue = receiptProjection(receiptBody?.projection);
  const aebValue = aebBody?.projection;
  for (const [role, body] of [['receipt', receiptBody], ['aeb', aebBody]] as const) {
    if (!body
        || body.relying_party_id !== packet.relying_party_id
        || body.tenant_id !== packet.tenant_id
        || body.operation_id !== packet.operation_id
        || body.caid !== proposal?.caid
        || body.action_digest !== proposal?.action_digest
        || body.role !== role) {
      reasons.push(`packet_${role}_binding_invalid`);
    }
  }
  if (!receiptValue
      || receiptValue.caid !== proposal?.caid
      || receiptValue.action_digest !== proposal?.action_digest) {
    reasons.push('packet_receipt_binding_invalid');
  }
  if (!isPlainObject(aebValue)
      || aebValue['@type'] !== 'AEB-EVALUATION-v1'
      || aebValue.operation_id !== packet.operation_id
      || aebValue.caid !== proposal?.caid
      || aebValue.requirement_ref !== proposal?.aeb?.requirement_ref
      || aebValue.consumption_nonce !== proposal?.aeb?.consumption_nonce
      || aebValue.verdict !== 'SATISFIED'
      || !DIGEST_RE.test(aebValue.consumption_nonce)
      || !DIGEST_RE.test(aebValue.evidence_digest)) {
    reasons.push('packet_aeb_binding_invalid');
  }

  const decision = packet.outcome?.decision;
  const reconciled = RECONCILED_DECISIONS.has(decision);
  const expectedState = decision === 'RECONCILED_NOT_EXECUTED'
    ? 'RELEASED'
    : 'COMMITTED';
  const expectedProviderOutcome = decision === 'RECONCILED_NOT_EXECUTED'
    ? 'NOT_COMMITTED'
    : decision === 'RECONCILED_EXECUTED'
      ? 'COMMITTED'
      : null;
  const attempt = publicAttempt(packet.outcome?.attempt);
  if (!EXPORTABLE_DECISIONS.has(decision)
      || packet.outcome?.proposal_to_effect_state !== expectedState
      || packet.outcome?.provider_outcome !== expectedProviderOutcome
      || packet.outcome?.authenticated_reconciliation !== reconciled
      || packet.outcome?.retry_safe !== (decision === 'RECONCILED_NOT_EXECUTED')) {
    reasons.push('packet_terminal_state_mismatch');
  }
  if (!attempt
      || attempt.tenant_id !== packet.tenant_id
      || attempt.provider_id !== proposal?.consequence?.provider_id
      || attempt.provider_account_id !== proposal?.consequence?.provider_account_id
      || attempt.environment !== proposal?.consequence?.environment
      || attempt.request_digest !== proposal?.consequence?.request_digest) {
    reasons.push('packet_attempt_binding_invalid');
  }

  const provider = assuranceAssertion(
    packet.protocol_evidence?.provider,
    'provider',
    assertionVersion,
    proofShapeCheck,
  );
  if (reconciled && !provider) {
    reasons.push('packet_reconciliation_evidence_required');
  } else if (!reconciled && packet.protocol_evidence?.provider !== undefined) {
    reasons.push('packet_reconciliation_evidence_unexpected');
  } else if (provider) {
    const body = provider.body;
    const projected = providerProjection(
      body.projection,
      body.projection?.evidence_digest,
    );
    if (!projected
        || body.relying_party_id !== packet.relying_party_id
        || body.tenant_id !== packet.tenant_id
        || body.operation_id !== packet.operation_id
        || body.caid !== proposal?.caid
        || body.action_digest !== proposal?.action_digest
        || body.artifact_digest !== projected.evidence_digest
        || projected.outcome !== expectedProviderOutcome
        || projected.attempt_id !== attempt?.attempt_id
        || projected.request_digest !== attempt?.request_digest
        || projected.provider_id !== attempt?.provider_id
        || projected.provider_account_id !== attempt?.provider_account_id
        || projected.environment !== attempt?.environment) {
      reasons.push('packet_reconciliation_evidence_invalid');
    }
  }

  const expectedTerminalEvent = reconciled ? 'RECONCILIATION' : 'EXECUTION';
  if (!Array.isArray(packet.chronology)
      || packet.chronology.length < 2
      || packet.chronology[0]?.event_type !== 'PREPARED'
      || packet.chronology.at(-1)?.event_type !== expectedTerminalEvent
      || !Array.isArray(packet.limitations)
      || digest(packet.limitations) !== digest(HEALTHCARE_ASSURANCE_LIMITATIONS)) {
    reasons.push('packet_chronology_or_limitations_invalid');
  }
  return {
    consistent: reasons.length === 0,
    reasons: [...new Set(reasons)],
  };
}

function trustPin(value: unknown): crypto.KeyObject | null {
  if (!exactKeys(value, ['key_id', 'public_key_spki_b64u'])
      || !identifier(value.key_id)) {
    return null;
  }
  const der = canonicalBase64url(value.public_key_spki_b64u);
  if (!der) return null;
  try {
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function verifyPinnedSignature(
  domain: string,
  value: JsonObject,
  proof: unknown,
  pin: unknown,
): boolean {
  if (!assuranceProofShape(proof)
      || !isPlainObject(pin)
      || proof.key_id !== pin.key_id) {
    return false;
  }
  const key = trustPin(pin);
  const signature = canonicalBase64url(proof.signature_b64u, 64);
  if (!key || !signature) return false;
  try {
    return crypto.verify(null, signingBytes(domain, value), key, signature);
  } catch {
    return false;
  }
}

/** Verify the packet offline using only relying-party-pinned Ed25519 keys. */
export function verifyHealthcareAssurancePacketOffline(
  packet: unknown,
  trust: unknown,
): {
  valid: boolean;
  reasons: string[];
} {
  const reasons = [
    ...checkHealthcareAssurancePacketInternalConsistency(packet).reasons,
  ];
  if (!exactKeys(trust, [
    '@version',
    'aeb',
    'evaluator',
    'provider',
    'receipt',
    'relying_party_id',
  ]) || trust['@version'] !== HEALTHCARE_ASSURANCE_TRUST_BUNDLE_VERSION
      || !identifier(trust.relying_party_id)
      || !ASSURANCE_ROLES.every((role) => trustPin(trust[role]) !== null)
      || new Set(ASSURANCE_ROLES.map((role) => trust[role].key_id)).size
        !== ASSURANCE_ROLES.length
      || new Set(
        ASSURANCE_ROLES.map((role) => trust[role].public_key_spki_b64u),
      ).size !== ASSURANCE_ROLES.length) {
    reasons.push('relying_party_trust_bundle_invalid');
  }
  if (!isPlainObject(packet) || !isPlainObject(trust)
      || packet.relying_party_id !== trust.relying_party_id) {
    reasons.push('relying_party_binding_invalid');
    return { valid: false, reasons: [...new Set(reasons)] };
  }
  const packetForSignature = clone(packet);
  const packetProof = packetForSignature.proof;
  delete packetForSignature.proof;
  if (!verifyPinnedSignature(
    'packet:evaluator',
    packetForSignature,
    packetProof,
    trust.evaluator,
  )) {
    reasons.push('evaluator_signature_invalid');
  }
  for (const role of ['receipt', 'aeb', 'provider'] as const) {
    const assertion = packet.protocol_evidence?.[role];
    if (role === 'provider' && assertion === undefined
        && !RECONCILED_DECISIONS.has(packet.outcome?.decision)) {
      continue;
    }
    if (!isPlainObject(assertion)) {
      reasons.push(`${role}_signature_invalid`);
      continue;
    }
    const unsigned = clone(assertion);
    const proof = unsigned.proof;
    delete unsigned.proof;
    if (!verifyPinnedSignature(
      `assertion:${role}`,
      unsigned,
      proof,
      trust[role],
    )) {
      reasons.push(`${role}_signature_invalid`);
    }
  }
  return { valid: reasons.length === 0, reasons: [...new Set(reasons)] };
}

/** v2 trust pin: BOTH public halves, pinned out of band. */
export interface HealthcareAssuranceHybridKeyPin {
  key_id: string;
  public_key_spki_b64u: string;
  pq_key_id: string;
  /** ML-DSA-65: base64url of the raw 1952-byte public key. */
  pq_public_key_b64u: string;
}

export interface HealthcareAssuranceHybridTrustBundle {
  '@version': typeof HEALTHCARE_ASSURANCE_PACKET_V2_VERSION;
  relying_party_id: string;
  evaluator: HealthcareAssuranceHybridKeyPin;
  receipt: HealthcareAssuranceHybridKeyPin;
  aeb: HealthcareAssuranceHybridKeyPin;
  provider: HealthcareAssuranceHybridKeyPin;
}

function hybridTrustPin(value: unknown): HealthcareAssuranceHybridKeyPin | null {
  if (!exactKeys(value, ['key_id', 'pq_key_id', 'pq_public_key_b64u', 'public_key_spki_b64u'])
      || !identifier(value.key_id)
      || !identifier(value.pq_key_id)
      || canonicalBase64url(value.public_key_spki_b64u) === null
      || canonicalBase64url(value.pq_public_key_b64u, 1952) === null) {
    return null;
  }
  // Curve/type-pin the classical half the same way trustPin() does, so an
  // Ed448 (or any non-Ed25519) SPKI masquerading as the pin fails here too.
  if (trustPin({ key_id: value.key_id, public_key_spki_b64u: value.public_key_spki_b64u }) === null) {
    return null;
  }
  return value as HealthcareAssuranceHybridKeyPin;
}

/**
 * v2 hybrid twin of verifyPinnedSignature. ASYNC (ML-DSA verification is
 * async). Verifies under the PINNED keys only, via verifyAgileSignatureSet
 * with policy 'hybrid_all' -- one leg alone never verifies.
 */
export async function verifyPinnedSignatureV2(
  domain: string,
  value: JsonObject,
  proof: unknown,
  pin: unknown,
): Promise<boolean> {
  if (!assuranceProofV2Shape(proof) || !isPlainObject(pin)) return false;
  const resolvedPin = hybridTrustPin(pin);
  if (!resolvedPin) return false;
  const bytes = Buffer.from(canonicalize({
    domain: signingBytes(domain, value).toString('base64url'),
    required_algorithms: [...HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS],
  }));
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(bytes),
      (proof as JsonObject).signatures,
      [
        { alg: 'Ed25519', public_key: resolvedPin.public_key_spki_b64u, key_id: resolvedPin.key_id },
        { alg: 'ML-DSA-65', public_key: resolvedPin.pq_public_key_b64u, key_id: resolvedPin.pq_key_id },
      ],
      {
        policy: 'hybrid_all',
        requiredAlgorithms: [...HEALTHCARE_ASSURANCE_V2_REQUIRED_ALGORITHMS],
      },
    );
  } catch {
    // verifyAgileSignatureSet documents that it never throws; an injected
    // backend that does is still a refusal here, never a pass.
    return false;
  }
  return setResult?.verified === true;
}

/**
 * v2 hybrid twin of verifyHealthcareAssurancePacketOffline. v1 above is
 * UNTOUCHED and stays synchronous; it refuses a v2 packet on the version
 * marker (via checkHealthcareAssurancePacketInternalConsistency's exact-key
 * check) before ever inspecting packet.proof. ASYNC because ML-DSA
 * verification is async, which is why this is a separate entry point rather
 * than a signature change to the v1 function.
 */
export async function verifyHealthcareAssurancePacketOfflineV2(
  packet: unknown,
  trust: unknown,
): Promise<{
  valid: boolean;
  reasons: string[];
}> {
  const reasons = [
    ...checkHealthcareAssurancePacketInternalConsistency(packet, {
      version: HEALTHCARE_ASSURANCE_PACKET_V2_VERSION,
      assertionVersion: HEALTHCARE_ASSURANCE_ASSERTION_V2_VERSION,
      proofShapeCheck: assuranceProofV2Shape,
    }).reasons,
  ];
  if (!exactKeys(trust, [
    '@version',
    'aeb',
    'evaluator',
    'provider',
    'receipt',
    'relying_party_id',
  ]) || trust['@version'] !== HEALTHCARE_ASSURANCE_PACKET_V2_VERSION
      || !identifier(trust.relying_party_id)
      || !ASSURANCE_ROLES.every((role) => hybridTrustPin(trust[role]) !== null)
      || new Set(ASSURANCE_ROLES.map((role) => trust[role].key_id)).size
        !== ASSURANCE_ROLES.length
      || new Set(ASSURANCE_ROLES.map((role) => trust[role].pq_key_id)).size
        !== ASSURANCE_ROLES.length) {
    reasons.push('relying_party_trust_bundle_invalid');
  }
  if (!isPlainObject(packet) || !isPlainObject(trust)
      || packet.relying_party_id !== trust.relying_party_id) {
    reasons.push('relying_party_binding_invalid');
    return { valid: false, reasons: [...new Set(reasons)] };
  }
  const packetForSignature = clone(packet);
  const packetProof = packetForSignature.proof;
  delete packetForSignature.proof;
  if (!(await verifyPinnedSignatureV2(
    'packet:evaluator',
    packetForSignature,
    packetProof,
    trust.evaluator,
  ))) {
    reasons.push('evaluator_signature_invalid');
  }
  for (const role of ['receipt', 'aeb', 'provider'] as const) {
    const assertion = packet.protocol_evidence?.[role];
    if (role === 'provider' && assertion === undefined
        && !RECONCILED_DECISIONS.has(packet.outcome?.decision)) {
      continue;
    }
    if (!isPlainObject(assertion)) {
      reasons.push(`${role}_signature_invalid`);
      continue;
    }
    const unsigned = clone(assertion);
    const proof = unsigned.proof;
    delete unsigned.proof;
    if (!(await verifyPinnedSignatureV2(
      `assertion:${role}`,
      unsigned,
      proof,
      trust[role],
    ))) {
      reasons.push(`${role}_signature_invalid`);
    }
  }
  return { valid: reasons.length === 0, reasons: [...new Set(reasons)] };
}

/**
 * Route a packet of EITHER version to its verifier. v1 packets get the exact
 * v1 verdict; v2 packets get the hybrid check. A packet whose `@version` is
 * neither refuses on the version marker, through the v1 verifier
 * (fail-closed).
 */
export async function verifyHealthcareAssurancePacketOfflineAny(
  packet: unknown,
  trust: unknown,
): Promise<{ valid: boolean; reasons: string[] }> {
  if (isPlainObject(packet) && packet['@version'] === HEALTHCARE_ASSURANCE_PACKET_V2_VERSION) {
    return verifyHealthcareAssurancePacketOfflineV2(packet, trust);
  }
  return verifyHealthcareAssurancePacketOffline(packet, trust);
}
