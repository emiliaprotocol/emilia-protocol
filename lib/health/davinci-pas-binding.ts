// SPDX-License-Identifier: Apache-2.0
// Deterministic, PHI-minimizing binding for server-observed medical prior
// authorization resources conforming to HL7 Da Vinci PAS FHIR IG v2.2.1.
//
// This module is a reference projection and verifier. It is not an EHR/FHIR
// client, a signature verifier, a production trust anchor, or a statement of
// legal/regulatory compliance. Callers remain responsible for obtaining the
// resources and accepted reviewer evidence from authenticated systems of
// record rather than from an agent or patient-facing request body.

import { createHash } from 'node:crypto';

import {
  computeCaid,
  verifyCaid,
} from '../../caid/impl/js/caid.mjs';

export const DAVINCI_PAS_ACTION_TYPE =
  'health.medical-prior-authorization-review.1';
export const DAVINCI_PAS_BINDING_TYPE =
  'EP-DAVINCI-PAS-REVIEW-BINDING-v1';
export const DAVINCI_PAS_PROFILE_ID =
  'davinci-pas-review-binding.v1';
export const DAVINCI_PAS_IG_VERSION = '2.2.1';
export const DAVINCI_PAS_MEDICAL_RAIL = 'hl7-davinci-pas-medical';

const CLAIM_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claim|2.2.1';
const CLAIM_RESPONSE_PROFILE =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/profile-claimresponse|2.2.1';
const REVIEWER_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-claimResponseReviewer';
const REVIEW_ACTION_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewAction';
const REVIEW_ACTION_CODE_URL =
  'http://hl7.org/fhir/us/davinci-pas/StructureDefinition/extension-reviewActionCode';
const X12_REVIEW_ACTION_SYSTEM = 'https://codesystem.x12.org/005010/306';
const ADJUDICATION_SYSTEM = 'http://terminology.hl7.org/CodeSystem/adjudication';
const REVIEWER_AUTHORITY_SCOPE = 'medical_prior_authorization.adverse_decision';

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const OPERATION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PAIRWISE_PATIENT_RE = /^pairwise:[A-Za-z0-9][A-Za-z0-9._~-]{7,127}$/;
const POLICY_ID_RE = /^policy:[A-Za-z0-9][A-Za-z0-9._:-]{2,191}$/;
const REVIEWER_REF_RE = /^reviewer:[A-Za-z0-9][A-Za-z0-9._:@/-]{2,191}$/;
const FHIR_ID_RE = /^[A-Za-z0-9\-.]{1,64}$/;
const NONEMPTY_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:/|@+-]{0,255}$/;

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 50_000;
const MAX_JSON_STRING_BYTES = 4 * 1024 * 1024;

type JsonRecord = Record<string, unknown>;

export type DavinciPasDecisionOutcome =
  | 'approved'
  | 'modified'
  | 'denied'
  | 'pended'
  | 'mixed';

export interface DavinciPasMaterialAction {
  action_type: typeof DAVINCI_PAS_ACTION_TYPE;
  operation_id: string;
  rail: typeof DAVINCI_PAS_MEDICAL_RAIL;
  ig_version: typeof DAVINCI_PAS_IG_VERSION;
  pairwise_patient_ref: string;
  claim_digest: string;
  claim_identifier_digest: string;
  claim_response_digest: string;
  request_reference_digest: string;
  service_request_digest: string;
  decision_digest: string;
  decision_outcome: DavinciPasDecisionOutcome;
  fhir_outcome: string;
  policy_id: string;
  policy_version: string;
  policy_digest: string;
  reviewer_ref?: string;
  reviewer_fhir_identity_digest?: string;
  reviewer_identity_evidence_digest?: string;
  reviewer_authority_evidence_digest?: string;
  reviewer_authority_scope?: typeof REVIEWER_AUTHORITY_SCOPE;
}

export interface DavinciPasReviewBinding {
  '@type': typeof DAVINCI_PAS_BINDING_TYPE;
  profile_id: typeof DAVINCI_PAS_PROFILE_ID;
  ig: {
    package: 'hl7.fhir.us.davinci-pas';
    version: typeof DAVINCI_PAS_IG_VERSION;
    fhir_release: 'R4';
    claim_profile: typeof CLAIM_PROFILE;
    claim_response_profile: typeof CLAIM_RESPONSE_PROFILE;
  };
  rail: typeof DAVINCI_PAS_MEDICAL_RAIL;
  action: DavinciPasMaterialAction;
  action_digest: string;
  caid: string;
}

export type DavinciPasBuildResult =
  | { ok: true; binding: DavinciPasReviewBinding }
  | { ok: false; reasons: string[] };

export interface DavinciPasVerificationResult {
  valid: boolean;
  reasons: string[];
}

const CAID_DEFINITION = Object.freeze({
  action_type: DAVINCI_PAS_ACTION_TYPE,
  required_fields: [
    { name: 'operation_id', type: 'string' },
    { name: 'rail', type: 'enum', values: [DAVINCI_PAS_MEDICAL_RAIL] },
    { name: 'ig_version', type: 'enum', values: [DAVINCI_PAS_IG_VERSION] },
    { name: 'pairwise_patient_ref', type: 'string' },
    { name: 'claim_digest', type: 'digest' },
    { name: 'claim_identifier_digest', type: 'digest' },
    { name: 'claim_response_digest', type: 'digest' },
    { name: 'request_reference_digest', type: 'digest' },
    { name: 'service_request_digest', type: 'digest' },
    { name: 'decision_digest', type: 'digest' },
    {
      name: 'decision_outcome',
      type: 'enum',
      values: ['approved', 'modified', 'denied', 'pended', 'mixed'],
    },
    { name: 'fhir_outcome', type: 'string' },
    { name: 'policy_id', type: 'string' },
    { name: 'policy_version', type: 'string' },
    { name: 'policy_digest', type: 'digest' },
  ],
  optional_fields: [
    { name: 'reviewer_ref', type: 'string' },
    { name: 'reviewer_fhir_identity_digest', type: 'digest' },
    { name: 'reviewer_identity_evidence_digest', type: 'digest' },
    { name: 'reviewer_authority_evidence_digest', type: 'digest' },
    {
      name: 'reviewer_authority_scope',
      type: 'enum',
      values: [REVIEWER_AUTHORITY_SCOPE],
    },
  ],
});

const TOP_LEVEL_FIELDS = new Set([
  '@type',
  'profile_id',
  'ig',
  'rail',
  'action',
  'action_digest',
  'caid',
]);
const IG_FIELDS = new Set([
  'package',
  'version',
  'fhir_release',
  'claim_profile',
  'claim_response_profile',
]);
const BASE_ACTION_FIELDS = new Set([
  'action_type',
  'operation_id',
  'rail',
  'ig_version',
  'pairwise_patient_ref',
  'claim_digest',
  'claim_identifier_digest',
  'claim_response_digest',
  'request_reference_digest',
  'service_request_digest',
  'decision_digest',
  'decision_outcome',
  'fhir_outcome',
  'policy_id',
  'policy_version',
  'policy_digest',
]);
const REVIEWER_ACTION_FIELDS = new Set([
  'reviewer_ref',
  'reviewer_fhir_identity_digest',
  'reviewer_identity_evidence_digest',
  'reviewer_authority_evidence_digest',
  'reviewer_authority_scope',
]);
const ACTION_FIELDS = new Set([
  ...BASE_ACTION_FIELDS,
  ...REVIEWER_ACTION_FIELDS,
]);

const FORBIDDEN_PORTABLE_KEYS = new Set([
  'patient',
  'patientname',
  'patientreference',
  'directpatientreference',
  'beneficiary',
  'beneficiaryname',
  'birthdate',
  'dateofbirth',
  'diagnosis',
  'procedure',
  'supportinginfo',
  'clinical',
  'clinicalnote',
  'rawclinicalresource',
  'rawclaim',
  'rawclaimresponse',
  'resource',
  'contained',
]);

const REVIEW_ACTION_TO_OUTCOME = Object.freeze({
  A1: 'approved',
  A2: 'modified',
  A3: 'denied',
  A4: 'pended',
} satisfies Record<string, DavinciPasDecisionOutcome>);

function own(value: unknown, key: PropertyKey): boolean {
  return value !== null
    && typeof value === 'object'
    && Object.prototype.hasOwnProperty.call(value, key);
}

function isPlainRecord(value: unknown): value is JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Canonical JSON used for PAS source-resource digests. FHIR decimal values are
 * valid JSON numbers, so this source digest permits finite numbers while the
 * smaller CAID action remains inside EMILIA's integer-only action profile.
 */
function canonicalizePasValue(value: unknown): string {
  let nodes = 0;
  let stringBytes = 0;
  const seen = new WeakSet<object>();

  function serialize(current: unknown, depth: number): string {
    nodes += 1;
    if (nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
      throw new TypeError('PAS value exceeds the canonical JSON resource profile');
    }
    if (current === null) return 'null';
    if (typeof current === 'boolean') return current ? 'true' : 'false';
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) throw new TypeError('PAS value contains a non-finite number');
      return JSON.stringify(current);
    }
    if (typeof current === 'string') {
      if (!validUnicode(current)) throw new TypeError('PAS value contains invalid Unicode');
      stringBytes += Buffer.byteLength(current, 'utf8');
      if (stringBytes > MAX_JSON_STRING_BYTES) {
        throw new TypeError('PAS value exceeds the canonical JSON string limit');
      }
      return JSON.stringify(current);
    }
    if (!Array.isArray(current) && !isPlainRecord(current)) {
      throw new TypeError('PAS value contains a non-JSON value');
    }
    if (seen.has(current)) throw new TypeError('PAS value contains a cycle or alias');
    seen.add(current);

    if (Array.isArray(current)) {
      const keys = Reflect.ownKeys(current);
      if (keys.length !== current.length + 1 || !keys.includes('length')) {
        throw new TypeError('PAS value contains a sparse or extended array');
      }
      const values: string[] = [];
      for (let index = 0; index < current.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
        if (!descriptor || descriptor.enumerable !== true || !own(descriptor, 'value')) {
          throw new TypeError('PAS value contains a sparse or accessor array');
        }
        values.push(serialize(descriptor.value, depth + 1));
      }
      return `[${values.join(',')}]`;
    }

    const entries: string[] = [];
    // Default string sort is UTF-16 code-unit order, as required by JCS. Do
    // not use locale-aware collation: locale data would make the digest
    // environment-dependent.
    for (const key of Reflect.ownKeys(current).sort()) {
      if (typeof key !== 'string' || !validUnicode(key)) {
        throw new TypeError('PAS value contains a non-JSON object key');
      }
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (!descriptor || descriptor.enumerable !== true || !own(descriptor, 'value')) {
        throw new TypeError('PAS value contains a non-data JSON property');
      }
      stringBytes += Buffer.byteLength(key, 'utf8');
      if (stringBytes > MAX_JSON_STRING_BYTES) {
        throw new TypeError('PAS value exceeds the canonical JSON string limit');
      }
      entries.push(`${JSON.stringify(key)}:${serialize(descriptor.value, depth + 1)}`);
    }
    return `{${entries.join(',')}}`;
  }

  return serialize(value, 0);
}

export function digestPasValue(value: unknown): string {
  const canonical = canonicalizePasValue(value);
  return `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalizePasValue(left) === canonicalizePasValue(right);
  } catch {
    return false;
  }
}

function canonicalClone<T>(value: T): T {
  return JSON.parse(canonicalizePasValue(value)) as T;
}

function addReason(reasons: string[], reason: string): void {
  if (!reasons.includes(reason)) reasons.push(reason);
}

function hasOnlyFields(value: unknown, allowed: Set<string>): boolean {
  return isPlainRecord(value)
    && Reflect.ownKeys(value).every((key) => typeof key === 'string' && allowed.has(key));
}

function hasAllFields(value: unknown, required: Set<string>): boolean {
  return isPlainRecord(value) && [...required].every((key) => own(value, key));
}

function validDigest(value: unknown): value is string {
  return typeof value === 'string' && SHA256_RE.test(value);
}

function validToken(value: unknown): value is string {
  return typeof value === 'string' && NONEMPTY_TOKEN_RE.test(value);
}

function positiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value > 0;
}

function isDecisionOutcome(value: unknown): value is DavinciPasDecisionOutcome {
  return value === 'approved'
    || value === 'modified'
    || value === 'denied'
    || value === 'pended'
    || value === 'mixed';
}

function validNpi(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{10}$/.test(value)) return false;
  const digits = `80840${value}`;
  let sum = 0;
  const parity = digits.length % 2;
  for (let index = 0; index < digits.length; index += 1) {
    let digit = Number(digits[index]);
    if (index % 2 === parity) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

function referenceOf(value: unknown): string | null {
  return isPlainRecord(value) && typeof value.reference === 'string' && value.reference.length > 0
    ? value.reference
    : null;
}

function profileIncludes(resource: JsonRecord, profile: string): boolean {
  return isPlainRecord(resource.meta)
    && Array.isArray(resource.meta.profile)
    && resource.meta.profile.includes(profile);
}

function extensionList(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.filter(isPlainRecord) : [];
}

function extensionsAt(value: unknown, url: string): JsonRecord[] {
  return extensionList(value).filter((entry) => entry.url === url);
}

function codingHas(value: unknown, system: string, code: string): boolean {
  return isPlainRecord(value)
    && Array.isArray(value.coding)
    && value.coding.some((coding: unknown) => isPlainRecord(coding)
      && coding.system === system
      && coding.code === code);
}

function identifierPresent(value: unknown): boolean {
  return Array.isArray(value)
    && value.length > 0
    && value.every((identifier) => isPlainRecord(identifier)
      && typeof identifier.system === 'string'
      && identifier.system.length > 0
      && typeof identifier.value === 'string'
      && identifier.value.length > 0);
}

function claimItemSequences(items: unknown, reasons: string[]): number[] {
  if (!Array.isArray(items) || items.length === 0) {
    addReason(reasons, 'claim_items_required');
    return [];
  }
  const sequences: number[] = [];
  for (const item of items) {
    if (!isPlainRecord(item)
        || !positiveSafeInteger(item.sequence)
        || !isPlainRecord(item.productOrService)) {
      addReason(reasons, 'claim_item_invalid');
      continue;
    }
    sequences.push(item.sequence);
  }
  if (new Set(sequences).size !== sequences.length) {
    addReason(reasons, 'claim_item_sequence_duplicate');
  }
  return sequences;
}

interface DecisionProjection {
  outcome: DavinciPasDecisionOutcome;
  digest: string;
  item_sequences: number[];
}

function projectDecision(
  response: JsonRecord,
  expectedSequences: number[],
  reasons: string[],
): DecisionProjection | null {
  if (!Array.isArray(response.item) || response.item.length === 0) {
    addReason(reasons, 'claim_response_items_required');
    return null;
  }

  const projected: Array<{ item_sequence: number; review_action_code: string; adjudication_digest: string }> = [];
  const responseSequences: number[] = [];
  const outcomes: DavinciPasDecisionOutcome[] = [];

  for (const item of response.item) {
    if (!isPlainRecord(item)
        || !positiveSafeInteger(item.itemSequence)
        || !Array.isArray(item.adjudication)) {
      addReason(reasons, 'claim_response_item_invalid');
      continue;
    }
    responseSequences.push(item.itemSequence);
    const codes: string[] = [];
    for (const adjudication of item.adjudication) {
      if (!isPlainRecord(adjudication)
          || !codingHas(adjudication.category, ADJUDICATION_SYSTEM, 'submitted')) continue;
      for (const reviewAction of extensionsAt(adjudication.extension, REVIEW_ACTION_URL)) {
        for (const actionCode of extensionsAt(reviewAction.extension, REVIEW_ACTION_CODE_URL)) {
          const coding = isPlainRecord(actionCode.valueCodeableConcept)
            && Array.isArray(actionCode.valueCodeableConcept.coding)
            ? actionCode.valueCodeableConcept.coding
            : [];
          for (const entry of coding) {
            if (isPlainRecord(entry)
                && entry.system === X12_REVIEW_ACTION_SYSTEM
                && typeof entry.code === 'string') {
              codes.push(entry.code);
            }
          }
        }
      }
    }
    if (codes.length !== 1 || !own(REVIEW_ACTION_TO_OUTCOME, codes[0])) {
      addReason(reasons, 'review_action_code_invalid');
      continue;
    }
    const code = codes[0];
    const outcome = REVIEW_ACTION_TO_OUTCOME[code as keyof typeof REVIEW_ACTION_TO_OUTCOME];
    outcomes.push(outcome);
    projected.push({
      item_sequence: item.itemSequence,
      review_action_code: code,
      adjudication_digest: digestPasValue(item.adjudication),
    });
  }

  if (new Set(responseSequences).size !== responseSequences.length) {
    addReason(reasons, 'claim_response_item_sequence_duplicate');
  }
  const expected = [...expectedSequences].sort((left, right) => left - right);
  const actual = [...responseSequences].sort((left, right) => left - right);
  if (!canonicalEqual(expected, actual)) {
    addReason(reasons, 'claim_response_item_sequence_mismatch');
  }
  if (projected.length !== response.item.length || reasons.includes('review_action_code_invalid')) {
    return null;
  }

  projected.sort((left, right) => left.item_sequence - right.item_sequence);
  const uniqueOutcomes = [...new Set(outcomes)];
  const outcome = uniqueOutcomes.length === 1 ? uniqueOutcomes[0] : 'mixed';
  return {
    outcome,
    digest: digestPasValue({
      fhir_outcome: response.outcome,
      response_items: projected,
    }),
    item_sequences: actual,
  };
}

function validatePasResources(
  claim: unknown,
  response: unknown,
  reasons: string[],
): { claim: JsonRecord; response: JsonRecord; decision: DecisionProjection } | null {
  if (!isPlainRecord(claim) || claim.resourceType !== 'Claim') {
    addReason(reasons, 'claim_resource_required');
  }
  if (!isPlainRecord(response) || response.resourceType !== 'ClaimResponse') {
    addReason(reasons, 'claim_response_resource_required');
  }
  if (!isPlainRecord(claim) || !isPlainRecord(response)) return null;

  try {
    digestPasValue(claim);
  } catch {
    addReason(reasons, 'claim_not_canonical_json');
  }
  try {
    digestPasValue(response);
  } catch {
    addReason(reasons, 'claim_response_not_canonical_json');
  }
  if (!profileIncludes(claim, CLAIM_PROFILE)) addReason(reasons, 'claim_profile_mismatch');
  if (!profileIncludes(response, CLAIM_RESPONSE_PROFILE)) {
    addReason(reasons, 'claim_response_profile_mismatch');
  }
  if (claim.use !== 'preauthorization') addReason(reasons, 'claim_use_mismatch');
  if (response.use !== 'preauthorization') addReason(reasons, 'claim_response_use_mismatch');
  if (claim.status !== 'active') addReason(reasons, 'claim_status_not_active');
  if (response.status !== 'active') addReason(reasons, 'claim_response_status_not_active');
  if (!canonicalEqual(claim.type, response.type)) addReason(reasons, 'claim_response_type_mismatch');
  if (!identifierPresent(claim.identifier)) addReason(reasons, 'claim_identifier_required');
  if (typeof claim.id !== 'string' || !FHIR_ID_RE.test(claim.id)) {
    addReason(reasons, 'claim_id_invalid');
  }
  if (response.outcome !== 'complete') addReason(reasons, 'claim_response_outcome_not_complete');
  if (Array.isArray(response.error) && response.error.length > 0) {
    addReason(reasons, 'claim_response_error_present');
  }
  if (!referenceOf(claim.provider)) addReason(reasons, 'claim_provider_reference_required');

  const claimPatient = referenceOf(claim.patient);
  const responsePatient = referenceOf(response.patient);
  if (!claimPatient) addReason(reasons, 'claim_patient_reference_required');
  if (!responsePatient) addReason(reasons, 'claim_response_patient_reference_required');
  if (claimPatient && responsePatient && claimPatient !== responsePatient) {
    addReason(reasons, 'claim_response_patient_mismatch');
  }

  const claimInsurer = referenceOf(claim.insurer);
  const responseInsurer = referenceOf(response.insurer);
  if (!claimInsurer) addReason(reasons, 'claim_insurer_reference_required');
  if (!responseInsurer) addReason(reasons, 'claim_response_insurer_reference_required');
  if (claimInsurer && responseInsurer && claimInsurer !== responseInsurer) {
    addReason(reasons, 'claim_response_insurer_mismatch');
  }

  const requestReference = referenceOf(response.request);
  if (!requestReference) {
    addReason(reasons, 'claim_response_request_required');
  } else if (typeof claim.id === 'string' && requestReference !== `Claim/${claim.id}`) {
    addReason(reasons, 'claim_response_request_mismatch');
  }

  const sequences = claimItemSequences(claim.item, reasons);
  const decision = projectDecision(response, sequences, reasons);
  if (reasons.length > 0 || !decision) return null;
  return { claim, response, decision };
}

function reviewIsAdverse(outcome: DavinciPasDecisionOutcome): boolean {
  return outcome !== 'approved';
}

function validateReviewer(
  response: JsonRecord,
  decision: DecisionProjection,
  reviewer: unknown,
  policyDigest: string,
  responseDigest: string,
  reasons: string[],
): Pick<DavinciPasMaterialAction,
  'reviewer_ref'
  | 'reviewer_fhir_identity_digest'
  | 'reviewer_identity_evidence_digest'
  | 'reviewer_authority_evidence_digest'
  | 'reviewer_authority_scope'> | null {
  if (!reviewIsAdverse(decision.outcome)) return null;
  if (!isPlainRecord(reviewer)) {
    addReason(reasons, 'adverse_reviewer_required');
    return null;
  }

  const reviewerRef = reviewer.reviewer_ref;
  if (typeof reviewerRef !== 'string' || !REVIEWER_REF_RE.test(reviewerRef)) {
    addReason(reasons, 'reviewer_ref_invalid');
  }

  const fhirReviewers = extensionsAt(response.extension, REVIEWER_URL);
  if (fhirReviewers.length !== 1) {
    addReason(reasons, 'fhir_reviewer_identity_required');
    return null;
  }
  const fhirReviewer = fhirReviewers[0];
  const humanFlags = extensionsAt(fhirReviewer.extension, 'wasHumanReviewedFlag');
  if (humanFlags.length !== 1 || humanFlags[0].valueBoolean !== true) {
    addReason(reasons, 'fhir_human_review_required');
  }
  const reviewerNpis = extensionsAt(fhirReviewer.extension, 'reviewerNPI');
  if (reviewerNpis.length !== 1
      || !isPlainRecord(reviewerNpis[0].valueIdentifier)
      || reviewerNpis[0].valueIdentifier.system !== 'http://hl7.org/fhir/sid/us-npi'
      || !validNpi(reviewerNpis[0].valueIdentifier.value)) {
    addReason(reasons, 'fhir_reviewer_identity_required');
  }
  const fhirReviewerDigest = digestPasValue(fhirReviewer);

  const identity = reviewer.identity_evidence;
  if (!isPlainRecord(identity)) {
    addReason(reasons, 'reviewer_identity_evidence_required');
  } else {
    if (identity.status !== 'accepted') addReason(reasons, 'reviewer_identity_not_accepted');
    if (identity.subject_ref !== reviewerRef) addReason(reasons, 'reviewer_identity_subject_mismatch');
    if (!validDigest(identity.evidence_digest)) addReason(reasons, 'reviewer_identity_digest_invalid');
    if (identity.fhir_reviewer_digest !== fhirReviewerDigest) {
      addReason(reasons, 'reviewer_identity_fhir_mismatch');
    }
  }

  const authority = reviewer.authority_evidence;
  if (!isPlainRecord(authority)) {
    addReason(reasons, 'reviewer_authority_evidence_required');
  } else {
    if (authority.status !== 'accepted') addReason(reasons, 'reviewer_authority_not_accepted');
    if (authority.subject_ref !== reviewerRef) addReason(reasons, 'reviewer_authority_subject_mismatch');
    if (!validDigest(authority.evidence_digest)) addReason(reasons, 'reviewer_authority_digest_invalid');
    if (authority.scope !== REVIEWER_AUTHORITY_SCOPE) addReason(reasons, 'reviewer_authority_scope_mismatch');
    if (authority.policy_digest !== policyDigest) {
      addReason(reasons, 'reviewer_authority_policy_mismatch');
    }
    if (authority.claim_response_digest !== responseDigest) {
      addReason(reasons, 'reviewer_authority_claim_response_mismatch');
    }
  }

  if (reasons.length > 0
      || !isPlainRecord(identity)
      || !isPlainRecord(authority)
      || typeof reviewerRef !== 'string'
      || !validDigest(identity.evidence_digest)
      || !validDigest(authority.evidence_digest)) return null;
  return {
    reviewer_ref: reviewerRef,
    reviewer_fhir_identity_digest: fhirReviewerDigest,
    reviewer_identity_evidence_digest: identity.evidence_digest,
    reviewer_authority_evidence_digest: authority.evidence_digest,
    reviewer_authority_scope: REVIEWER_AUTHORITY_SCOPE,
  };
}

function materialProjection(input: unknown):
  | { ok: true; action: DavinciPasMaterialAction }
  | { ok: false; reasons: string[] } {
  const reasons: string[] = [];
  if (!isPlainRecord(input)) return { ok: false, reasons: ['binding_input_required'] };

  if (typeof input.operation_id !== 'string' || !OPERATION_ID_RE.test(input.operation_id)) {
    addReason(reasons, 'operation_id_invalid');
  }
  if (typeof input.pairwise_patient_ref !== 'string'
      || !PAIRWISE_PATIENT_RE.test(input.pairwise_patient_ref)) {
    addReason(reasons, 'patient_reference_not_pairwise');
  }

  const policy = input.policy;
  if (!isPlainRecord(policy)) {
    addReason(reasons, 'policy_required');
  } else {
    if (typeof policy.policy_id !== 'string' || !POLICY_ID_RE.test(policy.policy_id)) {
      addReason(reasons, 'policy_id_invalid');
    }
    if (!validToken(policy.policy_version)) addReason(reasons, 'policy_version_invalid');
    if (!validDigest(policy.policy_digest)) addReason(reasons, 'policy_digest_invalid');
  }

  const resources = validatePasResources(input.claim, input.claim_response, reasons);
  if (!resources
      || !isPlainRecord(policy)
      || typeof input.operation_id !== 'string'
      || typeof input.pairwise_patient_ref !== 'string'
      || typeof policy.policy_id !== 'string'
      || !validToken(policy.policy_version)
      || !validDigest(policy.policy_digest)
      || reasons.length > 0) {
    return { ok: false, reasons };
  }

  const claimDigest = digestPasValue(resources.claim);
  const responseDigest = digestPasValue(resources.response);
  const reviewerProjection = validateReviewer(
    resources.response,
    resources.decision,
    input.reviewer,
    policy.policy_digest,
    responseDigest,
    reasons,
  );
  if (reasons.length > 0) return { ok: false, reasons };

  const action: DavinciPasMaterialAction = {
    action_type: DAVINCI_PAS_ACTION_TYPE,
    operation_id: input.operation_id,
    rail: DAVINCI_PAS_MEDICAL_RAIL,
    ig_version: DAVINCI_PAS_IG_VERSION,
    pairwise_patient_ref: input.pairwise_patient_ref,
    claim_digest: claimDigest,
    claim_identifier_digest: digestPasValue(resources.claim.identifier),
    claim_response_digest: responseDigest,
    request_reference_digest: digestPasValue(resources.response.request),
    service_request_digest: digestPasValue({
      careTeam: resources.claim.careTeam ?? [],
      supportingInfo: resources.claim.supportingInfo ?? [],
      diagnosis: resources.claim.diagnosis ?? [],
      procedure: resources.claim.procedure ?? [],
      insurance: resources.claim.insurance ?? [],
      item: resources.claim.item,
    }),
    decision_digest: resources.decision.digest,
    decision_outcome: resources.decision.outcome,
    fhir_outcome: 'complete',
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    policy_digest: policy.policy_digest,
    ...(reviewerProjection ?? {}),
  };
  return { ok: true, action: canonicalClone(action) };
}

/**
 * Build a portable binding from resources already obtained from the server's
 * authenticated PAS/system-of-record path. Raw FHIR and clinical content is
 * digested but never copied into the returned object.
 */
export function buildDavinciPasReviewBinding(input: unknown): DavinciPasBuildResult {
  try {
    const projected = materialProjection(input);
    if (!projected.ok) return projected;
    const computed = computeCaid(projected.action, {
      suite: 'jcs-sha256',
      definitions: [CAID_DEFINITION],
    });
    if (typeof computed?.caid !== 'string' || !validDigest(computed.digest)) {
      return {
        ok: false,
        reasons: (computed?.refusals ?? ['caid_projection_invalid'])
          .map((reason: string) => `caid:${reason}`),
      };
    }
    return {
      ok: true,
      binding: canonicalClone({
        '@type': DAVINCI_PAS_BINDING_TYPE,
        profile_id: DAVINCI_PAS_PROFILE_ID,
        ig: {
          package: 'hl7.fhir.us.davinci-pas',
          version: DAVINCI_PAS_IG_VERSION,
          fhir_release: 'R4',
          claim_profile: CLAIM_PROFILE,
          claim_response_profile: CLAIM_RESPONSE_PROFILE,
        },
        rail: DAVINCI_PAS_MEDICAL_RAIL,
        action: projected.action,
        action_digest: computed.digest,
        caid: computed.caid,
      }),
    };
  } catch {
    return { ok: false, reasons: ['binding_input_not_canonical_json'] };
  }
}

function findForbiddenPortableField(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false;
  const stack: object[] = [value];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    for (const key of Reflect.ownKeys(current)) {
      if (typeof key !== 'string') return true;
      const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (FORBIDDEN_PORTABLE_KEYS.has(normalized)) return true;
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (!descriptor || !own(descriptor, 'value')) return true;
      if (descriptor.value !== null && typeof descriptor.value === 'object') {
        stack.push(descriptor.value);
      }
    }
  }
  return false;
}

function validatePortableShape(binding: unknown, reasons: string[]): binding is DavinciPasReviewBinding {
  try {
    canonicalizePasValue(binding);
  } catch {
    addReason(reasons, 'portable_output_not_canonical_json');
  }
  if (findForbiddenPortableField(binding)) addReason(reasons, 'portable_phi_field');
  if (!isPlainRecord(binding)) {
    addReason(reasons, 'portable_binding_invalid');
    return false;
  }
  if (!hasOnlyFields(binding, TOP_LEVEL_FIELDS)) {
    addReason(reasons, 'portable_output_unknown_field');
  }
  if (!hasAllFields(binding, TOP_LEVEL_FIELDS)) addReason(reasons, 'portable_output_missing_field');
  if (!hasOnlyFields(binding.ig, IG_FIELDS)) addReason(reasons, 'portable_output_unknown_field');
  if (!hasAllFields(binding.ig, IG_FIELDS)) addReason(reasons, 'portable_output_missing_field');
  if (!hasOnlyFields(binding.action, ACTION_FIELDS)) {
    addReason(reasons, 'portable_output_unknown_field');
  }
  if (!hasAllFields(binding.action, BASE_ACTION_FIELDS)) {
    addReason(reasons, 'portable_output_missing_field');
  }
  if (!isPlainRecord(binding.action)) return false;

  if (binding['@type'] !== DAVINCI_PAS_BINDING_TYPE
      || binding.profile_id !== DAVINCI_PAS_PROFILE_ID) {
    addReason(reasons, 'binding_profile_mismatch');
  }
  if (!isPlainRecord(binding.ig)
      || binding.ig.package !== 'hl7.fhir.us.davinci-pas'
      || binding.ig.version !== DAVINCI_PAS_IG_VERSION
      || binding.ig.fhir_release !== 'R4'
      || binding.ig.claim_profile !== CLAIM_PROFILE
      || binding.ig.claim_response_profile !== CLAIM_RESPONSE_PROFILE) {
    addReason(reasons, 'ig_profile_mismatch');
  }
  if (binding.rail !== DAVINCI_PAS_MEDICAL_RAIL
      || binding.action.rail !== DAVINCI_PAS_MEDICAL_RAIL) {
    addReason(reasons, 'medical_rail_mismatch');
  }
  if (binding.action.action_type !== DAVINCI_PAS_ACTION_TYPE) {
    addReason(reasons, 'action_type_mismatch');
  }
  if (binding.action.ig_version !== DAVINCI_PAS_IG_VERSION) {
    addReason(reasons, 'ig_version_mismatch');
  }
  if (typeof binding.action.pairwise_patient_ref !== 'string'
      || !PAIRWISE_PATIENT_RE.test(binding.action.pairwise_patient_ref)) {
    addReason(reasons, 'patient_reference_not_pairwise');
  }
  if (typeof binding.action.operation_id !== 'string'
      || !OPERATION_ID_RE.test(binding.action.operation_id)) {
    addReason(reasons, 'operation_id_invalid');
  }
  for (const field of [
    'claim_digest',
    'claim_identifier_digest',
    'claim_response_digest',
    'request_reference_digest',
    'service_request_digest',
    'decision_digest',
    'policy_digest',
  ]) {
    if (!validDigest(binding.action[field])) addReason(reasons, 'portable_digest_invalid');
  }
  if (!validDigest(binding.action_digest)) addReason(reasons, 'action_digest_invalid');

  const decisionOutcome = binding.action.decision_outcome;
  if (!isDecisionOutcome(decisionOutcome)) {
    addReason(reasons, 'decision_outcome_invalid');
  }
  if (isDecisionOutcome(decisionOutcome)
      && reviewIsAdverse(decisionOutcome)
      && !hasAllFields(binding.action, REVIEWER_ACTION_FIELDS)) {
    addReason(reasons, 'portable_adverse_reviewer_missing');
  }
  if (own(binding.action, 'reviewer_ref')
      && (typeof binding.action.reviewer_ref !== 'string'
        || !REVIEWER_REF_RE.test(binding.action.reviewer_ref))) {
    addReason(reasons, 'reviewer_ref_invalid');
  }
  for (const field of [
    'reviewer_fhir_identity_digest',
    'reviewer_identity_evidence_digest',
    'reviewer_authority_evidence_digest',
  ]) {
    if (own(binding.action, field) && !validDigest(binding.action[field])) {
      addReason(reasons, 'portable_digest_invalid');
    }
  }
  if (own(binding.action, 'reviewer_authority_scope')
      && binding.action.reviewer_authority_scope !== REVIEWER_AUTHORITY_SCOPE) {
    addReason(reasons, 'reviewer_authority_scope_mismatch');
  }
  return true;
}

/**
 * Reproject the caller-supplied server-observed resources, verify every digest
 * and the CAID, enforce the portable allowlist, and apply caller-maintained
 * single-use state. The verifier does not mutate `consumed_caids`.
 */
export function verifyDavinciPasReviewBinding(
  binding: unknown,
  context: unknown,
): DavinciPasVerificationResult {
  const reasons: string[] = [];
  let portableBinding: DavinciPasReviewBinding | undefined;
  try {
    if (validatePortableShape(binding, reasons)) portableBinding = binding;
  } catch {
    addReason(reasons, 'portable_output_not_canonical_json');
    addReason(reasons, 'portable_binding_invalid');
  }
  const trustedContext = isPlainRecord(context) ? context : {};

  if (portableBinding) {
    const computed = computeCaid(portableBinding.action, {
      suite: 'jcs-sha256',
      definitions: [CAID_DEFINITION],
    });
    if (typeof computed?.digest !== 'string' || computed.digest !== portableBinding.action_digest) {
      addReason(reasons, 'action_digest_mismatch');
    }
    if (typeof computed?.caid !== 'string' || computed.caid !== portableBinding.caid) {
      addReason(reasons, 'caid_mismatch');
    }
    const caidVerification = verifyCaid(portableBinding.action, portableBinding.caid, {
      definitions: [CAID_DEFINITION],
    });
    if (caidVerification.valid !== true) addReason(reasons, 'caid_mismatch');

    if (typeof trustedContext.expected_operation_id === 'string'
        && trustedContext.expected_operation_id !== portableBinding.action.operation_id) {
      addReason(reasons, 'expected_operation_id_mismatch');
    }
    if (typeof trustedContext.expected_caid === 'string'
        && trustedContext.expected_caid !== portableBinding.caid) {
      addReason(reasons, 'expected_caid_mismatch');
    }
    if (trustedContext.consumed_caids instanceof Set
        && trustedContext.consumed_caids.has(portableBinding.caid)) {
      addReason(reasons, 'replay_refused');
    }

    try {
      if (digestPasValue(trustedContext.claim) !== portableBinding.action.claim_digest) {
        addReason(reasons, 'claim_digest_mismatch');
      }
    } catch {
      addReason(reasons, 'claim_digest_mismatch');
    }
    try {
      if (digestPasValue(trustedContext.claim_response) !== portableBinding.action.claim_response_digest) {
        addReason(reasons, 'claim_response_digest_mismatch');
      }
    } catch {
      addReason(reasons, 'claim_response_digest_mismatch');
    }
    if (isPlainRecord(trustedContext.policy)
        && trustedContext.policy.policy_digest !== portableBinding.action.policy_digest) {
      addReason(reasons, 'policy_digest_mismatch');
    }

    const expected = buildDavinciPasReviewBinding(trustedContext);
    if (!expected.ok || !canonicalEqual(expected.binding.action, portableBinding.action)) {
      addReason(reasons, 'action_projection_mismatch');
    }
  }

  return { valid: reasons.length === 0, reasons };
}

const davinciPasBinding = {
  DAVINCI_PAS_ACTION_TYPE,
  DAVINCI_PAS_BINDING_TYPE,
  DAVINCI_PAS_PROFILE_ID,
  DAVINCI_PAS_IG_VERSION,
  DAVINCI_PAS_MEDICAL_RAIL,
  buildDavinciPasReviewBinding,
  digestPasValue,
  verifyDavinciPasReviewBinding,
};

export default davinciPasBinding;
