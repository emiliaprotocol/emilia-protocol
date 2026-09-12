// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * EP-ACTION-RISK-CONTROL-SCHEDULE-v1.
 *
 * A relying-party-scoped, hybrid-signed statement of the technical controls
 * that must be observed for one action class. The schedule is evidence input
 * only. It never authorizes an action, creates policy or coverage, sets a
 * premium, allocates liability, or proves that a provider effect occurred.
 */
import { canonicalize } from './execution-binding.js';
import { RISK_DIGEST, RISK_HYBRID_PROFILE, RISK_HYBRID_REQUIRED_ALGORITHMS, riskDigest, riskExact, riskFreeze, riskIdentifier, riskInstant, riskRecord, signRiskBodyV2, verifyRiskBodyV2, } from './reliance-risk-crypto.js';
export const ACTION_RISK_CONTROL_SCHEDULE_VERSION = 'EP-ACTION-RISK-CONTROL-SCHEDULE-v1';
export const ACTION_RISK_QUALIFICATION_STATUS_VERSION = 'EP-ACTION-RISK-QUALIFICATION-STATUS-v1';
export const ACTION_RISK_CONTROL_EVALUATION_VERSION = 'EP-ACTION-RISK-CONTROL-EVALUATION-v1';
export const ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY = 'technical_control_requirements_only_not_policy_coverage_premium_liability_action_authorization_or_effect_proof';
export const ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY = 'technical_qualification_observation_only_not_policy_coverage_premium_liability_or_action_authorization';
export const ACTION_RISK_CONTROL_OUTCOMES = Object.freeze([
    'ELIGIBLE',
    'NOT_ELIGIBLE',
    'INDETERMINATE',
]);
export const ACTION_RISK_INDETERMINATE_HANDLING = 'REFUSE_RETRY_PRESERVE_OPEN_EXPOSURE_REQUIRE_RECONCILIATION';
export const ACTION_RISK_DIVERGENT_HANDLING = 'REFUSE_CLOSEOUT_PRESERVE_OPEN_EXPOSURE_ESCALATE';
const SOURCE_KEYS = [
    'schedule_id',
    'relying_party_id',
    'tenant_id',
    'issued_at',
    'valid_from',
    'expires_at',
    'action',
    'provider_binding',
    'qualification',
    'control_bindings',
    'complete_mediation',
    'loss_allocation',
    'open_exposure',
    'outcome_binding',
    'handling',
    'trust_pin_references',
    'claim_boundary',
];
const BODY_KEYS = ['@version', ...SOURCE_KEYS, 'issuer'];
const ISSUER_KEYS = ['id', 'key_id'];
const ACTION_KEYS = ['action_class', 'caid_profile_id', 'caid_profile_digest'];
const PROVIDER_KEYS = ['provider_id', 'account_id', 'environment', 'adapter_digest'];
const QUALIFICATION_KEYS = [
    'requirements_digest',
    'status_authority_id',
    'status_key_id',
    'min_sequence',
    'max_observation_age_sec',
];
const CONTROL_KEYS = ['aeb_digest', 'aec_digest', 'local_policy_digest'];
const MEDIATION_KEYS = ['surface_inventory_digest', 'refusal_probe_evidence_digest'];
const LOSS_ALLOCATION_KEYS = ['program_digest'];
const OPEN_EXPOSURE_KEYS = [
    'program_id',
    'program_digest',
    'currency',
    'per_action_ceiling_minor',
    'aggregate_ceiling_minor',
    'reconciler_id',
    'reconciliation_deadline_sec',
];
const OUTCOME_BINDING_KEYS = [
    'required_sources',
    'quorum',
    'observation_window',
    'require_control_domain_independence',
];
const OUTCOME_SOURCE_KEYS = ['role', 'source_class'];
const OUTCOME_WINDOW_KEYS = [
    'opens_before_provider_entry_sec',
    'closes_after_provider_entry_sec',
    'max_observation_age_sec',
];
const HANDLING_KEYS = ['indeterminate', 'divergent'];
const TRUST_REFERENCE_KEYS = ['purpose', 'authority_id', 'key_id', 'key_digest'];
const OBSERVED_CONTROL_KEYS = [
    'action',
    'provider_binding',
    'qualification_requirements_digest',
    'control_bindings',
    'complete_mediation',
    'loss_allocation',
    'open_exposure',
    'outcome_binding',
    'handling',
    'trust_pin_references',
];
const STATUS_SOURCE_KEYS = [
    'status_id',
    'schedule_id',
    'schedule_digest',
    'tenant_id',
    'requirements_digest',
    'sequence',
    'observed_at',
    'outcome',
    'evidence_digest',
    'claim_boundary',
];
const STATUS_BODY_KEYS = ['@version', ...STATUS_SOURCE_KEYS, 'issuer'];
const STATUS_HEAD_KEYS = [
    'schedule_id',
    'schedule_digest',
    'tenant_id',
    'status_authority_id',
    'status_key_id',
    'sequence',
    'status_digest',
    'recorded_at',
];
const HYBRID_PROOF_KEYS = [
    'profile',
    'required_algorithms',
    'key_id',
    'body_digest',
    'signatures',
];
const HYBRID_SIGNATURE_KEYS = ['alg', 'sig', 'key_id'];
const CURRENCY = /^[A-Z]{3}$/;
const MINOR_AMOUNT = /^(0|[1-9][0-9]*)$/;
const OUTCOME_SOURCE_ROLES = new Set(['executor', 'system_of_record', 'independent_observer']);
const TRUST_PURPOSES = new Set([
    'SCHEDULE_ISSUER',
    'QUALIFICATION_STATUS',
]);
const MAX_SECONDS = 31_536_000;
const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER;
export class ActionRiskControlScheduleValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'ActionRiskControlScheduleValidationError';
        this.code = code;
    }
}
function invalid(code, message) {
    throw new ActionRiskControlScheduleValidationError(code, message);
}
function denseArray(value, min, max) {
    if (!Array.isArray(value) || value.length < min || value.length > max)
        return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length'))
        return false;
    for (let i = 0; i < value.length; i += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
        if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value'))
            return false;
    }
    return keys.every((key) => key === 'length' || (typeof key === 'string' && /^(0|[1-9][0-9]*)$/.test(key)));
}
function digest(value) {
    return typeof value === 'string' && RISK_DIGEST.test(value);
}
function validateBoundHybridProof(value) {
    if (!riskRecord(value)
        || !riskExact(value.issuer, ISSUER_KEYS)
        || !riskExact(value.proof, HYBRID_PROOF_KEYS)
        || value.proof.profile !== RISK_HYBRID_PROFILE
        || !riskIdentifier(value.proof.key_id)
        || value.proof.key_id !== value.issuer.key_id
        || !digest(value.proof.body_digest)
        || !denseArray(value.proof.required_algorithms, 2, 2)
        || !value.proof.required_algorithms.every((algorithm, index) => algorithm === RISK_HYBRID_REQUIRED_ALGORITHMS[index])) {
        invalid('artifact_signature_envelope_invalid', 'hybrid proof envelope is not the registered closed shape');
    }
    if (!Array.isArray(value.proof.signatures) || value.proof.signatures.length < 2) {
        invalid('signature_set_incomplete', 'hybrid proof must carry exactly both required signatures');
    }
    if (!denseArray(value.proof.signatures, 2, 2)) {
        invalid('signature_set_invalid', 'hybrid proof must carry exactly two dense signature entries');
    }
    for (let index = 0; index < RISK_HYBRID_REQUIRED_ALGORITHMS.length; index += 1) {
        const signature = value.proof.signatures[index];
        if (!riskRecord(signature) || !Object.hasOwn(signature, 'key_id')) {
            invalid('signature_key_id_required', 'each hybrid signature must carry its key id');
        }
        if (!riskExact(signature, HYBRID_SIGNATURE_KEYS)
            || signature.alg !== RISK_HYBRID_REQUIRED_ALGORITHMS[index]
            || typeof signature.sig !== 'string' || signature.sig.length === 0) {
            invalid('signature_set_invalid', 'hybrid signatures must use the registered order and closed entry shape');
        }
        if (signature.key_id !== value.proof.key_id || signature.key_id !== value.issuer.key_id) {
            invalid('signature_key_id_mismatch', 'each hybrid signature key id must equal the proof and issuer key id');
        }
    }
}
function boundedInteger(value, min, max) {
    return Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;
}
function validAction(value) {
    return riskExact(value, ACTION_KEYS)
        && riskIdentifier(value.action_class)
        && riskIdentifier(value.caid_profile_id)
        && digest(value.caid_profile_digest);
}
function validProviderBinding(value) {
    return riskExact(value, PROVIDER_KEYS)
        && riskIdentifier(value.provider_id)
        && riskIdentifier(value.account_id)
        && riskIdentifier(value.environment)
        && digest(value.adapter_digest);
}
function validQualification(value) {
    return riskExact(value, QUALIFICATION_KEYS)
        && digest(value.requirements_digest)
        && riskIdentifier(value.status_authority_id)
        && riskIdentifier(value.status_key_id)
        && boundedInteger(value.min_sequence, 1, MAX_SEQUENCE)
        && boundedInteger(value.max_observation_age_sec, 1, MAX_SECONDS);
}
function validControlBindings(value) {
    return riskExact(value, CONTROL_KEYS)
        && digest(value.aeb_digest)
        && digest(value.aec_digest)
        && digest(value.local_policy_digest);
}
function validCompleteMediation(value) {
    return riskExact(value, MEDIATION_KEYS)
        && digest(value.surface_inventory_digest)
        && digest(value.refusal_probe_evidence_digest);
}
function validLossAllocation(value) {
    return riskExact(value, LOSS_ALLOCATION_KEYS) && digest(value.program_digest);
}
function validOpenExposure(value) {
    if (!riskExact(value, OPEN_EXPOSURE_KEYS)
        || !riskIdentifier(value.program_id)
        || !digest(value.program_digest)
        || typeof value.currency !== 'string' || !CURRENCY.test(value.currency)
        || typeof value.per_action_ceiling_minor !== 'string' || !MINOR_AMOUNT.test(value.per_action_ceiling_minor)
        || typeof value.aggregate_ceiling_minor !== 'string' || !MINOR_AMOUNT.test(value.aggregate_ceiling_minor)
        || !riskIdentifier(value.reconciler_id)
        || !boundedInteger(value.reconciliation_deadline_sec, 1, MAX_SECONDS))
        return false;
    try {
        const perAction = BigInt(value.per_action_ceiling_minor);
        const aggregate = BigInt(value.aggregate_ceiling_minor);
        return perAction > 0n && aggregate > 0n && perAction <= aggregate;
    }
    catch {
        return false;
    }
}
function validOutcomeBinding(value) {
    if (!riskExact(value, OUTCOME_BINDING_KEYS)
        || !denseArray(value.required_sources, 2, 16)
        || !boundedInteger(value.quorum, 2, value.required_sources.length)
        || value.require_control_domain_independence !== true
        || !riskExact(value.observation_window, OUTCOME_WINDOW_KEYS)
        || !boundedInteger(value.observation_window.opens_before_provider_entry_sec, 0, MAX_SECONDS)
        || !boundedInteger(value.observation_window.closes_after_provider_entry_sec, 0, MAX_SECONDS)
        || !boundedInteger(value.observation_window.max_observation_age_sec, 1, MAX_SECONDS))
        return false;
    let previous = null;
    const seen = new Set();
    for (const source of value.required_sources) {
        if (!riskExact(source, OUTCOME_SOURCE_KEYS)
            || typeof source.role !== 'string' || !OUTCOME_SOURCE_ROLES.has(source.role)
            || !riskIdentifier(source.source_class))
            return false;
        const identity = `${source.role}\0${source.source_class}`;
        if (seen.has(identity) || (previous !== null && previous > identity))
            return false;
        seen.add(identity);
        previous = identity;
    }
    return true;
}
function validHandling(value) {
    return riskExact(value, HANDLING_KEYS)
        && value.indeterminate === ACTION_RISK_INDETERMINATE_HANDLING
        && value.divergent === ACTION_RISK_DIVERGENT_HANDLING;
}
function validTrustReferences(value) {
    if (!denseArray(value, 2, 2))
        return false;
    const seen = new Set();
    const purposes = new Set();
    let previous = null;
    for (const reference of value) {
        if (!riskExact(reference, TRUST_REFERENCE_KEYS)
            || typeof reference.purpose !== 'string' || !TRUST_PURPOSES.has(reference.purpose)
            || !riskIdentifier(reference.authority_id)
            || !riskIdentifier(reference.key_id)
            || !digest(reference.key_digest))
            return false;
        const identity = `${reference.purpose}\0${reference.authority_id}\0${reference.key_id}`;
        if (seen.has(identity) || (previous !== null && previous > identity))
            return false;
        seen.add(identity);
        purposes.add(reference.purpose);
        previous = identity;
    }
    return purposes.has('SCHEDULE_ISSUER') && purposes.has('QUALIFICATION_STATUS');
}
function validateScheduleSource(value) {
    if (!riskExact(value, SOURCE_KEYS)
        || !riskIdentifier(value.schedule_id)
        || !riskIdentifier(value.relying_party_id)
        || !riskIdentifier(value.tenant_id)
        || !validAction(value.action)
        || !validProviderBinding(value.provider_binding)
        || !validQualification(value.qualification)
        || !validControlBindings(value.control_bindings)
        || !validCompleteMediation(value.complete_mediation)
        || !validLossAllocation(value.loss_allocation)
        || !validOpenExposure(value.open_exposure)
        || !validOutcomeBinding(value.outcome_binding)
        || !validHandling(value.handling)
        || !validTrustReferences(value.trust_pin_references)) {
        invalid('schedule_schema_invalid', 'action risk control schedule source must be a closed, bounded v1 object');
    }
    const issuedAt = riskInstant(value.issued_at);
    const validFrom = riskInstant(value.valid_from);
    const expiresAt = riskInstant(value.expires_at);
    if (!Number.isFinite(issuedAt) || !Number.isFinite(validFrom) || !Number.isFinite(expiresAt)
        || issuedAt > validFrom || validFrom >= expiresAt) {
        invalid('schedule_validity_invalid', 'action risk control schedule validity is invalid');
    }
    if (value.claim_boundary !== ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY) {
        invalid('claim_boundary_invalid', 'action risk control schedule claim boundary is missing or changed');
    }
    try {
        canonicalize(value);
    }
    catch {
        invalid('schedule_not_canonical', 'action risk control schedule is not canonicalizable JSON');
    }
}
function findTrustReference(body, purpose) {
    return body.trust_pin_references.find((reference) => reference.purpose === purpose);
}
function validateScheduleBody(value) {
    if (!riskExact(value, BODY_KEYS)
        || value['@version'] !== ACTION_RISK_CONTROL_SCHEDULE_VERSION
        || !riskExact(value.issuer, ISSUER_KEYS)
        || !riskIdentifier(value.issuer.id)
        || !riskIdentifier(value.issuer.key_id)) {
        invalid('schedule_schema_invalid', 'signed action risk control schedule must be a closed v1 object');
    }
    const { '@version': _version, issuer: _issuer, ...source } = value;
    validateScheduleSource(source);
    const scheduleIssuer = findTrustReference(value, 'SCHEDULE_ISSUER');
    const statusAuthority = findTrustReference(value, 'QUALIFICATION_STATUS');
    if (!scheduleIssuer
        || scheduleIssuer.authority_id !== value.issuer.id
        || scheduleIssuer.key_id !== value.issuer.key_id) {
        invalid('schedule_issuer_reference_mismatch', 'schedule issuer reference must match the hybrid signer identity');
    }
    if (!statusAuthority
        || statusAuthority.authority_id !== value.qualification.status_authority_id
        || statusAuthority.key_id !== value.qualification.status_key_id) {
        invalid('status_authority_reference_mismatch', 'qualification status reference must match the required status authority');
    }
}
function validateObservedControls(value) {
    if (!riskExact(value, OBSERVED_CONTROL_KEYS)
        || !validAction(value.action)
        || !validProviderBinding(value.provider_binding)
        || !digest(value.qualification_requirements_digest)
        || !validControlBindings(value.control_bindings)
        || !validCompleteMediation(value.complete_mediation)
        || !validLossAllocation(value.loss_allocation)
        || !validOpenExposure(value.open_exposure)
        || !validOutcomeBinding(value.outcome_binding)
        || !validHandling(value.handling)
        || !validTrustReferences(value.trust_pin_references)) {
        invalid('control_observation_invalid', 'observed controls must be a closed, bounded v1 object');
    }
    try {
        canonicalize(value);
    }
    catch {
        invalid('control_observation_invalid', 'observed controls are not canonicalizable JSON');
    }
}
function validOutcome(value) {
    return typeof value === 'string'
        && ACTION_RISK_CONTROL_OUTCOMES.includes(value);
}
function validateQualificationStatusSource(value) {
    if (!riskExact(value, STATUS_SOURCE_KEYS)
        || !riskIdentifier(value.status_id)
        || !riskIdentifier(value.schedule_id)
        || !digest(value.schedule_digest)
        || !riskIdentifier(value.tenant_id)
        || !digest(value.requirements_digest)
        || !boundedInteger(value.sequence, 1, MAX_SEQUENCE)
        || !Number.isFinite(riskInstant(value.observed_at))
        || !validOutcome(value.outcome)
        || !digest(value.evidence_digest)
        || value.claim_boundary !== ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY) {
        invalid('qualification_status_schema_invalid', 'qualification status must be a closed, bounded v1 object');
    }
    try {
        canonicalize(value);
    }
    catch {
        invalid('qualification_status_not_canonical', 'qualification status is not canonicalizable JSON');
    }
}
function validateQualificationStatusBody(value) {
    if (!riskExact(value, STATUS_BODY_KEYS)
        || value['@version'] !== ACTION_RISK_QUALIFICATION_STATUS_VERSION
        || !riskExact(value.issuer, ISSUER_KEYS)
        || !riskIdentifier(value.issuer.id)
        || !riskIdentifier(value.issuer.key_id)) {
        invalid('qualification_status_schema_invalid', 'signed qualification status must be a closed v1 object');
    }
    const { '@version': _version, issuer: _issuer, ...source } = value;
    validateQualificationStatusSource(source);
}
function validateQualificationStatusHead(value) {
    if (!riskExact(value, STATUS_HEAD_KEYS)
        || !riskIdentifier(value.schedule_id)
        || !digest(value.schedule_digest)
        || !riskIdentifier(value.tenant_id)
        || !riskIdentifier(value.status_authority_id)
        || !riskIdentifier(value.status_key_id)
        || !boundedInteger(value.sequence, 1, MAX_SEQUENCE)
        || !digest(value.status_digest)
        || !Number.isFinite(riskInstant(value.recorded_at))) {
        invalid('qualification_status_head_invalid', 'qualification status head must be a closed relying-party-owned record');
    }
    try {
        canonicalize(value);
    }
    catch {
        invalid('qualification_status_head_invalid', 'qualification status head is not canonicalizable JSON');
    }
}
function verificationTime(value) {
    if (value === undefined)
        return Date.now();
    if (value instanceof Date)
        return value.getTime();
    if (typeof value === 'number')
        return Number.isFinite(value) ? value : NaN;
    return riskInstant(value);
}
function sameCanonical(left, right) {
    try {
        return canonicalize(left) === canonicalize(right);
    }
    catch {
        return false;
    }
}
/** Canonical digest committed by a trust-pin reference for one hybrid key set. */
export function actionRiskHybridTrustPinDigest(keyId, pin) {
    if (!riskIdentifier(keyId)
        || !riskRecord(pin)
        || !riskIdentifier(pin.issuer_id)
        || typeof pin.public_key !== 'string' || pin.public_key.length === 0
        || typeof pin.pq_public_key !== 'string' || pin.pq_public_key.length === 0) {
        invalid('trust_pin_invalid', 'hybrid trust pin must bind issuer, key id, and both public keys');
    }
    return riskDigest({
        issuer_id: pin.issuer_id,
        key_id: keyId,
        public_key: pin.public_key,
        pq_public_key: pin.pq_public_key,
    });
}
/** Digest of the complete hybrid-signed schedule, including both signatures. */
export function actionRiskControlScheduleDigest(artifact) {
    validateBoundHybridProof(artifact);
    const { proof: _proof, ...body } = artifact;
    validateScheduleBody(body);
    return riskDigest(artifact);
}
/** Digest of the complete hybrid-signed qualification status. */
export function actionRiskQualificationStatusDigest(artifact) {
    validateBoundHybridProof(artifact);
    const { proof: _proof, ...body } = artifact;
    validateQualificationStatusBody(body);
    return riskDigest(artifact);
}
/** Mint the closed hybrid Ed25519 + ML-DSA-65 schedule. */
export async function signActionRiskControlSchedule(input, signer, options = {}) {
    validateScheduleSource(input);
    if (!riskRecord(signer)
        || !riskIdentifier(signer.issuer_id)
        || !riskIdentifier(signer.key_id)
        || !Object.hasOwn(signer, 'private_key')
        || !Object.hasOwn(signer, 'pq_private_key')) {
        invalid('signer_invalid', 'schedule signer must provide the hybrid issuer key pair');
    }
    const body = {
        '@version': ACTION_RISK_CONTROL_SCHEDULE_VERSION,
        ...input,
        issuer: { id: signer.issuer_id, key_id: signer.key_id },
    };
    validateScheduleBody(body);
    return signRiskBodyV2(ACTION_RISK_CONTROL_SCHEDULE_VERSION, body, signer, options);
}
/** Mint an independently signed qualification observation for one schedule. */
export async function signActionRiskQualificationStatus(input, signer, options = {}) {
    validateQualificationStatusSource(input);
    if (!riskRecord(signer)
        || !riskIdentifier(signer.issuer_id)
        || !riskIdentifier(signer.key_id)
        || !Object.hasOwn(signer, 'private_key')
        || !Object.hasOwn(signer, 'pq_private_key')) {
        invalid('status_signer_invalid', 'qualification status signer must provide the hybrid issuer key pair');
    }
    const body = {
        '@version': ACTION_RISK_QUALIFICATION_STATUS_VERSION,
        ...input,
        issuer: { id: signer.issuer_id, key_id: signer.key_id },
    };
    validateQualificationStatusBody(body);
    return signRiskBodyV2(ACTION_RISK_QUALIFICATION_STATUS_VERSION, body, signer, options);
}
/**
 * Verify and evaluate a schedule under caller-supplied trust roots and exact
 * runtime control observations. Only ELIGIBLE is a positive technical result.
 * Every result has authorizes_action=false: the caller's authorization check
 * remains a distinct step even when all scheduled controls are observed.
 */
export async function evaluateActionRiskControlSchedule(artifact, options = {}) {
    const result = (outcome, reason, fields = {}) => riskFreeze({
        '@version': ACTION_RISK_CONTROL_EVALUATION_VERSION,
        outcome,
        reason,
        schedule_verified: fields.scheduleVerified ?? false,
        qualification_status_verified: fields.statusVerified ?? false,
        schedule_digest: fields.scheduleDigest ?? null,
        qualification_status_digest: fields.statusDigest ?? null,
        schedule_id: fields.scheduleId ?? null,
        qualification_status_head_sequence: fields.statusHeadSequence ?? null,
        required_handling: fields.requiredHandling ?? null,
        authorizes_action: false,
        establishes_policy: false,
        establishes_coverage: false,
        sets_premium: false,
        allocates_liability: false,
        proves_provider_effect: false,
        claim_boundary: ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY,
    });
    try {
        validateBoundHybridProof(artifact);
    }
    catch (error) {
        return result('NOT_ELIGIBLE', error instanceof ActionRiskControlScheduleValidationError ? error.code : 'artifact_signature_envelope_invalid');
    }
    const signed = await verifyRiskBodyV2(artifact, ACTION_RISK_CONTROL_SCHEDULE_VERSION, options.trusted_schedule_keys, options);
    if (!signed.valid || !signed.body || !signed.artifact_digest) {
        return result(signed.reason === 'pq_backend_unavailable' ? 'INDETERMINATE' : 'NOT_ELIGIBLE', signed.reason ?? 'schedule_invalid');
    }
    try {
        validateScheduleBody(signed.body);
    }
    catch (error) {
        return result('NOT_ELIGIBLE', error instanceof ActionRiskControlScheduleValidationError ? error.code : 'schedule_schema_invalid', { scheduleVerified: true, scheduleDigest: signed.artifact_digest });
    }
    const body = signed.body;
    const base = {
        scheduleVerified: true,
        scheduleDigest: signed.artifact_digest,
        scheduleId: body.schedule_id,
    };
    const scheduleIssuerReference = findTrustReference(body, 'SCHEDULE_ISSUER');
    const schedulePin = options.trusted_schedule_keys?.[body.issuer.key_id];
    if (!schedulePin
        || scheduleIssuerReference.key_digest !== actionRiskHybridTrustPinDigest(body.issuer.key_id, schedulePin)) {
        return result('NOT_ELIGIBLE', 'schedule_trust_pin_reference_mismatch', base);
    }
    if (options.expected_schedule_id === undefined
        || options.expected_issuer_id === undefined
        || options.expected_relying_party_id === undefined
        || options.expected_tenant_id === undefined) {
        return result('NOT_ELIGIBLE', 'context_binding_required', base);
    }
    if (options.expected_schedule_id !== body.schedule_id) {
        return result('NOT_ELIGIBLE', 'schedule_id_mismatch', base);
    }
    if (options.expected_issuer_id !== body.issuer.id) {
        return result('NOT_ELIGIBLE', 'issuer_id_mismatch', base);
    }
    if (options.expected_relying_party_id !== body.relying_party_id) {
        return result('NOT_ELIGIBLE', 'relying_party_id_mismatch', base);
    }
    if (options.expected_tenant_id !== body.tenant_id) {
        return result('NOT_ELIGIBLE', 'tenant_id_mismatch', base);
    }
    const now = verificationTime(options.now);
    if (!Number.isFinite(now))
        return result('NOT_ELIGIBLE', 'verification_time_invalid', base);
    if (now < riskInstant(body.issued_at))
        return result('NOT_ELIGIBLE', 'schedule_not_yet_issued', base);
    if (now < riskInstant(body.valid_from))
        return result('NOT_ELIGIBLE', 'schedule_not_yet_valid', base);
    if (now >= riskInstant(body.expires_at))
        return result('NOT_ELIGIBLE', 'schedule_expired', base);
    if (options.observed_controls === undefined) {
        return result('NOT_ELIGIBLE', 'control_observation_required', base);
    }
    let observed;
    try {
        validateObservedControls(options.observed_controls);
        observed = options.observed_controls;
    }
    catch (error) {
        return result('NOT_ELIGIBLE', error instanceof ActionRiskControlScheduleValidationError ? error.code : 'control_observation_invalid', base);
    }
    const comparisons = [
        ['action_binding_mismatch', body.action, observed.action],
        ['provider_binding_mismatch', body.provider_binding, observed.provider_binding],
        ['qualification_requirements_mismatch', body.qualification.requirements_digest, observed.qualification_requirements_digest],
        ['control_bindings_mismatch', body.control_bindings, observed.control_bindings],
        ['complete_mediation_mismatch', body.complete_mediation, observed.complete_mediation],
        ['loss_allocation_mismatch', body.loss_allocation, observed.loss_allocation],
        ['open_exposure_mismatch', body.open_exposure, observed.open_exposure],
        ['outcome_binding_mismatch', body.outcome_binding, observed.outcome_binding],
        ['handling_mismatch', body.handling, observed.handling],
        ['trust_pin_references_mismatch', body.trust_pin_references, observed.trust_pin_references],
    ];
    for (const [reason, expected, actual] of comparisons) {
        if (!sameCanonical(expected, actual))
            return result('NOT_ELIGIBLE', reason, base);
    }
    const statusReference = findTrustReference(body, 'QUALIFICATION_STATUS');
    const statusPin = options.trusted_status_keys?.[body.qualification.status_key_id];
    if (!statusPin)
        return result('NOT_ELIGIBLE', 'qualification_status_trust_pin_required', base);
    if (statusPin.issuer_id !== body.qualification.status_authority_id
        || statusReference.key_digest
            !== actionRiskHybridTrustPinDigest(body.qualification.status_key_id, statusPin)) {
        return result('NOT_ELIGIBLE', 'qualification_status_trust_pin_reference_mismatch', base);
    }
    if (options.qualification_status === undefined) {
        return result('INDETERMINATE', 'qualification_status_required', {
            ...base,
            requiredHandling: body.handling.indeterminate,
        });
    }
    try {
        validateBoundHybridProof(options.qualification_status);
    }
    catch (error) {
        return result('NOT_ELIGIBLE', error instanceof ActionRiskControlScheduleValidationError ? error.code : 'artifact_signature_envelope_invalid', base);
    }
    const statusSigned = await verifyRiskBodyV2(options.qualification_status, ACTION_RISK_QUALIFICATION_STATUS_VERSION, options.trusted_status_keys, options);
    if (!statusSigned.valid || !statusSigned.body || !statusSigned.artifact_digest) {
        const unavailable = statusSigned.reason === 'pq_backend_unavailable';
        return result(unavailable ? 'INDETERMINATE' : 'NOT_ELIGIBLE', statusSigned.reason ?? 'qualification_status_invalid', {
            ...base,
            requiredHandling: unavailable ? body.handling.indeterminate : null,
        });
    }
    try {
        validateQualificationStatusBody(statusSigned.body);
    }
    catch (error) {
        return result('NOT_ELIGIBLE', error instanceof ActionRiskControlScheduleValidationError ? error.code : 'qualification_status_schema_invalid', { ...base, statusVerified: true, statusDigest: statusSigned.artifact_digest });
    }
    const status = statusSigned.body;
    const statusBase = {
        ...base,
        statusVerified: true,
        statusDigest: statusSigned.artifact_digest,
    };
    if (status.issuer.id !== body.qualification.status_authority_id
        || status.issuer.key_id !== body.qualification.status_key_id) {
        return result('NOT_ELIGIBLE', 'qualification_status_authority_mismatch', statusBase);
    }
    if (status.schedule_id !== body.schedule_id || status.schedule_digest !== signed.artifact_digest) {
        return result('NOT_ELIGIBLE', 'qualification_status_schedule_mismatch', statusBase);
    }
    if (status.tenant_id !== body.tenant_id) {
        return result('NOT_ELIGIBLE', 'qualification_status_tenant_mismatch', statusBase);
    }
    if (status.requirements_digest !== body.qualification.requirements_digest) {
        return result('NOT_ELIGIBLE', 'qualification_status_requirements_mismatch', statusBase);
    }
    if (options.qualification_status_head === undefined) {
        return result('INDETERMINATE', 'qualification_status_head_required', {
            ...statusBase,
            requiredHandling: body.handling.indeterminate,
        });
    }
    let statusHead;
    try {
        validateQualificationStatusHead(options.qualification_status_head);
        statusHead = options.qualification_status_head;
    }
    catch (error) {
        return result('NOT_ELIGIBLE', error instanceof ActionRiskControlScheduleValidationError ? error.code : 'qualification_status_head_invalid', statusBase);
    }
    const headBase = { ...statusBase, statusHeadSequence: statusHead.sequence };
    if (statusHead.schedule_id !== body.schedule_id
        || statusHead.schedule_digest !== signed.artifact_digest) {
        return result('NOT_ELIGIBLE', 'qualification_status_head_schedule_mismatch', headBase);
    }
    if (statusHead.tenant_id !== body.tenant_id) {
        return result('NOT_ELIGIBLE', 'qualification_status_head_tenant_mismatch', headBase);
    }
    if (statusHead.status_authority_id !== body.qualification.status_authority_id
        || statusHead.status_key_id !== body.qualification.status_key_id) {
        return result('NOT_ELIGIBLE', 'qualification_status_head_authority_mismatch', headBase);
    }
    const headRecordedAt = riskInstant(statusHead.recorded_at);
    if (headRecordedAt > now) {
        return result('NOT_ELIGIBLE', 'qualification_status_head_from_future', headBase);
    }
    if (status.sequence < body.qualification.min_sequence) {
        return result('INDETERMINATE', 'qualification_status_sequence_too_old', {
            ...headBase,
            requiredHandling: body.handling.indeterminate,
        });
    }
    if (status.sequence < statusHead.sequence) {
        return result('NOT_ELIGIBLE', 'qualification_status_rollback_detected', headBase);
    }
    if (status.sequence === statusHead.sequence
        && statusSigned.artifact_digest !== statusHead.status_digest) {
        return result('NOT_ELIGIBLE', 'qualification_status_head_digest_mismatch', headBase);
    }
    const observedAt = riskInstant(status.observed_at);
    if (observedAt > now) {
        return result('NOT_ELIGIBLE', 'qualification_status_from_future', headBase);
    }
    if (status.sequence === statusHead.sequence && headRecordedAt < observedAt) {
        return result('NOT_ELIGIBLE', 'qualification_status_head_recorded_before_observation', headBase);
    }
    if (now - observedAt > body.qualification.max_observation_age_sec * 1000) {
        return result('INDETERMINATE', 'qualification_status_stale', {
            ...headBase,
            requiredHandling: body.handling.indeterminate,
        });
    }
    if (status.outcome === 'NOT_ELIGIBLE') {
        return result('NOT_ELIGIBLE', 'qualification_status_not_eligible', headBase);
    }
    if (status.outcome === 'INDETERMINATE') {
        return result('INDETERMINATE', 'qualification_status_indeterminate', {
            ...headBase,
            requiredHandling: body.handling.indeterminate,
        });
    }
    return result('ELIGIBLE', 'technical_requirements_observed', headBase);
}
//# sourceMappingURL=action-risk-control-schedule.js.map