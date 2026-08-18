// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Relying-party-pinned recovery classification at the admission boundary.
 *
 * The signed artifact binds one exact action/provider/adapter tuple. Mutable
 * status and reservation evidence never comes from that presenter: the
 * evaluator obtains it from relying-party-injected callbacks immediately
 * before admission and treats every unavailable or malformed answer as a
 * refusal.
 */
import { RISK_CAID, RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskRecord, signRiskBody, signRiskBodyV2, verifyRiskBody, verifyRiskBodyV2, } from './reliance-risk-crypto.js';
export const RECOVERY_CAPABILITY_VERSION = 'EP-RECOVERY-CAPABILITY-v1';
export const RECOVERY_CAPABILITY_STATUS_VERSION = 'EP-RECOVERY-CAPABILITY-STATUS-v1';
export const RECOVERY_RESERVATION_STATUS_VERSION = 'EP-RECOVERY-RESERVATION-STATUS-v1';
export const RECOVERY_ADMISSION_BINDINGS_VERSION = 'EP-RECOVERY-ADMISSION-BINDINGS-v1';
export const RECOVERY_CAPABILITY_CLAIM_BOUNDARY = 'signed_policy_bound_recovery_classification_and_current_reserved_capacity_only_local_atomic_intra_transaction_only_compensation_requires_fresh_separate_admission_not_guaranteed_reversal_not_retry_authority_not_external_effect_truth_not_complete_mediation';
const INPUT_KEYS = [
    'capability_id', 'admission_id', 'admission_snapshot_digest', 'tenant_id',
    'audience', 'action_caid', 'action_digest', 'action_capability_expires_at',
    'provider_id', 'account_digest', 'environment_digest', 'operation_id',
    'issuer_digest', 'trust_epoch_digest', 'config_epoch_digest', 'adapter_id',
    'adapter_digest', 'resource_set_digest', 'issued_at', 'valid_from',
    'expires_at', 'mode', 'recovery',
];
const BODY_KEYS = [
    '@version', ...INPUT_KEYS, 'retry_permitted', 'claim_boundary', 'issuer',
];
const ISSUER_KEYS = ['id', 'key_id'];
const SIGNER_KEYS = ['issuer_id', 'key_id', 'private_key'];
const LOCAL_RECOVERY_KEYS = [
    'scope', 'state_domain_digest', 'adapter_id', 'adapter_digest', 'max_transaction_ms',
];
const RESERVED_RECOVERY_KEYS = [
    'scope', 'compensation_admission', 'remedy_caid', 'remedy_action_digest',
    'destination_digest', 'authority_digest', 'reservation_digest', 'units',
    'unit', 'available_until',
];
const CONTEXT_KEYS = ['trusted_keys', 'expected_policy', 'now'];
const EXPECTED_POLICY_KEYS = [
    'capability_id', 'admission_id', 'admission_snapshot_digest', 'mode',
    'recovery', 'tenant_id', 'audience', 'action_caid', 'action_digest',
    'action_capability_expires_at', 'provider_id', 'account_digest',
    'environment_digest', 'operation_id', 'issuer_id', 'issuer_digest',
    'trust_epoch_digest', 'config_epoch_digest', 'adapter_id', 'adapter_digest',
    'resource_set_digest',
];
const TRUSTED_KEY_KEYS = ['issuer_id', 'public_key'];
const CURRENT_STATUS_KEYS = [
    '@version', 'capability_id', 'capability_digest', 'tenant_id', 'audience',
    'action_caid', 'action_digest', 'provider_id', 'adapter_id', 'issuer_id',
    'status', 'observed_at', 'valid_from', 'valid_until',
];
const RESERVATION_STATUS_KEYS = [
    '@version', 'capability_id', 'capability_digest', 'tenant_id', 'audience',
    'action_caid', 'action_digest', 'provider_id', 'adapter_id',
    'reservation_digest', 'remedy_caid', 'remedy_action_digest',
    'destination_digest', 'authority_digest', 'units', 'unit', 'status',
    'observed_at', 'valid_from', 'available_until',
];
export class RecoveryCapabilityValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'RecoveryCapabilityValidationError';
        this.code = code;
    }
}
function invalid(code, message) {
    throw new RecoveryCapabilityValidationError(code, message);
}
function strictSnapshot(value, label) {
    try {
        return riskClone(value);
    }
    catch {
        invalid('non_json_value', `${label} is outside strict JSON data model`);
    }
}
function identifier(value, label) {
    if (!riskIdentifier(value))
        invalid('identifier_invalid', `${label} is invalid`);
    return value;
}
function digest(value, label) {
    if (typeof value !== 'string' || !RISK_DIGEST.test(value)) {
        invalid('digest_invalid', `${label} is invalid`);
    }
    return value;
}
function caid(value, label) {
    if (typeof value !== 'string' || !RISK_CAID.test(value)) {
        invalid('caid_invalid', `${label} is invalid`);
    }
    return value;
}
function canonicalInstant(value, label) {
    if (typeof value !== 'string')
        invalid('instant_invalid', `${label} is invalid`);
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
        invalid('instant_invalid', `${label} must be a canonical RFC 3339 instant`);
    }
    return value;
}
function positiveSafeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) > 0;
}
/**
 * Derive the privacy-preserving execution-context bindings carried by a
 * recovery capability from the exact ordinary admission snapshot. Issuers and
 * executors use this same derivation so a valid recovery signature cannot be
 * replayed onto a different provider account, environment, trust/configuration
 * epoch, adapter, or reserved resource set.
 */
export function deriveRecoveryAdmissionSnapshotBindings(snapshot) {
    const value = strictSnapshot(snapshot, 'admission snapshot body');
    if (!riskRecord(value)
        || !riskRecord(value.provider)
        || !riskIdentifier(value.provider.provider_id)
        || !riskIdentifier(value.provider.account_id)
        || !riskIdentifier(value.provider.environment)
        || typeof value.executor_adapter_digest !== 'string'
        || !RISK_DIGEST.test(value.executor_adapter_digest)
        || !Number.isSafeInteger(value.trust_epoch) || value.trust_epoch < 1
        || typeof value.trust_configuration_digest !== 'string'
        || !RISK_DIGEST.test(value.trust_configuration_digest)
        || !Number.isSafeInteger(value.configuration_epoch) || value.configuration_epoch < 1
        || typeof value.configuration_digest !== 'string'
        || !RISK_DIGEST.test(value.configuration_digest)
        || !Array.isArray(value.resource_reservations)) {
        invalid('admission_snapshot_binding_invalid', 'admission snapshot bindings are invalid');
    }
    const domain = RECOVERY_ADMISSION_BINDINGS_VERSION;
    return riskFreeze({
        provider_id: value.provider.provider_id,
        account_digest: riskDigest({
            '@version': domain,
            field: 'provider_account',
            provider_id: value.provider.provider_id,
            account_id: value.provider.account_id,
        }),
        environment_digest: riskDigest({
            '@version': domain,
            field: 'provider_environment',
            provider_id: value.provider.provider_id,
            environment: value.provider.environment,
        }),
        adapter_digest: value.executor_adapter_digest,
        trust_epoch_digest: riskDigest({
            '@version': domain,
            field: 'trust_epoch',
            trust_epoch: value.trust_epoch,
            trust_configuration_digest: value.trust_configuration_digest,
        }),
        config_epoch_digest: riskDigest({
            '@version': domain,
            field: 'configuration_epoch',
            configuration_epoch: value.configuration_epoch,
            configuration_digest: value.configuration_digest,
        }),
        resource_set_digest: riskDigest({
            '@version': domain,
            field: 'resource_reservations',
            resource_reservations: value.resource_reservations,
        }),
    });
}
function normalizeLocalRecovery(value, adapterId, adapterDigest) {
    if (!riskExact(value, LOCAL_RECOVERY_KEYS)) {
        invalid('local_recovery_invalid', 'local recovery shape is invalid');
    }
    const recovery = {
        scope: value.scope,
        state_domain_digest: digest(value.state_domain_digest, 'state_domain_digest'),
        adapter_id: identifier(value.adapter_id, 'recovery.adapter_id'),
        adapter_digest: digest(value.adapter_digest, 'adapter_digest'),
        max_transaction_ms: value.max_transaction_ms,
    };
    if (recovery.scope !== 'INTRA_TRANSACTION_ONLY') {
        invalid('local_recovery_invalid', 'local recovery must be intra-transaction only');
    }
    if (!positiveSafeInteger(recovery.max_transaction_ms)) {
        invalid('local_recovery_invalid', 'local recovery max transaction is invalid');
    }
    if (recovery.adapter_id !== adapterId || recovery.adapter_digest !== adapterDigest) {
        invalid('local_recovery_adapter_mismatch', 'local recovery adapter must match the provider adapter binding');
    }
    return recovery;
}
function normalizeReservedRecovery(value, actionCapabilityExpiresAt) {
    if (!riskExact(value, RESERVED_RECOVERY_KEYS)) {
        invalid('reserved_recovery_invalid', 'reserved recovery shape is invalid');
    }
    const recovery = {
        scope: value.scope,
        compensation_admission: value.compensation_admission,
        remedy_caid: caid(value.remedy_caid, 'remedy_caid'),
        remedy_action_digest: digest(value.remedy_action_digest, 'remedy_action_digest'),
        destination_digest: digest(value.destination_digest, 'destination_digest'),
        authority_digest: digest(value.authority_digest, 'authority_digest'),
        reservation_digest: digest(value.reservation_digest, 'reservation_digest'),
        units: value.units,
        unit: identifier(value.unit, 'reservation.unit'),
        available_until: canonicalInstant(value.available_until, 'available_until'),
    };
    if (recovery.scope !== 'RESERVED_CAPACITY_ONLY'
        || recovery.compensation_admission !== 'FRESH_SEPARATE_ACTION_REQUIRED') {
        invalid('reserved_recovery_invalid', 'reserved compensation is capacity only and requires fresh separate action admission');
    }
    if (!positiveSafeInteger(recovery.units)) {
        invalid('reserved_recovery_invalid', 'reservation units are invalid');
    }
    if (Date.parse(recovery.available_until) < Date.parse(actionCapabilityExpiresAt)) {
        invalid('reserved_recovery_coverage_invalid', 'reservation must cover the action capability expiry');
    }
    return recovery;
}
function normalizeInput(rawInput) {
    const input = strictSnapshot(rawInput, 'capability input');
    if (!riskExact(input, INPUT_KEYS)) {
        invalid('capability_input_invalid', 'capability input must be a closed JSON object');
    }
    if (!['LOCAL_ATOMIC', 'RESERVED_COMPENSATION', 'IRREVERSIBLE'].includes(input.mode)) {
        invalid('recovery_mode_invalid', 'recovery mode is invalid');
    }
    const capabilityId = identifier(input.capability_id, 'capability_id');
    const admissionId = identifier(input.admission_id, 'admission_id');
    const admissionSnapshotDigest = digest(input.admission_snapshot_digest, 'admission_snapshot_digest');
    const tenantId = identifier(input.tenant_id, 'tenant_id');
    const audience = identifier(input.audience, 'audience');
    const actionCaid = caid(input.action_caid, 'action_caid');
    const actionDigest = digest(input.action_digest, 'action_digest');
    const actionCapabilityExpiresAt = canonicalInstant(input.action_capability_expires_at, 'action_capability_expires_at');
    const providerId = identifier(input.provider_id, 'provider_id');
    const accountDigest = digest(input.account_digest, 'account_digest');
    const environmentDigest = digest(input.environment_digest, 'environment_digest');
    const operationId = identifier(input.operation_id, 'operation_id');
    const issuerDigest = digest(input.issuer_digest, 'issuer_digest');
    const trustEpochDigest = digest(input.trust_epoch_digest, 'trust_epoch_digest');
    const configEpochDigest = digest(input.config_epoch_digest, 'config_epoch_digest');
    const adapterId = identifier(input.adapter_id, 'adapter_id');
    const adapterDigest = digest(input.adapter_digest, 'adapter_digest');
    const resourceSetDigest = digest(input.resource_set_digest, 'resource_set_digest');
    const issuedAt = canonicalInstant(input.issued_at, 'issued_at');
    const validFrom = canonicalInstant(input.valid_from, 'valid_from');
    const expiresAt = canonicalInstant(input.expires_at, 'expires_at');
    if (Date.parse(issuedAt) > Date.parse(validFrom)
        || Date.parse(validFrom) >= Date.parse(actionCapabilityExpiresAt)
        || Date.parse(actionCapabilityExpiresAt) > Date.parse(expiresAt)) {
        invalid('capability_time_invalid', 'capability validity interval is invalid');
    }
    const common = {
        capability_id: capabilityId,
        admission_id: admissionId,
        admission_snapshot_digest: admissionSnapshotDigest,
        tenant_id: tenantId,
        audience,
        action_caid: actionCaid,
        action_digest: actionDigest,
        action_capability_expires_at: actionCapabilityExpiresAt,
        provider_id: providerId,
        account_digest: accountDigest,
        environment_digest: environmentDigest,
        operation_id: operationId,
        issuer_digest: issuerDigest,
        trust_epoch_digest: trustEpochDigest,
        config_epoch_digest: configEpochDigest,
        adapter_id: adapterId,
        adapter_digest: adapterDigest,
        resource_set_digest: resourceSetDigest,
        issued_at: issuedAt,
        valid_from: validFrom,
        expires_at: expiresAt,
    };
    if (input.mode === 'LOCAL_ATOMIC') {
        return {
            ...common,
            mode: 'LOCAL_ATOMIC',
            recovery: normalizeLocalRecovery(input.recovery, adapterId, adapterDigest),
        };
    }
    if (input.mode === 'RESERVED_COMPENSATION') {
        return {
            ...common,
            mode: 'RESERVED_COMPENSATION',
            recovery: normalizeReservedRecovery(input.recovery, actionCapabilityExpiresAt),
        };
    }
    if (input.recovery !== null) {
        invalid('irreversible_recovery_invalid', 'irreversible recovery must be null');
    }
    return { ...common, mode: 'IRREVERSIBLE', recovery: null };
}
function validateBody(value, version = RECOVERY_CAPABILITY_VERSION) {
    if (!riskExact(value, BODY_KEYS)
        || value['@version'] !== version
        || value.retry_permitted !== false
        || value.claim_boundary !== RECOVERY_CAPABILITY_CLAIM_BOUNDARY
        || !riskExact(value.issuer, ISSUER_KEYS)) {
        invalid('capability_schema_invalid', 'capability body is invalid');
    }
    const issuer = {
        id: identifier(value.issuer.id, 'issuer.id'),
        key_id: identifier(value.issuer.key_id, 'issuer.key_id'),
    };
    const input = normalizeInput(Object.fromEntries(INPUT_KEYS.map((key) => [key, value[key]])));
    const expected = {
        '@version': version,
        ...input,
        retry_permitted: false,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
        issuer,
    };
    if (riskDigest(expected) !== riskDigest(value)) {
        invalid('capability_schema_invalid', 'capability body is invalid');
    }
    const capability = riskFreeze(riskClone({
        '@version': version,
        ...input,
        retry_permitted: false,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    }));
    return { capability, issuer: riskFreeze(issuer) };
}
function normalizeExpectedPolicy(value) {
    if (!riskExact(value, EXPECTED_POLICY_KEYS)
        || !riskIdentifier(value.capability_id)
        || !riskIdentifier(value.admission_id)
        || typeof value.admission_snapshot_digest !== 'string'
        || !RISK_DIGEST.test(value.admission_snapshot_digest)
        || !['LOCAL_ATOMIC', 'RESERVED_COMPENSATION', 'IRREVERSIBLE'].includes(value.mode)
        || !riskIdentifier(value.tenant_id)
        || !riskIdentifier(value.audience)
        || typeof value.action_caid !== 'string' || !RISK_CAID.test(value.action_caid)
        || typeof value.action_digest !== 'string' || !RISK_DIGEST.test(value.action_digest)
        || !riskIdentifier(value.provider_id)
        || typeof value.account_digest !== 'string' || !RISK_DIGEST.test(value.account_digest)
        || typeof value.environment_digest !== 'string' || !RISK_DIGEST.test(value.environment_digest)
        || !riskIdentifier(value.operation_id)
        || !riskIdentifier(value.issuer_id)
        || typeof value.issuer_digest !== 'string' || !RISK_DIGEST.test(value.issuer_digest)
        || typeof value.trust_epoch_digest !== 'string' || !RISK_DIGEST.test(value.trust_epoch_digest)
        || typeof value.config_epoch_digest !== 'string' || !RISK_DIGEST.test(value.config_epoch_digest)
        || !riskIdentifier(value.adapter_id)
        || typeof value.adapter_digest !== 'string' || !RISK_DIGEST.test(value.adapter_digest)
        || typeof value.resource_set_digest !== 'string'
        || !RISK_DIGEST.test(value.resource_set_digest))
        return null;
    try {
        const actionCapabilityExpiresAt = canonicalInstant(value.action_capability_expires_at, 'expected action capability expiry');
        if (value.mode === 'LOCAL_ATOMIC') {
            return riskFreeze({
                ...value,
                mode: 'LOCAL_ATOMIC',
                recovery: normalizeLocalRecovery(value.recovery, value.adapter_id, value.adapter_digest),
            });
        }
        if (value.mode === 'RESERVED_COMPENSATION') {
            return riskFreeze({
                ...value,
                mode: 'RESERVED_COMPENSATION',
                recovery: normalizeReservedRecovery(value.recovery, actionCapabilityExpiresAt),
            });
        }
        if (value.recovery !== null)
            return null;
        return riskFreeze({
            ...value,
            mode: 'IRREVERSIBLE',
            recovery: null,
        });
    }
    catch {
        return null;
    }
}
function normalizeContext(rawContext) {
    let context;
    try {
        context = riskClone(rawContext);
    }
    catch {
        return null;
    }
    if (!riskExact(context, CONTEXT_KEYS)
        || !riskRecord(context.trusted_keys)
        || Object.keys(context.trusted_keys).length < 1
        || !Object.entries(context.trusted_keys).every(([keyId, pin]) => (riskIdentifier(keyId)
            && riskExact(pin, TRUSTED_KEY_KEYS)
            && riskIdentifier(pin.issuer_id)
            && typeof pin.public_key === 'string'
            && /^[A-Za-z0-9_-]+$/.test(pin.public_key))))
        return null;
    const expectedPolicy = normalizeExpectedPolicy(context.expected_policy);
    if (!expectedPolicy)
        return null;
    try {
        canonicalInstant(context.now, 'verification now');
    }
    catch {
        return null;
    }
    return riskFreeze({
        trusted_keys: context.trusted_keys,
        expected_policy: expectedPolicy,
        now: context.now,
    });
}
function verificationRefusal(reason, verified = false, capabilityDigest = null) {
    return riskFreeze({
        accepted: false,
        verified,
        reason,
        capability_digest: capabilityDigest,
        capability: null,
        issuer_id: null,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    });
}
/** Sign the closed v1 body with Ed25519 over reliance-risk-crypto JCS bytes. */
export function signRecoveryCapability(rawInput, rawSigner) {
    if (!riskExact(rawSigner, SIGNER_KEYS)
        || !riskIdentifier(rawSigner.issuer_id)
        || !riskIdentifier(rawSigner.key_id)) {
        invalid('signer_invalid', 'recovery capability signer is invalid');
    }
    const input = normalizeInput(rawInput);
    const body = {
        '@version': RECOVERY_CAPABILITY_VERSION,
        ...input,
        retry_permitted: false,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    };
    validateBody({
        ...body,
        issuer: { id: rawSigner.issuer_id, key_id: rawSigner.key_id },
    });
    try {
        return signRiskBody(RECOVERY_CAPABILITY_VERSION, body, rawSigner);
    }
    catch {
        invalid('signer_invalid', 'recovery capability signing key must be Ed25519');
    }
}
/** Digest of the complete signed artifact, including its Ed25519 proof. */
export function recoveryCapabilityDigest(artifact) {
    const snapshot = strictSnapshot(artifact, 'recovery capability artifact');
    if (!riskRecord(snapshot) || !riskRecord(snapshot.proof)) {
        invalid('capability_artifact_invalid', 'capability artifact is invalid');
    }
    return riskDigest(snapshot);
}
/** Verify signature, closed schema, complete expected tuple, and active time. */
export function verifyRecoveryCapability(artifact, rawContext) {
    const context = normalizeContext(rawContext);
    if (!context)
        return verificationRefusal('verification_context_required');
    let snapshot;
    try {
        snapshot = riskClone(artifact);
    }
    catch {
        return verificationRefusal('artifact_invalid');
    }
    const signed = verifyRiskBody(snapshot, RECOVERY_CAPABILITY_VERSION, context.trusted_keys);
    if (!signed.valid || !signed.body || !signed.artifact_digest) {
        return verificationRefusal(signed.reason === 'issuer_untrusted' ? 'issuer_untrusted' : 'signature_invalid');
    }
    let body;
    try {
        body = validateBody(signed.body);
    }
    catch {
        return verificationRefusal('capability_schema_invalid', true, signed.artifact_digest);
    }
    const capability = body.capability;
    const policy = context.expected_policy;
    const checks = [
        [capability.capability_id !== policy.capability_id, 'capability_id_mismatch'],
        [capability.admission_id !== policy.admission_id, 'admission_id_mismatch'],
        [capability.admission_snapshot_digest !== policy.admission_snapshot_digest,
            'admission_snapshot_digest_mismatch'],
        [capability.mode !== policy.mode, 'mode_mismatch'],
        [capability.tenant_id !== policy.tenant_id, 'tenant_mismatch'],
        [capability.audience !== policy.audience, 'audience_mismatch'],
        [capability.action_caid !== policy.action_caid, 'action_caid_mismatch'],
        [capability.action_digest !== policy.action_digest, 'action_digest_mismatch'],
        [capability.action_capability_expires_at !== policy.action_capability_expires_at,
            'action_capability_expiry_mismatch'],
        [capability.provider_id !== policy.provider_id, 'provider_mismatch'],
        [capability.account_digest !== policy.account_digest, 'account_mismatch'],
        [capability.environment_digest !== policy.environment_digest, 'environment_mismatch'],
        [capability.operation_id !== policy.operation_id, 'operation_mismatch'],
        [body.issuer.id !== policy.issuer_id, 'issuer_mismatch'],
        [capability.issuer_digest !== policy.issuer_digest, 'issuer_digest_mismatch'],
        [capability.trust_epoch_digest !== policy.trust_epoch_digest, 'trust_epoch_mismatch'],
        [capability.config_epoch_digest !== policy.config_epoch_digest, 'config_epoch_mismatch'],
        [capability.adapter_id !== policy.adapter_id, 'adapter_mismatch'],
        [capability.adapter_digest !== policy.adapter_digest, 'adapter_digest_mismatch'],
        [capability.resource_set_digest !== policy.resource_set_digest, 'resource_set_mismatch'],
        [riskDigest(capability.recovery) !== riskDigest(policy.recovery), 'recovery_mismatch'],
    ];
    for (const [mismatched, reason] of checks) {
        if (mismatched)
            return verificationRefusal(reason, true, signed.artifact_digest);
    }
    const now = Date.parse(context.now);
    if (now < Date.parse(capability.valid_from)) {
        return verificationRefusal('capability_not_yet_valid', true, signed.artifact_digest);
    }
    if (now >= Date.parse(capability.expires_at)) {
        return verificationRefusal('capability_expired', true, signed.artifact_digest);
    }
    if (now >= Date.parse(capability.action_capability_expires_at)) {
        return verificationRefusal('action_capability_expired', true, signed.artifact_digest);
    }
    return riskFreeze({
        accepted: true,
        verified: true,
        reason: null,
        capability_digest: signed.artifact_digest,
        capability,
        issuer_id: body.issuer.id,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    });
}
function normalizeCurrentStatus(value) {
    let status;
    try {
        status = riskClone(value);
    }
    catch {
        return null;
    }
    if (!riskExact(status, CURRENT_STATUS_KEYS)
        || status['@version'] !== RECOVERY_CAPABILITY_STATUS_VERSION
        || !riskIdentifier(status.capability_id)
        || typeof status.capability_digest !== 'string' || !RISK_DIGEST.test(status.capability_digest)
        || !riskIdentifier(status.tenant_id)
        || !riskIdentifier(status.audience)
        || typeof status.action_caid !== 'string' || !RISK_CAID.test(status.action_caid)
        || typeof status.action_digest !== 'string' || !RISK_DIGEST.test(status.action_digest)
        || !riskIdentifier(status.provider_id)
        || !riskIdentifier(status.adapter_id)
        || !riskIdentifier(status.issuer_id)
        || !['CURRENT', 'REVOKED'].includes(status.status))
        return null;
    try {
        canonicalInstant(status.observed_at, 'status.observed_at');
        canonicalInstant(status.valid_from, 'status.valid_from');
        canonicalInstant(status.valid_until, 'status.valid_until');
    }
    catch {
        return null;
    }
    return riskFreeze(status);
}
function normalizeReservationStatus(value) {
    let reservation;
    try {
        reservation = riskClone(value);
    }
    catch {
        return null;
    }
    if (!riskExact(reservation, RESERVATION_STATUS_KEYS)
        || reservation['@version'] !== RECOVERY_RESERVATION_STATUS_VERSION
        || !riskIdentifier(reservation.capability_id)
        || typeof reservation.capability_digest !== 'string'
        || !RISK_DIGEST.test(reservation.capability_digest)
        || !riskIdentifier(reservation.tenant_id)
        || !riskIdentifier(reservation.audience)
        || typeof reservation.action_caid !== 'string'
        || !RISK_CAID.test(reservation.action_caid)
        || typeof reservation.action_digest !== 'string'
        || !RISK_DIGEST.test(reservation.action_digest)
        || !riskIdentifier(reservation.provider_id)
        || !riskIdentifier(reservation.adapter_id)
        || typeof reservation.reservation_digest !== 'string'
        || !RISK_DIGEST.test(reservation.reservation_digest)
        || typeof reservation.remedy_caid !== 'string'
        || !RISK_CAID.test(reservation.remedy_caid)
        || typeof reservation.remedy_action_digest !== 'string'
        || !RISK_DIGEST.test(reservation.remedy_action_digest)
        || typeof reservation.destination_digest !== 'string'
        || !RISK_DIGEST.test(reservation.destination_digest)
        || typeof reservation.authority_digest !== 'string'
        || !RISK_DIGEST.test(reservation.authority_digest)
        || !positiveSafeInteger(reservation.units)
        || !riskIdentifier(reservation.unit)
        || !['RESERVED', 'RELEASED', 'REVOKED', 'CONSUMED'].includes(reservation.status))
        return null;
    try {
        canonicalInstant(reservation.observed_at, 'reservation.observed_at');
        canonicalInstant(reservation.valid_from, 'reservation.valid_from');
        canonicalInstant(reservation.available_until, 'reservation.available_until');
    }
    catch {
        return null;
    }
    return riskFreeze(reservation);
}
function decision(route, reason, verification, status = null, reservation = null) {
    const scope = route === 'LOCAL_ATOMIC' ? 'INTRA_TRANSACTION_ONLY'
        : route === 'RESERVED_COMPENSATION' ? 'RESERVED_CAPACITY_ONLY'
            : route === 'AUTHORITY_REQUIRED' ? 'FRESH_AUTHORITY_REQUIRED' : 'NONE';
    return riskFreeze({
        recovery_route_accepted: route === 'LOCAL_ATOMIC' || route === 'RESERVED_COMPENSATION',
        route,
        reason,
        scope,
        retry_permitted: false,
        fresh_action_admission_required: route === 'RESERVED_COMPENSATION' || route === 'AUTHORITY_REQUIRED',
        capability_digest: verification.capability_digest,
        capability: verification.capability,
        status,
        reservation,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    });
}
function currentStatusReason(status, input) {
    const capability = input.capability;
    if (status.capability_id !== capability.capability_id
        || status.capability_digest !== input.capability_digest
        || status.tenant_id !== capability.tenant_id
        || status.audience !== capability.audience
        || status.action_caid !== capability.action_caid
        || status.action_digest !== capability.action_digest
        || status.provider_id !== capability.provider_id
        || status.adapter_id !== capability.adapter_id
        || status.issuer_id !== input.issuer_id)
        return 'current_status_binding_mismatch';
    if (status.status === 'REVOKED')
        return 'current_status_revoked';
    const admission = Date.parse(input.admission_at);
    const observed = Date.parse(status.observed_at);
    const validFrom = Date.parse(status.valid_from);
    const validUntil = Date.parse(status.valid_until);
    const actionExpiry = Date.parse(input.action_capability_expires_at);
    if (validFrom > admission)
        return 'current_status_not_yet_valid';
    if (observed > admission || observed < validFrom)
        return 'current_status_invalid';
    if (validUntil <= admission || observed >= validUntil)
        return 'current_status_stale';
    if (validUntil < actionExpiry)
        return 'current_status_insufficient_coverage';
    return null;
}
function reservationReason(reservation, input) {
    const capability = input.capability;
    if (capability.mode !== 'RESERVED_COMPENSATION')
        return 'reservation_invalid';
    const recovery = capability.recovery;
    if (reservation.capability_id !== capability.capability_id
        || reservation.capability_digest !== input.capability_digest
        || reservation.tenant_id !== capability.tenant_id
        || reservation.audience !== capability.audience
        || reservation.action_caid !== capability.action_caid
        || reservation.action_digest !== capability.action_digest
        || reservation.provider_id !== capability.provider_id
        || reservation.adapter_id !== capability.adapter_id
        || reservation.reservation_digest !== recovery.reservation_digest
        || reservation.remedy_caid !== recovery.remedy_caid
        || reservation.remedy_action_digest !== recovery.remedy_action_digest
        || reservation.destination_digest !== recovery.destination_digest
        || reservation.authority_digest !== recovery.authority_digest
        || reservation.units !== recovery.units
        || reservation.unit !== recovery.unit)
        return 'reservation_binding_mismatch';
    if (reservation.status !== 'RESERVED')
        return 'reservation_not_current';
    const admission = Date.parse(input.admission_at);
    const observed = Date.parse(reservation.observed_at);
    const validFrom = Date.parse(reservation.valid_from);
    const availableUntil = Date.parse(reservation.available_until);
    const actionExpiry = Date.parse(input.action_capability_expires_at);
    if (validFrom > admission)
        return 'reservation_not_yet_valid';
    if (observed > admission || observed < validFrom)
        return 'reservation_invalid';
    if (availableUntil <= admission || observed >= availableUntil)
        return 'reservation_expired';
    if (availableUntil < actionExpiry)
        return 'reservation_insufficient_coverage';
    if (reservation.available_until !== recovery.available_until) {
        return 'reservation_binding_mismatch';
    }
    return null;
}
function dependencyReason(dependencies, mode) {
    if (!riskRecord(dependencies)
        || !Object.hasOwn(dependencies, 'current_status_resolver')
        || typeof dependencies.current_status_resolver !== 'function') {
        return 'current_status_resolver_required';
    }
    const keys = Reflect.ownKeys(dependencies);
    if (mode === 'RESERVED_COMPENSATION') {
        if (!Object.hasOwn(dependencies, 'reservation_verifier')
            || typeof dependencies.reservation_verifier !== 'function') {
            return 'reservation_verifier_required';
        }
        if (keys.length !== 2
            || !keys.includes('current_status_resolver')
            || !keys.includes('reservation_verifier'))
            return 'evaluator_configuration_invalid';
    }
    else if (keys.length !== 1 || !keys.includes('current_status_resolver')) {
        return 'evaluator_configuration_invalid';
    }
    return null;
}
/**
 * Resolve current status from relying-party code and return the only four v1
 * routes. Presenter-supplied mutable state is outside this API by design.
 */
export async function evaluateRecoveryAdmission(artifact, rawContext, dependencies) {
    const context = normalizeContext(rawContext);
    if (!context) {
        return decision('REFUSED', 'verification_context_required', verificationRefusal('verification_context_required'));
    }
    const verification = verifyRecoveryCapability(artifact, context);
    if (!verification.accepted || !verification.capability
        || !verification.capability_digest || !verification.issuer_id) {
        return decision('REFUSED', verification.reason, verification);
    }
    const configurationFailure = dependencyReason(dependencies, verification.capability.mode);
    if (configurationFailure)
        return decision('REFUSED', configurationFailure, verification);
    const callbackInput = riskFreeze({
        capability: verification.capability,
        capability_digest: verification.capability_digest,
        issuer_id: verification.issuer_id,
        admission_at: context.now,
        action_capability_expires_at: verification.capability.action_capability_expires_at,
    });
    let rawStatus;
    try {
        rawStatus = await dependencies.current_status_resolver(callbackInput);
    }
    catch {
        return decision('REFUSED', 'current_status_resolver_exception', verification);
    }
    const status = normalizeCurrentStatus(rawStatus);
    if (!status)
        return decision('REFUSED', 'current_status_invalid', verification);
    const statusFailure = currentStatusReason(status, callbackInput);
    if (statusFailure)
        return decision('REFUSED', statusFailure, verification, status);
    if (verification.capability.mode === 'IRREVERSIBLE') {
        return decision('AUTHORITY_REQUIRED', 'irreversible_authority_required', verification, status);
    }
    if (verification.capability.mode === 'LOCAL_ATOMIC') {
        return decision('LOCAL_ATOMIC', null, verification, status);
    }
    let rawReservation;
    try {
        rawReservation = await dependencies.reservation_verifier(callbackInput);
    }
    catch {
        return decision('REFUSED', 'reservation_verifier_exception', verification, status);
    }
    const reservation = normalizeReservationStatus(rawReservation);
    if (!reservation)
        return decision('REFUSED', 'reservation_invalid', verification, status);
    const reservationFailure = reservationReason(reservation, callbackInput);
    if (reservationFailure) {
        return decision('REFUSED', reservationFailure, verification, status, reservation);
    }
    return decision('RESERVED_COMPENSATION', null, verification, status, reservation);
}
// ===========================================================================
// EP-RECOVERY-CAPABILITY-v2 -- opt-in hybrid adoption of EP-RISK-HYBRID-v2
// ===========================================================================
// ADDITIVE: signRecoveryCapability / verifyRecoveryCapability above are
// UNCHANGED. This is the ADOPTION application of "PATTERN: the reference
// hybrid migration" (EP-REVOCATION-v2 is the template) in
// docs/protocol/pq-hybrid-program.md: this module already delegates signing
// to reliance-risk-crypto.js's shared signRiskBody/verifyRiskBody, so it
// adopts signRiskBodyV2/verifyRiskBodyV2 (EP-RISK-HYBRID-v2) rather than
// reimplementing the set-shaped proof, the anti-stripping bytes, or the pin
// discipline here. RECOVERY_CAPABILITY_STATUS and RECOVERY_RESERVATION_STATUS
// are relying-party-injected callback answers, not presenter-signed
// artifacts, so they carry no signature to migrate. A deployed v1 verifier
// handed a v2 capability refuses on its version/schema check BEFORE
// inspecting any signature; v2 verification is a SEPARATE async entry point.
export const RECOVERY_CAPABILITY_V2_VERSION = 'EP-RECOVERY-CAPABILITY-v2';
const TRUSTED_KEY_KEYS_V2 = ['issuer_id', 'public_key', 'pq_public_key'];
/** v2 twin of normalizeContext: trusted_keys entries pin BOTH key halves. */
function normalizeContextV2(rawContext) {
    let context;
    try {
        context = riskClone(rawContext);
    }
    catch {
        return null;
    }
    if (!riskExact(context, CONTEXT_KEYS)
        || !riskRecord(context.trusted_keys)
        || Object.keys(context.trusted_keys).length < 1
        || !Object.entries(context.trusted_keys).every(([keyId, pin]) => (riskIdentifier(keyId)
            && riskExact(pin, TRUSTED_KEY_KEYS_V2)
            && riskIdentifier(pin.issuer_id)
            && typeof pin.public_key === 'string'
            && /^[A-Za-z0-9_-]+$/.test(pin.public_key)
            && typeof pin.pq_public_key === 'string'
            && /^[A-Za-z0-9_-]+$/.test(pin.pq_public_key))))
        return null;
    const expectedPolicy = normalizeExpectedPolicy(context.expected_policy);
    if (!expectedPolicy)
        return null;
    try {
        canonicalInstant(context.now, 'verification now');
    }
    catch {
        return null;
    }
    return riskFreeze({
        trusted_keys: context.trusted_keys,
        expected_policy: expectedPolicy,
        now: context.now,
    });
}
function verificationRefusalV2(reason, verified = false, capabilityDigest = null) {
    return riskFreeze({
        accepted: false,
        verified,
        reason,
        capability_digest: capabilityDigest,
        capability: null,
        issuer_id: null,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    });
}
/** Mint the hybrid (Ed25519 + ML-DSA-65), set-committed twin of signRecoveryCapability. */
export async function signRecoveryCapabilityV2(rawInput, rawSigner, options = {}) {
    if (!riskIdentifier(rawSigner?.issuer_id) || !riskIdentifier(rawSigner?.key_id)) {
        invalid('signer_invalid', 'recovery capability hybrid signer is invalid');
    }
    const input = normalizeInput(rawInput);
    const body = {
        '@version': RECOVERY_CAPABILITY_V2_VERSION,
        ...input,
        retry_permitted: false,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    };
    validateBody({
        ...body,
        issuer: { id: rawSigner.issuer_id, key_id: rawSigner.key_id },
    }, RECOVERY_CAPABILITY_V2_VERSION);
    try {
        return await signRiskBodyV2(RECOVERY_CAPABILITY_V2_VERSION, body, rawSigner, options);
    }
    catch {
        invalid('signer_invalid', 'recovery capability hybrid signing keys must be Ed25519 + ML-DSA-65');
    }
}
/**
 * FAIL-CLOSED hybrid verify, the set-committed twin of verifyRecoveryCapability.
 * A v2 capability NEVER verifies on one leg alone; an absent ML-DSA backend is
 * a refusal, never a skipped check and never a pass on the surviving
 * classical leg.
 */
export async function verifyRecoveryCapabilityV2(artifact, rawContext) {
    const context = normalizeContextV2(rawContext);
    if (!context)
        return verificationRefusalV2('verification_context_required');
    let snapshot;
    try {
        snapshot = riskClone(artifact);
    }
    catch {
        return verificationRefusalV2('artifact_invalid');
    }
    const signed = await verifyRiskBodyV2(snapshot, RECOVERY_CAPABILITY_V2_VERSION, context.trusted_keys, context);
    if (!signed.valid || !signed.body || !signed.artifact_digest) {
        return verificationRefusalV2(signed.reason === 'issuer_untrusted' ? 'issuer_untrusted' : 'signature_invalid');
    }
    let body;
    try {
        body = validateBody(signed.body, RECOVERY_CAPABILITY_V2_VERSION);
    }
    catch {
        return verificationRefusalV2('capability_schema_invalid', true, signed.artifact_digest);
    }
    const capability = body.capability;
    const policy = context.expected_policy;
    const checks = [
        [capability.capability_id !== policy.capability_id, 'capability_id_mismatch'],
        [capability.admission_id !== policy.admission_id, 'admission_id_mismatch'],
        [capability.admission_snapshot_digest !== policy.admission_snapshot_digest,
            'admission_snapshot_digest_mismatch'],
        [capability.mode !== policy.mode, 'mode_mismatch'],
        [capability.tenant_id !== policy.tenant_id, 'tenant_mismatch'],
        [capability.audience !== policy.audience, 'audience_mismatch'],
        [capability.action_caid !== policy.action_caid, 'action_caid_mismatch'],
        [capability.action_digest !== policy.action_digest, 'action_digest_mismatch'],
        [capability.action_capability_expires_at !== policy.action_capability_expires_at,
            'action_capability_expiry_mismatch'],
        [capability.provider_id !== policy.provider_id, 'provider_mismatch'],
        [capability.account_digest !== policy.account_digest, 'account_mismatch'],
        [capability.environment_digest !== policy.environment_digest, 'environment_mismatch'],
        [capability.operation_id !== policy.operation_id, 'operation_mismatch'],
        [body.issuer.id !== policy.issuer_id, 'issuer_mismatch'],
        [capability.issuer_digest !== policy.issuer_digest, 'issuer_digest_mismatch'],
        [capability.trust_epoch_digest !== policy.trust_epoch_digest, 'trust_epoch_mismatch'],
        [capability.config_epoch_digest !== policy.config_epoch_digest, 'config_epoch_mismatch'],
        [capability.adapter_id !== policy.adapter_id, 'adapter_mismatch'],
        [capability.adapter_digest !== policy.adapter_digest, 'adapter_digest_mismatch'],
        [capability.resource_set_digest !== policy.resource_set_digest, 'resource_set_mismatch'],
        [riskDigest(capability.recovery) !== riskDigest(policy.recovery), 'recovery_mismatch'],
    ];
    for (const [mismatched, reason] of checks) {
        if (mismatched)
            return verificationRefusalV2(reason, true, signed.artifact_digest);
    }
    const now = Date.parse(context.now);
    if (now < Date.parse(capability.valid_from)) {
        return verificationRefusalV2('capability_not_yet_valid', true, signed.artifact_digest);
    }
    if (now >= Date.parse(capability.expires_at)) {
        return verificationRefusalV2('capability_expired', true, signed.artifact_digest);
    }
    if (now >= Date.parse(capability.action_capability_expires_at)) {
        return verificationRefusalV2('action_capability_expired', true, signed.artifact_digest);
    }
    return riskFreeze({
        accepted: true,
        verified: true,
        reason: null,
        capability_digest: signed.artifact_digest,
        capability,
        issuer_id: body.issuer.id,
        claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    });
}
export default {
    RECOVERY_CAPABILITY_VERSION,
    RECOVERY_CAPABILITY_STATUS_VERSION,
    RECOVERY_RESERVATION_STATUS_VERSION,
    RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    signRecoveryCapability,
    recoveryCapabilityDigest,
    verifyRecoveryCapability,
    evaluateRecoveryAdmission,
    RECOVERY_CAPABILITY_V2_VERSION,
    signRecoveryCapabilityV2,
    verifyRecoveryCapabilityV2,
};
//# sourceMappingURL=recovery-admission.js.map