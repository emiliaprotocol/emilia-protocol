// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Server-pinned EP-STATUS-v1 verification for Proposal-to-Effect AEB legs.
 *
 * Signed non-revocation status and relying-party consumption state answer
 * different questions. This helper authenticates the former with
 * verifyStatusArtifact and requires an authenticated local answer for the
 * latter. The later atomic AEB reserve remains the race-closing operation.
 */
import { verifyStatusArtifact, } from '@emilia-protocol/verify/status';
export { PROPOSAL_TO_EFFECT_STATUS_HEAD_STORE_VERSION, PROPOSAL_TO_EFFECT_STATUS_HEAD_TABLE, PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL, createPostgresProposalToEffectStatusHeadStore, } from './proposal-to-effect-status-head-store.js';
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CAID_PATTERN = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const EXPECTED_KEYS = [
    'tenant_id',
    'executor_id',
    'operation_id',
    'caid',
    'artifact_ref',
    'evidence_digest',
    'replay_unit',
];
const TARGET_KEYS = ['type', 'id', 'digest', 'usage'];
const AUTHORITY_PIN_KEYS = [
    'authority_domain',
    'authority_id',
    'key_id',
    'public_key',
];
function dataRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
        return false;
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return Boolean(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'));
    });
}
function exactDataRecord(value, keys) {
    if (!dataRecord(value))
        return false;
    const actual = Reflect.ownKeys(value);
    return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function boundedString(value, maximum = 512) {
    return typeof value === 'string' && value.length > 0 && value.length <= maximum;
}
function digest(value) {
    return typeof value === 'string' && DIGEST_PATTERN.test(value);
}
function snapshotAuthorityPin(value) {
    if (!exactDataRecord(value, AUTHORITY_PIN_KEYS)
        || !boundedString(value.authority_domain, 253)
        || !boundedString(value.authority_id)
        || !boundedString(value.key_id)
        || !boundedString(value.public_key, 4096))
        return null;
    return Object.freeze({
        authority_domain: value.authority_domain,
        authority_id: value.authority_id,
        key_id: value.key_id,
        public_key: value.public_key,
    });
}
function snapshotExpected(value) {
    if (!exactDataRecord(value, EXPECTED_KEYS)
        || !boundedString(value.tenant_id)
        || !boundedString(value.executor_id)
        || !boundedString(value.operation_id)
        || typeof value.caid !== 'string'
        || !CAID_PATTERN.test(value.caid)
        || !boundedString(value.artifact_ref)
        || !digest(value.evidence_digest)
        || !digest(value.replay_unit))
        return null;
    return Object.freeze({
        tenant_id: value.tenant_id,
        executor_id: value.executor_id,
        operation_id: value.operation_id,
        caid: value.caid,
        artifact_ref: value.artifact_ref,
        evidence_digest: value.evidence_digest,
        replay_unit: value.replay_unit,
    });
}
function snapshotTarget(value) {
    if (!exactDataRecord(value, TARGET_KEYS)
        || !['receipt', 'commit', 'delegation'].includes(value.type)
        || !boundedString(value.id)
        || !digest(value.digest)
        || !['authorization', 'execution', 'delegation'].includes(value.usage)) {
        return null;
    }
    return Object.freeze({
        type: value.type,
        id: value.id,
        digest: value.digest,
        usage: value.usage,
    });
}
function denseDataArray(value) {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
        return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length'))
        return false;
    for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value'))
            return false;
    }
    return true;
}
function snapshotJson(value, seen = new WeakSet()) {
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return value;
    if (typeof value === 'number') {
        if (Number.isFinite(value))
            return value;
        throw new TypeError('non-finite JSON number');
    }
    if (typeof value !== 'object' || seen.has(value)) {
        throw new TypeError('value is outside the JSON data model');
    }
    seen.add(value);
    if (denseDataArray(value)) {
        return value.map((member) => snapshotJson(member, seen));
    }
    if (!dataRecord(value))
        throw new TypeError('value is not a plain data object');
    const snapshot = {};
    for (const key of Object.keys(value)) {
        snapshot[key] = snapshotJson(value[key], seen);
    }
    return snapshot;
}
function normalizedInstant(value) {
    if (typeof value !== 'string')
        return null;
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds))
        return null;
    return new Date(milliseconds).toISOString();
}
function refusal(outcome, reason) {
    return {
        valid: false,
        outcome,
        status: null,
        reason,
    };
}
function verifierConfiguration(options) {
    const authorityPin = snapshotAuthorityPin(options?.authorityPin);
    if (!authorityPin
        || typeof options.targetMapper !== 'function'
        || typeof options.certificateResolver !== 'function'
        || !dataRecord(options.statusHeadStore)
        || options.statusHeadStore.durable !== true
        || !boundedString(options.statusHeadStore.tenantId)
        || !boundedString(options.statusHeadStore.relyingPartyId)
        || typeof options.statusHeadStore.accept !== 'function'
        || typeof options.consumptionStateResolver !== 'function') {
        throw new TypeError('proposal_to_effect_status_configuration_invalid');
    }
    return authorityPin;
}
/**
 * Build the server-side verifier expected by
 * `ProposalToEffectOptions.aeb.statusVerifier`.
 */
export function createProposalToEffectStatusVerifier(options) {
    const authorityPin = verifierConfiguration(options);
    const targetMapper = options.targetMapper;
    const certificateResolver = options.certificateResolver;
    const statusHeadStore = options.statusHeadStore;
    const consumptionStateResolver = options.consumptionStateResolver;
    return async (input) => {
        const expected = snapshotExpected(input?.expected);
        const checkedAt = normalizedInstant(input?.now);
        if (!expected || !checkedAt) {
            return refusal('indeterminate', 'status_expected_binding_invalid');
        }
        let statusArtifact;
        let target;
        try {
            statusArtifact = snapshotJson(input.status_artifact);
            const mapped = await targetMapper({ expected });
            const snapshot = snapshotTarget(mapped);
            if (!snapshot)
                return refusal('indeterminate', 'status_target_resolution_failed');
            target = snapshot;
        }
        catch {
            return refusal('indeterminate', 'status_target_resolution_failed');
        }
        const context = Object.freeze({ expected, target });
        let certificate;
        try {
            const resolvedCertificate = await certificateResolver(context);
            if (resolvedCertificate === undefined || resolvedCertificate === null) {
                return refusal('indeterminate', 'status_certificate_unavailable');
            }
            certificate = snapshotJson(resolvedCertificate);
        }
        catch {
            return refusal('indeterminate', 'status_certificate_unavailable');
        }
        if (statusHeadStore.tenantId !== expected.tenant_id) {
            return refusal('indeterminate', 'status_head_scope_mismatch');
        }
        let acceptance;
        try {
            acceptance = await statusHeadStore.accept({
                target,
                status: statusArtifact,
                verify: (previousStatus) => verifyStatusArtifact(target, statusArtifact, {
                    authorityPin,
                    certificate,
                    previousStatus,
                    now: input.now,
                }),
            });
        }
        catch {
            return refusal('indeterminate', 'status_head_store_unavailable');
        }
        if (!dataRecord(acceptance)
            || typeof acceptance.accepted !== 'boolean'
            || !Object.hasOwn(acceptance, 'verification')
            || !dataRecord(acceptance.verification)) {
            return refusal('indeterminate', 'status_head_store_invalid');
        }
        if (!acceptance.accepted) {
            return refusal('indeterminate', boundedString(acceptance.reason)
                ? acceptance.reason : 'status_head_store_refused');
        }
        const verification = acceptance.verification;
        if (!verification.valid || verification.outcome === 'indeterminate') {
            return refusal('indeterminate', verification.reasons[0] ?? 'status_verification_failed');
        }
        if (verification.outcome === 'revoked') {
            return refusal('revoked', 'status_revoked');
        }
        if (!digest(verification.status_digest)
            || !Number.isSafeInteger(verification.sequence)
            || verification.sequence === null) {
            return refusal('indeterminate', 'status_verification_incomplete');
        }
        let consumption;
        try {
            consumption = await consumptionStateResolver(Object.freeze({
                ...context,
                status_digest: verification.status_digest,
                sequence: verification.sequence,
            }));
        }
        catch {
            return refusal('indeterminate', 'status_consumption_state_unavailable');
        }
        if (!dataRecord(consumption)
            || consumption.authenticated !== true
            || typeof consumption.consumed !== 'boolean') {
            return refusal('indeterminate', 'status_consumption_state_unknown');
        }
        if (consumption.consumed) {
            return refusal('indeterminate', 'status_consumed');
        }
        const expiresAt = normalizedInstant(verification.next_update);
        if (!expiresAt || Date.parse(checkedAt) >= Date.parse(expiresAt)) {
            return refusal('indeterminate', 'status_expiry_invalid');
        }
        // This local answer is an authenticated pre-reservation observation. It
        // does not claim race freedom; Proposal-to-Effect's atomic AEB reserve does.
        const status = {
            checked_at: checkedAt,
            expires_at: expiresAt,
            revocation_checked: true,
            revoked: false,
            consumed: false,
        };
        return {
            valid: true,
            outcome: 'current_not_revoked',
            status,
        };
    };
}
//# sourceMappingURL=proposal-to-effect-status.js.map