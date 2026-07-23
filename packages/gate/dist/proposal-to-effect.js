// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Proposal-to-Effect is a product orchestration profile over existing EMILIA
 * artifacts. A proposal is deliberately NOT a bearer authorization object.
 * Authority remains in EP-RECEIPT-v1 and the relying party's pinned AEB
 * requirement; consequence custody remains in Gate and its durable stores.
 */
import crypto from 'node:crypto';
import { beginReceiptApproval, pollReceiptApproval, approvalActionHash, validateApprovalAuthorization, validateCaidSelector, validateRequiredFields, } from '@emilia-protocol/require-receipt/acquisition';
import { aebReservationKey, authorizeAebExecutionDurable, digestAeb, pinnedConfigDigest, reconcileAebExecutionDurable, verifyAebEvaluation, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { actionDigest as aecActionDigest } from '@emilia-protocol/verify/evidence-chain';
export const PROPOSAL_TO_EFFECT_VERSION = 'EMILIA-PROPOSAL-TO-EFFECT-v1';
const CAID_PATTERN = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PROPOSAL_INTEGRITY_DOMAIN = `${PROPOSAL_TO_EFFECT_VERSION}:INTEGRITY\0`;
function isPlainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function clone(value) {
    return structuredClone(value);
}
function assertIdentifier(value, name) {
    if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) {
        throw new Error(`${name}_invalid`);
    }
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_PATTERN.test(value);
}
function canonicalInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
        return NaN;
    return parsed;
}
function exactKeys(value, keys) {
    if (!isPlainObject(value))
        return false;
    const actual = Object.keys(value).sort();
    const expected = [...keys].sort();
    return actual.length === expected.length && expected.every((key, index) => key === actual[index]);
}
function secureConsequenceStore(store) {
    return store !== null && typeof store === 'object'
        && store.durable === true && store.ownershipFenced === true
        && store.compareAndSwap === true && store.atomicEvidenceBinding === true
        && typeof store.reserve === 'function' && typeof store.transition === 'function'
        && typeof store.reconcile === 'function' && typeof store.read === 'function';
}
function normalizedCurrentStatus(value) {
    return exactKeys(value, [
        'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed',
        ...(isPlainObject(value) && Object.hasOwn(value, 'unavailable') ? ['unavailable'] : []),
    ]) && typeof value.checked_at === 'string' && Number.isFinite(Date.parse(value.checked_at))
        && typeof value.expires_at === 'string' && Number.isFinite(Date.parse(value.expires_at))
        && typeof value.revocation_checked === 'boolean' && typeof value.revoked === 'boolean'
        && typeof value.consumed === 'boolean'
        && (value.unavailable === undefined || typeof value.unavailable === 'boolean');
}
function assertProfile(profile) {
    if (!isPlainObject(profile))
        throw new Error('proposal_profile_invalid');
    assertIdentifier(profile.id, 'proposal_profile_id');
    assertIdentifier(profile.action_type, 'proposal_action_type');
    assertIdentifier(profile.aeb_requirement_ref, 'proposal_aeb_requirement_ref');
    if (!isPlainObject(profile.selector) || Object.keys(profile.selector).length === 0) {
        throw new Error('proposal_selector_invalid');
    }
    const requiredFields = validateRequiredFields(profile.required_fields);
    if (!requiredFields.ok)
        throw new Error(requiredFields.reason);
    if (!Number.isSafeInteger(profile.ttl_sec) || profile.ttl_sec <= 0 || profile.ttl_sec > 86_400) {
        throw new Error('proposal_ttl_invalid');
    }
    if (typeof profile.canonicalize_action !== 'function') {
        throw new Error('proposal_canonicalizer_required');
    }
    const authorization = validateApprovalAuthorization(profile.authorization);
    if (!authorization.ok)
        throw new Error(authorization.reason);
    if (profile.caid_selector) {
        const caidSelector = validateCaidSelector(profile.caid_selector);
        if (!caidSelector.ok)
            throw new Error(caidSelector.reason);
    }
}
function canonicalizeForProfile(profile, input) {
    const normalized = profile.canonicalize_action(clone(input));
    if (!isPlainObject(normalized) || !isPlainObject(normalized.action)
        || typeof normalized.caid !== 'string' || !CAID_PATTERN.test(normalized.caid)) {
        throw new Error('proposal_canonicalization_invalid');
    }
    if (normalized.action.action_type !== profile.action_type) {
        throw new Error('proposal_action_type_mismatch');
    }
    for (const field of profile.required_fields) {
        if (!Object.hasOwn(normalized.action, field) || normalized.action[field] === undefined) {
            throw new Error(`proposal_required_field_missing:${field}`);
        }
    }
    if (profile.caid_selector) {
        const field = profile.caid_selector.field;
        if (typeof field !== 'string' || normalized.action[field] !== normalized.caid) {
            throw new Error(`proposal_caid_binding_invalid:${field}`);
        }
    }
    // Both digest functions reject unsupported/non-canonical JSON values.
    approvalActionHash(normalized.action);
    digestAeb(normalized.action);
    return { action: clone(normalized.action), caid: normalized.caid };
}
function assertSameObject(left, right, reason) {
    if (digestAeb(left) !== digestAeb(right))
        throw new Error(reason);
}
function exactProposalKeys(proposal) {
    const expected = [
        '@version', 'action', 'action_digest', 'aeb', 'aeb_action_digest', 'authorization',
        'caid', 'challenge', 'consequence', 'created_at', 'expires_at', 'initiator_id',
        'integrity', 'operation_id', 'profile_id', 'proposal_id',
    ].sort();
    const actual = Object.keys(proposal).sort();
    return expected.length === actual.length && expected.every((key, index) => key === actual[index]);
}
function proposalAdmissibility(proposal, record) {
    return {
        admissibility_profile: { id: `aeb:${proposal.aeb.requirement_ref}`, version: '1' },
        profile_hash: proposal.aeb.pinned_config_digest,
        verdict: 'admissible',
        replay_digest: record.evidence_digest,
        challenge_id: proposal.proposal_id,
        aeb_evaluation_digest: digestAeb(record),
    };
}
function refusal(reason, extra = {}) {
    return { ok: false, reason, ...extra };
}
export function proposalToEffectConsumptionNonce(operationId, pinnedConfigDigest) {
    assertIdentifier(operationId, 'proposal_operation_id');
    if (typeof pinnedConfigDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(pinnedConfigDigest)) {
        throw new Error('proposal_aeb_pin_invalid');
    }
    return digestAeb({
        domain: PROPOSAL_TO_EFFECT_VERSION,
        operation_id: operationId,
        pinned_config_digest: pinnedConfigDigest,
    });
}
function expectedAebCompositionDigest(proposal) {
    return `sha256:${aecActionDigest({
        caid: proposal.caid,
        normalized_action_digest: proposal.aeb_action_digest,
    })}`;
}
export function createProposalToEffect(options) {
    if (!options?.gate || typeof options.gate.check !== 'function' || typeof options.gate.run !== 'function') {
        throw new Error('proposal_gate_required');
    }
    if (!isPlainObject(options.profiles) || Object.keys(options.profiles).length === 0) {
        throw new Error('proposal_profiles_required');
    }
    for (const [id, profile] of Object.entries(options.profiles)) {
        assertProfile(profile);
        if (id !== profile.id)
            throw new Error('proposal_profile_registry_mismatch');
    }
    if (!options.aeb?.config || !options.aeb.adapters || !options.aeb.store
        || typeof options.aeb.resolve_artifacts !== 'function'
        || typeof options.aeb.currentStatusResolver !== 'function'
        || typeof options.aeb.statusVerifier !== 'function'
        || typeof options.aeb.verify_provider_evidence !== 'function') {
        throw new Error('proposal_aeb_configuration_required');
    }
    if (!(options.proposal_integrity?.hmac_sha256_key instanceof Uint8Array)
        || options.proposal_integrity.hmac_sha256_key.byteLength < 32) {
        throw new Error('proposal_integrity_configuration_required');
    }
    if (!options.consequence)
        throw new Error('proposal_consequence_configuration_required');
    assertIdentifier(options.consequence.tenant_id, 'proposal_tenant_id');
    assertIdentifier(options.consequence.provider_id, 'proposal_provider_id');
    assertIdentifier(options.consequence.provider_account_id, 'proposal_provider_account_id');
    assertIdentifier(options.consequence.environment, 'proposal_environment');
    assertIdentifier(options.consequence.executor_id, 'proposal_executor_id');
    if (!secureConsequenceStore(options.consequence.store)
        || (options.consequence.create_attempt_id !== undefined
            && typeof options.consequence.create_attempt_id !== 'function')) {
        throw new Error('proposal_consequence_store_required');
    }
    const now = options.now ?? Date.now;
    const configDigest = pinnedConfigDigest(options.aeb.config);
    const integrityKey = Buffer.from(options.proposal_integrity.hmac_sha256_key);
    const consequenceContext = Object.freeze({
        tenant_id: options.consequence.tenant_id,
        provider_id: options.consequence.provider_id,
        provider_account_id: options.consequence.provider_account_id,
        environment: options.consequence.environment,
        executor_id: options.consequence.executor_id,
    });
    // Active owner capabilities never become enumerable response/error data.
    // The same-process service can recover a handle from the exact object; after
    // restart it must use the durable store's separately authorized recovery API.
    const reconciliationHandles = new WeakMap();
    function rememberReconciliationHandle(target, reference) {
        reconciliationHandles.set(target, reference);
        return target;
    }
    function getReconciliationHandle(target) {
        const reference = reconciliationHandles.get(target);
        return reference ? clone(reference) : null;
    }
    function currentTime() {
        const value = now();
        if (!Number.isSafeInteger(value) || !Number.isFinite(new Date(value).getTime())) {
            throw new Error('proposal_time_invalid');
        }
        return value;
    }
    async function reconcileAebWithRecovery(key, outcome, authorization) {
        let result = await reconcileAebExecutionDurable(options.aeb.store, key, outcome);
        const recoveryStore = options.aeb.store;
        if (result.state === 'RECONCILIATION_REQUIRED'
            && authorization !== undefined
            && typeof recoveryStore.claimReservation === 'function'
            && await recoveryStore.claimReservation(key, authorization).catch(() => false)) {
            result = await reconcileAebExecutionDurable(options.aeb.store, key, outcome);
        }
        return result;
    }
    function requestDigestFor(proposal) {
        return digestAeb({
            domain: `${PROPOSAL_TO_EFFECT_VERSION}:REQUEST`,
            ...consequenceContext,
            proposal_id: proposal.proposal_id,
            operation_id: proposal.operation_id,
            initiator_id: proposal.initiator_id,
            profile_id: proposal.profile_id,
            action: proposal.action,
            action_digest: proposal.action_digest,
            aeb_action_digest: proposal.aeb_action_digest,
            caid: proposal.caid,
            created_at: proposal.created_at,
            expires_at: proposal.expires_at,
            challenge: proposal.challenge,
            authorization: proposal.authorization,
            aeb: proposal.aeb,
        });
    }
    function integrityMac(unsignedProposal) {
        return crypto.createHmac('sha256', integrityKey)
            .update(PROPOSAL_INTEGRITY_DOMAIN)
            .update(digestAeb(unsignedProposal))
            .digest('base64url');
    }
    function proposalIntegrityValid(proposal) {
        if (!exactKeys(proposal.integrity, ['alg', 'value'])
            || proposal.integrity.alg !== 'HMAC-SHA256'
            || typeof proposal.integrity.value !== 'string'
            || !/^[A-Za-z0-9_-]{43}$/.test(proposal.integrity.value))
            return false;
        const unsigned = clone(proposal);
        delete unsigned.integrity;
        const actual = Buffer.from(proposal.integrity.value, 'base64url');
        const expected = Buffer.from(integrityMac(unsigned), 'base64url');
        return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    }
    function profileFor(id) {
        if (typeof id !== 'string' || !options.profiles[id])
            throw new Error('proposal_profile_not_pinned');
        return options.profiles[id];
    }
    function prepare(input) {
        assertIdentifier(input?.proposal_id, 'proposal_id');
        assertIdentifier(input?.operation_id, 'proposal_operation_id');
        assertIdentifier(input?.initiator_id, 'proposal_initiator_id');
        const profile = profileFor(input?.profile_id);
        const normalized = canonicalizeForProfile(profile, input.action);
        const createdAtMs = currentTime();
        const actionDigest = approvalActionHash(normalized.action);
        const base = {
            '@version': PROPOSAL_TO_EFFECT_VERSION,
            proposal_id: input.proposal_id,
            operation_id: input.operation_id,
            initiator_id: input.initiator_id,
            profile_id: profile.id,
            action: normalized.action,
            action_digest: actionDigest,
            aeb_action_digest: digestAeb(normalized.action),
            caid: normalized.caid,
            created_at: new Date(createdAtMs).toISOString(),
            expires_at: new Date(createdAtMs + profile.ttl_sec * 1000).toISOString(),
            challenge: {
                action: profile.action_type,
                action_hash: actionDigest,
                required_fields: [...profile.required_fields],
                ...(profile.caid_selector ? { caid_selector: clone(profile.caid_selector) } : {}),
            },
            authorization: clone(profile.authorization),
            aeb: {
                requirement_ref: profile.aeb_requirement_ref,
                pinned_config_digest: configDigest,
                consumption_nonce: proposalToEffectConsumptionNonce(input.operation_id, configDigest),
            },
        };
        const unsigned = {
            ...base,
            consequence: {
                ...consequenceContext,
                request_digest: requestDigestFor(base),
            },
        };
        return clone({
            ...unsigned,
            integrity: { alg: 'HMAC-SHA256', value: integrityMac(unsigned) },
        });
    }
    function verifyProposal(input, { allowExpired = false } = {}) {
        if (!isPlainObject(input) || !exactProposalKeys(input)
            || input['@version'] !== PROPOSAL_TO_EFFECT_VERSION) {
            throw new Error('proposal_shape_invalid');
        }
        if (!proposalIntegrityValid(input))
            throw new Error('proposal_integrity_invalid');
        const proposal = input;
        assertIdentifier(proposal.proposal_id, 'proposal_id');
        assertIdentifier(proposal.operation_id, 'proposal_operation_id');
        assertIdentifier(proposal.initiator_id, 'proposal_initiator_id');
        const profile = profileFor(proposal.profile_id);
        const normalized = canonicalizeForProfile(profile, proposal.action);
        if (normalized.caid !== proposal.caid)
            throw new Error('proposal_caid_mismatch');
        assertSameObject(normalized.action, proposal.action, 'proposal_action_not_canonical');
        if (approvalActionHash(normalized.action) !== proposal.action_digest) {
            throw new Error('proposal_action_digest_mismatch');
        }
        if (digestAeb(normalized.action) !== proposal.aeb_action_digest) {
            throw new Error('proposal_aeb_action_digest_mismatch');
        }
        const createdAtMs = canonicalInstant(proposal.created_at);
        const expiresAtMs = canonicalInstant(proposal.expires_at);
        if (!Number.isFinite(createdAtMs) || !Number.isFinite(expiresAtMs))
            throw new Error('proposal_time_invalid');
        if (expiresAtMs - createdAtMs !== profile.ttl_sec * 1000)
            throw new Error('proposal_ttl_mismatch');
        const decisionTime = currentTime();
        if (createdAtMs > decisionTime)
            throw new Error('proposal_created_in_future');
        if (!allowExpired && decisionTime >= expiresAtMs)
            throw new Error('proposal_expired');
        assertSameObject(proposal.authorization, profile.authorization, 'proposal_authorization_mismatch');
        if (!isPlainObject(proposal.aeb)
            || Object.keys(proposal.aeb).sort().join(',') !== 'consumption_nonce,pinned_config_digest,requirement_ref'
            || proposal.aeb?.requirement_ref !== profile.aeb_requirement_ref
            || proposal.aeb?.pinned_config_digest !== configDigest) {
            throw new Error('proposal_aeb_pin_mismatch');
        }
        if (proposal.aeb.consumption_nonce !== proposalToEffectConsumptionNonce(proposal.operation_id, configDigest)) {
            throw new Error('proposal_aeb_nonce_mismatch');
        }
        if (!exactKeys(proposal.consequence, [
            'tenant_id', 'provider_id', 'provider_account_id', 'environment', 'executor_id', 'request_digest',
        ]) || proposal.consequence.tenant_id !== consequenceContext.tenant_id
            || proposal.consequence.provider_id !== consequenceContext.provider_id
            || proposal.consequence.provider_account_id !== consequenceContext.provider_account_id
            || proposal.consequence.environment !== consequenceContext.environment
            || proposal.consequence.executor_id !== consequenceContext.executor_id
            || proposal.consequence.request_digest !== requestDigestFor(proposal)) {
            throw new Error('proposal_consequence_binding_mismatch');
        }
        const expectedChallenge = {
            action: profile.action_type,
            action_hash: proposal.action_digest,
            required_fields: [...profile.required_fields],
            ...(profile.caid_selector ? { caid_selector: clone(profile.caid_selector) } : {}),
        };
        assertSameObject(proposal.challenge, expectedChallenge, 'proposal_challenge_mismatch');
        return { proposal: clone(proposal), profile };
    }
    async function verifyEvaluation(proposal, evaluation) {
        if (!isPlainObject(evaluation))
            return { valid: false, reason: 'aeb_evaluation_missing', record: null };
        const record = evaluation;
        if (record.operation_id !== proposal.operation_id
            || record.consumption_nonce !== proposal.aeb.consumption_nonce
            || record.initiator_id !== proposal.initiator_id
            || record.executor_id !== proposal.consequence.executor_id
            || record.requirement_ref !== proposal.aeb.requirement_ref
            || record.caid !== proposal.caid) {
            return { valid: false, reason: 'aeb_evaluation_binding_mismatch', record };
        }
        if (record.verdict === 'SATISFIED'
            && record.composition?.action_digest !== expectedAebCompositionDigest(proposal)) {
            return { valid: false, reason: 'aeb_evaluation_binding_mismatch', record };
        }
        let artifacts;
        try {
            artifacts = await options.aeb.resolve_artifacts({ proposal: clone(proposal), evaluation: clone(record) });
        }
        catch {
            return { valid: false, reason: 'aeb_artifact_resolution_failed', record };
        }
        const decisionNow = new Date(currentTime()).toISOString();
        const currentStatuses = {};
        for (const leg of record.legs ?? []) {
            try {
                const statusArtifact = await options.aeb.currentStatusResolver({
                    proposal: clone(proposal),
                    evaluation: clone(record),
                    leg: clone(leg),
                });
                if (statusArtifact === undefined || statusArtifact === null) {
                    return { valid: false, reason: 'aeb_current_status_refused', record };
                }
                const status = await options.aeb.statusVerifier({
                    status_artifact: clone(statusArtifact),
                    expected: {
                        tenant_id: proposal.consequence.tenant_id,
                        executor_id: proposal.consequence.executor_id,
                        operation_id: proposal.operation_id,
                        caid: proposal.caid,
                        artifact_ref: leg.artifact_ref,
                        evidence_digest: leg.evidence_digest,
                        replay_unit: leg.replay_unit,
                    },
                    now: decisionNow,
                });
                if (!status?.valid || status.outcome !== 'current_not_revoked'
                    || !normalizedCurrentStatus(status.status)
                    || status.status.revocation_checked !== true || status.status.revoked !== false
                    || status.status.consumed !== false || status.status.unavailable === true) {
                    return { valid: false, reason: 'aeb_current_status_refused', record };
                }
                currentStatuses[leg.artifact_ref] = clone(status.status);
            }
            catch {
                return { valid: false, reason: 'aeb_current_status_refused', record };
            }
        }
        if (record.legs.length === 0 || Object.keys(currentStatuses).length !== record.legs.length) {
            return { valid: false, reason: 'aeb_current_status_refused', record };
        }
        const verificationOptions = {
            mode: 'execution',
            config: options.aeb.config,
            adapters: options.aeb.adapters,
            artifacts,
            expected_action: clone(proposal.action),
            executor_id: proposal.consequence.executor_id,
            current_statuses: currentStatuses,
            now: decisionNow,
        };
        const checked = verifyAebEvaluation(record, verificationOptions);
        if (!checked.valid || checked.execution_authorizing !== true
            || record.verdict !== 'SATISFIED'
            || record.authority_constraints?.one_time_consumption !== true) {
            return { valid: false, reason: 'aeb_evaluation_refused', record, checked };
        }
        return { valid: true, reason: null, record, checked };
    }
    function gateInput(proposal, profile, receipt, record) {
        return {
            selector: {
                ...clone(profile.selector),
                operation_id: proposal.operation_id,
                initiator_id: proposal.initiator_id,
                aeb_requirement_ref: proposal.aeb.requirement_ref,
                tenant_id: proposal.consequence.tenant_id,
                provider_id: proposal.consequence.provider_id,
                provider_account_id: proposal.consequence.provider_account_id,
                environment: proposal.consequence.environment,
                executor_id: proposal.consequence.executor_id,
                request_digest: proposal.consequence.request_digest,
            },
            receipt,
            observedAction: clone(proposal.action),
            admissibility: proposalAdmissibility(proposal, record),
        };
    }
    async function execute(input, effect) {
        if (typeof effect !== 'function')
            throw new Error('proposal_effect_required');
        const { proposal, profile } = verifyProposal(input?.proposal);
        const evaluation = await verifyEvaluation(proposal, input?.evaluation);
        if (!evaluation.valid || !evaluation.record) {
            return refusal(evaluation.reason || 'aeb_evaluation_refused', { aeb: evaluation.checked ?? null });
        }
        if (!evaluation.checked?.valid || evaluation.checked.execution_authorizing !== true) {
            return refusal('aeb_execution_verification_required', { aeb: evaluation.checked ?? null });
        }
        const preparedGateInput = gateInput(proposal, profile, input.receipt, evaluation.record);
        const preflight = await options.gate.check({ ...preparedGateInput, consumptionMode: 'none' });
        if (preflight.allow !== true) {
            return refusal(preflight.reason || 'gate_refused', { authorization: preflight });
        }
        if (preflight.reason === 'not_guarded' || preflight.requirement?.receipt_required !== true) {
            return refusal('gate_profile_not_receipt_guarded', { authorization: preflight });
        }
        const reservation = await authorizeAebExecutionDurable(evaluation.record, {
            verification: evaluation.checked,
            local_authorization: true,
            store: options.aeb.store,
        });
        if (!reservation.invoke_allowed || !reservation.reservation_key) {
            return refusal(reservation.reason === 'consumption_conflict' ? 'aeb_consumption_conflict' : reservation.reason, { aeb: reservation });
        }
        const key = reservation.reservation_key;
        let attemptId;
        try {
            attemptId = options.consequence.create_attempt_id
                ? await options.consequence.create_attempt_id({
                    tenant_id: proposal.consequence.tenant_id,
                    request_digest: proposal.consequence.request_digest,
                })
                : `attempt:${crypto.randomUUID()}`;
            assertIdentifier(attemptId, 'proposal_attempt_id');
        }
        catch {
            await options.aeb.store.release(key).catch(() => false);
            return refusal('consequence_attempt_allocation_failed');
        }
        const binding = {
            tenant_id: proposal.consequence.tenant_id,
            provider_id: proposal.consequence.provider_id,
            provider_account_id: proposal.consequence.provider_account_id,
            environment: proposal.consequence.environment,
            attempt_id: attemptId,
            request_digest: proposal.consequence.request_digest,
        };
        let reservedAttempt;
        try {
            reservedAttempt = await options.consequence.store.reserve(clone(binding));
        }
        catch {
            await options.aeb.store.release(key).catch(() => false);
            return refusal('consequence_attempt_store_unavailable');
        }
        if (!reservedAttempt?.reserved || typeof reservedAttempt.owner !== 'string'
            || reservedAttempt.owner.length < 1 || reservedAttempt.owner.length > 1024) {
            await options.aeb.store.release(key).catch(() => false);
            const reason = reservedAttempt.reserved === false
                ? reservedAttempt.reason : 'consequence_attempt_conflict';
            return refusal(reason);
        }
        const attempt = {
            ...binding,
            owner: reservedAttempt.owner,
        };
        const attemptRef = {
            tenant_id: attempt.tenant_id,
            attempt_id: attempt.attempt_id,
            owner: attempt.owner,
        };
        const attemptCustody = { state: 'RESERVED' };
        const transition = async (change) => {
            try {
                const changed = await options.consequence.store.transition({
                    ...attemptRef,
                    ...change,
                });
                if (changed === true)
                    attemptCustody.state = change.next_state;
                return changed === true;
            }
            catch {
                return false;
            }
        };
        if (!await transition({ expected_state: 'RESERVED', next_state: 'INVOKING' })) {
            await options.aeb.store.release(key).catch(() => false);
            return refusal('consequence_attempt_transition_conflict');
        }
        let callbackEntered = false;
        const freeze = async () => (attemptCustody.state === 'INDETERMINATE'
            || (attemptCustody.state === 'INVOKING'
                && await transition({ expected_state: 'INVOKING', next_state: 'INDETERMINATE' })));
        const attachAttempt = (thrown, outcome) => {
            const error = thrown && (typeof thrown === 'object' || typeof thrown === 'function')
                ? thrown : new Error(String(thrown));
            error.proposalToEffect = {
                ...(isPlainObject(error.proposalToEffect) ? error.proposalToEffect : {}),
                ...(outcome ? { outcome } : {}),
                reservation_key: key,
                attempt: clone(binding),
                attempt_state: attemptCustody.state,
            };
            return rememberReconciliationHandle(error, attemptRef);
        };
        try {
            const result = await options.gate.run(preparedGateInput, async (authorization) => {
                callbackEntered = true;
                return effect({
                    action: clone(proposal.action),
                    proposal: clone(proposal),
                    authorization: clone(authorization),
                    attempt: clone(binding),
                });
            });
            if (!await freeze()) {
                throw attachAttempt(new Error('consequence_attempt_freeze_failed'), 'indeterminate');
            }
            if (result?.ok !== true) {
                if (callbackEntered) {
                    return rememberReconciliationHandle(refusal(result?.authorization?.reason || result?.reason || 'gate_refused', {
                        authorization: result?.authorization ?? null,
                        consequence: { state: 'INDETERMINATE', attempt: clone(binding) },
                    }), attemptRef);
                }
                if (!await transition({ expected_state: 'INDETERMINATE', next_state: 'RELEASED' })) {
                    return rememberReconciliationHandle(refusal('consequence_attempt_transition_conflict', {
                        consequence: { state: 'INDETERMINATE', attempt: clone(binding) },
                    }), attemptRef);
                }
                await options.aeb.store.release(key).catch(() => false);
                return refusal(result?.authorization?.reason || result?.reason || 'gate_refused', {
                    authorization: result?.authorization ?? null,
                    consequence: { state: 'RELEASED', attempt: clone(binding) },
                });
            }
            if (!callbackEntered) {
                if (await transition({ expected_state: 'INDETERMINATE', next_state: 'RELEASED' })) {
                    await options.aeb.store.release(key).catch(() => false);
                }
                const response = refusal('gate_effect_not_invoked', {
                    consequence: { state: attemptCustody.state, attempt: clone(binding) },
                });
                return attemptCustody.state === 'INDETERMINATE'
                    ? rememberReconciliationHandle(response, attemptRef) : response;
            }
            const committed = await reconcileAebWithRecovery(key, 'COMMITTED');
            if (committed.state !== 'CONSUMED') {
                const error = new Error('aeb_consumption_commit_failed');
                error.code = 'EMILIA_PROPOSAL_TO_EFFECT_COMMIT_FAILED';
                throw attachAttempt(error, 'indeterminate');
            }
            if (!await transition({ expected_state: 'INDETERMINATE', next_state: 'COMMITTED' })) {
                throw attachAttempt(new Error('consequence_attempt_commit_failed'), 'executed');
            }
            return {
                ...result,
                proposal: clone(proposal),
                aeb: committed,
                consequence: { state: 'COMMITTED', attempt: clone(binding) },
            };
        }
        catch (error) {
            const outcome = error?.proposalToEffect?.outcome ?? error?.emiliaGateOutcome?.outcome;
            if (attemptCustody.state === 'INVOKING')
                await freeze();
            if (attemptCustody.state === 'INDETERMINATE' && outcome === 'executed') {
                const committed = await reconcileAebWithRecovery(key, 'COMMITTED');
                if (committed.state === 'CONSUMED') {
                    await transition({ expected_state: 'INDETERMINATE', next_state: 'COMMITTED' });
                }
            }
            else if (attemptCustody.state === 'INDETERMINATE' && !callbackEntered && outcome !== 'indeterminate') {
                if (await transition({ expected_state: 'INDETERMINATE', next_state: 'RELEASED' })) {
                    await options.aeb.store.release(key).catch(() => false);
                }
            }
            throw attachAttempt(error, callbackEntered ? (outcome || 'indeterminate') : outcome);
        }
    }
    async function reconcile(input) {
        const { proposal } = verifyProposal(input?.proposal, { allowExpired: true });
        if (!isPlainObject(input?.evaluation))
            return refusal('aeb_evaluation_missing');
        const record = input.evaluation;
        if (record.operation_id !== proposal.operation_id
            || record.consumption_nonce !== proposal.aeb.consumption_nonce
            || record.initiator_id !== proposal.initiator_id
            || record.executor_id !== proposal.consequence.executor_id
            || record.requirement_ref !== proposal.aeb.requirement_ref
            || record.caid !== proposal.caid) {
            return refusal('aeb_evaluation_binding_mismatch');
        }
        if (record.composition?.action_digest !== expectedAebCompositionDigest(proposal)) {
            return refusal('aeb_evaluation_binding_mismatch');
        }
        let artifacts;
        try {
            artifacts = await options.aeb.resolve_artifacts({ proposal: clone(proposal), evaluation: clone(record) });
        }
        catch {
            return refusal('aeb_artifact_resolution_failed');
        }
        const historicalOptions = {
            mode: 'historical',
            config: options.aeb.config,
            adapters: options.aeb.adapters,
            artifacts,
            expected_action: clone(proposal.action),
            executor_id: proposal.consequence.executor_id,
        };
        const historical = verifyAebEvaluation(record, historicalOptions);
        if (!historical.valid)
            return refusal('aeb_evaluation_refused', { aeb: historical });
        if (record.verdict !== 'SATISFIED'
            || record.authority_constraints?.one_time_consumption !== true) {
            return refusal('aeb_evaluation_refused', { aeb: historical });
        }
        if (!isPlainObject(input?.attempt)
            || input.attempt.tenant_id !== proposal.consequence.tenant_id
            || typeof input.attempt.attempt_id !== 'string'
            || !IDENTIFIER_PATTERN.test(input.attempt.attempt_id)
            || typeof input.attempt.owner !== 'string'
            || input.attempt.owner.length < 1 || input.attempt.owner.length > 1024) {
            return refusal('consequence_attempt_binding_mismatch');
        }
        const attemptRef = {
            tenant_id: proposal.consequence.tenant_id,
            attempt_id: input.attempt.attempt_id,
            owner: input.attempt.owner,
        };
        const publicAttempt = {
            tenant_id: proposal.consequence.tenant_id,
            provider_id: proposal.consequence.provider_id,
            provider_account_id: proposal.consequence.provider_account_id,
            environment: proposal.consequence.environment,
            attempt_id: attemptRef.attempt_id,
            request_digest: proposal.consequence.request_digest,
        };
        let provider;
        try {
            provider = await options.aeb.verify_provider_evidence({
                evidence: clone(input.provider_evidence),
                expected: {
                    operation_id: proposal.operation_id,
                    caid: proposal.caid,
                    action_digest: proposal.aeb_action_digest,
                    tenant_id: proposal.consequence.tenant_id,
                    request_digest: proposal.consequence.request_digest,
                    provider_id: proposal.consequence.provider_id,
                    provider_account_id: proposal.consequence.provider_account_id,
                    environment: proposal.consequence.environment,
                    attempt_id: attemptRef.attempt_id,
                },
            });
        }
        catch {
            return refusal('provider_evidence_unverified');
        }
        const observedAtMs = typeof provider?.observed_at === 'string'
            ? Date.parse(provider.observed_at) : NaN;
        const proposalCreatedAtMs = Date.parse(proposal.created_at);
        if (!provider?.valid || !['COMMITTED', 'NOT_COMMITTED', 'ESCALATED'].includes(provider.outcome ?? '')
            || typeof provider.evidence_id !== 'string' || !IDENTIFIER_PATTERN.test(provider.evidence_id)
            || !Number.isFinite(observedAtMs) || observedAtMs < proposalCreatedAtMs
            || observedAtMs > currentTime()
            || !validDigest(provider.evidence_digest)) {
            return refusal(provider?.reason || 'provider_evidence_unverified');
        }
        if (provider.tenant_id !== proposal.consequence.tenant_id
            || provider.request_digest !== proposal.consequence.request_digest
            || provider.provider_id !== proposal.consequence.provider_id
            || provider.provider_account_id !== proposal.consequence.provider_account_id
            || provider.environment !== proposal.consequence.environment
            || provider.attempt_id !== attemptRef.attempt_id
            || provider.operation_id !== proposal.operation_id
            || provider.caid !== proposal.caid
            || provider.action_digest !== proposal.aeb_action_digest) {
            return refusal('provider_evidence_binding_mismatch');
        }
        const providerOutcome = provider.outcome;
        const evidence = {
            operation_id: proposal.operation_id,
            caid: proposal.caid,
            action_digest: proposal.aeb_action_digest,
            tenant_id: proposal.consequence.tenant_id,
            provider_id: proposal.consequence.provider_id,
            provider_account_id: proposal.consequence.provider_account_id,
            environment: proposal.consequence.environment,
            attempt_id: attemptRef.attempt_id,
            request_digest: proposal.consequence.request_digest,
            evidence_id: provider.evidence_id,
            observed_at: provider.observed_at,
            outcome: providerOutcome,
            evidence_digest: provider.evidence_digest,
        };
        const terminalState = providerOutcome === 'COMMITTED'
            ? 'COMMITTED' : providerOutcome === 'NOT_COMMITTED' ? 'RELEASED' : 'ESCALATED';
        const key = aebReservationKey(record);
        // For a committed real-world effect, consume replay authority before the
        // attempt becomes terminal. A failed AEB commit leaves the attempt
        // INDETERMINATE and therefore repairable, never terminal split-brain.
        const preTerminalAeb = providerOutcome === 'COMMITTED'
            ? await reconcileAebWithRecovery(key, 'COMMITTED', input.aeb_recovery_authorization)
            : null;
        if (providerOutcome === 'COMMITTED' && preTerminalAeb?.state !== 'CONSUMED') {
            return refusal('aeb_consumption_reconciliation_failed', {
                state: 'INDETERMINATE',
                consequence: { state: 'INDETERMINATE', attempt: clone(publicAttempt) },
                aeb: preTerminalAeb,
            });
        }
        let attemptReconciled = false;
        try {
            attemptReconciled = await options.consequence.store.reconcile({
                ...attemptRef,
                expected_state: 'INDETERMINATE',
                next_state: terminalState,
                evidence: clone(evidence),
            });
        }
        catch {
            return refusal('consequence_attempt_store_unavailable');
        }
        if (!attemptReconciled)
            return refusal('consequence_attempt_not_indeterminate');
        const reconciled = providerOutcome === 'ESCALATED'
            ? { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'execution_escalated' }
            : providerOutcome === 'COMMITTED'
                ? preTerminalAeb
                : await reconcileAebWithRecovery(key, providerOutcome, input.aeb_recovery_authorization);
        if (providerOutcome !== 'ESCALATED' && reconciled.state === 'RECONCILIATION_REQUIRED') {
            return refusal('aeb_consumption_reconciliation_failed', {
                state: terminalState,
                consequence: { state: terminalState, attempt: clone(publicAttempt) },
                aeb: reconciled,
            });
        }
        return {
            ok: true,
            state: terminalState,
            outcome: providerOutcome,
            evidence_digest: provider.evidence_digest,
            reservation_key: key,
            consequence: { state: terminalState, attempt: clone(publicAttempt) },
            aeb: reconciled,
        };
    }
    /**
     * Converge legacy or crash-window terminal consequence state with the AEB
     * reservation. This never invokes an effect and trusts only the signed
     * proposal/evaluation plus the durable consequence store's terminal state.
     */
    async function repairAeb(input) {
        const { proposal } = verifyProposal(input?.proposal, { allowExpired: true });
        if (!isPlainObject(input?.evaluation))
            return refusal('aeb_evaluation_missing');
        const record = input.evaluation;
        if (record.operation_id !== proposal.operation_id
            || record.consumption_nonce !== proposal.aeb.consumption_nonce
            || record.initiator_id !== proposal.initiator_id
            || record.executor_id !== proposal.consequence.executor_id
            || record.requirement_ref !== proposal.aeb.requirement_ref
            || record.caid !== proposal.caid
            || record.composition?.action_digest !== expectedAebCompositionDigest(proposal)) {
            return refusal('aeb_evaluation_binding_mismatch');
        }
        let artifacts;
        try {
            artifacts = await options.aeb.resolve_artifacts({ proposal: clone(proposal), evaluation: clone(record) });
        }
        catch {
            return refusal('aeb_artifact_resolution_failed');
        }
        const historicalOptions = {
            mode: 'historical',
            config: options.aeb.config,
            adapters: options.aeb.adapters,
            artifacts,
            expected_action: clone(proposal.action),
            executor_id: proposal.consequence.executor_id,
        };
        const historical = verifyAebEvaluation(record, historicalOptions);
        if (!historical.valid || record.verdict !== 'SATISFIED'
            || record.authority_constraints?.one_time_consumption !== true) {
            return refusal('aeb_evaluation_refused', { aeb: historical });
        }
        if (!exactKeys(input?.attempt, [
            'tenant_id', 'provider_id', 'provider_account_id', 'environment',
            'attempt_id', 'request_digest',
        ])) {
            return refusal('consequence_attempt_binding_mismatch');
        }
        const attempt = input.attempt;
        if (attempt.tenant_id !== proposal.consequence.tenant_id
            || attempt.provider_id !== proposal.consequence.provider_id
            || attempt.provider_account_id !== proposal.consequence.provider_account_id
            || attempt.environment !== proposal.consequence.environment
            || attempt.request_digest !== proposal.consequence.request_digest
            || typeof attempt.attempt_id !== 'string' || !IDENTIFIER_PATTERN.test(attempt.attempt_id)) {
            return refusal('consequence_attempt_binding_mismatch');
        }
        let snapshot;
        try {
            snapshot = await options.consequence.store.read(clone(attempt));
        }
        catch {
            return refusal('consequence_attempt_store_unavailable');
        }
        if (!snapshot)
            return refusal('consequence_attempt_not_found');
        if (!['COMMITTED', 'RELEASED', 'ESCALATED'].includes(snapshot.state)) {
            return refusal('consequence_attempt_not_terminal', { state: snapshot.state });
        }
        if (snapshot.state === 'ESCALATED') {
            return {
                ok: true,
                state: 'ESCALATED',
                consequence: { state: 'ESCALATED', attempt: clone(attempt) },
                aeb: { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'execution_escalated' },
            };
        }
        const key = aebReservationKey(record);
        const outcome = snapshot.state === 'COMMITTED' ? 'COMMITTED' : 'NOT_COMMITTED';
        const repaired = await reconcileAebWithRecovery(key, outcome, input.aeb_recovery_authorization);
        const expectedState = outcome === 'COMMITTED' ? 'CONSUMED' : 'AVAILABLE';
        if (repaired.state !== expectedState) {
            return refusal('aeb_consumption_repair_failed', {
                state: snapshot.state,
                consequence: { state: snapshot.state, attempt: clone(attempt) },
                aeb: repaired,
            });
        }
        return {
            ok: true,
            state: snapshot.state,
            consequence: { state: snapshot.state, attempt: clone(attempt) },
            reservation_key: key,
            aeb: repaired,
        };
    }
    async function beginApproval(input) {
        const { proposal, profile } = verifyProposal(input?.proposal);
        return beginReceiptApproval({
            authorization: proposal.authorization,
            trustedAuthorization: profile.authorization,
            challenge: proposal.challenge,
            action: proposal.action,
            approver_id: input.approver_id,
            idempotency_key: input.idempotency_key,
            requesterAuthorization: input.requester_authorization,
            fetchImpl: input.fetch_impl,
        });
    }
    async function pollApproval(input) {
        const { proposal, profile } = verifyProposal(input?.proposal, { allowExpired: true });
        return pollReceiptApproval({
            authorization: proposal.authorization,
            trustedAuthorization: profile.authorization,
            request_id: input.request_id,
            poll_token: input.poll_token,
            fetchImpl: input.fetch_impl,
        });
    }
    return Object.freeze({
        prepare,
        verifyProposal,
        beginApproval,
        pollApproval,
        execute,
        reconcile,
        repairAeb,
        getReconciliationHandle,
    });
}
export default {
    PROPOSAL_TO_EFFECT_VERSION,
    proposalToEffectConsumptionNonce,
    createProposalToEffect,
};
//# sourceMappingURL=proposal-to-effect.js.map