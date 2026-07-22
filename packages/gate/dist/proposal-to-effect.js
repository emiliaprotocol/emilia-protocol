// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Proposal-to-Effect is a product orchestration profile over existing EMILIA
 * artifacts. A proposal is deliberately NOT a bearer authorization object.
 * Authority remains in EP-RECEIPT-v1 and the relying party's pinned AEB
 * requirement; consequence custody remains in Gate and its durable stores.
 */
import { beginReceiptApproval, pollReceiptApproval, approvalActionHash, validateApprovalAuthorization, validateCaidSelector, validateRequiredFields, } from '@emilia-protocol/require-receipt/acquisition';
import { aebReservationKey, authorizeAebExecutionDurable, digestAeb, pinnedConfigDigest, reconcileAebExecutionDurable, verifyAebEvaluation, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { actionDigest as aecActionDigest } from '@emilia-protocol/verify/evidence-chain';
export const PROPOSAL_TO_EFFECT_VERSION = 'EMILIA-PROPOSAL-TO-EFFECT-v1';
const CAID_PATTERN = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
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
        'caid', 'challenge', 'created_at', 'expires_at', 'initiator_id', 'operation_id',
        'profile_id', 'proposal_id',
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
        || typeof options.aeb.verify_provider_evidence !== 'function') {
        throw new Error('proposal_aeb_configuration_required');
    }
    const now = options.now ?? Date.now;
    const configDigest = pinnedConfigDigest(options.aeb.config);
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
        const createdAtMs = now();
        if (!Number.isFinite(createdAtMs))
            throw new Error('proposal_time_invalid');
        const actionDigest = approvalActionHash(normalized.action);
        return clone({
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
        });
    }
    function verifyProposal(input, { allowExpired = false } = {}) {
        if (!isPlainObject(input) || !exactProposalKeys(input)
            || input['@version'] !== PROPOSAL_TO_EFFECT_VERSION) {
            throw new Error('proposal_shape_invalid');
        }
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
        if (!Number.isFinite(Date.parse(proposal.created_at)) || !Number.isFinite(Date.parse(proposal.expires_at))
            || Date.parse(proposal.expires_at) <= Date.parse(proposal.created_at)) {
            throw new Error('proposal_time_invalid');
        }
        if (!allowExpired && now() >= Date.parse(proposal.expires_at))
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
            || record.requirement_ref !== proposal.aeb.requirement_ref
            || record.caid !== proposal.caid) {
            return { valid: false, reason: 'aeb_evaluation_binding_mismatch', record };
        }
        let artifacts;
        try {
            artifacts = await options.aeb.resolve_artifacts({ proposal: clone(proposal), evaluation: clone(record) });
        }
        catch {
            return { valid: false, reason: 'aeb_artifact_resolution_failed', record };
        }
        const checked = verifyAebEvaluation(record, {
            config: options.aeb.config,
            adapters: options.aeb.adapters,
            artifacts,
            now: new Date(now()).toISOString(),
        });
        if (!checked.valid || record.verdict !== 'SATISFIED'
            || record.authority_constraints?.one_time_consumption !== true) {
            return { valid: false, reason: 'aeb_evaluation_refused', record, checked };
        }
        if (record.composition?.action_digest !== expectedAebCompositionDigest(proposal)) {
            return { valid: false, reason: 'aeb_evaluation_binding_mismatch', record, checked };
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
        const preparedGateInput = gateInput(proposal, profile, input.receipt, evaluation.record);
        const preflight = await options.gate.check({ ...preparedGateInput, consumptionMode: 'none' });
        if (preflight.allow !== true) {
            return refusal(preflight.reason || 'gate_refused', { authorization: preflight });
        }
        if (preflight.reason === 'not_guarded' || preflight.requirement?.receipt_required !== true) {
            return refusal('gate_profile_not_receipt_guarded', { authorization: preflight });
        }
        const reservation = await authorizeAebExecutionDurable(evaluation.record, {
            verified: true,
            local_authorization: true,
            store: options.aeb.store,
        });
        if (!reservation.invoke_allowed || !reservation.reservation_key) {
            return refusal(reservation.reason === 'consumption_conflict' ? 'aeb_consumption_conflict' : reservation.reason, { aeb: reservation });
        }
        const key = reservation.reservation_key;
        try {
            const result = await options.gate.run(preparedGateInput, async (authorization) => effect({
                action: clone(proposal.action),
                proposal: clone(proposal),
                authorization: clone(authorization),
            }));
            if (result?.ok !== true) {
                await options.aeb.store.release(key);
                return refusal(result?.authorization?.reason || result?.reason || 'gate_refused', {
                    authorization: result?.authorization ?? null,
                });
            }
            const committed = await reconcileAebExecutionDurable(options.aeb.store, key, 'COMMITTED');
            if (committed.state !== 'CONSUMED') {
                const error = new Error('aeb_consumption_commit_failed');
                error.code = 'EMILIA_PROPOSAL_TO_EFFECT_COMMIT_FAILED';
                error.proposalToEffect = { outcome: 'executed', reservation_key: key };
                throw error;
            }
            return { ...result, proposal: clone(proposal), aeb: committed };
        }
        catch (error) {
            const outcome = error?.proposalToEffect?.outcome ?? error?.emiliaGateOutcome?.outcome;
            if (outcome === 'executed') {
                await reconcileAebExecutionDurable(options.aeb.store, key, 'COMMITTED');
            }
            else if (outcome !== 'indeterminate') {
                await options.aeb.store.release(key);
            }
            throw error;
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
            || record.requirement_ref !== proposal.aeb.requirement_ref
            || record.caid !== proposal.caid) {
            return refusal('aeb_evaluation_binding_mismatch');
        }
        const artifacts = await options.aeb.resolve_artifacts({ proposal: clone(proposal), evaluation: clone(record) });
        const historical = verifyAebEvaluation(record, {
            config: options.aeb.config,
            adapters: options.aeb.adapters,
            artifacts,
            now: record.evaluated_at,
        });
        if (!historical.valid)
            return refusal('aeb_evaluation_refused', { aeb: historical });
        if (record.verdict !== 'SATISFIED'
            || record.authority_constraints?.one_time_consumption !== true) {
            return refusal('aeb_evaluation_refused', { aeb: historical });
        }
        if (record.composition?.action_digest !== expectedAebCompositionDigest(proposal)) {
            return refusal('aeb_evaluation_binding_mismatch');
        }
        let provider;
        try {
            provider = await options.aeb.verify_provider_evidence({
                evidence: clone(input.provider_evidence),
                expected: {
                    operation_id: proposal.operation_id,
                    caid: proposal.caid,
                    action_digest: proposal.aeb_action_digest,
                },
            });
        }
        catch {
            return refusal('provider_evidence_unverified');
        }
        if (!provider?.valid || (provider.outcome !== 'COMMITTED' && provider.outcome !== 'NOT_COMMITTED')) {
            return refusal(provider?.reason || 'provider_evidence_unverified');
        }
        const key = aebReservationKey(record);
        const reconciled = await reconcileAebExecutionDurable(options.aeb.store, key, provider.outcome);
        if (reconciled.state === 'RECONCILIATION_REQUIRED') {
            return refusal(reconciled.reason, { state: reconciled.state });
        }
        return {
            ok: true,
            state: reconciled.state,
            outcome: provider.outcome,
            evidence_digest: provider.evidence_digest ?? null,
            reservation_key: key,
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
    });
}
export default {
    PROPOSAL_TO_EFFECT_VERSION,
    proposalToEffectConsumptionNonce,
    createProposalToEffect,
};
//# sourceMappingURL=proposal-to-effect.js.map