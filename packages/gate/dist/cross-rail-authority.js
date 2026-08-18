// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Rail-neutral authority admission for agentic commerce.
 *
 * Payment providers retain credentials, custody, settlement, refunds, and
 * dispute handling. Gate decides only whether one exact provider request may
 * enter one configured connector, then issues an opaque permit consumed once
 * inside that connector.
 */
import crypto from 'node:crypto';
import { allowanceDigest, executeWithGateAllowance } from './allowance.js';
import { capabilityActionDigest, capabilityBaseReceiptDigest } from './capability-receipt.js';
import { RISK_CAID, RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskInstant, riskRecord, signRiskBody, signRiskBodyV2, verifyRiskBody, verifyRiskBodyV2, } from './reliance-risk-crypto.js';
export const HUMAN_INTERRUPTION_DECISION_VERSION = 'EP-HUMAN-INTERRUPTION-DECISION-v1';
export const RAIL_ENTRY_PERMIT_VERSION = 'EP-RAIL-ENTRY-PERMIT-v1';
export const CROSS_RAIL_OBSERVATION_VERSION = 'EP-CROSS-RAIL-OBSERVATION-v1';
export const CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY = Object.freeze({
    interruption_decision: 'selects_whether_exact_action_requires_human_interruption_not_authorization_safety_identity_payment_custody_settlement_refund_or_effect',
    rail_entry_permit: 'authorizes_one_entry_to_one_configured_connector_not_funds_availability_payment_custody_settlement_refund_reversibility_or_provider_effect',
    observation: 'minimized_gate_outcome_observation_not_population_completeness_causation_loss_coverage_payment_or_effect_proof',
});
const DECISION_INPUT_KEYS = [
    'decision_id', 'tenant_id', 'subject_id', 'connector_id', 'caid',
    'action_digest', 'provider_request_digest', 'policy_digest',
    'configuration_digest', 'mode', 'reason_codes', 'issued_at', 'expires_at',
];
const DECISION_BODY_KEYS = [
    '@version', ...DECISION_INPUT_KEYS, 'claim_boundary', 'issuer',
];
const PERMIT_BODY_KEYS = [
    '@version', 'permit_id', 'tenant_id', 'subject_id', 'connector_id', 'caid',
    'action_digest', 'provider_request_digest', 'operation_id',
    'authorization_receipt_digest', 'allowance_digest',
    'interruption_decision_digest', 'human_authorization_digest', 'mode',
    'issued_at', 'expires_at', 'single_use', 'claim_boundary', 'issuer',
];
const MODES = new Set(['standing_policy', 'require_human']);
const MAX_DECISION_LIFETIME_MS = 60 * 60 * 1000;
const MAX_REASON_CODES = 32;
function milliseconds(now) {
    const value = typeof now === 'function' ? now() : now;
    if (!Number.isSafeInteger(value) || value < 0)
        throw new TypeError('cross-rail clock must return a non-negative safe integer');
    return value;
}
function sortedUniqueIdentifiers(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_REASON_CODES
        || !value.every(riskIdentifier) || new Set(value).size !== value.length) {
        throw new TypeError('interruption reason_codes are invalid');
    }
    return [...value].sort();
}
function normalizeDecisionInput(input) {
    if (!riskExact(input, DECISION_INPUT_KEYS)
        || !riskIdentifier(input.decision_id) || !riskIdentifier(input.tenant_id)
        || !riskIdentifier(input.subject_id) || !riskIdentifier(input.connector_id)
        || typeof input.caid !== 'string' || !RISK_CAID.test(input.caid)
        || typeof input.action_digest !== 'string' || !RISK_DIGEST.test(input.action_digest)
        || typeof input.provider_request_digest !== 'string' || !RISK_DIGEST.test(input.provider_request_digest)
        || typeof input.policy_digest !== 'string' || !RISK_DIGEST.test(input.policy_digest)
        || typeof input.configuration_digest !== 'string' || !RISK_DIGEST.test(input.configuration_digest)
        || typeof input.mode !== 'string' || !MODES.has(input.mode)) {
        throw new TypeError('interruption decision input is invalid');
    }
    const issued = riskInstant(input.issued_at);
    const expires = riskInstant(input.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued
        || expires - issued > MAX_DECISION_LIFETIME_MS) {
        throw new TypeError('interruption decision lifetime is invalid');
    }
    return {
        ...Object.fromEntries(DECISION_INPUT_KEYS.map((key) => [key, input[key]])),
        reason_codes: sortedUniqueIdentifiers(input.reason_codes),
    };
}
export function signHumanInterruptionDecision(input, signer) {
    const normalized = normalizeDecisionInput(input);
    return signRiskBody(HUMAN_INTERRUPTION_DECISION_VERSION, {
        '@version': HUMAN_INTERRUPTION_DECISION_VERSION,
        ...normalized,
        claim_boundary: CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.interruption_decision,
    }, signer);
}
export function verifyHumanInterruptionDecision(artifact, { trusted_keys, now = Date.now, expected } = {}) {
    const signed = verifyRiskBody(artifact, HUMAN_INTERRUPTION_DECISION_VERSION, trusted_keys);
    if (!signed.valid || !signed.body)
        return { accepted: false, reason: signed.reason === 'issuer_untrusted' ? 'interruption_issuer_untrusted' : 'interruption_signature_invalid' };
    try {
        const body = signed.body;
        if (!riskExact(body, DECISION_BODY_KEYS)
            || body.claim_boundary !== CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.interruption_decision) {
            return { accepted: false, reason: 'interruption_shape_invalid' };
        }
        const normalized = normalizeDecisionInput(Object.fromEntries(DECISION_INPUT_KEYS.map((key) => [key, body[key]])));
        const instant = milliseconds(now);
        if (instant < riskInstant(normalized.issued_at))
            return { accepted: false, reason: 'interruption_not_yet_valid' };
        if (instant >= riskInstant(normalized.expires_at))
            return { accepted: false, reason: 'interruption_expired' };
        if (!expected)
            return { accepted: false, reason: 'interruption_expected_context_required' };
        const comparisons = [
            ['decision_id', 'decision'], ['tenant_id', 'tenant'], ['subject_id', 'subject'],
            ['connector_id', 'connector'], ['caid', 'caid'], ['action_digest', 'action'],
            ['provider_request_digest', 'provider_request'], ['policy_digest', 'policy'],
            ['configuration_digest', 'configuration'], ['mode', 'mode'],
            ['issued_at', 'issued_at'], ['expires_at', 'expires_at'],
        ];
        for (const [field, reason] of comparisons) {
            if (typeof expected[field] === 'string' && expected[field] !== normalized[field]) {
                return { accepted: false, reason: `interruption_${reason}_mismatch` };
            }
        }
        const mandatory = [
            'tenant_id', 'subject_id', 'connector_id', 'caid', 'action_digest', 'provider_request_digest',
        ];
        if (mandatory.some((field) => typeof expected[field] !== 'string' || expected[field].length === 0)) {
            return { accepted: false, reason: 'interruption_expected_context_incomplete' };
        }
        return {
            accepted: true,
            reason: null,
            decision: riskFreeze(riskClone(artifact)),
            decision_digest: signed.artifact_digest,
            mode: normalized.mode,
            expires_at: normalized.expires_at,
        };
    }
    catch {
        return { accepted: false, reason: 'interruption_shape_invalid' };
    }
}
// ===========================================================================
// EP-HUMAN-INTERRUPTION-DECISION-v2 -- opt-in hybrid adoption of EP-RISK-HYBRID-v2
// ===========================================================================
// ADDITIVE: signHumanInterruptionDecision / verifyHumanInterruptionDecision
// above are UNCHANGED. This is the ADOPTION application of "PATTERN: the
// reference hybrid migration" (EP-REVOCATION-v2 is the template) in
// docs/protocol/pq-hybrid-program.md: this artifact already delegates
// signing to reliance-risk-crypto.js's shared signRiskBody/verifyRiskBody,
// so it adopts signRiskBodyV2/verifyRiskBodyV2 (EP-RISK-HYBRID-v2) rather
// than reimplementing the set-shaped proof, the anti-stripping bytes, or the
// pin discipline here. A deployed v1 verifier handed a v2 decision refuses
// on its version/schema check BEFORE inspecting any signature; v2
// verification is a SEPARATE async entry point.
export const HUMAN_INTERRUPTION_DECISION_V2_VERSION = 'EP-HUMAN-INTERRUPTION-DECISION-v2';
/** Mint the hybrid (Ed25519 + ML-DSA-65), set-committed twin of signHumanInterruptionDecision. */
export async function signHumanInterruptionDecisionV2(input, signer, options = {}) {
    const normalized = normalizeDecisionInput(input);
    return signRiskBodyV2(HUMAN_INTERRUPTION_DECISION_V2_VERSION, {
        '@version': HUMAN_INTERRUPTION_DECISION_V2_VERSION,
        ...normalized,
        claim_boundary: CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.interruption_decision,
    }, signer, options);
}
/**
 * FAIL-CLOSED hybrid verify, the set-committed twin of
 * verifyHumanInterruptionDecision. A v2 decision NEVER verifies on one leg
 * alone; an absent ML-DSA backend is a refusal, never a skipped check and
 * never a pass on the surviving classical leg.
 */
export async function verifyHumanInterruptionDecisionV2(artifact, { trusted_keys, now = Date.now, expected, ...pqOptions } = {}) {
    const signed = await verifyRiskBodyV2(artifact, HUMAN_INTERRUPTION_DECISION_V2_VERSION, trusted_keys, pqOptions);
    if (!signed.valid || !signed.body)
        return { accepted: false, reason: signed.reason === 'issuer_untrusted' ? 'interruption_issuer_untrusted' : 'interruption_signature_invalid' };
    try {
        const body = signed.body;
        if (!riskExact(body, DECISION_BODY_KEYS)
            || body.claim_boundary !== CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.interruption_decision) {
            return { accepted: false, reason: 'interruption_shape_invalid' };
        }
        const normalized = normalizeDecisionInput(Object.fromEntries(DECISION_INPUT_KEYS.map((key) => [key, body[key]])));
        const instant = milliseconds(now);
        if (instant < riskInstant(normalized.issued_at))
            return { accepted: false, reason: 'interruption_not_yet_valid' };
        if (instant >= riskInstant(normalized.expires_at))
            return { accepted: false, reason: 'interruption_expired' };
        if (!expected)
            return { accepted: false, reason: 'interruption_expected_context_required' };
        const comparisons = [
            ['decision_id', 'decision'], ['tenant_id', 'tenant'], ['subject_id', 'subject'],
            ['connector_id', 'connector'], ['caid', 'caid'], ['action_digest', 'action'],
            ['provider_request_digest', 'provider_request'], ['policy_digest', 'policy'],
            ['configuration_digest', 'configuration'], ['mode', 'mode'],
            ['issued_at', 'issued_at'], ['expires_at', 'expires_at'],
        ];
        for (const [field, reason] of comparisons) {
            if (typeof expected[field] === 'string' && expected[field] !== normalized[field]) {
                return { accepted: false, reason: `interruption_${reason}_mismatch` };
            }
        }
        const mandatory = [
            'tenant_id', 'subject_id', 'connector_id', 'caid', 'action_digest', 'provider_request_digest',
        ];
        if (mandatory.some((field) => typeof expected[field] !== 'string' || expected[field].length === 0)) {
            return { accepted: false, reason: 'interruption_expected_context_incomplete' };
        }
        return {
            accepted: true,
            reason: null,
            decision: riskFreeze(riskClone(artifact)),
            decision_digest: signed.artifact_digest,
            mode: normalized.mode,
            expires_at: normalized.expires_at,
        };
    }
    catch {
        return { accepted: false, reason: 'interruption_shape_invalid' };
    }
}
// ===========================================================================
// EP-RAIL-ENTRY-PERMIT-v2 -- opt-in hybrid adoption of EP-RISK-HYBRID-v2
// ===========================================================================
// ADDITIVE: createRailEntryPermitBroker's v1 mint/consume flow below is
// UNCHANGED. This is the artifact-level ADOPTION of "PATTERN: the reference
// hybrid migration" (EP-REVOCATION-v2 is the template): the permit BODY (the
// signed artifact) migrates to signRiskBodyV2/verifyRiskBodyV2
// (EP-RISK-HYBRID-v2), exactly mirroring the shape mintPermit/consumePermit
// build and check below, one version bump ahead. The stateful single-use
// broker (WeakMap-scoped replay prevention, TTL pruning, capacity bounds) is
// an operational concern independent of the signature algorithm and is left
// on the v1 path; a caller wiring the hybrid permit into that broker signs
// with signRailEntryPermitV2 and verifies with verifyRailEntryPermitV2 using
// the same field discipline the broker already enforces around it.
export const RAIL_ENTRY_PERMIT_V2_VERSION = 'EP-RAIL-ENTRY-PERMIT-v2';
/** Mint the hybrid (Ed25519 + ML-DSA-65), set-committed twin of a v1 rail-entry permit body. */
export async function signRailEntryPermitV2(input, signer, options = {}) {
    const body = {
        ...input,
        '@version': RAIL_ENTRY_PERMIT_V2_VERSION,
    };
    return signRiskBodyV2(RAIL_ENTRY_PERMIT_V2_VERSION, body, signer, options);
}
/**
 * FAIL-CLOSED hybrid verify, the set-committed twin of the v1 consumePermit
 * signature/shape check. A v2 permit NEVER verifies on one leg alone; an
 * absent ML-DSA backend is a refusal, never a skipped check and never a pass
 * on the surviving classical leg.
 */
export async function verifyRailEntryPermitV2(artifact, trustedKeys, options = {}) {
    const signed = await verifyRiskBodyV2(artifact, RAIL_ENTRY_PERMIT_V2_VERSION, trustedKeys, options);
    if (!signed.valid || !signed.body)
        return signed;
    if (!riskExact(signed.body, PERMIT_BODY_KEYS)) {
        return { valid: false, reason: 'rail_entry_permit_shape_invalid', body: null, artifact_digest: null };
    }
    return signed;
}
const permitBrokers = new WeakMap();
function pruneExpired(state, instant) {
    for (const [handle, artifact] of state.permits) {
        if (riskInstant(artifact.expires_at) <= instant)
            state.permits.delete(handle);
    }
}
export function createRailEntryPermitBroker({ signer, now = Date.now, max_ttl_ms = 30_000, max_active_permits = 1_000, } = {}) {
    if (!signer || !riskIdentifier(signer.issuer_id) || !riskIdentifier(signer.key_id)) {
        throw new TypeError('rail-entry permit signer is required');
    }
    if (!Number.isSafeInteger(max_ttl_ms) || max_ttl_ms < 1_000 || max_ttl_ms > 60_000
        || !Number.isSafeInteger(max_active_permits) || max_active_permits < 1 || max_active_permits > 100_000) {
        throw new TypeError('rail-entry permit broker bounds are invalid');
    }
    const key = signer.private_key instanceof crypto.KeyObject
        ? signer.private_key : crypto.createPrivateKey(signer.private_key);
    if (key.asymmetricKeyType !== 'ed25519')
        throw new TypeError('rail-entry permit key must be Ed25519');
    const publicKey = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
    const broker = Object.freeze({});
    permitBrokers.set(broker, {
        signer: { ...signer, private_key: key },
        trustedKeys: { [signer.key_id]: { issuer_id: signer.issuer_id, public_key: publicKey } },
        now, maxTtlMs: max_ttl_ms, maxActive: max_active_permits, permits: new Map(),
    });
    return broker;
}
function mintPermit(broker, input) {
    const state = permitBrokers.get(broker);
    if (!state)
        throw new TypeError('configured rail-entry permit broker required');
    const instant = milliseconds(state.now);
    pruneExpired(state, instant);
    if (state.permits.size >= state.maxActive)
        throw new Error('rail_entry_permit_capacity_exceeded');
    const permitId = `permit:${crypto.randomUUID()}`;
    const issuedAt = new Date(instant).toISOString();
    const notAfter = riskInstant(input.not_after);
    if (!Number.isFinite(notAfter) || notAfter <= instant)
        throw new Error('rail_entry_permit_parent_expired');
    const expiresAt = new Date(Math.min(instant + state.maxTtlMs, notAfter)).toISOString();
    const body = {
        '@version': RAIL_ENTRY_PERMIT_VERSION,
        permit_id: permitId,
        tenant_id: input.tenant_id,
        subject_id: input.subject_id,
        connector_id: input.connector_id,
        caid: input.caid,
        action_digest: input.action_digest,
        provider_request_digest: input.provider_request_digest,
        operation_id: input.operation_id,
        authorization_receipt_digest: input.authorization_receipt_digest,
        allowance_digest: input.allowance_digest,
        interruption_decision_digest: input.interruption_decision_digest,
        human_authorization_digest: input.human_authorization_digest,
        mode: input.mode,
        issued_at: issuedAt,
        expires_at: expiresAt,
        single_use: true,
        claim_boundary: CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.rail_entry_permit,
    };
    const artifact = signRiskBody(RAIL_ENTRY_PERMIT_VERSION, body, state.signer);
    const handle = crypto.randomBytes(32).toString('base64url');
    state.permits.set(handle, artifact);
    return { handle, permit_digest: riskDigest(artifact), permit_version: RAIL_ENTRY_PERMIT_VERSION };
}
function consumePermit(broker, handle, expected) {
    const state = permitBrokers.get(broker);
    if (!state || typeof handle !== 'string')
        return { ok: false, reason: 'rail_entry_permit_unknown' };
    const instant = milliseconds(state.now);
    pruneExpired(state, instant);
    const artifact = state.permits.get(handle);
    if (!artifact)
        return { ok: false, reason: 'rail_entry_permit_unknown' };
    state.permits.delete(handle);
    const signed = verifyRiskBody(artifact, RAIL_ENTRY_PERMIT_VERSION, state.trustedKeys);
    if (!signed.valid || !signed.body || !riskExact(signed.body, PERMIT_BODY_KEYS)) {
        return { ok: false, reason: 'rail_entry_permit_invalid' };
    }
    const body = signed.body;
    const exact = body.claim_boundary === CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.rail_entry_permit
        && body.single_use === true && riskInstant(body.issued_at) <= instant && instant < riskInstant(body.expires_at)
        && riskIdentifier(body.permit_id) && riskIdentifier(body.tenant_id) && riskIdentifier(body.subject_id)
        && riskIdentifier(body.connector_id) && typeof body.caid === 'string' && RISK_CAID.test(body.caid)
        && RISK_DIGEST.test(body.action_digest) && RISK_DIGEST.test(body.provider_request_digest)
        && riskIdentifier(body.operation_id) && RISK_DIGEST.test(body.authorization_receipt_digest)
        && RISK_DIGEST.test(body.allowance_digest) && RISK_DIGEST.test(body.interruption_decision_digest)
        && (body.human_authorization_digest === null || RISK_DIGEST.test(body.human_authorization_digest))
        && MODES.has(body.mode)
        && ['tenant_id', 'subject_id', 'connector_id', 'caid', 'action_digest', 'provider_request_digest',
            'operation_id', 'authorization_receipt_digest', 'allowance_digest', 'interruption_decision_digest',
            'human_authorization_digest', 'mode'].every((field) => body[field] === expected[field]);
    return exact
        ? { ok: true, permit_digest: signed.artifact_digest, permit: riskFreeze(riskClone(artifact)) }
        : { ok: false, reason: 'rail_entry_permit_binding_mismatch' };
}
const connectors = new WeakMap();
export function createCrossRailConnector({ connector_id, rail, action_class, action_type, project_request, resolve_caid, invoke, } = {}) {
    if (!riskIdentifier(connector_id) || !riskIdentifier(rail) || !riskIdentifier(action_class)
        || !riskIdentifier(action_type) || typeof project_request !== 'function'
        || typeof resolve_caid !== 'function' || typeof invoke !== 'function') {
        throw new TypeError('cross-rail connector configuration is invalid');
    }
    const connector = Object.freeze({});
    connectors.set(connector, {
        connectorId: connector_id, rail, actionClass: action_class, actionType: action_type,
        project: project_request, resolveCaid: resolve_caid, invoke,
    });
    return connector;
}
function projectConnectorRequest(state, request) {
    if (!riskRecord(request))
        throw new TypeError('cross-rail request must be a strict JSON object');
    const projected = state.project(riskClone(request));
    if (!riskExact(projected, ['action', 'provider_request'])
        || !riskRecord(projected.action) || !riskRecord(projected.provider_request)
        || projected.action.action_type !== state.actionType) {
        throw new TypeError('cross-rail connector projection is invalid');
    }
    const action = riskFreeze(riskClone(projected.action));
    const providerRequest = riskFreeze(riskClone(projected.provider_request));
    const caid = state.resolveCaid(riskClone(action));
    if (typeof caid !== 'string' || !RISK_CAID.test(caid))
        throw new TypeError('cross-rail CAID resolution failed');
    return {
        action,
        provider_request: providerRequest,
        caid,
        action_digest: capabilityActionDigest(action),
        provider_request_digest: riskDigest(providerRequest),
    };
}
function reasonClass(reason) {
    if (reason === 'effect_indeterminate' || reason === 'capability_commit_indeterminate')
        return 'indeterminate';
    if (typeof reason !== 'string')
        return 'internal';
    if (reason.includes('status') || reason.includes('expired') || reason.includes('current'))
        return 'status';
    if (reason.includes('provider') || reason.includes('permit'))
        return 'provider';
    if (reason.includes('scope') || reason.includes('action') || reason.includes('target') || reason.includes('amount'))
        return 'scope';
    return 'authorization';
}
async function emitObservation(observe, state, mode, result, now) {
    if (typeof observe !== 'function')
        return;
    const outcome = result.ok === true ? 'executed'
        : (result.reason === 'effect_indeterminate' || result.reason === 'capability_commit_indeterminate') ? 'indeterminate' : 'refused';
    const event = riskFreeze({
        '@version': CROSS_RAIL_OBSERVATION_VERSION,
        connector_class: state.rail,
        action_class: state.actionClass,
        human_interruption: mode === 'require_human',
        outcome,
        reason_class: result.ok === true ? 'none' : reasonClass(result.reason),
        occurred_at: new Date(milliseconds(now)).toISOString(),
    });
    try {
        await observe(event);
    }
    catch { /* Observation cannot rewrite an effect outcome. */ }
}
/**
 * Authorize one exact request into one configured payment connector.
 * The provider invocation happens only after allowance verification, current
 * status, atomic reservation, optional exact human authorization, and an
 * internally consumed one-use permit.
 */
export async function executeCrossRailAllowance(options = {}) {
    const state = connectors.get(options.connector);
    if (!state)
        return { ok: false, reason: 'cross_rail_connector_required' };
    if (!permitBrokers.has(options.permit_broker))
        return { ok: false, reason: 'rail_entry_permit_broker_required' };
    let projection;
    try {
        projection = projectConnectorRequest(state, options.request);
    }
    catch {
        return { ok: false, reason: 'cross_rail_projection_invalid' };
    }
    if (!riskRecord(options.expected) || options.expected.connector_id !== state.connectorId) {
        return { ok: false, reason: 'cross_rail_expected_connector_mismatch' };
    }
    if (!riskExact(options.expectedInterruption, ['policy_digest', 'configuration_digest'])
        || !RISK_DIGEST.test(options.expectedInterruption.policy_digest)
        || !RISK_DIGEST.test(options.expectedInterruption.configuration_digest)) {
        return { ok: false, reason: 'interruption_expected_policy_required' };
    }
    const decision = verifyHumanInterruptionDecision(options.interruption_decision, {
        trusted_keys: options.trustedInterruptionKeys,
        now: options.now ?? Date.now,
        expected: {
            tenant_id: options.expected.tenant_id,
            subject_id: options.expected.subject_id,
            connector_id: state.connectorId,
            caid: projection.caid,
            action_digest: projection.action_digest,
            provider_request_digest: projection.provider_request_digest,
            policy_digest: options.expectedInterruption.policy_digest,
            configuration_digest: options.expectedInterruption.configuration_digest,
        },
    });
    if (!decision.accepted)
        return { ok: false, reason: decision.reason };
    let humanAuthorizationDigest = null;
    if (decision.mode === 'require_human') {
        if (options.human_authorization === undefined || typeof options.verifyHumanAuthorization !== 'function') {
            return { ok: false, reason: 'human_authorization_required' };
        }
        let human;
        try {
            human = await options.verifyHumanAuthorization(riskClone(options.human_authorization), {
                interruption_decision_digest: decision.decision_digest,
                caid: projection.caid,
                action_digest: projection.action_digest,
                provider_request_digest: projection.provider_request_digest,
                connector_id: state.connectorId,
            });
        }
        catch {
            return { ok: false, reason: 'human_authorization_verification_failed' };
        }
        if (!riskRecord(human) || human.ok !== true || human.human_authorized !== true
            || human.interruption_decision_digest !== decision.decision_digest
            || human.caid !== projection.caid || human.action_digest !== projection.action_digest
            || human.provider_request_digest !== projection.provider_request_digest
            || typeof human.artifact_digest !== 'string' || !RISK_DIGEST.test(human.artifact_digest)) {
            return { ok: false, reason: 'human_authorization_binding_failed' };
        }
        humanAuthorizationDigest = human.artifact_digest;
    }
    const authorizationReceipt = options.capabilityReceipt?.receipt;
    if (!riskRecord(authorizationReceipt))
        return { ok: false, reason: 'cross_rail_authorization_receipt_required' };
    const permitExpected = {
        tenant_id: options.expected.tenant_id,
        subject_id: options.expected.subject_id,
        connector_id: state.connectorId,
        caid: projection.caid,
        action_digest: projection.action_digest,
        provider_request_digest: projection.provider_request_digest,
        operation_id: options.operationId,
        authorization_receipt_digest: capabilityBaseReceiptDigest(authorizationReceipt),
        allowance_digest: allowanceDigest(options.allowance),
        interruption_decision_digest: decision.decision_digest,
        human_authorization_digest: humanAuthorizationDigest,
        mode: decision.mode,
        not_after: decision.expires_at,
    };
    const permitState = { current: null };
    let permitConsumed = false;
    const result = await executeWithGateAllowance({
        allowance: options.allowance,
        capabilityReceipt: options.capabilityReceipt,
        secret: options.secret,
        action: projection.action,
        operationId: options.operationId,
        store: options.store,
        verifyAuthorizationReceipt: options.verifyAuthorizationReceipt,
        verifyAllowanceStatus: options.verifyAllowanceStatus,
        trustedAllowanceKeys: options.trustedAllowanceKeys,
        trustedCapabilityIssuerKeys: options.trustedCapabilityIssuerKeys,
        expected: options.expected,
        now: options.now ?? Date.now,
        providerEntryGuard: (context) => {
            if (context.capability?.action_digest !== projection.action_digest) {
                return { ok: false, reason: 'rail_entry_action_binding_failed' };
            }
            try {
                permitState.current = mintPermit(options.permit_broker, permitExpected);
                return { ok: true, evidence: { permit_digest: permitState.current.permit_digest } };
            }
            catch (error) {
                return { ok: false, reason: error?.message || 'rail_entry_permit_mint_failed' };
            }
        },
        executeAction: async (_verifiedAction, context) => {
            const permit = permitState.current;
            if (!permit)
                throw new Error('rail_entry_permit_missing');
            const consumed = consumePermit(options.permit_broker, permit.handle, permitExpected);
            if (!consumed.ok)
                throw new Error(consumed.reason);
            permitConsumed = true;
            return state.invoke(riskClone(projection.provider_request), riskFreeze({
                connector_id: state.connectorId,
                rail: state.rail,
                caid: projection.caid,
                action_digest: context.action_digest,
                provider_request_digest: projection.provider_request_digest,
                operation_id: context.operation_id,
                permit_digest: consumed.permit_digest,
                permit_version: RAIL_ENTRY_PERMIT_VERSION,
            }));
        },
    });
    await emitObservation(options.observe, state, decision.mode, result, options.now ?? Date.now);
    const issuedPermit = permitState.current;
    return issuedPermit
        ? {
            ...result,
            rail_entry_permit_digest: issuedPermit.permit_digest,
            rail_entry_permit_version: issuedPermit.permit_version,
            rail_entry_permit_consumed: permitConsumed,
        }
        : result;
}
export default {
    HUMAN_INTERRUPTION_DECISION_VERSION,
    RAIL_ENTRY_PERMIT_VERSION,
    CROSS_RAIL_OBSERVATION_VERSION,
    CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY,
    signHumanInterruptionDecision,
    verifyHumanInterruptionDecision,
    createRailEntryPermitBroker,
    createCrossRailConnector,
    executeCrossRailAllowance,
    HUMAN_INTERRUPTION_DECISION_V2_VERSION,
    signHumanInterruptionDecisionV2,
    verifyHumanInterruptionDecisionV2,
    RAIL_ENTRY_PERMIT_V2_VERSION,
    signRailEntryPermitV2,
    verifyRailEntryPermitV2,
};
//# sourceMappingURL=cross-rail-authority.js.map