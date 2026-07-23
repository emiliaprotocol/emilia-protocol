// SPDX-License-Identifier: Apache-2.0
/**
 * Fail-closed verifier for draft-nivalto-agentroa-route-authorization-01.
 *
 * This module verifies one root ROA envelope, its ordered ARA delegation
 * chain, and the resulting AER under relying-party-owned, role-scoped Ed25519
 * pins. It intentionally does not perform key discovery, wildcard expansion,
 * policy retrieval, or time discovery from presenter-controlled material.
 *
 * A successful PERMIT result is suitable for use as an EP-AEC custom verifier:
 * it returns the digest of the exact AgentROA AER action only after the caller's
 * action is byte-for-byte equal under JCS. A signed DENY remains verified
 * negative evidence but never becomes a valid authorization component.
 *
 * AgentROA AERs are pre-execution enforcement decisions. They do not prove
 * that the protected operation subsequently executed or succeeded.
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
export const AGENTROA_DRAFT = 'draft-nivalto-agentroa-route-authorization-01';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ENVELOPE_ID = /^env:[0-9a-f]{16}$/;
const ARA_ID = /^ara:[0-9a-f]{16}$/;
const AER_ID = /^aer:[0-9a-f]{16}$/;
const AGENT_ID = /^aha:[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const CHANNELS = new Set(['api', 'mcp_client', 'voice', 'browser', 'mobile_app']);
const AUTH_STRENGTHS = new Set(['session_only', 'device_bound', 'device_bound_with_attestation', 'dual_control']);
const APPROVAL_STATES = new Set(['pending', 'granted', 'not_required']);
const OUTCOMES = new Set(['permit', 'deny']);
const MODES = new Set(['normal', 'degraded']);
const TOPOLOGIES = new Set([
    'topology_a_protocol_proxy',
    'topology_b_service_mesh',
    'topology_c_egress_gateway',
    'topology_d_domain_boundary',
]);
const DENIAL_REASONS = new Set([
    'invalid_signature',
    'envelope_expired',
    'envelope_revoked',
    'replay_detected',
    'chain_integrity_violation',
    'scope_expansion_violation',
    'budget_expansion_denied',
    'slo_relaxation_denied',
    'capability_not_in_scope',
    'policy_digest_mismatch',
    'approval_required',
    'auth_strength_insufficient',
]);
const MAX_CHAIN_DEPTH = 32;
const MAX_CAPABILITIES = 256;
const MAX_SIGNATURES = 8;
const MAX_PROVENANCE = 128;
const MAX_STRING_BYTES = 4096;
const RESULT_BASE = Object.freeze({
    valid: false,
    verified: false,
    action_digest: null,
    decision: null,
    pre_execution: false,
    execution_proven: false,
    enforcement_mode: null,
    chain_depth: null,
});
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
function record(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}
function nonEmptyString(value, maxBytes = MAX_STRING_BYTES) {
    return typeof value === 'string'
        && value.length > 0
        && Buffer.byteLength(value, 'utf8') <= maxBytes
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function exactObject(value, required, optional = []) {
    if (!record(value))
        return false;
    const allowed = new Set([...required, ...optional]);
    const keys = Object.keys(value);
    return required.every((key) => own(value, key))
        && keys.every((key) => allowed.has(key));
}
function exactArrayOfStrings(value, { min = 0, max = MAX_CAPABILITIES, unique = false } = {}) {
    if (!Array.isArray(value) || value.length < min || value.length > max)
        return false;
    if (!value.every((item) => nonEmptyString(item)))
        return false;
    return !unique || new Set(value).size === value.length;
}
function nonNegativeNumber(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}
function nonNegativeInteger(value) {
    return Number.isSafeInteger(value) && value >= 0;
}
function instantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = RFC3339.exec(value);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second, , , offsetHour, offsetMinute] = match;
    if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))
        return NaN;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
        return NaN;
    return Date.parse(value);
}
function sha256(value) {
    return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}
function canonicalBase64url(value, expectedBytes) {
    if (typeof value !== 'string' || value.length === 0
        || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value)
        return null;
    return expectedBytes === undefined || decoded.length === expectedBytes ? decoded : null;
}
function loadEd25519Key(value) {
    try {
        if (typeof value !== 'string' || value.length === 0)
            return null;
        let key;
        if (value.includes('-----BEGIN')) {
            key = crypto.createPublicKey(value);
        }
        else {
            const der = canonicalBase64url(value);
            if (!der || der.length === 0)
                return null;
            key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
        }
        return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    catch {
        return null;
    }
}
function validSignatureEnvelope(signatures) {
    if (!Array.isArray(signatures) || signatures.length === 0 || signatures.length > MAX_SIGNATURES)
        return false;
    const signers = new Set();
    for (const signature of signatures) {
        if (!exactObject(signature, ['signer', 'alg', 'sig'])
            || !nonEmptyString(signature.signer)
            || signature.alg !== 'EdDSA'
            || !canonicalBase64url(signature.sig, 64)
            || signers.has(signature.signer))
            return false;
        signers.add(signature.signer);
    }
    return true;
}
function signingBytes(object) {
    const body = {};
    for (const [key, value] of Object.entries(object)) {
        if (key !== 'signatures')
            body[key] = value;
    }
    return Buffer.from(canonicalize(body), 'utf8');
}
function verifySignatures(object, pins, role, expectedSigner = null) {
    if (!record(pins))
        return `missing_${role}_key_pins`;
    const bytes = signingBytes(object);
    for (const signature of object.signatures) {
        if (expectedSigner !== null && signature.signer !== expectedSigner) {
            return `${role}_signer_mismatch`;
        }
        if (!own(pins, signature.signer))
            return `unpinned_${role}_signer`;
        const key = loadEd25519Key(pins[signature.signer]);
        if (!key)
            return `invalid_${role}_key`;
        let verified = false;
        try {
            verified = crypto.verify(null, bytes, key, Buffer.from(signature.sig, 'base64url'));
        }
        catch {
            verified = false;
        }
        if (!verified)
            return `invalid_${role}_signature`;
    }
    return null;
}
function validCapability(value, { wildcard = true } = {}) {
    if (!nonEmptyString(value, 512) || /\s/.test(value) || !value.includes(':'))
        return false;
    const stars = [...value].filter((character) => character === '*').length;
    if (stars === 0)
        return true;
    return wildcard && stars === 1 && value.endsWith('.*');
}
function validCapabilities(value) {
    return exactArrayOfStrings(value, { min: 1, max: MAX_CAPABILITIES, unique: true })
        && value.every((capability) => validCapability(capability));
}
function validSession(session, { aer = false } = {}) {
    if (!exactObject(session, ['session_id', 'agent_id'], aer
        ? ['device_attestation_ref']
        : ['channel', 'device_attestation_ref']))
        return false;
    if (!nonEmptyString(session.session_id) || !AGENT_ID.test(session.agent_id))
        return false;
    if (!aer && !CHANNELS.has(session.channel))
        return false;
    if (own(session, 'device_attestation_ref')) {
        if (aer && session.device_attestation_ref === null)
            return true;
        if (!nonEmptyString(session.device_attestation_ref))
            return false;
    }
    return true;
}
function validRootScope(scope) {
    if (!exactObject(scope, ['capabilities', 'max_delegation_depth', 'cross_org_permitted'], ['data_classification_ceiling', 'budget_ceiling', 'budget_unit', 'price_class', 'slo_class']))
        return false;
    if (!validCapabilities(scope.capabilities)
        || !nonNegativeInteger(scope.max_delegation_depth)
        || scope.max_delegation_depth > MAX_CHAIN_DEPTH
        || typeof scope.cross_org_permitted !== 'boolean')
        return false;
    if (own(scope, 'data_classification_ceiling') && !nonEmptyString(scope.data_classification_ceiling))
        return false;
    if (own(scope, 'budget_ceiling') !== own(scope, 'budget_unit'))
        return false;
    if (own(scope, 'budget_ceiling')
        && (!nonNegativeNumber(scope.budget_ceiling) || !nonEmptyString(scope.budget_unit, 64)))
        return false;
    if (own(scope, 'price_class') && !nonNegativeInteger(scope.price_class))
        return false;
    if (own(scope, 'slo_class') && !nonNegativeInteger(scope.slo_class))
        return false;
    return true;
}
function validPolicy(policy, { root = false } = {}) {
    if (!exactObject(policy, root ? ['policy_id', 'policy_version', 'policy_digest'] : ['policy_digest', 'policy_version'], root ? ['policy_uri'] : []))
        return false;
    if ((root && !nonEmptyString(policy.policy_id))
        || !nonEmptyString(policy.policy_version)
        || !SHA256.test(policy.policy_digest))
        return false;
    if (root && own(policy, 'policy_uri')) {
        try {
            const uri = new URL(policy.policy_uri);
            if (!uri.protocol)
                return false;
        }
        catch {
            return false;
        }
    }
    return true;
}
function validRoot(root) {
    if (!exactObject(root, [
        'schema_version',
        'envelope_id',
        'issued_at',
        'expires_at',
        'session',
        'authorized_scope',
        'policy',
        'authorization',
        'evidence',
        'signatures',
    ]))
        return false;
    if (root.schema_version !== '1.0'
        || !ENVELOPE_ID.test(root.envelope_id)
        || !Number.isFinite(instantMs(root.issued_at))
        || !Number.isFinite(instantMs(root.expires_at))
        || !validSession(root.session)
        || !validRootScope(root.authorized_scope)
        || !validPolicy(root.policy, { root: true }))
        return false;
    if (!exactObject(root.authorization, ['auth_strength', 'approval_state'], ['approval_artifact_ref'])
        || !AUTH_STRENGTHS.has(root.authorization.auth_strength)
        || !APPROVAL_STATES.has(root.authorization.approval_state)
        || (own(root.authorization, 'approval_artifact_ref')
            && !nonEmptyString(root.authorization.approval_artifact_ref)))
        return false;
    if (!exactObject(root.evidence, ['session_hash', 'model_provenance'])
        || !SHA256.test(root.evidence.session_hash)
        || !exactArrayOfStrings(root.evidence.model_provenance, { max: MAX_PROVENANCE, unique: true })
        || !validSignatureEnvelope(root.signatures))
        return false;
    return true;
}
function validDelegatedScope(scope) {
    // budget/price/SLO are included because Sections 4.3 and 5.3 normatively
    // require them even though the Section 5.1 field list omits them.
    if (!exactObject(scope, ['capabilities', 'max_delegation_depth'], ['task_context', 'budget_ceiling', 'budget_unit', 'price_class', 'slo_class']))
        return false;
    if (!validCapabilities(scope.capabilities)
        || !nonNegativeInteger(scope.max_delegation_depth)
        || scope.max_delegation_depth > MAX_CHAIN_DEPTH)
        return false;
    if (own(scope, 'task_context') && !nonEmptyString(scope.task_context))
        return false;
    if (own(scope, 'budget_ceiling') !== own(scope, 'budget_unit'))
        return false;
    if (own(scope, 'budget_ceiling')
        && (!nonNegativeNumber(scope.budget_ceiling) || !nonEmptyString(scope.budget_unit, 64)))
        return false;
    if (own(scope, 'price_class') && !nonNegativeInteger(scope.price_class))
        return false;
    if (own(scope, 'slo_class') && !nonNegativeInteger(scope.slo_class))
        return false;
    return true;
}
function validARA(ara) {
    if (!exactObject(ara, [
        'schema_version',
        'ara_id',
        'issued_at',
        'upstream_ref',
        'delegating_agent',
        'delegated_agent',
        'delegated_scope',
        'policy',
        'signatures',
    ]))
        return false;
    if (ara.schema_version !== '1.0'
        || !ARA_ID.test(ara.ara_id)
        || !Number.isFinite(instantMs(ara.issued_at)))
        return false;
    if (!exactObject(ara.upstream_ref, ['ref_type', 'ref_id', 'ref_digest'])
        || !new Set(['roa_envelope', 'ara']).has(ara.upstream_ref.ref_type)
        || !nonEmptyString(ara.upstream_ref.ref_id)
        || !SHA256.test(ara.upstream_ref.ref_digest))
        return false;
    if (!exactObject(ara.delegating_agent, ['agent_id', 'session_id'])
        || !AGENT_ID.test(ara.delegating_agent.agent_id)
        || !nonEmptyString(ara.delegating_agent.session_id))
        return false;
    if (!exactObject(ara.delegated_agent, ['agent_id'], ['capability_declaration_ref'])
        || !AGENT_ID.test(ara.delegated_agent.agent_id)
        || (own(ara.delegated_agent, 'capability_declaration_ref')
            && !nonEmptyString(ara.delegated_agent.capability_declaration_ref)))
        return false;
    return validDelegatedScope(ara.delegated_scope)
        && validPolicy(ara.policy)
        && validSignatureEnvelope(ara.signatures);
}
function validAction(action) {
    return exactObject(action, ['capability', 'target_service_id', 'operation', 'input_hash'])
        && validCapability(action.capability)
        && nonEmptyString(action.target_service_id)
        && nonEmptyString(action.operation)
        && SHA256.test(action.input_hash);
}
function validAER(aer) {
    if (!exactObject(aer, [
        'schema_version',
        'aer_id',
        'produced_at',
        'enforcement_outcome',
        'enforcement_mode',
        'session',
        'action',
        'policy',
        'chain_summary',
        'border_gateway',
        'signatures',
    ], ['deployment_topology', 'denial_reason', 'plan_hash']))
        return false;
    if (aer.schema_version !== '1.0'
        || !AER_ID.test(aer.aer_id)
        || !Number.isFinite(instantMs(aer.produced_at))
        || !OUTCOMES.has(aer.enforcement_outcome)
        || !MODES.has(aer.enforcement_mode)
        || (own(aer, 'deployment_topology') && !TOPOLOGIES.has(aer.deployment_topology))
        || !validSession(aer.session, { aer: true })
        || !validAction(aer.action))
        return false;
    if (aer.enforcement_outcome === 'permit' && own(aer, 'denial_reason'))
        return false;
    if (aer.enforcement_outcome === 'deny'
        && (!own(aer, 'denial_reason') || !DENIAL_REASONS.has(aer.denial_reason)))
        return false;
    if (!exactObject(aer.policy, ['policy_id', 'policy_digest'])
        || !nonEmptyString(aer.policy.policy_id)
        || !SHA256.test(aer.policy.policy_digest))
        return false;
    if (!exactObject(aer.chain_summary, ['chain_depth', 'root_envelope_id', 'chain_digest'])
        || !nonNegativeInteger(aer.chain_summary.chain_depth)
        || !ENVELOPE_ID.test(aer.chain_summary.root_envelope_id)
        || !SHA256.test(aer.chain_summary.chain_digest))
        return false;
    if (!exactObject(aer.border_gateway, ['gateway_id', 'gateway_version'])
        || !nonEmptyString(aer.border_gateway.gateway_id)
        || !nonEmptyString(aer.border_gateway.gateway_version))
        return false;
    if (own(aer, 'plan_hash') && !SHA256.test(aer.plan_hash))
        return false;
    return validSignatureEnvelope(aer.signatures);
}
function validateManifest(manifest) {
    if (!record(manifest))
        return false;
    for (const [wildcard, entries] of Object.entries(manifest)) {
        if (!validCapability(wildcard) || !wildcard.endsWith('.*')
            || !exactArrayOfStrings(entries, { min: 1, max: MAX_CAPABILITIES, unique: true })
            || !entries.every((entry) => validCapability(entry, { wildcard: false })))
            return false;
    }
    return true;
}
function validateProfile(profile) {
    if (!exactObject(profile, [
        'expected_policy_id',
        'expected_policy_version',
        'expected_policy_digest',
        'allow_degraded',
        'allowed_topologies',
        'capability_manifest',
    ]))
        return false;
    return nonEmptyString(profile.expected_policy_id)
        && nonEmptyString(profile.expected_policy_version)
        && SHA256.test(profile.expected_policy_digest)
        && typeof profile.allow_degraded === 'boolean'
        && Array.isArray(profile.allowed_topologies)
        && profile.allowed_topologies.length > 0
        && profile.allowed_topologies.length <= TOPOLOGIES.size
        && new Set(profile.allowed_topologies).size === profile.allowed_topologies.length
        && profile.allowed_topologies.every((topology) => TOPOLOGIES.has(topology))
        && validateManifest(profile.capability_manifest);
}
/**
 * @param {string[]} capabilities
 * @param {Record<string, string[]>} manifest
 * @returns {{ ok: true, capabilities: Set<string> } | { ok: false, reason: string }}
 */
function resolveCapabilities(capabilities, manifest) {
    const resolved = new Set();
    for (const capability of capabilities) {
        if (!capability.includes('*')) {
            resolved.add(capability);
            continue;
        }
        if (!own(manifest, capability))
            return { ok: false, reason: 'ambiguous_capability_wildcard' };
        for (const concrete of manifest[capability])
            resolved.add(concrete);
    }
    return { ok: true, capabilities: resolved };
}
function organization(agentId) {
    return agentId.slice(4).split('/')[0];
}
function narrowScope(parent, child, manifest) {
    const parentCapabilities = resolveCapabilities(parent.capabilities, manifest);
    if (!parentCapabilities.ok)
        return parentCapabilities.reason;
    const childCapabilities = resolveCapabilities(child.capabilities, manifest);
    if (!childCapabilities.ok)
        return childCapabilities.reason;
    for (const capability of childCapabilities.capabilities) {
        if (!parentCapabilities.capabilities.has(capability))
            return 'scope_expansion';
    }
    if (own(parent, 'budget_ceiling') && !own(child, 'budget_ceiling'))
        return 'budget_constraint_omitted';
    if (own(child, 'budget_ceiling')) {
        if (own(parent, 'budget_ceiling') && child.budget_ceiling > parent.budget_ceiling)
            return 'budget_expansion';
        if (own(parent, 'budget_unit') && child.budget_unit !== parent.budget_unit)
            return 'budget_unit_mismatch';
    }
    if (own(parent, 'price_class') && !own(child, 'price_class'))
        return 'price_class_constraint_omitted';
    if (own(child, 'price_class') && own(parent, 'price_class') && child.price_class > parent.price_class) {
        return 'price_class_expansion';
    }
    if (own(parent, 'slo_class') && !own(child, 'slo_class'))
        return 'slo_constraint_omitted';
    if (own(child, 'slo_class') && own(parent, 'slo_class') && child.slo_class < parent.slo_class) {
        return 'slo_relaxation';
    }
    if (child.max_delegation_depth >= parent.max_delegation_depth)
        return 'delegation_depth_not_narrowed';
    return null;
}
function refusal(reason, extra = {}) {
    return { ...RESULT_BASE, ...extra, valid: false, reason };
}
function verifyAgentROAInternal(evidence, context) {
    if (!exactObject(evidence, ['chain', 'aer']))
        return refusal('malformed_agentroa_bundle');
    if (!Array.isArray(evidence.chain)
        || evidence.chain.length === 0
        || evidence.chain.length > MAX_CHAIN_DEPTH + 1)
        return refusal('malformed_agentroa_chain');
    const [root, ...aras] = evidence.chain;
    if (!validRoot(root))
        return refusal('malformed_roa_or_unknown_field');
    const araIds = new Set();
    for (const ara of aras) {
        if (!validARA(ara))
            return refusal('malformed_ara_or_unknown_field');
        if (araIds.has(ara.ara_id))
            return refusal('duplicate_ara_id');
        araIds.add(ara.ara_id);
    }
    if (!validAER(evidence.aer))
        return refusal('malformed_aer_or_unknown_field');
    if (!record(context))
        return refusal('malformed_verification_context');
    const verificationTime = instantMs(context.verificationTime);
    if (!Number.isFinite(verificationTime))
        return refusal('invalid_verification_time');
    if (!record(context.keysByType)
        || !record(context.keysByType.agentroa)
        || !exactObject(context.keysByType.agentroa, ['roa', 'ara', 'aer'])) {
        return refusal('missing_role_scoped_key_pins');
    }
    const pins = context.keysByType.agentroa;
    if (!record(context.policiesByType) || !own(context.policiesByType, 'agentroa')) {
        return refusal('missing_policy_profile');
    }
    const profile = context.policiesByType.agentroa;
    if (!validateProfile(profile))
        return refusal('malformed_policy_profile');
    if (!validAction(context.action))
        return refusal('malformed_expected_action');
    const rootSignature = verifySignatures(root, pins.roa, 'roa');
    if (rootSignature)
        return refusal(rootSignature);
    for (const ara of aras) {
        const signature = verifySignatures(ara, pins.ara, 'ara', ara.delegating_agent.agent_id);
        if (signature)
            return refusal(signature);
    }
    const aerSignature = verifySignatures(evidence.aer, pins.aer, 'aer', evidence.aer.border_gateway.gateway_id);
    if (aerSignature)
        return refusal(aerSignature);
    const rootIssued = instantMs(root.issued_at);
    const rootExpires = instantMs(root.expires_at);
    if (rootIssued >= rootExpires)
        return refusal('invalid_roa_validity_interval');
    if (verificationTime < rootIssued)
        return refusal('roa_not_yet_valid');
    if (verificationTime > rootExpires)
        return refusal('roa_expired');
    if (root.authorization.approval_state === 'pending')
        return refusal('roa_approval_pending');
    if (root.policy.policy_id !== profile.expected_policy_id)
        return refusal('policy_id_mismatch');
    if (root.policy.policy_version !== profile.expected_policy_version)
        return refusal('policy_version_mismatch');
    if (root.policy.policy_digest !== profile.expected_policy_digest)
        return refusal('policy_digest_mismatch');
    if (aras.length > root.authorized_scope.max_delegation_depth)
        return refusal('delegation_depth_exceeded');
    if (aras.length > 0 && own(root.authorized_scope, 'data_classification_ceiling')) {
        return refusal('data_classification_narrowing_ambiguous');
    }
    let parent = root;
    let parentScope = root.authorized_scope;
    let parentAgent = root.session.agent_id;
    let previousTime = rootIssued;
    for (let index = 0; index < aras.length; index++) {
        const ara = aras[index];
        const araTime = instantMs(ara.issued_at);
        if (araTime < previousTime || araTime > rootExpires || araTime > verificationTime) {
            return refusal('ara_time_outside_session');
        }
        const expectedType = index === 0 ? 'roa_envelope' : 'ara';
        const expectedId = index === 0 ? parent.envelope_id : parent.ara_id;
        if (ara.upstream_ref.ref_type !== expectedType || ara.upstream_ref.ref_id !== expectedId) {
            return refusal('ara_parent_reference_mismatch');
        }
        if (ara.upstream_ref.ref_digest !== sha256(parent))
            return refusal('ara_parent_digest_mismatch');
        if (ara.delegating_agent.agent_id !== parentAgent)
            return refusal('ara_delegator_mismatch');
        if (ara.delegating_agent.session_id !== root.session.session_id)
            return refusal('ara_session_mismatch');
        if (ara.policy.policy_digest !== root.policy.policy_digest
            || ara.policy.policy_version !== root.policy.policy_version)
            return refusal('ara_policy_mismatch');
        if (!root.authorized_scope.cross_org_permitted
            && organization(ara.delegated_agent.agent_id) !== organization(parentAgent)) {
            return refusal('cross_org_delegation_refused');
        }
        const scopeFailure = narrowScope(parentScope, ara.delegated_scope, profile.capability_manifest);
        if (scopeFailure)
            return refusal(scopeFailure);
        parent = ara;
        parentScope = ara.delegated_scope;
        parentAgent = ara.delegated_agent.agent_id;
        previousTime = araTime;
    }
    const aer = evidence.aer;
    const aerTime = instantMs(aer.produced_at);
    if (aerTime < previousTime)
        return refusal('aer_time_before_chain');
    if (aerTime > rootExpires || aerTime > verificationTime)
        return refusal('aer_time_outside_session');
    if (aer.session.session_id !== root.session.session_id)
        return refusal('aer_session_mismatch');
    if (aer.session.agent_id !== parentAgent)
        return refusal('aer_agent_mismatch');
    if (aer.policy.policy_id !== root.policy.policy_id
        || aer.policy.policy_digest !== root.policy.policy_digest)
        return refusal('aer_policy_mismatch');
    if (aer.chain_summary.chain_depth !== aras.length
        || aer.chain_summary.root_envelope_id !== root.envelope_id) {
        return refusal('aer_chain_summary_mismatch');
    }
    if (aer.chain_summary.chain_digest !== sha256(evidence.chain))
        return refusal('aer_chain_digest_mismatch');
    if (canonicalize(aer.action) !== canonicalize(context.action))
        return refusal('aer_action_mismatch');
    const effective = resolveCapabilities(parentScope.capabilities, profile.capability_manifest);
    if (!effective.ok)
        return refusal(effective.reason);
    if (aer.enforcement_outcome === 'permit' && !effective.capabilities.has(aer.action.capability)) {
        return refusal('capability_not_in_scope');
    }
    const bound = {
        verified: true,
        action_digest: sha256(context.action),
        decision: aer.enforcement_outcome,
        pre_execution: true,
        execution_proven: false,
        enforcement_mode: aer.enforcement_mode,
        chain_depth: aras.length,
    };
    if (aer.deployment_topology === undefined
        || !profile.allowed_topologies.includes(aer.deployment_topology)) {
        return refusal('deployment_topology_refused', bound);
    }
    if (aer.enforcement_mode === 'degraded' && profile.allow_degraded !== true) {
        return refusal('degraded_mode_refused', bound);
    }
    if (aer.enforcement_outcome === 'deny')
        return refusal('aer_denied', bound);
    return { valid: true, ...bound, reason: null };
}
/**
 * Verify an AgentROA -01 evidence bundle.
 *
 * Expected evidence:
 *   { chain: [roaEnvelope, ...araObjects], aer }
 *
 * Expected relying-party context (the shape AEC supplies custom verifiers):
 *   {
 *     keysByType: {
 *       agentroa: {
 *         roa: { [signer]: ed25519Spki },
 *         ara: { [signer]: ed25519Spki },
 *         aer: { [gatewayId]: ed25519Spki }
 *       }
 *     },
 *     policiesByType: {
 *       agentroa: {
 *         expected_policy_id,
 *         expected_policy_version,
 *         expected_policy_digest,
 *         allow_degraded,
 *         allowed_topologies,
 *         capability_manifest: { [wildcard]: [concreteCapability, ...] }
 *       }
 *     },
 *     verificationTime,
 *     action
 *   }
 */
export function verifyAgentROA(evidence, context = {}) {
    try {
        return verifyAgentROAInternal(evidence, context);
    }
    catch {
        return refusal('unexpected_verification_error');
    }
}
//# sourceMappingURL=agentroa.js.map