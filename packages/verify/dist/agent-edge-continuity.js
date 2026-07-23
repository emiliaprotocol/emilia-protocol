// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AGENT-EDGE-CONTINUITY-v1.
 *
 * A relying-party-pinned provenance and action-lineage profile for carrying
 * one material action across user, harness, model, tool, agent, and effect
 * boundaries. It contributes evidence to AEB; it never creates authority.
 */
import crypto from 'node:crypto';
import { authorizeAebExecution, authorizeAebExecutionDurable, canonicalizeAeb, digestAeb, } from './aeb-adapter-contract.js';
export const AGENT_CONTINUITY_VERSION = 'EP-AGENT-EDGE-CONTINUITY-v1';
export const AGENT_CONTINUITY_DOMAIN = `${AGENT_CONTINUITY_VERSION}\0`;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{1,256}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,256}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const EDGES = new Set([
    'user-harness',
    'harness-model',
    'model-harness',
    'harness-tool',
    'agent-agent',
    'effect',
]);
const CLAIM_KEYS = new Set([
    'intent_digest', 'display_digest', 'model_id', 'model_version',
    'model_manifest_digest', 'harness_digest', 'prompt_context_digest',
    'output_digest', 'protocol', 'tool_id', 'tool_schema_digest',
    'request_digest', 'from_agent', 'to_agent', 'delegation_digest',
    'scope_digest', 'scope', 'source_identity_digest', 'destination_identity_digest',
    'source_discovery_digest', 'destination_discovery_digest', 'source_attestation_digest',
    'destination_attestation_digest', 'executor_id', 'effect_digest', 'outcome',
]);
function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function sortedUnique(values) {
    return [...new Set(values)].sort();
}
function instant(value) {
    if (typeof value !== 'string' || !RFC3339_RE.test(value))
        return Number.NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : Number.NaN;
}
function validId(value) {
    return typeof value === 'string' && ID_RE.test(value);
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function validBase64url(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length % 4 === 1
        || !/^[A-Za-z0-9_-]+$/.test(value))
        return false;
    const decoded = Buffer.from(value, 'base64url');
    return decoded.toString('base64url') === value;
}
function validScope(scope) {
    if (!isObject(scope) || !Array.isArray(scope.action_types) || !Array.isArray(scope.resources))
        return false;
    if (!scope.action_types.every((value) => typeof value === 'string' && ID_RE.test(value)))
        return false;
    if (!scope.resources.every((value) => typeof value === 'string' && ID_RE.test(value)))
        return false;
    return scope.max_amount_minor === undefined
        || (typeof scope.max_amount_minor === 'string' && /^(0|[1-9][0-9]*)$/.test(scope.max_amount_minor));
}
function validClaims(value) {
    if (!isObject(value) || Object.keys(value).some((key) => !CLAIM_KEYS.has(key)))
        return false;
    const digestKeys = [
        'intent_digest', 'display_digest', 'model_manifest_digest', 'harness_digest',
        'prompt_context_digest', 'output_digest', 'tool_schema_digest', 'request_digest',
        'delegation_digest', 'scope_digest', 'source_identity_digest',
        'destination_identity_digest', 'source_discovery_digest',
        'destination_discovery_digest', 'source_attestation_digest',
        'destination_attestation_digest', 'effect_digest',
    ];
    for (const key of digestKeys)
        if (value[key] !== undefined && !validDigest(value[key]))
            return false;
    const idKeys = ['model_id', 'model_version', 'tool_id', 'from_agent', 'to_agent', 'executor_id'];
    for (const key of idKeys)
        if (value[key] !== undefined && !validId(value[key]))
            return false;
    if (value.protocol !== undefined && !['native', 'MCP', 'A2A'].includes(value.protocol))
        return false;
    if (value.outcome !== undefined && !['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE'].includes(value.outcome))
        return false;
    return value.scope === undefined || validScope(value.scope);
}
function edgeClaimReasons(envelope) {
    const { edge, source, destination, initiator_id: initiatorId, executor_id: executorId, claims } = envelope;
    const reasons = [];
    if (edge === 'user-harness') {
        if (source !== initiatorId)
            reasons.push('initiator_source_mismatch');
        if (!claims.intent_digest || !claims.display_digest)
            reasons.push('user_intent_binding_missing');
    }
    if (edge === 'harness-model') {
        for (const key of [
            'model_id', 'model_version', 'model_manifest_digest', 'harness_digest',
            'prompt_context_digest', 'output_digest',
        ])
            if (!claims[key])
                reasons.push(`model_provenance_missing:${key}`);
    }
    if (edge === 'model-harness' && !claims.output_digest)
        reasons.push('model_output_binding_missing');
    if (edge === 'harness-tool') {
        if (claims.protocol !== 'MCP')
            reasons.push('mcp_protocol_not_declared');
        if (claims.tool_id !== destination)
            reasons.push('mcp_tool_endpoint_mismatch');
        for (const key of ['tool_id', 'tool_schema_digest', 'request_digest']) {
            if (!claims[key])
                reasons.push(`mcp_mapping_missing:${key}`);
        }
    }
    if (edge === 'agent-agent') {
        if (claims.protocol !== 'A2A')
            reasons.push('a2a_protocol_not_declared');
        if (claims.from_agent !== source || claims.to_agent !== destination)
            reasons.push('a2a_endpoints_not_bound');
        for (const key of ['delegation_digest', 'scope_digest']) {
            if (!claims[key])
                reasons.push(`a2a_mapping_missing:${key}`);
        }
        if (!claims.scope)
            reasons.push('a2a_scope_missing');
        else if (claims.scope_digest !== digestAeb(claims.scope))
            reasons.push('a2a_scope_digest_mismatch');
    }
    if (edge === 'effect') {
        if (claims.executor_id !== executorId || destination !== executorId)
            reasons.push('effect_executor_mismatch');
        for (const key of ['executor_id', 'effect_digest', 'outcome']) {
            if (!claims[key])
                reasons.push(`effect_observation_missing:${key}`);
        }
    }
    return reasons;
}
function shapeReasons(value) {
    const reasons = [];
    if (!isObject(value) || value['@type'] !== AGENT_CONTINUITY_VERSION)
        return ['invalid_type'];
    if (!validId(value.continuity_id))
        reasons.push('invalid_continuity_id');
    if (value.parent_continuity_id !== null && !validId(value.parent_continuity_id))
        reasons.push('invalid_parent_continuity_id');
    if (!EDGES.has(value.edge))
        reasons.push('invalid_edge');
    for (const key of [
        'source', 'destination', 'relying_party_id', 'initiator_id', 'executor_id',
        'operation_id', 'handoff_nonce',
    ])
        if (!validId(value[key]))
            reasons.push(`invalid_${key}`);
    if (typeof value.caid !== 'string' || !CAID_RE.test(value.caid))
        reasons.push('invalid_caid');
    for (const key of ['pinned_config_digest', 'action_digest', 'proposal_digest']) {
        if (!validDigest(value[key]))
            reasons.push(`invalid_${key}`);
    }
    if (!Array.isArray(value.evidence_refs) || !value.evidence_refs.every(validDigest)
        || JSON.stringify(value.evidence_refs) !== JSON.stringify(sortedUnique(value.evidence_refs))) {
        reasons.push('invalid_evidence_refs');
    }
    if (!validClaims(value.claims))
        reasons.push('invalid_claims');
    if (!Number.isInteger(value.sequence) || value.sequence < 0)
        reasons.push('invalid_sequence');
    if (!Number.isFinite(instant(value.issued_at)))
        reasons.push('invalid_issued_at');
    if (!Number.isFinite(instant(value.expires_at)))
        reasons.push('invalid_expires_at');
    if (instant(value.issued_at) >= instant(value.expires_at))
        reasons.push('invalid_time_range');
    if (typeof value.handoff_nonce !== 'string' || !NONCE_RE.test(value.handoff_nonce))
        reasons.push('invalid_handoff_nonce');
    const signature = value.signature;
    if (!isObject(signature) || signature.alg !== 'Ed25519' || !validId(signature.key_id)
        || !validBase64url(signature.value) || Buffer.from(signature.value, 'base64url').length !== 64) {
        reasons.push('invalid_signature');
    }
    if (reasons.length === 0) {
        reasons.push(...edgeClaimReasons(value));
    }
    return sortedUnique(reasons);
}
function endpointPinReasons(envelope, pins) {
    if (!pins)
        return [];
    const reasons = [];
    for (const [endpoint, prefix] of [[envelope.source, 'source'], [envelope.destination, 'destination']]) {
        const pin = pins[endpoint];
        for (const kind of ['identity', 'discovery', 'attestation']) {
            const claimed = envelope.claims[`${prefix}_${kind}_digest`];
            const expected = pin?.[`${kind}_digest`];
            if (claimed !== undefined && expected !== claimed)
                reasons.push(`endpoint_${kind}_pin_mismatch:${endpoint}`);
            if (expected !== undefined && claimed === undefined)
                reasons.push(`endpoint_${kind}_evidence_missing:${endpoint}`);
        }
    }
    return reasons;
}
function unsignedForSignature(envelope) {
    const { signature: _signature, ...unsigned } = envelope;
    return unsigned;
}
function signingBytes(value) {
    return Buffer.from(`${AGENT_CONTINUITY_DOMAIN}${canonicalizeAeb(value)}`, 'utf8');
}
function publicKeyObject(value) {
    if (typeof value !== 'string')
        return value;
    if (/^[A-Za-z0-9_-]+$/.test(value)) {
        return crypto.createPublicKey({ key: Buffer.from(value, 'base64url'), format: 'der', type: 'spki' });
    }
    return crypto.createPublicKey(value);
}
function continuityId(body) {
    return `ec:${digestAeb(body).slice('sha256:'.length)}`;
}
function validTopology(topology) {
    if (!isObject(topology) || !Array.isArray(topology.accepted_edges)
        || !isObject(topology.allowed_transitions))
        return false;
    const accepted = new Set(topology.accepted_edges);
    const transitionEntries = Object.entries(topology.allowed_transitions);
    return accepted.size === topology.accepted_edges.length
        && topology.accepted_edges.length > 0
        && topology.accepted_edges.every((edge) => EDGES.has(edge))
        && Array.isArray(topology.root_edges)
        && topology.root_edges.length > 0
        && topology.root_edges.every((edge) => topology.accepted_edges.includes(edge))
        && Array.isArray(topology.execution_edges)
        && topology.execution_edges.length > 0
        && topology.execution_edges.every((edge) => topology.accepted_edges.includes(edge))
        && transitionEntries.every(([parent, children]) => EDGES.has(parent)
            && accepted.has(parent)
            && Array.isArray(children)
            && children.every((child) => accepted.has(child)))
        && Number.isInteger(topology.max_depth) && topology.max_depth >= 1
        && Number.isInteger(topology.max_validity_seconds) && topology.max_validity_seconds >= 1
        && (topology.max_age_seconds === undefined
            || (Number.isInteger(topology.max_age_seconds) && topology.max_age_seconds >= 0));
}
/** Build and sign an immutable continuity envelope. */
export function createAgentContinuityEnvelope(options) {
    const body = {
        '@type': AGENT_CONTINUITY_VERSION,
        parent_continuity_id: options.parent_continuity_id,
        edge: options.edge,
        source: options.source,
        destination: options.destination,
        relying_party_id: options.relying_party_id,
        pinned_config_digest: options.pinned_config_digest,
        initiator_id: options.initiator_id,
        executor_id: options.executor_id,
        caid: options.caid,
        action_digest: options.action_digest,
        proposal_digest: options.proposal_digest,
        operation_id: options.operation_id,
        evidence_refs: sortedUnique(options.evidence_refs ?? []),
        claims: options.claims,
        sequence: options.sequence,
        issued_at: options.issued_at,
        expires_at: options.expires_at,
        handoff_nonce: options.handoff_nonce,
    };
    const candidate = {
        ...body,
        continuity_id: continuityId(body),
        signature: { alg: 'Ed25519', key_id: options.signer.key_id, value: '' },
    };
    candidate.signature.value = crypto.sign(null, signingBytes(unsignedForSignature(candidate)), options.signer.private_key).toString('base64url');
    const reasons = shapeReasons(candidate);
    if (reasons.length > 0)
        throw new Error(`invalid continuity envelope: ${reasons.join(',')}`);
    return candidate;
}
export function createUserHarnessContinuity(options) {
    return createAgentContinuityEnvelope({
        ...options,
        edge: 'user-harness',
        claims: {
            intent_digest: digestAeb(options.intent),
            display_digest: digestAeb(options.display),
            ...(options.scope ? { scope: options.scope } : {}),
        },
    });
}
export function createHarnessModelContinuity(options) {
    return createAgentContinuityEnvelope({
        ...options,
        edge: 'harness-model',
        claims: {
            model_id: options.model_id,
            model_version: options.model_version,
            model_manifest_digest: digestAeb(options.model_manifest),
            harness_digest: digestAeb(options.harness),
            prompt_context_digest: digestAeb(options.prompt_context),
            output_digest: digestAeb(options.output),
            ...(options.scope ? { scope: options.scope } : {}),
        },
    });
}
export function createMcpToolContinuity(options) {
    return createAgentContinuityEnvelope({
        ...options,
        edge: 'harness-tool',
        claims: {
            protocol: 'MCP',
            tool_id: options.tool_id,
            tool_schema_digest: digestAeb(options.tool_schema),
            request_digest: digestAeb(options.request),
            ...(options.scope ? { scope: options.scope } : {}),
        },
    });
}
export function createA2AHandoffContinuity(options) {
    return createAgentContinuityEnvelope({
        ...options,
        edge: 'agent-agent',
        claims: {
            protocol: 'A2A',
            from_agent: options.from_agent,
            to_agent: options.to_agent,
            delegation_digest: digestAeb(options.delegation),
            scope_digest: digestAeb(options.scope),
            scope: options.scope,
        },
    });
}
export function createEffectContinuity(options) {
    return createAgentContinuityEnvelope({
        ...options,
        edge: 'effect',
        claims: {
            executor_id: options.executor_id,
            effect_digest: digestAeb(options.effect),
            outcome: options.outcome,
        },
    });
}
function blankVerification(reason) {
    return {
        valid: false,
        checks: {
            schema: false,
            identity: false,
            signature: false,
            signer_authority: false,
            time: false,
            expected_action: false,
            expected_operation: false,
            expected_context: false,
        },
        reasons: [reason],
    };
}
/** Offline deterministic verification under relying-party-pinned topology and signer authority. */
export function verifyAgentContinuityEnvelope(value, options) {
    try {
        const checks = {
            schema: false,
            identity: false,
            signature: false,
            signer_authority: false,
            time: false,
            expected_action: false,
            expected_operation: false,
            expected_context: false,
        };
        const reasons = shapeReasons(value);
        if (reasons.length > 0 || !isObject(value))
            return { valid: false, checks, reasons };
        const envelope = value;
        checks.schema = validTopology(options.topology);
        if (!checks.schema)
            reasons.push('invalid_relying_party_topology');
        const { continuity_id: _continuityId, signature: _signature, ...idBody } = envelope;
        const expectedId = continuityId(idBody);
        checks.identity = expectedId === envelope.continuity_id
            && options.topology.accepted_edges.includes(envelope.edge)
            && edgeClaimReasons(envelope).length === 0
            && endpointPinReasons(envelope, options.endpoint_pins).length === 0;
        if (!checks.identity)
            reasons.push('continuity_identity_or_edge_claim_invalid');
        const pin = options.signer_pins?.[envelope.signature.key_id];
        if (pin) {
            try {
                checks.signature = crypto.verify(null, signingBytes(unsignedForSignature(envelope)), publicKeyObject(pin.public_key), Buffer.from(envelope.signature.value, 'base64url'));
            }
            catch {
                checks.signature = false;
            }
        }
        if (!checks.signature)
            reasons.push('signature_not_pinned_or_invalid');
        const now = options.now ?? new Date().toISOString().replace('.000Z', 'Z');
        const nowMs = instant(now);
        const issuedMs = instant(envelope.issued_at);
        const expiresMs = instant(envelope.expires_at);
        const pinStarts = instant(pin?.valid_from);
        const pinEnds = instant(pin?.valid_until);
        checks.signer_authority = pin !== undefined
            && pin.status === 'active'
            && pin.allowed_sources.includes(envelope.source)
            && pin.allowed_edges.includes(envelope.edge)
            && Number.isFinite(nowMs)
            && issuedMs >= pinStarts && issuedMs < pinEnds
            && nowMs >= pinStarts && nowMs < pinEnds;
        if (!checks.signer_authority)
            reasons.push('signer_not_authorized_for_source_or_edge');
        const lifetime = expiresMs - issuedMs;
        const age = nowMs - issuedMs;
        checks.time = Number.isFinite(nowMs)
            && nowMs >= issuedMs && nowMs < expiresMs
            && lifetime <= options.topology.max_validity_seconds * 1000
            && (options.topology.max_age_seconds === undefined
                || (age >= 0 && age <= options.topology.max_age_seconds * 1000));
        if (!checks.time)
            reasons.push('continuity_expired_stale_or_not_yet_valid');
        checks.expected_action = (options.expected_caid === undefined || options.expected_caid === envelope.caid)
            && (options.expected_action_digest === undefined || options.expected_action_digest === envelope.action_digest);
        if (!checks.expected_action)
            reasons.push('expected_action_mismatch');
        checks.expected_operation = options.expected_operation_id === undefined
            || options.expected_operation_id === envelope.operation_id;
        if (!checks.expected_operation)
            reasons.push('expected_operation_mismatch');
        checks.expected_context = (options.expected_proposal_digest === undefined
            || options.expected_proposal_digest === envelope.proposal_digest)
            && (options.expected_relying_party_id === undefined
                || options.expected_relying_party_id === envelope.relying_party_id)
            && (options.expected_pinned_config_digest === undefined
                || options.expected_pinned_config_digest === envelope.pinned_config_digest)
            && (options.expected_initiator_id === undefined
                || options.expected_initiator_id === envelope.initiator_id)
            && (options.expected_executor_id === undefined
                || options.expected_executor_id === envelope.executor_id);
        if (!checks.expected_context)
            reasons.push('expected_execution_context_mismatch');
        return {
            valid: Object.values(checks).every(Boolean) && reasons.length === 0,
            checks,
            reasons: sortedUnique(reasons),
        };
    }
    catch {
        return blankVerification('continuity_verification_error');
    }
}
function isSubset(child, parent) {
    const allowed = new Set(parent);
    return child.every((item) => allowed.has(item));
}
function scopeContained(child, parent) {
    if (!isSubset(child.action_types, parent.action_types) || !isSubset(child.resources, parent.resources))
        return false;
    if (parent.max_amount_minor !== undefined) {
        if (child.max_amount_minor === undefined)
            return false;
        try {
            if (BigInt(child.max_amount_minor) > BigInt(parent.max_amount_minor))
                return false;
        }
        catch {
            return false;
        }
    }
    return true;
}
function blankGraph(reason) {
    const base = blankVerification(reason);
    return {
        ...base,
        checks: {
            ...base.checks,
            parents: false,
            sequence: false,
            joins: false,
            topology: false,
            scope: false,
            replay: false,
        },
    };
}
/** Verify a connected cross-edge graph. Branches are allowed; every parent is pinned. */
export function verifyAgentContinuityGraph(values, options) {
    try {
        const checks = {
            schema: true,
            identity: true,
            signature: true,
            signer_authority: true,
            time: true,
            expected_action: true,
            expected_operation: true,
            expected_context: true,
            parents: true,
            sequence: true,
            joins: true,
            topology: true,
            scope: true,
            replay: true,
        };
        const reasons = [];
        const envelopes = [];
        const ids = new Set();
        const nonces = new Set();
        for (const value of values) {
            const result = verifyAgentContinuityEnvelope(value, options);
            for (const key of [
                'schema', 'identity', 'signature', 'signer_authority', 'time',
                'expected_action', 'expected_operation', 'expected_context',
            ])
                checks[key] = checks[key] && result.checks[key];
            reasons.push(...result.reasons);
            if (!result.checks.schema || !isObject(value))
                continue;
            const envelope = value;
            envelopes.push(envelope);
            if (ids.has(envelope.continuity_id)) {
                checks.replay = false;
                reasons.push('duplicate_continuity_id');
            }
            ids.add(envelope.continuity_id);
            if (nonces.has(envelope.handoff_nonce)) {
                checks.replay = false;
                reasons.push('duplicate_handoff_nonce');
            }
            nonces.add(envelope.handoff_nonce);
        }
        if (envelopes.length === 0) {
            checks.parents = false;
            reasons.push('empty_graph');
        }
        const byId = new Map(envelopes.map((envelope) => [envelope.continuity_id, envelope]));
        const roots = envelopes.filter((envelope) => envelope.sequence === 0);
        if (roots.length !== 1) {
            checks.parents = false;
            reasons.push(roots.length === 0 ? 'root_missing' : 'multiple_roots');
        }
        else if (!options.topology.root_edges.includes(roots[0].edge)) {
            checks.topology = false;
            reasons.push('root_edge_not_allowed');
        }
        for (const envelope of envelopes) {
            if (envelope.sequence > options.topology.max_depth) {
                checks.topology = false;
                reasons.push('topology_depth_exceeded');
            }
            if (envelope.sequence === 0) {
                if (envelope.parent_continuity_id !== null) {
                    checks.parents = false;
                    reasons.push('root_has_parent');
                }
                continue;
            }
            const parent = envelope.parent_continuity_id
                ? byId.get(envelope.parent_continuity_id)
                : undefined;
            if (!parent) {
                checks.parents = false;
                reasons.push('parent_missing');
                continue;
            }
            if (envelope.sequence !== parent.sequence + 1) {
                checks.sequence = false;
                reasons.push('sequence_not_monotonic');
            }
            if (parent.destination !== envelope.source) {
                checks.joins = false;
                reasons.push('edge_endpoint_not_joined');
            }
            if (parent.caid !== envelope.caid
                || parent.action_digest !== envelope.action_digest
                || parent.operation_id !== envelope.operation_id
                || parent.proposal_digest !== envelope.proposal_digest
                || parent.relying_party_id !== envelope.relying_party_id
                || parent.pinned_config_digest !== envelope.pinned_config_digest
                || parent.initiator_id !== envelope.initiator_id
                || parent.executor_id !== envelope.executor_id) {
                checks.joins = false;
                reasons.push('execution_binding_drift');
            }
            if (!(options.topology.allowed_transitions[parent.edge] ?? []).includes(envelope.edge)) {
                checks.topology = false;
                reasons.push('edge_transition_not_allowed');
            }
            if (envelope.edge === 'agent-agent') {
                if (!parent.claims.scope || !envelope.claims.scope
                    || !scopeContained(envelope.claims.scope, parent.claims.scope)) {
                    checks.scope = false;
                    reasons.push('delegated_scope_widened_or_unbound');
                }
            }
            else if (envelope.claims.scope && parent.claims.scope
                && !scopeContained(envelope.claims.scope, parent.claims.scope)) {
                checks.scope = false;
                reasons.push('scope_widened');
            }
        }
        return {
            valid: Object.values(checks).every(Boolean) && reasons.length === 0,
            checks,
            reasons: sortedUnique(reasons),
        };
    }
    catch {
        return blankGraph('continuity_graph_verification_error');
    }
}
export const verifyAgentContinuityChain = verifyAgentContinuityGraph;
function executionVerification(options) {
    return verifyAgentContinuityGraph(options.continuity, {
        ...options.verifier,
        now: options.execution_now,
        expected_caid: options.aeb_record.caid,
        expected_action_digest: options.aeb_record.composition.action_digest,
        expected_operation_id: options.aeb_record.operation_id,
        expected_proposal_digest: options.expected_proposal_digest,
        expected_relying_party_id: options.aeb_record.evaluator.id,
        expected_pinned_config_digest: options.aeb_record.evaluator.pinned_config_digest,
        expected_initiator_id: options.aeb_record.initiator_id,
        expected_executor_id: options.aeb_record.executor_id ?? '',
    });
}
function preExecutionGraphValid(values, topology) {
    const envelopes = values.filter(isObject);
    return envelopes.every((envelope) => envelope.edge !== 'effect')
        && topology.execution_edges.some((edge) => envelopes.some((envelope) => envelope.edge === edge));
}
function continuityReplayKeys(record, values) {
    const envelopes = values.filter(isObject);
    return sortedUnique(envelopes.flatMap((envelope) => [
        `continuity-id:${digestAeb({
            relying_party_id: record.evaluator.id,
            config_digest: record.evaluator.pinned_config_digest,
            continuity_id: envelope.continuity_id,
        })}`,
        `continuity-nonce:${digestAeb({
            relying_party_id: record.evaluator.id,
            config_digest: record.evaluator.pinned_config_digest,
            signer_key_id: envelope.signature.key_id,
            handoff_nonce: envelope.handoff_nonce,
        })}`,
    ]));
}
/** Reference single-process path. Production callers must use the durable variant. */
export function authorizeAgentContinuityExecution(options) {
    const continuity = executionVerification(options);
    if (!continuity.valid) {
        return {
            allowed: false,
            invoke_allowed: false,
            state: 'REFUSED',
            reason: 'continuity_not_verified',
            continuity,
        };
    }
    if (!preExecutionGraphValid(options.continuity, options.verifier.topology)) {
        return {
            allowed: false,
            invoke_allowed: false,
            state: 'REFUSED',
            reason: 'pre_execution_continuity_required',
            continuity,
        };
    }
    return {
        ...authorizeAebExecution(options.aeb_record, {
            verification: options.aeb_verification,
            local_authorization: options.local_authorization,
            store: options.store,
            additional_replay_keys: continuityReplayKeys(options.aeb_record, options.continuity),
        }),
        continuity,
    };
}
/** Fleet-safe path: continuity and native replay keys reserve atomically. */
export async function authorizeAgentContinuityExecutionDurable(options) {
    const continuity = executionVerification(options);
    if (!continuity.valid) {
        return {
            allowed: false,
            invoke_allowed: false,
            state: 'REFUSED',
            reason: 'continuity_not_verified',
            continuity,
        };
    }
    if (!preExecutionGraphValid(options.continuity, options.verifier.topology)) {
        return {
            allowed: false,
            invoke_allowed: false,
            state: 'REFUSED',
            reason: 'pre_execution_continuity_required',
            continuity,
        };
    }
    return {
        ...await authorizeAebExecutionDurable(options.aeb_record, {
            verification: options.aeb_verification,
            local_authorization: options.local_authorization,
            store: options.store,
            additional_replay_keys: continuityReplayKeys(options.aeb_record, options.continuity),
        }),
        continuity,
    };
}
//# sourceMappingURL=agent-edge-continuity.js.map