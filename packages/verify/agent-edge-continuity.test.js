// SPDX-License-Identifier: Apache-2.0
// Generated from agent-edge-continuity.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import { AGENT_CONTINUITY_VERSION, authorizeAgentContinuityExecution, authorizeAgentContinuityExecutionDurable, createA2AHandoffContinuity, createAgentContinuityEnvelope, createEffectContinuity, createMcpToolContinuity, verifyAgentContinuityEnvelope, verifyAgentContinuityGraph, } from './agent-edge-continuity.js';
import { digestAeb, InMemoryAebConsumptionStore } from './aeb-adapter-contract.js';
const vectors = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/agent-edge-continuity.v1.json', import.meta.url), 'utf8'));
const CAID = `caid:1:order.purchase.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = digestAeb({ action_type: 'order.purchase.1', order_id: 'o-1', amount_minor: '1000' });
const OTHER_ACTION = digestAeb({ action_type: 'order.purchase.1', order_id: 'o-2', amount_minor: '1000' });
const NOW = '2026-07-22T12:00:00Z';
const SCOPE = {
    action_types: ['order.purchase.1'],
    resources: ['order:o-1'],
    max_amount_minor: '1000',
};
const ACCEPTED_EDGES = [
    'user-harness',
    'harness-model',
    'model-harness',
    'harness-tool',
    'agent-agent',
    'effect',
];
const TOPOLOGY = {
    accepted_edges: ACCEPTED_EDGES,
    root_edges: ['user-harness'],
    allowed_transitions: {
        'user-harness': ['harness-model', 'harness-tool', 'agent-agent'],
        'harness-model': ['model-harness'],
        'model-harness': ['harness-tool', 'agent-agent'],
        'harness-tool': ['effect'],
        'agent-agent': ['effect'],
        effect: [],
    },
    execution_edges: ['harness-tool', 'agent-agent'],
    max_depth: 8,
    max_validity_seconds: 3600,
    max_age_seconds: 300,
};
function keyMaterial() {
    const keyPair = crypto.generateKeyPairSync('ed25519');
    const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    return { keyPair, publicKey };
}
function makeChain({ includeEffect = false } = {}) {
    const { keyPair, publicKey } = keyMaterial();
    const signer = { key_id: 'key:continuity:test', private_key: keyPair.privateKey };
    const common = {
        relying_party_id: 'rp:test',
        pinned_config_digest: digestAeb({ config: 'test' }),
        initiator_id: 'user:alice',
        executor_id: 'executor:payments',
        caid: CAID,
        action_digest: ACTION,
        proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        operation_id: 'op-1',
        expires_at: '2026-07-22T13:00:00Z',
        signer,
    };
    const root = createAgentContinuityEnvelope({
        ...common,
        parent_continuity_id: null,
        edge: 'user-harness',
        source: 'user:alice',
        destination: 'agent:planner',
        sequence: 0,
        issued_at: NOW,
        handoff_nonce: 'nonce-user-000001',
        evidence_refs: [digestAeb({ type: 'proposal-permit', id: 'permit-1' })],
        claims: {
            intent_digest: digestAeb({ intent: 'buy', order_id: 'o-1' }),
            display_digest: digestAeb({ display: 'Buy order o-1 for 1000' }),
            scope: SCOPE,
        },
    });
    const model = createAgentContinuityEnvelope({
        ...common,
        parent_continuity_id: root.continuity_id,
        edge: 'harness-model',
        source: 'agent:planner',
        destination: 'model:gpt',
        sequence: 1,
        issued_at: NOW,
        handoff_nonce: 'nonce-model-000001',
        claims: {
            model_id: 'model:gpt',
            model_version: '1',
            model_manifest_digest: digestAeb({ model: 'gpt' }),
            harness_digest: digestAeb({ harness: 'planner' }),
            prompt_context_digest: digestAeb({ prompt: 'buy' }),
            output_digest: digestAeb({ output: 'call tool' }),
            scope: SCOPE,
        },
    });
    const returned = createAgentContinuityEnvelope({
        ...common,
        parent_continuity_id: model.continuity_id,
        edge: 'model-harness',
        source: 'model:gpt',
        destination: 'agent:planner',
        sequence: 2,
        issued_at: NOW,
        handoff_nonce: 'nonce-return-000001',
        claims: { output_digest: model.claims.output_digest, scope: SCOPE },
    });
    const mcp = createMcpToolContinuity({
        ...common,
        parent_continuity_id: returned.continuity_id,
        source: 'agent:planner',
        destination: 'tool:payments',
        sequence: 3,
        issued_at: NOW,
        handoff_nonce: 'nonce-mcp-000001',
        tool_id: 'tool:payments',
        tool_schema: { version: 1 },
        request: { name: 'charge', arguments: { order_id: 'o-1', amount_minor: '1000' } },
        scope: SCOPE,
    });
    const a2a = createA2AHandoffContinuity({
        ...common,
        parent_continuity_id: returned.continuity_id,
        source: 'agent:planner',
        destination: 'agent:executor',
        sequence: 3,
        issued_at: NOW,
        handoff_nonce: 'nonce-a2a-000001',
        from_agent: 'agent:planner',
        to_agent: 'agent:executor',
        delegation: { id: 'd-1' },
        scope: SCOPE,
    });
    const envelopes = [root, model, returned, mcp, a2a];
    if (includeEffect) {
        envelopes.push(createEffectContinuity({
            ...common,
            parent_continuity_id: a2a.continuity_id,
            source: 'agent:executor',
            destination: 'executor:payments',
            sequence: 4,
            issued_at: NOW,
            handoff_nonce: 'nonce-effect-000001',
            executor_id: 'executor:payments',
            effect: { effect: 'charge', order_id: 'o-1' },
            outcome: 'COMMITTED',
        }));
    }
    return { envelopes, publicKey, keyPair };
}
function verifier(chain, overrides = {}) {
    return {
        signer_pins: {
            'key:continuity:test': {
                public_key: chain.publicKey,
                status: 'active',
                valid_from: '2026-07-22T00:00:00Z',
                valid_until: '2026-07-23T00:00:00Z',
                allowed_sources: ['user:alice', 'agent:planner', 'model:gpt', 'agent:executor'],
                allowed_edges: ACCEPTED_EDGES,
            },
        },
        topology: TOPOLOGY,
        now: NOW,
        ...overrides,
    };
}
function aebRecord(overrides = {}) {
    return {
        caid: CAID,
        verdict: 'SATISFIED',
        operation_id: 'op-1',
        consumption_nonce: 'aeb-consumption-1',
        initiator_id: 'user:alice',
        executor_id: 'executor:payments',
        evaluator: {
            id: 'rp:test',
            pinned_config_digest: digestAeb({ config: 'test' }),
        },
        composition: { action_digest: ACTION },
        legs: [{ replay_unit: digestAeb({ native: 'permit-1' }) }],
        authority_constraints: { one_time_consumption: true },
        ...overrides,
    };
}
test('publishes the complete continuity refusal vector set', () => {
    assert.equal(vectors['@type'], AGENT_CONTINUITY_VERSION);
    assert.deepEqual(vectors.vectors.map((vector) => vector.id), [
        'complete_user_model_mcp_a2a_effect_graph',
        'changed_action_is_refused',
        'operation_swap_is_refused',
        'missing_parent_or_sequence_gap_is_refused',
        'a2a_scope_widening_is_refused',
        'duplicate_nonce_is_replay',
        'signer_source_or_edge_escalation_is_refused',
        'revoked_or_stale_signer_is_refused',
        'required_pre_execution_edge_is_missing',
        'historical_aeb_verification_is_not_execution_authority',
        'continuity_replay_is_fenced_across_aeb_wrappers',
        'effect_evidence_cannot_precede_execution_reservation',
        'malformed_graph_never_touches_the_store',
        'production_path_requires_durable_ownership_fenced_store',
        'indeterminate_effect_is_not_success',
    ]);
});
test('verifies a complete user/model/MCP/A2A/effect graph', () => {
    const chain = makeChain({ includeEffect: true });
    const result = verifyAgentContinuityGraph(chain.envelopes, verifier(chain, {
        expected_caid: CAID,
        expected_action_digest: ACTION,
        expected_operation_id: 'op-1',
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        expected_relying_party_id: 'rp:test',
        expected_pinned_config_digest: digestAeb({ config: 'test' }),
        expected_initiator_id: 'user:alice',
        expected_executor_id: 'executor:payments',
    }));
    assert.equal(result.valid, true);
    assert.equal(result.checks.signer_authority, true);
    assert.equal(result.checks.expected_operation, true);
});
test('MCP and A2A adapters compute bindings instead of accepting caller digests', () => {
    const chain = makeChain();
    assert.equal(chain.envelopes[3].claims.protocol, 'MCP');
    assert.equal(chain.envelopes[3].claims.request_digest, digestAeb({
        name: 'charge',
        arguments: { order_id: 'o-1', amount_minor: '1000' },
    }));
    assert.equal(chain.envelopes[4].claims.protocol, 'A2A');
    assert.equal(chain.envelopes[4].claims.scope_digest, digestAeb(SCOPE));
});
test('refuses action or operation substitution', () => {
    const chain = makeChain();
    assert.equal(verifyAgentContinuityGraph(chain.envelopes, verifier(chain, {
        expected_action_digest: OTHER_ACTION,
    })).valid, false);
    assert.equal(verifyAgentContinuityGraph(chain.envelopes, verifier(chain, {
        expected_operation_id: 'op-2',
    })).valid, false);
});
test('refuses missing parents, replayed nonces, and widened delegation scope', () => {
    const missingParent = makeChain();
    const broken = structuredClone(missingParent.envelopes);
    broken[2].parent_continuity_id = 'ec:does-not-exist';
    assert.equal(verifyAgentContinuityGraph(broken, verifier(missingParent)).checks.parents, false);
    const replayed = makeChain();
    const replay = structuredClone(replayed.envelopes);
    replay[4].handoff_nonce = replay[0].handoff_nonce;
    assert.equal(verifyAgentContinuityGraph(replay, verifier(replayed)).checks.replay, false);
    const widened = makeChain();
    const scopeAttack = widened.envelopes.map((envelope) => structuredClone(envelope));
    scopeAttack[4].claims.scope.action_types.push('admin.delete.1');
    scopeAttack[4].claims.scope_digest = digestAeb(scopeAttack[4].claims.scope);
    assert.equal(verifyAgentContinuityGraph(scopeAttack, verifier(widened)).checks.scope, false);
});
test('a valid signature cannot escalate to an unpinned source or edge', () => {
    const chain = makeChain();
    const result = verifyAgentContinuityEnvelope(chain.envelopes[0], {
        ...verifier(chain),
        signer_pins: {
            'key:continuity:test': {
                public_key: chain.publicKey,
                status: 'active',
                valid_from: '2026-07-22T00:00:00Z',
                valid_until: '2026-07-23T00:00:00Z',
                allowed_sources: ['agent:planner'],
                allowed_edges: ['harness-model'],
            },
        },
    });
    assert.equal(result.checks.signature, true);
    assert.equal(result.checks.signer_authority, false);
    assert.equal(result.valid, false);
});
test('revoked or stale signer authority is refused', () => {
    const chain = makeChain();
    const revoked = verifier(chain);
    revoked.signer_pins['key:continuity:test'].status = 'revoked';
    assert.equal(verifyAgentContinuityGraph(chain.envelopes, revoked).checks.signer_authority, false);
    assert.equal(verifyAgentContinuityGraph(chain.envelopes, verifier(chain, {
        now: '2026-07-22T12:10:00Z',
    })).checks.time, false);
});
test('execution derives CAID, action, and operation pins from the AEB record', () => {
    const chain = makeChain();
    const decision = authorizeAgentContinuityExecution({
        continuity: chain.envelopes,
        aeb_record: aebRecord(),
        aeb_verification: { valid: true, execution_authorizing: true },
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        local_authorization: true,
        store: new InMemoryAebConsumptionStore(),
        verifier: verifier(chain),
        execution_now: NOW,
    });
    assert.equal(decision.invoke_allowed, true);
    assert.equal(decision.state, 'AUTHORIZED');
});
test('historical AEB verification cannot authorize execution', () => {
    const chain = makeChain();
    const store = new InMemoryAebConsumptionStore();
    const decision = authorizeAgentContinuityExecution({
        continuity: chain.envelopes,
        aeb_record: aebRecord(),
        aeb_verification: { valid: true, execution_authorizing: false },
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        local_authorization: true,
        store,
        verifier: verifier(chain),
        execution_now: NOW,
    });
    assert.equal(decision.invoke_allowed, false);
    assert.equal(decision.reason, 'execution_verification_required');
});
test('policy-required execution edge cannot be omitted', () => {
    const chain = makeChain();
    const decision = authorizeAgentContinuityExecution({
        continuity: chain.envelopes.slice(0, 3),
        aeb_record: aebRecord(),
        aeb_verification: { valid: true, execution_authorizing: true },
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        local_authorization: true,
        store: new InMemoryAebConsumptionStore(),
        verifier: verifier(chain),
        execution_now: NOW,
    });
    assert.equal(decision.invoke_allowed, false);
    assert.equal(decision.reason, 'pre_execution_continuity_required');
});
test('continuity replay is fenced across newly wrapped AEB records', () => {
    const chain = makeChain();
    const store = new InMemoryAebConsumptionStore();
    const base = {
        continuity: chain.envelopes,
        aeb_verification: { valid: true, execution_authorizing: true },
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        local_authorization: true,
        store,
        verifier: verifier(chain),
        execution_now: NOW,
    };
    assert.equal(authorizeAgentContinuityExecution({
        ...base,
        aeb_record: aebRecord(),
    }).invoke_allowed, true);
    const replay = authorizeAgentContinuityExecution({
        ...base,
        aeb_record: aebRecord({ consumption_nonce: 'aeb-consumption-2' }),
    });
    assert.equal(replay.invoke_allowed, false);
    assert.equal(replay.reason, 'consumption_conflict');
});
test('effect evidence cannot be supplied before execution reservation', () => {
    const chain = makeChain({ includeEffect: true });
    const decision = authorizeAgentContinuityExecution({
        continuity: chain.envelopes,
        aeb_record: aebRecord(),
        aeb_verification: { valid: true, execution_authorizing: true },
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        local_authorization: true,
        store: new InMemoryAebConsumptionStore(),
        verifier: verifier(chain),
        execution_now: NOW,
    });
    assert.equal(decision.invoke_allowed, false);
    assert.equal(decision.reason, 'pre_execution_continuity_required');
});
test('malformed continuity never touches the reservation store', () => {
    const chain = makeChain();
    let reserveCalls = 0;
    const store = {
        reserve() { reserveCalls += 1; return true; },
        commit() { return true; },
        release() { return true; },
        state() { return 'AVAILABLE'; },
    };
    const decision = authorizeAgentContinuityExecution({
        continuity: [{ malicious: true }],
        aeb_record: aebRecord(),
        aeb_verification: { valid: true, execution_authorizing: true },
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        local_authorization: true,
        store,
        verifier: verifier(chain),
        execution_now: NOW,
    });
    assert.equal(decision.invoke_allowed, false);
    assert.equal(reserveCalls, 0);
});
test('production execution refuses a non-durable store', async () => {
    const chain = makeChain();
    const decision = await authorizeAgentContinuityExecutionDurable({
        continuity: chain.envelopes,
        aeb_record: aebRecord(),
        aeb_verification: { valid: true, execution_authorizing: true },
        expected_proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        local_authorization: true,
        store: new InMemoryAebConsumptionStore(),
        verifier: verifier(chain),
        execution_now: NOW,
    });
    assert.equal(decision.invoke_allowed, false);
    assert.equal(decision.reason, 'secure_consumption_store_required');
});
test('an indeterminate effect remains valid evidence but never success', () => {
    const chain = makeChain();
    const effect = createEffectContinuity({
        parent_continuity_id: chain.envelopes[4].continuity_id,
        relying_party_id: 'rp:test',
        pinned_config_digest: digestAeb({ config: 'test' }),
        initiator_id: 'user:alice',
        executor_id: 'executor:payments',
        caid: CAID,
        action_digest: ACTION,
        proposal_digest: digestAeb({ proposal: 'purchase-o-1' }),
        operation_id: 'op-1',
        source: 'agent:executor',
        destination: 'executor:payments',
        sequence: 4,
        issued_at: NOW,
        expires_at: '2026-07-22T13:00:00Z',
        handoff_nonce: 'nonce-effect-000002',
        signer: { key_id: 'key:continuity:test', private_key: chain.keyPair.privateKey },
        executor_id: 'executor:payments',
        effect: { effect: 'charge', order_id: 'o-1' },
        outcome: 'INDETERMINATE',
    });
    const result = verifyAgentContinuityGraph([...chain.envelopes, effect], verifier(chain));
    assert.equal(result.valid, true);
    assert.equal(effect.claims.outcome, 'INDETERMINATE');
    assert.notEqual(effect.claims.outcome, 'COMMITTED');
});
