// SPDX-License-Identifier: Apache-2.0
// Generated from proposal-to-effect.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import { adapterPinDigest, digestAeb, evaluateAebEvidence, mappingProfileDigest, pinnedConfigDigest, registryEntryDigest, unifiedRegistryDigest, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { approvalActionHash } from '@emilia-protocol/require-receipt/acquisition';
import { createEg1Harness, createTrustedActionFirewall, EG1_DEFAULT_SELECTOR, } from './index.js';
import { PROPOSAL_TO_EFFECT_VERSION, createProposalToEffect, proposalToEffectConsumptionNonce, } from './proposal-to-effect.js';
const NOW = '2026-07-22T12:00:00Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const VECTOR_SUITE = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/proposal-to-effect.v1.json', import.meta.url), 'utf8'));
function vector(id) {
    const found = VECTOR_SUITE.vectors.find((candidate) => candidate.id === id);
    assert.ok(found, `missing proposal-to-effect vector: ${id}`);
    return found;
}
function registryEntry(entryId, kind, version, definition) {
    const entry = { kind, version, status: 'active', definition };
    entry.definition_digest = registryEntryDigest(entryId, entry);
    return entry;
}
function aebFixture(action, overrides = {}) {
    const adapter = {
        id: 'test:human',
        version: '1',
        verifyNative({ artifact, status, trust_roots }) {
            const trusted = trust_roots.includes(artifact.root);
            return {
                native_verification: trusted ? 'VERIFIED' : 'FAILED',
                acceptance: trusted ? 'ACCEPTED' : 'REJECTED',
                evidence_digest: digestAeb(artifact),
                status_digest: digestAeb({
                    checked_at: status.checked_at,
                    expires_at: status.expires_at,
                    revocation_checked: status.revocation_checked,
                    revoked: status.revoked,
                    consumed: status.consumed,
                    unavailable: status.unavailable === true,
                }),
                evidence_role: 'human-authorization',
                subject: { id: 'human:alice', kind: 'human' },
                reasons: trusted ? [] : ['native_trust_root_not_pinned'],
            };
        },
        mapAction({ artifact, native }) {
            return {
                mapping: native.native_verification === 'VERIFIED' ? 'MATCH' : 'INDETERMINATE',
                caid: artifact.caid,
                action_digest: digestAeb(artifact.action),
                reasons: [],
            };
        },
    };
    const profile = {
        version: 'payment-release-v1',
        definition: { action_type: 'payment.release' },
        registry_entry_ref: 'mapping:payment-release',
        mapper_id: 'mapper:payment-release',
        resolver: {
            id: 'resolver:payment-release',
            version: '1',
            implementation_digest: digestAeb({ implementation: 'resolver:payment-release:1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [],
        },
    };
    profile.profile_digest = mappingProfileDigest('payment-release', profile);
    const entries = {
        'mapping:payment-release': registryEntry('mapping:payment-release', 'mapping-profile', '1', { profile_digest: profile.profile_digest }),
        'role:human-authorization': registryEntry('role:human-authorization', 'evidence-role', '1', { role: 'human-authorization', subject_kinds: ['human'] }),
    };
    const registry = {
        '@version': 'EP-EVIDENCE-REGISTRY-v1',
        registry_id: 'registry:proposal-to-effect-test',
        epoch: 1,
        entries,
    };
    registry.registry_digest = unifiedRegistryDigest(registry);
    const pin = {
        version: '1',
        trust_roots: ['root:test'],
        config: { mode: 'offline' },
        max_status_age_sec: 300,
    };
    pin.config_digest = adapterPinDigest('test:human', pin);
    const evaluator = crypto.generateKeyPairSync('ed25519');
    const evaluatorPublicKey = evaluator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const config = {
        '@version': 'AEB-ADAPTER-v1',
        relying_party_id: 'rp:proposal-to-effect-test',
        evaluator_keys: { 'eval:test': { public_key: evaluatorPublicKey } },
        registry,
        accepted_mappers: ['mapper:payment-release'],
        adapters: { 'test:human': pin },
        profiles: { 'payment-release': profile },
        requirements: {
            'requirement:proposal-to-effect': {
                '@version': 'AEB-REQUIREMENT-v1',
                all_of: ['human-authorization'],
                terms: [
                    { type: 'initiator-exclusion', roles: ['human-authorization'] },
                    { type: 'one-time-consumption' },
                ],
            },
        },
    };
    const artifact = {
        root: 'root:test',
        caid: CAID,
        action,
    };
    const status = {
        checked_at: '2026-07-22T11:59:00Z',
        expires_at: '2026-07-22T12:05:00Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
        ...overrides,
    };
    const evaluated = evaluateAebEvidence({
        config,
        adapters: { 'test:human': adapter },
        operation_id: 'operation:release-1',
        consumption_nonce: proposalToEffectConsumptionNonce('operation:release-1', pinnedConfigDigest(config)),
        initiator_id: 'agent:buyer',
        requirement_ref: 'requirement:proposal-to-effect',
        caid: CAID,
        legs: [{
                adapter_id: 'test:human',
                profile_id: 'payment-release',
                artifact_ref: 'artifact:human-approval',
                artifact,
                status,
            }],
        evaluated_at: NOW,
        signer: { key_id: 'eval:test', private_key: evaluator.privateKey },
    });
    return {
        adapters: { 'test:human': adapter },
        artifacts: { 'artifact:human-approval': artifact },
        config,
        evaluation: evaluated.record,
    };
}
function durableStore() {
    const states = new Map();
    return {
        durable: true,
        ownershipFenced: true,
        permanentConsumption: true,
        states,
        async reserve(key) {
            if (states.has(key))
                return false;
            states.set(key, 'RESERVED');
            return true;
        },
        async commit(key) {
            if (states.get(key) !== 'RESERVED')
                return false;
            states.set(key, 'CONSUMED');
            return true;
        },
        async release(key) {
            if (states.get(key) !== 'RESERVED')
                return false;
            states.delete(key);
            return true;
        },
    };
}
function fixture({ status = {}, gate_override = null, } = {}) {
    const harness = createEg1Harness({ now: () => Date.parse(NOW) });
    const aeb = aebFixture(harness.action, status);
    const aebStore = durableStore();
    const gate = gate_override ?? createTrustedActionFirewall({
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        allowEphemeralStore: true,
        now: () => Date.parse(NOW),
    });
    const controller = createProposalToEffect({
        gate,
        profiles: {
            'payment-release': {
                id: 'payment-release',
                action_type: 'payment.release',
                selector: EG1_DEFAULT_SELECTOR,
                required_fields: Object.keys(harness.action),
                authorization: {
                    authorization_endpoint: 'https://approve.example.test/v1/approvals',
                    flow: 'EP-APPROVAL-v1',
                },
                aeb_requirement_ref: 'requirement:proposal-to-effect',
                ttl_sec: 300,
                canonicalize_action(input) {
                    return { action: structuredClone(input), caid: CAID };
                },
            },
        },
        aeb: {
            config: aeb.config,
            adapters: aeb.adapters,
            store: aebStore,
            resolve_artifacts: async () => aeb.artifacts,
            verify_provider_evidence: async ({ evidence, expected }) => ({
                valid: evidence?.authenticated === true
                    && evidence.operation_id === expected.operation_id
                    && evidence.caid === expected.caid
                    && evidence.action_digest === expected.action_digest
                    && ['COMMITTED', 'NOT_COMMITTED'].includes(evidence.outcome),
                outcome: evidence?.outcome,
                evidence_digest: evidence ? digestAeb(evidence) : null,
            }),
        },
        now: () => Date.parse(NOW),
    });
    const proposal = controller.prepare({
        proposal_id: 'proposal:release-1',
        profile_id: 'payment-release',
        operation_id: 'operation:release-1',
        initiator_id: 'agent:buyer',
        action: harness.action,
    });
    return { aeb, aebStore, controller, gate, harness, proposal };
}
test('proposal is a server-derived request object, not a second authorization artifact', () => {
    const f = fixture();
    const expected = VECTOR_SUITE.expected;
    assert.equal(f.proposal['@version'], PROPOSAL_TO_EFFECT_VERSION);
    assert.deepEqual(f.proposal.action, VECTOR_SUITE.action);
    assert.equal(f.proposal.caid, expected.caid);
    assert.equal(f.proposal.action_digest, expected.action_digest);
    assert.equal(f.proposal.aeb_action_digest, expected.aeb_action_digest);
    assert.equal(f.proposal.aeb.consumption_nonce, f.aeb.evaluation.consumption_nonce);
    assert.equal(f.proposal.challenge.action_hash, f.proposal.action_digest);
    assert.equal(f.proposal.authorization.flow, VECTOR_SUITE.profile.authorization_flow);
    const claim = vector('proposal_is_not_authority').expect;
    assert.equal(Object.hasOwn(f.proposal, 'signature'), claim.signature);
    assert.equal(Object.hasOwn(f.proposal, 'permit'), claim.permit);
    assert.equal(Object.hasOwn(f.proposal, 'authorized'), claim.authorized);
});
test('exact proposal mutation refuses before Gate, reservation, or effect', async () => {
    const f = fixture();
    const mutated = structuredClone(f.proposal);
    const mutation = vector('mutated_material_action_refused');
    mutated.action[mutation.mutation.field] = mutation.mutation.value;
    let invoked = false;
    await assert.rejects(f.controller.execute({ proposal: mutated, receipt: f.harness.mint(), evaluation: f.aeb.evaluation }, async () => {
        invoked = true;
    }), new RegExp(mutation.expect.error));
    assert.equal(invoked, false);
    assert.equal(f.aebStore.states.size, 0);
});
test('recomputed proposal digests cannot detach the action from signed AEB evidence', async () => {
    const f = fixture();
    const mutated = structuredClone(f.proposal);
    mutated.action.amount_usd = 40001;
    mutated.action_digest = approvalActionHash(mutated.action);
    mutated.aeb_action_digest = digestAeb(mutated.action);
    mutated.challenge.action_hash = mutated.action_digest;
    let invoked = false;
    const out = await f.controller.execute({
        proposal: mutated,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => { invoked = true; });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'aeb_evaluation_binding_mismatch');
    assert.equal(invoked, false);
    assert.equal(f.aebStore.states.size, 0);
});
test('evaluation consumption nonce is bound to the server-derived proposal operation', async () => {
    const f = fixture();
    const evaluation = structuredClone(f.aeb.evaluation);
    evaluation.consumption_nonce = 'nonce:alternate-valid-evaluation';
    let invoked = false;
    const out = await f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation,
    }, async () => { invoked = true; });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'aeb_evaluation_binding_mismatch');
    assert.equal(invoked, false);
    assert.equal(f.aebStore.states.size, 0);
});
test('proposal AEB block is closed and refuses presenter-added control fields', () => {
    const f = fixture();
    const proposal = structuredClone(f.proposal);
    proposal.aeb.authorized = true;
    assert.throws(() => f.controller.verifyProposal(proposal), /proposal_aeb_pin_mismatch/);
});
test('verified AEB plus Gate authorization reserves once and executes the exact effect', async () => {
    const f = fixture();
    let effects = 0;
    const first = await f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async ({ action }) => {
        effects += 1;
        return { released: action.payment_instruction_id };
    });
    assert.equal(first.ok, true);
    assert.equal(first.result.released, f.harness.action.payment_instruction_id);
    assert.equal(effects, 1);
    assert.deepEqual([...f.aebStore.states.values()], ['CONSUMED']);
    const replay = await f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => {
        effects += 1;
    });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, vector('fresh_receipt_cannot_replay_consumed_operation').expect.reason);
    assert.equal(effects, 1, 'a fresh receipt cannot replay one proposal operation');
});
test('executed effect with failed AEB commit remains reserved for reconciliation', async () => {
    const f = fixture();
    f.aebStore.commit = async () => false;
    let effects = 0;
    await assert.rejects(f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => {
        effects += 1;
        return { released: true };
    }), (error) => error?.code === vector('executed_effect_commit_failure_stays_reserved').expect.error);
    assert.equal(effects, 1);
    assert.deepEqual([...f.aebStore.states.values()], ['RESERVED']);
});
test('stale AEB evidence fails closed before Gate reservation and effect', async () => {
    const f = fixture({ status: { checked_at: '2026-07-22T10:00:00Z' } });
    let invoked = false;
    const out = await f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => { invoked = true; });
    assert.equal(out.ok, false);
    assert.equal(out.reason, vector('stale_aeb_refused').expect.reason);
    assert.equal(invoked, false);
    assert.equal(f.aebStore.states.size, 0);
});
test('Gate refusal never consumes the proposal operation reservation', async () => {
    const f = fixture();
    let invoked = false;
    const out = await f.controller.execute({
        proposal: f.proposal,
        receipt: null,
        evaluation: f.aeb.evaluation,
    }, async () => { invoked = true; });
    assert.equal(out.ok, false);
    assert.match(out.reason, /receipt_required/);
    assert.equal(invoked, false);
    assert.equal(f.aebStore.states.size, 0);
});
test('Gate pass-through cannot satisfy a Proposal-to-Effect profile', async () => {
    let runCalled = false;
    const f = fixture({
        gate_override: {
            async check() {
                return { allow: true, status: 200, reason: 'not_guarded', requirement: null };
            },
            async run() {
                runCalled = true;
                return { ok: true };
            },
        },
    });
    let invoked = false;
    const out = await f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => { invoked = true; });
    assert.equal(out.ok, false);
    assert.equal(out.reason, vector('unguarded_gate_selector_refused').expect.reason);
    assert.equal(runCalled, false);
    assert.equal(invoked, false);
    assert.equal(f.aebStore.states.size, 0);
});
test('indeterminate effect freezes replay until authenticated provider reconciliation', async () => {
    const f = fixture();
    await assert.rejects(f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => {
        throw new Error('provider response lost');
    }), (error) => error?.emiliaGateOutcome?.outcome === 'indeterminate');
    assert.deepEqual([...f.aebStore.states.values()], ['RESERVED']);
    const blocked = await f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => assert.fail('blind replay crossed the effect boundary'));
    assert.equal(blocked.ok, false);
    assert.equal(blocked.reason, 'aeb_consumption_conflict');
    const wrong = await f.controller.reconcile({
        proposal: f.proposal,
        evaluation: f.aeb.evaluation,
        provider_evidence: {
            authenticated: false,
            operation_id: f.proposal.operation_id,
            caid: f.proposal.caid,
            action_digest: digestAeb(f.proposal.action),
            outcome: 'COMMITTED',
        },
    });
    assert.equal(wrong.ok, false);
    assert.equal(wrong.reason, 'provider_evidence_unverified');
    assert.deepEqual([...f.aebStore.states.values()], ['RESERVED']);
    const reconciled = await f.controller.reconcile({
        proposal: f.proposal,
        evaluation: f.aeb.evaluation,
        provider_evidence: {
            authenticated: true,
            operation_id: f.proposal.operation_id,
            caid: f.proposal.caid,
            action_digest: digestAeb(f.proposal.action),
            outcome: 'COMMITTED',
        },
    });
    assert.equal(reconciled.ok, true);
    assert.equal(reconciled.state, 'CONSUMED');
    assert.deepEqual([...f.aebStore.states.values()], ['CONSUMED']);
});
test('authenticated NOT_COMMITTED reconciliation permits one explicit retry', async () => {
    const f = fixture();
    let effects = 0;
    await assert.rejects(f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => {
        effects += 1;
        throw new Error('provider rejected before commit but response was lost');
    }), (error) => error?.emiliaGateOutcome?.outcome === 'indeterminate');
    const reconciled = await f.controller.reconcile({
        proposal: f.proposal,
        evaluation: f.aeb.evaluation,
        provider_evidence: {
            authenticated: true,
            operation_id: f.proposal.operation_id,
            caid: f.proposal.caid,
            action_digest: f.proposal.aeb_action_digest,
            outcome: 'NOT_COMMITTED',
        },
    });
    assert.equal(reconciled.ok, true);
    assert.equal(reconciled.state, vector('authenticated_not_committed_reconciliation_releases_operation').expect.state);
    const retried = await f.controller.execute({
        proposal: f.proposal,
        receipt: f.harness.mint(),
        evaluation: f.aeb.evaluation,
    }, async () => {
        effects += 1;
        return { released: true };
    });
    assert.equal(retried.ok, true);
    assert.equal(effects, 2);
    assert.deepEqual([...f.aebStore.states.values()], ['CONSUMED']);
});
test('beginApproval uses the existing pinned EP-APPROVAL-v1 acquisition rail', async () => {
    const f = fixture();
    let posted = null;
    const pending = await f.controller.beginApproval({
        proposal: f.proposal,
        approver_id: 'approver@example.test',
        idempotency_key: 'proposal-release-0001',
        requester_authorization: 'Bearer ep_requester_test_12345678',
        fetch_impl: async (_url, init) => {
            posted = JSON.parse(init.body);
            return new Response(JSON.stringify({
                request_id: `apr_${'a'.repeat(32)}`,
                approval_url: 'https://approve.example.test/review/1',
                poll_token: `apt_${'b'.repeat(48)}`,
                status: 'pending',
                expires_at: '2026-07-22T12:05:00Z',
            }), { status: 201, headers: { 'content-type': 'application/json' } });
        },
    });
    assert.equal(pending.status, 'pending');
    assert.equal(posted.flow, 'EP-APPROVAL-v1');
    assert.deepEqual(posted.action, f.proposal.action);
    assert.equal(posted.challenge.action_hash, f.proposal.action_digest);
    assert.equal(posted.permit, undefined);
});
