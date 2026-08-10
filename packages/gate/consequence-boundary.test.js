// SPDX-License-Identifier: Apache-2.0
// Generated from consequence-boundary.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { adapterPinDigest, digestAeb, evaluateAebEvidence, mappingProfileDigest, registryEntryDigest, unifiedRegistryDigest, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { createConsequenceBoundary, } from './consequence-boundary.js';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION = Object.freeze({
    action_type: 'payment.release.1',
    transfer_id: 'transfer-1',
    amount: '500.00',
    currency: 'USD',
});
const EVALUATED_AT = '2026-08-09T12:00:00.000Z';
const NOW = '2026-08-09T12:00:01.000Z';
const EXECUTOR = 'executor:gate-1';
function registryEntry(entryId, kind, definition) {
    const entry = { kind, version: '1', status: 'active', definition };
    entry.definition_digest = registryEntryDigest(entryId, entry);
    return entry;
}
function fixture({ operationId = 'operation:release-1', executorId = EXECUTOR, replayId = 'native-mandate:one', } = {}) {
    const adapter = {
        id: 'test:native-mandate',
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
                evidence_role: 'native-mandate',
                subject: { id: 'agent:buyer', kind: 'workload' },
                replay_unit: digestAeb({ adapter: 'test:native-mandate', replay_id: artifact.replay_id }),
                reasons: trusted ? [] : ['native_trust_root_not_pinned'],
            };
        },
        mapAction({ artifact, native, expected_action }) {
            return {
                mapping: native.native_verification === 'VERIFIED' ? 'MATCH' : 'INDETERMINATE',
                caid: artifact.caid,
                action_digest: digestAeb(expected_action),
                reasons: [],
            };
        },
    };
    const profile = {
        version: 'payment-release-v1',
        definition: { action_type: 'payment.release.1' },
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
        'mapping:payment-release': registryEntry('mapping:payment-release', 'mapping-profile', { profile_digest: profile.profile_digest }),
        'role:native-mandate': registryEntry('role:native-mandate', 'evidence-role', { role: 'native-mandate', subject_kinds: ['workload'] }),
    };
    const registry = {
        '@version': 'EP-EVIDENCE-REGISTRY-v1',
        registry_id: 'registry:consequence-boundary-test',
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
    pin.config_digest = adapterPinDigest('test:native-mandate', pin);
    const evaluator = crypto.generateKeyPairSync('ed25519');
    const config = {
        '@version': 'AEB-ADAPTER-v1',
        relying_party_id: 'rp:consequence-boundary-test',
        evaluator_keys: {
            'eval:test': {
                public_key: evaluator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
        },
        registry,
        accepted_mappers: ['mapper:payment-release'],
        adapters: { 'test:native-mandate': pin },
        profiles: { 'payment-release': profile },
        requirements: {
            'requirement:native-mandate': {
                '@version': 'AEB-REQUIREMENT-v1',
                all_of: ['native-mandate'],
                terms: [{ type: 'one-time-consumption' }],
            },
        },
    };
    const artifact = {
        root: 'root:test',
        caid: CAID,
        replay_id: replayId,
        mandate_id: 'ap2-like-mandate-1',
    };
    const status = {
        checked_at: '2026-08-09T11:59:59.000Z',
        expires_at: '2026-08-09T12:05:00.000Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
    };
    const evaluation = evaluateAebEvidence({
        config,
        adapters: { 'test:native-mandate': adapter },
        operation_id: operationId,
        consumption_nonce: `nonce:${operationId}`,
        initiator_id: 'agent:buyer',
        executor_id: executorId,
        requirement_ref: 'requirement:native-mandate',
        caid: CAID,
        expected_action: ACTION,
        legs: [{
                adapter_id: 'test:native-mandate',
                profile_id: 'payment-release',
                artifact_ref: 'artifact:native-mandate',
                artifact,
                status,
            }],
        evaluated_at: EVALUATED_AT,
        signer: { key_id: 'eval:test', private_key: evaluator.privateKey },
    });
    assert.equal(evaluation.valid, true, JSON.stringify(evaluation.reasons));
    return {
        config,
        adapters: { 'test:native-mandate': adapter },
        evaluation: evaluation.record,
        artifacts: { 'artifact:native-mandate': artifact },
        current_statuses: { 'artifact:native-mandate': status },
    };
}
function durableAebStore() {
    const operations = new Map();
    const replayOwners = new Map();
    return {
        durable: true,
        ownershipFenced: true,
        permanentConsumption: true,
        atomicReplayFenced: true,
        operations,
        async reserve(key, replayKeys) {
            if (operations.has(key))
                return 'CONSUMPTION_CONFLICT';
            if (replayKeys.some((replayKey) => replayOwners.has(replayKey))) {
                return 'NATIVE_REPLAY_CONFLICT';
            }
            operations.set(key, 'RESERVED');
            for (const replayKey of replayKeys)
                replayOwners.set(replayKey, key);
            return 'RESERVED';
        },
        async commit(key) {
            if (operations.get(key) !== 'RESERVED')
                return false;
            operations.set(key, 'CONSUMED');
            return true;
        },
        async release(key) {
            if (operations.get(key) !== 'RESERVED')
                return false;
            operations.delete(key);
            for (const [replayKey, owner] of replayOwners) {
                if (owner === key)
                    replayOwners.delete(replayKey);
            }
            return true;
        },
    };
}
function attemptStore() {
    const rows = new Map();
    return {
        durable: true,
        ownershipFenced: true,
        compareAndSwap: true,
        atomicEvidenceBinding: true,
        rows,
        async reserve(binding) {
            if (rows.has(binding.attempt_id))
                return { reserved: false, reason: 'attempt_exists' };
            const owner = `owner:${crypto.randomBytes(24).toString('base64url')}`;
            rows.set(binding.attempt_id, { binding: structuredClone(binding), owner, state: 'RESERVED' });
            return { reserved: true, owner: owner };
        },
        async transition(input) {
            const row = rows.get(input.attempt_id);
            if (!row || row.owner !== input.owner || row.state !== input.expected_state)
                return false;
            row.state = input.next_state;
            return true;
        },
        async reconcile(input) {
            const row = rows.get(input.attempt_id);
            if (!row || row.owner !== input.owner || row.state !== input.expected_state)
                return false;
            const binding = row.binding;
            const evidence = input.evidence;
            for (const field of [
                'tenant_id', 'provider_id', 'provider_account_id', 'environment',
                'attempt_id', 'request_digest',
            ]) {
                if (evidence[field] !== binding[field])
                    return false;
            }
            row.state = input.next_state;
            row.evidence = structuredClone(evidence);
            return true;
        },
    };
}
function input(f, action = ACTION) {
    return {
        evaluation: f.evaluation,
        action,
        artifacts: f.artifacts,
        current_statuses: f.current_statuses,
    };
}
function executedEvidence() {
    return {
        evidence_id: 'provider-evidence:executed-1',
        observed_at: '2026-08-09T12:00:02.000Z',
        evidence_digest: digestAeb({ provider: 'bank', outcome: 'executed', id: 1 }),
    };
}
function makeBoundary({ f = fixture(), aebStore = durableAebStore(), attempts = attemptStore(), invoke = async () => ({ state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect-1' } }), } = {}) {
    let attemptCounter = 0;
    const boundary = createConsequenceBoundary({
        executor_id: EXECUTOR,
        provider: {
            tenant_id: 'tenant:acme',
            provider_id: 'provider:bank',
            provider_account_id: 'account:one',
            environment: 'sandbox',
        },
        aeb: { config: f.config, adapters: f.adapters, store: aebStore },
        attempts: {
            store: attempts,
            create_id: () => `attempt:${++attemptCounter}`,
            recover: ({ attempt, recovery_authorization }) => {
                if (recovery_authorization !== 'recovery:approved')
                    return null;
                const row = attempts.rows.get(attempt.attempt_id);
                if (!row)
                    return null;
                return { ...structuredClone(row.binding), owner: row.owner };
            },
        },
        local_authorize: () => true,
        invoke,
        now: () => NOW,
    });
    return { boundary, aebStore, attempts };
}
test('neutral consequence boundary executes native mandate evidence without requiring a receipt or human role', async () => {
    const f = fixture();
    let calls = 0;
    const h = makeBoundary({
        f,
        invoke: async (context) => {
            calls += 1;
            assert.equal(Object.isFrozen(context), true);
            assert.equal(Object.isFrozen(context.action), true);
            assert.equal(context.caid, CAID);
            return { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect-1' } };
        },
    });
    const result = await h.boundary.run(input(f));
    assert.equal(result.state, 'EXECUTED');
    assert.equal(result.invoked, true);
    assert.equal(calls, 1);
});
test('approve-A execute-B substitution is refused before the provider callback', async () => {
    const f = fixture();
    let calls = 0;
    const h = makeBoundary({ f, invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        } });
    const result = await h.boundary.run(input(f, { ...ACTION, amount: '5000.00' }));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.invoked, false);
    assert.equal(calls, 0);
});
test('same native mandate cannot be wrapped under a new operation and admitted twice', async () => {
    const first = fixture({ operationId: 'operation:first' });
    const second = fixture({ operationId: 'operation:second' });
    const aebStore = durableAebStore();
    const firstBoundary = makeBoundary({ f: first, aebStore }).boundary;
    const secondBoundary = makeBoundary({ f: second, aebStore }).boundary;
    assert.equal((await firstBoundary.run(input(first))).state, 'EXECUTED');
    const replay = await secondBoundary.run(input(second));
    assert.equal(replay.state, 'REFUSED');
    assert.equal(replay.reason, 'native_replay_conflict');
});
test('provider exception becomes INDETERMINATE and keeps the authorization fenced', async () => {
    const f = fixture();
    const h = makeBoundary({ f, invoke: async () => { throw new Error('connection_lost'); } });
    const first = await h.boundary.run(input(f));
    assert.equal(first.state, 'INDETERMINATE');
    assert.equal(first.invoked, true);
    assert.equal(first.retry_allowed, false);
    const retry = await h.boundary.run(input(f));
    assert.equal(retry.state, 'REFUSED');
    assert.match(retry.reason, /consumption_conflict/);
});
test('authoritative FAILED burns the one-time authorization and requires a new action instance', async () => {
    const f = fixture();
    const h = makeBoundary({
        f,
        invoke: async () => ({
            state: 'FAILED',
            reason: 'provider_declined',
            evidence: {
                evidence_id: 'provider-evidence:failed-1',
                observed_at: '2026-08-09T12:00:02.000Z',
                evidence_digest: digestAeb({ provider: 'bank', outcome: 'not-committed', id: 1 }),
            },
        }),
    });
    const failed = await h.boundary.run(input(f));
    assert.equal(failed.state, 'FAILED');
    assert.equal(failed.retry_allowed, false);
    const replay = await h.boundary.run(input(f));
    assert.equal(replay.state, 'REFUSED');
});
test('evaluation for another executor is refused before local policy and effect', async () => {
    const f = fixture({ executorId: 'executor:other' });
    let calls = 0;
    const h = makeBoundary({ f, invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        } });
    const result = await h.boundary.run(input(f));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'executor_binding_mismatch');
    assert.equal(calls, 0);
});
test('concurrent admission invokes the provider exactly once', async () => {
    const f = fixture();
    let calls = 0;
    const h = makeBoundary({ f, invoke: async () => {
            calls += 1;
            await Promise.resolve();
            return { state: 'EXECUTED', evidence: executedEvidence(), result: { ok: true } };
        } });
    const results = await Promise.all([
        h.boundary.run(input(f)),
        h.boundary.run(input(f)),
    ]);
    assert.equal(calls, 1);
    assert.deepEqual(results.map((result) => result.state).sort(), ['EXECUTED', 'REFUSED']);
});
test('post-effect hostile outcome objects fail closed and non-JSON provider results do not throw', async () => {
    const hostileFixture = fixture({ operationId: 'operation:hostile-result' });
    const hostile = {};
    Object.defineProperty(hostile, 'state', {
        enumerable: true,
        get() { throw new Error('outcome accessor executed'); },
    });
    const hostileBoundary = makeBoundary({
        f: hostileFixture,
        invoke: async () => hostile,
    }).boundary;
    const hostileResult = await hostileBoundary.run(input(hostileFixture));
    assert.equal(hostileResult.state, 'INDETERMINATE');
    assert.equal(hostileResult.reason, 'provider_outcome_invalid');
    const binaryFixture = fixture({ operationId: 'operation:binary-result', replayId: 'native-mandate:binary' });
    const binary = Buffer.from('provider-native-result');
    const binaryBoundary = makeBoundary({
        f: binaryFixture,
        invoke: async () => ({ state: 'EXECUTED', evidence: executedEvidence(), result: binary }),
    }).boundary;
    const binaryResult = await binaryBoundary.run(input(binaryFixture));
    assert.equal(binaryResult.state, 'EXECUTED');
    if (binaryResult.state === 'EXECUTED')
        assert.equal(binaryResult.result, binary);
});
test('INDETERMINATE is closed to replay but can be reconciled through separately authorized custody recovery', async () => {
    const f = fixture({ operationId: 'operation:reconcile', replayId: 'native-mandate:reconcile' });
    const h = makeBoundary({
        f,
        invoke: async () => ({ state: 'INDETERMINATE', reason: 'provider_timeout' }),
    });
    const first = await h.boundary.run(input(f));
    assert.equal(first.state, 'INDETERMINATE');
    assert.ok(first.attempt);
    const refusedRecovery = await h.boundary.reconcile({
        evaluation: f.evaluation,
        action: ACTION,
        artifacts: f.artifacts,
        attempt: first.attempt,
        outcome: { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect:recovered' } },
        recovery_authorization: 'recovery:wrong',
    });
    assert.equal(refusedRecovery.state, 'REFUSED');
    assert.equal(refusedRecovery.reason, 'attempt_recovery_refused');
    const reconciled = await h.boundary.reconcile({
        evaluation: f.evaluation,
        action: ACTION,
        artifacts: f.artifacts,
        attempt: first.attempt,
        outcome: { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect:recovered' } },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    const replay = await h.boundary.run(input(f));
    assert.equal(replay.state, 'REFUSED');
});
