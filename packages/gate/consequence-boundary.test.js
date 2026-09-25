// SPDX-License-Identifier: Apache-2.0
// Generated from consequence-boundary.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { adapterPinDigest, aebReservationKey, digestAeb, evaluateAebEvidence, mappingProfileDigest, registryEntryDigest, unifiedRegistryDigest, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION, AEB_NATIVE_AUTHORIZATION_PINS_VERSION, AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION, AEB_NATIVE_AUTHORIZATION_STATUS_VERSION, aebNativeAuthorizationReplayKey, digestAebNativeAuthorizationAction, issueAebNativeAuthorizationHandoff, verifyAebNativeAuthorizationHandoff, } from '@emilia-protocol/verify/aeb';
import { loadDefaultAgilityMldsaBackend } from '@emilia-protocol/verify/pq-signature-agility';
import { consequenceBoundaryActionFenceHolderKey, consequenceBoundaryRecoveryAttemptIdentity, consequenceBoundaryRecoveryClaimKey, consequenceBoundaryRecoveryClaimMarkerKey, consequenceBoundaryProviderIdempotencyKey, createConsequenceBoundary, createNativeConsequenceBoundary, nativeConsequenceBoundaryActionFenceKey, nativeConsequenceBoundaryAttemptReservationKeys, nativeConsequenceBoundaryProviderIdempotencyKey, nativeConsequenceBoundaryReservationKey, } from './consequence-boundary.js';
import { FINANCE_CUMULATIVE_EXPOSURE_PROFILE, createConsequenceEnvelopeBoundary, createMemoryConsequenceEnvelopeStore, issueConsequenceEnvelope, } from './dist/consequence-envelope.js';
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
const PROVIDER = Object.freeze({
    tenant_id: 'tenant:acme',
    provider_id: 'provider:bank',
    provider_account_id: 'account:one',
    environment: 'sandbox',
});
const COMPOSED_BOUNDARY_ID = 'composed-boundary-1';
const NATIVE_BOUNDARY_ID = 'native-boundary-1';
function registryEntry(entryId, kind, definition) {
    const entry = { kind, version: '1', status: 'active', definition };
    entry.definition_digest = registryEntryDigest(entryId, entry);
    return entry;
}
function fixture({ operationId = 'operation:release-1', executorId = EXECUTOR, replayId = 'native-mandate:one', evaluatorKeys = undefined, } = {}) {
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
    const evaluator = evaluatorKeys ?? crypto.generateKeyPairSync('ed25519');
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
        evaluatorKeys: evaluator,
    };
}
function durableAebDatabase() {
    return {
        operations: new Map(),
        ownerTokens: new Map(),
        replayOwners: new Map(),
    };
}
/**
 * Durable test store with the shipped PostgreSQL store's ownership model:
 * the database outlives the process, but commit and release are fenced to the
 * store instance that reserved (or has since claimed) the row. A restarted
 * process is a new instance over the same database and holds no owner token
 * until an authorized recovery claim.
 */
function durableAebStore(db = durableAebDatabase(), authorizeClaim = ({ authorization }) => authorization === 'recovery:approved') {
    const owned = new Map();
    const claims = [];
    const claimScopes = [];
    const ownsRow = (key) => owned.has(key)
        && db.ownerTokens.get(key) === owned.get(key);
    return {
        durable: true,
        ownershipFenced: true,
        permanentConsumption: true,
        atomicReplayFenced: true,
        recoveryClaimSupported: true,
        db,
        operations: db.operations,
        replayOwners: db.replayOwners,
        claims,
        claimScopes,
        async reserve(key, replayKeys) {
            if (db.operations.has(key))
                return 'CONSUMPTION_CONFLICT';
            if (replayKeys.some((replayKey) => db.replayOwners.has(replayKey))) {
                return 'NATIVE_REPLAY_CONFLICT';
            }
            const token = crypto.randomUUID();
            db.operations.set(key, 'RESERVED');
            db.ownerTokens.set(key, token);
            owned.set(key, token);
            for (const replayKey of replayKeys)
                db.replayOwners.set(replayKey, key);
            return 'RESERVED';
        },
        // Like the PostgreSQL store, any commit or release attempt drops this
        // instance's owner token, so a token another claim replaced is not kept.
        async commit(key) {
            if (db.operations.get(key) !== 'RESERVED' || !ownsRow(key)) {
                owned.delete(key);
                return false;
            }
            db.operations.set(key, 'CONSUMED');
            db.ownerTokens.delete(key);
            owned.delete(key);
            return true;
        },
        async release(key) {
            if (db.operations.get(key) !== 'RESERVED' || !ownsRow(key)) {
                owned.delete(key);
                return false;
            }
            db.operations.delete(key);
            db.ownerTokens.delete(key);
            owned.delete(key);
            for (const [replayKey, owner] of db.replayOwners) {
                if (owner === key)
                    db.replayOwners.delete(replayKey);
            }
            return true;
        },
        terminalRelease: true,
        async releaseTerminal(key) {
            if (db.operations.get(key) === 'RELEASED_NOT_ENTERED')
                return true;
            if (db.operations.get(key) !== 'RESERVED' || !ownsRow(key)) {
                owned.delete(key);
                return false;
            }
            // The row stays, so the key and its replay fences can never be reserved again.
            db.operations.set(key, 'RELEASED_NOT_ENTERED');
            db.ownerTokens.delete(key);
            owned.delete(key);
            return true;
        },
        async claimReservation(key, authorization, scope) {
            if (owned.has(key) || !authorizeClaim({ key, authorization, scope })
                || db.operations.get(key) !== 'RESERVED')
                return false;
            const token = crypto.randomUUID();
            db.ownerTokens.set(key, token);
            owned.set(key, token);
            claims.push(key);
            claimScopes.push(scope);
            return true;
        },
        state(key) {
            return db.operations.get(key) ?? 'AVAILABLE';
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
        notEnteredMarker: true,
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
            // A move to RELEASED persists its not-entered marker with the state.
            if (input.next_state === 'RELEASED')
                row.evidence = structuredClone(input.evidence);
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
                'attempt_id', 'request_digest', 'provider_idempotency_key',
            ]) {
                if (evidence[field] !== binding[field])
                    return false;
            }
            row.state = input.next_state;
            row.evidence = structuredClone(evidence);
            return true;
        },
        async state(input) {
            const row = rows.get(input.attempt_id);
            if (!row || row.owner !== input.owner)
                throw new Error('attempt_not_owned');
            return {
                state: row.state,
                ...(row.evidence ? { evidence: structuredClone(row.evidence) } : {}),
            };
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
/**
 * The only verifier answer a boundary accepts: an affirmation of the exact
 * purpose, attempt, and provider idempotency key it was asked about.
 */
function affirm(context) {
    return {
        verified: true,
        purpose: context.purpose,
        attempt_id: context.attempt.attempt_id,
        provider_idempotency_key: context.provider_idempotency_key,
    };
}
function makeBoundary({ f = fixture(), aebStore = durableAebStore(), attempts = attemptStore(), consequenceEnvelope = undefined, localAuthorize = () => true, invoke = async () => ({ state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect-1' } }), attemptPrefix = '', providerOutcomeVerify = affirm, createId = undefined, boundaryId = COMPOSED_BOUNDARY_ID, } = {}) {
    let attemptCounter = 0;
    const boundary = createConsequenceBoundary({
        executor_id: EXECUTOR,
        boundary_id: boundaryId,
        provider: PROVIDER,
        aeb: { config: f.config, adapters: f.adapters, store: aebStore },
        attempts: {
            store: attempts,
            create_id: createId ?? (() => `attempt:${attemptPrefix}${++attemptCounter}`),
            recover: ({ attempt, recovery_authorization }) => {
                if (recovery_authorization !== 'recovery:approved')
                    return null;
                const row = attempts.rows.get(attempt.attempt_id);
                if (!row)
                    return null;
                return { ...structuredClone(row.binding), owner: row.owner };
            },
        },
        consequence_envelope: consequenceEnvelope,
        allow_test_consequence_envelope: consequenceEnvelope ? true : undefined,
        local_authorize: localAuthorize,
        invoke,
        ...(providerOutcomeVerify ? { provider_outcomes: { verify: providerOutcomeVerify } } : {}),
        now: () => NOW,
    });
    return { boundary, aebStore, attempts };
}
async function unitConsequenceEnvelope(capacityUnits = '1') {
    const edPrivate = crypto.createPrivateKey({
        key: {
            crv: 'Ed25519',
            d: 'EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y',
            x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
            kty: 'OKP',
        },
        format: 'jwk',
    });
    const edPublic = crypto.createPublicKey(edPrivate);
    const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x61));
    const mldsaBackend = await loadDefaultAgilityMldsaBackend();
    assert.ok(mldsaBackend);
    const envelope = await issueConsequenceEnvelope({
        envelope_id: 'envelope:boundary-integration:1',
        state_domain_id: 'state-domain:boundary-integration',
        epoch: 1,
        capacity_units: capacityUnits,
        impact_profile_id: FINANCE_CUMULATIVE_EXPOSURE_PROFILE.id,
        impact_profile_digest: FINANCE_CUMULATIVE_EXPOSURE_PROFILE.digest,
        validity: {
            not_before: '2026-08-09T12:00:00.000Z',
            not_after: '2026-08-09T12:10:00.000Z',
        },
        issuer: { id: 'authority:boundary-integration', key_id: 'envelope-ed' },
        parent_allocation: null,
        renewable: false,
    }, {
        signing_keys: [
            { alg: 'Ed25519', key_id: 'envelope-ed', private_key: edPrivate },
            { alg: 'ML-DSA-65', key_id: 'envelope-pq', private_key: pqPair.secretKey },
        ],
        mldsaBackend,
    });
    return createConsequenceEnvelopeBoundary({
        envelope,
        verification_keys: [
            {
                alg: 'Ed25519',
                key_id: 'envelope-ed',
                public_key: edPublic.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
            {
                alg: 'ML-DSA-65',
                key_id: 'envelope-pq',
                public_key: Buffer.from(pqPair.publicKey).toString('base64url'),
            },
        ],
        mldsaBackend,
        profile: {
            ...FINANCE_CUMULATIVE_EXPOSURE_PROFILE,
            derive() {
                return { ok: true, impact_units: 1n };
            },
        },
        store: createMemoryConsequenceEnvelopeStore(),
        allow_test_store: true,
        now: () => NOW,
        authorize_recovery: ({ recovery_authorization }) => recovery_authorization === 'recovery:approved',
    });
}
test('neutral consequence boundary executes native mandate evidence without requiring a receipt or human role', async () => {
    const f = fixture();
    let calls = 0;
    const h = makeBoundary({
        f,
        localAuthorize: (context) => {
            assert.equal(Object.isFrozen(context), true);
            assert.equal(Object.isFrozen(context.action), true);
            assert.deepEqual(context.action, ACTION);
            assert.equal(context.evaluation.operation_id, f.evaluation.operation_id);
            assert.equal(context.provider.provider_account_id, PROVIDER.provider_account_id);
            return true;
        },
        invoke: async (context) => {
            calls += 1;
            assert.equal(Object.isFrozen(context), true);
            assert.equal(Object.isFrozen(context.action), true);
            assert.equal(context.caid, CAID);
            assert.equal(context.provider_idempotency_key, consequenceBoundaryProviderIdempotencyKey({
                provider: PROVIDER,
                caid: CAID,
                action_digest: digestAeb(ACTION),
                authorization_instance: f.evaluation.consumption_nonce,
            }));
            assert.equal(context.attempt.provider_idempotency_key, context.provider_idempotency_key);
            return { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'effect-1' } };
        },
    });
    const result = await h.boundary.run(input(f));
    assert.equal(result.state, 'EXECUTED');
    assert.equal(result.invoked, true);
    assert.equal(calls, 1);
});
test('provider idempotency key is canonical, provider-scoped, and bound to one exact authorization instance', () => {
    const base = {
        provider: PROVIDER,
        caid: CAID,
        action_digest: digestAeb(ACTION),
        authorization_instance: 'nonce:operation:release-1',
    };
    const first = consequenceBoundaryProviderIdempotencyKey(base);
    assert.match(first, /^epcb1:[a-f0-9]{64}$/);
    assert.equal(consequenceBoundaryProviderIdempotencyKey(base), first);
    assert.notEqual(consequenceBoundaryProviderIdempotencyKey({
        ...base,
        provider: { ...PROVIDER, provider_account_id: 'account:two' },
    }), first);
    assert.notEqual(consequenceBoundaryProviderIdempotencyKey({
        ...base,
        action_digest: digestAeb({ ...ACTION, amount: '501.00' }),
    }), first);
    assert.notEqual(consequenceBoundaryProviderIdempotencyKey({
        ...base,
        authorization_instance: 'nonce:operation:release-2',
    }), first);
});
test('approve-A execute-B substitution is refused before the provider callback', async () => {
    const f = fixture();
    let localCalls = 0;
    let calls = 0;
    const h = makeBoundary({
        f,
        localAuthorize: () => {
            localCalls += 1;
            return true;
        },
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        },
    });
    const result = await h.boundary.run(input(f, { ...ACTION, amount: '5000.00' }));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.invoked, false);
    assert.equal(result.reason, 'exact_action_binding_mismatch');
    assert.equal(localCalls, 0);
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal(calls, 0);
});
test('an untrusted evaluation cannot obtain the trusted exact-action mismatch reason', async () => {
    const f = fixture({ operationId: 'operation:untrusted-substitution', replayId: 'native-mandate:untrusted-substitution' });
    const evaluation = structuredClone(f.evaluation);
    evaluation.signature.value = `${evaluation.signature.value[0] === 'A' ? 'B' : 'A'}${evaluation.signature.value.slice(1)}`;
    let localCalls = 0;
    let calls = 0;
    const h = makeBoundary({
        f,
        localAuthorize: () => {
            localCalls += 1;
            return true;
        },
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        },
    });
    const result = await h.boundary.run({
        ...input(f, { ...ACTION, amount: '5000.00' }),
        evaluation,
    });
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.invoked, false);
    assert.notEqual(result.reason, 'exact_action_binding_mismatch');
    assert.equal(localCalls, 0);
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal(calls, 0);
});
test('local authorization denial is load-bearing and blocks provider entry', async () => {
    const f = fixture({ operationId: 'operation:local-refusal', replayId: 'native-mandate:local-refusal' });
    let calls = 0;
    const h = makeBoundary({
        f,
        localAuthorize: () => false,
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        },
    });
    const result = await h.boundary.run(input(f));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.invoked, false);
    assert.equal(result.reason, 'local_authorization_denied');
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal(calls, 0);
});
test('local authorization exceptions fail closed before provider entry', async () => {
    const f = fixture({ operationId: 'operation:local-error', replayId: 'native-mandate:local-error' });
    let calls = 0;
    const h = makeBoundary({
        f,
        localAuthorize: () => { throw new Error('policy_unavailable'); },
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        },
    });
    const result = await h.boundary.run(input(f));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.invoked, false);
    assert.equal(result.reason, 'local_authorization_denied');
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal(calls, 0);
});
test('local authorization requires the exact boolean true', async () => {
    const f = fixture({ operationId: 'operation:local-truthy', replayId: 'native-mandate:local-truthy' });
    let calls = 0;
    const h = makeBoundary({
        f,
        localAuthorize: () => 1,
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        },
    });
    const result = await h.boundary.run(input(f));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.invoked, false);
    assert.equal(result.reason, 'local_authorization_denied');
    assert.equal(h.aebStore.operations.size, 0);
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
    let localCalls = 0;
    let calls = 0;
    const h = makeBoundary({
        f,
        localAuthorize: () => {
            localCalls += 1;
            return true;
        },
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: null };
        },
    });
    const result = await h.boundary.run(input(f));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'executor_binding_mismatch');
    assert.equal(localCalls, 0);
    assert.equal(h.aebStore.operations.size, 0);
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
    const binary = Buffer.from('provider-native-result');
    // The result is snapshotted before it is verified, as on the native path;
    // a non-JSON result is invalid, not a throw.
    const verifiedFixture = fixture({ operationId: 'operation:binary-verified', replayId: 'native-mandate:binary-verified' });
    const verifiedBoundary = makeBoundary({
        f: verifiedFixture,
        invoke: async () => ({ state: 'EXECUTED', evidence: executedEvidence(), result: binary }),
    }).boundary;
    const verifiedResult = await verifiedBoundary.run(input(verifiedFixture));
    assert.equal(verifiedResult.state, 'INDETERMINATE');
    assert.equal(verifiedResult.reason, 'provider_outcome_invalid');
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
    const tamperedBinding = await h.boundary.reconcile({
        evaluation: f.evaluation,
        action: ACTION,
        artifacts: f.artifacts,
        attempt: {
            ...first.attempt,
            provider_idempotency_key: `epcb1:${'0'.repeat(64)}`,
        },
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), result: { id: 'effect:wrong-key' } },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(tamperedBinding.state, 'REFUSED');
    assert.equal(tamperedBinding.reason, 'reconciliation_binding_mismatch');
    const refusedRecovery = await h.boundary.reconcile({
        evaluation: f.evaluation,
        action: ACTION,
        artifacts: f.artifacts,
        attempt: first.attempt,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), result: { id: 'effect:recovered' } },
        recovery_authorization: 'recovery:wrong',
    });
    assert.equal(refusedRecovery.state, 'REFUSED');
    assert.equal(refusedRecovery.reason, 'attempt_recovery_refused');
    const reconciled = await h.boundary.reconcile({
        evaluation: f.evaluation,
        action: ACTION,
        artifacts: f.artifacts,
        attempt: first.attempt,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), result: { id: 'effect:recovered' } },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    const replay = await h.boundary.run(input(f));
    assert.equal(replay.state, 'REFUSED');
});
test('a shared consequence envelope refuses oversubscription before a second provider entry', async () => {
    const envelope = await unitConsequenceEnvelope('1');
    const first = fixture({ operationId: 'operation:capacity:first', replayId: 'native-mandate:capacity:first' });
    const second = fixture({ operationId: 'operation:capacity:second', replayId: 'native-mandate:capacity:second' });
    let providerCalls = 0;
    const invoke = async () => {
        providerCalls += 1;
        return { state: 'EXECUTED', evidence: executedEvidence(), result: { admitted: true } };
    };
    const firstBoundary = makeBoundary({ f: first, consequenceEnvelope: envelope, invoke });
    const secondBoundary = makeBoundary({ f: second, consequenceEnvelope: envelope, invoke });
    assert.equal((await firstBoundary.boundary.run(input(first))).state, 'EXECUTED');
    const refused = await secondBoundary.boundary.run(input(second));
    assert.equal(refused.state, 'REFUSED');
    assert.equal(refused.reason, 'consequence_envelope_capacity_exceeded');
    assert.equal(providerCalls, 1);
    assert.equal(secondBoundary.aebStore.operations.size, 0);
    assert.deepEqual(envelope.snapshot(), {
        capacity_units: '1',
        available_units: '0',
        held_units: '0',
        committed_units: '1',
    });
});
test('unknown provider outcome keeps aggregate capacity unavailable and reconciliation never reexecutes', async () => {
    const envelope = await unitConsequenceEnvelope('1');
    const f = fixture({ operationId: 'operation:capacity:unknown', replayId: 'native-mandate:capacity:unknown' });
    let providerCalls = 0;
    const h = makeBoundary({
        f,
        consequenceEnvelope: envelope,
        invoke: async () => {
            providerCalls += 1;
            throw new Error('response_lost');
        },
    });
    const first = await h.boundary.run(input(f));
    assert.equal(first.state, 'INDETERMINATE');
    assert.ok(first.attempt);
    assert.equal(providerCalls, 1);
    assert.equal(envelope.snapshot().committed_units, '1');
    const retry = await h.boundary.run(input(f));
    assert.equal(retry.state, 'REFUSED');
    assert.equal(providerCalls, 1);
    const reconciled = await h.boundary.reconcile({
        evaluation: f.evaluation,
        action: ACTION,
        artifacts: f.artifacts,
        attempt: first.attempt,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), result: { id: 'effect:reconciled' } },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    assert.equal(providerCalls, 1);
    assert.equal(envelope.snapshot().committed_units, '1');
});
test('authoritative non-commitment releases aggregate capacity without reviving spent authority', async () => {
    const envelope = await unitConsequenceEnvelope('1');
    const f = fixture({ operationId: 'operation:capacity:failed', replayId: 'native-mandate:capacity:failed' });
    const h = makeBoundary({
        f,
        consequenceEnvelope: envelope,
        invoke: async () => ({
            state: 'FAILED',
            reason: 'provider_declined',
            evidence: {
                evidence_id: 'provider-evidence:capacity-failed',
                observed_at: '2026-08-09T12:00:02.000Z',
                evidence_digest: digestAeb({ provider: 'bank', outcome: 'not-committed', id: 'capacity' }),
            },
        }),
    });
    const failed = await h.boundary.run(input(f));
    assert.equal(failed.state, 'FAILED');
    assert.equal(envelope.snapshot().available_units, '1');
    assert.equal(envelope.snapshot().committed_units, '0');
    assert.equal((await h.boundary.run(input(f))).state, 'REFUSED');
});
function nativeFixture(system = 'authzen', relyingPartyId = 'rp:payments') {
    const pair = crypto.generateKeyPairSync('ed25519');
    const gatewayId = `gateway:${system}`;
    const keyId = `gateway-key:${system}:one`;
    const nativeAuthorization = {
        system,
        profile: `${system}:exact-action-result:1`,
        issuer: `https://${system}.example`,
        authorization_id: `native-authz:${system}:123`,
    };
    const pins = {
        '@version': AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
        relying_party_id: relyingPartyId,
        audience: 'https://gate.example/payments',
        executor_id: EXECUTOR,
        provider: PROVIDER,
        max_handoff_age_seconds: 120,
        max_status_age_seconds: 30,
        clock_skew_seconds: 2,
        gateway_keys: [{
                '@version': AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
                gateway_id: gatewayId,
                key_id: keyId,
                algorithm: 'Ed25519',
                public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            }],
        accepted_sources: [{
                '@version': AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
                gateway_id: gatewayId,
                system,
                profile: nativeAuthorization.profile,
                issuer: nativeAuthorization.issuer,
            }],
    };
    const handoffInput = {
        gateway_id: gatewayId,
        native_authorization: nativeAuthorization,
        relying_party_id: pins.relying_party_id,
        audience: pins.audience,
        executor_id: pins.executor_id,
        provider: PROVIDER,
        action: ACTION,
        issued_at: '2026-08-09T12:00:00.000Z',
        not_before: '2026-08-09T12:00:00.000Z',
        expires_at: '2026-08-09T12:01:00.000Z',
        revocation_id: `revocation:${system}:123`,
    };
    const signer = { key_id: keyId, private_key: pair.privateKey };
    const handoff = issueAebNativeAuthorizationHandoff(handoffInput, signer);
    const status = {
        '@version': AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
        gateway_id: gatewayId,
        native_authorization: handoff.native_authorization,
        revocation_id: handoffInput.revocation_id,
        checked_at: '2026-08-09T12:00:00.000Z',
        valid_until: '2026-08-09T12:00:30.000Z',
        revoked: false,
    };
    return { pins, handoffInput, signer, handoff, status };
}
function issueNative(f, overrides) {
    return issueAebNativeAuthorizationHandoff({ ...f.handoffInput, ...overrides }, f.signer);
}
function makeNativeBoundary({ f = nativeFixture(), aebStore = durableAebStore(), attempts = attemptStore(), localAuthorize = () => true, resolveStatus = () => f.status, resolveHistoricalPins = () => f.pins, providerOutcomeVerify = affirm, trustSnapshotId = 'native-trust-snapshot:test:1', localAuthorizationProgramDigest = digestAeb({
    program: 'native-local-authorization:test:1',
}), providerOutcomeVerificationProgramDigest = digestAeb({
    program: 'native-provider-outcome-verifier:test:1',
}), recover = undefined, invoke = async () => ({
    state: 'EXECUTED',
    evidence: executedEvidence(),
    result: { id: 'native-effect-1' },
}), now = () => NOW, attemptPrefix = '', createId = undefined, boundaryId = NATIVE_BOUNDARY_ID, } = {}) {
    let attemptCounter = 0;
    const configuration = {
        executor_id: EXECUTOR,
        boundary_id: boundaryId,
        provider: PROVIDER,
        native_authorization: {
            pins: f.pins,
            trust_snapshot_id: trustSnapshotId,
            store: aebStore,
            resolve_status: resolveStatus,
            resolve_historical_pins: resolveHistoricalPins,
        },
        attempts: {
            store: attempts,
            create_id: createId ?? (() => `native-attempt:${attemptPrefix}${++attemptCounter}`),
            recover: recover ?? (({ attempt, recovery_authorization }) => {
                if (recovery_authorization !== 'recovery:approved')
                    return null;
                const row = attempts.rows.get(attempt.attempt_id);
                return row ? { ...structuredClone(row.binding), owner: row.owner } : null;
            }),
        },
        local_authorization_program_digest: localAuthorizationProgramDigest,
        local_authorize: localAuthorize,
        invoke,
        provider_outcomes: {
            verification_program_digest: providerOutcomeVerificationProgramDigest,
            verify: providerOutcomeVerify,
        },
        now,
    };
    const boundary = createNativeConsequenceBoundary(configuration);
    return { boundary, aebStore, attempts, configuration };
}
function nativeInput(f, operationId = 'operation:native:one', overrides = {}) {
    return {
        operation_id: operationId,
        handoff: f.handoff,
        action: ACTION,
        ...overrides,
    };
}
test('direct native AIMS and COAZ PERMITs execute without a CAID or AEC evaluation', async () => {
    for (const system of ['aims', 'coaz']) {
        const f = nativeFixture(system);
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            localAuthorize: (context) => {
                assert.equal(context.verification.execution_authorizing, true);
                assert.equal(context.handoff.native_authorization.system, system);
                assert.match(context.local_authorization_program_digest, /^sha256:[0-9a-f]{64}$/);
                return true;
            },
            invoke: async (context) => {
                calls += 1;
                assert.equal(Object.hasOwn(context, 'caid'), false);
                assert.equal(Object.hasOwn(context, 'evaluation'), false);
                assert.equal(context.local_authorization.decision, 'PERMIT');
                assert.equal(context.local_authorization.program_digest, context.attempt.local_authorization_program_digest);
                assert.equal(context.local_authorization.decision_digest, context.attempt.local_decision_digest);
                assert.equal(context.authorization_program_digest, context.attempt.authorization_program_digest);
                assert.equal(context.trust_snapshot_digest, context.attempt.trust_snapshot_digest);
                return { state: 'EXECUTED', evidence: executedEvidence(), result: { system } };
            },
        });
        const result = await h.boundary.run(nativeInput(f, `operation:native:${system}`));
        assert.equal(result.state, 'EXECUTED', system);
        assert.equal(calls, 1, system);
    }
});
test('direct native binding, source, freshness, and revocation failures stop before local policy and provider entry', async () => {
    const cases = [
        {
            name: 'action',
            prepare: () => ({ action: { ...ACTION, amount: '5000.00' } }),
            reason: 'native_handoff_exact_action_mismatch',
        },
        {
            name: 'provider',
            prepare: (f) => ({
                handoff: issueNative(f, {
                    provider: { ...PROVIDER, provider_account_id: 'account:other' },
                }),
            }),
            reason: 'native_handoff_provider_mismatch',
        },
        {
            name: 'audience',
            prepare: (f) => ({ handoff: issueNative(f, { audience: 'https://other.example/gate' }) }),
            reason: 'native_handoff_audience_mismatch',
        },
        {
            name: 'executor',
            prepare: (f) => ({ handoff: issueNative(f, { executor_id: 'executor:other' }) }),
            reason: 'native_handoff_executor_mismatch',
        },
        {
            name: 'source',
            prepare: (f) => ({
                handoff: issueNative(f, {
                    native_authorization: {
                        ...f.handoffInput.native_authorization,
                        profile: 'authzen:untrusted-profile:1',
                    },
                }),
            }),
            reason: 'native_handoff_source_not_pinned',
        },
        {
            name: 'freshness',
            prepare: () => ({}),
            now: () => '2026-08-09T12:03:00.000Z',
            reason: 'native_handoff_stale_or_not_current',
        },
        {
            // Status reaches the boundary only through the trusted resolver. These
            // resolver cases send well-formed run input so the resolver is reached.
            name: 'revocation',
            prepare: () => ({}),
            resolveStatus: (f) => ({ ...f.status, revoked: true }),
            reason: 'native_handoff_revoked',
        },
        {
            name: 'status-resolver-error',
            prepare: () => ({}),
            resolveStatus: () => { throw new Error('status source unavailable'); },
            reason: 'native_status_resolution_failed',
        },
        {
            name: 'status-resolver-invalid',
            prepare: () => ({}),
            resolveStatus: () => ({ revoked: false }),
            reason: 'native_handoff_revocation_status_invalid',
        },
        {
            // A caller cannot inject status: the extra member closes the input shape.
            name: 'caller-status-injection',
            prepare: (f) => ({ status: { ...f.status, revoked: false } }),
            resolveStatus: (f) => ({ ...f.status, revoked: true }),
            reason: 'native_execution_input_invalid',
        },
    ];
    for (const testCase of cases) {
        const f = nativeFixture();
        let localCalls = 0;
        let providerCalls = 0;
        let statusLookups = 0;
        const h = makeNativeBoundary({
            f,
            now: testCase.now ?? (() => NOW),
            resolveStatus: testCase.resolveStatus
                ? () => { statusLookups += 1; return testCase.resolveStatus(f); }
                : () => { statusLookups += 1; return f.status; },
            localAuthorize: () => { localCalls += 1; return true; },
            invoke: async () => {
                providerCalls += 1;
                return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        const result = await h.boundary.run(nativeInput(f, `operation:native:mutation:${testCase.name}`, testCase.prepare(f)));
        if (testCase.name.startsWith('status-') || testCase.name === 'revocation') {
            assert.equal(statusLookups, 1, `${testCase.name} must reach the trusted resolver`);
        }
        assert.equal(result.state, 'REFUSED', testCase.name);
        if (result.state === 'REFUSED')
            assert.equal(result.reason, testCase.reason, testCase.name);
        assert.equal(localCalls, 0, testCase.name);
        assert.equal(providerCalls, 0, testCase.name);
        assert.equal(h.aebStore.operations.size, 0, testCase.name);
    }
});
test('direct native local denial remains separate and blocks reservation and provider entry', async () => {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        localAuthorize: () => false,
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        },
    });
    const result = await h.boundary.run(nativeInput(f));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'local_authorization_denied');
    assert.equal(calls, 0);
});
test('direct native replay fencing is stable across operation IDs and concurrent dispatch', async () => {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        invoke: async () => {
            calls += 1;
            await new Promise((resolve) => setTimeout(resolve, 5));
            return { state: 'EXECUTED', evidence: executedEvidence(), result: { id: 'winner' } };
        },
    });
    const [first, second] = await Promise.all([
        h.boundary.run(nativeInput(f, 'operation:native:concurrent:one')),
        h.boundary.run(nativeInput(f, 'operation:native:concurrent:two')),
    ]);
    assert.equal(calls, 1);
    assert.deepEqual([first.state, second.state].sort(), ['EXECUTED', 'REFUSED']);
    const refusedResult = first.state === 'REFUSED' ? first : second;
    assert.equal(refusedResult.reason, 'native_replay_conflict');
});
test('post-entry throw, invalid result, and explicit uncertainty stay fenced against blind replay', async () => {
    for (const [name, outcome] of [
        ['throw', 'throw'],
        ['invalid', { state: 'EXECUTED', result: {} }],
        ['indeterminate', { state: 'INDETERMINATE', reason: 'provider_timeout' }],
    ]) {
        const f = nativeFixture();
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            invoke: async () => {
                calls += 1;
                if (outcome === 'throw')
                    throw new Error('response lost');
                return outcome;
            },
        });
        const first = await h.boundary.run(nativeInput(f, `operation:native:${name}:one`));
        assert.equal(first.state, 'INDETERMINATE', name);
        assert.equal(first.retry_allowed, false, name);
        const replay = await h.boundary.run(nativeInput(f, `operation:native:${name}:two`));
        assert.equal(replay.state, 'REFUSED', name);
        assert.equal(replay.reason, 'native_replay_conflict', name);
        assert.equal(calls, 1, name);
    }
});
test('direct native authenticated reconciliation closes uncertainty without re-invocation', async () => {
    const f = nativeFixture('oauth');
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        invoke: async () => {
            calls += 1;
            throw new Error('provider accepted request but response was lost');
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:reconcile'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.ok(first.attempt);
    assert.equal(calls, 1);
    const reconciled = await h.boundary.reconcile({
        operation_id: 'operation:native:reconcile',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: {
            state: 'EXECUTED', evidence_kind: 'provider_outcome',
            evidence: executedEvidence(),
            result: { id: 'provider-confirmed' },
        },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    assert.equal(calls, 1);
    const replay = await h.boundary.run(nativeInput(f, 'operation:native:reconcile:replay'));
    assert.equal(replay.state, 'REFUSED');
    assert.equal(replay.reason, 'native_replay_conflict');
    assert.equal(calls, 1);
});
test('invalid direct-native handoffs never trigger the trusted status lookup', async () => {
    const f = nativeFixture();
    const tampered = structuredClone(f.handoff);
    tampered.signature.value = `${tampered.signature.value[0] === 'A' ? 'B' : 'A'}${tampered.signature.value.slice(1)}`;
    let statusLookups = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: () => {
            statusLookups += 1;
            return f.status;
        },
    });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:invalid-preflight', {
        handoff: tampered,
    }));
    assert.equal(result.state, 'REFUSED');
    assert.equal(statusLookups, 0);
});
test('untrusted replay-key input cannot poison another authorization', async () => {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        },
    });
    const poisoned = await h.boundary.run({
        ...nativeInput(f, 'operation:native:poisoned'),
        additional_replay_keys: ['aeb-native:victim'],
    });
    assert.equal(poisoned.state, 'REFUSED');
    assert.equal(poisoned.reason, 'native_execution_input_invalid');
    assert.equal(calls, 0);
    const clean = await h.boundary.run(nativeInput(f, 'operation:native:clean'));
    assert.equal(clean.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('freshness and revocation are rechecked immediately before provider entry', async () => {
    const f = nativeFixture();
    const times = [
        '2026-08-09T12:00:01.000Z',
        '2026-08-09T12:00:02.000Z',
        '2026-08-09T12:00:33.000Z',
    ];
    let statusLookups = 0;
    let providerCalls = 0;
    const h = makeNativeBoundary({
        f,
        now: () => times.shift() ?? '2026-08-09T12:00:33.000Z',
        resolveStatus: () => {
            statusLookups += 1;
            return f.status;
        },
        invoke: async () => {
            providerCalls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        },
    });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:toctou'));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'native_handoff_revocation_status_not_current');
    assert.equal(statusLookups, 2);
    assert.equal(providerCalls, 0);
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal([...h.attempts.rows.values()][0]?.state, 'RELEASED');
});
test('revocation during a delayed custody transition prevents provider entry', async () => {
    const f = nativeFixture();
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    let revoked = false;
    let providerCalls = 0;
    attempts.transition = async (entry) => {
        const result = await transition(entry);
        if (entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
            revoked = true;
        }
        return result;
    };
    const h = makeNativeBoundary({
        f,
        attempts,
        resolveStatus: () => ({ ...f.status, revoked }),
        invoke: async () => {
            providerCalls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        },
    });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:transition-delay'));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'native_handoff_revoked');
    assert.equal(providerCalls, 0);
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal([...attempts.rows.values()][0]?.state, 'RELEASED');
});
test('terminal provider evidence must pass the pinned verifier for the exact attempt binding', async () => {
    for (const mode of ['forged', 'wrong-operation']) {
        const f = nativeFixture();
        let attestation = null;
        const h = makeNativeBoundary({
            f,
            invoke: async (context) => {
                const evidence = executedEvidence();
                attestation = {
                    operation_id: mode === 'wrong-operation'
                        ? 'operation:native:other'
                        : context.operation_id,
                    action_digest: context.action_digest,
                    native_replay_unit: context.native_replay_unit,
                    attempt_id: context.attempt.attempt_id,
                    outcome: 'EXECUTED',
                    evidence_digest: mode === 'forged'
                        ? digestAeb({ forged: true })
                        : evidence.evidence_digest,
                };
                return { state: 'EXECUTED', evidence, result: { id: mode } };
            },
            providerOutcomeVerify: (context) => (attestation !== null
                && attestation.operation_id === context.operation_id
                && attestation.action_digest === context.action_digest
                && attestation.native_replay_unit === context.native_replay_unit
                && attestation.attempt_id === context.attempt.attempt_id
                && attestation.outcome === context.outcome.state
                && attestation.evidence_digest === context.outcome.evidence.evidence_digest
                && context.verification_program_digest
                    === context.attempt.provider_outcome_verification_program_digest)
                ? affirm(context)
                : false,
        });
        const result = await h.boundary.run(nativeInput(f, `operation:native:provider-auth:${mode}`));
        assert.equal(result.state, 'INDETERMINATE', mode);
        assert.equal(result.reason, 'provider_outcome_authentication_failed', mode);
        assert.equal([...h.aebStore.operations.values()][0], 'RESERVED', mode);
        assert.equal([...h.attempts.rows.values()][0]?.state, 'INDETERMINATE', mode);
    }
});
test('authenticated provider evidence closes a fully bound direct-native attempt', async () => {
    const f = nativeFixture();
    let attestation = null;
    const h = makeNativeBoundary({
        f,
        invoke: async (context) => {
            const evidence = executedEvidence();
            attestation = {
                operation_id: context.operation_id,
                action_digest: context.action_digest,
                native_replay_unit: context.native_replay_unit,
                attempt_id: context.attempt.attempt_id,
                outcome: 'EXECUTED',
                evidence_digest: evidence.evidence_digest,
            };
            return { state: 'EXECUTED', evidence, result: { id: 'authenticated' } };
        },
        providerOutcomeVerify: (context) => (attestation !== null
            && attestation.operation_id === context.operation_id
            && attestation.action_digest === context.action_digest
            && attestation.native_replay_unit === context.native_replay_unit
            && attestation.attempt_id === context.attempt.attempt_id
            && attestation.outcome === context.outcome.state
            && attestation.evidence_digest === context.outcome.evidence.evidence_digest)
            ? affirm(context)
            : false,
    });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:provider-auth:valid'));
    assert.equal(result.state, 'EXECUTED');
    assert.equal([...h.aebStore.operations.values()][0], 'CONSUMED');
    assert.equal([...h.attempts.rows.values()][0]?.state, 'COMMITTED');
});
test('the provider cannot mutate a result after its verified outcome snapshot is accepted', async () => {
    const f = nativeFixture();
    const mutableResult = { id: 'verified-result', amount: '500.00' };
    const h = makeNativeBoundary({
        f,
        invoke: async () => ({
            state: 'EXECUTED',
            evidence: executedEvidence(),
            result: mutableResult,
        }),
        providerOutcomeVerify: (context) => (context.outcome.state === 'EXECUTED'
            && context.outcome.result.id === 'verified-result'
            && context.outcome.result.amount === '500.00')
            ? affirm(context)
            : false,
    });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:provider-result-snapshot'));
    assert.equal(result.state, 'EXECUTED');
    mutableResult.id = 'mutated-after-verification';
    mutableResult.amount = '5000.00';
    if (result.state === 'EXECUTED') {
        assert.deepEqual(result.result, { id: 'verified-result', amount: '500.00' });
        assert.equal(Object.isFrozen(result.result), true);
    }
});
test('lost commit and terminal-write acknowledgements are closed from durable state', async () => {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const commit = aebStore.commit.bind(aebStore);
    const terminal = attempts.reconcile.bind(attempts);
    let loseCommitAck = true;
    let loseTerminalAck = true;
    aebStore.commit = async (key) => {
        const result = await commit(key);
        if (loseCommitAck) {
            loseCommitAck = false;
            throw new Error('commit acknowledgement lost');
        }
        return result;
    };
    attempts.reconcile = async (entry) => {
        const result = await terminal(entry);
        if (loseTerminalAck) {
            loseTerminalAck = false;
            throw new Error('terminal acknowledgement lost');
        }
        return result;
    };
    const h = makeNativeBoundary({ f, aebStore, attempts });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:lost-acks'));
    assert.equal(result.state, 'EXECUTED');
    assert.equal([...aebStore.operations.values()][0], 'CONSUMED');
    assert.equal([...attempts.rows.values()][0]?.state, 'COMMITTED');
});
test('reconciliation resumes after the first terminal write failed, and nothing is closed before it', async () => {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const terminal = attempts.reconcile.bind(attempts);
    let failBeforeWrite = true;
    attempts.reconcile = async (entry) => {
        if (failBeforeWrite) {
            failBeforeWrite = false;
            throw new Error('attempt store unavailable before write');
        }
        return terminal(entry);
    };
    const h = makeNativeBoundary({ f, aebStore, attempts });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:partial-close'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.equal(first.reason, 'attempt_terminal_record_unconfirmed');
    // R2: nothing is committed or released before the terminal record.
    assert.deepEqual([...aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED']);
    assert.equal([...attempts.rows.values()][0]?.state, 'INDETERMINATE');
    assert.ok(first.attempt);
    const reconciliation = {
        operation_id: 'operation:native:partial-close',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: {
            state: 'EXECUTED', evidence_kind: 'provider_outcome',
            evidence: executedEvidence(),
            result: { id: 'recovered' },
        },
        recovery_authorization: 'recovery:approved',
    };
    const closed = await h.boundary.reconcile(reconciliation);
    assert.equal(closed.state, 'EXECUTED');
    assert.equal([...attempts.rows.values()][0]?.state, 'COMMITTED');
    assert.deepEqual([...aebStore.operations.values()].slice(0, 3), ['CONSUMED', 'CONSUMED', 'CONSUMED']);
    const repeated = await h.boundary.reconcile(reconciliation);
    assert.equal(repeated.state, 'EXECUTED');
});
test('reconciliation can freeze an invoking attempt after the first freeze write failed', async () => {
    const f = nativeFixture();
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    let failFreeze = true;
    attempts.transition = async (entry) => {
        if (failFreeze
            && entry.expected_state === 'INVOKING'
            && entry.next_state === 'INDETERMINATE') {
            failFreeze = false;
            throw new Error('freeze write did not land');
        }
        return transition(entry);
    };
    const h = makeNativeBoundary({
        f,
        attempts,
        invoke: async () => { throw new Error('provider response lost'); },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:freeze-recovery'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.ok(first.attempt);
    assert.equal([...attempts.rows.values()][0]?.state, 'INVOKING');
    const closed = await h.boundary.reconcile({
        operation_id: 'operation:native:freeze-recovery',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: {
            state: 'EXECUTED', evidence_kind: 'provider_outcome',
            evidence: executedEvidence(),
            result: { id: 'confirmed' },
        },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(closed.state, 'EXECUTED');
    assert.equal([...attempts.rows.values()][0]?.state, 'COMMITTED');
});
test('reconciliation uses the persisted historical trust snapshot after key rotation and restart', async () => {
    const old = nativeFixture('oauth');
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const firstBoundary = makeNativeBoundary({
        f: old,
        aebStore,
        attempts,
        trustSnapshotId: 'native-trust-snapshot:old:1',
        invoke: async () => { throw new Error('provider response lost'); },
    });
    const first = await firstBoundary.boundary.run(nativeInput(old, 'operation:native:key-rotation'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.ok(first.attempt);
    const rotated = nativeFixture('oauth');
    let requestedSnapshot = null;
    // A restart is a new store instance over the same database: it owns no
    // reservation until reconciliation claims it through the recovery path.
    const restartedStore = durableAebStore(aebStore.db);
    const restarted = makeNativeBoundary({
        f: rotated,
        aebStore: restartedStore,
        attempts,
        trustSnapshotId: 'native-trust-snapshot:new:2',
        resolveHistoricalPins: ({ trust_snapshot_id }) => {
            requestedSnapshot = trust_snapshot_id;
            return trust_snapshot_id === 'native-trust-snapshot:old:1' ? old.pins : null;
        },
    });
    const result = await restarted.boundary.reconcile({
        operation_id: 'operation:native:key-rotation',
        handoff: old.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: {
            state: 'EXECUTED', evidence_kind: 'provider_outcome',
            evidence: executedEvidence(),
            result: { id: 'confirmed-after-rotation' },
        },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(requestedSnapshot, 'native-trust-snapshot:old:1');
    assert.equal(result.state, 'EXECUTED');
    assert.equal(restartedStore.claims.length, 3, 'operation, authority, and action-fence holder claimed');
    assert.deepEqual([...aebStore.operations.values()].slice(0, 3), ['CONSUMED', 'CONSUMED', 'CONSUMED']);
});
test('direct native security callbacks are pinned when the boundary is constructed', async () => {
    {
        const f = nativeFixture();
        let providerCalls = 0;
        const h = makeNativeBoundary({
            f,
            localAuthorize: () => false,
            invoke: async () => {
                providerCalls += 1;
                return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        h.configuration.local_authorize = () => true;
        const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-local-policy'));
        assert.equal(result.state, 'REFUSED');
        assert.equal(result.reason, 'local_authorization_denied');
        assert.equal(providerCalls, 0);
    }
    {
        const f = nativeFixture();
        let providerCalls = 0;
        const h = makeNativeBoundary({
            f,
            resolveStatus: () => ({ ...f.status, revoked: true }),
            invoke: async () => {
                providerCalls += 1;
                return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        h.configuration.native_authorization.resolve_status = () => f.status;
        const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-status'));
        assert.equal(result.state, 'REFUSED');
        assert.equal(result.reason, 'native_handoff_revoked');
        assert.equal(providerCalls, 0);
    }
    {
        const f = nativeFixture();
        let originalCalls = 0;
        let replacementCalls = 0;
        const h = makeNativeBoundary({
            f,
            invoke: async () => {
                originalCalls += 1;
                return { state: 'EXECUTED', evidence: executedEvidence(), result: { source: 'pinned' } };
            },
        });
        h.configuration.invoke = async () => {
            replacementCalls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: { source: 'replacement' } };
        };
        const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-invoke'));
        assert.equal(result.state, 'EXECUTED');
        assert.equal(originalCalls, 1);
        assert.equal(replacementCalls, 0);
        if (result.state === 'EXECUTED')
            assert.deepEqual(result.result, { source: 'pinned' });
    }
    {
        const f = nativeFixture();
        const h = makeNativeBoundary({ f, providerOutcomeVerify: () => false });
        h.configuration.provider_outcomes.verify = affirm;
        const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-provider-verifier'));
        assert.equal(result.state, 'INDETERMINATE');
        assert.equal(result.reason, 'provider_outcome_authentication_failed');
    }
});
test('direct native recovery callbacks cannot be replaced after construction', async () => {
    {
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const attempts = attemptStore();
        const first = makeNativeBoundary({
            f,
            aebStore,
            attempts,
            invoke: async () => { throw new Error('provider response lost'); },
        });
        const uncertain = await first.boundary.run(nativeInput(f, 'operation:native:mutated-historical-pins'));
        assert.equal(uncertain.state, 'INDETERMINATE');
        assert.ok(uncertain.attempt);
        const restarted = makeNativeBoundary({
            f,
            aebStore,
            attempts,
            resolveHistoricalPins: () => null,
        });
        restarted.configuration.native_authorization.resolve_historical_pins = () => f.pins;
        const result = await restarted.boundary.reconcile({
            operation_id: 'operation:native:mutated-historical-pins',
            handoff: f.handoff,
            action: ACTION,
            attempt: uncertain.attempt,
            outcome: {
                state: 'EXECUTED', evidence_kind: 'provider_outcome',
                evidence: executedEvidence(),
                result: { id: 'must-not-close-under-replaced-trust-resolver' },
            },
            recovery_authorization: 'recovery:approved',
        });
        assert.equal(result.state, 'REFUSED');
        assert.equal(result.reason, 'native_historical_trust_snapshot_unavailable');
    }
    {
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const attempts = attemptStore();
        const first = makeNativeBoundary({
            f,
            aebStore,
            attempts,
            invoke: async () => { throw new Error('provider response lost'); },
        });
        const uncertain = await first.boundary.run(nativeInput(f, 'operation:native:mutated-recovery'));
        assert.equal(uncertain.state, 'INDETERMINATE');
        assert.ok(uncertain.attempt);
        const restarted = makeNativeBoundary({
            f,
            aebStore,
            attempts,
            recover: () => null,
        });
        restarted.configuration.attempts.recover = ({ attempt }) => {
            const row = attempts.rows.get(attempt.attempt_id);
            return row ? { ...structuredClone(row.binding), owner: row.owner } : null;
        };
        const result = await restarted.boundary.reconcile({
            operation_id: 'operation:native:mutated-recovery',
            handoff: f.handoff,
            action: ACTION,
            attempt: uncertain.attempt,
            outcome: {
                state: 'EXECUTED', evidence_kind: 'provider_outcome',
                evidence: executedEvidence(),
                result: { id: 'must-not-close-under-replaced-recovery' },
            },
            recovery_authorization: 'recovery:approved',
        });
        assert.equal(result.state, 'REFUSED');
        assert.equal(result.reason, 'attempt_recovery_refused');
    }
});
test('direct native durable-store methods are pinned when the boundary is constructed', async () => {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const h = makeNativeBoundary({ f, aebStore, attempts });
    const replacementCalls = [];
    for (const name of ['reserve', 'commit', 'state']) {
        const original = aebStore[name].bind(aebStore);
        aebStore[name] = (...args) => {
            replacementCalls.push(`consumption.${name}`);
            return original(...args);
        };
    }
    for (const name of ['reserve', 'transition', 'reconcile', 'state']) {
        const original = attempts[name].bind(attempts);
        attempts[name] = (...args) => {
            replacementCalls.push(`attempt.${name}`);
            return original(...args);
        };
    }
    const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-stores'));
    assert.equal(result.state, 'EXECUTED');
    assert.deepEqual(replacementCalls, []);
});
test('direct native pre-entry release uses the store method pinned at construction', async () => {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    attempts.reserve = async () => ({ reserved: false, reason: 'attempt_policy_refused' });
    const h = makeNativeBoundary({ f, aebStore, attempts });
    const originalRelease = aebStore.release.bind(aebStore);
    let replacementCalls = 0;
    aebStore.release = async (...args) => {
        replacementCalls += 1;
        return originalRelease(...args);
    };
    const result = await h.boundary.run(nativeInput(f, 'operation:native:mutated-release'));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'attempt_policy_refused');
    assert.equal(replacementCalls, 0);
});
// ---------------------------------------------------------------------------
// Same-action in-flight fence, relabel-invariant replay identity, recovery
// after restart, and hostile in-process inputs (PR #788 follow-up).
// ---------------------------------------------------------------------------
function nativeStatusFor(f, handoff) {
    return {
        ...f.status,
        gateway_id: handoff.gateway_id,
        native_authorization: handoff.native_authorization,
        revocation_id: handoff.revocation_id,
    };
}
function freshAuthorization(f, suffix, overrides = {}) {
    return issueNative(f, {
        native_authorization: {
            ...f.handoffInput.native_authorization,
            authorization_id: `native-authz:fresh:${suffix}`,
        },
        revocation_id: `revocation:fresh:${suffix}`,
        ...overrides,
    });
}
function providerOutcomeFor(calls) {
    return {
        evidence_id: `provider-evidence:call-${calls}`,
        observed_at: '2026-08-09T12:00:02.000Z',
        evidence_digest: digestAeb({ provider: 'bank', call: calls }),
    };
}
test('a fresh native authorization cannot re-enter the provider while the same action is INDETERMINATE', async () => {
    // Regression for the C1 probe: before the fence this returned
    // INDETERMINATE, then EXECUTED, with two provider calls.
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            if (calls === 1)
                throw new Error('provider timeout');
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:fence:1'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.equal(first.reason, 'provider_outcome_indeterminate');
    const second = await h.boundary.run({
        operation_id: 'operation:native:fence:2',
        handoff: freshAuthorization(f, '124'),
        action: ACTION,
    });
    assert.equal(second.state, 'REFUSED');
    assert.equal(second.reason, 'native_action_in_flight');
    assert.equal(calls, 1);
    // The refused attempt handed its own reservations back: only the first
    // attempt's operation, authority, and fence-holder reservations remain.
    assert.deepEqual([...h.aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED']);
    const reconciled = await h.boundary.reconcile({
        operation_id: 'operation:native:fence:1',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(1), result: {} },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    const third = await h.boundary.run({
        operation_id: 'operation:native:fence:3',
        handoff: freshAuthorization(f, '125'),
        action: ACTION,
    });
    assert.equal(third.state, 'REFUSED');
    assert.equal(third.reason, 'native_action_already_executed');
    assert.equal(calls, 1);
});
test('concurrent fresh authorizations for one exact action enter the provider once', async () => {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            await new Promise((resolve) => setTimeout(resolve, 5));
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const results = await Promise.all(Array.from({ length: 6 }, (_, index) => h.boundary.run({
        operation_id: `operation:native:fence:concurrent:${index}`,
        handoff: freshAuthorization(f, `concurrent-${index}`),
        action: ACTION,
    })));
    assert.equal(calls, 1);
    assert.equal(results.filter((result) => result.state === 'EXECUTED').length, 1);
    for (const result of results) {
        if (result.state === 'REFUSED') {
            assert.ok(['native_action_in_flight', 'native_action_already_executed'].includes(result.reason));
        }
    }
});
test('an authenticated FAILED releases the action fence but keeps the spent authorization burned', async () => {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            return calls === 1
                ? { state: 'FAILED', evidence: providerOutcomeFor(calls), reason: 'insufficient_funds' }
                : { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: { retry: true } };
        },
    });
    const failed = await h.boundary.run(nativeInput(f, 'operation:native:fence:failed:1'));
    assert.equal(failed.state, 'FAILED');
    const sameAuthority = await h.boundary.run(nativeInput(f, 'operation:native:fence:failed:2'));
    assert.equal(sameAuthority.state, 'REFUSED');
    assert.equal(sameAuthority.reason, 'native_replay_conflict');
    const retried = await h.boundary.run({
        operation_id: 'operation:native:fence:failed:3',
        handoff: freshAuthorization(f, 'after-failed'),
        action: ACTION,
    });
    assert.equal(retried.state, 'EXECUTED');
    assert.equal(calls, 2);
});
test('reconciliation to an authenticated FAILED releases the fence; reconciliation to EXECUTED keeps it', async () => {
    for (const terminal of ['FAILED', 'EXECUTED']) {
        const f = nativeFixture();
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                if (calls === 1)
                    throw new Error('response lost');
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const first = await h.boundary.run(nativeInput(f, `operation:native:fence:reconcile:${terminal}`));
        assert.equal(first.state, 'INDETERMINATE', terminal);
        const reconciled = await h.boundary.reconcile({
            operation_id: `operation:native:fence:reconcile:${terminal}`,
            handoff: f.handoff,
            action: ACTION,
            attempt: first.attempt,
            outcome: terminal === 'FAILED'
                ? { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(1), reason: 'provider_declined' }
                : { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(1), result: {} },
            recovery_authorization: 'recovery:approved',
        });
        assert.equal(reconciled.state, terminal, terminal);
        const retry = await h.boundary.run({
            operation_id: `operation:native:fence:reconcile:${terminal}:retry`,
            handoff: freshAuthorization(f, `reconcile-${terminal}`),
            action: ACTION,
        });
        if (terminal === 'FAILED') {
            assert.equal(retry.state, 'EXECUTED', terminal);
            assert.equal(calls, 2, terminal);
        }
        else {
            assert.equal(retry.state, 'REFUSED', terminal);
            assert.equal(retry.reason, 'native_action_already_executed', terminal);
            assert.equal(calls, 1, terminal);
        }
    }
});
test('an intentional repeat differs in the canonical action and is not fenced', async () => {
    const f = nativeFixture();
    let calls = 0;
    const second = { ...ACTION, transfer_id: 'transfer-2' };
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            if (calls === 1)
                throw new Error('provider timeout');
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:instance:1'));
    assert.equal(first.state, 'INDETERMINATE');
    const repeat = await h.boundary.run({
        operation_id: 'operation:native:instance:2',
        handoff: freshAuthorization(f, 'instance-2', { action: second }),
        action: second,
    });
    assert.equal(repeat.state, 'EXECUTED');
    assert.equal(calls, 2);
});
test('a pre-entry refusal releases the action fence for a later authorization', async () => {
    const f = nativeFixture();
    let lookups = 0;
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => {
            lookups += 1;
            // The provider-entry recheck of the first attempt sees a revocation.
            return { ...nativeStatusFor(f, handoff), revoked: lookups === 2 };
        },
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const refusedAtEntry = await h.boundary.run(nativeInput(f, 'operation:native:fence:pre-entry'));
    assert.equal(refusedAtEntry.state, 'REFUSED');
    assert.equal(refusedAtEntry.reason, 'native_handoff_revoked');
    assert.equal(h.aebStore.operations.size, 0);
    const later = await h.boundary.run({
        operation_id: 'operation:native:fence:pre-entry:later',
        handoff: freshAuthorization(f, 'pre-entry-later'),
        action: ACTION,
    });
    assert.equal(later.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('the action fence is durable across a process restart', async () => {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const first = makeNativeBoundary({
        f,
        aebStore,
        attempts,
        invoke: async () => { throw new Error('process died after provider entry'); },
    });
    const uncertain = await first.boundary.run(nativeInput(f, 'operation:native:fence:restart'));
    assert.equal(uncertain.state, 'INDETERMINATE');
    let calls = 0;
    const restarted = makeNativeBoundary({
        f,
        aebStore: durableAebStore(aebStore.db),
        attempts,
        attemptPrefix: 'restarted:',
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const retry = await restarted.boundary.run({
        operation_id: 'operation:native:fence:restart:retry',
        handoff: freshAuthorization(f, 'restart'),
        action: ACTION,
    });
    assert.equal(retry.state, 'REFUSED');
    assert.equal(retry.reason, 'native_action_in_flight');
    assert.equal(calls, 0);
});
test('one native grant relabelled under a second pinned profile or system is one spend', async () => {
    // Regression for the C2 probe: before the fix this returned EXECUTED twice.
    for (const relabel of ['profile', 'system']) {
        for (const sameAction of [true, false]) {
            const f = nativeFixture();
            const source = f.handoffInput.native_authorization;
            const relabelled = relabel === 'profile'
                ? { ...source, profile: 'authzen:exact-action-result:2' }
                : { ...source, system: 'coaz', profile: 'coaz:exact-action-result:1' };
            f.pins.accepted_sources.push({
                ...f.pins.accepted_sources[0],
                system: relabelled.system,
                profile: relabelled.profile,
            });
            const otherAction = sameAction ? ACTION : { ...ACTION, transfer_id: 'transfer-relabel' };
            let calls = 0;
            const h = makeNativeBoundary({
                f,
                resolveStatus: (handoff) => nativeStatusFor(f, handoff),
                invoke: async () => {
                    calls += 1;
                    return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
                },
            });
            const label = `${relabel}:${sameAction ? 'same-action' : 'other-action'}`;
            const first = await h.boundary.run(nativeInput(f, `operation:native:relabel:${label}:1`));
            assert.equal(first.state, 'EXECUTED', label);
            const relabelledHandoff = issueNative(f, { native_authorization: relabelled, action: otherAction });
            const second = await h.boundary.run({
                operation_id: `operation:native:relabel:${label}:2`,
                handoff: relabelledHandoff,
                action: otherAction,
            });
            assert.equal(second.state, 'REFUSED', label);
            assert.equal(second.reason, 'native_replay_conflict', label);
            assert.equal(calls, 1, label);
            // The relabelled grant derives the same replay unit, so with the same
            // action it would also carry the same provider idempotency key.
            const relabelledVerification = verifyAebNativeAuthorizationHandoff(relabelledHandoff, {
                mode: 'historical',
                pins: f.pins,
                expected_action: otherAction,
                now: NOW,
            });
            assert.equal(relabelledVerification.valid, true, label);
            if (first.state === 'EXECUTED') {
                assert.equal(relabelledVerification.native_replay_identity, first.attempt.native_replay_unit, label);
                assert.equal(nativeConsequenceBoundaryProviderIdempotencyKey({
                    provider: PROVIDER,
                    action_digest: first.attempt.action_digest,
                    native_replay_unit: relabelledVerification.native_replay_identity,
                }), first.attempt.provider_idempotency_key, label);
            }
        }
    }
});
test('one exact issuer under two declared namespaces, or mixed declarations, is refused at construction', async () => {
    {
        // R7 regression (N8 exact-issuer-distinct-ns): two namespaces for one
        // exact issuer gave one grant two replay identities, and it executed
        // twice. It is now refused like aliased spellings.
        const f = nativeFixture();
        f.pins.accepted_sources[0].authority_namespace = 'namespace:decisions';
        f.pins.accepted_sources.push({
            ...f.pins.accepted_sources[0],
            profile: 'authzen:exact-action-result:2',
            authority_namespace: 'namespace:grants',
        });
        assert.throws(() => makeNativeBoundary({ f }), /native_consequence_boundary_configuration_invalid: native_pins_issuer_namespace_conflict/);
    }
    {
        // A pin set that mixes declared and default namespaces for one issuer is
        // refused when the boundary is constructed, before any attempt runs.
        const f = nativeFixture();
        f.pins.accepted_sources.push({
            ...f.pins.accepted_sources[0],
            profile: 'authzen:exact-action-result:2',
            authority_namespace: 'namespace:grants',
        });
        assert.throws(() => makeNativeBoundary({ f }), /native_consequence_boundary_configuration_invalid: native_pins_namespace_declaration_mixed/);
    }
});
test('reconciling a never-entered RELEASED attempt is refused and cannot burn a later attempt', async () => {
    // Regression for H4e-burn: the reconcile used to commit attempt 2's live
    // reservation of the same operation key with zero provider calls.
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    let lookups = 0;
    let calls = 0;
    let unblock = () => { };
    const blocked = new Promise((resolve) => { unblock = resolve; });
    const h = makeNativeBoundary({
        f,
        aebStore,
        attempts,
        resolveStatus: async (handoff) => {
            lookups += 1;
            if (lookups === 2)
                throw new Error('status service timeout');
            if (lookups === 5) {
                await blocked;
                throw new Error('status service timeout');
            }
            return nativeStatusFor(f, handoff);
        },
        providerOutcomeVerify: affirm,
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:burn'));
    assert.equal(first.state, 'REFUSED');
    const released = [...attempts.rows.values()][0];
    assert.equal(released.state, 'RELEASED');
    const second = h.boundary.run(nativeInput(f, 'operation:native:burn'));
    await new Promise((resolve) => setTimeout(resolve, 10));
    const reservedBySecond = [...aebStore.operations.values()];
    assert.deepEqual(reservedBySecond, ['RESERVED', 'RESERVED', 'RESERVED']);
    const recovery = {
        operation_id: 'operation:native:burn',
        handoff: f.handoff,
        action: ACTION,
        attempt: released.binding,
        outcome: {
            state: 'FAILED', evidence_kind: 'provider_outcome',
            evidence: providerOutcomeFor(99),
            reason: 'no_such_operation',
        },
        recovery_authorization: 'recovery:approved',
    };
    // Terminal reconciliation never applies to a record that never reached
    // INVOKING, and changes nothing.
    const terminal = await h.boundary.reconcile(recovery);
    assert.equal(terminal.state, 'INDETERMINATE');
    assert.equal(terminal.reason, 'pre_entry_recovery_required');
    assert.deepEqual([...aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED']);
    // The same "no such operation" answer presented under the wrong label is
    // refused before anything else; labelled as a lookup it recovers.
    const mislabelled = await h.boundary.reconcile({ ...recovery, mode: 'pre_entry' });
    assert.deepEqual([mislabelled.state, mislabelled.reason], ['REFUSED', 'evidence_kind_mismatch']);
    const reconciled = await h.boundary.reconcile({
        ...recovery,
        mode: 'pre_entry',
        outcome: { ...recovery.outcome, evidence_kind: 'pre_entry_lookup' },
    });
    assert.equal(reconciled.state, 'REFUSED');
    assert.equal(reconciled.reason, 'attempt_never_entered_provider');
    // Pre-entry recovery of attempt 1 touched only attempt 1's keys; attempt
    // 2, which reused the operation ID and the grant, keeps all three rows.
    assert.deepEqual([...aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED']);
    unblock();
    assert.equal((await second).state, 'REFUSED');
    const third = await h.boundary.run(nativeInput(f, 'operation:native:burn:new'));
    assert.equal(third.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('reservations stay held when a pre-entry attempt release is unconfirmed', async () => {
    const f = nativeFixture();
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    let releasedWritesFail = true;
    attempts.transition = async (entry) => {
        if (releasedWritesFail && entry.next_state === 'RELEASED')
            throw new Error('attempt store unavailable');
        return transition(entry);
    };
    let lookups = 0;
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        attempts,
        resolveStatus: (handoff) => {
            lookups += 1;
            return { ...nativeStatusFor(f, handoff), revoked: lookups === 2 };
        },
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:release-unconfirmed'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.equal(first.reason, 'native_pre_entry_release_unconfirmed');
    assert.equal(first.invoked, false);
    // The attempt is still RESERVED, so its operation key and fence stay held.
    assert.deepEqual([...h.aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED']);
    const reuse = await h.boundary.run(nativeInput(f, 'operation:native:release-unconfirmed'));
    assert.equal(reuse.state, 'REFUSED');
    assert.equal(reuse.reason, 'consumption_conflict');
    assert.equal(calls, 0);
    // While the attempt store still refuses the RELEASED write, recovery cannot
    // prove the stop and releases nothing.
    const recovery = {
        operation_id: 'operation:native:release-unconfirmed',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' },
        recovery_authorization: 'recovery:approved',
        mode: 'pre_entry',
    };
    const blocked = await h.boundary.reconcile(recovery);
    assert.equal(blocked.state, 'INDETERMINATE');
    assert.equal(blocked.reason, 'attempt_release_unconfirmed');
    assert.deepEqual([...h.aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED']);
    // Once the store recovers, the durable RESERVED record proves no provider
    // entry and one recovery call releases every reservation of the attempt.
    releasedWritesFail = false;
    const recovered = await h.boundary.reconcile(recovery);
    assert.equal(recovered.state, 'REFUSED');
    assert.equal(recovered.reason, 'attempt_never_entered_provider');
    assert.equal(h.aebStore.operations.size, 0);
    const retry = await h.boundary.run(nativeInput(f, 'operation:native:release-unconfirmed'));
    assert.equal(retry.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('a reconcile outcome that conflicts with the terminal record changes nothing', async () => {
    const f = nativeFixture();
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => { throw new Error('response lost'); },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:conflict'));
    assert.equal(first.state, 'INDETERMINATE');
    const base = {
        operation_id: 'operation:native:conflict',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        recovery_authorization: 'recovery:approved',
    };
    const executed = await h.boundary.reconcile({
        ...base,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(1), result: {} },
    });
    assert.equal(executed.state, 'EXECUTED');
    const flipped = await h.boundary.reconcile({
        ...base,
        outcome: { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(2), reason: 'declined' },
    });
    assert.equal(flipped.state, 'REFUSED');
    assert.equal(flipped.reason, 'reconciliation_outcome_conflict');
    const retry = await h.boundary.run({
        operation_id: 'operation:native:conflict:retry',
        handoff: freshAuthorization(f, 'conflict'),
        action: ACTION,
    });
    assert.equal(retry.state, 'REFUSED');
    assert.equal(retry.reason, 'native_action_already_executed');
});
test('a relying party ID outside the Gate identifier grammar is refused at construction', () => {
    for (const relyingPartyId of ['rp', 'rp:payments#eu', `rp:${'a'.repeat(300)}`]) {
        const f = nativeFixture();
        f.pins.relying_party_id = relyingPartyId;
        assert.throws(() => makeNativeBoundary({ f }), /native_consequence_boundary_configuration_invalid/, relyingPartyId.slice(0, 24));
    }
    assert.throws(() => nativeConsequenceBoundaryActionFenceKey({
        relying_party_id: 'rp:payments#eu',
        provider: PROVIDER,
        action_digest: digestAeb({ action: 1 }),
    }), /native_action_fence_binding_invalid/);
});
test('hostile in-process run and reconcile inputs refuse with a reason instead of throwing', async () => {
    const f = nativeFixture();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        invoke: async () => {
            calls += 1;
            throw new Error('response lost');
        },
    });
    const protoRun = JSON.parse(`{"operation_id":"operation:native:proto","handoff":${JSON.stringify(f.handoff)},"action":${JSON.stringify(ACTION)},"__proto__":{"status":{"revoked":false}}}`);
    const getterRun = Object.defineProperty({ handoff: f.handoff, action: ACTION }, 'operation_id', { get() { throw new Error('getter'); }, enumerable: true });
    const proxyRun = new Proxy({ operation_id: 'operation:native:proxy', handoff: f.handoff, action: ACTION }, { getOwnPropertyDescriptor() { throw new Error('trap'); } });
    const getTrapRun = new Proxy({ operation_id: 'operation:native:get-trap', handoff: f.handoff, action: ACTION }, { get(target, key) { if (key === 'handoff')
            throw new Error('trap'); return target[key]; } });
    const nestedProxyRun = {
        operation_id: 'operation:native:nested-proxy',
        handoff: f.handoff,
        action: new Proxy({ ...ACTION }, {}),
    };
    for (const [name, value] of Object.entries({
        protoRun, getterRun, proxyRun, getTrapRun, nestedProxyRun,
    })) {
        const result = await h.boundary.run(value);
        assert.equal(result.state, 'REFUSED', name);
        assert.equal(result.reason, 'native_execution_input_invalid', name);
    }
    assert.equal(calls, 0);
    const uncertain = await h.boundary.run(nativeInput(f, 'operation:native:hostile-reconcile'));
    assert.equal(uncertain.state, 'INDETERMINATE');
    const good = {
        operation_id: 'operation:native:hostile-reconcile',
        handoff: f.handoff,
        action: ACTION,
        attempt: uncertain.attempt,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), result: {} },
        recovery_authorization: 'recovery:approved',
    };
    const outcomeGetter = Object.defineProperty({ ...good }, 'outcome', {
        get() { throw new Error('getter'); },
        enumerable: true,
    });
    const proxyOutcome = new Proxy({ ...good }, {
        getOwnPropertyDescriptor(target, key) {
            if (key === 'outcome')
                throw new Error('trap');
            return Reflect.getOwnPropertyDescriptor(target, key);
        },
    });
    const protoReconcile = JSON.parse(JSON.stringify({ ...good, attempt: uncertain.attempt })
        .replace(/^\{/, '{"__proto__":{"recovery_authorization":"recovery:approved"},'));
    const extraMember = { ...good, status: { revoked: false } };
    for (const [name, value] of Object.entries({
        outcomeGetter, proxyOutcome, protoReconcile, extraMember,
    })) {
        const result = await h.boundary.reconcile(value);
        assert.equal(result.state, 'REFUSED', name);
        assert.equal(result.reason, 'native_reconciliation_input_invalid', name);
    }
    const closed = await h.boundary.reconcile(good);
    assert.equal(closed.state, 'EXECUTED');
});
test('a hostile attempt-store reservation answer refuses and hands both reservations back', async () => {
    const f = nativeFixture();
    const attempts = attemptStore();
    attempts.reserve = async () => Object.defineProperty({}, 'reserved', {
        get() { throw new Error('getter'); },
        enumerable: true,
    });
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        attempts,
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        },
    });
    const result = await h.boundary.run(nativeInput(f, 'operation:native:hostile-attempt-store'));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'attempt_conflict');
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal(calls, 0);
});
test('an unconfirmed fence release after FAILED stays reconcilable and never opens a second entry early', async () => {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const release = aebStore.release.bind(aebStore);
    let failHolderRelease = true;
    aebStore.release = async (key) => {
        if (failHolderRelease && key.startsWith('aeb-native-action-holder:')) {
            failHolderRelease = false;
            throw new Error('store unavailable before write');
        }
        return release(key);
    };
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        aebStore,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            return calls === 1
                ? { state: 'FAILED', evidence: providerOutcomeFor(calls), reason: 'declined' }
                : { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:fence-release-lost'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.equal(first.reason, 'native_action_fence_release_unconfirmed');
    // R2: the terminal record came first and is confirmed; the holder, released
    // only after it, is still RESERVED, so the fence stays closed.
    const record = [...h.attempts.rows.values()][0];
    assert.equal(record?.state, 'RELEASED');
    assert.equal(record?.evidence?.evidence_id, providerOutcomeFor(1).evidence_id);
    const early = await h.boundary.run({
        operation_id: 'operation:native:fence-release-lost:early',
        handoff: freshAuthorization(f, 'release-lost-early'),
        action: ACTION,
    });
    assert.equal(early.state, 'REFUSED');
    assert.equal(early.reason, 'native_action_in_flight');
    // The terminal record is never rewritten: a FAILED with other evidence is a
    // conflict and changes nothing; the recorded outcome finishes the close.
    const reconciliation = {
        operation_id: 'operation:native:fence-release-lost',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(42), reason: 'declined' },
        recovery_authorization: 'recovery:approved',
    };
    const conflicting = await h.boundary.reconcile(reconciliation);
    assert.equal(conflicting.state, 'REFUSED');
    assert.equal(conflicting.reason, 'reconciliation_outcome_conflict');
    assert.equal((await h.boundary.run({
        operation_id: 'operation:native:fence-release-lost:early-2',
        handoff: freshAuthorization(f, 'release-lost-early-2'),
        action: ACTION,
    })).reason, 'native_action_in_flight');
    const reconciled = await h.boundary.reconcile({
        ...reconciliation,
        outcome: { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(1), reason: 'declined' },
    });
    assert.equal(reconciled.state, 'FAILED');
    const retried = await h.boundary.run({
        operation_id: 'operation:native:fence-release-lost:retry',
        handoff: freshAuthorization(f, 'release-lost-retry'),
        action: ACTION,
    });
    assert.equal(retried.state, 'EXECUTED');
    assert.equal(calls, 2);
});
// ---------------------------------------------------------------------------
// PR #790 round 2: reservation ownership, pre-entry recovery, one-credential
// restart reconciliation, the composed-boundary fence, and issuer aliasing.
// ---------------------------------------------------------------------------
function failedEvidence(n) {
    return {
        evidence_id: `provider-evidence:not-found-${n}`,
        observed_at: '2026-08-09T12:00:02.000Z',
        evidence_digest: digestAeb({ provider: 'bank', outcome: 'not-found', n }),
    };
}
function deferred() {
    let resolve;
    const promise = new Promise((done) => { resolve = done; });
    return { promise, resolve };
}
/**
 * Label a presented EXECUTED or FAILED outcome with the evidence kind its
 * reconcile mode expects, as a correct operator does; an explicit label wins.
 */
function labelled(outcome, mode) {
    if (!outcome || typeof outcome !== 'object' || Object.hasOwn(outcome, 'evidence_kind'))
        return outcome;
    const state = outcome.state;
    if (state !== 'EXECUTED' && state !== 'FAILED')
        return outcome;
    return { ...outcome, evidence_kind: mode === 'pre_entry' ? 'pre_entry_lookup' : 'provider_outcome' };
}
function nativeRecovery(f, operationId, attempt, outcome, recoveryAuthorization = 'recovery:approved', mode = 'pre_entry') {
    return {
        operation_id: operationId,
        handoff: f.handoff,
        action: ACTION,
        attempt,
        outcome: labelled(outcome, mode),
        recovery_authorization: recoveryAuthorization,
        ...(mode ? { mode } : {}),
    };
}
test('B4: a transient store error while handing back a pre-entry refusal is recoverable in one authorized reconcile', async () => {
    // Regression for B4: the holder release threw after a pre-entry refusal, the
    // attempt was RELEASED without evidence, and reconcile refused it as
    // attempt_never_entered_provider while the fence stayed held forever.
    for (const lookup of ['FAILED', 'INDETERMINATE']) {
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const release = aebStore.release.bind(aebStore);
        let holderReleaseFailures = 1;
        aebStore.release = async (key) => {
            if (holderReleaseFailures > 0 && key.startsWith('aeb-native-action-holder:')) {
                holderReleaseFailures -= 1;
                throw new Error('pg: connection reset');
            }
            return release(key);
        };
        let lookups = 0;
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            aebStore,
            resolveStatus: (handoff) => {
                lookups += 1;
                return { ...nativeStatusFor(f, handoff), revoked: lookups === 2 };
            },
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const first = await h.boundary.run(nativeInput(f, `operation:native:b4:${lookup}`));
        assert.equal(first.state, 'INDETERMINATE', lookup);
        assert.equal(first.reason, 'native_pre_entry_release_unconfirmed', lookup);
        assert.equal(first.invoked, false, lookup);
        const row = [...h.attempts.rows.values()][0];
        assert.equal(row.state, 'RELEASED', lookup);
        assert.deepEqual(row.evidence, { kind: 'not_entered', attempt_id: row.binding.attempt_id }, lookup);
        const early = await h.boundary.run({
            operation_id: `operation:native:b4:${lookup}:early`,
            handoff: freshAuthorization(f, `b4-early-${lookup}`),
            action: ACTION,
        });
        assert.equal(early.state, 'REFUSED', lookup);
        assert.equal(early.reason, 'native_action_in_flight', lookup);
        // A provider claim that the action executed contradicts the durable record
        // and releases nothing; an unauthorized caller cannot recover at all.
        const contradicted = await h.boundary.reconcile(nativeRecovery(f, `operation:native:b4:${lookup}`, first.attempt, { state: 'EXECUTED', evidence: providerOutcomeFor(7), result: {} }));
        assert.equal(contradicted.state, 'REFUSED', lookup);
        assert.equal(contradicted.reason, 'reconciliation_outcome_conflict', lookup);
        const unauthorized = await h.boundary.reconcile(nativeRecovery(f, `operation:native:b4:${lookup}`, first.attempt, { state: 'FAILED', evidence: failedEvidence(1), reason: 'not_found' }, 'recovery:forged'));
        assert.equal(unauthorized.state, 'REFUSED', lookup);
        assert.equal(unauthorized.reason, 'attempt_recovery_refused', lookup);
        assert.equal(h.aebStore.operations.size, 1, lookup);
        // Terminal reconciliation is a separate mode and never releases a
        // pre-entry stop.
        const terminal = await h.boundary.reconcile(nativeRecovery(f, `operation:native:b4:${lookup}`, first.attempt, { state: 'FAILED', evidence: failedEvidence(1), reason: 'not_found' }, 'recovery:approved', 'terminal'));
        assert.equal(terminal.state, 'INDETERMINATE', lookup);
        assert.equal(terminal.reason, 'pre_entry_recovery_required', lookup);
        assert.equal(h.aebStore.operations.size, 1, lookup);
        const recovered = await h.boundary.reconcile(nativeRecovery(f, `operation:native:b4:${lookup}`, first.attempt, lookup === 'FAILED'
            ? { state: 'FAILED', evidence: failedEvidence(1), reason: 'not_found' }
            : { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }));
        assert.equal(recovered.state, 'REFUSED', lookup);
        assert.equal(recovered.reason, 'attempt_never_entered_provider', lookup);
        assert.equal(recovered.invoked, false, lookup);
        assert.equal(h.aebStore.operations.size, 0, lookup);
        // Idempotent: a repeated recovery finds nothing held.
        const again = await h.boundary.reconcile(nativeRecovery(f, `operation:native:b4:${lookup}`, first.attempt, { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }));
        assert.equal(again.reason, 'attempt_never_entered_provider', lookup);
        const fresh = await h.boundary.run({
            operation_id: `operation:native:b4:${lookup}:fresh`,
            handoff: freshAuthorization(f, `b4-fresh-${lookup}`),
            action: ACTION,
        });
        assert.equal(fresh.state, 'EXECUTED', lookup);
        assert.equal(calls, 1, lookup);
    }
});
test('B5: a crash while the attempt is RESERVED is recovered after restart with one scoped credential', async () => {
    // Regression for B5, and the recovery race: the original call resumes after
    // recovery and cannot enter the provider.
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const entryStatus = deferred();
    let lookups = 0;
    let calls = 0;
    const invoke = async () => {
        calls += 1;
        return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
    };
    const before = makeNativeBoundary({
        f,
        aebStore,
        attempts,
        resolveStatus: async (handoff) => {
            lookups += 1;
            if (lookups === 2)
                await entryStatus.promise;
            return nativeStatusFor(f, handoff);
        },
        invoke,
    });
    const stalled = before.boundary.run(nativeInput(f, 'operation:native:b5'));
    await new Promise((resolve) => setTimeout(resolve, 10));
    const row = [...attempts.rows.values()][0];
    assert.equal(row.state, 'RESERVED');
    assert.equal(aebStore.operations.size, 3);
    // Restart: a new store instance over the same database owns nothing.
    const scopes = [];
    const restartedStore = durableAebStore(aebStore.db, ({ authorization, scope }) => {
        scopes.push(scope);
        // One credential, bound to the attempt, not to each row key.
        return authorization?.attempt_id === scope?.attemptId;
    });
    const after = makeNativeBoundary({
        f,
        aebStore: restartedStore,
        attempts,
        attemptPrefix: 'restarted:',
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke,
    });
    const fenced = await after.boundary.run({
        operation_id: 'operation:native:b5:fresh-early',
        handoff: freshAuthorization(f, 'b5-early'),
        action: ACTION,
    });
    assert.equal(fenced.state, 'REFUSED');
    assert.equal(fenced.reason, 'native_action_in_flight');
    const recovered = await after.boundary.reconcile(nativeRecovery(f, 'operation:native:b5', row.binding, { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }, { attempt_id: row.binding.attempt_id }));
    // recover() in this harness accepts only the literal 'recovery:approved'.
    assert.equal(recovered.state, 'REFUSED');
    assert.equal(recovered.reason, 'attempt_recovery_refused');
    const afterWithCustody = makeNativeBoundary({
        f,
        aebStore: restartedStore,
        attempts,
        attemptPrefix: 'restarted-2:',
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke,
        recover: ({ attempt, recovery_authorization }) => {
            if (recovery_authorization?.attempt_id !== attempt.attempt_id)
                return null;
            const stored = attempts.rows.get(attempt.attempt_id);
            return stored ? { ...structuredClone(stored.binding), owner: stored.owner } : null;
        },
    });
    const released = await afterWithCustody.boundary.reconcile(nativeRecovery(f, 'operation:native:b5', row.binding, { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }, { attempt_id: row.binding.attempt_id }));
    assert.equal(released.state, 'REFUSED');
    assert.equal(released.reason, 'attempt_never_entered_provider');
    assert.equal(row.state, 'RELEASED');
    assert.equal(restartedStore.claims.length, 3);
    const keys = nativeConsequenceBoundaryAttemptReservationKeys({
        relying_party_id: 'rp:payments',
        provider: PROVIDER,
        operation_id: 'operation:native:b5',
        action_digest: row.binding.action_digest,
        boundary_id: NATIVE_BOUNDARY_ID,
        attempt_id: row.binding.attempt_id,
    });
    assert.deepEqual(restartedStore.claims, [keys.holder, keys.authority, keys.operation]);
    assert.deepEqual(restartedStore.claimScopes.map((scope) => scope.reservation), ['action-fence-holder', 'native-authority', 'operation']);
    for (const scope of restartedStore.claimScopes) {
        assert.equal(scope.attemptId, row.binding.attempt_id);
        assert.equal(scope.operationId, 'operation:native:b5');
        assert.equal(scope.recoveryOperationKey, keys.operation_fence);
        assert.equal(scope.recoveryOperationKey, nativeConsequenceBoundaryReservationKey({
            relying_party_id: 'rp:payments',
            operation_id: 'operation:native:b5',
            action_digest: row.binding.action_digest,
        }));
    }
    assert.equal(aebStore.operations.size, 0);
    // The stalled original call resumes after recovery and cannot enter: its
    // RESERVED -> INVOKING transition fails against the RELEASED record, and it
    // hands back whatever it still holds (R8: nothing is stranded).
    entryStatus.resolve();
    const resumed = await stalled;
    assert.equal(resumed.state, 'REFUSED');
    assert.equal(resumed.reason, 'attempt_released_by_recovery');
    assert.equal(resumed.invoked, false);
    assert.equal(calls, 0);
    assert.equal(aebStore.operations.size, 0);
    const fresh = await afterWithCustody.boundary.run({
        operation_id: 'operation:native:b5:fresh',
        handoff: freshAuthorization(f, 'b5-fresh'),
        action: ACTION,
    });
    assert.equal(fresh.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('B6: no reservation precedes the durable attempt record, so a crash before it locks nothing', async () => {
    // Regression for B6: the fence holder was reserved before the attempt row
    // existed, so a crash there left a holder no recovery could find.
    {
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const attempts = attemptStore();
        const never = new Promise(() => { });
        const before = makeNativeBoundary({ f, aebStore, attempts, createId: () => never });
        void before.boundary.run(nativeInput(f, 'operation:native:b6'));
        await new Promise((resolve) => setTimeout(resolve, 10));
        assert.equal(attempts.rows.size, 0);
        assert.equal(aebStore.operations.size, 0);
        let calls = 0;
        const after = makeNativeBoundary({
            f,
            aebStore: durableAebStore(aebStore.db),
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const fresh = await after.boundary.run({
            operation_id: 'operation:native:b6:fresh',
            handoff: freshAuthorization(f, 'b6-fresh'),
            action: ACTION,
        });
        assert.equal(fresh.state, 'EXECUTED');
    }
    {
        // A crash right after the holder write (its acknowledgement never
        // arrives): the attempt record already exists and recovery finds it.
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const attempts = attemptStore();
        const reserve = aebStore.reserve.bind(aebStore);
        aebStore.reserve = async (key, replayKeys) => {
            const result = await reserve(key, replayKeys);
            if (key.startsWith('aeb-native-action-holder:'))
                await new Promise(() => { });
            return result;
        };
        const before = makeNativeBoundary({ f, aebStore, attempts });
        void before.boundary.run(nativeInput(f, 'operation:native:b6:holder'));
        await new Promise((resolve) => setTimeout(resolve, 10));
        const row = [...attempts.rows.values()][0];
        assert.equal(row.state, 'RESERVED');
        assert.equal(aebStore.operations.size, 3);
        let calls = 0;
        const after = makeNativeBoundary({
            f,
            aebStore: durableAebStore(aebStore.db),
            attempts,
            attemptPrefix: 'restarted:',
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const fenced = await after.boundary.run({
            operation_id: 'operation:native:b6:holder:early',
            handoff: freshAuthorization(f, 'b6-holder-early'),
            action: ACTION,
        });
        assert.equal(fenced.reason, 'native_action_in_flight');
        const recovered = await after.boundary.reconcile(nativeRecovery(f, 'operation:native:b6:holder', row.binding, { state: 'FAILED', evidence: failedEvidence(6), reason: 'not_found' }));
        assert.equal(recovered.reason, 'attempt_never_entered_provider');
        const fresh = await after.boundary.run({
            operation_id: 'operation:native:b6:holder:fresh',
            handoff: freshAuthorization(f, 'b6-holder-fresh'),
            action: ACTION,
        });
        assert.equal(fresh.state, 'EXECUTED');
        assert.equal(calls, 1);
    }
});
test('B7: a lost RESERVED to INVOKING write is recoverable; an applied one needs a provider outcome', async () => {
    // Regression for B7: attempt_start_unconfirmed with invoked=false could not
    // be reconciled and locked the action forever.
    {
        const f = nativeFixture();
        const attempts = attemptStore();
        const transition = attempts.transition.bind(attempts);
        let failStart = true;
        attempts.transition = async (entry) => {
            if (failStart && entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
                failStart = false;
                throw new Error('timeout before write');
            }
            return transition(entry);
        };
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        // R3: the start write failed before landing, so the durable record is
        // still RESERVED. The run closes it as not entered itself and releases.
        const first = await h.boundary.run(nativeInput(f, 'operation:native:b7'));
        assert.equal(first.state, 'REFUSED');
        assert.equal(first.reason, 'attempt_start_conflict');
        assert.equal(first.invoked, false);
        assert.equal(h.aebStore.operations.size, 0);
        const b7Attempt = [...h.attempts.rows.values()][0];
        assert.equal(b7Attempt.state, 'RELEASED');
        // A later pre-entry recovery of the same attempt is idempotent.
        const recovered = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:b7', b7Attempt.binding, { state: 'FAILED', evidence: failedEvidence(7), reason: 'not_found' }));
        assert.equal(recovered.reason, 'attempt_never_entered_provider');
        const fresh = await h.boundary.run({
            operation_id: 'operation:native:b7:fresh',
            handoff: freshAuthorization(f, 'b7-fresh'),
            action: ACTION,
        });
        assert.equal(fresh.state, 'EXECUTED');
        assert.equal(calls, 1);
    }
    {
        // S5c: the write landed, its acknowledgement was lost, and one confirming
        // read failed. The run reads again, finds INVOKING, and proceeds as the
        // owner, so the attempt closes normally with one provider call.
        const f = nativeFixture();
        const attempts = attemptStore();
        const transition = attempts.transition.bind(attempts);
        const state = attempts.state.bind(attempts);
        let loseStartAck = true;
        let failNextRead = false;
        attempts.transition = async (entry) => {
            const result = await transition(entry);
            if (loseStartAck && entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
                loseStartAck = false;
                failNextRead = true;
                throw new Error('acknowledgement lost');
            }
            return result;
        };
        attempts.state = async (entry) => {
            if (failNextRead) {
                failNextRead = false;
                throw new Error('read timeout');
            }
            return state(entry);
        };
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const first = await h.boundary.run(nativeInput(f, 'operation:native:b7:applied'));
        assert.equal(first.state, 'EXECUTED');
        assert.equal([...attempts.rows.values()][0].state, 'COMMITTED');
        assert.equal(calls, 1);
    }
});
/**
 * An attempt store whose start write lands with a lost acknowledgement, after
 * which the next `failedReads` durable reads fail (Infinity: until reset).
 */
function lostStartAttemptStore(failedReads) {
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    const state = attempts.state.bind(attempts);
    let loseStartAck = true;
    let readsToFail = 0;
    attempts.transition = async (entry) => {
        const result = await transition(entry);
        if (loseStartAck && entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
            loseStartAck = false;
            readsToFail = failedReads;
            throw new Error('acknowledgement lost');
        }
        return result;
    };
    attempts.state = async (entry) => {
        if (readsToFail > 0) {
            readsToFail -= 1;
            throw new Error('read timeout');
        }
        return state(entry);
    };
    return Object.assign(attempts, { restoreReads() { readsToFail = 0; } });
}
/**
 * A verifier that authenticates only evidence of non-existence for the
 * attempt's provider idempotency key (for example a provider-issued
 * cancellation of the key) as a terminal outcome, and a "not found" lookup
 * only as a pre-entry lookup. Which evidence proves non-existence is the
 * verifier's decision; Gate only routes it.
 */
function nonExistenceVerifier(context) {
    if (context.purpose === 'provider_outcome') {
        const authenticated = context.outcome.state === 'EXECUTED'
            || context.outcome.evidence.evidence_id === `provider-evidence:key-cancelled:${context.provider_idempotency_key}`;
        return authenticated ? affirm(context) : false;
    }
    return context.outcome.reason === 'not_found' ? affirm(context) : false;
}
function keyCancelledEvidence(providerIdempotencyKey) {
    return {
        evidence_id: `provider-evidence:key-cancelled:${providerIdempotencyKey}`,
        observed_at: '2026-08-09T12:00:03.000Z',
        evidence_digest: digestAeb({ provider: 'bank', cancelled: providerIdempotencyKey }),
    };
}
test('T1 NA12 native: a start write that lands with an unreadable record is held without a not-entered write, and closes only on authenticated non-existence', async () => {
    {
        // Every read fails while the run decides. The run holds everything and
        // never writes the not-entered marker; the record stays INVOKING.
        const f = nativeFixture();
        const attempts = lostStartAttemptStore(Infinity);
        const written = [];
        const transition = attempts.transition;
        attempts.transition = async (entry) => {
            written.push(`${entry.expected_state}->${entry.next_state}`);
            return transition(entry);
        };
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            providerOutcomeVerify: nonExistenceVerifier,
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const first = await h.boundary.run(nativeInput(f, 'operation:native:na12'));
        assert.equal(first.state, 'INDETERMINATE');
        assert.equal(first.reason, 'attempt_start_unconfirmed');
        assert.equal(first.invoked, false);
        assert.deepEqual(written, ['RESERVED->INVOKING'], 'no not-entered write was sent');
        const row = [...attempts.rows.values()][0];
        assert.equal(row.state, 'INVOKING');
        assert.equal(row.evidence, undefined);
        assert.equal([...h.aebStore.operations.values()].filter((value) => value === 'RESERVED').length, 3);
        attempts.restoreReads();
        // Fail safe: the record is INVOKING, so it is fenced. A "not found"
        // lookup cannot prove non-entry of an INVOKING attempt.
        const fenced = await h.boundary.run({
            operation_id: 'operation:native:na12:early',
            handoff: freshAuthorization(f, 'na12-early'),
            action: ACTION,
        });
        assert.equal(fenced.reason, 'native_action_in_flight');
        const lookup = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:na12', first.attempt, { state: 'FAILED', evidence: failedEvidence(12), reason: 'not_found' }));
        assert.deepEqual([lookup.state, lookup.reason], ['INDETERMINATE', 'recovery_lost_to_live_attempt']);
        const notFound = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:na12', first.attempt, { state: 'FAILED', evidence: failedEvidence(12), reason: 'not_found' }, 'recovery:approved', 'terminal'));
        assert.deepEqual([notFound.state, notFound.reason], ['INDETERMINATE', 'provider_outcome_authentication_failed']);
        assert.equal(row.state, 'INVOKING');
        // Terminal reconciliation with provider evidence that the verifier
        // accepts as authenticating non-existence of the attempt's provider
        // idempotency key closes it.
        const closed = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:na12', first.attempt, {
            state: 'FAILED',
            evidence: keyCancelledEvidence(first.attempt.provider_idempotency_key),
            reason: 'idempotency_key_cancelled',
        }, 'recovery:approved', 'terminal'));
        assert.equal(closed.state, 'FAILED');
        assert.equal(row.state, 'RELEASED');
        const fresh = await h.boundary.run({
            operation_id: 'operation:native:na12:fresh',
            handoff: freshAuthorization(f, 'na12-fresh'),
            action: ACTION,
        });
        assert.equal(fresh.state, 'EXECUTED');
        assert.equal(calls, 1);
    }
    {
        // A read settles it before the retries run out: the run confirms INVOKING
        // and invokes as the owner, having sent no not-entered write.
        const f = nativeFixture();
        const attempts = lostStartAttemptStore(1 + 2);
        const written = [];
        const transition = attempts.transition;
        attempts.transition = async (entry) => {
            written.push(`${entry.expected_state}->${entry.next_state}`);
            return transition(entry);
        };
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const first = await h.boundary.run(nativeInput(f, 'operation:native:na12b'));
        assert.equal(first.state, 'EXECUTED');
        assert.deepEqual(written, ['RESERVED->INVOKING', 'INVOKING->INDETERMINATE']);
        assert.equal(calls, 1);
    }
    {
        // One read short: held again, with no not-entered write.
        const f = nativeFixture();
        const attempts = lostStartAttemptStore(1 + 3);
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} }; },
        });
        const first = await h.boundary.run(nativeInput(f, 'operation:native:na12c'));
        assert.deepEqual([first.state, first.reason, first.invoked], ['INDETERMINATE', 'attempt_start_unconfirmed', false]);
        assert.equal([...attempts.rows.values()][0].state, 'INVOKING');
        assert.equal(calls, 0);
    }
});
test('T1 NX1 native: a delayed not-entered write can never land on an attempt that entered the provider', async () => {
    // Port of the round-4 NX1 probe. The start write lands and the next four
    // reads fail. The round-4 run then sent INVOKING -> RELEASED with the
    // marker, whose acknowledgement was lost; a later read showed INVOKING and
    // it invoked; the queued marker committed during the provider call, and
    // pre-entry recovery released the grant for a second call.
    for (const lookup of ['INDETERMINATE', 'FAILED']) {
        const f = nativeFixture();
        const attempts = attemptStore();
        const transition = attempts.transition.bind(attempts);
        const state = attempts.state.bind(attempts);
        let armed = true;
        let failReads = 0;
        let pendingMarker = null;
        const notEnteredWrites = [];
        attempts.transition = async (entry) => {
            if (armed && entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
                armed = false;
                const result = await transition(entry);
                failReads = 4;
                return result;
            }
            if (entry.next_state === 'RELEASED')
                notEnteredWrites.push(entry.expected_state);
            if (entry.expected_state === 'INVOKING' && entry.next_state === 'RELEASED' && !pendingMarker) {
                pendingMarker = () => transition(entry);
                throw new Error('write timeout');
            }
            return transition(entry);
        };
        attempts.state = async (entry) => {
            if (failReads > 0) {
                failReads -= 1;
                throw new Error('read timeout');
            }
            return state(entry);
        };
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                if (pendingMarker)
                    await pendingMarker();
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const run = await h.boundary.run(nativeInput(f, 'operation:native:nx1'));
        assert.deepEqual([run.state, run.reason, run.invoked], ['INDETERMINATE', 'attempt_start_unconfirmed', false], lookup);
        assert.deepEqual(notEnteredWrites, [], `${lookup}: no not-entered write after an unconfirmed start`);
        const row = [...attempts.rows.values()][0];
        assert.equal(row.state, 'INVOKING', lookup);
        const recovery = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:nx1', structuredClone(row.binding), lookup === 'FAILED'
            ? { state: 'FAILED', evidence: failedEvidence(1), reason: 'not_found' }
            : { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }));
        assert.deepEqual([recovery.state, recovery.reason], ['INDETERMINATE', 'recovery_lost_to_live_attempt'], lookup);
        const again = await h.boundary.run(nativeInput(f, 'operation:native:nx1'));
        assert.notEqual(again.state, 'EXECUTED', lookup);
        const otherOperation = await h.boundary.run(nativeInput(f, 'operation:native:nx1:second'));
        assert.notEqual(otherOperation.state, 'EXECUTED', lookup);
        assert.equal(calls, 0, `${lookup}: the grant never entered the provider twice`);
    }
});
test('S5c NA10 native: a terminal outcome the verifier refuses leaves an INVOKING record unfrozen and the live run finishes it', async () => {
    const f = nativeFixture();
    const atProvider = deferred();
    const providerGo = deferred();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        // Accepts only the provider's own result, never a caller's junk evidence.
        providerOutcomeVerify: (context) => (context.purpose === 'provider_outcome'
            && context.outcome.evidence.evidence_id.startsWith('provider-evidence:call-'))
            ? affirm(context)
            : false,
        invoke: async () => {
            calls += 1;
            atProvider.resolve();
            await providerGo.promise;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const live = h.boundary.run(nativeInput(f, 'operation:native:na10'));
    await atProvider.promise;
    const row = [...h.attempts.rows.values()][0];
    const junk = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:na10', row.binding, { state: 'FAILED', evidence: failedEvidence(10), reason: 'not_found' }, 'recovery:approved', 'terminal'));
    assert.equal(junk.state, 'INDETERMINATE');
    assert.equal(junk.reason, 'provider_outcome_authentication_failed');
    assert.equal(row.state, 'INVOKING');
    providerGo.resolve();
    const result = await live;
    assert.equal(result.state, 'EXECUTED');
    assert.equal(row.state, 'COMMITTED');
    assert.equal(calls, 1);
});
test('a reserve error never releases a reservation another attempt holds under the same operation ID', async () => {
    // Regression for PG6 (in-memory store with the PostgreSQL ownership model):
    // the reserve-error catch released the operation key using the per-instance
    // owner token of a live attempt that shared the caller-chosen operation ID,
    // which dropped its native replay fence and let its grant be spent twice.
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const reserve = aebStore.reserve.bind(aebStore);
    let failNextOperationReserve = false;
    aebStore.reserve = async (key, replayKeys) => {
        if (failNextOperationReserve && key.startsWith('aeb-native-attempt-operation:')) {
            failNextOperationReserve = false;
            throw new Error('statement timeout');
        }
        return reserve(key, replayKeys);
    };
    const providerGate = deferred();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        aebStore,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            if (calls === 1)
                await providerGate.promise;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const victimRun = h.boundary.run(nativeInput(f, 'operation:native:shared-id'));
    await new Promise((resolve) => setTimeout(resolve, 10));
    const held = [...aebStore.operations.entries()];
    assert.equal(held.length, 3);
    const replayFences = aebStore.replayOwners.size;
    failNextOperationReserve = true;
    const attacker = await h.boundary.run({
        operation_id: 'operation:native:shared-id',
        handoff: freshAuthorization(f, 'shared-id-attacker'),
        action: ACTION,
    });
    // T6: a reserve that threw may still land, so the stop is INDETERMINATE,
    // never a clean refusal; it still never touches another attempt's rows.
    assert.equal(attacker.state, 'INDETERMINATE');
    assert.equal(attacker.reason, 'consumption_reservation_unconfirmed');
    assert.equal(attacker.invoked, false);
    assert.deepEqual([...aebStore.operations.entries()], held, 'victim rows untouched');
    assert.equal(aebStore.replayOwners.size, replayFences, 'victim fences untouched');
    providerGate.resolve();
    const victim = await victimRun;
    assert.equal(victim.state, 'EXECUTED');
    const reuse = await h.boundary.run({
        operation_id: 'operation:native:shared-id:reuse',
        handoff: issueNative(f, { action: { ...ACTION, transfer_id: 'transfer-other' } }),
        action: { ...ACTION, transfer_id: 'transfer-other' },
    });
    assert.equal(reuse.state, 'REFUSED');
    assert.equal(reuse.reason, 'native_replay_conflict');
    assert.equal(calls, 1);
});
test('restart reconciliation completes in one call with one credential bound to the attempt', async () => {
    // Regression for PG4: an authorizer that binds a credential to one attempt
    // needed a second reconcile with a holder-bound credential.
    for (const terminal of ['FAILED', 'EXECUTED']) {
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const attempts = attemptStore();
        const before = makeNativeBoundary({
            f,
            aebStore,
            attempts,
            invoke: async () => { throw new Error('process lost the response'); },
        });
        const uncertain = await before.boundary.run(nativeInput(f, `operation:native:one-credential:${terminal}`));
        assert.equal(uncertain.state, 'INDETERMINATE');
        const restartedStore = durableAebStore(aebStore.db, ({ authorization, scope }) => authorization?.attempt_id === scope?.attemptId);
        const after = makeNativeBoundary({
            f,
            aebStore: restartedStore,
            attempts,
            attemptPrefix: 'restarted:',
            recover: ({ attempt, recovery_authorization }) => {
                if (recovery_authorization?.attempt_id !== attempt.attempt_id)
                    return null;
                const stored = attempts.rows.get(attempt.attempt_id);
                return stored ? { ...structuredClone(stored.binding), owner: stored.owner } : null;
            },
        });
        const reconciled = await after.boundary.reconcile({
            operation_id: `operation:native:one-credential:${terminal}`,
            handoff: f.handoff,
            action: ACTION,
            attempt: uncertain.attempt,
            outcome: terminal === 'FAILED'
                ? { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(1), reason: 'declined' }
                : { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: providerOutcomeFor(1), result: {} },
            recovery_authorization: { attempt_id: uncertain.attempt.attempt_id },
        });
        assert.equal(reconciled.state, terminal, terminal);
        assert.equal(restartedStore.claims.length, 3, terminal);
        const states = [...aebStore.operations.values()].slice(0, 3);
        assert.deepEqual(states, terminal === 'FAILED' ? ['CONSUMED', 'CONSUMED'] : ['CONSUMED', 'CONSUMED', 'CONSUMED'], terminal);
    }
});
test('pins that alias one issuer are refused at construction; one shared namespace makes one spend', async () => {
    // Regression for C5/C6 at the Gate boundary.
    const f = nativeFixture();
    const alias = `${f.handoffInput.native_authorization.issuer}/`;
    const aliased = nativeFixture();
    aliased.pins.accepted_sources.push({ ...aliased.pins.accepted_sources[0], issuer: alias });
    assert.throws(() => makeNativeBoundary({ f: aliased }), /native_consequence_boundary_configuration_invalid: native_pins_issuer_alias_without_shared_namespace/);
    f.pins.accepted_sources[0].authority_namespace = 'namespace:authzen';
    f.pins.accepted_sources.push({
        ...f.pins.accepted_sources[0],
        issuer: alias,
        authority_namespace: 'namespace:authzen',
    });
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    assert.equal((await h.boundary.run(nativeInput(f, 'operation:native:alias:1'))).state, 'EXECUTED');
    const other = { ...ACTION, transfer_id: 'transfer-alias' };
    const second = await h.boundary.run({
        operation_id: 'operation:native:alias:2',
        handoff: issueNative(f, {
            native_authorization: { ...f.handoffInput.native_authorization, issuer: alias },
            action: other,
        }),
        action: other,
    });
    assert.equal(second.state, 'REFUSED');
    assert.equal(second.reason, 'native_replay_conflict');
    assert.equal(calls, 1);
});
// ------------------------------ composed path ------------------------------
function composedFresh(base, suffix) {
    return fixture({
        operationId: `operation:composed:${suffix}`,
        replayId: `native-mandate:composed:${suffix}`,
        evaluatorKeys: base.evaluatorKeys,
    });
}
test('C1 composed: a fresh evaluation cannot re-enter the provider while the same action is INDETERMINATE', async () => {
    // Regression for OLD1 / the composed C1 probe: createConsequenceBoundary had
    // no same-action fence, so fresh native evidence for the identical action
    // was admitted while the first attempt was INDETERMINATE: 2 provider calls.
    const first = fixture({ operationId: 'operation:composed:1', replayId: 'native-mandate:composed:1' });
    let calls = 0;
    const h = makeBoundary({
        f: first,
        invoke: async () => {
            calls += 1;
            if (calls === 1)
                throw new Error('provider timeout');
            return { state: 'EXECUTED', evidence: executedEvidence(), result: { n: calls } };
        },
    });
    const uncertain = await h.boundary.run(input(first));
    assert.equal(uncertain.state, 'INDETERMINATE');
    assert.equal(uncertain.reason, 'provider_outcome_indeterminate');
    const second = composedFresh(first, '2');
    const fenced = await h.boundary.run(input(second));
    assert.equal(fenced.state, 'REFUSED');
    assert.equal(fenced.reason, 'native_action_in_flight');
    assert.equal(calls, 1);
    // The refused evaluation handed its own reservation back and is still usable.
    assert.equal(h.aebStore.operations.get(aebReservationKey(second.evaluation)), undefined);
    const reconciled = await h.boundary.reconcile({
        evaluation: first.evaluation,
        action: ACTION,
        artifacts: first.artifacts,
        attempt: uncertain.attempt,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), result: { n: 1 } },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    const third = await h.boundary.run(input(composedFresh(first, '3')));
    assert.equal(third.state, 'REFUSED');
    assert.equal(third.reason, 'native_action_already_executed');
    assert.equal(calls, 1);
});
test('composed: an authenticated FAILED in run or reconcile releases the fence; concurrency enters once', async () => {
    {
        const first = fixture({ operationId: 'operation:composed:f1', replayId: 'native-mandate:composed:f1' });
        let calls = 0;
        const h = makeBoundary({
            f: first,
            invoke: async () => {
                calls += 1;
                return calls === 1
                    ? { state: 'FAILED', evidence: failedEvidence(calls), reason: 'declined' }
                    : { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        assert.equal((await h.boundary.run(input(first))).state, 'FAILED');
        assert.equal((await h.boundary.run(input(first))).reason, 'consumption_conflict');
        assert.equal((await h.boundary.run(input(composedFresh(first, 'f2')))).state, 'EXECUTED');
        assert.equal(calls, 2);
    }
    {
        const first = fixture({ operationId: 'operation:composed:r1', replayId: 'native-mandate:composed:r1' });
        let calls = 0;
        const h = makeBoundary({
            f: first,
            invoke: async () => {
                calls += 1;
                if (calls === 1)
                    throw new Error('lost');
                return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        const uncertain = await h.boundary.run(input(first));
        const failed = await h.boundary.reconcile({
            evaluation: first.evaluation,
            action: ACTION,
            artifacts: first.artifacts,
            attempt: uncertain.attempt,
            outcome: { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: failedEvidence(1), reason: 'declined' },
            recovery_authorization: 'recovery:approved',
        });
        assert.equal(failed.state, 'FAILED');
        assert.equal((await h.boundary.run(input(composedFresh(first, 'r2')))).state, 'EXECUTED');
        assert.equal(calls, 2);
    }
    {
        const first = fixture({ operationId: 'operation:composed:c0', replayId: 'native-mandate:composed:c0' });
        let calls = 0;
        const h = makeBoundary({
            f: first,
            invoke: async () => {
                calls += 1;
                await new Promise((resolve) => setTimeout(resolve, 5));
                return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        const evaluations = [first, ...[1, 2, 3, 4, 5].map((n) => composedFresh(first, `c${n}`))];
        const results = await Promise.all(evaluations.map((f) => h.boundary.run(input(f))));
        assert.equal(calls, 1);
        assert.equal(results.filter((result) => result.state === 'EXECUTED').length, 1);
        for (const result of results) {
            if (result.state === 'REFUSED') {
                assert.ok(['native_action_in_flight', 'native_action_already_executed'].includes(result.reason));
            }
        }
    }
});
test('composed: a pre-entry lockout is recovered by pre-entry reconcile and leaves only that evaluation spent', async () => {
    const first = fixture({ operationId: 'operation:composed:lock', replayId: 'native-mandate:composed:lock' });
    const aebStore = durableAebStore();
    const release = aebStore.release.bind(aebStore);
    let failHolderRelease = true;
    aebStore.release = async (key) => {
        if (failHolderRelease && key.startsWith('aeb-action-holder:')) {
            failHolderRelease = false;
            throw new Error('connection reset');
        }
        return release(key);
    };
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    attempts.transition = async (entry) => (entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING' && entry.attempt_id === 'attempt:1'
        ? false
        : transition(entry));
    let calls = 0;
    const h = makeBoundary({
        f: first,
        aebStore,
        attempts,
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        },
    });
    // The start write answers false and the durable record is still RESERVED,
    // so the run closes the attempt as not entered first (R2, R3). The holder
    // release then fails, so the holder, and behind it R(E), stay held.
    const locked = await h.boundary.run(input(first));
    assert.equal(locked.state, 'INDETERMINATE');
    assert.equal(locked.reason, 'native_pre_entry_release_unconfirmed');
    assert.equal(locked.invoked, false);
    assert.equal(attempts.rows.get('attempt:1').state, 'RELEASED');
    const reservationKey = aebReservationKey(first.evaluation);
    const holderKey = consequenceBoundaryActionFenceHolderKey({ reservation_key: reservationKey, boundary_id: COMPOSED_BOUNDARY_ID, attempt_id: 'attempt:1' });
    assert.equal(aebStore.operations.get(holderKey), 'RESERVED');
    assert.equal(aebStore.operations.get(reservationKey), 'RESERVED');
    const fenced = await h.boundary.run(input(composedFresh(first, 'lock-2')));
    assert.equal(fenced.reason, 'native_action_in_flight');
    const recovery = {
        evaluation: first.evaluation,
        action: ACTION,
        artifacts: first.artifacts,
        attempt: locked.attempt,
        outcome: { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' },
        recovery_authorization: 'recovery:approved',
    };
    // Terminal reconciliation is a separate mode and changes nothing here.
    const terminal = await h.boundary.reconcile({
        ...recovery,
        outcome: { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), reason: 'not_found' },
    });
    assert.equal(terminal.state, 'INDETERMINATE');
    assert.equal(terminal.reason, 'pre_entry_recovery_required');
    assert.equal(aebStore.operations.get(holderKey), 'RESERVED');
    assert.equal((await h.boundary.run(input(composedFresh(first, 'lock-2b')))).reason, 'native_action_in_flight');
    const recovered = await h.boundary.reconcile({ ...recovery, mode: 'pre_entry' });
    assert.equal(recovered.state, 'REFUSED');
    assert.equal(recovered.reason, 'attempt_never_entered_provider');
    // Pre-entry recovery releases only this attempt's holder. It never touches
    // R(E), which is keyed by the evaluation: it stays RESERVED, so this
    // evaluation cannot be reserved again, and the fence is open.
    assert.equal(aebStore.operations.get(holderKey), undefined);
    assert.equal(aebStore.operations.get(reservationKey), 'RESERVED');
    assert.equal((await h.boundary.run(input(first))).reason, 'consumption_conflict');
    assert.equal((await h.boundary.run(input(composedFresh(first, 'lock-3')))).state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('composed: restart reconciliation claims the evaluation and the fence holder with one credential', async () => {
    const first = fixture({ operationId: 'operation:composed:restart', replayId: 'native-mandate:composed:restart' });
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const before = makeBoundary({ f: first, aebStore, attempts, invoke: async () => { throw new Error('lost'); } });
    const uncertain = await before.boundary.run(input(first));
    assert.equal(uncertain.state, 'INDETERMINATE');
    const restartedStore = durableAebStore(aebStore.db);
    const after = makeBoundary({ f: first, aebStore: restartedStore, attempts, attemptPrefix: 'restarted:' });
    const reconciled = await after.boundary.reconcile({
        evaluation: first.evaluation,
        action: ACTION,
        artifacts: first.artifacts,
        attempt: uncertain.attempt,
        outcome: { state: 'EXECUTED', evidence_kind: 'provider_outcome', evidence: executedEvidence(), result: {} },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    assert.deepEqual(restartedStore.claimScopes.map((scope) => scope.reservation), ['operation', 'action-fence-holder']);
    assert.ok(restartedStore.claimScopes.every((scope) => scope.attemptId === uncertain.attempt.attempt_id
        && scope.recoveryOperationKey === aebReservationKey(first.evaluation)));
    assert.equal((await after.boundary.run(input(composedFresh(first, 'restart-2')))).reason, 'native_action_already_executed');
});
test('the composed and native boundaries share one action fence per relying party and provider', async () => {
    const composed = fixture({ operationId: 'operation:shared-fence', replayId: 'native-mandate:shared-fence' });
    const nativeF = nativeFixture('authzen', composed.config.relying_party_id);
    const aebStore = durableAebStore();
    let calls = 0;
    const invoke = async () => {
        calls += 1;
        if (calls === 1)
            throw new Error('provider timeout');
        return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
    };
    const nativeBoundary = makeNativeBoundary({
        f: nativeF,
        aebStore,
        resolveStatus: (handoff) => nativeStatusFor(nativeF, handoff),
        invoke,
    });
    const composedBoundary = makeBoundary({ f: composed, aebStore, invoke });
    assert.equal((await nativeBoundary.boundary.run(nativeInput(nativeF, 'operation:shared-fence:native'))).state, 'INDETERMINATE');
    const fenced = await composedBoundary.boundary.run(input(composed));
    assert.equal(fenced.state, 'REFUSED');
    assert.equal(fenced.reason, 'native_action_in_flight');
    assert.equal(calls, 1);
    assert.equal(nativeConsequenceBoundaryActionFenceKey({
        relying_party_id: composed.config.relying_party_id,
        provider: PROVIDER,
        action_digest: digestAebNativeAuthorizationAction(ACTION),
    }), [...aebStore.replayOwners.keys()].find((key) => key.startsWith('aeb-native-action:')));
});
// ---------------------------------------------------------------------------
// PR #790 round 3: pre-entry recovery linearization (R1), release ordering
// (R2), lost start acknowledgements (R3), strict answers (R4), claim binding
// (R5), evaluation-reservation ownership (R6), liveness (R8), and hostile
// composed input (R9). Each test is ported from the round-2 probe named in it.
// ---------------------------------------------------------------------------
/**
 * Attempt store whose live RESERVED -> INVOKING write blocks until a
 * RESERVED -> RELEASED write (recovery) arrives; that write then finds the
 * live write already applied, exactly as when the live run wins the race.
 */
function racingAttemptStore(liveWins = true) {
    const base = attemptStore();
    const liveArrived = deferred();
    const liveGo = deferred();
    let liveAnswer = false;
    let blocked = false;
    let armed = true;
    const store = {
        ...base,
        rows: base.rows,
        liveArrived,
        async transition(entry) {
            if (!blocked && entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
                blocked = true;
                liveArrived.resolve();
                await liveGo.promise;
                return liveAnswer === 'apply' ? base.transition(entry) : liveAnswer;
            }
            if (armed && entry.expected_state === 'RESERVED' && entry.next_state === 'RELEASED') {
                armed = false;
                if (liveWins) {
                    base.rows.get(entry.attempt_id).state = 'INVOKING';
                    liveAnswer = true;
                    liveGo.resolve();
                    return base.transition(entry);
                }
                const answer = await base.transition(entry);
                liveAnswer = 'apply';
                liveGo.resolve();
                return answer;
            }
            return base.transition(entry);
        },
    };
    return store;
}
test('R1 N1a/RR4 native: a pre-entry recovery that loses its transition to the live run releases nothing', async () => {
    for (const lookup of ['FAILED', 'INDETERMINATE']) {
        const f = nativeFixture();
        const attempts = racingAttemptStore(true);
        const atProvider = deferred();
        const providerGo = deferred();
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => {
                calls += 1;
                if (calls === 1) {
                    atProvider.resolve();
                    await providerGo.promise;
                }
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const live = h.boundary.run(nativeInput(f, `operation:native:r1:${lookup}`));
        await attempts.liveArrived.promise;
        const row = [...attempts.rows.values()][0];
        assert.equal(row.state, 'RESERVED', lookup);
        // The operator sees RESERVED and presents a truthful "not found" lookup.
        const recovery = await h.boundary.reconcile(nativeRecovery(f, `operation:native:r1:${lookup}`, structuredClone(row.binding), lookup === 'FAILED'
            ? { state: 'FAILED', evidence: failedEvidence(11), reason: 'not_found' }
            : { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }));
        assert.equal(recovery.state, 'INDETERMINATE', lookup);
        assert.equal(recovery.reason, 'recovery_lost_to_live_attempt', lookup);
        assert.equal(row.state, 'INVOKING', lookup);
        assert.deepEqual([...h.aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED'], lookup);
        await atProvider.promise;
        // The first call is still at the provider: a fresh authorization for the
        // same action stays fenced.
        const fresh = await h.boundary.run({
            operation_id: `operation:native:r1:${lookup}:fresh`,
            handoff: freshAuthorization(f, `r1-${lookup}`),
            action: ACTION,
        });
        assert.equal(fresh.state, 'REFUSED', lookup);
        assert.equal(fresh.reason, 'native_action_in_flight', lookup);
        providerGo.resolve();
        const result = await live;
        assert.equal(result.state, 'EXECUTED', lookup);
        assert.equal(calls, 1, lookup);
    }
});
test('R1 native: once pre-entry recovery linearizes first, the live run never invokes and hands back its rows', async () => {
    const f = nativeFixture();
    const attempts = racingAttemptStore(false);
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        attempts,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const live = h.boundary.run(nativeInput(f, 'operation:native:r1-win'));
    await attempts.liveArrived.promise;
    const row = [...attempts.rows.values()][0];
    const recovery = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:r1-win', structuredClone(row.binding), { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }));
    assert.equal(recovery.state, 'REFUSED');
    assert.equal(recovery.reason, 'attempt_never_entered_provider');
    const result = await live;
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'attempt_released_by_recovery');
    assert.equal(result.invoked, false);
    assert.equal(row.state, 'RELEASED');
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal(calls, 0);
});
test('R1 pre-entry mode input: an unknown mode is refused, and the verifier sees the lookup purpose', async () => {
    const f = nativeFixture();
    const purposes = [];
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => {
            // Refuse at provider entry so the attempt stops before the callback.
            return { ...nativeStatusFor(f, handoff), revoked: true };
        },
        providerOutcomeVerify: (context) => {
            purposes.push(context.purpose);
            return affirm(context);
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:mode'));
    assert.equal(first.state, 'REFUSED');
    const record = [...h.attempts.rows.values()];
    assert.equal(record.length, 0);
    const g = nativeFixture();
    const aebStore = durableAebStore();
    const release = aebStore.release.bind(aebStore);
    let fail = true;
    aebStore.release = async (key) => {
        if (fail && key.startsWith('aeb-native-action-holder:')) {
            fail = false;
            throw new Error('reset');
        }
        return release(key);
    };
    let lookups = 0;
    const k = makeNativeBoundary({
        f: g,
        aebStore,
        resolveStatus: (handoff) => {
            lookups += 1;
            return { ...nativeStatusFor(g, handoff), revoked: lookups === 2 };
        },
        providerOutcomeVerify: (context) => {
            purposes.push(context.purpose);
            return affirm(context);
        },
    });
    const stopped = await k.boundary.run(nativeInput(g, 'operation:native:mode'));
    assert.equal(stopped.reason, 'native_pre_entry_release_unconfirmed');
    const bogus = await k.boundary.reconcile({
        ...nativeRecovery(g, 'operation:native:mode', stopped.attempt, { state: 'FAILED', evidence: failedEvidence(21), reason: 'not_found' }),
        mode: 'both',
    });
    assert.equal(bogus.state, 'REFUSED');
    assert.equal(bogus.reason, 'native_reconciliation_input_invalid');
    const recovered = await k.boundary.reconcile(nativeRecovery(g, 'operation:native:mode', stopped.attempt, { state: 'FAILED', evidence: failedEvidence(21), reason: 'not_found' }));
    assert.equal(recovered.reason, 'attempt_never_entered_provider');
    assert.deepEqual(purposes, ['pre_entry_lookup']);
});
test('R1 N1b native: a verifier that accepts lookups only as pre-entry evidence keeps a live call fenced', async () => {
    const f = nativeFixture();
    const atProvider = deferred();
    const providerGo = deferred();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        // A pinned program following the documented rule: a "not found" lookup is
        // pre-entry evidence, never a terminal NOT_COMMITTED.
        providerOutcomeVerify: (context) => (context.purpose === 'pre_entry_lookup'
            || context.outcome.evidence.evidence_id.startsWith('provider-evidence:call-'))
            ? affirm(context)
            : false,
        invoke: async () => {
            calls += 1;
            if (calls === 1) {
                atProvider.resolve();
                await providerGo.promise;
            }
            return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const live = h.boundary.run(nativeInput(f, 'operation:native:n1b'));
    await atProvider.promise;
    const row = [...h.attempts.rows.values()][0];
    assert.equal(row.state, 'INVOKING');
    const asLookup = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:n1b', structuredClone(row.binding), { state: 'FAILED', evidence: failedEvidence(31), reason: 'not_found' }));
    assert.equal(asLookup.reason, 'recovery_lost_to_live_attempt');
    const asTerminal = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:n1b', structuredClone(row.binding), { state: 'FAILED', evidence: failedEvidence(31), reason: 'not_found' }, 'recovery:approved', 'terminal'));
    assert.equal(asTerminal.state, 'INDETERMINATE');
    assert.equal(asTerminal.reason, 'provider_outcome_authentication_failed');
    const fresh = await h.boundary.run({
        operation_id: 'operation:native:n1b:fresh',
        handoff: freshAuthorization(f, 'n1b'),
        action: ACTION,
    });
    assert.equal(fresh.reason, 'native_action_in_flight');
    providerGo.resolve();
    // The refused reconciliation only froze the record; the live run closes it
    // with its own authenticated outcome, and a repeated terminal
    // reconciliation with that outcome is idempotent.
    const result = await live;
    assert.equal(result.state, 'EXECUTED');
    const closed = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:n1b', structuredClone(row.binding), { state: 'EXECUTED', evidence: providerOutcomeFor(1), result: {} }, 'recovery:approved', 'terminal'));
    assert.equal(closed.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('R2 native: terminal reconciliation closes nothing until the terminal record is confirmed', async () => {
    const f = nativeFixture();
    const attempts = attemptStore();
    const terminal = attempts.reconcile.bind(attempts);
    let failTerminal = true;
    attempts.reconcile = async (entry) => {
        if (failTerminal)
            throw new Error('attempt store unavailable');
        return terminal(entry);
    };
    const h = makeNativeBoundary({
        f,
        attempts,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => { throw new Error('response lost'); },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:r2'));
    assert.equal(first.reason, 'provider_outcome_indeterminate');
    const reconciliation = nativeRecovery(f, 'operation:native:r2', first.attempt, { state: 'FAILED', evidence: providerOutcomeFor(1), reason: 'declined' }, 'recovery:approved', 'terminal');
    const unconfirmed = await h.boundary.reconcile(reconciliation);
    assert.equal(unconfirmed.state, 'INDETERMINATE');
    assert.equal(unconfirmed.reason, 'attempt_terminal_record_unconfirmed');
    assert.deepEqual([...h.aebStore.operations.values()], ['RESERVED', 'RESERVED', 'RESERVED']);
    assert.equal((await h.boundary.run({
        operation_id: 'operation:native:r2:fresh',
        handoff: freshAuthorization(f, 'r2'),
        action: ACTION,
    })).reason, 'native_action_in_flight');
    failTerminal = false;
    assert.equal((await h.boundary.reconcile(reconciliation)).state, 'FAILED');
});
test('R3/R4 N6b native: a truthy non-true start answer and a lost start acknowledgement follow the durable record', async () => {
    {
        const f = nativeFixture();
        const attempts = attemptStore();
        const transition = attempts.transition.bind(attempts);
        attempts.transition = async (entry) => (entry.next_state === 'INVOKING' ? { ok: false, reason: 'cas_conflict' } : transition(entry));
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(1), result: {} }; },
        });
        const result = await h.boundary.run(nativeInput(f, 'operation:native:truthy'));
        assert.equal(result.state, 'REFUSED');
        assert.equal(result.reason, 'attempt_start_conflict');
        assert.equal(calls, 0);
        assert.equal([...attempts.rows.values()][0].state, 'RELEASED');
        assert.equal(h.aebStore.operations.size, 0);
    }
    {
        // The write lands but its acknowledgement is lost: the durable record
        // says INVOKING and this owner proceeds, releasing nothing on the way.
        const f = nativeFixture();
        const attempts = attemptStore();
        const transition = attempts.transition.bind(attempts);
        attempts.transition = async (entry) => {
            const answer = await transition(entry);
            if (entry.next_state === 'INVOKING')
                throw new Error('acknowledgement lost');
            return answer;
        };
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            attempts,
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(1), result: {} }; },
        });
        const result = await h.boundary.run(nativeInput(f, 'operation:native:lost-start-ack'));
        assert.equal(result.state, 'EXECUTED');
        assert.equal(calls, 1);
    }
});
test('R8 N10 native: a recovery racing a still-reserving run does not strand that run\'s holder', async () => {
    const f = nativeFixture();
    const aebStore = durableAebStore();
    const reserve = aebStore.reserve.bind(aebStore);
    const atHolder = deferred();
    const holderGo = deferred();
    let blocked = false;
    aebStore.reserve = async (key, fences) => {
        if (!blocked && key.startsWith('aeb-native-action-holder:')) {
            blocked = true;
            atHolder.resolve();
            await holderGo.promise;
        }
        return reserve(key, fences);
    };
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        aebStore,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} }; },
    });
    const live = h.boundary.run(nativeInput(f, 'operation:native:n10'));
    await atHolder.promise;
    const row = [...h.attempts.rows.values()][0];
    const recovery = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:n10', structuredClone(row.binding), { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }));
    assert.equal(recovery.reason, 'attempt_never_entered_provider');
    holderGo.resolve();
    const result = await live;
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'attempt_released_by_recovery');
    assert.equal(result.invoked, false);
    assert.equal(aebStore.operations.size, 0);
    // No second recovery is needed: the fence is already open.
    const fresh = await h.boundary.run({
        operation_id: 'operation:native:n10:fresh',
        handoff: freshAuthorization(f, 'n10'),
        action: ACTION,
    });
    assert.equal(fresh.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('R5 recovery-claim scopes name exactly the rows both boundaries derive', () => {
    const nativeKeys = nativeConsequenceBoundaryAttemptReservationKeys({
        relying_party_id: 'rp:payments',
        provider: PROVIDER,
        operation_id: 'operation:native:claim',
        action_digest: digestAebNativeAuthorizationAction(ACTION),
        boundary_id: NATIVE_BOUNDARY_ID,
        attempt_id: 'native-attempt:claim:1',
    });
    const nativeScope = (reservation) => ({
        boundary: 'native',
        boundaryId: NATIVE_BOUNDARY_ID,
        attemptId: 'native-attempt:claim:1',
        operationId: 'operation:native:claim',
        recoveryOperationKey: nativeKeys.operation_fence,
        reservation,
    });
    assert.equal(consequenceBoundaryRecoveryClaimKey(nativeScope('operation')), nativeKeys.operation);
    assert.equal(consequenceBoundaryRecoveryClaimKey(nativeScope('native-authority')), nativeKeys.authority);
    assert.equal(consequenceBoundaryRecoveryClaimKey(nativeScope('action-fence-holder')), nativeKeys.holder);
    assert.equal(consequenceBoundaryRecoveryClaimMarkerKey(nativeScope('operation')), null);
    // The same operation key under another attempt names other rows.
    assert.notEqual(consequenceBoundaryRecoveryClaimKey({ ...nativeScope('action-fence-holder'), attemptId: 'native-attempt:claim:2' }), nativeKeys.holder);
    const f = fixture({ operationId: 'operation:composed:claim', replayId: 'native-mandate:composed:claim' });
    const reservationKey = aebReservationKey(f.evaluation);
    const composedScope = (reservation) => ({
        boundary: 'composed',
        boundaryId: COMPOSED_BOUNDARY_ID,
        attemptId: 'attempt:claim:1',
        operationId: 'operation:composed:claim',
        recoveryOperationKey: reservationKey,
        reservation,
    });
    const holder = consequenceBoundaryActionFenceHolderKey({ reservation_key: reservationKey, boundary_id: COMPOSED_BOUNDARY_ID, attempt_id: 'attempt:claim:1' });
    assert.equal(consequenceBoundaryRecoveryClaimKey(composedScope('operation')), reservationKey);
    assert.equal(consequenceBoundaryRecoveryClaimKey(composedScope('action-fence-holder')), holder);
    assert.equal(consequenceBoundaryRecoveryClaimMarkerKey(composedScope('operation')), holder);
    assert.equal(consequenceBoundaryRecoveryClaimKey(composedScope('native-authority')), null);
    for (const hostile of [null, 7, { ...composedScope('operation'), extra: 1 }, { ...composedScope('operation'), recoveryOperationKey: 'aeb:x' }]) {
        assert.equal(consequenceBoundaryRecoveryClaimKey(hostile), null);
    }
    // S4: the boundary kind is part of the scope. A scope without it, or whose
    // kind does not match its recovery operation key, names no row, so a
    // native scope can never derive a composed row or the reverse.
    const { boundary: _kind, ...unscoped } = composedScope('action-fence-holder');
    assert.equal(consequenceBoundaryRecoveryClaimKey(unscoped), null);
    assert.equal(consequenceBoundaryRecoveryClaimKey({ ...composedScope('action-fence-holder'), boundary: 'native' }), null);
    assert.equal(consequenceBoundaryRecoveryClaimKey({ ...nativeScope('action-fence-holder'), boundary: 'composed' }), null);
    assert.equal(consequenceBoundaryRecoveryClaimMarkerKey({ ...composedScope('operation'), boundary: 'native' }), null);
    // Equal attempt IDs on the two boundaries carry different attempt identities.
    const shared = 'attempt:shared:1';
    assert.equal(consequenceBoundaryRecoveryAttemptIdentity({ ...nativeScope('operation'), attemptId: shared }), `native:${NATIVE_BOUNDARY_ID}:${shared}`);
    assert.equal(consequenceBoundaryRecoveryAttemptIdentity({ ...composedScope('operation'), attemptId: shared }), `composed:${COMPOSED_BOUNDARY_ID}:${shared}`);
    assert.equal(consequenceBoundaryRecoveryAttemptIdentity(unscoped), null);
    // T4: the boundary ID is part of every attempt-derived row key and of the
    // identity, so two boundaries of one kind reusing an attempt ID never name
    // each other's rows. A scope without a boundary ID, or with one outside the
    // grammar, names no row.
    const otherNative = { ...nativeScope('action-fence-holder'), boundaryId: 'native-boundary-2' };
    assert.notEqual(consequenceBoundaryRecoveryClaimKey(otherNative), nativeKeys.holder);
    assert.notEqual(consequenceBoundaryRecoveryAttemptIdentity(otherNative), consequenceBoundaryRecoveryAttemptIdentity(nativeScope('action-fence-holder')));
    const otherComposed = { ...composedScope('action-fence-holder'), boundaryId: 'composed-boundary-2' };
    assert.notEqual(consequenceBoundaryRecoveryClaimKey(otherComposed), holder);
    const { boundaryId: _boundaryId, ...noBoundaryId } = nativeScope('operation');
    assert.equal(consequenceBoundaryRecoveryClaimKey(noBoundaryId), null);
    for (const bad of ['', 'a:b', 'has space', '-lead', 'x'.repeat(129), 7]) {
        assert.equal(consequenceBoundaryRecoveryClaimKey({ ...nativeScope('operation'), boundaryId: bad }), null, String(bad));
    }
    assert.throws(() => consequenceBoundaryActionFenceHolderKey({
        reservation_key: reservationKey, boundary_id: 'a:b', attempt_id: 'attempt:claim:1',
    }), /action_fence_holder_binding_invalid/);
    assert.throws(() => nativeConsequenceBoundaryAttemptReservationKeys({
        relying_party_id: 'rp:payments',
        provider: PROVIDER,
        operation_id: 'operation:native:claim',
        action_digest: digestAebNativeAuthorizationAction(ACTION),
        attempt_id: 'native-attempt:claim:1',
    }), /native_attempt_reservation_binding_invalid/);
});
function makeComposedRace(f, attempts, aebStore = durableAebStore(), invoke) {
    let calls = 0;
    const h = makeBoundary({
        f,
        aebStore,
        attempts,
        invoke: invoke ?? (async () => {
            calls += 1;
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        }),
    });
    return { ...h, calls: () => calls };
}
function composedRecovery(f, attempt, outcome, mode) {
    return {
        evaluation: f.evaluation,
        action: ACTION,
        artifacts: f.artifacts,
        attempt,
        outcome: labelled(outcome, mode),
        recovery_authorization: 'recovery:approved',
        ...(mode ? { mode } : {}),
    };
}
test('R1 N1d/RR3 composed: a pre-entry recovery that loses its transition to the live run releases nothing', async () => {
    const first = fixture({ operationId: 'operation:composed:r1', replayId: 'native-mandate:composed:r1' });
    const attempts = racingAttemptStore(true);
    const atProvider = deferred();
    const providerGo = deferred();
    let calls = 0;
    const h = makeComposedRace(first, attempts, durableAebStore(), async () => {
        calls += 1;
        if (calls === 1) {
            atProvider.resolve();
            await providerGo.promise;
        }
        return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
    });
    const live = h.boundary.run(input(first));
    await attempts.liveArrived.promise;
    const row = [...attempts.rows.values()][0];
    const recovery = await h.boundary.reconcile(composedRecovery(first, structuredClone(row.binding), { state: 'FAILED', evidence: executedEvidence(), reason: 'not_found' }, 'pre_entry'));
    assert.equal(recovery.state, 'INDETERMINATE');
    assert.equal(recovery.reason, 'recovery_lost_to_live_attempt');
    await atProvider.promise;
    const fresh = await h.boundary.run(input(composedFresh(first, 'r1-fresh')));
    assert.equal(fresh.state, 'REFUSED');
    assert.equal(fresh.reason, 'native_action_in_flight');
    providerGo.resolve();
    assert.equal((await live).state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('R2 N1c/RR2 composed: reconcile releases nothing before the terminal record is confirmed', async () => {
    for (const failure of ['terminal', 'freeze']) {
        const first = fixture({ operationId: `operation:composed:r2:${failure}`, replayId: `native-mandate:composed:r2:${failure}` });
        const aebStore = durableAebStore();
        const attempts = attemptStore();
        const transition = attempts.transition.bind(attempts);
        const terminal = attempts.reconcile.bind(attempts);
        let failRecovery = false;
        attempts.transition = async (entry) => (failRecovery && failure === 'freeze' && entry.next_state === 'INDETERMINATE' ? false : transition(entry));
        attempts.reconcile = async (entry) => (failRecovery && failure === 'terminal' ? false : terminal(entry));
        const atProvider = deferred();
        const providerGo = deferred();
        let calls = 0;
        const h = makeComposedRace(first, attempts, aebStore, async () => {
            calls += 1;
            if (calls === 1) {
                atProvider.resolve();
                await providerGo.promise;
            }
            return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        });
        const live = h.boundary.run(input(first));
        await atProvider.promise;
        const row = [...attempts.rows.values()][0];
        assert.equal(row.state, 'INVOKING');
        if (failure === 'terminal') {
            // Freeze the record the way a crashed run would have left it.
            row.state = 'INDETERMINATE';
        }
        failRecovery = true;
        const recovery = await h.boundary.reconcile(composedRecovery(first, structuredClone(row.binding), { state: 'FAILED', evidence: executedEvidence(), reason: 'declined' }));
        assert.equal(recovery.state, 'INDETERMINATE', failure);
        assert.equal(recovery.reason, failure === 'terminal' ? 'attempt_terminal_record_unconfirmed' : 'attempt_freeze_unconfirmed', failure);
        const reservationKey = aebReservationKey(first.evaluation);
        assert.equal(aebStore.operations.get(reservationKey), 'RESERVED', failure);
        assert.equal(aebStore.operations.get(consequenceBoundaryActionFenceHolderKey({
            reservation_key: reservationKey,
            boundary_id: COMPOSED_BOUNDARY_ID,
            attempt_id: row.binding.attempt_id,
        })), 'RESERVED', failure);
        const fresh = await h.boundary.run(input(composedFresh(first, `r2-${failure}`)));
        assert.equal(fresh.reason, 'native_action_in_flight', failure);
        failRecovery = false;
        providerGo.resolve();
        await live;
        assert.equal(calls, 1, failure);
    }
});
test('R2 N2 composed: a 0.26.0-style attempt store never releases a RESERVED attempt on a terminal outcome', async () => {
    const first = fixture({ operationId: 'operation:composed:legacy', replayId: 'native-mandate:composed:legacy' });
    const aebStore = durableAebStore();
    const full = attemptStore();
    let answerFalseOnce = true;
    const { state: _dropped, ...rest } = full;
    const legacy = {
        ...rest,
        rows: full.rows,
        async transition(entry) {
            if (answerFalseOnce && entry.next_state === 'INVOKING') {
                answerFalseOnce = false;
                return false;
            }
            return full.transition(entry);
        },
    };
    const release = aebStore.release.bind(aebStore);
    let failHolderRelease = true;
    aebStore.release = async (key) => {
        if (failHolderRelease && key.startsWith('aeb-action-holder:')) {
            failHolderRelease = false;
            throw new Error('connection reset');
        }
        return release(key);
    };
    const h = makeComposedRace(first, legacy, aebStore);
    // T1: without a durable read a start answer other than `true` is an
    // unconfirmed start. The run holds everything, never invokes, and sends no
    // not-entered write.
    const stopped = await h.boundary.run(input(first));
    assert.equal(stopped.state, 'INDETERMINATE');
    assert.equal(stopped.reason, 'attempt_start_unconfirmed');
    assert.equal(stopped.invoked, false);
    const row = full.rows.get(stopped.attempt.attempt_id);
    assert.equal(row.state, 'RESERVED');
    assert.equal(row.evidence, undefined);
    const terminal = await h.boundary.reconcile(composedRecovery(first, stopped.attempt, { state: 'FAILED', evidence: executedEvidence(), reason: 'not_found' }));
    assert.equal(terminal.state, 'INDETERMINATE');
    assert.equal(terminal.reason, 'attempt_terminal_record_unconfirmed');
    assert.equal(row.state, 'RESERVED');
    assert.equal((await h.boundary.run(input(composedFresh(first, 'legacy-2')))).reason, 'native_action_in_flight');
    // Pre-entry recovery proves the stop by its own acknowledged
    // RESERVED -> RELEASED and releases the holder, never R(E).
    failHolderRelease = false;
    const recovered = await h.boundary.reconcile(composedRecovery(first, stopped.attempt, { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }, 'pre_entry'));
    assert.equal(recovered.state, 'REFUSED');
    assert.equal(recovered.reason, 'attempt_never_entered_provider');
    assert.equal(row.state, 'RELEASED');
    assert.equal(aebStore.state(aebReservationKey(first.evaluation)), 'RESERVED');
    // A RESERVED record behind a legacy store: the terminal path fails both
    // writes and releases nothing; the pre-entry mode proves the stop by its own
    // acknowledged transition and releases the holder.
    const second = composedFresh(first, 'legacy-3');
    const reserved = attemptStore();
    const { state: _unused, ...reservedRest } = reserved;
    let stall = true;
    const stalledStore = {
        ...reservedRest,
        rows: reserved.rows,
        async transition(entry) {
            if (stall && entry.next_state === 'INVOKING')
                await new Promise(() => { });
            return reserved.transition(entry);
        },
    };
    const g = makeComposedRace(second, stalledStore, durableAebStore());
    void g.boundary.run(input(second));
    await new Promise((resolve) => setTimeout(resolve, 10));
    const stuck = [...reserved.rows.values()][0];
    assert.equal(stuck.state, 'RESERVED');
    const refusedTerminal = await g.boundary.reconcile(composedRecovery(second, structuredClone(stuck.binding), { state: 'FAILED', evidence: executedEvidence(), reason: 'not_found' }));
    assert.equal(refusedTerminal.reason, 'attempt_terminal_record_unconfirmed');
    assert.equal(stuck.state, 'RESERVED');
    stall = false;
    const preEntry = await g.boundary.reconcile(composedRecovery(second, structuredClone(stuck.binding), { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }, 'pre_entry'));
    assert.equal(preEntry.state, 'REFUSED');
    assert.equal(preEntry.reason, 'attempt_never_entered_provider');
    assert.equal(stuck.state, 'RELEASED');
    assert.equal((await g.boundary.run(input(composedFresh(first, 'legacy-4')))).state, 'EXECUTED');
});
test('R3 RR1 composed: a lost acknowledgement on the start write proceeds as the owner and releases nothing', async () => {
    const first = fixture({ operationId: 'operation:composed:rr1', replayId: 'native-mandate:composed:rr1' });
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    let loseAck = true;
    const releases = [];
    const release = aebStore.release.bind(aebStore);
    aebStore.release = async (key) => { releases.push(key); return release(key); };
    attempts.transition = async (entry) => {
        const answer = await transition(entry);
        if (loseAck && entry.next_state === 'INVOKING') {
            loseAck = false;
            throw new Error('acknowledgement lost');
        }
        return answer;
    };
    const h = makeComposedRace(first, attempts, aebStore);
    const result = await h.boundary.run(input(first));
    assert.equal(result.state, 'EXECUTED');
    assert.equal(h.calls(), 1);
    assert.deepEqual(releases, []);
    assert.equal(aebStore.operations.get(aebReservationKey(first.evaluation)), 'CONSUMED');
});
test('R6 N4 composed: recovery of one attempt never commits another attempt\'s evaluation reservation', async () => {
    const first = fixture({ operationId: 'operation:composed:r6', replayId: 'native-mandate:composed:r6' });
    const aebStore = durableAebStore();
    const attempts = attemptStore();
    let calls = 0;
    const atProvider = deferred();
    const providerGo = deferred();
    const h = makeComposedRace(first, attempts, aebStore, async () => {
        calls += 1;
        if (calls === 1)
            throw new Error('response lost');
        atProvider.resolve();
        await providerGo.promise;
        return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
    });
    const lost = await h.boundary.run(input(first));
    assert.equal(lost.reason, 'provider_outcome_indeterminate');
    const reservationKey = aebReservationKey(first.evaluation);
    const holder1 = consequenceBoundaryActionFenceHolderKey({ reservation_key: reservationKey, boundary_id: COMPOSED_BOUNDARY_ID, attempt_id: 'attempt:1' });
    // Simulate the round-2 defect that let this happen: attempt 1's holder and
    // R(E) handed back although its record says INDETERMINATE.
    assert.equal(await aebStore.release(holder1), true);
    assert.equal(await aebStore.release(reservationKey), true);
    const live = h.boundary.run(input(first));
    await atProvider.promise;
    assert.equal(aebStore.operations.get(reservationKey), 'RESERVED');
    const recovery = await h.boundary.reconcile(composedRecovery(first, lost.attempt, { state: 'FAILED', evidence: executedEvidence(), reason: 'declined' }));
    assert.equal(recovery.state, 'INDETERMINATE');
    assert.equal(recovery.reason, 'evaluation_reservation_not_owned');
    assert.equal(aebStore.operations.get(reservationKey), 'RESERVED');
    providerGo.resolve();
    const second = await live;
    assert.equal(second.state, 'EXECUTED');
    assert.equal(aebStore.operations.get(reservationKey), 'CONSUMED');
    assert.equal(calls, 2);
});
test('R8 N5 composed: a failed evaluation release after a pre-entry stop is not reported as a clean refusal', async () => {
    const first = fixture({ operationId: 'operation:composed:n5', replayId: 'native-mandate:composed:n5' });
    const aebStore = durableAebStore();
    const reservationKey = aebReservationKey(first.evaluation);
    const release = aebStore.release.bind(aebStore);
    let failEvaluationRelease = true;
    aebStore.release = async (key) => {
        if (failEvaluationRelease && key === reservationKey) {
            failEvaluationRelease = false;
            throw new Error('connection reset');
        }
        return release(key);
    };
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    let conflictOnce = true;
    attempts.transition = async (entry) => {
        if (conflictOnce && entry.next_state === 'INVOKING') {
            conflictOnce = false;
            return false;
        }
        return transition(entry);
    };
    const h = makeComposedRace(first, attempts, aebStore);
    const result = await h.boundary.run(input(first));
    assert.equal(result.state, 'INDETERMINATE');
    assert.equal(result.reason, 'evaluation_release_unconfirmed');
    assert.equal(result.invoked, false);
    assert.equal(h.calls(), 0);
    // The fence is open; a fresh evaluation proceeds.
    assert.equal((await h.boundary.run(input(composedFresh(first, 'n5-fresh')))).state, 'EXECUTED');
});
test('R3/R4 N6 composed: a truthy non-true start answer never counts as provider entry', async () => {
    const first = fixture({ operationId: 'operation:composed:n6', replayId: 'native-mandate:composed:n6' });
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    attempts.transition = async (entry) => (entry.next_state === 'INVOKING' ? { ok: false, reason: 'cas_conflict' } : transition(entry));
    const h = makeComposedRace(first, attempts);
    const result = await h.boundary.run(input(first));
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'attempt_start_conflict');
    assert.equal(h.calls(), 0);
    assert.equal([...attempts.rows.values()][0].state, 'RELEASED');
    assert.equal(h.aebStore.operations.size, 0);
    // The evaluation was handed back, so it may be presented again.
    assert.equal((await h.boundary.run(input(first))).reason, 'attempt_start_conflict');
    assert.equal(h.calls(), 0);
});
test('R8 composed: once pre-entry recovery linearizes first, the live run hands back the holder and R(E)', async () => {
    const first = fixture({ operationId: 'operation:composed:r8', replayId: 'native-mandate:composed:r8' });
    const attempts = racingAttemptStore(false);
    const h = makeComposedRace(first, attempts);
    const live = h.boundary.run(input(first));
    await attempts.liveArrived.promise;
    const row = [...attempts.rows.values()][0];
    const recovery = await h.boundary.reconcile(composedRecovery(first, structuredClone(row.binding), { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }, 'pre_entry'));
    assert.equal(recovery.reason, 'attempt_never_entered_provider');
    const result = await live;
    assert.equal(result.state, 'REFUSED');
    assert.equal(result.reason, 'attempt_released_by_recovery');
    assert.equal(h.aebStore.operations.size, 0);
    assert.equal(h.calls(), 0);
    assert.equal((await h.boundary.run(input(first))).state, 'EXECUTED');
});
test('R9 N9 composed: hostile run and reconcile input refuses with a reason and never throws', async () => {
    const first = fixture({ operationId: 'operation:composed:n9', replayId: 'native-mandate:composed:n9' });
    const h = makeComposedRace(first, attemptStore());
    const getter = (key, base) => Object.defineProperty({ ...base }, key, {
        get() { throw new Error('boom'); },
        enumerable: true,
    });
    for (const key of ['artifacts', 'current_statuses', 'additional_replay_keys', 'evaluation', 'action']) {
        const result = await h.boundary.run(getter(key, input(first)));
        assert.equal(result.state, 'REFUSED', key);
        assert.equal(result.reason, 'execution_input_invalid', key);
    }
    const revoked = Proxy.revocable({ ...input(first) }, {});
    revoked.revoke();
    assert.equal((await h.boundary.run(revoked.proxy)).reason, 'execution_input_invalid');
    assert.equal((await h.boundary.run({ ...input(first), additional_replay_keys: [7] })).reason, 'execution_input_invalid');
    assert.equal((await h.boundary.run(null)).reason, 'execution_input_invalid');
    const lostRun = makeComposedRace(first, attemptStore(), durableAebStore(), async () => { throw new Error('lost'); });
    const lost = await lostRun.boundary.run(input(first));
    assert.equal(lost.state, 'INDETERMINATE');
    const good = composedRecovery(first, lost.attempt, { state: 'FAILED', evidence: executedEvidence(), reason: 'x' });
    for (const key of ['outcome', 'artifacts', 'attempt', 'mode']) {
        const result = await lostRun.boundary.reconcile(getter(key, good));
        assert.equal(result.state, 'REFUSED', key);
        assert.equal(result.reason, 'reconciliation_input_invalid', key);
    }
    const revokedOutcome = Proxy.revocable({ ...good.outcome }, {});
    revokedOutcome.revoke();
    assert.equal((await lostRun.boundary.reconcile({ ...good, outcome: revokedOutcome.proxy })).reason, 'reconciliation_input_invalid');
    assert.equal((await lostRun.boundary.reconcile({ ...good, mode: 'both' })).reason, 'reconciliation_input_invalid');
    assert.equal((await lostRun.boundary.reconcile(null)).reason, 'reconciliation_input_invalid');
});
test('R9 N9 composed: a synchronous attempt store answering plain booleans never throws after provider entry', async () => {
    const first = fixture({ operationId: 'operation:composed:sync', replayId: 'native-mandate:composed:sync' });
    const base = attemptStore();
    const sync = {
        ...base,
        rows: base.rows,
        reserve: (binding) => {
            const owner = `owner:${crypto.randomBytes(24).toString('base64url')}`;
            base.rows.set(binding.attempt_id, { binding: structuredClone(binding), owner, state: 'RESERVED' });
            return { reserved: true, owner };
        },
        transition: (entry) => {
            const row = base.rows.get(entry.attempt_id);
            if (!row || row.owner !== entry.owner || row.state !== entry.expected_state)
                return false;
            row.state = entry.next_state;
            return true;
        },
        reconcile: (entry) => {
            const row = base.rows.get(entry.attempt_id);
            if (!row || row.owner !== entry.owner || row.state !== entry.expected_state)
                return false;
            row.state = entry.next_state;
            row.evidence = structuredClone(entry.evidence);
            return true;
        },
        state: (entry) => {
            const row = base.rows.get(entry.attempt_id);
            return { state: row.state, ...(row.evidence ? { evidence: structuredClone(row.evidence) } : {}) };
        },
    };
    const h = makeComposedRace(first, sync);
    const result = await h.boundary.run(input(first));
    assert.equal(result.state, 'EXECUTED');
    assert.equal(h.calls(), 1);
    assert.equal([...base.rows.values()][0].state, 'COMMITTED');
    // A store that throws synchronously after provider entry: the result is
    // INDETERMINATE with the attempt, never a thrown error.
    const second = composedFresh(first, 'sync-throw');
    const throwing = attemptStore();
    const throwingSync = {
        ...throwing,
        rows: throwing.rows,
        reconcile: () => { throw new Error('store exploded'); },
    };
    const g = makeComposedRace(second, throwingSync);
    const thrown = await g.boundary.run(input(second));
    assert.equal(thrown.state, 'INDETERMINATE');
    assert.equal(thrown.reason, 'attempt_terminal_record_unconfirmed');
    assert.equal(thrown.invoked, true);
    assert.ok(thrown.attempt);
});
test('R7: trailing-dot, slashless, and URN-case issuer aliases are refused at construction', () => {
    // Regression for N8: each alias below executed one grant twice.
    const cases = [
        ['https://authzen.example', 'https://authzen.example.'],
        ['https://authzen.example', 'https:authzen.example'],
        ['urn:example:issuer', 'URN:example:issuer'],
        ['urn:example:issuer', 'urn:EXAMPLE:issuer'],
    ];
    for (const [issuer, alias] of cases) {
        const f = nativeFixture();
        f.pins.accepted_sources[0].issuer = issuer;
        f.pins.accepted_sources.push({ ...f.pins.accepted_sources[0], profile: 'authzen:exact-action-result:2', issuer: alias });
        assert.throws(() => makeNativeBoundary({ f }), /native_consequence_boundary_configuration_invalid: native_pins_issuer_alias_without_shared_namespace/, alias);
    }
});
test('the native authority reservation also fences the verify 4.1.0 key: 0.26.0 spends and namespace rotations stay spent', async () => {
    {
        // A grant consumed by Gate 0.26.0 is recorded only under the 4.1.0 key.
        const f = nativeFixture();
        const aebStore = durableAebStore();
        aebStore.db.operations.set('aeb-native-operation:legacy-0.26.0-row', 'CONSUMED');
        aebStore.db.replayOwners.set(aebNativeAuthorizationReplayKey(f.handoff), 'aeb-native-operation:legacy-0.26.0-row');
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            aebStore,
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(1), result: {} }; },
        });
        const replayed = await h.boundary.run(nativeInput(f, 'operation:native:legacy-spent'));
        assert.equal(replayed.state, 'REFUSED');
        assert.equal(replayed.reason, 'native_replay_conflict');
        assert.equal(calls, 0);
    }
    {
        // C8: rotating a declared namespace changes the identity key, but the
        // 4.1.0 key does not depend on it, so a burned grant stays burned.
        const f = nativeFixture();
        const aebStore = durableAebStore();
        let calls = 0;
        const invoke = async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} }; };
        f.pins.accepted_sources[0].authority_namespace = 'namespace:before';
        const before = makeNativeBoundary({ f, aebStore, invoke });
        assert.equal((await before.boundary.run(nativeInput(f, 'operation:native:rotate:1'))).state, 'EXECUTED');
        f.pins.accepted_sources[0].authority_namespace = 'namespace:after';
        const other = { ...ACTION, transfer_id: 'transfer-rotated' };
        const after = makeNativeBoundary({ f, aebStore, invoke, attemptPrefix: 'rotated:' });
        const replayed = await after.boundary.run({
            operation_id: 'operation:native:rotate:2',
            handoff: issueNative(f, { action: other }),
            action: other,
        });
        assert.equal(replayed.state, 'REFUSED');
        assert.equal(replayed.reason, 'native_replay_conflict');
        assert.equal(calls, 1);
    }
});
// ---------------------------------------------------------------------------
// PR #790 round 4: the explicit not-entered marker (S1), verified terminal
// evidence on both boundaries (S2), legacy label fences (S3), and liveness
// residuals (S5). S4 store tests live in aeb-consumption-store.test.ts.
// ---------------------------------------------------------------------------
/** An attempt store that declares the marker but drops stored evidence from state(). */
function evidenceDroppingAttemptStore() {
    const attempts = attemptStore();
    const state = attempts.state.bind(attempts);
    attempts.state = async (entry) => {
        const { evidence: _dropped, ...rest } = await state(entry);
        return rest;
    };
    return attempts;
}
test('S1 NA9 native: a RELEASED record without the not-entered marker is never read as not entered, so one grant never enters twice', async () => {
    const f = nativeFixture();
    const attempts = evidenceDroppingAttemptStore();
    let calls = 0;
    const h = makeNativeBoundary({
        f,
        attempts,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => {
            calls += 1;
            return calls === 1
                ? { state: 'FAILED', evidence: providerOutcomeFor(calls), reason: 'provider_declined' }
                : { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
        },
    });
    const first = await h.boundary.run(nativeInput(f, 'operation:native:na9'));
    assert.equal(first.state, 'INDETERMINATE');
    assert.equal(first.reason, 'attempt_terminal_record_unconfirmed');
    const row = [...attempts.rows.values()][0];
    assert.equal(row.state, 'RELEASED');
    const terminal = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:na9', row.binding, { state: 'FAILED', evidence: providerOutcomeFor(1), reason: 'provider_declined' }, 'recovery:approved', 'terminal'));
    assert.equal(terminal.state, 'INDETERMINATE');
    assert.equal(terminal.reason, 'attempt_record_unproven');
    const preEntry = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:na9', row.binding, { state: 'FAILED', evidence: failedEvidence(9), reason: 'not_found' }));
    assert.equal(preEntry.state, 'INDETERMINATE');
    assert.equal(preEntry.reason, 'attempt_record_unproven');
    const keys = nativeConsequenceBoundaryAttemptReservationKeys({
        relying_party_id: f.pins.relying_party_id,
        provider: PROVIDER,
        operation_id: 'operation:native:na9',
        action_digest: row.binding.action_digest,
        boundary_id: NATIVE_BOUNDARY_ID,
        attempt_id: row.binding.attempt_id,
    });
    assert.equal(h.aebStore.state(keys.authority), 'RESERVED', 'the one-time authorization stays held');
    const again = await h.boundary.run(nativeInput(f, 'operation:native:na9:again'));
    assert.notEqual(again.state, 'EXECUTED');
    assert.equal(again.invoked, false);
    assert.equal(calls, 1);
});
test('S1 native: an attempt store that does not declare the not-entered marker is refused at construction', () => {
    const attempts = attemptStore();
    delete attempts.notEnteredMarker;
    assert.throws(() => makeNativeBoundary({ attempts }), /native_consequence_boundary_configuration_invalid/);
});
test('S1 native: a pre-entry stop whose marker was not stored holds its rows, and recovery cannot prove it', async () => {
    const f = nativeFixture();
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    // A store that applies RELEASED but drops the marker.
    attempts.transition = async (entry) => {
        const { evidence: _dropped, ...rest } = entry;
        const applied = await transition(rest);
        const row = attempts.rows.get(entry.attempt_id);
        if (applied && row && entry.next_state === 'RELEASED')
            delete row.evidence;
        return applied;
    };
    let lookups = 0;
    const h = makeNativeBoundary({
        f,
        attempts,
        // Revoked at provider entry: the attempt stops before the callback.
        resolveStatus: (handoff) => {
            lookups += 1;
            return { ...nativeStatusFor(f, handoff), revoked: lookups >= 2 };
        },
        invoke: async () => { throw new Error('never called'); },
    });
    const stopped = await h.boundary.run(nativeInput(f, 'operation:native:no-marker'));
    assert.equal(stopped.state, 'INDETERMINATE');
    assert.equal(stopped.reason, 'native_pre_entry_release_unconfirmed');
    assert.equal([...attempts.rows.values()][0].state, 'RELEASED');
    const recovered = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:no-marker', stopped.attempt, { state: 'FAILED', evidence: failedEvidence(31), reason: 'not_found' }));
    assert.equal(recovered.state, 'INDETERMINATE');
    assert.equal(recovered.reason, 'attempt_record_unproven');
    assert.equal([...h.aebStore.operations.values()].filter((value) => value === 'RESERVED').length, 3);
});
test('S1 CA9 composed: pre-entry recovery never calls an attempt that entered and FAILED "never entered"', async () => {
    {
        const f = fixture({ operationId: 'operation:composed:ca9', replayId: 'native-mandate:composed:ca9' });
        const attempts = evidenceDroppingAttemptStore();
        let calls = 0;
        const h = makeBoundary({
            f,
            attempts,
            invoke: async () => {
                calls += 1;
                return { state: 'FAILED', evidence: failedEvidence(4), reason: 'declined' };
            },
        });
        const first = await h.boundary.run(input(f));
        assert.equal(first.state, 'INDETERMINATE');
        assert.equal(first.reason, 'attempt_terminal_record_unconfirmed');
        const row = [...attempts.rows.values()][0];
        assert.equal(row.state, 'RELEASED');
        const holder = consequenceBoundaryActionFenceHolderKey({
            reservation_key: aebReservationKey(f.evaluation),
            boundary_id: COMPOSED_BOUNDARY_ID,
            attempt_id: row.binding.attempt_id,
        });
        for (const mode of ['pre_entry', 'terminal']) {
            const recovered = await h.boundary.reconcile(composedRecovery(f, row.binding, { state: 'FAILED', evidence: failedEvidence(5), reason: 'not_found' }, mode));
            assert.equal(recovered.state, 'INDETERMINATE', mode);
            assert.equal(recovered.reason, 'attempt_record_unproven', mode);
        }
        assert.equal(h.aebStore.state(holder), 'RESERVED');
        assert.equal(h.aebStore.state(aebReservationKey(f.evaluation)), 'RESERVED');
        assert.equal(calls, 1);
    }
    {
        // An attempt store written for 0.26.0 (state() but no marker declaration)
        // is used without reads, as 0.26.0 used it: recovery needs its own
        // acknowledged RESERVED -> RELEASED, which a terminal record refuses.
        const f = fixture({ operationId: 'operation:composed:ca9-legacy', replayId: 'native-mandate:composed:ca9-legacy' });
        const attempts = attemptStore();
        delete attempts.notEnteredMarker;
        const h = makeBoundary({
            f,
            attempts,
            invoke: async () => ({ state: 'FAILED', evidence: failedEvidence(6), reason: 'declined' }),
        });
        const first = await h.boundary.run(input(f));
        assert.equal(first.state, 'FAILED');
        const row = [...attempts.rows.values()][0];
        const recovered = await h.boundary.reconcile(composedRecovery(f, row.binding, { state: 'FAILED', evidence: failedEvidence(7), reason: 'not_found' }, 'pre_entry'));
        assert.equal(recovered.state, 'INDETERMINATE');
        assert.equal(recovered.reason, 'attempt_release_unconfirmed');
    }
});
test('S2 N1c composed: terminal reconciliation needs a verifier that affirms the terminal purpose; a live call stays fenced', async () => {
    // T2: a composed boundary without a provider-outcome verifier is refused
    // at construction, exactly like the native boundary.
    assert.throws(() => makeBoundary({ providerOutcomeVerify: null }), /^TypeError: consequence_boundary_configuration_invalid: provider_outcome_verifier_required$/);
    for (const verifier of ['purpose-honoring', 'always-true']) {
        const f = fixture({
            operationId: `operation:composed:n1c:${verifier}`,
            replayId: `native-mandate:composed:n1c:${verifier}`,
        });
        const atProvider = deferred();
        const providerGo = deferred();
        let calls = 0;
        const h = makeBoundary({
            f,
            providerOutcomeVerify: verifier === 'always-true'
                ? () => true
                : (context) => (context.purpose === 'provider_outcome'
                    && context.outcome.evidence.evidence_id === executedEvidence().evidence_id)
                    ? affirm(context)
                    : false,
            invoke: async () => {
                calls += 1;
                if (calls === 1) {
                    atProvider.resolve();
                    await providerGo.promise;
                }
                return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        const live = h.boundary.run(input(f));
        await atProvider.promise;
        const row = [...h.attempts.rows.values()][0];
        const misuse = await h.boundary.reconcile(composedRecovery(f, row.binding, { state: 'FAILED', evidence: failedEvidence(3), reason: 'not_found' }, 'terminal'));
        assert.equal(misuse.state, 'INDETERMINATE', verifier);
        assert.equal(misuse.reason, 'provider_outcome_authentication_failed', verifier);
        assert.equal(row.state, 'INVOKING', verifier);
        const fresh = await h.boundary.run(input(composedFresh(f, `n1c-${verifier}`)));
        assert.equal(fresh.reason, 'native_action_in_flight', verifier);
        providerGo.resolve();
        const result = await live;
        // A plain `true` is never an affirmation, even for the provider's own result.
        assert.equal(result.state, verifier === 'always-true' ? 'INDETERMINATE' : 'EXECUTED', verifier);
        assert.equal(calls, 1, verifier);
    }
});
test('S2 N1b native: only an affirmation of the exact purpose, attempt, and key counts; a plain true never closes a live attempt', async () => {
    {
        const f = nativeFixture();
        const atProvider = deferred();
        const providerGo = deferred();
        let calls = 0;
        const contexts = [];
        const h = makeNativeBoundary({
            f,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            providerOutcomeVerify: (context) => { contexts.push(context); return true; },
            invoke: async () => {
                calls += 1;
                if (calls === 1) {
                    atProvider.resolve();
                    await providerGo.promise;
                }
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const live = h.boundary.run(nativeInput(f, 'operation:native:n1b-true'));
        await atProvider.promise;
        const row = [...h.attempts.rows.values()][0];
        const misuse = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:n1b-true', row.binding, { state: 'FAILED', evidence: failedEvidence(2), reason: 'not_found' }, 'recovery:approved', 'terminal'));
        assert.equal(misuse.state, 'INDETERMINATE');
        assert.equal(misuse.reason, 'provider_outcome_authentication_failed');
        assert.equal(row.state, 'INVOKING', 'verified before any freeze');
        const fresh = await h.boundary.run({
            operation_id: 'operation:native:n1b-true:fresh',
            handoff: freshAuthorization(f, 'n1b-true-fresh'),
            action: ACTION,
        });
        assert.equal(fresh.reason, 'native_action_in_flight');
        providerGo.resolve();
        const result = await live;
        assert.equal(result.state, 'INDETERMINATE');
        assert.equal(result.reason, 'provider_outcome_authentication_failed');
        assert.equal(calls, 1);
        assert.ok(contexts.every((context) => context.provider_idempotency_key
            === context.attempt.provider_idempotency_key));
        assert.deepEqual([...new Set(contexts.map((context) => context.purpose))], ['provider_outcome']);
    }
    for (const [label, answer] of [
        ['wrong purpose', (context) => ({ ...affirm(context), purpose: 'pre_entry_lookup' })],
        ['other attempt', (context) => ({ ...affirm(context), attempt_id: 'native-attempt:other' })],
        ['other key', (context) => ({ ...affirm(context), provider_idempotency_key: 'epnb1:other' })],
        ['extra member', (context) => ({ ...affirm(context), note: 'extra' })],
        ['string verified', (context) => ({ ...affirm(context), verified: 'true' })],
        ['truthy object', () => ({ ok: true })],
    ]) {
        const f = nativeFixture();
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            providerOutcomeVerify: answer,
            invoke: async () => {
                calls += 1;
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const result = await h.boundary.run(nativeInput(f, 'operation:native:affirmation'));
        assert.equal(result.state, 'INDETERMINATE', label);
        assert.equal(result.reason, 'provider_outcome_authentication_failed', label);
        assert.equal(calls, 1, label);
    }
});
test('S3 native: a grant consumed by Gate 0.26.0 under one pinned label is refused under every other pinned label of its namespace', async () => {
    const labelFor = (f) => ({
        ...f.handoffInput.native_authorization,
        profile: 'authzen:exact-action-result:2',
    });
    const pinLabel = (f) => {
        f.pins.accepted_sources.push({ ...f.pins.accepted_sources[0], profile: labelFor(f).profile });
    };
    {
        // Gate 0.26.0 recorded the spend under label A's 4.1.0 key only.
        const f = nativeFixture();
        pinLabel(f);
        const aebStore = durableAebStore();
        aebStore.db.operations.set('aeb-native-operation:legacy-0.26.0-label-a', 'CONSUMED');
        aebStore.db.replayOwners.set(aebNativeAuthorizationReplayKey(f.handoff), 'aeb-native-operation:legacy-0.26.0-label-a');
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            aebStore,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} }; },
        });
        const relabelled = await h.boundary.run({
            operation_id: 'operation:native:s3',
            handoff: issueNative(f, { native_authorization: labelFor(f) }),
            action: ACTION,
        });
        assert.equal(relabelled.state, 'REFUSED');
        assert.equal(relabelled.reason, 'native_replay_conflict');
        assert.equal(calls, 0);
    }
    {
        // The reverse: a grant this Gate consumes under label A also fences label
        // B's 4.1.0 key, which is the only key a 0.26.0 replica checks.
        const f = nativeFixture();
        pinLabel(f);
        const h = makeNativeBoundary({
            f,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        });
        assert.equal((await h.boundary.run(nativeInput(f, 'operation:native:s3-reverse'))).state, 'EXECUTED');
        const labelB = issueNative(f, { native_authorization: labelFor(f) });
        assert.ok(h.aebStore.replayOwners.has(aebNativeAuthorizationReplayKey(labelB)));
        assert.ok(h.aebStore.replayOwners.has(aebNativeAuthorizationReplayKey(f.handoff)));
    }
});
test('S5a CA7 composed: a refusal before the attempt record is INDETERMINATE when the evaluation release is unconfirmed', async () => {
    for (const path of ['reserve-refused', 'reserve-throws', 'allocation-fails']) {
        for (const releaseWorks of [false, true]) {
            const label = `${path}:${releaseWorks ? 'released' : 'release-lost'}`;
            const f = fixture({ operationId: `operation:composed:ca7:${label}`, replayId: `native-mandate:ca7:${label}` });
            const aebStore = durableAebStore();
            const release = aebStore.release.bind(aebStore);
            aebStore.release = async (key) => {
                if (!releaseWorks && key.startsWith('aeb:'))
                    throw new Error('release lost');
                return release(key);
            };
            const attempts = attemptStore();
            if (path === 'reserve-refused') {
                attempts.reserve = async () => ({ reserved: false, reason: 'attempt_exists' });
            }
            if (path === 'reserve-throws') {
                attempts.reserve = async () => { throw new Error('attempt store down'); };
            }
            let calls = 0;
            const h = makeBoundary({
                f,
                aebStore,
                attempts,
                ...(path === 'allocation-fails' ? { createId: () => { throw new Error('id service down'); } } : {}),
                invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: executedEvidence(), result: {} }; },
            });
            const result = await h.boundary.run(input(f));
            const evaluationState = aebStore.state(aebReservationKey(f.evaluation));
            if (releaseWorks) {
                assert.equal(result.state, 'REFUSED', label);
                assert.equal(evaluationState, 'AVAILABLE', label);
            }
            else {
                assert.equal(result.state, 'INDETERMINATE', label);
                assert.equal(result.reason, 'evaluation_release_unconfirmed', label);
                assert.equal(result.invoked, false, label);
                assert.equal(evaluationState, 'RESERVED', label);
            }
            assert.equal(calls, 0, label);
        }
    }
});
test('S5b CA8 composed: an evaluation reservation that lands with a lost acknowledgement is INDETERMINATE, not a clean refusal', async () => {
    for (const applied of [true, false]) {
        const f = fixture({
            operationId: `operation:composed:ca8:${applied}`,
            replayId: `native-mandate:ca8:${applied}`,
        });
        const aebStore = durableAebStore();
        const reserve = aebStore.reserve.bind(aebStore);
        let armed = true;
        aebStore.reserve = async (key, fences) => {
            if (armed && key.startsWith('aeb:')) {
                armed = false;
                if (applied)
                    await reserve(key, fences);
                throw new Error('acknowledgement lost');
            }
            return reserve(key, fences);
        };
        let calls = 0;
        const h = makeBoundary({
            f,
            aebStore,
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: executedEvidence(), result: {} }; },
        });
        const result = await h.boundary.run(input(f));
        if (applied) {
            assert.equal(result.state, 'INDETERMINATE');
            assert.equal(result.reason, 'consumption_reservation_unconfirmed');
            assert.equal(aebStore.state(aebReservationKey(f.evaluation)), 'RESERVED');
        }
        else {
            // T6: an AVAILABLE read after a reserve that threw is not proof that
            // nothing was reserved, so this is INDETERMINATE too.
            assert.equal(result.state, 'INDETERMINATE');
            assert.equal(result.reason, 'consumption_reservation_unconfirmed');
            assert.equal(aebStore.state(aebReservationKey(f.evaluation)), 'AVAILABLE');
        }
        assert.equal(calls, 0);
    }
});
test('S5d native: a recovery whose claim loses to the live run handing back its own rows counts them as released', async () => {
    const f = nativeFixture();
    const db = durableAebDatabase();
    const liveStore = durableAebStore(db);
    const recoveryStore = durableAebStore(db);
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    const arrived = deferred();
    const go = deferred();
    let armed = true;
    attempts.transition = async (entry) => {
        if (armed && entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
            armed = false;
            arrived.resolve();
            await go.promise;
        }
        return transition(entry);
    };
    let calls = 0;
    const live = makeNativeBoundary({
        f,
        aebStore: liveStore,
        attempts,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} }; },
    });
    const liveRun = live.boundary.run(nativeInput(f, 'operation:native:s5d'));
    await arrived.promise;
    // The claim runs only after the live run, now refused by the recovery's
    // RESERVED -> RELEASED, has deleted its own rows.
    const claim = recoveryStore.claimReservation.bind(recoveryStore);
    recoveryStore.claimReservation = async (...args) => {
        go.resolve();
        await liveRun;
        return claim(...args);
    };
    const recovery = makeNativeBoundary({
        f,
        aebStore: recoveryStore,
        attempts,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        attemptPrefix: 'recovery:',
    });
    const row = [...attempts.rows.values()][0];
    const recovered = await recovery.boundary.reconcile(nativeRecovery(f, 'operation:native:s5d', row.binding, { state: 'FAILED', evidence: failedEvidence(55), reason: 'not_found' }));
    assert.equal(recovered.state, 'REFUSED');
    assert.equal(recovered.reason, 'attempt_never_entered_provider');
    const liveResult = await liveRun;
    assert.equal(liveResult.state, 'REFUSED');
    assert.equal(liveResult.reason, 'attempt_released_by_recovery');
    assert.equal(db.operations.size, 0);
    assert.equal(calls, 0);
});
test('S6 native: did:web host case and spiffe trust-domain case are issuer aliases', () => {
    for (const [label, issuers] of [
        ['did:web host case', ['did:web:authzen.example', 'did:web:AUTHZEN.example']],
        ['did:web trailing dot with path', ['did:web:authzen.example:user:pay', 'did:web:Authzen.Example.:user:pay']],
        ['spiffe trust-domain case', ['spiffe://authzen.example/ns/pay', 'spiffe://AUTHZEN.example/ns/pay']],
    ]) {
        const f = nativeFixture();
        f.pins.accepted_sources = issuers.map((issuer, index) => ({
            ...f.pins.accepted_sources[0],
            profile: `authzen:exact-action-result:${index + 1}`,
            issuer,
        }));
        assert.throws(() => makeNativeBoundary({ f }), /native_pins_issuer_alias_without_shared_namespace/, label);
        for (const source of f.pins.accepted_sources)
            source.authority_namespace = 'namespace:authzen';
        assert.doesNotThrow(() => makeNativeBoundary({ f }), label);
    }
});
test('S5d native: a recovery whose claim another recovery overtakes claims again instead of reporting unconfirmed', async () => {
    const f = nativeFixture();
    const db = durableAebDatabase();
    const crashedStore = durableAebStore(db);
    const attempts = attemptStore();
    const transition = attempts.transition.bind(attempts);
    let crashed = false;
    attempts.transition = async (entry) => {
        if (!crashed && entry.expected_state === 'RESERVED' && entry.next_state === 'INVOKING') {
            crashed = true;
            return new Promise(() => { });
        }
        return transition(entry);
    };
    const live = makeNativeBoundary({
        f,
        aebStore: crashedStore,
        attempts,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
    });
    void live.boundary.run(nativeInput(f, 'operation:native:s5d-overtaken'));
    while (!crashed)
        await new Promise((done) => setImmediate(done));
    // A second recovery instance takes each row right after this one claims it,
    // once, the way two concurrent recoveries rotate one row's owner token.
    const competitor = durableAebStore(db);
    const recoveryStore = durableAebStore(db);
    const claim = recoveryStore.claimReservation.bind(recoveryStore);
    const overtaken = new Set();
    recoveryStore.claimReservation = async (key, authorization, scope) => {
        const claimed = await claim(key, authorization, scope);
        if (claimed && !overtaken.has(key)) {
            overtaken.add(key);
            await competitor.claimReservation(key, authorization, scope);
        }
        return claimed;
    };
    const recovery = makeNativeBoundary({
        f,
        aebStore: recoveryStore,
        attempts,
        resolveStatus: (handoff) => nativeStatusFor(f, handoff),
        attemptPrefix: 'recovery:',
    });
    const row = [...attempts.rows.values()][0];
    const recovered = await recovery.boundary.reconcile(nativeRecovery(f, 'operation:native:s5d-overtaken', row.binding, { state: 'FAILED', evidence: failedEvidence(56), reason: 'not_found' }));
    assert.equal(recovered.state, 'REFUSED');
    assert.equal(recovered.reason, 'attempt_never_entered_provider');
    assert.equal(overtaken.size, 3);
    assert.equal(db.operations.size, 0);
});
// ---------------------------------------------------------------------------
// Round five (T1-T6).
// ---------------------------------------------------------------------------
/** Honors purpose: a "not found" lookup is accepted only as a pre-entry lookup. */
function strictVerify(context) {
    if (context.outcome.reason === 'not_found' && context.purpose !== 'pre_entry_lookup')
        return false;
    return affirm(context);
}
test('T2 CX6 composed: run() never releases the fence on an adapter FAILED the verifier does not affirm', async () => {
    // Port of the round-4 CX6 probe: an adapter maps a timeout on a call the
    // provider committed to FAILED. Round 4 without a verifier released the
    // holder and R(E), and a fresh evaluation executed a second time.
    const f = fixture({ operationId: 'operation:composed:cx6', replayId: 'native-mandate:composed:cx6' });
    let effects = 0;
    let verified = 0;
    const h = makeBoundary({
        f,
        providerOutcomeVerify: (context) => {
            verified += 1;
            // Authenticates provider-issued evidence only; the adapter's own
            // "timeout mapped to FAILED" is not provider evidence.
            return String(context.outcome.evidence.evidence_id).startsWith('provider-evidence:')
                ? strictVerify(context)
                : false;
        },
        invoke: async () => {
            effects += 1;
            return effects === 1
                ? {
                    state: 'FAILED',
                    evidence: { ...failedEvidence(1), evidence_id: 'adapter:timeout-mapped-to-failed' },
                    reason: 'provider_timeout',
                }
                : { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
        },
    });
    const run = await h.boundary.run(input(f));
    assert.deepEqual([run.state, run.reason, run.invoked], ['INDETERMINATE', 'provider_outcome_authentication_failed', true]);
    assert.equal(verified, 1);
    const row = [...h.attempts.rows.values()][0];
    assert.equal(row.state, 'INDETERMINATE');
    const fresh = await h.boundary.run(input(composedFresh(f, 'cx6-fresh')));
    assert.equal(fresh.reason, 'native_action_in_flight');
    assert.equal(effects, 1);
    // Construction without the verifier is refused, so this path cannot be
    // configured away.
    assert.throws(() => createConsequenceBoundary({
        executor_id: EXECUTOR,
        boundary_id: COMPOSED_BOUNDARY_ID,
        provider: PROVIDER,
        aeb: { config: f.config, adapters: f.adapters, store: durableAebStore() },
        attempts: { store: attemptStore(), recover: () => null },
        local_authorize: () => true,
        invoke: async () => ({ state: 'INDETERMINATE', reason: 'x' }),
    }), /provider_outcome_verifier_required/);
});
test('T3 NX3/CX3: an echo verifier cannot turn a lookup labelled pre_entry_lookup into a terminal FAILED', async () => {
    // Port of the round-4 NX3 and CX3 probes. The verifier restates whatever
    // context it is given. The operator labels the "not found" lookup
    // correctly, so terminal reconciliation refuses it before the verifier.
    const echo = (context) => affirm(context);
    {
        const f = nativeFixture();
        const atProvider = deferred();
        const providerGo = deferred();
        let calls = 0;
        let verifierCalls = 0;
        const h = makeNativeBoundary({
            f,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            providerOutcomeVerify: (context) => { verifierCalls += 1; return echo(context); },
            invoke: async () => {
                calls += 1;
                if (calls === 1) {
                    atProvider.resolve();
                    await providerGo.promise;
                }
                return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} };
            },
        });
        const live = h.boundary.run(nativeInput(f, 'operation:native:nx3'));
        await atProvider.promise;
        const row = [...h.attempts.rows.values()][0];
        const lookup = { state: 'FAILED', evidence_kind: 'pre_entry_lookup', evidence: failedEvidence(3), reason: 'not_found' };
        const terminal = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:nx3', structuredClone(row.binding), lookup, 'recovery:approved', 'terminal'));
        assert.deepEqual([terminal.state, terminal.reason], ['REFUSED', 'evidence_kind_mismatch']);
        assert.equal(verifierCalls, 0, 'refused before the verifier');
        assert.equal(row.state, 'INVOKING');
        // An unlabelled outcome is refused too, before the verifier.
        const { evidence_kind: _kind, ...unlabelled } = lookup;
        const bare = await h.boundary.reconcile({
            ...nativeRecovery(f, 'operation:native:nx3', structuredClone(row.binding), null, 'recovery:approved', 'terminal'),
            outcome: unlabelled,
        });
        assert.deepEqual([bare.state, bare.reason], ['REFUSED', 'evidence_kind_required']);
        const fresh = await h.boundary.run({
            operation_id: 'operation:native:nx3:fresh',
            handoff: freshAuthorization(f, 'nx3'),
            action: ACTION,
        });
        assert.equal(fresh.reason, 'native_action_in_flight');
        providerGo.resolve();
        assert.equal((await live).state, 'EXECUTED');
        // Pre-entry recovery refuses a provider outcome the same way.
        const preEntry = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:nx3', structuredClone(row.binding), { state: 'FAILED', evidence_kind: 'provider_outcome', evidence: failedEvidence(3), reason: 'not_found' }));
        assert.deepEqual([preEntry.state, preEntry.reason], ['REFUSED', 'evidence_kind_mismatch']);
        assert.equal(verifierCalls, 1, 'only the live run\'s own result reached the verifier');
        assert.equal(calls, 1);
    }
    {
        const f = fixture({ operationId: 'operation:composed:cx3', replayId: 'native-mandate:composed:cx3' });
        const atProvider = deferred();
        const providerGo = deferred();
        let calls = 0;
        let verifierCalls = 0;
        const h = makeBoundary({
            f,
            providerOutcomeVerify: (context) => { verifierCalls += 1; return echo(context); },
            invoke: async () => {
                calls += 1;
                if (calls === 1) {
                    atProvider.resolve();
                    await providerGo.promise;
                }
                return { state: 'EXECUTED', evidence: executedEvidence(), result: {} };
            },
        });
        const live = h.boundary.run(input(f));
        await atProvider.promise;
        const row = [...h.attempts.rows.values()][0];
        const terminal = await h.boundary.reconcile(composedRecovery(f, row.binding, { state: 'FAILED', evidence_kind: 'pre_entry_lookup', evidence: failedEvidence(4), reason: 'not_found' }, 'terminal'));
        assert.deepEqual([terminal.state, terminal.reason], ['REFUSED', 'evidence_kind_mismatch']);
        const bare = await h.boundary.reconcile({
            ...composedRecovery(f, row.binding, null, 'terminal'),
            outcome: { state: 'FAILED', evidence: failedEvidence(4), reason: 'not_found' },
        });
        assert.deepEqual([bare.state, bare.reason], ['REFUSED', 'evidence_kind_required']);
        const unknownKind = await h.boundary.reconcile({
            ...composedRecovery(f, row.binding, null, 'terminal'),
            outcome: { state: 'FAILED', evidence_kind: 'lookup', evidence: failedEvidence(4), reason: 'not_found' },
        });
        assert.deepEqual([unknownKind.state, unknownKind.reason], ['REFUSED', 'evidence_kind_required']);
        assert.equal(verifierCalls, 0);
        assert.equal(row.state, 'INVOKING');
        const fresh = await h.boundary.run(input(composedFresh(f, 'cx3-fresh')));
        assert.equal(fresh.reason, 'native_action_in_flight');
        providerGo.resolve();
        assert.equal((await live).state, 'EXECUTED');
        assert.equal(calls, 1);
    }
});
test('T4 PG4c (memory): two native boundaries on one store that reuse an attempt ID never share a row or a credential', async () => {
    // Port of the round-4 PG4c probe with the PostgreSQL store's authorizer
    // contract: a credential bound to the attempt identity. N1's attempt X
    // crashed; N2's attempt X is live at the provider on another action.
    const db = durableAebDatabase();
    const credentialFor = new Map();
    const claims = [];
    const authorize = ({ key, authorization, scope }) => {
        const identity = consequenceBoundaryRecoveryAttemptIdentity(scope);
        const granted = identity !== null
            && consequenceBoundaryRecoveryClaimKey(scope) === key
            && credentialFor.get(String(authorization)) === identity;
        claims.push({ identity, granted });
        return granted;
    };
    const sharedId = 'native-attempt:same-kind:X';
    const f1 = nativeFixture();
    const f2 = nativeFixture();
    const otherAction = { ...ACTION, transfer_id: 'transfer-n2' };
    // Another grant (its own authorization ID) for another action.
    const handoff2 = issueNative(f2, {
        action: otherAction,
        native_authorization: { ...f2.handoffInput.native_authorization, authorization_id: 'native-authz:pg4c:n2' },
        revocation_id: 'revocation:pg4c:n2',
    });
    let n2Calls = 0;
    let n2Ids = 0;
    const n2Go = deferred();
    const n2At = deferred();
    const n1 = makeNativeBoundary({
        f: f1,
        aebStore: durableAebStore(db, authorize),
        boundaryId: 'native-boundary-n1',
        createId: () => sharedId,
        resolveStatus: (handoff) => nativeStatusFor(f1, handoff),
        invoke: async () => ({ state: 'INDETERMINATE', reason: 'provider_timeout' }),
    });
    const n2 = makeNativeBoundary({
        f: f2,
        aebStore: durableAebStore(db, authorize),
        boundaryId: 'native-boundary-n2',
        createId: () => (++n2Ids === 1 ? sharedId : `native-attempt:n2:${n2Ids}`),
        resolveStatus: (handoff) => nativeStatusFor(f2, handoff),
        invoke: async () => {
            n2Calls += 1;
            if (n2Calls === 1) {
                n2At.resolve();
                await n2Go.promise;
            }
            return { state: 'EXECUTED', evidence: providerOutcomeFor(n2Calls), result: {} };
        },
    });
    const crashed = await n1.boundary.run(nativeInput(f1, 'operation:pg4c:n1'));
    assert.equal(crashed.reason, 'provider_timeout');
    const live = n2.boundary.run({ operation_id: 'operation:pg4c:n2', handoff: handoff2, action: otherAction });
    await n2At.promise;
    const n1Keys = nativeConsequenceBoundaryAttemptReservationKeys({
        relying_party_id: f1.pins.relying_party_id,
        provider: PROVIDER,
        operation_id: 'operation:pg4c:n1',
        action_digest: digestAebNativeAuthorizationAction(ACTION),
        boundary_id: 'native-boundary-n1',
        attempt_id: sharedId,
    });
    const n2Keys = nativeConsequenceBoundaryAttemptReservationKeys({
        relying_party_id: f2.pins.relying_party_id,
        provider: PROVIDER,
        operation_id: 'operation:pg4c:n2',
        action_digest: digestAebNativeAuthorizationAction(otherAction),
        boundary_id: 'native-boundary-n2',
        attempt_id: sharedId,
    });
    assert.notEqual(n1Keys.holder, n2Keys.holder);
    const n1Scope = (reservation) => ({
        boundary: 'native', boundaryId: 'native-boundary-n1', attemptId: sharedId,
        operationId: 'operation:pg4c:n1', recoveryOperationKey: n1Keys.operation_fence, reservation,
    });
    const n2Scope = (reservation) => ({
        boundary: 'native', boundaryId: 'native-boundary-n2', attemptId: sharedId,
        operationId: 'operation:pg4c:n2', recoveryOperationKey: n2Keys.operation_fence, reservation,
    });
    // The operator of N1 holds a credential bound to N1's attempt identity.
    const n1Identity = consequenceBoundaryRecoveryAttemptIdentity(n1Scope('action-fence-holder'));
    assert.equal(n1Identity, `native:native-boundary-n1:${sharedId}`);
    credentialFor.set('credential:n1:X', n1Identity);
    const attacker = durableAebStore(db, authorize);
    // With N2's scope the identity differs; with N1's scope the key differs.
    assert.equal(await attacker.claimReservation(n2Keys.holder, 'credential:n1:X', n2Scope('action-fence-holder')), false);
    assert.equal(await attacker.claimReservation(n2Keys.holder, 'credential:n1:X', n1Scope('action-fence-holder')), false);
    assert.equal(db.operations.get(n2Keys.holder), 'RESERVED');
    const fresh = await n2.boundary.run({
        operation_id: 'operation:pg4c:n2:fresh',
        handoff: issueNative(f2, {
            action: otherAction,
            native_authorization: { ...f2.handoffInput.native_authorization, authorization_id: 'native-authz:pg4c:fresh' },
            revocation_id: 'revocation:pg4c:fresh',
        }),
        action: otherAction,
    });
    assert.equal(fresh.reason, 'native_action_in_flight');
    // N1's own credential still recovers N1's attempt, and only N1's rows.
    const n1Recovered = durableAebStore(db, authorize);
    assert.equal(await n1Recovered.claimReservation(n1Keys.holder, 'credential:n1:X', n1Scope('action-fence-holder')), true);
    n2Go.resolve();
    assert.equal((await live).state, 'EXECUTED');
    assert.equal(n2Calls, 1);
    assert.deepEqual(claims.map((claim) => claim.granted), [false, false, true]);
});
test('T4: a boundary ID outside the grammar is refused at construction on both boundaries', () => {
    for (const bad of [null, '', 'has:colon', 'has space', '-lead', 'x'.repeat(129), 7]) {
        assert.throws(() => makeNativeBoundary({ boundaryId: bad }), /^TypeError: native_consequence_boundary_configuration_invalid: boundary_id_invalid$/, String(bad));
        assert.throws(() => makeBoundary({ boundaryId: bad }), /^TypeError: consequence_boundary_configuration_invalid: boundary_id_invalid$/, String(bad));
    }
    // A missing boundary ID is refused the same way.
    const { configuration } = makeNativeBoundary();
    const { boundary_id: _missing, ...withoutBoundaryId } = configuration;
    assert.throws(() => createNativeConsequenceBoundary(withoutBoundaryId), /^TypeError: native_consequence_boundary_configuration_invalid: boundary_id_invalid$/);
    // A native boundary without a verifier names the missing verifier.
    const { provider_outcomes: _verifier, ...withoutVerifier } = configuration;
    assert.throws(() => createNativeConsequenceBoundary(withoutVerifier), /^TypeError: native_consequence_boundary_configuration_invalid: provider_outcome_verifier_required$/);
    assert.equal(makeNativeBoundary({ boundaryId: 'a' }).boundary.boundary_id, 'a');
    assert.equal(makeBoundary({ boundaryId: 'Zz_9.-' }).boundary.boundary_id, 'Zz_9.-');
});
test('T6 native: an unknown reserve answer is resolved by a durable read and is never a clean refusal', async () => {
    const unknownAnswers = [
        ['applied, truthy object', async (apply) => { await apply(); return { ok: true }; }],
        ['applied, 1', async (apply) => { await apply(); return 1; }],
        ['applied, ack lost', async (apply) => { await apply(); throw new Error('ack lost'); }],
        ['not applied, undefined', async () => undefined],
        ['not applied, throw', async () => { throw new Error('down'); }],
    ];
    for (const target of ['aeb-native-attempt-operation:', 'aeb-native-attempt-authority:', 'aeb-native-action-holder:']) {
        for (const [label, answer] of unknownAnswers) {
            const f = nativeFixture();
            const aebStore = durableAebStore();
            const reserve = aebStore.reserve.bind(aebStore);
            let armed = true;
            aebStore.reserve = async (key, fences) => {
                if (armed && key.startsWith(target)) {
                    armed = false;
                    return answer(() => reserve(key, fences));
                }
                return reserve(key, fences);
            };
            let calls = 0;
            const h = makeNativeBoundary({
                f,
                aebStore,
                resolveStatus: (handoff) => nativeStatusFor(f, handoff),
                invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} }; },
            });
            const tag = `${target}${label}`.replace(/[^A-Za-z0-9]+/g, '-');
            const result = await h.boundary.run(nativeInput(f, `operation:native:t6:${tag}`));
            const at = `${target} ${label}`;
            assert.deepEqual([result.state, result.reason, result.invoked], ['INDETERMINATE', 'consumption_reservation_unconfirmed', false], at);
            const row = [...h.attempts.rows.values()][0];
            assert.equal(row.state, 'RELEASED', at);
            assert.deepEqual(row.evidence, { kind: 'not_entered', attempt_id: row.binding.attempt_id }, at);
            assert.equal([...aebStore.operations.values()].filter((state) => state === 'RESERVED').length, 0, at);
            const fresh = await h.boundary.run({
                operation_id: `operation:native:t6:fresh:${tag}`,
                handoff: freshAuthorization(f, `t6-${tag}`),
                action: ACTION,
            });
            assert.equal(fresh.state, 'EXECUTED', at);
            assert.equal(calls, 1, at);
        }
    }
    // A write that lands after the run released everything is recovered by
    // pre-entry recovery: the attempt record carries the not-entered marker.
    {
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const reserve = aebStore.reserve.bind(aebStore);
        let pending = null;
        aebStore.reserve = async (key, fences) => {
            if (!pending && key.startsWith('aeb-native-action-holder:')) {
                pending = () => reserve(key, fences);
                throw new Error('query timeout');
            }
            return reserve(key, fences);
        };
        let calls = 0;
        const h = makeNativeBoundary({
            f,
            aebStore,
            resolveStatus: (handoff) => nativeStatusFor(f, handoff),
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: providerOutcomeFor(calls), result: {} }; },
        });
        const result = await h.boundary.run(nativeInput(f, 'operation:native:t6:delayed'));
        assert.deepEqual([result.state, result.reason], ['INDETERMINATE', 'consumption_reservation_unconfirmed']);
        await pending();
        const fenced = await h.boundary.run({
            operation_id: 'operation:native:t6:delayed:fresh',
            handoff: freshAuthorization(f, 't6-delayed'),
            action: ACTION,
        });
        assert.equal(fenced.reason, 'native_action_in_flight');
        const recovered = await h.boundary.reconcile(nativeRecovery(f, 'operation:native:t6:delayed', result.attempt, { state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' }));
        assert.deepEqual([recovered.state, recovered.reason], ['REFUSED', 'attempt_never_entered_provider']);
        const fresh = await h.boundary.run({
            operation_id: 'operation:native:t6:delayed:fresh-2',
            handoff: freshAuthorization(f, 't6-delayed-2'),
            action: ACTION,
        });
        assert.equal(fresh.state, 'EXECUTED');
        assert.equal(calls, 1);
    }
    // Defined conflicts stay clean refusals.
    {
        const f = nativeFixture();
        const aebStore = durableAebStore();
        const h = makeNativeBoundary({ f, aebStore, resolveStatus: (handoff) => nativeStatusFor(f, handoff) });
        assert.equal((await h.boundary.run(nativeInput(f, 'operation:native:t6:defined'))).state, 'EXECUTED');
        const replay = await h.boundary.run(nativeInput(f, 'operation:native:t6:defined:2'));
        assert.deepEqual([replay.state, replay.reason], ['REFUSED', 'native_replay_conflict']);
    }
});
test('T6 composed: an unknown action-fence holder answer is never a clean refusal', async () => {
    for (const [label, answer] of [
        ['applied, truthy object', async (apply) => { await apply(); return { ok: true }; }],
        ['applied, ack lost', async (apply) => { await apply(); throw new Error('ack lost'); }],
        ['not applied, throw', async () => { throw new Error('down'); }],
    ]) {
        const tag = label.replace(/[^A-Za-z0-9]+/g, '-');
        const f = fixture({ operationId: `operation:composed:t6:${tag}`, replayId: `native-mandate:composed:t6:${tag}` });
        const aebStore = durableAebStore();
        const reserve = aebStore.reserve.bind(aebStore);
        let armed = true;
        aebStore.reserve = async (key, fences) => {
            if (armed && key.startsWith('aeb-action-holder:')) {
                armed = false;
                return answer(() => reserve(key, fences));
            }
            return reserve(key, fences);
        };
        let calls = 0;
        const h = makeBoundary({
            f,
            aebStore,
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: executedEvidence(), result: {} }; },
        });
        const result = await h.boundary.run(input(f));
        assert.deepEqual([result.state, result.reason, result.invoked], ['INDETERMINATE', 'consumption_reservation_unconfirmed', false], label);
        const row = [...h.attempts.rows.values()][0];
        assert.equal(row.state, 'RELEASED', label);
        assert.equal([...aebStore.operations.values()].filter((state) => state === 'RESERVED').length, 0, label);
        assert.equal((await h.boundary.run(input(composedFresh(f, `t6-fresh-${tag}`)))).state, 'EXECUTED', label);
        assert.equal(calls, 1, label);
    }
});
test('T1 CX5 composed: an unconfirmed start is held with no not-entered write, with and without a durable read', async () => {
    for (const noState of [false, true]) {
        const f = fixture({ operationId: `operation:composed:cx5:${noState}`, replayId: `native-mandate:composed:cx5:${noState}` });
        const full = attemptStore();
        const transition = full.transition.bind(full);
        const state = full.state.bind(full);
        let failReads = 0;
        let armed = true;
        const written = [];
        const store = noState ? (() => { const { state: _s, ...rest } = full; return { ...rest, rows: full.rows }; })() : full;
        store.transition = async (entry) => {
            written.push(`${entry.expected_state}->${entry.next_state}`);
            if (armed && entry.next_state === 'INVOKING') {
                armed = false;
                await transition(entry);
                failReads = Infinity;
                throw new Error('ack lost');
            }
            return transition(entry);
        };
        if (!noState) {
            store.state = async (entry) => {
                if (failReads > 0) {
                    failReads -= 1;
                    throw new Error('read timeout');
                }
                return state(entry);
            };
        }
        let calls = 0;
        const h = makeBoundary({
            f,
            attempts: store,
            invoke: async () => { calls += 1; return { state: 'EXECUTED', evidence: executedEvidence(), result: {} }; },
        });
        const result = await h.boundary.run(input(f));
        assert.deepEqual([result.state, result.reason, result.invoked], ['INDETERMINATE', 'attempt_start_unconfirmed', false], String(noState));
        assert.deepEqual(written, ['RESERVED->INVOKING'], `${noState}: no not-entered write`);
        const row = full.rows.get(result.attempt.attempt_id);
        assert.equal(row.state, 'INVOKING');
        assert.equal(row.evidence, undefined);
        failReads = 0;
        assert.equal((await h.boundary.run(input(composedFresh(f, `cx5-${noState}`)))).reason, 'native_action_in_flight');
        assert.equal(calls, 0);
    }
});
