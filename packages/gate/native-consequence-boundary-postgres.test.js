// SPDX-License-Identifier: Apache-2.0
// Generated from native-consequence-boundary-postgres.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// The shipped PostgreSQL consumption store backing the direct-native
// consequence boundary, driven through a deterministic fake of the store's
// exact SQL. Commit and release are fenced by owner tokens that live only in
// the store instance that reserved the row, so a "restart" here is a new store
// instance over the same fake database.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
import { AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION, AEB_NATIVE_AUTHORIZATION_PINS_VERSION, AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION, AEB_NATIVE_AUTHORIZATION_STATUS_VERSION, issueAebNativeAuthorizationHandoff, } from '@emilia-protocol/verify/aeb';
import { AEB_CONSUMPTION_DDL, AEB_CONSUMPTION_SQL, createPostgresAebDurableConsumptionStore, } from './aeb-consumption-store.js';
import { createNativeConsequenceBoundary, nativeConsequenceBoundaryAttemptReservationKeys, nativeConsequenceBoundaryReservationKey, } from './consequence-boundary.js';
const TENANT = 'tenant:acme';
const RELYING_PARTY = 'rp:payments';
const EXECUTOR = 'executor:gate-1';
const NOW = '2026-08-09T12:00:01.000Z';
const PROVIDER = Object.freeze({
    tenant_id: TENANT,
    provider_id: 'provider:bank',
    provider_account_id: 'account:one',
    environment: 'sandbox',
});
const ACTION = Object.freeze({
    action_type: 'payment.release.1',
    transfer_id: 'transfer-1',
    amount: '500.00',
    currency: 'USD',
});
function scoped(tenantId, relyingPartyId, key) {
    return JSON.stringify([tenantId, relyingPartyId, key]);
}
function cloneDb(db) {
    return {
        operations: new Map([...db.operations].map(([key, row]) => [key, { ...row }])),
        replays: new Map(db.replays),
    };
}
/** Deterministic, serializable fake of exactly the SQL the store issues. */
function fakePostgres() {
    let committed = { operations: new Map(), replays: new Map() };
    let tail = Promise.resolve();
    const statements = [];
    let failOperationState = 0;
    const failures = new Map();
    async function lock() {
        let release;
        const turn = new Promise((resolve) => { release = resolve; });
        const previous = tail;
        tail = previous.then(() => turn);
        await previous;
        return release;
    }
    const pool = {
        async connect() {
            let transaction = null;
            let unlock = null;
            return {
                async query(text, params = []) {
                    await Promise.resolve();
                    statements.push(text);
                    const pending = failures.get(text) ?? 0;
                    if (pending > 0) {
                        failures.set(text, pending - 1);
                        throw new Error('pg: connection reset');
                    }
                    if (text === 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE') {
                        unlock = await lock();
                        transaction = cloneDb(committed);
                        return { rowCount: 0, rows: [] };
                    }
                    if (text === 'COMMIT') {
                        committed = transaction;
                        transaction = null;
                        unlock?.();
                        return { rowCount: 0, rows: [] };
                    }
                    if (text === 'ROLLBACK') {
                        transaction = null;
                        unlock?.();
                        return { rowCount: 0, rows: [] };
                    }
                    const [tenantId, relyingPartyId, key, fourth] = params;
                    if (text === AEB_CONSUMPTION_SQL.operationState) {
                        if (failOperationState > 0) {
                            failOperationState -= 1;
                            throw new Error('pg_unavailable');
                        }
                        const row = (transaction ?? committed).operations.get(scoped(tenantId, relyingPartyId, key));
                        return { rowCount: 1, rows: [{ state: row?.state ?? 'AVAILABLE' }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.hasReplayFence) {
                        return {
                            rowCount: 1,
                            rows: [{ fenced: (transaction ?? committed).replays.has(scoped(tenantId, relyingPartyId, key)) }],
                        };
                    }
                    assert.ok(transaction, `statement outside a transaction: ${text}`);
                    const id = scoped(tenantId, relyingPartyId, key);
                    const row = transaction.operations.get(id);
                    if (text === AEB_CONSUMPTION_SQL.reserveOperation) {
                        if (row)
                            return { rowCount: 0, rows: [] };
                        transaction.operations.set(id, { state: 'RESERVED', ownerToken: fourth });
                        return { rowCount: 1, rows: [{ operation_key: key }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.reserveReplayKeys) {
                        let inserted = 0;
                        for (const replayKey of fourth) {
                            const replayId = scoped(tenantId, relyingPartyId, replayKey);
                            if (transaction.replays.has(replayId))
                                continue;
                            transaction.replays.set(replayId, key);
                            inserted += 1;
                        }
                        return { rowCount: inserted, rows: [] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.commitOperation) {
                        if (!row || row.state !== 'RESERVED' || row.ownerToken !== fourth)
                            return { rowCount: 0, rows: [] };
                        transaction.operations.set(id, { state: 'CONSUMED', ownerToken: null });
                        return { rowCount: 1, rows: [{ operation_key: key }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.claimOperation) {
                        if (!row || row.state !== 'RESERVED')
                            return { rowCount: 0, rows: [] };
                        transaction.operations.set(id, { ...row, ownerToken: fourth });
                        return { rowCount: 1, rows: [{ operation_key: key }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.releaseOperation) {
                        if (!row || row.state !== 'RESERVED' || row.ownerToken !== fourth)
                            return { rowCount: 0, rows: [] };
                        transaction.operations.delete(id);
                        // ON DELETE CASCADE removes the fences this row holds.
                        for (const [replayId, operationKey] of transaction.replays) {
                            const [replayTenant, replayRp] = JSON.parse(replayId);
                            if (replayTenant === tenantId && replayRp === relyingPartyId && operationKey === key) {
                                transaction.replays.delete(replayId);
                            }
                        }
                        return { rowCount: 1, rows: [{ operation_key: key }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.releaseTerminalOperation) {
                        if (row?.state === 'RELEASED_NOT_ENTERED')
                            return { rowCount: 1, rows: [{ operation_key: key }] };
                        if (!row || row.state !== 'RESERVED' || row.ownerToken !== fourth)
                            return { rowCount: 0, rows: [] };
                        transaction.operations.set(id, { state: 'RELEASED_NOT_ENTERED', ownerToken: null });
                        return { rowCount: 1, rows: [{ operation_key: key }] };
                    }
                    throw new Error(`fake pg received unknown SQL: ${text}`);
                },
                release() {
                    assert.equal(transaction, null, 'client released with an open transaction');
                },
            };
        },
    };
    return {
        pool,
        statements,
        operation(key) {
            return committed.operations.get(scoped(TENANT, RELYING_PARTY, key));
        },
        fenceHolder(replayKey) {
            return committed.replays.get(scoped(TENANT, RELYING_PARTY, replayKey));
        },
        failNextOperationState(count = 1) {
            failOperationState += count;
        },
        /** The next `count` executions of this exact statement throw before running. */
        failNext(text, count = 1) {
            failures.set(text, (failures.get(text) ?? 0) + count);
        },
        restoreOperationState() {
            failOperationState = 0;
        },
    };
}
function pgStore(db, authorize = (claim) => claim.authorization === 'recovery:approved', claims = []) {
    return createPostgresAebDurableConsumptionStore({
        pool: db.pool,
        recoveryPool: { connect: () => db.pool.connect() },
        tenantId: TENANT,
        relyingPartyId: RELYING_PARTY,
        authorizeRecoveryClaim: (claim) => {
            claims.push(claim);
            return authorize(claim);
        },
    });
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
            row.state = input.next_state;
            row.evidence = structuredClone(input.evidence);
            return true;
        },
        async state(input) {
            const row = rows.get(input.attempt_id);
            if (!row || row.owner !== input.owner)
                throw new Error('attempt_not_owned');
            return { state: row.state, ...(row.evidence ? { evidence: structuredClone(row.evidence) } : {}) };
        },
    };
}
function nativeFixture() {
    const pair = crypto.generateKeyPairSync('ed25519');
    const gatewayId = 'gateway:authzen';
    const keyId = 'gateway-key:authzen:one';
    const source = {
        system: 'authzen',
        profile: 'authzen:exact-action-result:1',
        issuer: 'https://authzen.example',
        authorization_id: 'native-authz:authzen:123',
    };
    const pins = {
        '@version': AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
        relying_party_id: RELYING_PARTY,
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
                system: source.system,
                profile: source.profile,
                issuer: source.issuer,
            }],
    };
    const handoffInput = {
        gateway_id: gatewayId,
        native_authorization: source,
        relying_party_id: RELYING_PARTY,
        audience: pins.audience,
        executor_id: EXECUTOR,
        provider: PROVIDER,
        action: ACTION,
        issued_at: '2026-08-09T12:00:00.000Z',
        not_before: '2026-08-09T12:00:00.000Z',
        expires_at: '2026-08-09T12:01:00.000Z',
        revocation_id: 'revocation:authzen:123',
    };
    const signer = { key_id: keyId, private_key: pair.privateKey };
    const issue = (authorizationId) => issueAebNativeAuthorizationHandoff({
        ...handoffInput,
        native_authorization: { ...source, authorization_id: authorizationId },
        revocation_id: `revocation:${authorizationId}`,
    }, signer);
    return { pins, handoff: issue(source.authorization_id), issue, signer, handoffInput };
}
function statusFor(handoff) {
    return {
        '@version': AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
        gateway_id: handoff.gateway_id,
        native_authorization: handoff.native_authorization,
        revocation_id: handoff.revocation_id,
        checked_at: '2026-08-09T12:00:00.000Z',
        valid_until: '2026-08-09T12:00:30.000Z',
        revoked: false,
    };
}
function evidence(n) {
    return {
        evidence_id: `provider-evidence:${n}`,
        observed_at: '2026-08-09T12:00:02.000Z',
        evidence_digest: digestAeb({ provider: 'bank', n }),
    };
}
function boundary(f, store, attempts, invoke, options = {}) {
    let counter = 0;
    return createNativeConsequenceBoundary({
        executor_id: EXECUTOR,
        provider: PROVIDER,
        native_authorization: {
            pins: f.pins,
            trust_snapshot_id: 'native-trust-snapshot:pg:1',
            store,
            resolve_status: options.resolveStatus ?? ((handoff) => statusFor(handoff)),
            resolve_historical_pins: () => f.pins,
        },
        attempts: {
            store: attempts,
            create_id: () => `native-attempt:pg:${crypto.randomUUID()}:${++counter}`,
            recover: options.recover ?? (({ attempt, recovery_authorization }) => {
                if (recovery_authorization !== 'recovery:approved')
                    return null;
                const row = attempts.rows.get(attempt.attempt_id);
                return row ? { ...structuredClone(row.binding), owner: row.owner } : null;
            }),
        },
        local_authorization_program_digest: digestAeb({ program: 'local:pg:1' }),
        local_authorize: () => true,
        invoke,
        provider_outcomes: {
            verification_program_digest: digestAeb({ program: 'outcome:pg:1' }),
            verify: () => true,
        },
        now: () => NOW,
    });
}
function keysFor(attempt) {
    return nativeConsequenceBoundaryAttemptReservationKeys({
        relying_party_id: RELYING_PARTY,
        provider: PROVIDER,
        operation_id: attempt.operation_id,
        action_digest: attempt.action_digest,
        attempt_id: attempt.attempt_id,
    });
}
test('the PostgreSQL store declares the durable state read and its DDL grants it to the executor only', async () => {
    const db = fakePostgres();
    const store = pgStore(db);
    assert.equal(typeof store.state, 'function');
    assert.equal(await store.state('aeb-native-operation:missing'), 'AVAILABLE');
    assert.match(AEB_CONSUMPTION_DDL, /CREATE OR REPLACE FUNCTION ep_aeb_private\.operation_state\(/);
    assert.match(AEB_CONSUMPTION_DDL, /GRANT EXECUTE ON FUNCTION ep_aeb_private\.operation_state\(TEXT, TEXT, TEXT\)\n  TO ep_aeb_executor;/);
    assert.ok(AEB_CONSUMPTION_DDL.indexOf('ALTER FUNCTION ep_aeb_private.operation_state')
        < AEB_CONSUMPTION_DDL.indexOf('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private'));
    db.failNextOperationState();
    await assert.rejects(store.state('aeb-native-operation:missing'), /pg_unavailable/);
});
test('a malformed operation-state answer throws instead of reporting a state', async () => {
    const store = createPostgresAebDurableConsumptionStore({
        pool: { connect: async () => ({ query: async () => ({ rowCount: 1, rows: [{ state: 'OPEN' }] }), release() { } }) },
        recoveryPool: { connect: async () => ({ query: async () => ({ rowCount: 0, rows: [] }), release() { } }) },
        tenantId: TENANT,
        relyingPartyId: RELYING_PARTY,
        authorizeRecoveryClaim: () => false,
    });
    await assert.rejects(store.state('aeb-native-operation:x'), /malformed PostgreSQL result/);
});
test('the shipped PostgreSQL store backs the native boundary and closes all three reservations', async () => {
    const db = fakePostgres();
    const f = nativeFixture();
    let calls = 0;
    const h = boundary(f, pgStore(db), attemptStore(), async () => {
        calls += 1;
        return { state: 'EXECUTED', evidence: evidence(calls), result: { ok: true } };
    });
    const result = await h.run({ operation_id: 'operation:pg:1', handoff: f.handoff, action: ACTION });
    assert.equal(result.state, 'EXECUTED');
    assert.ok(result.state === 'EXECUTED');
    const keys = keysFor(result.attempt);
    assert.equal(db.operation(keys.operation)?.state, 'CONSUMED');
    assert.equal(db.operation(keys.authority)?.state, 'CONSUMED');
    assert.equal(db.operation(keys.holder)?.state, 'CONSUMED');
    const again = await h.run({ operation_id: 'operation:pg:2', handoff: f.issue('native-authz:fresh:1'), action: ACTION });
    assert.equal(again.state, 'REFUSED');
    assert.equal(again.reason, 'native_action_already_executed');
    assert.equal(calls, 1);
});
test('after a restart, reconciliation claims every reservation through the authorized recovery path', async () => {
    const db = fakePostgres();
    const f = nativeFixture();
    const attempts = attemptStore();
    const before = boundary(f, pgStore(db), attempts, async () => { throw new Error('process lost the response'); });
    const uncertain = await before.run({ operation_id: 'operation:pg:restart', handoff: f.handoff, action: ACTION });
    assert.equal(uncertain.state, 'INDETERMINATE');
    assert.ok(uncertain.attempt);
    const keys = keysFor(uncertain.attempt);
    assert.equal(db.operation(keys.operation)?.state, 'RESERVED');
    assert.equal(db.operation(keys.authority)?.state, 'RESERVED');
    assert.equal(db.operation(keys.holder)?.state, 'RESERVED');
    // A fresh authorization for the same action is fenced across the restart.
    const claims = [];
    let calls = 0;
    const after = boundary(f, pgStore(db, undefined, claims), attempts, async () => {
        calls += 1;
        return { state: 'EXECUTED', evidence: evidence(calls), result: {} };
    });
    const fenced = await after.run({
        operation_id: 'operation:pg:restart:retry',
        handoff: f.issue('native-authz:fresh:restart'),
        action: ACTION,
    });
    assert.equal(fenced.state, 'REFUSED');
    assert.equal(fenced.reason, 'native_action_in_flight');
    assert.equal(calls, 0);
    const reconciled = await after.reconcile({
        operation_id: 'operation:pg:restart',
        handoff: f.handoff,
        action: ACTION,
        attempt: uncertain.attempt,
        outcome: { state: 'EXECUTED', evidence: evidence(1), result: { recovered: true } },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(reconciled.state, 'EXECUTED');
    assert.deepEqual(claims.map((claim) => claim.operationKey), [keys.authority, keys.operation, keys.holder]);
    assert.ok(claims.every((claim) => claim.authorization === 'recovery:approved'
        && claim.requiredState === 'RESERVED'
        && claim.scope?.attemptId === uncertain.attempt.attempt_id
        && claim.scope?.recoveryOperationKey === keys.operation_fence));
    assert.deepEqual(claims.map((claim) => claim.scope?.reservation), ['native-authority', 'operation', 'action-fence-holder']);
    assert.equal(db.operation(keys.operation)?.state, 'CONSUMED');
    assert.equal(db.operation(keys.authority)?.state, 'CONSUMED');
    assert.equal(db.operation(keys.holder)?.state, 'CONSUMED');
});
test('an unauthorized restart reconciliation leaves every reservation held', async () => {
    const db = fakePostgres();
    const f = nativeFixture();
    const attempts = attemptStore();
    const before = boundary(f, pgStore(db), attempts, async () => { throw new Error('lost'); });
    const uncertain = await before.run({ operation_id: 'operation:pg:unauthorized', handoff: f.handoff, action: ACTION });
    assert.equal(uncertain.state, 'INDETERMINATE');
    const keys = keysFor(uncertain.attempt);
    const denied = boundary(f, pgStore(db, () => false), attempts, async () => { throw new Error('no'); });
    const result = await denied.reconcile({
        operation_id: 'operation:pg:unauthorized',
        handoff: f.handoff,
        action: ACTION,
        attempt: uncertain.attempt,
        outcome: { state: 'EXECUTED', evidence: evidence(1), result: {} },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(result.state, 'INDETERMINATE');
    assert.equal(result.reason, 'authorization_consumption_unconfirmed');
    assert.equal(db.operation(keys.operation)?.state, 'RESERVED');
    assert.equal(db.operation(keys.authority)?.state, 'RESERVED');
    assert.equal(db.operation(keys.holder)?.state, 'RESERVED');
    assert.equal([...attempts.rows.values()][0]?.state, 'INDETERMINATE');
});
test('after a restart, reconciliation to FAILED burns the authorization and releases the action fence', async () => {
    const db = fakePostgres();
    const f = nativeFixture();
    const attempts = attemptStore();
    const before = boundary(f, pgStore(db), attempts, async () => { throw new Error('lost'); });
    const uncertain = await before.run({ operation_id: 'operation:pg:failed', handoff: f.handoff, action: ACTION });
    assert.equal(uncertain.state, 'INDETERMINATE');
    const keys = keysFor(uncertain.attempt);
    let calls = 0;
    const after = boundary(f, pgStore(db), attempts, async () => {
        calls += 1;
        return { state: 'EXECUTED', evidence: evidence(10 + calls), result: {} };
    });
    const failed = await after.reconcile({
        operation_id: 'operation:pg:failed',
        handoff: f.handoff,
        action: ACTION,
        attempt: uncertain.attempt,
        outcome: { state: 'FAILED', evidence: evidence(1), reason: 'provider_declined' },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(failed.state, 'FAILED');
    assert.equal(db.operation(keys.operation)?.state, 'CONSUMED');
    assert.equal(db.operation(keys.authority)?.state, 'CONSUMED');
    assert.equal(db.operation(keys.holder), undefined, 'fence holder released');
    const sameAuthority = await after.run({ operation_id: 'operation:pg:failed:2', handoff: f.handoff, action: ACTION });
    assert.equal(sameAuthority.state, 'REFUSED');
    assert.equal(sameAuthority.reason, 'native_replay_conflict');
    const fresh = await after.run({
        operation_id: 'operation:pg:failed:3',
        handoff: f.issue('native-authz:fresh:after-failed'),
        action: ACTION,
    });
    assert.equal(fresh.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('an unreadable operation state never becomes a provider entry', async () => {
    const db = fakePostgres();
    const f = nativeFixture();
    let calls = 0;
    const h = boundary(f, pgStore(db), attemptStore(), async () => {
        calls += 1;
        return { state: 'EXECUTED', evidence: evidence(calls), result: {} };
    });
    // Every durable state read fails: the boundary cannot confirm consumption,
    // reports INDETERMINATE after the one provider entry, and keeps the fences.
    db.failNextOperationState(50);
    const result = await h.run({ operation_id: 'operation:pg:state-down', handoff: f.handoff, action: ACTION });
    assert.equal(result.state, 'INDETERMINATE');
    assert.equal(result.reason, 'authorization_consumption_unconfirmed');
    assert.equal(calls, 1);
    db.restoreOperationState();
    const retry = await h.run({
        operation_id: 'operation:pg:state-down:retry',
        handoff: f.issue('native-authz:fresh:state-down'),
        action: ACTION,
    });
    assert.equal(retry.state, 'REFUSED');
    assert.equal(retry.reason, 'native_action_in_flight');
    assert.equal(calls, 1);
});
// ---------------------------------------------------------------------------
// PR #790 round 2 over the shipped store's exact SQL.
// ---------------------------------------------------------------------------
function failed(n) {
    return { ...evidence(900 + n), evidence_id: `provider-evidence:not-found-${n}` };
}
test('PG6: a reserve error on a shared operation ID never deletes the live attempt\'s rows', async () => {
    // Regression for PG6: the reserve-error catch released the operation key
    // with the per-instance owner token of a live attempt in the same process,
    // deleted its row and native replay fence, locked the action, and let the
    // grant already sent to the provider be spent on a second action.
    const db = fakePostgres();
    const f = nativeFixture();
    const store = pgStore(db);
    const attempts = attemptStore();
    let release;
    const providerGate = new Promise((resolve) => { release = resolve; });
    let calls = 0;
    const h = boundary(f, store, attempts, async () => {
        calls += 1;
        if (calls === 1)
            await providerGate;
        return { state: 'EXECUTED', evidence: evidence(calls), result: {} };
    });
    const victimHandoff = f.issue('native-authz:victim');
    const victimRun = h.run({ operation_id: 'operation:pg:shared', handoff: victimHandoff, action: ACTION });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const victimAttempt = [...attempts.rows.values()][0].binding;
    const keys = keysFor(victimAttempt);
    assert.equal(db.operation(keys.operation)?.state, 'RESERVED');
    assert.equal(db.operation(keys.authority)?.state, 'RESERVED');
    assert.equal(db.operation(keys.holder)?.state, 'RESERVED');
    db.failNext(AEB_CONSUMPTION_SQL.reserveOperation);
    const attacker = await h.run({
        operation_id: 'operation:pg:shared',
        handoff: f.issue('native-authz:attacker'),
        action: ACTION,
    });
    assert.equal(attacker.state, 'REFUSED');
    assert.equal(attacker.reason, 'consumption_store_unavailable');
    assert.equal(db.operation(keys.operation)?.state, 'RESERVED');
    assert.equal(db.operation(keys.authority)?.state, 'RESERVED');
    assert.equal(db.operation(keys.holder)?.state, 'RESERVED');
    release();
    const victim = await victimRun;
    assert.equal(victim.state, 'EXECUTED');
    const secondAction = { ...ACTION, transfer_id: 'transfer-2' };
    const reuse = await h.run({
        operation_id: 'operation:pg:shared:B',
        // The victim's grant, already sent to the provider, on a second action.
        handoff: issueAebNativeAuthorizationHandoff({
            ...f.handoffInput,
            native_authorization: {
                ...f.handoffInput.native_authorization,
                authorization_id: victimHandoff.native_authorization.authorization_id,
            },
            action: secondAction,
            revocation_id: 'revocation:victim:B',
        }, f.signer),
        action: secondAction,
    });
    assert.equal(reuse.state, 'REFUSED');
    assert.equal(reuse.reason, 'native_replay_conflict');
    assert.equal(calls, 1);
});
test('PG5: a transient release error after a pre-entry refusal is recovered after restart', async () => {
    // Regression for PG5: one connection reset on the holder release left the
    // holder RESERVED, reconcile refused attempt_never_entered_provider, and every
    // fresh authority was refused native_action_in_flight forever.
    const db = fakePostgres();
    const f = nativeFixture();
    const attempts = attemptStore();
    let lookups = 0;
    const before = boundary(f, pgStore(db), attempts, async () => {
        throw new Error('must not be called');
    }, {
        resolveStatus: (handoff) => {
            lookups += 1;
            if (lookups === 2)
                db.failNext(AEB_CONSUMPTION_SQL.releaseOperation);
            return { ...statusFor(handoff), revoked: lookups === 2 };
        },
    });
    const first = await before.run({ operation_id: 'operation:pg:pre-entry', handoff: f.handoff, action: ACTION });
    assert.equal(first.state, 'INDETERMINATE');
    assert.equal(first.reason, 'native_pre_entry_release_unconfirmed');
    const keys = keysFor(first.attempt);
    assert.equal(db.operation(keys.holder)?.state, 'RESERVED');
    let calls = 0;
    const claims = [];
    const after = boundary(f, pgStore(db, undefined, claims), attempts, async () => {
        calls += 1;
        return { state: 'EXECUTED', evidence: evidence(calls), result: {} };
    });
    const fenced = await after.run({
        operation_id: 'operation:pg:pre-entry:early',
        handoff: f.issue('native-authz:pre-entry-early'),
        action: ACTION,
    });
    assert.equal(fenced.reason, 'native_action_in_flight');
    const recovered = await after.reconcile({
        operation_id: 'operation:pg:pre-entry',
        handoff: f.handoff,
        action: ACTION,
        attempt: first.attempt,
        outcome: { state: 'FAILED', evidence: failed(1), reason: 'not_found' },
        recovery_authorization: 'recovery:approved',
    });
    assert.equal(recovered.state, 'REFUSED');
    assert.equal(recovered.reason, 'attempt_never_entered_provider');
    assert.equal(db.operation(keys.holder), undefined);
    assert.equal(db.operation(keys.operation), undefined);
    assert.equal(db.operation(keys.authority), undefined);
    assert.deepEqual(claims.map((claim) => claim.scope?.reservation), ['action-fence-holder']);
    const fresh = await after.run({
        operation_id: 'operation:pg:pre-entry:fresh',
        handoff: f.issue('native-authz:pre-entry-fresh'),
        action: ACTION,
    });
    assert.equal(fresh.state, 'EXECUTED');
    assert.equal(calls, 1);
});
test('PG4: one credential bound to the attempt finishes restart reconciliation in one call', async () => {
    // Regression for PG4: a credential bound to the exact row key left the
    // holder RESERVED (native_action_fence_release_unconfirmed) until a second
    // reconcile with a holder-bound credential.
    for (const terminal of ['FAILED', 'EXECUTED']) {
        const db = fakePostgres();
        const f = nativeFixture();
        const attempts = attemptStore();
        const before = boundary(f, pgStore(db), attempts, async () => { throw new Error('lost'); });
        const operationId = `operation:pg:one-credential:${terminal}`;
        const uncertain = await before.run({ operation_id: operationId, handoff: f.handoff, action: ACTION });
        assert.equal(uncertain.state, 'INDETERMINATE');
        const keys = keysFor(uncertain.attempt);
        const claims = [];
        const strict = (claim) => claim.authorization?.attempt_id === claim.scope?.attemptId
            && claim.authorization?.operation_key === claim.scope?.recoveryOperationKey;
        const credential = { attempt_id: uncertain.attempt.attempt_id, operation_key: keys.operation_fence };
        const after = boundary(f, pgStore(db, strict, claims), attempts, async () => {
            throw new Error('must not be called');
        }, {
            recover: ({ attempt, recovery_authorization }) => {
                if (recovery_authorization?.attempt_id !== attempt.attempt_id)
                    return null;
                const row = attempts.rows.get(attempt.attempt_id);
                return row ? { ...structuredClone(row.binding), owner: row.owner } : null;
            },
        });
        const result = await after.reconcile({
            operation_id: operationId,
            handoff: f.handoff,
            action: ACTION,
            attempt: uncertain.attempt,
            outcome: terminal === 'FAILED'
                ? { state: 'FAILED', evidence: failed(2), reason: 'declined' }
                : { state: 'EXECUTED', evidence: evidence(2), result: {} },
            recovery_authorization: credential,
        });
        assert.equal(result.state, terminal, terminal);
        assert.equal(claims.length, 3, terminal);
        assert.equal(db.operation(keys.operation)?.state, 'CONSUMED', terminal);
        assert.equal(db.operation(keys.authority)?.state, 'CONSUMED', terminal);
        assert.equal(db.operation(keys.holder)?.state, terminal === 'EXECUTED' ? 'CONSUMED' : undefined, terminal);
    }
});
test('a recovery claim scope is validated and passed to the authorizer unchanged', async () => {
    const db = fakePostgres();
    const claims = [];
    const store = pgStore(db, () => true, claims);
    const scope = {
        attemptId: 'native-attempt:scope:1',
        operationId: 'operation:scope:1',
        recoveryOperationKey: 'aeb-native-operation:sha256:' + '0'.repeat(64),
        reservation: 'operation',
    };
    assert.equal(await store.claimReservation('aeb-native-attempt-operation:missing', 'x', scope), false);
    assert.deepEqual(claims[0]?.scope, scope);
    assert.equal(Object.isFrozen(claims[0]?.scope), true);
    await assert.rejects(store.claimReservation('k', 'x', { ...scope, reservation: 'everything' }), /recovery claim scope is invalid/);
    await assert.rejects(store.claimReservation('k', 'x', { ...scope, extra: true }), /recovery claim scope is invalid/);
    let getterRan = false;
    const getterScope = Object.defineProperty({ ...scope }, 'attemptId', {
        get() { getterRan = true; return 'native-attempt:scope:1'; },
        enumerable: true,
    });
    await assert.rejects(store.claimReservation('k', 'x', getterScope), /recovery claim scope is invalid/);
    assert.equal(getterRan, false);
    assert.equal(await store.claimReservation('aeb-native-attempt-operation:missing', 'x'), false);
    assert.equal(claims[1]?.scope, undefined);
    assert.equal(Object.hasOwn(claims[1], 'scope'), false);
});
