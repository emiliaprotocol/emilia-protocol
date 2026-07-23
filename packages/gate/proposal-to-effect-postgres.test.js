// SPDX-License-Identifier: Apache-2.0
// Generated from proposal-to-effect-postgres.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { PROPOSAL_TO_EFFECT_POSTGRES_DDL, PROPOSAL_TO_EFFECT_POSTGRES_SQL, createProposalToEffectPostgresStore, } from './proposal-to-effect-postgres.js';
const DIGESTS = {
    operation_digest: `sha256:${'1'.repeat(64)}`,
    request_digest: `sha256:${'2'.repeat(64)}`,
    action_digest: `sha256:${'3'.repeat(64)}`,
    config_digest: `sha256:${'4'.repeat(64)}`,
};
function binding(overrides = {}) {
    return {
        tenant_id: 'tenant:alpha',
        provider_id: 'provider:stripe',
        provider_account_id: 'account:primary',
        environment: 'production',
        attempt_id: 'attempt:001',
        request_digest: DIGESTS.request_digest,
        ...overrides,
    };
}
function evidence(attempt, outcome = 'COMMITTED', overrides = {}) {
    return {
        ...attempt,
        operation_id: 'operation:payment:001',
        caid: 'caid:payment:001',
        action_digest: DIGESTS.action_digest,
        evidence_id: 'evidence:provider:001',
        observed_at: '2026-07-22T18:00:00.000Z',
        outcome,
        evidence_digest: `sha256:${'5'.repeat(64)}`,
        ...overrides,
    };
}
function fakePostgres() {
    let attempts = new Map();
    let evidenceRows = new Map();
    let malformedAfterNextMutation = false;
    let malformedNextLookupBinding = false;
    let nextMutationError = null;
    let loseNextCommitAcknowledgement = false;
    let nowMs = Date.parse('2026-07-22T18:00:00.000Z');
    const transactionLog = [];
    const queryParameters = [];
    const queryPrincipals = [];
    const discardedConnections = [];
    const namespaceKey = (tenantId, providerId, providerAccountId, environment, attemptId) => JSON.stringify([tenantId, providerId, providerAccountId, environment, attemptId]);
    const evidenceKey = (tenantId, providerId, providerAccountId, environment, value) => JSON.stringify([tenantId, providerId, providerAccountId, environment, value]);
    const cloneAttempts = () => new Map([...attempts].map(([key, value]) => [key, structuredClone(value)]));
    const cloneEvidence = () => new Map([...evidenceRows].map(([key, value]) => [key, structuredClone(value)]));
    const instant = (value) => new Date(value).toISOString();
    const success = (applied, reason = null) => ({
        rowCount: 1,
        rows: [{ applied, reason }],
    });
    const makePool = (principal) => ({
        async connect() {
            let snapshot = null;
            return {
                async query(text, params = []) {
                    queryParameters.push([...params]);
                    queryPrincipals.push(principal);
                    if (text.startsWith('BEGIN ')) {
                        assert.equal(snapshot, null);
                        snapshot = {
                            attempts: cloneAttempts(),
                            evidenceRows: cloneEvidence(),
                        };
                        transactionLog.push(text);
                        return { rowCount: null, rows: [] };
                    }
                    if (text === 'COMMIT') {
                        assert.notEqual(snapshot, null);
                        snapshot = null;
                        transactionLog.push(text);
                        if (loseNextCommitAcknowledgement) {
                            loseNextCommitAcknowledgement = false;
                            throw new Error('connection lost after COMMIT');
                        }
                        return { rowCount: null, rows: [] };
                    }
                    if (text === 'ROLLBACK') {
                        assert.notEqual(snapshot, null);
                        attempts = snapshot.attempts;
                        evidenceRows = snapshot.evidenceRows;
                        snapshot = null;
                        transactionLog.push(text);
                        return { rowCount: null, rows: [] };
                    }
                    const mutation = text !== PROPOSAL_TO_EFFECT_POSTGRES_SQL.read
                        && text !== PROPOSAL_TO_EFFECT_POSTGRES_SQL.lookup;
                    if (mutation && nextMutationError) {
                        const error = nextMutationError;
                        nextMutationError = null;
                        throw error;
                    }
                    if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.recover) {
                        assert.equal(principal, 'recovery');
                    }
                    else if (mutation) {
                        assert.equal(principal, 'executor');
                    }
                    let result;
                    if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.reserve) {
                        const [tenantId, providerId, providerAccountId, environment, attemptId, operationDigest, requestDigest, actionDigest, configDigest, attemptDigest, ownerDigest, leaseSeconds,] = params;
                        const key = namespaceKey(tenantId, providerId, providerAccountId, environment, attemptId);
                        const namespacePrefix = JSON.stringify([
                            tenantId, providerId, providerAccountId, environment,
                        ]).slice(0, -1);
                        const existing = attempts.get(key);
                        const sameReservation = existing
                            && existing.operation_digest === operationDigest
                            && existing.request_digest === requestDigest
                            && existing.action_digest === actionDigest
                            && existing.config_digest === configDigest
                            && existing.attempt_digest === attemptDigest
                            && existing.owner_digest === ownerDigest
                            && existing.owner_generation === 0
                            && existing.state === 'RESERVED';
                        const bindingConflict = [...attempts.entries()].some(([storedKey, stored]) => (storedKey.startsWith(namespacePrefix)
                            && (stored.operation_digest === operationDigest
                                || stored.request_digest === requestDigest
                                || stored.attempt_digest === attemptDigest)));
                        if (sameReservation) {
                            result = success(true);
                        }
                        else if (existing) {
                            result = success(false, 'attempt_exists');
                        }
                        else if (bindingConflict) {
                            result = success(false, 'binding_conflict');
                        }
                        else {
                            attempts.set(key, {
                                tenant_id: tenantId,
                                provider_id: providerId,
                                provider_account_id: providerAccountId,
                                environment,
                                attempt_id: attemptId,
                                operation_digest: operationDigest,
                                request_digest: requestDigest,
                                action_digest: actionDigest,
                                config_digest: configDigest,
                                attempt_digest: attemptDigest,
                                owner_digest: ownerDigest,
                                owner_generation: 0,
                                state: 'RESERVED',
                                evidence_digest: null,
                                evidence_binding_digest: null,
                                last_heartbeat_at: instant(nowMs),
                                lease_expires_at: instant(nowMs + leaseSeconds * 1_000),
                            });
                            result = success(true);
                        }
                    }
                    else if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.transition) {
                        const [tenantId, attemptId, ownerDigest, expectedState, nextState, leaseSeconds,] = params;
                        const record = [...attempts.values()].find((candidate) => (candidate.tenant_id === tenantId
                            && candidate.attempt_id === attemptId
                            && candidate.owner_digest === ownerDigest));
                        const allowed = ((expectedState === 'RESERVED' && nextState === 'INVOKING')
                            || (expectedState === 'INVOKING' && nextState === 'INDETERMINATE')
                            || (expectedState === 'INDETERMINATE'
                                && ['COMMITTED', 'RELEASED', 'ESCALATED'].includes(nextState)));
                        const applied = Boolean(record && allowed
                            && (record.state === expectedState || record.state === nextState));
                        if (applied && record.state === expectedState) {
                            record.state = nextState;
                            record.last_heartbeat_at = instant(nowMs);
                            record.lease_expires_at = instant(nowMs + leaseSeconds * 1_000);
                        }
                        result = success(applied);
                    }
                    else if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.heartbeat) {
                        const [tenantId, attemptId, ownerDigest, leaseSeconds] = params;
                        const record = [...attempts.values()].find((candidate) => (candidate.tenant_id === tenantId
                            && candidate.attempt_id === attemptId
                            && candidate.owner_digest === ownerDigest
                            && ['RESERVED', 'INVOKING', 'INDETERMINATE'].includes(candidate.state)));
                        if (record) {
                            record.last_heartbeat_at = instant(nowMs);
                            record.lease_expires_at = instant(nowMs + leaseSeconds * 1_000);
                        }
                        result = success(Boolean(record));
                    }
                    else if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.reconcile) {
                        const [tenantId, providerId, providerAccountId, environment, attemptId, ownerDigest, operationDigest, requestDigest, actionDigest, configDigest, attemptDigest, operationId, caid, nextState, evidenceId, observedAt, outcome, providerEvidenceDigest, evidenceBindingDigest,] = params;
                        const record = attempts.get(namespaceKey(tenantId, providerId, providerAccountId, environment, attemptId));
                        const mappedState = outcome === 'COMMITTED'
                            ? 'COMMITTED' : outcome === 'NOT_COMMITTED' ? 'RELEASED' : 'ESCALATED';
                        const idKey = evidenceKey(tenantId, providerId, providerAccountId, environment, evidenceId);
                        const digestKey = evidenceKey(tenantId, providerId, providerAccountId, environment, providerEvidenceDigest);
                        const exactEvidence = [...evidenceRows.values()].find((stored) => (stored.tenant_id === tenantId
                            && stored.provider_id === providerId
                            && stored.provider_account_id === providerAccountId
                            && stored.environment === environment
                            && stored.attempt_id === attemptId
                            && stored.attempt_digest === attemptDigest
                            && stored.operation_id === operationId
                            && stored.caid === caid
                            && stored.action_digest === actionDigest
                            && stored.evidence_id === evidenceId
                            && stored.observed_at === observedAt
                            && stored.outcome === outcome
                            && stored.evidence_digest === providerEvidenceDigest
                            && stored.evidence_binding_digest === evidenceBindingDigest));
                        const idempotent = Boolean(record
                            && record.owner_digest === ownerDigest
                            && record.state === nextState
                            && record.evidence_digest === providerEvidenceDigest
                            && record.evidence_binding_digest === evidenceBindingDigest
                            && exactEvidence);
                        const applied = Boolean(record
                            && record.owner_digest === ownerDigest
                            && record.state === 'INDETERMINATE'
                            && record.operation_digest === operationDigest
                            && record.request_digest === requestDigest
                            && record.action_digest === actionDigest
                            && record.config_digest === configDigest
                            && record.attempt_digest === attemptDigest
                            && nextState === mappedState
                            && ![...evidenceRows.values()].some((stored) => (evidenceKey(stored.tenant_id, stored.provider_id, stored.provider_account_id, stored.environment, stored.evidence_id) === idKey
                                || evidenceKey(stored.tenant_id, stored.provider_id, stored.provider_account_id, stored.environment, stored.evidence_digest) === digestKey)));
                        if (applied) {
                            record.state = nextState;
                            record.evidence_digest = providerEvidenceDigest;
                            record.evidence_binding_digest = evidenceBindingDigest;
                            evidenceRows.set(digestKey, {
                                tenant_id: tenantId,
                                provider_id: providerId,
                                provider_account_id: providerAccountId,
                                environment: environment,
                                attempt_id: attemptId,
                                attempt_digest: attemptDigest,
                                operation_id: operationId,
                                caid: caid,
                                action_digest: actionDigest,
                                evidence_id: evidenceId,
                                observed_at: observedAt,
                                outcome: outcome,
                                evidence_digest: providerEvidenceDigest,
                                evidence_binding_digest: evidenceBindingDigest,
                            });
                        }
                        result = success(applied || idempotent);
                    }
                    else if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.lookup) {
                        const [tenantId, providerId, providerAccountId, environment, requestDigest,] = params;
                        const matches = [...attempts.values()].filter((record) => (record.tenant_id === tenantId
                            && record.provider_id === providerId
                            && record.provider_account_id === providerAccountId
                            && record.environment === environment
                            && record.request_digest === requestDigest));
                        result = {
                            rowCount: matches.length,
                            rows: matches.map((record) => ({
                                tenant_id: malformedNextLookupBinding
                                    ? 'tenant-unexpected'
                                    : record.tenant_id,
                                provider_id: record.provider_id,
                                provider_account_id: record.provider_account_id,
                                environment: record.environment,
                                attempt_id: record.attempt_id,
                                request_digest: record.request_digest,
                            })),
                        };
                        malformedNextLookupBinding = false;
                    }
                    else if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.read) {
                        const [tenantId, providerId, providerAccountId, environment, attemptId, requestDigest,] = params;
                        const record = attempts.get(namespaceKey(tenantId, providerId, providerAccountId, environment, attemptId));
                        result = record && record.request_digest === requestDigest ? {
                            rowCount: 1,
                            rows: [{
                                    tenant_id: record.tenant_id,
                                    provider_id: record.provider_id,
                                    provider_account_id: record.provider_account_id,
                                    environment: record.environment,
                                    attempt_id: record.attempt_id,
                                    operation_digest: record.operation_digest,
                                    request_digest: record.request_digest,
                                    action_digest: record.action_digest,
                                    config_digest: record.config_digest,
                                    attempt_digest: record.attempt_digest,
                                    state: record.state,
                                    evidence_digest: record.evidence_digest,
                                    owner_generation: String(record.owner_generation),
                                    last_heartbeat_at: record.last_heartbeat_at,
                                    lease_expires_at: record.lease_expires_at,
                                    lease_stale: Date.parse(record.lease_expires_at) <= nowMs,
                                }],
                        } : { rowCount: 0, rows: [] };
                    }
                    else if (text === PROPOSAL_TO_EFFECT_POSTGRES_SQL.recover) {
                        const [tenantId, providerId, providerAccountId, environment, attemptId, requestDigest, attemptDigest, ownerGeneration, expectedState, expectedLeaseExpiresAt, nextOwnerDigest, leaseSeconds,] = params;
                        const record = attempts.get(namespaceKey(tenantId, providerId, providerAccountId, environment, attemptId));
                        const targetState = expectedState === 'RESERVED' ? 'RESERVED' : 'INDETERMINATE';
                        const idempotent = Boolean(record
                            && record.request_digest === requestDigest
                            && record.attempt_digest === attemptDigest
                            && record.owner_generation === ownerGeneration + 1
                            && record.owner_digest === nextOwnerDigest
                            && record.state === targetState);
                        const stale = Boolean(record
                            && record.request_digest === requestDigest
                            && record.attempt_digest === attemptDigest
                            && record.owner_generation === ownerGeneration
                            && record.state === expectedState
                            && record.lease_expires_at === expectedLeaseExpiresAt
                            && Date.parse(record.lease_expires_at) <= nowMs);
                        if (stale) {
                            record.owner_digest = nextOwnerDigest;
                            record.owner_generation += 1;
                            record.state = targetState;
                            record.last_heartbeat_at = instant(nowMs);
                            record.lease_expires_at = instant(nowMs + leaseSeconds * 1_000);
                            result = success(true);
                        }
                        else if (idempotent) {
                            result = success(true);
                        }
                        else if (record
                            && record.owner_generation === ownerGeneration
                            && record.state === expectedState
                            && record.lease_expires_at === expectedLeaseExpiresAt
                            && Date.parse(record.lease_expires_at) > nowMs) {
                            result = success(false, 'attempt_not_stale');
                        }
                        else {
                            result = success(false, 'recovery_conflict');
                        }
                    }
                    else {
                        throw new Error(`unexpected SQL: ${text}`);
                    }
                    if (mutation && malformedAfterNextMutation) {
                        malformedAfterNextMutation = false;
                        return { rowCount: 1, rows: [{ applied: 'yes', reason: null }] };
                    }
                    return result;
                },
                release(error) {
                    if (error)
                        discardedConnections.push(error);
                },
            };
        },
    });
    const pool = makePool('executor');
    const recoveryPool = makePool('recovery');
    return {
        pool,
        recoveryPool,
        get attempts() {
            return attempts;
        },
        get evidenceRows() {
            return evidenceRows;
        },
        transactionLog,
        queryParameters,
        queryPrincipals,
        discardedConnections,
        namespaceKey,
        advanceTime(milliseconds) {
            nowMs += milliseconds;
        },
        loseCommitAcknowledgementOnce() {
            loseNextCommitAcknowledgement = true;
        },
        malformAfterNextMutation() {
            malformedAfterNextMutation = true;
        },
        malformNextLookupBinding() {
            malformedNextLookupBinding = true;
        },
        failNextMutation(error = new Error('database unavailable')) {
            nextMutationError = error;
        },
    };
}
function storeFixture({ pg = fakePostgres(), authorizeRecovery = async () => true, randomStart = 0, } = {}) {
    let randomSequence = randomStart;
    const store = createProposalToEffectPostgresStore({
        pool: pg.pool,
        recovery_pool: pg.recoveryPool,
        owner_hmac_sha256_key: new Uint8Array(32).fill(9),
        resolve_binding_digests: async (input) => {
            assert.match(input.request_digest, /^sha256:[a-f0-9]{64}$/);
            return {
                operation_digest: DIGESTS.operation_digest,
                action_digest: DIGESTS.action_digest,
                config_digest: DIGESTS.config_digest,
            };
        },
        authorize_recovery: authorizeRecovery,
        lease_seconds: 30,
        random_bytes(size) {
            randomSequence += 1;
            return new Uint8Array(size).fill(randomSequence);
        },
    });
    return { pg, store };
}
async function reserveOwner(store, attempt = binding()) {
    const reserved = await store.reserve(attempt);
    assert.equal(reserved.reserved, true);
    return reserved.owner;
}
async function makeIndeterminate(store, attempt = binding()) {
    const owner = await reserveOwner(store, attempt);
    assert.equal(await store.transition({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'RESERVED',
        next_state: 'INVOKING',
    }), true);
    assert.equal(await store.transition({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INVOKING',
        next_state: 'INDETERMINATE',
    }), true);
    return owner;
}
test('secure DDL separates database roles, tenant principals, and recovery authority', () => {
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /CREATE SCHEMA IF NOT EXISTS proposal_to_effect_private/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /CREATE ROLE proposal_to_effect_executor NOLOGIN/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /CREATE ROLE proposal_to_effect_recovery NOLOGIN/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /CREATE TABLE IF NOT EXISTS proposal_to_effect_private\.tenant_principals/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /PTE_TENANT_PRINCIPAL_REFUSED/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /recover_attempt\([\s\S]*\) TO proposal_to_effect_recovery;/);
    assert.doesNotMatch(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /TO service_role/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /PRIMARY KEY \(\s*tenant_id, provider_id, provider_account_id, environment, attempt_id\s*\)/);
    for (const column of [
        'operation_digest', 'request_digest', 'action_digest', 'config_digest', 'attempt_digest',
        'owner_digest', 'evidence_digest', 'evidence_binding_digest',
        'last_heartbeat_at', 'lease_expires_at',
    ]) {
        assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, new RegExp(`\\b${column}\\b`));
    }
    assert.doesNotMatch(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /\bowner_token\b/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /ENABLE ROW LEVEL SECURITY/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /FORCE ROW LEVEL SECURITY/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /REVOKE ALL ON TABLE proposal_to_effect_private\.consequence_attempts FROM PUBLIC/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /SECURITY DEFINER/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /SET search_path = ''/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /state = 'INDETERMINATE'/);
    assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /state IN \('COMMITTED', 'RELEASED', 'ESCALATED'\)/);
    assert.equal(PROPOSAL_TO_EFFECT_POSTGRES_DDL.match(/HH24:MI:SS\.US/g)?.length, 2, 'recovery snapshots must preserve PostgreSQL microseconds for exact lease fencing');
    assert.doesNotMatch(PROPOSAL_TO_EFFECT_POSTGRES_DDL, /HH24:MI:SS\.MS/);
    for (const column of ['operation_id', 'caid', 'action_digest']) {
        assert.match(PROPOSAL_TO_EFFECT_POSTGRES_DDL, new RegExp(`provider_evidence[\\s\\S]*\\b${column}\\b`));
    }
});
test('reserve is namespaced, one-winner, and never sends the opaque owner to PostgreSQL', async () => {
    const { pg, store } = storeFixture();
    const attempt = binding();
    const results = await Promise.all(Array.from({ length: 24 }, () => store.reserve(attempt)));
    assert.equal(results.filter((result) => result.reserved).length, 1);
    const winner = results.find((result) => result.reserved);
    assert.ok(winner?.reserved);
    assert.match(winner.owner, /^pto-owner:v1:[A-Za-z0-9_-]{43}$/);
    assert.equal(pg.queryParameters.some((params) => params.includes(winner.owner)), false, 'only the keyed owner digest may cross the database boundary');
    const stored = pg.attempts.get(pg.namespaceKey(attempt.tenant_id, attempt.provider_id, attempt.provider_account_id, attempt.environment, attempt.attempt_id));
    assert.ok(stored);
    assert.notEqual(stored.owner_digest, winner.owner);
    assert.match(stored.attempt_digest, /^sha256:[a-f0-9]{64}$/);
});
test('concurrent exact reconciliation is idempotent and persists one bound evidence row', async () => {
    const { pg, store } = storeFixture();
    const attempt = binding();
    const owner = await makeIndeterminate(store, attempt);
    const wrongAttempt = evidence(attempt, 'COMMITTED', { attempt_id: 'attempt:wrong' });
    await assert.rejects(store.reconcile({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
        evidence: wrongAttempt,
    }), /evidence binding is invalid/);
    await assert.rejects(store.reconcile({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
        evidence: evidence(attempt, 'COMMITTED', {
            action_digest: `sha256:${'a'.repeat(64)}`,
        }),
    }), /evidence binding is invalid/);
    await assert.rejects(store.reconcile({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
        evidence: {
            ...evidence(attempt),
            operation_id: undefined,
        },
    }), /evidence operation_id is invalid/);
    const exactEvidence = evidence(attempt);
    const results = await Promise.all(Array.from({ length: 24 }, () => store.reconcile({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
        evidence: exactEvidence,
    })));
    assert.equal(results.filter(Boolean).length, 24);
    assert.equal(pg.evidenceRows.size, 1);
    const stored = pg.attempts.get(pg.namespaceKey(attempt.tenant_id, attempt.provider_id, attempt.provider_account_id, attempt.environment, attempt.attempt_id));
    assert.equal(stored?.state, 'COMMITTED');
    assert.equal(stored?.evidence_digest, exactEvidence.evidence_digest);
    assert.match(stored?.evidence_binding_digest ?? '', /^sha256:[a-f0-9]{64}$/);
    const persisted = [...pg.evidenceRows.values()][0];
    assert.equal(persisted?.operation_id, exactEvidence.operation_id);
    assert.equal(persisted?.caid, exactEvidence.caid);
    assert.equal(persisted?.action_digest, exactEvidence.action_digest);
});
test('tenant and provider/account/environment namespaces are isolated', async () => {
    const { pg, store } = storeFixture();
    const contexts = [
        binding(),
        binding({ tenant_id: 'tenant:beta' }),
        binding({ provider_id: 'provider:adyen' }),
        binding({ provider_account_id: 'account:secondary' }),
        binding({ environment: 'sandbox' }),
    ];
    const owners = await Promise.all(contexts.map((attempt) => reserveOwner(store, attempt)));
    assert.equal(pg.attempts.size, contexts.length);
    for (let index = 0; index < contexts.length; index += 1) {
        const attempt = contexts[index];
        assert.equal(await store.transition({
            tenant_id: attempt.tenant_id,
            attempt_id: attempt.attempt_id,
            owner: owners[index],
            expected_state: 'RESERVED',
            next_state: 'INVOKING',
        }), true);
    }
    const primary = contexts[0];
    assert.equal(await store.transition({
        tenant_id: primary.tenant_id,
        attempt_id: primary.attempt_id,
        owner: owners[1],
        expected_state: 'INVOKING',
        next_state: 'INDETERMINATE',
    }), false);
});
test('exact lookup rediscovers only the authenticated public attempt binding', async () => {
    const { pg, store } = storeFixture();
    const attempt = binding();
    await reserveOwner(store, attempt);
    const lookup = {
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        request_digest: attempt.request_digest,
    };
    assert.deepEqual(await store.lookup(lookup), attempt);
    assert.equal(await store.lookup({ ...lookup, request_digest: DIGESTS.action_digest }), null);
    assert.equal(await store.lookup({ ...lookup, tenant_id: 'tenant-other' }), null);
    assert.equal(pg.queryPrincipals.at(-1), 'executor');
    assert.equal(pg.transactionLog.filter((entry) => (entry === 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')).length, 3);
    assert.equal(pg.attempts.values().next().value?.state, 'RESERVED');
    assert.deepEqual(Object.keys(await store.lookup(lookup) ?? {}).sort(), [
        'attempt_id',
        'environment',
        'provider_account_id',
        'provider_id',
        'request_digest',
        'tenant_id',
    ]);
});
test('lookup fails closed on malformed, mismatched, ambiguous, or overbroad input', async () => {
    const { pg, store } = storeFixture();
    const attempt = binding();
    await reserveOwner(store, attempt);
    const lookup = {
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        request_digest: attempt.request_digest,
    };
    pg.malformNextLookupBinding();
    await assert.rejects(store.lookup(lookup), /malformed Postgres result: lookup binding/);
    await assert.rejects(store.lookup({ ...lookup, attempt_id: attempt.attempt_id }), /attempt lookup is invalid/);
    const duplicate = structuredClone(pg.attempts.values().next().value);
    duplicate.attempt_id = 'attempt-duplicate';
    pg.attempts.set(pg.namespaceKey(duplicate.tenant_id, duplicate.provider_id, duplicate.provider_account_id, duplicate.environment, duplicate.attempt_id), duplicate);
    await assert.rejects(store.lookup(lookup), /malformed Postgres result: lookup/);
});
test('terminal states are immutable and cannot be reopened', async () => {
    const { pg, store } = storeFixture();
    const attempt = binding();
    const owner = await makeIndeterminate(store, attempt);
    assert.equal(await store.transition({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'RELEASED',
    }), true);
    await assert.rejects(store.transition({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'RELEASED',
        next_state: 'RESERVED',
    }), /state transition is invalid/);
    assert.equal(await store.transition({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
    }), false);
    assert.equal([...pg.attempts.values()][0]?.state, 'RELEASED');
});
test('restart recovery requires server authorization, rotates custody, and fences stale owners', async () => {
    const pg = fakePostgres();
    const seen = [];
    const first = storeFixture({ pg });
    const attempt = binding();
    const staleOwner = await makeIndeterminate(first.store, attempt);
    const stored = pg.attempts.get(pg.namespaceKey(attempt.tenant_id, attempt.provider_id, attempt.provider_account_id, attempt.environment, attempt.attempt_id));
    assert.ok(stored);
    stored.last_heartbeat_at = stored.last_heartbeat_at.replace(/(\.\d{3})Z$/, (_match, milliseconds) => `${milliseconds}123Z`);
    stored.lease_expires_at = stored.lease_expires_at.replace(/(\.\d{3})Z$/, (_match, milliseconds) => `${milliseconds}456Z`);
    const nonterminal = await first.store.read({
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        attempt_id: attempt.attempt_id,
        request_digest: attempt.request_digest,
    });
    assert.equal(nonterminal?.state, 'INDETERMINATE');
    assert.equal(nonterminal?.evidence_digest, null);
    assert.match(nonterminal?.last_heartbeat_at ?? '', /\.\d{6}Z$/);
    assert.match(nonterminal?.lease_expires_at ?? '', /\.\d{6}Z$/);
    const restarted = storeFixture({
        pg,
        randomStart: 100,
        authorizeRecovery(authorization) {
            seen.push(structuredClone(authorization));
            assert.equal(Object.hasOwn(authorization, 'owner'), false);
            assert.equal(Object.hasOwn(authorization, 'owner_digest'), false);
            return authorization.state === 'INDETERMINATE'
                && authorization.lease_stale === true
                && authorization.tenant_id === attempt.tenant_id
                && authorization.attempt_id === attempt.attempt_id
                && authorization.request_digest === attempt.request_digest
                && authorization.attempt_digest.startsWith('sha256:');
        },
    });
    pg.advanceTime(30_001);
    const recovered = await restarted.store.recover({
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        attempt_id: attempt.attempt_id,
        request_digest: attempt.request_digest,
    });
    assert.equal(recovered.recovered, true);
    assert.equal(seen.length, 1);
    assert.ok(recovered.recovered);
    assert.notEqual(recovered.owner, staleOwner);
    assert.equal(await first.store.reconcile({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner: staleOwner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
        evidence: evidence(attempt),
    }), false);
    assert.equal(await restarted.store.reconcile({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner: recovered.owner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
        evidence: evidence(attempt),
    }), true);
    const terminal = await restarted.store.read({
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        attempt_id: attempt.attempt_id,
        request_digest: attempt.request_digest,
    });
    assert.ok(terminal);
    const { last_heartbeat_at: terminalHeartbeat, lease_expires_at: terminalLease, lease_stale: terminalLeaseStale, ...terminalBinding } = terminal;
    assert.deepEqual(terminalBinding, {
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        attempt_id: attempt.attempt_id,
        operation_digest: DIGESTS.operation_digest,
        request_digest: attempt.request_digest,
        action_digest: DIGESTS.action_digest,
        config_digest: DIGESTS.config_digest,
        attempt_digest: seen[0].attempt_digest,
        state: 'COMMITTED',
        evidence_digest: evidence(attempt).evidence_digest,
    });
    assert.match(terminalHeartbeat, /^\d{4}-\d{2}-\d{2}T/);
    assert.match(terminalLease, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(terminalLeaseStale, false);
    assert.equal(Object.hasOwn(terminal, 'owner'), false);
    assert.equal(Object.hasOwn(terminal, 'owner_digest'), false);
    assert.equal(await restarted.store.read({
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        attempt_id: attempt.attempt_id,
        request_digest: `sha256:${'f'.repeat(64)}`,
    }), null);
});
test('recovery denial and terminal recovery both fail closed without rotating owners', async () => {
    const pg = fakePostgres();
    const denied = storeFixture({ pg, authorizeRecovery: async () => false });
    const attempt = binding();
    const owner = await makeIndeterminate(denied.store, attempt);
    pg.advanceTime(30_001);
    assert.deepEqual(await denied.store.recover({
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        attempt_id: attempt.attempt_id,
        request_digest: attempt.request_digest,
    }), { recovered: false, reason: 'recovery_not_authorized' });
    assert.equal(await denied.store.transition({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'ESCALATED',
    }), true);
    assert.deepEqual(await denied.store.recover({
        tenant_id: attempt.tenant_id,
        provider_id: attempt.provider_id,
        provider_account_id: attempt.provider_account_id,
        environment: attempt.environment,
        attempt_id: attempt.attempt_id,
        request_digest: attempt.request_digest,
    }), { recovered: false, reason: 'terminal_state_immutable' });
});
test('malformed results roll back atomically and database errors leave custody unchanged', async () => {
    const { pg, store } = storeFixture();
    const attempt = binding();
    const owner = await makeIndeterminate(store, attempt);
    pg.malformAfterNextMutation();
    await assert.rejects(store.reconcile({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED',
        evidence: evidence(attempt),
    }), /malformed Postgres result/);
    assert.equal([...pg.attempts.values()][0]?.state, 'INDETERMINATE');
    assert.equal([...pg.attempts.values()][0]?.evidence_digest, null);
    assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
    pg.failNextMutation();
    await assert.rejects(store.transition({
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner,
        expected_state: 'INDETERMINATE',
        next_state: 'ESCALATED',
    }), /database unavailable/);
    assert.equal([...pg.attempts.values()][0]?.state, 'INDETERMINATE');
    assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
});
