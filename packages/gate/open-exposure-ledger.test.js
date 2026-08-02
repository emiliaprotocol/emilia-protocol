// SPDX-License-Identifier: Apache-2.0
// Generated from open-exposure-ledger.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { createMemoryOpenExposureLedger, } from './open-exposure-ledger.js';
const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const DIGEST_C = `sha256:${'c'.repeat(64)}`;
const DIGEST_D = `sha256:${'d'.repeat(64)}`;
const DIGEST_E = `sha256:${'e'.repeat(64)}`;
const DIGEST_F = `sha256:${'f'.repeat(64)}`;
const DIGEST_0 = `sha256:${'0'.repeat(64)}`;
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const WINDOW_START = '2026-07-01T00:00:00.000Z';
const WINDOW_END = '2026-08-01T00:00:00.000Z';
const DEFAULT_NOW = '2026-07-28T12:01:00.000Z';
function auth(tenantId, role, authorityId) {
    return {
        role,
        authorityId,
        credential: `${tenantId}:${role}:${authorityId}`,
    };
}
function authenticator(input) {
    return input.auth.credential
        === `${input.tenantId}:${input.auth.role}:${input.auth.authorityId}`;
}
function ceiling(scope, scopeValue, limitMinor, tenantId = 'tenant-a') {
    return {
        tenantId,
        ceilingId: `ceiling-${scope.toLowerCase()}-${scopeValue === '*' ? 'all' : scopeValue}`,
        scope,
        scopeValue,
        currency: 'USD',
        windowStart: WINDOW_START,
        windowEnd: WINDOW_END,
        limitMinor,
        policyDigest: DIGEST_A,
    };
}
const CEILINGS = [
    ceiling('TENANT', '*', 100n),
    ceiling('PROGRAM', 'program-a', 100n),
    ceiling('COUNTERPARTY', 'counterparty-a', 100n),
    ceiling('ACTION_CLASS', 'payment.release', 100n),
];
function reservation(exposureId, operationToken, amountMinor, tenantId = 'tenant-a') {
    return {
        tenantId,
        exposureId,
        operationToken,
        programId: 'program-a',
        programVersion: 'program-a@1.0.0',
        programSourceDigest: DIGEST_B,
        programDigest: DIGEST_C,
        caid: CAID,
        actionDigest: DIGEST_D,
        admissionSnapshotDigest: DIGEST_E,
        authorizationDigest: DIGEST_F,
        authorizationExpiresAt: '2026-07-28T12:05:00.000Z',
        counterpartyId: 'counterparty-a',
        actionClass: 'payment.release',
        amountMinor,
        currency: 'USD',
        windowStart: WINDOW_START,
        windowEnd: WINDOW_END,
        reservedAt: '2026-07-28T12:00:00.000Z',
        invokeBy: '2026-07-28T12:05:00.000Z',
        reconcileBy: '2026-07-28T13:00:00.000Z',
        originAuthorityId: 'origin-a',
        executorAuthorityId: 'executor-a',
        reconciliationAuthorityId: 'reconciler-a',
        reservationEvidenceDigest: DIGEST_A,
    };
}
function beginInput(input) {
    return {
        tenantId: input.tenantId,
        exposureId: input.exposureId,
        operationToken: input.operationToken,
        programVersion: input.programVersion,
        programSourceDigest: input.programSourceDigest,
        programDigest: input.programDigest,
        caid: input.caid,
        actionDigest: input.actionDigest,
        admissionSnapshotDigest: input.admissionSnapshotDigest,
        authorizationDigest: input.authorizationDigest,
        authorizationExpiresAt: input.authorizationExpiresAt,
    };
}
test('open exposure refuses ghost state without invoking accessors', async () => {
    const ledger = createMemoryOpenExposureLedger({ authenticate: authenticator, clock: () => DEFAULT_NOW });
    const value = ceiling('TENANT', '*', 100n);
    let getterCalls = 0;
    Object.defineProperty(value, 'scopeValue', {
        enumerable: true,
        get() { getterCalls += 1; return '*'; },
    });
    await assert.rejects(ledger.registerCeiling(value, auth('tenant-a', 'POLICY_ADMIN', 'policy-admin')), /accessors are not permitted/);
    assert.equal(getterCalls, 0);
    const credentials = auth('tenant-a', 'POLICY_ADMIN', 'policy-admin');
    Object.defineProperty(credentials, 'shadow', { value: 'admin', enumerable: false });
    const denied = await ledger.registerCeiling(ceiling('TENANT', '*', 100n), credentials);
    assert.deepEqual(denied, { ok: false, reason: 'unauthenticated' });
});
async function configuredLedger(extraCeilings = [], clock = () => DEFAULT_NOW) {
    const ledger = createMemoryOpenExposureLedger({ authenticate: authenticator, clock });
    for (const configured of [...CEILINGS, ...extraCeilings]) {
        const result = await ledger.registerCeiling(configured, auth(configured.tenantId, 'POLICY_ADMIN', 'policy-admin'));
        assert.equal(result.ok, true);
    }
    return ledger;
}
test('atomic reservations admit one racing operation and refuse oversubscription', async () => {
    const ledger = await configuredLedger();
    const [first, second] = await Promise.all([
        ledger.reserve(reservation('exposure-1', `open-exposure-op:v1:${'1'.repeat(32)}`, 60n), auth('tenant-a', 'ORIGIN', 'origin-a')),
        ledger.reserve(reservation('exposure-2', `open-exposure-op:v1:${'2'.repeat(32)}`, 60n), auth('tenant-a', 'ORIGIN', 'origin-a')),
    ]);
    assert.equal([first, second].filter((result) => result.ok).length, 1);
    assert.deepEqual([first, second].filter((result) => !result.ok).map((result) => result.reason), ['ceiling_exceeded']);
    const sum = await ledger.sumOpen({
        tenantId: 'tenant-a',
        currency: 'USD',
        windowStart: WINDOW_START,
        windowEnd: WINDOW_END,
    }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(sum.ok, true);
    if (sum.ok)
        assert.equal(sum.totalMinor, 60n);
});
test('operation tokens are exact-replay idempotent and conflict on changed semantics', async () => {
    const ledger = await configuredLedger();
    const input = reservation('exposure-replay', `open-exposure-op:v1:${'r'.repeat(32)}`, 40n);
    const caller = auth('tenant-a', 'ORIGIN', 'origin-a');
    const first = await ledger.reserve(input, caller);
    const replay = await ledger.reserve(structuredClone(input), caller);
    const conflict = await ledger.reserve({ ...input, amountMinor: 41n }, caller);
    assert.equal(first.ok, true);
    assert.equal(replay.ok, true);
    if (first.ok && replay.ok) {
        assert.equal(first.replayed, false);
        assert.equal(replay.replayed, true);
        assert.equal(replay.record.recordDigest, first.record.recordDigest);
        assert.equal(replay.record.revision, 0);
    }
    assert.deepEqual(conflict, { ok: false, reason: 'operation_token_conflict' });
});
test('reservation composes immutable execution and authorization pins into record and history', async () => {
    const ledger = await configuredLedger();
    const input = reservation('exposure-binding', `open-exposure-op:v1:${'b'.repeat(32)}`, 20n);
    const result = await ledger.reserve(input, auth('tenant-a', 'ORIGIN', 'origin-a'));
    assert.equal(result.ok, true);
    if (!result.ok)
        return;
    for (const field of [
        'programVersion',
        'programSourceDigest',
        'programDigest',
        'caid',
        'actionDigest',
        'admissionSnapshotDigest',
        'authorizationDigest',
        'authorizationExpiresAt',
    ]) {
        assert.equal(result.record[field], input[field]);
    }
    const history = await ledger.history({ tenantId: input.tenantId, exposureId: input.exposureId }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(history.ok, true);
    if (history.ok) {
        assert.equal(history.entries.length, 1);
        assert.equal(history.entries[0].programVersion, input.programVersion);
        assert.equal(history.entries[0].authorizationDigest, input.authorizationDigest);
        assert.equal(history.entries[0].authorizationExpiresAt, input.authorizationExpiresAt);
        assert.equal(history.entries[0].invocationPermitDigest, null);
    }
});
test('reservation rejects malformed immutable pins and invocation beyond a window or authorization expiry', async () => {
    const ledger = await configuredLedger();
    const base = reservation('exposure-invalid-binding', `open-exposure-op:v1:${'v'.repeat(32)}`, 20n);
    await assert.rejects(ledger.reserve({ ...base, caid: 'caid:invalid' }, auth('tenant-a', 'ORIGIN', 'origin-a')), (error) => error instanceof TypeError
        && 'code' in error && error.code === 'invalid_caid');
    await assert.rejects(ledger.reserve({
        ...base,
        authorizationExpiresAt: '2026-07-28T12:04:00.000Z',
        invokeBy: '2026-07-28T12:05:00.000Z',
    }, auth('tenant-a', 'ORIGIN', 'origin-a')), (error) => error instanceof TypeError
        && 'code' in error && error.code === 'invalid_time');
    await assert.rejects(ledger.reserve({ ...base, invokeBy: '2026-08-01T00:00:00.001Z' }, auth('tenant-a', 'ORIGIN', 'origin-a')), (error) => error instanceof TypeError
        && 'code' in error && error.code === 'invalid_time');
});
test('tenant authentication prevents cross-tenant reads and token collisions remain tenant scoped', async () => {
    const tenantBCeilings = CEILINGS.map((entry) => ({
        ...entry,
        tenantId: 'tenant-b',
        ceilingId: `${entry.ceilingId}-tenant-b`,
    }));
    const ledger = await configuredLedger(tenantBCeilings);
    const token = `open-exposure-op:v1:${'t'.repeat(32)}`;
    const tenantA = await ledger.reserve(reservation('exposure-a', token, 25n), auth('tenant-a', 'ORIGIN', 'origin-a'));
    const tenantB = await ledger.reserve({
        ...reservation('exposure-b', token, 35n, 'tenant-b'),
        originAuthorityId: 'origin-b',
        executorAuthorityId: 'executor-b',
        reconciliationAuthorityId: 'reconciler-b',
    }, auth('tenant-b', 'ORIGIN', 'origin-b'));
    assert.equal(tenantA.ok, true);
    assert.equal(tenantB.ok, true);
    const crossed = await ledger.read({ tenantId: 'tenant-a', exposureId: 'exposure-a' }, auth('tenant-b', 'READER', 'risk-reader'));
    assert.deepEqual(crossed, { ok: false, reason: 'unauthenticated' });
    const sumB = await ledger.sumOpen({
        tenantId: 'tenant-b',
        currency: 'USD',
        windowStart: WINDOW_START,
        windowEnd: WINDOW_END,
    }, auth('tenant-b', 'READER', 'risk-reader'));
    assert.equal(sumB.ok, true);
    if (sumB.ok)
        assert.equal(sumB.totalMinor, 35n);
});
test('origin, executor, and reconciliation authorities are distinct and role-bound', async () => {
    const ledger = await configuredLedger();
    const token = `open-exposure-op:v1:${'a'.repeat(32)}`;
    const invalid = await ledger.reserve({
        ...reservation('exposure-invalid-authorities', token, 10n),
        reconciliationAuthorityId: 'executor-a',
    }, auth('tenant-a', 'ORIGIN', 'origin-a'));
    assert.deepEqual(invalid, { ok: false, reason: 'authority_separation_required' });
    const reserved = await ledger.reserve(reservation('exposure-authorities', token, 10n), auth('tenant-a', 'ORIGIN', 'origin-a'));
    assert.equal(reserved.ok, true);
    const invocation = beginInput(reservation('exposure-authorities', token, 10n));
    const wrongBegin = await ledger.beginInvocation(invocation, auth('tenant-a', 'ORIGIN', 'origin-a'));
    assert.deepEqual(wrongBegin, { ok: false, reason: 'wrong_authority' });
    const begun = await ledger.beginInvocation(invocation, auth('tenant-a', 'EXECUTOR', 'executor-a'));
    assert.equal(begun.ok, true);
    const wrongClose = await ledger.reconcile({
        tenantId: 'tenant-a',
        exposureId: 'exposure-authorities',
        operationToken: token,
        reconciliationToken: `open-exposure-reconcile:v1:${'x'.repeat(32)}`,
        outcome: 'COMMITTED',
        evidenceDigest: DIGEST_B,
        observedAt: '2026-07-28T12:02:00.000Z',
    }, auth('tenant-a', 'EXECUTOR', 'executor-a'));
    assert.deepEqual(wrongClose, { ok: false, reason: 'wrong_authority' });
});
test('parallel beginInvocation issues exactly one bound one-use effect-entry permit', async () => {
    const ledger = await configuredLedger();
    const input = reservation('exposure-permit-race', `open-exposure-op:v1:${'p'.repeat(32)}`, 25n);
    assert.equal((await ledger.reserve(input, auth('tenant-a', 'ORIGIN', 'origin-a'))).ok, true);
    const request = beginInput(input);
    const [first, second] = await Promise.all([
        ledger.beginInvocation(request, auth('tenant-a', 'EXECUTOR', 'executor-a')),
        ledger.beginInvocation(structuredClone(request), auth('tenant-a', 'EXECUTOR', 'executor-a')),
    ]);
    const authorized = [first, second].filter((result) => result.ok);
    const refused = [first, second].filter((result) => !result.ok);
    assert.equal(authorized.length, 1);
    assert.deepEqual(refused, [{ ok: false, reason: 'reconciliation_required' }]);
    if (!authorized[0].ok)
        return;
    assert.equal(authorized[0].replayed, false);
    assert.match(authorized[0].invocationPermit, /^open-exposure-invoke:v1:[0-9a-f]{64}$/);
    assert.match(authorized[0].record.invocationPermitDigest ?? '', /^sha256:[0-9a-f]{64}$/);
    const replay = await ledger.beginInvocation(request, auth('tenant-a', 'EXECUTOR', 'executor-a'));
    assert.deepEqual(replay, { ok: false, reason: 'reconciliation_required' });
    const history = await ledger.history({ tenantId: input.tenantId, exposureId: input.exposureId }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(history.ok, true);
    if (history.ok) {
        assert.deepEqual(history.entries.map((entry) => entry.event), ['RESERVED', 'INVOKING']);
        assert.equal(history.entries[1].invocationPermitDigest, authorized[0].record.invocationPermitDigest);
    }
});
test('beginInvocation uses the injected monotonic clock, rejects expiry, and rechecks every immutable pin', async () => {
    const expiredLedger = await configuredLedger([], () => '2026-07-28T12:05:00.001Z');
    const expired = reservation('exposure-expired', `open-exposure-op:v1:${'e'.repeat(32)}`, 10n);
    assert.equal((await expiredLedger.reserve(expired, auth('tenant-a', 'ORIGIN', 'origin-a'))).ok, true);
    assert.deepEqual(await expiredLedger.beginInvocation(beginInput(expired), auth('tenant-a', 'EXECUTOR', 'executor-a')), { ok: false, reason: 'invocation_expired' });
    let now = '2026-07-28T12:01:00.000Z';
    const ledger = await configuredLedger([], () => now);
    const bound = reservation('exposure-pin-check', `open-exposure-op:v1:${'m'.repeat(32)}`, 10n);
    const clockGuard = reservation('exposure-clock-guard', `open-exposure-op:v1:${'g'.repeat(32)}`, 10n);
    assert.equal((await ledger.reserve(bound, auth('tenant-a', 'ORIGIN', 'origin-a'))).ok, true);
    assert.equal((await ledger.reserve(clockGuard, auth('tenant-a', 'ORIGIN', 'origin-a'))).ok, true);
    assert.deepEqual(await ledger.beginInvocation({ ...beginInput(bound), actionDigest: DIGEST_0 }, auth('tenant-a', 'EXECUTOR', 'executor-a')), { ok: false, reason: 'immutable_binding_conflict' });
    const read = await ledger.read({ tenantId: bound.tenantId, exposureId: bound.exposureId }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(read.ok, true);
    if (read.ok)
        assert.equal(read.record?.status, 'RESERVED');
    assert.equal((await ledger.beginInvocation(beginInput(bound), auth('tenant-a', 'EXECUTOR', 'executor-a'))).ok, true);
    now = '2026-07-28T12:00:59.999Z';
    await assert.rejects(ledger.beginInvocation(beginInput(clockGuard), auth('tenant-a', 'EXECUTOR', 'executor-a')), (error) => error instanceof TypeError
        && 'code' in error && error.code === 'clock_regressed');
});
test('indeterminate custody stays open, blocks blind invocation retry, and closes only on authenticated evidence', async () => {
    const ledger = await configuredLedger();
    const token = `open-exposure-op:v1:${'i'.repeat(32)}`;
    const exposureId = 'exposure-indeterminate';
    assert.equal((await ledger.reserve(reservation(exposureId, token, 45n), auth('tenant-a', 'ORIGIN', 'origin-a'))).ok, true);
    const invocation = beginInput(reservation(exposureId, token, 45n));
    assert.equal((await ledger.beginInvocation(invocation, auth('tenant-a', 'EXECUTOR', 'executor-a'))).ok, true);
    assert.equal((await ledger.markIndeterminate({
        tenantId: 'tenant-a', exposureId, operationToken: token,
        evidenceDigest: DIGEST_B,
        observedAt: '2026-07-28T12:02:00.000Z',
    }, auth('tenant-a', 'EXECUTOR', 'executor-a'))).ok, true);
    const blindRetry = await ledger.beginInvocation(invocation, auth('tenant-a', 'EXECUTOR', 'executor-a'));
    assert.deepEqual(blindRetry, { ok: false, reason: 'reconciliation_required' });
    const stillUnknown = await ledger.reconcile({
        tenantId: 'tenant-a', exposureId, operationToken: token,
        reconciliationToken: `open-exposure-reconcile:v1:${'1'.repeat(32)}`,
        outcome: 'INDETERMINATE', evidenceDigest: DIGEST_C,
        observedAt: '2026-07-28T12:10:00.000Z',
    }, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
    assert.equal(stillUnknown.ok, true);
    if (stillUnknown.ok)
        assert.equal(stillUnknown.record.status, 'INDETERMINATE');
    const sumWhileUnknown = await ledger.sumOpen({
        tenantId: 'tenant-a', currency: 'USD',
        windowStart: WINDOW_START, windowEnd: WINDOW_END,
    }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(sumWhileUnknown.ok, true);
    if (sumWhileUnknown.ok)
        assert.equal(sumWhileUnknown.totalMinor, 45n);
    const closed = await ledger.reconcile({
        tenantId: 'tenant-a', exposureId, operationToken: token,
        reconciliationToken: `open-exposure-reconcile:v1:${'2'.repeat(32)}`,
        outcome: 'COMMITTED', evidenceDigest: DIGEST_A,
        observedAt: '2026-07-28T12:20:00.000Z',
    }, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
    assert.equal(closed.ok, true);
    if (closed.ok)
        assert.equal(closed.record.status, 'CLOSED_COMMITTED');
});
test('closeout replay cannot underflow deterministic open sums and history is immutable', async () => {
    const ledger = await configuredLedger();
    const token = `open-exposure-op:v1:${'u'.repeat(32)}`;
    const reconcileToken = `open-exposure-reconcile:v1:${'u'.repeat(32)}`;
    const exposureId = 'exposure-underflow';
    await ledger.reserve(reservation(exposureId, token, 30n), auth('tenant-a', 'ORIGIN', 'origin-a'));
    const request = {
        tenantId: 'tenant-a', exposureId, operationToken: token,
        reconciliationToken: reconcileToken,
        outcome: 'PROVEN_NOT_COMMITTED',
        evidenceDigest: DIGEST_B,
        observedAt: '2026-07-28T12:30:00.000Z',
    };
    const first = await ledger.reconcile(request, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
    const replay = await ledger.reconcile(structuredClone(request), auth('tenant-a', 'RECONCILER', 'reconciler-a'));
    const conflict = await ledger.reconcile({ ...request, outcome: 'COMMITTED' }, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
    assert.equal(first.ok, true);
    assert.equal(replay.ok, true);
    if (replay.ok)
        assert.equal(replay.replayed, true);
    assert.deepEqual(conflict, { ok: false, reason: 'reconciliation_token_conflict' });
    const sum = await ledger.sumOpen({
        tenantId: 'tenant-a', currency: 'USD',
        windowStart: WINDOW_START, windowEnd: WINDOW_END,
    }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(sum.ok, true);
    if (sum.ok) {
        assert.equal(sum.totalMinor, 0n);
        assert.deepEqual(sum.byProgram, []);
    }
    const history = await ledger.history({ tenantId: 'tenant-a', exposureId }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(history.ok, true);
    if (history.ok) {
        assert.deepEqual(history.entries.map((entry) => entry.event), [
            'RESERVED', 'CLOSED_PROVEN_NOT_COMMITTED',
        ]);
        assert.ok(history.entries.every(Object.isFrozen));
        assert.throws(() => {
            history.entries.push({});
        }, TypeError);
    }
});
test('aging and deadline queries are tenant-scoped and deterministically ordered', async () => {
    const ledger = await configuredLedger();
    const older = reservation('exposure-old', `open-exposure-op:v1:${'o'.repeat(32)}`, 10n);
    const newer = reservation('exposure-new', `open-exposure-op:v1:${'n'.repeat(32)}`, 15n);
    await ledger.reserve({
        ...newer,
        reservedAt: '2026-07-28T12:02:00.000Z',
        invokeBy: '2026-07-28T12:04:00.000Z',
    }, auth('tenant-a', 'ORIGIN', 'origin-a'));
    await ledger.reserve({
        ...older,
        reservedAt: '2026-07-28T12:00:00.000Z',
        invokeBy: '2026-07-28T12:03:00.000Z',
    }, auth('tenant-a', 'ORIGIN', 'origin-a'));
    const aging = await ledger.listAging({
        tenantId: 'tenant-a',
        asOf: '2026-07-28T12:10:00.000Z',
        minimumAgeMs: 8 * 60_000,
        limit: 10,
    }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(aging.ok, true);
    if (aging.ok)
        assert.deepEqual(aging.records.map((record) => record.exposureId), ['exposure-old', 'exposure-new']);
    const due = await ledger.listDeadlines({
        tenantId: 'tenant-a',
        dueAtOrBefore: '2026-07-28T12:04:00.000Z',
        limit: 10,
    }, auth('tenant-a', 'READER', 'risk-reader'));
    assert.equal(due.ok, true);
    if (due.ok)
        assert.deepEqual(due.records.map((record) => record.exposureId), ['exposure-old', 'exposure-new']);
});
test('tenant-wide read, history, sum, aging, and deadline surfaces are READER-only', async () => {
    const ledger = await configuredLedger();
    const input = reservation('exposure-reader-only', `open-exposure-op:v1:${'q'.repeat(32)}`, 10n);
    assert.equal((await ledger.reserve(input, auth('tenant-a', 'ORIGIN', 'origin-a'))).ok, true);
    const executor = auth('tenant-a', 'EXECUTOR', 'executor-a');
    const reconciler = auth('tenant-a', 'RECONCILER', 'reconciler-a');
    assert.deepEqual(await ledger.read({ tenantId: input.tenantId, exposureId: input.exposureId }, executor), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.history({ tenantId: input.tenantId, exposureId: input.exposureId }, reconciler), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.sumOpen({
        tenantId: input.tenantId,
        currency: input.currency,
        windowStart: input.windowStart,
        windowEnd: input.windowEnd,
    }, executor), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.listAging({
        tenantId: input.tenantId,
        asOf: '2026-07-28T12:10:00.000Z',
        minimumAgeMs: 0,
        limit: 10,
    }, reconciler), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.listDeadlines({
        tenantId: input.tenantId,
        dueAtOrBefore: input.invokeBy,
        limit: 10,
    }, executor), { ok: false, reason: 'wrong_authority' });
});
