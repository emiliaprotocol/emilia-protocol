// SPDX-License-Identifier: Apache-2.0
// Generated from open-exposure-ledger-postgres.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createOpenExposurePostgresLedger, OPEN_EXPOSURE_POSTGRES_SQL, OpenExposurePostgresProtocolError, } from './open-exposure-ledger-postgres.js';
const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const DIGEST_C = `sha256:${'c'.repeat(64)}`;
const DIGEST_D = `sha256:${'d'.repeat(64)}`;
const DIGEST_E = `sha256:${'e'.repeat(64)}`;
const DIGEST_F = `sha256:${'f'.repeat(64)}`;
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const WINDOW_START = '2026-07-01T00:00:00.000Z';
const WINDOW_END = '2026-08-01T00:00:00.000Z';
function auth(role, authorityId) {
    return { role, authorityId, credential: 'postgres-session' };
}
const CEILING = {
    tenantId: 'tenant-a',
    ceilingId: 'tenant-usd-july',
    scope: 'TENANT',
    scopeValue: '*',
    currency: 'USD',
    windowStart: WINDOW_START,
    windowEnd: WINDOW_END,
    limitMinor: 100n,
    policyDigest: DIGEST_A,
};
const RESERVATION = {
    tenantId: 'tenant-a',
    exposureId: 'exposure-a',
    operationToken: `open-exposure-op:v1:${'o'.repeat(32)}`,
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
    amountMinor: 60n,
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
function wireRecord(overrides = {}) {
    return {
        version: 'EP-OPEN-EXPOSURE-LEDGER-v1',
        tenant_id: 'tenant-a',
        exposure_id: 'exposure-a',
        operation_token_digest: DIGEST_A,
        reservation_digest: DIGEST_B,
        program_id: 'program-a',
        program_version: 'program-a@1.0.0',
        program_source_digest: DIGEST_B,
        program_digest: DIGEST_C,
        caid: CAID,
        action_digest: DIGEST_D,
        admission_snapshot_digest: DIGEST_E,
        authorization_digest: DIGEST_F,
        authorization_expires_at: '2026-07-28T12:05:00.000Z',
        counterparty_id: 'counterparty-a',
        action_class: 'payment.release',
        amount_minor: '60',
        currency: 'USD',
        window_start: WINDOW_START,
        window_end: WINDOW_END,
        reserved_at: '2026-07-28T12:00:00.000Z',
        invoke_by: '2026-07-28T12:05:00.000Z',
        reconcile_by: '2026-07-28T13:00:00.000Z',
        origin_authority_id: 'origin-a',
        executor_authority_id: 'executor-a',
        reconciliation_authority_id: 'reconciler-a',
        reservation_evidence_digest: DIGEST_A,
        ceiling_digests: [DIGEST_A],
        revision: 0,
        status: 'RESERVED',
        invoked_at: null,
        invocation_permit_digest: null,
        indeterminate_evidence_digest: null,
        reconciliation_outcome: null,
        reconciliation_evidence_digest: null,
        last_changed_at: '2026-07-28T12:00:00.000Z',
        predecessor_record_digest: null,
        record_digest: DIGEST_B,
        ...overrides,
    };
}
function invocationInput() {
    return {
        tenantId: RESERVATION.tenantId,
        exposureId: RESERVATION.exposureId,
        operationToken: RESERVATION.operationToken,
        programVersion: RESERVATION.programVersion,
        programSourceDigest: RESERVATION.programSourceDigest,
        programDigest: RESERVATION.programDigest,
        caid: RESERVATION.caid,
        actionDigest: RESERVATION.actionDigest,
        admissionSnapshotDigest: RESERVATION.admissionSnapshotDigest,
        authorizationDigest: RESERVATION.authorizationDigest,
        authorizationExpiresAt: RESERVATION.authorizationExpiresAt,
    };
}
test('reserve sends one credential-free RPC payload and parses fixed minor units', async () => {
    const calls = [];
    const query = async (text, params) => {
        calls.push({ text, params });
        return {
            rowCount: 1,
            rows: [{ result: { ok: true, replayed: false, record: wireRecord() } }],
        };
    };
    const ledger = createOpenExposurePostgresLedger({ query, tenantId: 'tenant-a' });
    const result = await ledger.reserve(RESERVATION, auth('ORIGIN', 'origin-a'));
    assert.equal(result.ok, true);
    if (result.ok) {
        assert.equal(result.record.amountMinor, 60n);
        assert.equal(result.record.status, 'RESERVED');
        assert.ok(Object.isFrozen(result.record));
    }
    assert.equal(calls.length, 1);
    assert.equal(calls[0].text, OPEN_EXPOSURE_POSTGRES_SQL.reserve);
    assert.equal(calls[0].params.length, 1);
    const payload = JSON.parse(String(calls[0].params[0]));
    assert.equal(payload.amount_minor, '60');
    assert.equal(payload.authority_id, 'origin-a');
    assert.equal(payload.program_version, RESERVATION.programVersion);
    assert.equal(payload.program_source_digest, RESERVATION.programSourceDigest);
    assert.equal(payload.program_digest, RESERVATION.programDigest);
    assert.equal(payload.caid, RESERVATION.caid);
    assert.equal(payload.action_digest, RESERVATION.actionDigest);
    assert.equal(payload.admission_snapshot_digest, RESERVATION.admissionSnapshotDigest);
    assert.equal(payload.authorization_digest, RESERVATION.authorizationDigest);
    assert.equal(payload.authorization_expires_at, RESERVATION.authorizationExpiresAt);
    assert.equal(payload.operation_token, undefined);
    assert.match(payload.operation_token_digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(payload).includes('postgres-session'), false);
});
test('beginInvocation sends exact immutable pins without caller time and parses a one-use permit', async () => {
    const calls = [];
    const permit = `open-exposure-invoke:v1:${'1'.repeat(64)}`;
    const query = async (text, params) => {
        calls.push({ text, params });
        return {
            rowCount: 1,
            rows: [{ result: {
                        ok: true,
                        replayed: false,
                        invocation_permit: permit,
                        record: wireRecord({
                            status: 'INVOKING',
                            revision: 1,
                            invoked_at: '2026-07-28T12:01:00.000Z',
                            invocation_permit_digest: DIGEST_A,
                        }),
                    } }],
        };
    };
    const ledger = createOpenExposurePostgresLedger({ query, tenantId: 'tenant-a' });
    const result = await ledger.beginInvocation(invocationInput(), auth('EXECUTOR', 'executor-a'));
    assert.equal(result.ok, true);
    if (result.ok) {
        assert.equal(result.replayed, false);
        assert.equal(result.invocationPermit, permit);
        assert.equal(result.record.invocationPermitDigest, DIGEST_A);
    }
    assert.equal(calls[0].text, OPEN_EXPOSURE_POSTGRES_SQL.beginInvocation);
    const payload = JSON.parse(String(calls[0].params[0]));
    assert.equal(payload.invoked_at, undefined);
    assert.equal(payload.program_version, RESERVATION.programVersion);
    assert.equal(payload.program_source_digest, RESERVATION.programSourceDigest);
    assert.equal(payload.program_digest, RESERVATION.programDigest);
    assert.equal(payload.caid, RESERVATION.caid);
    assert.equal(payload.action_digest, RESERVATION.actionDigest);
    assert.equal(payload.admission_snapshot_digest, RESERVATION.admissionSnapshotDigest);
    assert.equal(payload.authorization_digest, RESERVATION.authorizationDigest);
    assert.equal(payload.authorization_expires_at, RESERVATION.authorizationExpiresAt);
});
test('adapter permits only READER on tenant-wide query surfaces before SQL', async () => {
    let calls = 0;
    const ledger = createOpenExposurePostgresLedger({
        tenantId: 'tenant-a',
        query: async () => {
            calls += 1;
            return { rowCount: 1, rows: [{ result: { ok: false, reason: 'wrong_authority' } }] };
        },
    });
    const executor = auth('EXECUTOR', 'executor-a');
    const reconciler = auth('RECONCILER', 'reconciler-a');
    assert.deepEqual(await ledger.read({
        tenantId: 'tenant-a', exposureId: 'exposure-a',
    }, executor), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.history({
        tenantId: 'tenant-a', exposureId: 'exposure-a',
    }, reconciler), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.sumOpen({
        tenantId: 'tenant-a', currency: 'USD',
        windowStart: WINDOW_START, windowEnd: WINDOW_END,
    }, executor), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.listAging({
        tenantId: 'tenant-a', asOf: '2026-07-28T12:10:00.000Z',
        minimumAgeMs: 0, limit: 10,
    }, reconciler), { ok: false, reason: 'wrong_authority' });
    assert.deepEqual(await ledger.listDeadlines({
        tenantId: 'tenant-a', dueAtOrBefore: '2026-07-28T12:05:00.000Z', limit: 10,
    }, executor), { ok: false, reason: 'wrong_authority' });
    assert.equal(calls, 0);
});
test('adapter is deployment-tenant bound and refuses cross-tenant access before SQL', async () => {
    let calls = 0;
    const ledger = createOpenExposurePostgresLedger({
        tenantId: 'tenant-a',
        query: async () => {
            calls += 1;
            return { rowCount: 0, rows: [] };
        },
    });
    const result = await ledger.read({ tenantId: 'tenant-b', exposureId: 'exposure-a' }, auth('READER', 'reader-b'));
    assert.deepEqual(result, { ok: false, reason: 'unauthenticated' });
    assert.equal(calls, 0);
});
test('adapter enforces operation role separation before a database call', async () => {
    let calls = 0;
    const ledger = createOpenExposurePostgresLedger({
        tenantId: 'tenant-a',
        query: async () => {
            calls += 1;
            return { rowCount: 0, rows: [] };
        },
    });
    const result = await ledger.reconcile({
        tenantId: 'tenant-a',
        exposureId: 'exposure-a',
        operationToken: RESERVATION.operationToken,
        reconciliationToken: `open-exposure-reconcile:v1:${'r'.repeat(32)}`,
        outcome: 'COMMITTED',
        evidenceDigest: DIGEST_B,
        observedAt: '2026-07-28T12:10:00.000Z',
    }, auth('EXECUTOR', 'executor-a'));
    assert.deepEqual(result, { ok: false, reason: 'wrong_authority' });
    assert.equal(calls, 0);
});
test('business refusals are closed results while malformed database records fail closed', async () => {
    let mode = 'refusal';
    const query = async () => ({
        rowCount: 1,
        rows: [{ result: mode === 'refusal'
                    ? { ok: false, reason: 'ceiling_exceeded' }
                    : { ok: true, replayed: false, record: wireRecord({ amount_minor: '-1' }) } }],
    });
    const ledger = createOpenExposurePostgresLedger({ query, tenantId: 'tenant-a' });
    assert.deepEqual(await ledger.reserve(RESERVATION, auth('ORIGIN', 'origin-a')), { ok: false, reason: 'ceiling_exceeded' });
    mode = 'malformed';
    await assert.rejects(ledger.reserve(RESERVATION, auth('ORIGIN', 'origin-a')), OpenExposurePostgresProtocolError);
});
test('register ceiling is create-only and carries bigint and policy digest without a session credential', async () => {
    const calls = [];
    const query = async (text, params) => {
        calls.push({ text, params });
        return {
            rowCount: 1,
            rows: [{ result: {
                        ok: true,
                        replayed: false,
                        ceiling: {
                            version: 'EP-OPEN-EXPOSURE-LEDGER-v1',
                            tenant_id: CEILING.tenantId,
                            ceiling_id: CEILING.ceilingId,
                            scope: CEILING.scope,
                            scope_value: CEILING.scopeValue,
                            currency: CEILING.currency,
                            window_start: CEILING.windowStart,
                            window_end: CEILING.windowEnd,
                            limit_minor: '100',
                            policy_digest: CEILING.policyDigest,
                            ceiling_digest: DIGEST_B,
                        },
                    } }],
        };
    };
    const ledger = createOpenExposurePostgresLedger({ query, tenantId: 'tenant-a' });
    const result = await ledger.registerCeiling(CEILING, auth('POLICY_ADMIN', 'policy-admin-a'));
    assert.equal(result.ok, true);
    if (result.ok)
        assert.equal(result.ceiling.limitMinor, 100n);
    assert.equal(calls[0].text, OPEN_EXPOSURE_POSTGRES_SQL.registerCeiling);
    const payload = JSON.parse(String(calls[0].params[0]));
    assert.equal(payload.limit_minor, '100');
    assert.equal(payload.policy_digest, DIGEST_A);
    assert.equal(JSON.stringify(payload).includes('postgres-session'), false);
});
test('migration enforces RPC-only custody, immutable history, open-status sums, and locked ceilings', () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const migration = fs.readFileSync(path.join(here, '../../supabase/migrations/20260728210700_open_exposure_ledger.sql'), 'utf8');
    assert.match(migration, /CREATE ROLE ep_open_exposure_store_owner NOLOGIN/);
    assert.match(migration, /CREATE ROLE ep_open_exposure_origin NOLOGIN/);
    assert.match(migration, /CREATE ROLE ep_open_exposure_executor NOLOGIN/);
    assert.match(migration, /CREATE ROLE ep_open_exposure_reconciler NOLOGIN/);
    assert.match(migration, /CREATE ROLE ep_open_exposure_policy_admin NOLOGIN/);
    assert.match(migration, /CREATE ROLE ep_open_exposure_reader NOLOGIN/);
    assert.match(migration, /NOBYPASSRLS/);
    assert.match(migration, /ENABLE ROW LEVEL SECURITY/g);
    assert.match(migration, /FORCE ROW LEVEL SECURITY/g);
    assert.match(migration, /SESSION_USER/);
    assert.match(migration, /authority_kind/);
    assert.match(migration, /origin_authority_id <> executor_authority_id/);
    assert.match(migration, /reconciliation_authority_id <> origin_authority_id/);
    assert.match(migration, /reconciliation_authority_id <> executor_authority_id/);
    assert.match(migration, /status IN \('RESERVED', 'INVOKING', 'INDETERMINATE'\)/);
    for (const field of [
        'program_version',
        'program_source_digest',
        'program_digest',
        'caid',
        'action_digest',
        'admission_snapshot_digest',
        'authorization_digest',
        'authorization_expires_at',
        'invocation_permit_digest',
    ])
        assert.match(migration, new RegExp(`\\b${field}\\b`));
    assert.match(migration, /invoke_by <= window_end/);
    assert.match(migration, /invoke_by <= authorization_expires_at/);
    assert.match(migration, /extensions\.gen_random_bytes\(INTEGER\)/);
    assert.match(migration, /begin_invocation[\s\S]+transaction_timestamp\(\)/);
    assert.match(migration, /status = 'INVOKING'[\s\S]+reconciliation_required/);
    assert.match(migration, /ORDER BY ceilings\.scope, ceilings\.scope_value[\s\S]+FOR UPDATE/);
    assert.match(migration, /COALESCE\(SUM\(exposures\.amount_minor\), 0\)/);
    assert.match(migration, /BEFORE UPDATE OR DELETE ON open_exposure_private\.history/);
    assert.match(migration, /CREATE INDEX[\s\S]+tenant_id, currency, window_start, window_end/);
    assert.match(migration, /WHERE status IN \('RESERVED', 'INVOKING', 'INDETERMINATE'\)/);
    assert.match(migration, /CREATE INDEX[\s\S]+tenant_id, status, reserved_at, exposure_id/);
    assert.match(migration, /CREATE INDEX[\s\S]+tenant_id, status, invoke_by, reconcile_by/);
    assert.match(migration, /REVOKE ALL ON ALL TABLES IN SCHEMA open_exposure_private[\s\S]+service_role/);
    assert.match(migration, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA open_exposure_private[\s\S]+service_role/);
    const privateGrants = migration.match(/GRANT[^;]+(?:SCHEMA open_exposure_private|open_exposure_private\.)[^;]+;/g) ?? [];
    for (const grant of privateGrants) {
        assert.doesNotMatch(grant, /TO[^;]*\bservice_role\b/);
    }
    assert.doesNotMatch(migration, /open_exposure_(?:blind_)?release/i);
    assert.match(migration, /GRANT EXECUTE ON FUNCTION open_exposure_private\.reserve\(JSONB\)[\s\S]+TO ep_open_exposure_origin/);
    assert.match(migration, /GRANT EXECUTE ON FUNCTION open_exposure_private\.reconcile\(JSONB\)[\s\S]+TO ep_open_exposure_reconciler/);
    const grants = migration.match(/GRANT EXECUTE ON FUNCTION[\s\S]*?;/g) ?? [];
    for (const functionName of [
        'read_exposure', 'read_history', 'sum_open', 'list_aging', 'list_deadlines',
    ]) {
        const grant = grants.find((statement) => statement.includes(`.${functionName}(JSONB)`));
        assert.ok(grant, `missing grant for ${functionName}`);
        assert.match(grant, /TO ep_open_exposure_reader/);
        assert.doesNotMatch(grant, /ep_open_exposure_(?:origin|executor|reconciler)/);
    }
});
test('PostgreSQL surface contains no blind release operation', () => {
    assert.deepEqual(Object.keys(OPEN_EXPOSURE_POSTGRES_SQL).sort(), [
        'beginInvocation',
        'history',
        'listAging',
        'listDeadlines',
        'markIndeterminate',
        'read',
        'reconcile',
        'registerCeiling',
        'reserve',
        'sumOpen',
    ]);
});
