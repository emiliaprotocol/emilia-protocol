// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createOpenExposurePostgresLedger,
  OPEN_EXPOSURE_POSTGRES_SQL,
  OpenExposurePostgresProtocolError,
  type OpenExposurePostgresQuery,
} from './open-exposure-ledger-postgres.js';
import type {
  OpenExposureAuth,
  OpenExposureCeilingInput,
  OpenExposureReserveInput,
} from './open-exposure-ledger.js';

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const WINDOW_START = '2026-07-01T00:00:00.000Z';
const WINDOW_END = '2026-08-01T00:00:00.000Z';

function auth(role: OpenExposureAuth['role'], authorityId: string): OpenExposureAuth {
  return { role, authorityId, credential: 'postgres-session' };
}

const CEILING: OpenExposureCeilingInput = {
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

const RESERVATION: OpenExposureReserveInput = {
  tenantId: 'tenant-a',
  exposureId: 'exposure-a',
  operationToken: `open-exposure-op:v1:${'o'.repeat(32)}`,
  programId: 'program-a',
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

function wireRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 'EP-OPEN-EXPOSURE-LEDGER-v1',
    tenant_id: 'tenant-a',
    exposure_id: 'exposure-a',
    operation_token_digest: DIGEST_A,
    reservation_digest: DIGEST_B,
    program_id: 'program-a',
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
    indeterminate_evidence_digest: null,
    reconciliation_outcome: null,
    reconciliation_evidence_digest: null,
    last_changed_at: '2026-07-28T12:00:00.000Z',
    predecessor_record_digest: null,
    record_digest: DIGEST_B,
    ...overrides,
  };
}

test('reserve sends one credential-free RPC payload and parses fixed minor units', async () => {
  const calls: Array<{ text: string; params: readonly unknown[] }> = [];
  const query: OpenExposurePostgresQuery = async (text, params) => {
    calls.push({ text, params });
    return {
      rowCount: 1,
      rows: [{ result: { ok: true, replayed: false, record: wireRecord() } }],
    };
  };
  const ledger = createOpenExposurePostgresLedger({ query, tenantId: 'tenant-a' });

  const result = await ledger.reserve(
    RESERVATION,
    auth('ORIGIN', 'origin-a'),
  );

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
  assert.equal(payload.operation_token, undefined);
  assert.match(payload.operation_token_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(payload).includes('postgres-session'), false);
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

  const result = await ledger.read(
    { tenantId: 'tenant-b', exposureId: 'exposure-a' },
    auth('READER', 'reader-b'),
  );
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
  let mode: 'refusal' | 'malformed' = 'refusal';
  const query: OpenExposurePostgresQuery = async () => ({
    rowCount: 1,
    rows: [{ result: mode === 'refusal'
      ? { ok: false, reason: 'ceiling_exceeded' }
      : { ok: true, replayed: false, record: wireRecord({ amount_minor: '-1' }) } }],
  });
  const ledger = createOpenExposurePostgresLedger({ query, tenantId: 'tenant-a' });

  assert.deepEqual(
    await ledger.reserve(RESERVATION, auth('ORIGIN', 'origin-a')),
    { ok: false, reason: 'ceiling_exceeded' },
  );
  mode = 'malformed';
  await assert.rejects(
    ledger.reserve(RESERVATION, auth('ORIGIN', 'origin-a')),
    OpenExposurePostgresProtocolError,
  );
});

test('register ceiling is create-only and carries bigint and policy digest without a session credential', async () => {
  const calls: Array<{ text: string; params: readonly unknown[] }> = [];
  const query: OpenExposurePostgresQuery = async (text, params) => {
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
  const result = await ledger.registerCeiling(
    CEILING,
    auth('POLICY_ADMIN', 'policy-admin-a'),
  );
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.ceiling.limitMinor, 100n);
  assert.equal(calls[0].text, OPEN_EXPOSURE_POSTGRES_SQL.registerCeiling);
  const payload = JSON.parse(String(calls[0].params[0]));
  assert.equal(payload.limit_minor, '100');
  assert.equal(payload.policy_digest, DIGEST_A);
  assert.equal(JSON.stringify(payload).includes('postgres-session'), false);
});

test('migration enforces RPC-only custody, immutable history, open-status sums, and locked ceilings', () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const migration = fs.readFileSync(path.join(
    here,
    '../../supabase/migrations/20260728210700_open_exposure_ledger.sql',
  ), 'utf8');

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
  assert.match(migration, /ORDER BY ceilings\.scope, ceilings\.scope_value[\s\S]+FOR UPDATE/);
  assert.match(migration, /COALESCE\(SUM\(exposures\.amount_minor\), 0\)/);
  assert.match(migration, /BEFORE UPDATE OR DELETE ON open_exposure_private\.history/);
  assert.match(migration, /CREATE INDEX[\s\S]+tenant_id, currency, window_start, window_end/);
  assert.match(migration, /WHERE status IN \('RESERVED', 'INVOKING', 'INDETERMINATE'\)/);
  assert.match(migration, /CREATE INDEX[\s\S]+tenant_id, status, reserved_at, exposure_id/);
  assert.match(migration, /CREATE INDEX[\s\S]+tenant_id, status, invoke_by, reconcile_by/);
  assert.match(migration, /REVOKE ALL ON ALL TABLES IN SCHEMA open_exposure_private[\s\S]+service_role/);
  assert.match(migration, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA open_exposure_private[\s\S]+service_role/);
  assert.doesNotMatch(migration, /GRANT[^;]+TO service_role/);
  assert.doesNotMatch(migration, /open_exposure_(?:blind_)?release/i);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION open_exposure_private\.reserve\(JSONB\)[\s\S]+TO ep_open_exposure_origin/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION open_exposure_private\.reconcile\(JSONB\)[\s\S]+TO ep_open_exposure_reconciler/);
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
