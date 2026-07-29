// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260728210700_open_exposure_ledger.sql',
    import.meta.url,
  ),
  'utf8',
);
const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;

const DATABASE = 'ep_open_exposure_ledger_test';
const LOGIN_PASSWORD = 'ep-open-exposure-test-password';
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};
const controlDatabase = process.env.PGDATABASE ?? 'ep_test';

const TENANT_ALPHA = 'tenant:open-exposure:alpha';
const TENANT_BETA = 'tenant:open-exposure:beta';
const AUTHORITY = {
  policy: 'policy:open-exposure:alpha',
  origin: 'origin:open-exposure:alpha',
  executor: 'executor:open-exposure:alpha',
  reconciler: 'reconciler:open-exposure:alpha',
  reader: 'reader:open-exposure:alpha',
  betaOrigin: 'origin:open-exposure:beta',
} as const;
const LOGIN = {
  policy: 'open_exposure_policy_alpha_login',
  origin: 'open_exposure_origin_alpha_login',
  executor: 'open_exposure_executor_alpha_login',
  reconciler: 'open_exposure_reconciler_alpha_login',
  reader: 'open_exposure_reader_alpha_login',
  betaOrigin: 'open_exposure_origin_beta_login',
} as const;
const TEST_LOGINS = Object.values(LOGIN);
const GENERIC_ROLES = ['anon', 'authenticated', 'service_role'] as const;
const MANAGED_ROLES = [
  'ep_open_exposure_store_owner',
  'ep_open_exposure_origin',
  'ep_open_exposure_executor',
  'ep_open_exposure_reconciler',
  'ep_open_exposure_policy_admin',
  'ep_open_exposure_reader',
] as const;
const SHARED_ROLES = [...GENERIC_ROLES, ...MANAGED_ROLES];

const digest = (character: string): string =>
  `sha256:${character.repeat(64)}`;
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const PROGRAM_ID = 'program:open-exposure';
const PROGRAM_VERSION = 'program-v1';
const PROGRAM_SOURCE_DIGEST = digest('1');
const PROGRAM_DIGEST = digest('2');
const ACTION_DIGEST = digest('3');
const ADMISSION_SNAPSHOT_DIGEST = digest('4');
const AUTHORIZATION_DIGEST = digest('5');
const OPERATION_TOKEN_DIGEST = digest('6');
const RESERVATION_EVIDENCE_DIGEST = digest('7');
const INDETERMINATE_EVIDENCE_DIGEST = digest('8');
const RECONCILIATION_EVIDENCE_DIGEST = digest('9');
const RECONCILIATION_TOKEN_DIGEST = digest('a');
const EXPOSURE_ID = 'exposure:open-exposure:alpha:1';
const COUNTERPARTY_ID = 'counterparty:open-exposure';
const ACTION_CLASS = 'payment.release';
const CURRENCY = 'USD';

type RpcResult = {
  ok: boolean;
  replayed?: boolean;
  reason?: string;
  invocation_permit?: string;
  record?: Record<string, unknown>;
  entries?: Array<Record<string, unknown>>;
  total_minor?: string;
  by_status?: Array<{ key: string; amount_minor: string }>;
};

type RpcName =
  | 'register_ceiling'
  | 'reserve'
  | 'begin_invocation'
  | 'mark_indeterminate'
  | 'reconcile'
  | 'read_exposure'
  | 'read_history'
  | 'sum_open';

let admin: pg.Client;
let database: pg.Pool;
let initiallyPresentRoles = new Set<string>();

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function clientFor(role: string): pg.Client {
  return new pg.Client({
    ...baseConnection,
    database: DATABASE,
    user: role,
    password: LOGIN_PASSWORD,
  });
}

async function asRole<T>(
  role: string,
  callback: (client: pg.Client) => Promise<T>,
): Promise<T> {
  const client = clientFor(role);
  await client.connect();
  try {
    return await callback(client);
  } finally {
    await client.end();
  }
}

async function callRpc(
  role: string,
  name: RpcName,
  payload: Record<string, unknown>,
): Promise<RpcResult> {
  return asRole(role, async (client) => {
    const result = await client.query<{ result: RpcResult }>(
      `SELECT open_exposure_private.${name}($1::jsonb) AS result`,
      [JSON.stringify(payload)],
    );
    return result.rows[0].result;
  });
}

async function terminateTestDatabaseConnections(): Promise<void> {
  await admin.query(
    `SELECT pg_catalog.pg_terminate_backend(pid)
     FROM pg_catalog.pg_stat_activity
     WHERE datname = $1
       AND pid <> pg_catalog.pg_backend_pid()`,
    [DATABASE],
  );
}

async function dropTestLogins(): Promise<void> {
  for (const role of TEST_LOGINS) {
    await admin.query(`DROP ROLE IF EXISTS ${identifier(role)}`);
  }
}

async function cleanup(): Promise<void> {
  if (database) {
    await database.end();
  }
  await terminateTestDatabaseConnections();
  await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
  await dropTestLogins();

  for (const role of [...MANAGED_ROLES, ...GENERIC_ROLES]) {
    if (!initiallyPresentRoles.has(role)) {
      await admin.query(`DROP ROLE IF EXISTS ${identifier(role)}`);
    }
  }
}

async function createLogin(role: string): Promise<void> {
  await database.query(`
    CREATE ROLE ${identifier(role)}
      LOGIN INHERIT PASSWORD '${LOGIN_PASSWORD}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  `);
}

const startedAt = Date.now();
const WINDOW_START = new Date(startedAt - 60_000).toISOString();
const WINDOW_END = new Date(startedAt + 60 * 60_000).toISOString();
const RESERVED_AT = new Date(startedAt - 1_000).toISOString();
const INVOKE_BY = new Date(startedAt + 10 * 60_000).toISOString();
const RECONCILE_BY = new Date(startedAt + 30 * 60_000).toISOString();
const AUTHORIZATION_EXPIRES_AT = new Date(
  startedAt + 20 * 60_000,
).toISOString();

function ceilingPayload(
  scope: 'TENANT' | 'PROGRAM' | 'COUNTERPARTY' | 'ACTION_CLASS',
  scopeValue: string,
  overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    version: 'EP-OPEN-EXPOSURE-LEDGER-v1',
    tenant_id: TENANT_ALPHA,
    authority_kind: 'POLICY_ADMIN',
    authority_id: AUTHORITY.policy,
    ceiling_id: `ceiling:${scope.toLowerCase()}:alpha`,
    scope,
    scope_value: scopeValue,
    currency: CURRENCY,
    window_start: WINDOW_START,
    window_end: WINDOW_END,
    limit_minor: '1000',
    policy_digest: digest('b'),
    ...overrides,
  };
}

function reservationPayload(
  overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    version: 'EP-OPEN-EXPOSURE-LEDGER-v1',
    tenant_id: TENANT_ALPHA,
    exposure_id: EXPOSURE_ID,
    authority_kind: 'ORIGIN',
    authority_id: AUTHORITY.origin,
    operation_token_digest: OPERATION_TOKEN_DIGEST,
    program_id: PROGRAM_ID,
    program_version: PROGRAM_VERSION,
    program_source_digest: PROGRAM_SOURCE_DIGEST,
    program_digest: PROGRAM_DIGEST,
    caid: CAID,
    action_digest: ACTION_DIGEST,
    admission_snapshot_digest: ADMISSION_SNAPSHOT_DIGEST,
    authorization_digest: AUTHORIZATION_DIGEST,
    authorization_expires_at: AUTHORIZATION_EXPIRES_AT,
    counterparty_id: COUNTERPARTY_ID,
    action_class: ACTION_CLASS,
    amount_minor: '600',
    currency: CURRENCY,
    window_start: WINDOW_START,
    window_end: WINDOW_END,
    reserved_at: RESERVED_AT,
    invoke_by: INVOKE_BY,
    reconcile_by: RECONCILE_BY,
    origin_authority_id: AUTHORITY.origin,
    executor_authority_id: AUTHORITY.executor,
    reconciliation_authority_id: AUTHORITY.reconciler,
    reservation_evidence_digest: RESERVATION_EVIDENCE_DIGEST,
    ...overrides,
  };
}

function invocationPayload(): Record<string, unknown> {
  return {
    tenant_id: TENANT_ALPHA,
    exposure_id: EXPOSURE_ID,
    authority_kind: 'EXECUTOR',
    authority_id: AUTHORITY.executor,
    operation_token_digest: OPERATION_TOKEN_DIGEST,
    program_version: PROGRAM_VERSION,
    program_source_digest: PROGRAM_SOURCE_DIGEST,
    program_digest: PROGRAM_DIGEST,
    caid: CAID,
    action_digest: ACTION_DIGEST,
    admission_snapshot_digest: ADMISSION_SNAPSHOT_DIGEST,
    authorization_digest: AUTHORIZATION_DIGEST,
    authorization_expires_at: AUTHORIZATION_EXPIRES_AT,
  };
}

function readerPayload(
  overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    tenant_id: TENANT_ALPHA,
    authority_kind: 'READER',
    authority_id: AUTHORITY.reader,
    ...overrides,
  };
}

suite('Open Exposure Ledger migration on clean PostgreSQL 17', () => {
  beforeAll(async () => {
    admin = new pg.Client({ ...baseConnection, database: controlDatabase });
    await admin.connect();
    const environment = await admin.query<{
      server_version_num: string;
      is_superuser: boolean;
      current_database: string;
    }>(`
      SELECT
        pg_catalog.current_setting('server_version_num') AS server_version_num,
        pg_catalog.current_setting('is_superuser')::boolean AS is_superuser,
        pg_catalog.current_database() AS current_database
    `);
    expect(Number.parseInt(
      environment.rows[0].server_version_num,
      10,
    )).toBeGreaterThanOrEqual(170000);
    expect(Number.parseInt(
      environment.rows[0].server_version_num,
      10,
    )).toBeLessThan(180000);
    expect(environment.rows[0].is_superuser).toBe(true);
    expect(environment.rows[0].current_database).not.toBe(DATABASE);

    const roles = await admin.query<{ rolname: string }>(
      `SELECT rolname
       FROM pg_catalog.pg_roles
       WHERE rolname = ANY($1::text[])`,
      [SHARED_ROLES],
    );
    initiallyPresentRoles = new Set(roles.rows.map(({ rolname }) => rolname));

    await terminateTestDatabaseConnections();
    await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
    await dropTestLogins();
    for (const role of GENERIC_ROLES) {
      await admin.query(`
        DO $role$ BEGIN
          CREATE ROLE ${identifier(role)} NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $role$
      `);
    }
    await admin.query(
      `CREATE DATABASE ${identifier(DATABASE)} TEMPLATE template0`,
    );

    database = new pg.Pool({
      ...baseConnection,
      database: DATABASE,
      max: 4,
    });
    await database.query(`
      CREATE SCHEMA extensions;
      CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
      CREATE OR REPLACE FUNCTION public.gov_consequence_control_security_assertions()
        RETURNS TABLE(assertion TEXT)
        LANGUAGE sql
        AS $predecessor$
          SELECT NULL::TEXT WHERE FALSE
        $predecessor$;
    `);
    await database.query(migration);

    for (const role of TEST_LOGINS) await createLogin(role);
    await database.query(`
      GRANT ep_open_exposure_policy_admin
        TO ${identifier(LOGIN.policy)} WITH INHERIT TRUE, SET FALSE;
      GRANT ep_open_exposure_origin
        TO ${identifier(LOGIN.origin)}, ${identifier(LOGIN.betaOrigin)}
        WITH INHERIT TRUE, SET FALSE;
      GRANT ep_open_exposure_executor
        TO ${identifier(LOGIN.executor)} WITH INHERIT TRUE, SET FALSE;
      GRANT ep_open_exposure_reconciler
        TO ${identifier(LOGIN.reconciler)} WITH INHERIT TRUE, SET FALSE;
      GRANT ep_open_exposure_reader
        TO ${identifier(LOGIN.reader)} WITH INHERIT TRUE, SET FALSE;

      INSERT INTO open_exposure_private.tenant_principals (
        principal_name, tenant_id, authority_kind, authority_id
      ) VALUES
        ('${LOGIN.policy}', '${TENANT_ALPHA}', 'POLICY_ADMIN', '${AUTHORITY.policy}'),
        ('${LOGIN.origin}', '${TENANT_ALPHA}', 'ORIGIN', '${AUTHORITY.origin}'),
        ('${LOGIN.executor}', '${TENANT_ALPHA}', 'EXECUTOR', '${AUTHORITY.executor}'),
        ('${LOGIN.reconciler}', '${TENANT_ALPHA}', 'RECONCILER', '${AUTHORITY.reconciler}'),
        ('${LOGIN.reader}', '${TENANT_ALPHA}', 'READER', '${AUTHORITY.reader}'),
        ('${LOGIN.betaOrigin}', '${TENANT_BETA}', 'ORIGIN', '${AUTHORITY.betaOrigin}')
    `);
  });

  afterAll(async () => {
    if (!admin) return;
    try {
      await cleanup();
      const databaseGone = await admin.query<{ exists: boolean }>(
        `SELECT EXISTS (
           SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1
         ) AS exists`,
        [DATABASE],
      );
      const rolesGone = await admin.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count
         FROM pg_catalog.pg_roles
         WHERE rolname = ANY($1::text[])`,
        [TEST_LOGINS],
      );
      expect(databaseGone.rows).toEqual([{ exists: false }]);
      expect(rolesGone.rows).toEqual([{ count: '0' }]);
    } finally {
      await admin.end();
    }
  });

  it('denies cross-tenant, wrong-role, direct-table, and service_role access', async () => {
    await expect(callRpc(
      LOGIN.origin,
      'reserve',
      reservationPayload({
        tenant_id: TENANT_BETA,
        authority_id: AUTHORITY.betaOrigin,
        origin_authority_id: AUTHORITY.betaOrigin,
      }),
    )).rejects.toMatchObject({
      code: '42501',
      message: 'OPEN_EXPOSURE_AUTHORITY_REFUSED',
    });

    await expect(callRpc(
      LOGIN.executor,
      'reserve',
      reservationPayload(),
    )).rejects.toMatchObject({ code: '42501' });

    await expect(asRole(
      LOGIN.origin,
      async (client) => client.query(
        'SELECT * FROM open_exposure_private.exposures',
      ),
    )).rejects.toMatchObject({ code: '42501' });

    const serviceClient = await database.connect();
    try {
      await serviceClient.query('SET ROLE service_role');
      await expect(serviceClient.query(
        'SELECT open_exposure_private.sum_open($1::jsonb)',
        [JSON.stringify(readerPayload())],
      )).rejects.toMatchObject({ code: '42501' });
    } finally {
      await serviceClient.query('RESET ROLE');
      serviceClient.release();
    }
  });

  it('enforces ceilings and preserves exact open exposure through reconciliation', async () => {
    const ceilings = [
      ceilingPayload('TENANT', '*'),
      ceilingPayload('PROGRAM', PROGRAM_ID),
      ceilingPayload('COUNTERPARTY', COUNTERPARTY_ID),
      ceilingPayload('ACTION_CLASS', ACTION_CLASS),
    ];
    for (const payload of ceilings) {
      const registered = await callRpc(
        LOGIN.policy,
        'register_ceiling',
        payload,
      );
      expect(registered).toMatchObject({ ok: true, replayed: false });
    }
    await expect(callRpc(
      LOGIN.policy,
      'register_ceiling',
      ceilings[0],
    )).resolves.toMatchObject({ ok: true, replayed: true });
    await expect(callRpc(
      LOGIN.policy,
      'register_ceiling',
      { ...ceilings[0], limit_minor: '999' },
    )).resolves.toEqual({ ok: false, reason: 'ceiling_id_conflict' });

    const reservation = reservationPayload();
    const reserved = await callRpc(LOGIN.origin, 'reserve', reservation);
    expect(reserved).toMatchObject({
      ok: true,
      replayed: false,
      record: {
        exposure_id: EXPOSURE_ID,
        amount_minor: '600',
        status: 'RESERVED',
        revision: 0,
      },
    });
    await expect(callRpc(
      LOGIN.origin,
      'reserve',
      reservation,
    )).resolves.toMatchObject({ ok: true, replayed: true });
    await expect(callRpc(
      LOGIN.origin,
      'reserve',
      { ...reservation, amount_minor: '601' },
    )).resolves.toEqual({ ok: false, reason: 'operation_token_conflict' });
    await expect(callRpc(
      LOGIN.origin,
      'reserve',
      reservationPayload({
        exposure_id: 'exposure:open-exposure:alpha:over-limit',
        operation_token_digest: digest('c'),
        reservation_evidence_digest: digest('d'),
        amount_minor: '500',
      }),
    )).resolves.toEqual({ ok: false, reason: 'ceiling_exceeded' });

    const sumPayload = readerPayload({
      currency: CURRENCY,
      window_start: WINDOW_START,
      window_end: WINDOW_END,
    });
    await expect(callRpc(
      LOGIN.reader,
      'sum_open',
      sumPayload,
    )).resolves.toMatchObject({
      ok: true,
      total_minor: '600',
      by_status: [{ key: 'RESERVED', amount_minor: '600' }],
    });

    const invocation = invocationPayload();
    const invoking = await callRpc(
      LOGIN.executor,
      'begin_invocation',
      invocation,
    );
    expect(invoking).toMatchObject({
      ok: true,
      replayed: false,
      record: { status: 'INVOKING', revision: 1 },
    });
    expect(invoking.invocation_permit).toMatch(
      /^open-exposure-invoke:v1:[0-9a-f]{64}$/,
    );
    await expect(callRpc(
      LOGIN.executor,
      'begin_invocation',
      invocation,
    )).resolves.toEqual({ ok: false, reason: 'reconciliation_required' });
    await expect(callRpc(
      LOGIN.reader,
      'sum_open',
      sumPayload,
    )).resolves.toMatchObject({
      total_minor: '600',
      by_status: [{ key: 'INVOKING', amount_minor: '600' }],
    });

    const invokedAt = invoking.record?.invoked_at;
    expect(invokedAt).toEqual(expect.any(String));
    const indeterminateAt = new Date(
      Date.parse(invokedAt as string) + 1,
    ).toISOString();
    const indeterminatePayload = {
      tenant_id: TENANT_ALPHA,
      exposure_id: EXPOSURE_ID,
      authority_kind: 'EXECUTOR',
      authority_id: AUTHORITY.executor,
      operation_token_digest: OPERATION_TOKEN_DIGEST,
      evidence_digest: INDETERMINATE_EVIDENCE_DIGEST,
      observed_at: indeterminateAt,
    };
    const indeterminate = await callRpc(
      LOGIN.executor,
      'mark_indeterminate',
      indeterminatePayload,
    );
    expect(indeterminate).toMatchObject({
      ok: true,
      replayed: false,
      record: { status: 'INDETERMINATE', revision: 2 },
    });
    await expect(callRpc(
      LOGIN.executor,
      'mark_indeterminate',
      indeterminatePayload,
    )).resolves.toMatchObject({ ok: true, replayed: true });
    await expect(callRpc(
      LOGIN.executor,
      'mark_indeterminate',
      { ...indeterminatePayload, evidence_digest: digest('e') },
    )).resolves.toEqual({ ok: false, reason: 'state_conflict' });
    await expect(callRpc(
      LOGIN.reader,
      'sum_open',
      sumPayload,
    )).resolves.toMatchObject({
      total_minor: '600',
      by_status: [{ key: 'INDETERMINATE', amount_minor: '600' }],
    });

    const reconciledAt = new Date(
      Date.parse(indeterminateAt) + 1,
    ).toISOString();
    const reconciliationPayload = {
      tenant_id: TENANT_ALPHA,
      exposure_id: EXPOSURE_ID,
      authority_kind: 'RECONCILER',
      authority_id: AUTHORITY.reconciler,
      operation_token_digest: OPERATION_TOKEN_DIGEST,
      reconciliation_token_digest: RECONCILIATION_TOKEN_DIGEST,
      outcome: 'COMMITTED',
      evidence_digest: RECONCILIATION_EVIDENCE_DIGEST,
      observed_at: reconciledAt,
    };
    const reconciled = await callRpc(
      LOGIN.reconciler,
      'reconcile',
      reconciliationPayload,
    );
    expect(reconciled).toMatchObject({
      ok: true,
      replayed: false,
      record: {
        status: 'CLOSED_COMMITTED',
        reconciliation_outcome: 'COMMITTED',
        revision: 3,
      },
    });
    await expect(callRpc(
      LOGIN.reconciler,
      'reconcile',
      reconciliationPayload,
    )).resolves.toMatchObject({ ok: true, replayed: true });
    await expect(callRpc(
      LOGIN.reconciler,
      'reconcile',
      { ...reconciliationPayload, evidence_digest: digest('f') },
    )).resolves.toEqual({
      ok: false,
      reason: 'reconciliation_token_conflict',
    });

    await expect(callRpc(
      LOGIN.reader,
      'sum_open',
      sumPayload,
    )).resolves.toMatchObject({
      ok: true,
      total_minor: '0',
      by_status: [],
    });
    const history = await callRpc(
      LOGIN.reader,
      'read_history',
      readerPayload({ exposure_id: EXPOSURE_ID }),
    );
    expect(history.entries?.map(({ event }) => event)).toEqual([
      'RESERVED',
      'INVOKING',
      'INDETERMINATE',
      'CLOSED_COMMITTED',
    ]);
    await expect(callRpc(
      LOGIN.reader,
      'read_exposure',
      readerPayload({ exposure_id: EXPOSURE_ID }),
    )).resolves.toMatchObject({
      ok: true,
      record: { status: 'CLOSED_COMMITTED', revision: 3 },
    });
  });
});
