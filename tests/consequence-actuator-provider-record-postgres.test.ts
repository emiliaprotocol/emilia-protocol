// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const actuatorMigration = readFileSync(
  new URL(
    '../supabase/migrations/20260725010000_consequence_actuator_store.sql',
    import.meta.url,
  ),
  'utf8',
);
const providerMigration = readFileSync(
  new URL(
    '../supabase/migrations/20260725143000_consequence_actuator_provider_records.sql',
    import.meta.url,
  ),
  'utf8',
);
const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;

const OWNER_ROLE = 'consequence_actuator_store_owner';
const EXECUTOR_ROLE = 'consequence_actuator_executor';
const TENANT_ALPHA_LOGIN = 'provider_record_tenant_alpha_login';
const TENANT_BETA_LOGIN = 'provider_record_tenant_beta_login';
const UNMAPPED_LOGIN = 'provider_record_unmapped_login';
const UNTRUSTED_LOGIN = 'provider_record_untrusted_login';
const LOGIN_PASSWORD = 'ep-provider-record-test-password';
const TEST_ROLES = [
  TENANT_ALPHA_LOGIN,
  TENANT_BETA_LOGIN,
  UNMAPPED_LOGIN,
  UNTRUSTED_LOGIN,
  EXECUTOR_ROLE,
  OWNER_ROLE,
];

const connection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  database: process.env.PGDATABASE ?? 'ep_test',
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};

const TENANT_ALPHA = 'tenant:alpha';
const TENANT_BETA = 'tenant:beta';
const PROVIDER_ACCOUNT = 'emiliaprotocol';
const ENVIRONMENT = 'production-smoke';
const OPERATION = 'github.issue.update.1';
const CAID = `caid:1:${OPERATION}:jcs-sha256:${'A'.repeat(43)}`;
const ACTION_DIGEST = `sha256:${'1'.repeat(64)}`;
const TARGET_DIGEST = `sha256:${'2'.repeat(64)}`;
const REQUEST_DIGEST = `sha256:${'3'.repeat(64)}`;
const EFFECT_DIGEST = `sha256:${'4'.repeat(64)}`;
const ATTRIBUTION_DIGEST = `sha256:${'5'.repeat(64)}`;
const ENVELOPE_DIGEST = `sha256:${'6'.repeat(64)}`;
const RECORD_DIGEST = `sha256:${'7'.repeat(64)}`;
const NONCE = 'provider_record_nonce_000001';
const ATTEMPT_ID = 'attempt:provider-record:000001';
const OPERATION_ID = 'operation:provider-record:000001';
const IDEMPOTENCY_KEY = OPERATION_ID;
const RECORDED_AT = '2026-07-25T12:00:00.000Z';

let admin: pg.Pool;
let cleanupAllowed = false;
let createdPostgresRole = false;

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function cleanup(): Promise<void> {
  await admin.query(
    `SELECT pg_catalog.pg_terminate_backend(pid)
     FROM pg_catalog.pg_stat_activity
     WHERE usename = ANY($1::text[])
       AND pid <> pg_catalog.pg_backend_pid()`,
    [[
      TENANT_ALPHA_LOGIN,
      TENANT_BETA_LOGIN,
      UNMAPPED_LOGIN,
      UNTRUSTED_LOGIN,
    ]],
  );
  await admin.query(
    'DROP SCHEMA IF EXISTS consequence_actuator_private CASCADE',
  );
  await admin.query(
    'DROP TABLE IF EXISTS public.consequence_actuator_envelopes CASCADE',
  );

  for (const role of TEST_ROLES) {
    const exists = await admin.query<{ exists: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1
       ) AS exists`,
      [role],
    );
    if (!exists.rows[0].exists) continue;
    await admin.query(`DROP OWNED BY ${identifier(role)} CASCADE`);
    await admin.query(`DROP ROLE ${identifier(role)}`);
  }
  if (createdPostgresRole) {
    await admin.query('DROP ROLE IF EXISTS postgres');
    createdPostgresRole = false;
  }
}

async function createLogin(role: string): Promise<void> {
  await admin.query(`
    CREATE ROLE ${identifier(role)}
      LOGIN PASSWORD '${LOGIN_PASSWORD}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  `);
}

function clientFor(role: string): pg.Client {
  return new pg.Client({
    ...connection,
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

function providerRecord(overrides: {
  tenantId?: string;
  attemptId?: string;
  providerRecordId?: string;
} = {}): Record<string, unknown> {
  const tenantId = overrides.tenantId ?? TENANT_ALPHA;
  const attemptId = overrides.attemptId ?? ATTEMPT_ID;
  return {
    '@version': 'EP-GITHUB-PROVIDER-ATTRIBUTION-RECORD-v2',
    payload: {
      '@version': 'EP-GITHUB-PROVIDER-ATTRIBUTION-RECORD-v2',
      outcome: 'COMMITTED',
      provider_record_id:
        overrides.providerRecordId ?? 'github-provider-record:test-000001',
      recorded_at: RECORDED_AT,
      provider_response: {
        status: 200,
        number: 1,
        title: 'Exact approved effect',
        body: 'Exact approved body',
      },
      provider_attribution: {
        payload: {
          '@version': 'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1',
          issuer_id: 'consequence-control',
          tenant_id: tenantId,
          provider_id: 'github',
          provider_account_id: PROVIDER_ACCOUNT,
          environment: ENVIRONMENT,
          request_digest: REQUEST_DIGEST,
          attempt_id: attemptId,
          operation_id: OPERATION_ID,
          caid: CAID,
          action_digest: ACTION_DIGEST,
          target_digest: TARGET_DIGEST,
          operation: OPERATION,
          nonce: NONCE,
          envelope_digest: ENVELOPE_DIGEST,
          effect_digest: EFFECT_DIGEST,
          issued_at: RECORDED_AT,
        },
        signature: {
          algorithm: 'Ed25519',
          key_id: 'provider-attribution-key',
          value: 'A'.repeat(86),
        },
      },
      provider_attribution_digest: ATTRIBUTION_DIGEST,
    },
    signature: {
      algorithm: 'Ed25519',
      key_id: 'provider-record-key',
      value: 'B'.repeat(86),
    },
  };
}

async function reserveEnvelope(): Promise<void> {
  await asRole(TENANT_ALPHA_LOGIN, async (client) => {
    const now = new Date();
    const result = await client.query<{ envelope_digest: string }>(
      `SELECT envelope_digest
       FROM consequence_actuator_private.reserve_envelope(
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
       )`,
      [
        TENANT_ALPHA,
        ATTEMPT_ID,
        ACTION_DIGEST,
        CAID,
        PROVIDER_ACCOUNT,
        TARGET_DIGEST,
        OPERATION,
        IDEMPOTENCY_KEY,
        NONCE,
        now.toISOString(),
        new Date(now.getTime() + 60_000).toISOString(),
        ENVELOPE_DIGEST,
      ],
    );
    expect(result.rows).toEqual([{ envelope_digest: ENVELOPE_DIGEST }]);
  });
}

async function writeRecord(
  role: string,
  record: Record<string, unknown>,
  digest = RECORD_DIGEST,
): Promise<string> {
  return asRole(role, async (client) => {
    const result = await client.query<{ provider_record_digest: string }>(
      `SELECT provider_record_digest
       FROM consequence_actuator_private.record_provider_record($1::jsonb, $2)`,
      [JSON.stringify(record), digest],
    );
    return result.rows[0]?.provider_record_digest;
  });
}

suite('consequence actuator provider-record migration on PostgreSQL 17', () => {
  beforeAll(async () => {
    admin = new pg.Pool({ ...connection, max: 4 });
    const environment = await admin.query<{
      database: string;
      server_version_num: string;
      is_superuser: boolean;
    }>(`
      SELECT
        pg_catalog.current_database() AS database,
        pg_catalog.current_setting('server_version_num') AS server_version_num,
        current_setting('is_superuser')::boolean AS is_superuser
    `);
    expect(environment.rows[0].database).toBe('ep_test');
    expect(Number.parseInt(
      environment.rows[0].server_version_num,
      10,
    )).toBeGreaterThanOrEqual(170000);
    expect(Number.parseInt(
      environment.rows[0].server_version_num,
      10,
    )).toBeLessThan(180000);
    expect(environment.rows[0].is_superuser).toBe(true);
    cleanupAllowed = true;

    await cleanup();
    await admin.query(`
      DO $$ BEGIN
        CREATE ROLE anon NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL;
      END $$;
      DO $$ BEGIN
        CREATE ROLE authenticated NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL;
      END $$;
      DO $$ BEGIN
        CREATE ROLE service_role NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL;
      END $$;
      CREATE ROLE ${identifier(OWNER_ROLE)} NOLOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
      CREATE ROLE ${identifier(EXECUTOR_ROLE)} NOLOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    `);
    const postgresRole = await admin.query<{ exists: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'postgres'
       ) AS exists`,
    );
    if (!postgresRole.rows[0].exists) {
      await admin.query('CREATE ROLE postgres NOLOGIN SUPERUSER');
      createdPostgresRole = true;
    }
    for (const role of [
      TENANT_ALPHA_LOGIN,
      TENANT_BETA_LOGIN,
      UNMAPPED_LOGIN,
      UNTRUSTED_LOGIN,
    ]) {
      await createLogin(role);
    }
    await admin.query(`
      GRANT ${identifier(EXECUTOR_ROLE)}
        TO ${identifier(TENANT_ALPHA_LOGIN)},
           ${identifier(TENANT_BETA_LOGIN)},
           ${identifier(UNMAPPED_LOGIN)}
        WITH INHERIT TRUE;
    `);

    await admin.query(actuatorMigration);
    const migrationClient = await admin.connect();
    try {
      await migrationClient.query(providerMigration);
    } finally {
      try {
        await migrationClient.query('RESET ROLE');
      } finally {
        migrationClient.release();
      }
    }
    await admin.query(`
      SET ROLE ${identifier(OWNER_ROLE)};
      INSERT INTO consequence_actuator_private.tenant_principals (
        tenant_id, principal_name
      ) VALUES
        ('${TENANT_ALPHA}', '${TENANT_ALPHA_LOGIN}'),
        ('${TENANT_BETA}', '${TENANT_BETA_LOGIN}');
      RESET ROLE;
    `);
    await reserveEnvelope();
  });

  afterAll(async () => {
    if (!admin) return;
    try {
      if (cleanupAllowed) await cleanup();
    } finally {
      await admin.end();
    }
  });

  it('installs a FORCE-RLS append-only table with executor-only RPCs', async () => {
    const result = await admin.query<{
      owner: string;
      rls_enabled: boolean;
      rls_forced: boolean;
      executor_record: boolean;
      executor_read: boolean;
      service_record: boolean;
      public_record: boolean;
    }>(`
      SELECT
        pg_catalog.pg_get_userbyid(c.relowner) AS owner,
        c.relrowsecurity AS rls_enabled,
        c.relforcerowsecurity AS rls_forced,
        pg_catalog.has_function_privilege(
          '${EXECUTOR_ROLE}',
          'consequence_actuator_private.record_provider_record(jsonb,text)',
          'EXECUTE'
        ) AS executor_record,
        pg_catalog.has_function_privilege(
          '${EXECUTOR_ROLE}',
          'consequence_actuator_private.read_provider_record(text,text,text,text,text,text,text,text,text)',
          'EXECUTE'
        ) AS executor_read,
        pg_catalog.has_function_privilege(
          'service_role',
          'consequence_actuator_private.record_provider_record(jsonb,text)',
          'EXECUTE'
        ) AS service_record,
        pg_catalog.has_function_privilege(
          'public',
          'consequence_actuator_private.record_provider_record(jsonb,text)',
          'EXECUTE'
        ) AS public_record
      FROM pg_catalog.pg_class AS c
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'consequence_actuator_private'
        AND c.relname = 'provider_records'
    `);
    expect(result.rows).toEqual([{
      owner: OWNER_ROLE,
      rls_enabled: true,
      rls_forced: true,
      executor_record: true,
      executor_read: true,
      service_record: false,
      public_record: false,
    }]);
  });

  it('records, reads, and idempotently replays one exact terminal record', async () => {
    const record = providerRecord();
    await expect(
      writeRecord(TENANT_ALPHA_LOGIN, record),
    ).resolves.toBe(RECORD_DIGEST);
    await expect(
      writeRecord(TENANT_ALPHA_LOGIN, record),
    ).resolves.toBe(RECORD_DIGEST);

    const found = await asRole(TENANT_ALPHA_LOGIN, async (client) => client.query<{
      provider_record: Record<string, unknown>;
      provider_record_digest: string;
    }>(
      `SELECT provider_record, provider_record_digest
       FROM consequence_actuator_private.read_provider_record(
         $1, $2, $3, $4, $5, $6, $7, $8, $9
       )`,
      [
        TENANT_ALPHA,
        'github',
        PROVIDER_ACCOUNT,
        ENVIRONMENT,
        REQUEST_DIGEST,
        ATTEMPT_ID,
        OPERATION_ID,
        CAID,
        ACTION_DIGEST,
      ],
    ));
    expect(found.rows).toEqual([{
      provider_record: record,
      provider_record_digest: RECORD_DIGEST,
    }]);
  });

  it('rejects conflicting replay and an unbound execution attempt', async () => {
    await expect(
      writeRecord(
        TENANT_ALPHA_LOGIN,
        providerRecord({ providerRecordId: 'github-provider-record:conflict' }),
        `sha256:${'8'.repeat(64)}`,
      ),
    ).rejects.toMatchObject({
      code: '23505',
      message: 'provider record conflict',
    });
    await expect(
      writeRecord(
        TENANT_ALPHA_LOGIN,
        providerRecord({ attemptId: 'attempt:not-reserved' }),
        `sha256:${'9'.repeat(64)}`,
      ),
    ).rejects.toMatchObject({
      code: '23503',
      message: 'provider record does not match its execution envelope',
    });
  });

  it('fails closed for cross-tenant and unmapped executor principals', async () => {
    await expect(
      writeRecord(TENANT_BETA_LOGIN, providerRecord()),
    ).rejects.toMatchObject({
      code: '42501',
      message: 'tenant principal binding required',
    });
    await expect(
      writeRecord(UNMAPPED_LOGIN, providerRecord()),
    ).rejects.toMatchObject({
      code: '42501',
      message: 'tenant principal binding required',
    });
  });

  it('denies direct table access and RPC access without executor authority', async () => {
    await expect(asRole(
      TENANT_ALPHA_LOGIN,
      async (client) => client.query(
        'SELECT * FROM consequence_actuator_private.provider_records',
      ),
    )).rejects.toMatchObject({ code: '42501' });
    await expect(
      writeRecord(UNTRUSTED_LOGIN, providerRecord()),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('rejects owner-level UPDATE and DELETE through the immutability trigger', async () => {
    for (const statement of [
      `UPDATE consequence_actuator_private.provider_records
       SET recorded_at = recorded_at + INTERVAL '1 second'`,
      'DELETE FROM consequence_actuator_private.provider_records',
    ]) {
      const mutationClient = await admin.connect();
      try {
        await mutationClient.query(`SET ROLE ${identifier(OWNER_ROLE)}`);
        await expect(
          mutationClient.query(statement),
        ).rejects.toMatchObject({
          code: '55000',
          message: 'consequence actuator provider records are immutable',
        });
      } finally {
        try {
          await mutationClient.query('RESET ROLE');
        } finally {
          mutationClient.release();
        }
      }
    }
  });
});
