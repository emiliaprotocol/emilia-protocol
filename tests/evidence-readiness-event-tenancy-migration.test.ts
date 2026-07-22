// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const databaseUrl = process.env.EVIDENCE_READINESS_TEST_DATABASE_URL;
const migration = readFileSync(
  new URL('../supabase/migrations/20260722020000_evidence_readiness_event_tenancy.sql', import.meta.url),
  'utf8',
);

const TENANT_ID = '00000000-0000-4000-8000-000000000007';
const KEY_ID = '00000000-0000-4000-8000-000000000008';
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;

const ids = {
  beforeLock: '00000000-0000-4000-8000-000000000010',
  afterLock: '00000000-0000-4000-8000-000000000011',
  ignored: '00000000-0000-4000-8000-000000000012',
};

const receipts = {
  beforeLock: 'finding-7-before-lock',
  afterLock: 'finding-7-after-lock',
  ignored: 'finding-7-ignored',
};

const suite = databaseUrl ? describe.sequential : describe.skip;
let pool: pg.Pool;

function createdEvent(eventId: string, receiptId: string) {
  return {
    text: `INSERT INTO public.audit_events (
             id, event_type, actor_id, actor_type, target_type, target_id,
             action, after_state, created_at
           ) VALUES ($1::uuid, 'guard.trust_receipt.created', $2, 'principal',
             'trust_receipt', $3, 'create', $4::jsonb, pg_catalog.now())`,
    values: [
      eventId,
      `ep:cloud-key:${KEY_ID}`,
      receiptId,
      JSON.stringify({ organization_id: TENANT_ID, action_hash: ACTION_HASH }),
    ],
  };
}

async function waitUntilBlocked(
  observer: pg.PoolClient,
  pid: number,
  mode: 'RowExclusiveLock' | 'ShareRowExclusiveLock',
) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await observer.query<{ blocked: boolean }>(`
      SELECT COALESCE(pg_catalog.bool_or(NOT granted), false) AS blocked
      FROM pg_catalog.pg_locks
      WHERE pid = $1
        AND locktype = 'relation'
        AND relation = 'public.audit_events'::regclass
        AND mode = $2
    `, [pid, mode]);
    if (result.rows[0]?.blocked) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`backend ${pid} did not block on audit_events with ${mode}`);
}

suite('Evidence Readiness event-tenancy migration on PostgreSQL', () => {
  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: databaseUrl, max: 6 });
    const database = await pool.query<{ current_database: string }>('SELECT current_database()');
    expect(database.rows[0]?.current_database).toMatch(/^emilia_evidence_readiness_test_/);

    await pool.query(`
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

      CREATE TABLE public.audit_events (
        id UUID PRIMARY KEY,
        event_type TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_type TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        action TEXT NOT NULL,
        before_state JSONB,
        after_state JSONB,
        metadata JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
      );

      CREATE TABLE public.tenant_environments (
        tenant_id UUID NOT NULL,
        name TEXT NOT NULL,
        PRIMARY KEY (tenant_id, name)
      );

      CREATE TABLE public.tenant_api_keys (
        key_id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        environment TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ
      );

      INSERT INTO public.tenant_environments (tenant_id, name)
      VALUES ('${TENANT_ID}', 'production');
      INSERT INTO public.tenant_api_keys (
        key_id, tenant_id, environment, created_at
      ) VALUES (
        '${KEY_ID}', '${TENANT_ID}', 'production',
        pg_catalog.now() - INTERVAL '1 day'
      );
    `);
  });

  afterAll(async () => {
    await pool?.end();
  });

  it('backfills an event that commits while the migration waits for its lock', async () => {
    const writer = await pool.connect();
    const migrator = await pool.connect();
    const observer = await pool.connect();

    try {
      await writer.query('BEGIN');
      await writer.query(createdEvent(ids.beforeLock, receipts.beforeLock));
      const migrationPid = await migrator.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      const applyingMigration = migrator.query(migration);

      await waitUntilBlocked(observer, migrationPid.rows[0].pid, 'ShareRowExclusiveLock');
      await writer.query('COMMIT');
      await applyingMigration;

      const binding = await observer.query(`
        SELECT receipt_id, tenant_id::text, environment
        FROM public.guard_receipt_event_bindings
        WHERE event_id = $1::uuid
      `, [ids.beforeLock]);
      expect(binding.rows).toEqual([{
        receipt_id: receipts.beforeLock,
        tenant_id: TENANT_ID,
        environment: 'production',
      }]);
    } finally {
      await writer.query('ROLLBACK').catch(() => undefined);
      writer.release();
      migrator.release();
      observer.release();
    }
  });

  it('blocks later writers until the installed trigger can bind them', async () => {
    const locker = await pool.connect();
    const writer = await pool.connect();
    const observer = await pool.connect();

    try {
      await locker.query('BEGIN');
      await locker.query('LOCK TABLE public.audit_events IN SHARE ROW EXCLUSIVE MODE');
      const writerPid = await writer.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      const inserting = writer.query(createdEvent(ids.afterLock, receipts.afterLock));

      await waitUntilBlocked(observer, writerPid.rows[0].pid, 'RowExclusiveLock');
      const beforeCommit = await observer.query(`
        SELECT pg_catalog.count(*)::int AS count
        FROM public.guard_receipt_event_bindings
        WHERE event_id = $1::uuid
      `, [ids.afterLock]);
      expect(beforeCommit.rows[0].count).toBe(0);

      await locker.query('COMMIT');
      await inserting;

      const afterCommit = await observer.query(`
        SELECT receipt_id, tenant_id::text, environment
        FROM public.guard_receipt_event_bindings
        WHERE event_id = $1::uuid
      `, [ids.afterLock]);
      expect(afterCommit.rows).toEqual([{
        receipt_id: receipts.afterLock,
        tenant_id: TENANT_ID,
        environment: 'production',
      }]);
    } finally {
      await locker.query('ROLLBACK').catch(() => undefined);
      locker.release();
      writer.release();
      observer.release();
    }
  });

  it('leaves an unprovable event unbound after the trigger is live', async () => {
    await pool.query({
      ...createdEvent(ids.ignored, receipts.ignored),
      values: [
        ids.ignored,
        'ep:cloud-key:00000000-0000-4000-8000-000000000099',
        receipts.ignored,
        JSON.stringify({ organization_id: TENANT_ID, action_hash: ACTION_HASH }),
      ],
    });

    const result = await pool.query(`
      SELECT pg_catalog.count(*)::int AS count
      FROM public.guard_receipt_event_bindings
      WHERE event_id = $1::uuid
    `, [ids.ignored]);
    expect(result.rows[0].count).toBe(0);
  });
});
