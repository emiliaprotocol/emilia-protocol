// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260725180000_reconcile_unjournaled_security_invariants.sql',
    import.meta.url,
  ),
  'utf8',
);
const rolloutMigration = readFileSync(
  new URL(
    '../supabase/migrations/20260725160000_rollout_attempt_store.sql',
    import.meta.url,
  ),
  'utf8',
);
const assertionFunctionStart = rolloutMigration.indexOf(
  'CREATE OR REPLACE FUNCTION public.gov_consequence_control_security_assertions()',
);
const assertionFunctionEnd = rolloutMigration.indexOf(
  '\n$$;',
  assertionFunctionStart,
);
if (assertionFunctionStart < 0 || assertionFunctionEnd < 0) {
  throw new Error('consequence-control security assertion function is missing');
}
const assertionFunction = rolloutMigration.slice(
  assertionFunctionStart,
  assertionFunctionEnd + '\n$$;'.length,
);
const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;
const DATABASE = 'ep_history_reconciliation_test';
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};

let admin: pg.Client;
let database: pg.Pool;

suite('forward history reconciliation on PostgreSQL 17', () => {
  beforeAll(async () => {
    admin = new pg.Client({ ...baseConnection, database: process.env.PGDATABASE ?? 'ep_test' });
    await admin.connect();
    await admin.query(
      `SELECT pg_catalog.pg_terminate_backend(pid)
       FROM pg_catalog.pg_stat_activity
       WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()`,
      [DATABASE],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${DATABASE}`);
    await admin.query(`CREATE DATABASE ${DATABASE}`);

    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 2 });
    await database.query(`
      DO $$ BEGIN CREATE ROLE anon NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;
      DO $$ BEGIN CREATE ROLE authenticated NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;
      DO $$ BEGIN CREATE ROLE service_role NOLOGIN;
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;

      CREATE TABLE public.security_events (
        event_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        previous_hash TEXT,
        event_hash TEXT NOT NULL UNIQUE
      );
      CREATE TABLE public.authorities (
        authority_id TEXT PRIMARY KEY,
        key_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
        valid_to TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        organization_id TEXT,
        subject_type TEXT,
        subject_ref TEXT,
        assurance_class TEXT
      );
      ALTER TABLE public.authorities ENABLE ROW LEVEL SECURITY;
      CREATE TABLE public.commits (
        commit_id TEXT PRIMARY KEY,
        signature TEXT NOT NULL,
        public_key TEXT NOT NULL,
        nonce TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        decision TEXT NOT NULL,
        status TEXT NOT NULL,
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        scope JSONB NOT NULL DEFAULT '{}'::jsonb
      );
      ALTER TABLE public.commits ENABLE ROW LEVEL SECURITY;
      CREATE TABLE public.revoked_commit_keys (
        kid TEXT PRIMARY KEY,
        reason TEXT,
        revoked_by TEXT NOT NULL,
        revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE public.consumed_gate_refs (
        gate_ref TEXT PRIMARY KEY,
        consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        consumed_by_entity TEXT NOT NULL,
        consumed_for_action TEXT NOT NULL
      );
      ALTER TABLE public.consumed_gate_refs ENABLE ROW LEVEL SECURITY;
      CREATE TABLE public.receipts (
        receipt_id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        previous_hash TEXT
      );
      CREATE TABLE public.fraud_flags (
        id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL
      );
      CREATE TABLE public.ep_capability_state (
        capability_id TEXT PRIMARY KEY
      );
      CREATE TABLE public.ep_capability_operations (
        operation_id TEXT PRIMARY KEY
      );
    `);

    await database.query(`
      CREATE UNIQUE INDEX idx_security_events_single_child_per_parent
      ON public.security_events (event_id)
    `);
    await expect(database.query(migration)).rejects.toMatchObject({
      code: '55000',
      message:
        'idx_security_events_single_child_per_parent has the wrong security shape',
    });
    await database.query(
      'DROP INDEX public.idx_security_events_single_child_per_parent',
    );

    await database.query(`
      CREATE UNIQUE INDEX idx_receipts_single_child_per_parent
      ON public.receipts (receipt_id)
    `);
    await expect(database.query(migration)).rejects.toMatchObject({
      code: '55000',
      message:
        'idx_receipts_single_child_per_parent has the wrong security shape',
    });
    await database.query(
      'DROP INDEX public.idx_receipts_single_child_per_parent',
    );

    await database.query(migration);
    await database.query(assertionFunction);
  });

  afterAll(async () => {
    if (database) await database.end();
    if (admin) {
      await admin.query(
        `SELECT pg_catalog.pg_terminate_backend(pid)
         FROM pg_catalog.pg_stat_activity
         WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()`,
        [DATABASE],
      );
      await admin.query(`DROP DATABASE IF EXISTS ${DATABASE}`);
      await admin.end();
    }
  });

  it('installs all safety indexes and scoped-authority columns', async () => {
    const result = await database.query<{ name: string }>(`
      SELECT indexname AS name
      FROM pg_catalog.pg_indexes
      WHERE schemaname = 'public'
        AND indexname = ANY($1::text[])
      ORDER BY indexname
    `, [[
      'idx_authorities_delegation_parent',
      'idx_commits_kid',
      'idx_receipts_single_child_per_parent',
      'idx_security_events_single_child_per_parent',
    ]]);
    expect(result.rows.map(({ name }) => name)).toEqual([
      'idx_authorities_delegation_parent',
      'idx_commits_kid',
      'idx_receipts_single_child_per_parent',
      'idx_security_events_single_child_per_parent',
    ]);

    const columns = await database.query<{ column_name: string }>(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'authorities'
        AND column_name = ANY($1::text[])
      ORDER BY column_name
    `, [[
      'action_scopes',
      'currency',
      'delegation_parent',
      'max_amount_usd',
      'policy_hash',
    ]]);
    expect(columns.rows).toHaveLength(5);
  });

  it('pins the exact unique btree key shape for both parent fences', async () => {
    const result = await database.query<{
      name: string;
      access_method: string;
      unique: boolean;
      predicate: string | null;
      key_1: string;
      key_2: string;
    }>(`
      SELECT
        index_relation.relname AS name,
        access_method.amname AS access_method,
        index_catalog.indisunique AS unique,
        pg_catalog.pg_get_expr(
          index_catalog.indpred,
          index_catalog.indrelid,
          true
        ) AS predicate,
        pg_catalog.pg_get_indexdef(index_catalog.indexrelid, 1, true) AS key_1,
        pg_catalog.pg_get_indexdef(index_catalog.indexrelid, 2, true) AS key_2
      FROM pg_catalog.pg_index AS index_catalog
      JOIN pg_catalog.pg_class AS index_relation
        ON index_relation.oid = index_catalog.indexrelid
      JOIN pg_catalog.pg_am AS access_method
        ON access_method.oid = index_relation.relam
      WHERE index_relation.relname = ANY($1::text[])
      ORDER BY index_relation.relname
    `, [[
      'idx_receipts_single_child_per_parent',
      'idx_security_events_single_child_per_parent',
    ]]);

    expect(result.rows).toEqual([
      {
        name: 'idx_receipts_single_child_per_parent',
        access_method: 'btree',
        unique: true,
        predicate: null,
        key_1: 'entity_id',
        key_2: "COALESCE(previous_hash, 'root'::text)",
      },
      {
        name: 'idx_security_events_single_child_per_parent',
        access_method: 'btree',
        unique: true,
        predicate: null,
        key_1: "COALESCE(tenant_id, ''::text)",
        key_2: "COALESCE(previous_hash, 'root'::text)",
      },
    ]);
  });

  it('exports both exact index-shape assertions to the live schema contract', async () => {
    const assertions = await database.query<{ assertion: string }>(`
      SELECT assertion
      FROM public.gov_consequence_control_security_assertions()
        AS security_assertions(assertion)
      WHERE assertion LIKE 'contract:index:%'
      ORDER BY assertion
    `);
    expect(assertions.rows.map(({ assertion }) => assertion)).toEqual([
      'contract:index:public.idx_receipts_single_child_per_parent:exact-unique-btree',
      'contract:index:public.idx_security_events_single_child_per_parent:exact-unique-btree',
    ]);
  });

  it('increments the organization authority epoch on each mutation', async () => {
    await database.query(`
      INSERT INTO public.authorities (
        authority_id, key_id, public_key, role, status, organization_id
      ) VALUES ('authority:1', 'key:1', 'public-key', 'approver', 'active', 'org:1')
    `);
    await expect(
      database.query(
        `SELECT epoch FROM public.authority_registry_epoch
         WHERE organization_id = 'org:1'`,
      ).then(({ rows }) => rows[0].epoch),
    ).resolves.toBe('1');

    await database.query(`
      UPDATE public.authorities SET role = 'reviewer'
      WHERE authority_id = 'authority:1'
    `);
    await expect(
      database.query(
        `SELECT epoch FROM public.authority_registry_epoch
         WHERE organization_id = 'org:1'`,
      ).then(({ rows }) => rows[0].epoch),
    ).resolves.toBe('2');

    await database.query(`
      UPDATE public.authorities SET organization_id = 'org:2'
      WHERE authority_id = 'authority:1'
    `);
    const moved = await database.query<{ organization_id: string; epoch: string }>(`
      SELECT organization_id, epoch
      FROM public.authority_registry_epoch
      WHERE organization_id IN ('org:1', 'org:2')
      ORDER BY organization_id
    `);
    expect(moved.rows).toEqual([
      { organization_id: 'org:1', epoch: '3' },
      { organization_id: 'org:2', epoch: '1' },
    ]);
  });

  it('rejects security-event and receipt forks', async () => {
    await database.query(`
      INSERT INTO public.security_events (event_id, tenant_id, previous_hash, event_hash)
      VALUES ('event:1', 'tenant:1', NULL, 'hash:1')
    `);
    await expect(database.query(`
      INSERT INTO public.security_events (event_id, tenant_id, previous_hash, event_hash)
      VALUES ('event:2', 'tenant:1', NULL, 'hash:2')
    `)).rejects.toMatchObject({ code: '23505' });

    await database.query(`
      INSERT INTO public.receipts (receipt_id, entity_id, previous_hash)
      VALUES ('receipt:1', 'entity:1', NULL)
    `);
    await expect(database.query(`
      INSERT INTO public.receipts (receipt_id, entity_id, previous_hash)
      VALUES ('receipt:2', 'entity:1', NULL)
    `)).rejects.toMatchObject({ code: '23505' });
  });

  it('consumes once and refuses a kid revoked under the same lock domain', async () => {
    const insertCommit = async (commitId: string, kid: string): Promise<void> => {
      await database.query(`
        INSERT INTO public.commits (
          commit_id, signature, public_key, nonce, entity_id, action_type,
          decision, status, expires_at, scope, kid
        ) VALUES (
          $1, 'signature', 'public-key', 'nonce', 'entity:1', 'payment.release',
          'allow', 'active', now() + interval '10 minutes',
          '{"gate_binding_version":"v1","gate_binding_hash":"hash:binding"}'::jsonb,
          $2
        )
      `, [commitId, kid]);
    };

    await insertCommit('commit:consume', 'kid:consume');
    const consumed = await database.query(`
      SELECT gate_ref FROM public.consume_gate_ref_atomic(
        'commit:consume', 'entity:1', 'payment.release', 'v1', 'hash:binding'
      )
    `);
    expect(consumed.rows).toEqual([{ gate_ref: 'commit:consume' }]);
    await expect(database.query(`
      SELECT gate_ref FROM public.consume_gate_ref_atomic(
        'commit:consume', 'entity:1', 'payment.release', 'v1', 'hash:binding'
      )
    `)).rejects.toMatchObject({ code: '23505' });

    await insertCommit('commit:revoked', 'kid:revoked');
    await database.query(`
      SELECT kid FROM public.revoke_commit_key_atomic(
        'kid:revoked', 'compromised', 'operator:test'
      )
    `);
    await expect(database.query(`
      SELECT gate_ref FROM public.consume_gate_ref_atomic(
        'commit:revoked', 'entity:1', 'payment.release', 'v1', 'hash:binding'
      )
    `)).rejects.toMatchObject({ code: 'P0006' });
  });

  it('keeps the one-time consumption fence outside direct service-role mutation', async () => {
    const client = await database.connect();
    try {
      await client.query('SET ROLE service_role');
      await expect(
        client.query(
          `DELETE FROM public.consumed_gate_refs
           WHERE gate_ref = 'commit:consume'`,
        ),
      ).rejects.toMatchObject({ code: '42501' });
    } finally {
      await client.query('RESET ROLE');
      client.release();
    }
  });

  it('keeps untrusted roles outside tables and security-definer RPCs', async () => {
    const privileges = await database.query<{
      authority_read: boolean;
      epoch_read: boolean;
      consume_execute: boolean;
      partner_read: boolean;
      fraud_read: boolean;
      authority_write: boolean;
    }>(`
      SELECT
        has_table_privilege('anon', 'public.authorities', 'SELECT') AS authority_read,
        has_table_privilege('authenticated', 'public.authority_registry_epoch', 'SELECT') AS epoch_read,
        has_function_privilege(
          'anon',
          'public.consume_gate_ref_atomic(text,text,text,text,text)',
          'EXECUTE'
        ) AS consume_execute,
        has_table_privilege('anon', 'public.partner_inquiries', 'SELECT') AS partner_read,
        has_table_privilege('anon', 'public.fraud_flags', 'SELECT') AS fraud_read,
        has_table_privilege('service_role', 'public.authorities', 'INSERT') AS authority_write
    `);
    expect(privileges.rows).toEqual([{
      authority_read: false,
      epoch_read: false,
      consume_execute: false,
      partner_read: false,
      fraud_read: false,
      authority_write: false,
    }]);
  });
});
