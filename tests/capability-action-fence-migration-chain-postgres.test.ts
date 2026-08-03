// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from 'vitest';

// These are the unchanged pre-fence migrations that create or structurally
// extend the two capability tables. The later history-reconciliation migration
// only reasserts the same table ACLs and depends on the unrelated full schema.
const HISTORICAL_CAPABILITY_MIGRATIONS = [
  '20260718190000_marvel_capability_store.sql',
  '20260718200000_fortress_db_security_invariants_capability.sql',
  '20260719043735_capability_operation_action_binding.sql',
  '20260802090000_gate_allowance_currentness_atomicity.sql',
].map((filename) => readFileSync(
  new URL(`../supabase/migrations/${filename}`, import.meta.url),
  'utf8',
));
const FENCE_MIGRATION = readFileSync(
  new URL(
    '../supabase/migrations/20260803010000_capability_action_digest_fence.sql',
    import.meta.url,
  ),
  'utf8',
);
const PACKAGED_PREFLIGHT = readFileSync(
  new URL(
    '../packages/gate/deploy/sql/capability-action-fence-preflight.sql',
    import.meta.url,
  ),
  'utf8',
);

// The core source lane may rename only the unique fence projection while this
// migration test is in flight. Discover that projection from the owned
// migration so this helper tests the contract rather than pinning stale prose.
const fenceColumnMatch = FENCE_MIGRATION.match(
  /ON\s+(?:public\.)?ep_capability_operations\s*\(\s*operation_namespace\s*,\s*(action(?:_fence)?_digest)\s*\)/,
);
if (!fenceColumnMatch) {
  throw new Error('capability action-fence migration does not declare a recognized digest key');
}
const FENCE_DIGEST_COLUMN = fenceColumnMatch[1];

const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;
const DATABASE = 'ep_capability_action_fence_chain_test';
const GLOBAL_ROLES = ['anon', 'authenticated', 'service_role'] as const;
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};

let admin: pg.Client;
let database: pg.Pool;
let createdRoles: string[] = [];

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
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

async function applyHistoricalCapabilityChain(): Promise<void> {
  for (const migration of HISTORICAL_CAPABILITY_MIGRATIONS) {
    await database.query(migration);
  }
}

async function applyFenceMigration(): Promise<void> {
  const client = await database.connect();
  try {
    await client.query('BEGIN');
    await client.query(FENCE_MIGRATION);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function runPackagedPreflight(): Promise<void> {
  const client = await database.connect();
  try {
    await client.query(PACKAGED_PREFLIGHT);
  } catch (error) {
    // The script starts its own read-only transaction. A failed DO block leaves
    // that transaction aborted, so return the pooled connection only after the
    // explicit rollback has restored a clean session.
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function operationNamespaceExists(): Promise<boolean> {
  const result = await database.query<{ exists: boolean }>(`
    SELECT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_attribute
      WHERE attrelid = 'public.ep_capability_operations'::pg_catalog.regclass
        AND attname = 'operation_namespace'
        AND attnum > 0
        AND NOT attisdropped
    ) AS exists
  `);
  return result.rows[0].exists;
}

async function insertCapability(capabilityId = 'capability:history'): Promise<void> {
  await database.query(
    `INSERT INTO public.ep_capability_state (
       capability_id,
       capability_fingerprint,
       budget_amount,
       currency,
       expires_at
     ) VALUES ($1, $2, 100, 'USD', now() + interval '1 hour')`,
    [capabilityId, `sha256:${'1'.repeat(64)}`],
  );
}

async function insertOperation(
  operationId: string,
  actionDigest: string,
  capabilityId = 'capability:history',
): Promise<void> {
  await database.query(
    `INSERT INTO public.ep_capability_operations (
       operation_id,
       capability_id,
       action_digest,
       amount,
       currency,
       status,
       reservation_token,
       reserved_at
     ) VALUES ($1, $2, $3, 1, 'USD', 'reserved', $4, now())`,
    [operationId, capabilityId, actionDigest, `reservation:${operationId}`],
  );
}

function normalizedPredicate(predicate: string | null): string {
  return (predicate ?? '').replace(/\s+/g, '').replaceAll('::text', '');
}

suite('capability action fence over the PostgreSQL 17 migration chain', () => {
  beforeAll(async () => {
    admin = new pg.Client({
      ...baseConnection,
      database: process.env.PGDATABASE ?? 'ep_test',
    });
    await admin.connect();

    const environment = await admin.query<{
      server_version_num: string;
      is_superuser: boolean;
    }>(`
      SELECT
        pg_catalog.current_setting('server_version_num') AS server_version_num,
        pg_catalog.current_setting('is_superuser')::boolean AS is_superuser
    `);
    expect(Number.parseInt(environment.rows[0].server_version_num, 10))
      .toBeGreaterThanOrEqual(170000);
    expect(Number.parseInt(environment.rows[0].server_version_num, 10))
      .toBeLessThan(180000);
    expect(environment.rows[0].is_superuser).toBe(true);

    const existingRoles = await admin.query<{ rolname: string }>(
      'SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])',
      [GLOBAL_ROLES],
    );
    const existingRoleNames = new Set(existingRoles.rows.map(({ rolname }) => rolname));
    createdRoles = GLOBAL_ROLES.filter((role) => !existingRoleNames.has(role));
    for (const role of createdRoles) {
      await admin.query(`CREATE ROLE ${identifier(role)} NOLOGIN`);
    }

    await terminateTestDatabaseConnections();
    await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
    await admin.query(`CREATE DATABASE ${identifier(DATABASE)} TEMPLATE template0`);
    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 4 });
  });

  beforeEach(async () => {
    await database.query(`
      DROP SCHEMA public CASCADE;
      CREATE SCHEMA public;
      GRANT ALL ON SCHEMA public TO PUBLIC;
    `);
  });

  afterAll(async () => {
    if (database) await database.end();
    if (admin) {
      await terminateTestDatabaseConnections();
      await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
      for (const role of [...createdRoles].reverse()) {
        await admin.query(`DROP ROLE IF EXISTS ${identifier(role)}`);
      }
      await admin.end();
    }
  });

  it('backfills the historical namespace, migrates the primary key, and installs the exact fence', async () => {
    await applyHistoricalCapabilityChain();
    expect(await operationNamespaceExists()).toBe(false);

    await insertCapability();
    const digest = `sha256:${'a'.repeat(64)}`;
    await insertOperation('operation:historical', digest);

    // The deployment preflight must be usable before the migration, not only
    // against the package-created table shape.
    await expect(runPackagedPreflight()).resolves.toBeUndefined();
    await expect(applyFenceMigration()).resolves.toBeUndefined();
    await expect(runPackagedPreflight()).resolves.toBeUndefined();

    const operation = await database.query<{
      operation_namespace: string;
      capability_id: string;
      fence_digest: string;
    }>(`
      SELECT
        operation_namespace,
        capability_id,
        pg_catalog.to_jsonb(operations) ->> $1 AS fence_digest
      FROM public.ep_capability_operations AS operations
      WHERE operation_id = 'operation:historical'
    `, [FENCE_DIGEST_COLUMN]);
    expect(operation.rows).toEqual([{
      operation_namespace: 'capability:history',
      capability_id: 'capability:history',
      fence_digest: digest,
    }]);

    const namespaceColumn = await database.query<{ is_nullable: string }>(`
      SELECT is_nullable
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'ep_capability_operations'
        AND column_name = 'operation_namespace'
    `);
    expect(namespaceColumn.rows).toEqual([{ is_nullable: 'NO' }]);

    const primaryKey = await database.query<{ columns: string[] }>(`
      SELECT ARRAY(
        SELECT attribute_catalog.attname
        FROM unnest(constraint_catalog.conkey)
          WITH ORDINALITY AS key_column(attnum, ordinal)
        JOIN pg_catalog.pg_attribute AS attribute_catalog
          ON attribute_catalog.attrelid = constraint_catalog.conrelid
         AND attribute_catalog.attnum = key_column.attnum
        ORDER BY key_column.ordinal
      )::TEXT[] AS columns
      FROM pg_catalog.pg_constraint AS constraint_catalog
      WHERE constraint_catalog.conrelid =
        'public.ep_capability_operations'::pg_catalog.regclass
        AND constraint_catalog.contype = 'p'
    `);
    expect(primaryKey.rows).toEqual([{
      columns: ['operation_namespace', 'operation_id'],
    }]);

    const fence = await database.query<{
      unique: boolean;
      valid: boolean;
      ready: boolean;
      immediate: boolean;
      exclusion: boolean;
      nulls_not_distinct: boolean;
      access_method: string;
      table_name: string;
      key_count: number;
      attribute_count: number;
      key_columns: string[];
      predicate: string | null;
    }>(`
      SELECT
        index_catalog.indisunique AS unique,
        index_catalog.indisvalid AS valid,
        index_catalog.indisready AS ready,
        index_catalog.indimmediate AS immediate,
        index_catalog.indisexclusion AS exclusion,
        index_catalog.indnullsnotdistinct AS nulls_not_distinct,
        access_method.amname AS access_method,
        pg_catalog.format('%I.%I', table_namespace.nspname, table_relation.relname)
          AS table_name,
        index_catalog.indnkeyatts::INTEGER AS key_count,
        index_catalog.indnatts::INTEGER AS attribute_count,
        ARRAY(
          SELECT attribute_catalog.attname
          FROM unnest(index_catalog.indkey::SMALLINT[])
            WITH ORDINALITY AS key_column(attnum, ordinal)
          JOIN pg_catalog.pg_attribute AS attribute_catalog
            ON attribute_catalog.attrelid = index_catalog.indrelid
           AND attribute_catalog.attnum = key_column.attnum
          WHERE key_column.ordinal <= index_catalog.indnkeyatts
          ORDER BY key_column.ordinal
        )::TEXT[] AS key_columns,
        pg_catalog.pg_get_expr(
          index_catalog.indpred,
          index_catalog.indrelid
        ) AS predicate
      FROM pg_catalog.pg_index AS index_catalog
      JOIN pg_catalog.pg_class AS index_relation
        ON index_relation.oid = index_catalog.indexrelid
      JOIN pg_catalog.pg_class AS table_relation
        ON table_relation.oid = index_catalog.indrelid
      JOIN pg_catalog.pg_namespace AS table_namespace
        ON table_namespace.oid = table_relation.relnamespace
      JOIN pg_catalog.pg_am AS access_method
        ON access_method.oid = index_relation.relam
      WHERE index_catalog.indexrelid =
        'public.ep_capability_operations_live_action_uniq'::pg_catalog.regclass
    `);
    expect(fence.rows).toHaveLength(1);
    expect(fence.rows[0]).toMatchObject({
      unique: true,
      valid: true,
      ready: true,
      immediate: true,
      exclusion: false,
      nulls_not_distinct: false,
      access_method: 'btree',
      table_name: 'public.ep_capability_operations',
      key_count: 2,
      attribute_count: 2,
      key_columns: ['operation_namespace', FENCE_DIGEST_COLUMN],
    });
    expect(normalizedPredicate(fence.rows[0].predicate)).toBe(
      "(status=ANY(ARRAY['reserved','provider_entered','committed']))",
    );
  });

  it('rejects a same-named non-unique index in preflight and migration', async () => {
    await applyHistoricalCapabilityChain();
    await database.query(`
      CREATE INDEX ep_capability_operations_live_action_uniq
      ON public.ep_capability_operations (operation_id, action_digest)
    `);

    await expect(runPackagedPreflight()).rejects.toMatchObject({
      code: '55000',
      message:
        'EMILIA capability action-digest fence index does not match its required contract',
    });
    await expect(applyFenceMigration()).rejects.toMatchObject({
      code: '55000',
      message:
        'EMILIA capability action-digest fence index does not match its required contract',
    });

    expect(await operationNamespaceExists()).toBe(false);
    const hostileIndex = await database.query<{ unique: boolean }>(`
      SELECT indisunique AS unique
      FROM pg_catalog.pg_index
      WHERE indexrelid =
        'public.ep_capability_operations_live_action_uniq'::pg_catalog.regclass
    `);
    expect(hostileIndex.rows).toEqual([{ unique: false }]);
  });

  it('rejects duplicate live rows without deleting, relabeling, or binding them', async () => {
    await applyHistoricalCapabilityChain();
    await insertCapability();
    const duplicateDigest = `sha256:${'d'.repeat(64)}`;
    await insertOperation('operation:duplicate:1', duplicateDigest);
    await insertOperation('operation:duplicate:2', duplicateDigest);

    await expect(runPackagedPreflight()).rejects.toMatchObject({
      code: '23505',
      message: 'EMILIA capability action-digest preflight found 1 duplicate live group(s)',
    });
    await expect(applyFenceMigration()).rejects.toMatchObject({
      code: '23505',
      message:
        'EMILIA capability action-digest fence preflight found 1 duplicate live group(s)',
    });

    expect(await operationNamespaceExists()).toBe(false);
    const preserved = await database.query<{
      operation_id: string;
      status: string;
      action_digest: string;
    }>(`
      SELECT operation_id, status, action_digest
      FROM public.ep_capability_operations
      ORDER BY operation_id
    `);
    expect(preserved.rows).toEqual([
      {
        operation_id: 'operation:duplicate:1',
        status: 'reserved',
        action_digest: duplicateDigest,
      },
      {
        operation_id: 'operation:duplicate:2',
        status: 'reserved',
        action_digest: duplicateDigest,
      },
    ]);
  });

  it('refuses a blank historical capability binding instead of inventing a namespace', async () => {
    await applyHistoricalCapabilityChain();
    await insertCapability('');
    await insertOperation(
      'operation:unbound',
      `sha256:${'e'.repeat(64)}`,
      '',
    );

    await expect(runPackagedPreflight()).rejects.toMatchObject({
      code: '23502',
      message:
        'EMILIA capability action-digest preflight found 1 unbound operation row(s)',
    });
    await expect(applyFenceMigration()).rejects.toMatchObject({
      code: '23502',
      message:
        'EMILIA capability namespace migration found 1 unbound operation row(s)',
    });

    expect(await operationNamespaceExists()).toBe(false);
    const preserved = await database.query<{ capability_id: string }>(`
      SELECT capability_id
      FROM public.ep_capability_operations
      WHERE operation_id = 'operation:unbound'
    `);
    expect(preserved.rows).toEqual([{ capability_id: '' }]);
  });
});
