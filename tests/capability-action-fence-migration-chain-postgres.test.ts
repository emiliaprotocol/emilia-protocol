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
const REVOCATION_MIGRATION = readFileSync(
  new URL(
    '../supabase/migrations/20260807010000_capability_revocation_inheritance.sql',
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
    await client.query(FENCE_MIGRATION);
  } catch (error) {
    // The migration owns its BEGIN/COMMIT boundary. A failed statement leaves
    // that explicit transaction aborted until the caller rolls it back.
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function applyRevocationMigration(): Promise<void> {
  const client = await database.connect();
  try {
    await client.query(REVOCATION_MIGRATION);
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
  status = 'reserved',
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
     ) VALUES ($1, $2, $3, 1, 'USD', $4, $5, now())`,
    [
      operationId,
      capabilityId,
      actionDigest,
      status,
      `reservation:${operationId}`,
    ],
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

  it('atomically upgrades the true historical schema and quarantines its capability', async () => {
    await applyHistoricalCapabilityChain();
    expect(await operationNamespaceExists()).toBe(false);

    // Simulate an incomplete package bootstrap that added the readiness flag
    // with its default before the tracked fence migration reached production.
    // A legacy ID must still be quarantined; TRUE is not grandfathered.
    await database.query(`
      ALTER TABLE public.ep_capability_state
      ADD COLUMN semantic_fence_ready BOOLEAN NOT NULL DEFAULT TRUE
    `);

    await insertCapability();
    await insertCapability('capability:fresh');
    const digest = `sha256:${'a'.repeat(64)}`;
    await insertOperation('operation:historical', digest, 'capability:history', 'committed');

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

    const lifecycleColumns = await database.query<{ column_name: string }>(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'ep_capability_operations'
        AND column_name = ANY($1::TEXT[])
      ORDER BY column_name
    `, [[
      'entry_deadline_at',
      'provider_entry_at',
      'released_at',
      'release_reason',
      'release_evidence_profile',
      'release_evidence_digest',
    ]]);
    expect(lifecycleColumns.rows.map(({ column_name }) => column_name)).toEqual([
      'entry_deadline_at',
      'provider_entry_at',
      'release_evidence_digest',
      'release_evidence_profile',
      'release_reason',
      'released_at',
    ]);

    const statusConstraint = await database.query<{ definition: string }>(`
      SELECT pg_catalog.pg_get_constraintdef(oid) AS definition
      FROM pg_catalog.pg_constraint
      WHERE conrelid = 'public.ep_capability_operations'::pg_catalog.regclass
        AND conname = 'ep_capability_operations_status_check'
    `);
    expect(normalizedPredicate(statusConstraint.rows[0]?.definition ?? '')).toContain(
      "ARRAY['reserved','provider_entered','committed','released']",
    );

    const digestConstraints = await database.query<{ conname: string }>(`
      SELECT conname
      FROM pg_catalog.pg_constraint
      WHERE conrelid = 'public.ep_capability_operations'::pg_catalog.regclass
        AND conname = ANY($1::TEXT[])
      ORDER BY conname
    `, [[
      'ep_capability_operations_action_digest_check',
      'ep_capability_operations_action_fence_digest_check',
      'ep_capability_operations_release_evidence_digest_check',
    ]]);
    expect(digestConstraints.rows.map(({ conname }) => conname)).toEqual([
      'ep_capability_operations_action_digest_check',
      'ep_capability_operations_action_fence_digest_check',
      'ep_capability_operations_release_evidence_digest_check',
    ]);

    const semanticState = await database.query<{
      capability_id: string;
      semantic_fence_ready: boolean;
    }>(`
      SELECT capability_id, semantic_fence_ready
      FROM public.ep_capability_state
      WHERE capability_id = 'capability:history'
    `);
    expect(semanticState.rows).toEqual([{
      capability_id: 'capability:history',
      semantic_fence_ready: false,
    }]);

    await expect(database.query(`
      INSERT INTO public.ep_capability_operations (
        operation_namespace,
        operation_id,
        capability_id,
        action_digest,
        action_fence_digest,
        amount,
        currency,
        status,
        reservation_token,
        reserved_at,
        entry_deadline_at
      ) VALUES ($1, $2, $3, $4, $5, 1, 'USD', 'reserved', $6, now(), now() + interval '1 minute')
    `, [
      'capability:history',
      'operation:semantic-retry',
      'capability:history',
      `sha256:${'b'.repeat(64)}`,
      `sha256:${'c'.repeat(64)}`,
      'reservation:semantic-retry',
    ])).rejects.toMatchObject({
      code: '55000',
      message: 'capability semantic action fence is not ready',
      hint: 'Do not unquarantine this legacy capability ID or infer semantic equivalence from historical exact digests. After review, issue a fresh capability with a new capability ID.',
    });

    const freshSemanticState = await database.query<{
      semantic_fence_ready: boolean;
    }>(`
      SELECT semantic_fence_ready
      FROM public.ep_capability_state
      WHERE capability_id = 'capability:fresh'
    `);
    expect(freshSemanticState.rows).toEqual([{ semantic_fence_ready: true }]);

    const freshActionDigest = `sha256:${'4'.repeat(64)}`;
    const freshFenceDigest = `sha256:${'5'.repeat(64)}`;
    await expect(database.query(`
      INSERT INTO public.ep_capability_operations (
        operation_namespace,
        operation_id,
        capability_id,
        action_digest,
        action_fence_digest,
        amount,
        currency,
        status,
        reservation_token,
        reserved_at,
        entry_deadline_at
      ) VALUES ($1, $2, $3, $4, $5, 1, 'USD', 'reserved', $6, now(), now() + interval '1 minute')
    `, [
      'capability:fresh',
      'operation:fresh',
      'capability:fresh',
      freshActionDigest,
      freshFenceDigest,
      'reservation:fresh',
    ])).resolves.toBeDefined();
    await expect(database.query(`
      UPDATE public.ep_capability_operations
      SET status = 'provider_entered', provider_entry_at = now()
      WHERE operation_namespace = 'capability:fresh'
        AND operation_id = 'operation:fresh'
    `)).resolves.toBeDefined();
    await expect(database.query(`
      UPDATE public.ep_capability_operations
      SET status = 'released',
          released_at = now(),
          release_reason = 'authenticated_provider_non_entry',
          release_evidence_profile = 'test-profile',
          release_evidence_digest = $1
      WHERE operation_namespace = 'capability:fresh'
        AND operation_id = 'operation:fresh'
    `, [`sha256:${'6'.repeat(64)}`])).resolves.toBeDefined();

    await expect(database.query(`
      INSERT INTO public.ep_capability_operations (
        operation_namespace,
        operation_id,
        capability_id,
        action_digest,
        action_fence_digest,
        amount,
        currency,
        status,
        reservation_token,
        reserved_at,
        entry_deadline_at
      ) VALUES (
        'capability:fresh',
        'operation:malformed',
        'capability:fresh',
        $1,
        'not-a-digest',
        1,
        'USD',
        'reserved',
        'reservation:malformed',
        now(),
        now() + interval '1 minute'
      )
    `, [freshActionDigest])).rejects.toMatchObject({ code: '23514' });

    // A successful second application proves the explicit transaction,
    // quarantine, trigger, restored constraints, and index contract converge.
    await expect(applyFenceMigration()).resolves.toBeUndefined();

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
    await insertOperation('operation:duplicate:1', duplicateDigest, 'capability:history', 'committed');
    await insertOperation('operation:duplicate:2', duplicateDigest, 'capability:history', 'committed');

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
        status: 'committed',
        action_digest: duplicateDigest,
      },
      {
        operation_id: 'operation:duplicate:2',
        status: 'committed',
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

  it('blocks a legacy reserved row and rolls the complete migration back', async () => {
    await applyHistoricalCapabilityChain();
    await insertCapability();
    await insertOperation('operation:unsafe-reserved', `sha256:${'f'.repeat(64)}`);

    await expect(runPackagedPreflight()).rejects.toMatchObject({
      code: '55000',
      message: 'EMILIA capability action-digest preflight found 1 unsafe legacy reserved operation(s)',
    });
    await expect(applyFenceMigration()).rejects.toMatchObject({
      code: '55000',
      message: 'EMILIA capability action-fence migration found 1 unsafe legacy reserved operation(s)',
    });

    expect(await operationNamespaceExists()).toBe(false);
    const primaryKey = await database.query<{ definition: string }>(`
      SELECT pg_catalog.pg_get_constraintdef(oid) AS definition
      FROM pg_catalog.pg_constraint
      WHERE conrelid = 'public.ep_capability_operations'::pg_catalog.regclass
        AND contype = 'p'
    `);
    expect(primaryKey.rows).toEqual([{ definition: 'PRIMARY KEY (operation_id)' }]);
    const semanticColumn = await database.query<{ exists: boolean }>(`
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'ep_capability_state'
          AND column_name = 'semantic_fence_ready'
      ) AS exists
    `);
    expect(semanticColumn.rows).toEqual([{ exists: false }]);
  });

  it('quarantines unknown legacy revocation policy and accepts only explicit fresh lineage', async () => {
    await applyHistoricalCapabilityChain();
    await insertCapability('capability:legacy-revocation-unknown');
    await applyFenceMigration();
    await expect(applyRevocationMigration()).resolves.toBeUndefined();
    await expect(applyRevocationMigration()).resolves.toBeUndefined();

    const legacy = await database.query<{
      revocation_mode: string | null;
      revocation_state_ready: boolean;
    }>(`
      SELECT revocation_mode, revocation_state_ready
      FROM public.ep_capability_state
      WHERE capability_id = 'capability:legacy-revocation-unknown'
    `);
    expect(legacy.rows).toEqual([{
      revocation_mode: null,
      revocation_state_ready: false,
    }]);

    await expect(database.query(`
      INSERT INTO public.ep_capability_state (
        capability_id, capability_fingerprint, budget_amount, currency,
        expires_at, semantic_fence_ready
      ) VALUES ($1, $2, 10, 'USD', now() + interval '1 hour', TRUE)
    `, [
      'capability:mode-omitted',
      `sha256:${'2'.repeat(64)}`,
    ])).rejects.toMatchObject({ code: '55000' });

    await database.query(`
      INSERT INTO public.ep_capability_state (
        capability_id, capability_fingerprint, budget_amount, currency,
        expires_at, semantic_fence_ready, revocation_mode
      ) VALUES ($1, $2, 10, 'USD', now() + interval '1 hour', TRUE, 'cascade')
    `, [
      'capability:explicit-parent',
      `sha256:${'3'.repeat(64)}`,
    ]);
    await database.query(`
      INSERT INTO public.ep_capability_state (
        capability_id, capability_fingerprint, budget_amount, currency,
        expires_at, semantic_fence_ready, revocation_mode,
        parent_capability_id
      ) VALUES ($1, $2, 5, 'USD', now() + interval '30 minutes', TRUE, 'direct', $3)
    `, [
      'capability:explicit-child',
      `sha256:${'4'.repeat(64)}`,
      'capability:explicit-parent',
    ]);

    const fresh = await database.query<{
      capability_id: string;
      revocation_mode: string;
      parent_capability_id: string | null;
      revocation_state_ready: boolean;
    }>(`
      SELECT capability_id, revocation_mode, parent_capability_id,
             revocation_state_ready
      FROM public.ep_capability_state
      WHERE capability_id IN ('capability:explicit-parent', 'capability:explicit-child')
      ORDER BY capability_id
    `);
    expect(fresh.rows).toEqual([
      {
        capability_id: 'capability:explicit-child',
        revocation_mode: 'direct',
        parent_capability_id: 'capability:explicit-parent',
        revocation_state_ready: true,
      },
      {
        capability_id: 'capability:explicit-parent',
        revocation_mode: 'cascade',
        parent_capability_id: null,
        revocation_state_ready: true,
      },
    ]);

    await expect(database.query(`
      INSERT INTO public.ep_capability_state (
        capability_id, capability_fingerprint, budget_amount, currency,
        expires_at, semantic_fence_ready, revocation_mode,
        parent_capability_id
      ) VALUES ($1, $2, 1, 'USD', now() + interval '10 minutes', TRUE, 'direct', $3)
    `, [
      'capability:missing-parent-child',
      `sha256:${'5'.repeat(64)}`,
      'capability:missing-parent',
    ])).rejects.toMatchObject({ code: '23503' });
  });

  it.each([
    {
      name: 'non-default btree operator classes',
      operationNamespaceDefinition: 'TEXT',
      keys: 'operation_namespace text_pattern_ops, action_fence_digest text_pattern_ops',
    },
    {
      name: 'index collations that differ from their columns',
      operationNamespaceDefinition: 'TEXT COLLATE public.ep_case_insensitive',
      keys: 'operation_namespace COLLATE "C", action_fence_digest COLLATE "C"',
    },
  ])('rejects a same-named fence using $name', async ({
    operationNamespaceDefinition,
    keys,
  }) => {
    await database.query(`
      CREATE COLLATION public.ep_case_insensitive (
        provider = icu,
        locale = 'und-u-ks-level2',
        deterministic = false
      )
    `);
    await applyHistoricalCapabilityChain();
    await database.query(`
      ALTER TABLE public.ep_capability_operations
        ADD COLUMN operation_namespace ${operationNamespaceDefinition},
        ADD COLUMN action_fence_digest TEXT
    `);
    await database.query(`
      CREATE UNIQUE INDEX ep_capability_operations_live_action_uniq
      ON public.ep_capability_operations (${keys})
      WHERE status IN ('reserved', 'provider_entered', 'committed')
    `);

    await expect(runPackagedPreflight()).rejects.toMatchObject({
      code: '55000',
      message: 'EMILIA capability action-digest fence index does not match its required contract',
    });
    await expect(applyFenceMigration()).rejects.toMatchObject({
      code: '55000',
      message: 'EMILIA capability action-digest fence index does not match its required contract',
    });
  });
});
