// SPDX-License-Identifier: Apache-2.0
/**
 * Real PostgreSQL 17 proof for Agent Record v1.
 *
 * The suite applies the production migration unchanged in a disposable database
 * and exercises its RPC, ACL, RLS, replay, custody, and immutability boundaries.
 * Local runs skip unless INTEGRATION_POSTGRES=1 is explicit; the PostgreSQL CI
 * lane sets that flag and therefore cannot silently replace this with a mock.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260803020000_agent_record_v1.sql',
    import.meta.url,
  ),
  'utf8',
);

const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;

const DATABASE = 'ep_agent_record_runtime_test';
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};
const controlDatabase = process.env.PGDATABASE ?? 'ep_test';
const GENERIC_ROLES = ['anon', 'authenticated', 'service_role'] as const;
const GLOBAL_ROLES = [...GENERIC_ROLES, 'agent_record_store_owner'] as const;

const ADOPTION_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_TOKEN = `eaa1_${'1'.repeat(64)}`;
const BOND_ID = '22222222-2222-4222-8222-222222222222';
const BOND_DIGEST = `sha256:${'2'.repeat(64)}`;
const RECORD_ID = `agent_record_${'3'.repeat(40)}`;
const ARENA_SHARE_ID = `arena_share_${'4'.repeat(40)}`;
const ACTION_DIGEST = `sha256:${'5'.repeat(64)}`;
const REFUSAL_DIGEST = `sha256:${'6'.repeat(64)}`;
const SIGNATURE = 'A'.repeat(86);
const CLAIM_BOUNDARY =
  'one_operator_observation_of_one_verified_signed_arena_refusal_only';

type JsonObject = Record<string, unknown>;
type CreatedRecord = {
  record_id: string;
  owner_token: string;
  created_at: string;
  retention_expires_at: string;
  public_projection: JsonObject;
};

let admin: pg.Client;
let database: pg.Pool;
let adminConnected = false;
let initiallyPresentRoles = new Set<string>();

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function instant(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function sourceProjection(input: {
  actionDigest: string;
  refusalDigest: string;
  refusedAt: string;
  decision?: 'refuse' | 'permit';
}): JsonObject {
  return {
    profile: 'EP-ARENA-PUBLIC-REFUSAL-v1',
    attempt: {
      decision: input.decision ?? 'refuse',
      action_digest: input.actionDigest,
      created_at: input.refusedAt,
    },
    refusal_artifact: {
      '@version': 'EP-ACTION-REFUSAL-STATEMENT-v1',
    },
    refusal_digest: input.refusalDigest,
  };
}

function recordProjection(input: {
  recordId: string;
  bondId: string;
  bondDigest: string;
  arenaShareId: string;
  sourceArtifactDigest: string;
  actionDigest: string;
  refusalDigest: string;
  refusedAt: string;
  observedAt: string;
  retentionExpiresAt: string;
}): JsonObject {
  return {
    '@version': 'EP-AGENT-RECORD-OBSERVATION-v1',
    record: {
      record_id: input.recordId,
      bond: {
        bond_id: input.bondId,
        bond_digest: input.bondDigest,
      },
      source: {
        profile: 'EP-ACTION-REFUSAL-STATEMENT-v1',
        arena_share_id: input.arenaShareId,
        artifact_digest: input.sourceArtifactDigest,
      },
      action: { action_digest: input.actionDigest },
      refusal: {
        refusal_digest: input.refusalDigest,
        refused_at: input.refusedAt,
      },
      observed_at: input.observedAt,
      retention_expires_at: input.retentionExpiresAt,
      claim_boundary: CLAIM_BOUNDARY,
    },
    signature: {
      algorithm: 'Ed25519',
      key_id: 'ep-signing-key-1',
      key_source: 'operator-commit-signing-key',
      value: SIGNATURE,
    },
  };
}

type CreateInput = {
  adoptionId: string;
  sessionToken: string;
  recordId: string;
  bondId: string;
  bondDigest: string;
  arenaShareId: string;
  sourceArtifactDigest: string;
  actionDigest: string;
  refusalDigest: string;
  refusedAt: string;
  observedAt: string;
  retentionExpiresAt: string;
  publicProjection: JsonObject;
};

function createInput(overrides: Partial<CreateInput> = {}): CreateInput {
  const observedAt = overrides.observedAt ?? instant(-1_000);
  const refusedAt = overrides.refusedAt ?? instant(-2_000);
  const retentionExpiresAt = overrides.retentionExpiresAt
    ?? new Date(Date.parse(observedAt) + 365 * 24 * 60 * 60 * 1_000).toISOString();
  const input = {
    adoptionId: ADOPTION_ID,
    sessionToken: SESSION_TOKEN,
    recordId: RECORD_ID,
    bondId: BOND_ID,
    bondDigest: BOND_DIGEST,
    arenaShareId: ARENA_SHARE_ID,
    sourceArtifactDigest: REFUSAL_DIGEST,
    actionDigest: ACTION_DIGEST,
    refusalDigest: REFUSAL_DIGEST,
    refusedAt,
    observedAt,
    retentionExpiresAt,
    ...overrides,
  };
  return {
    ...input,
    publicProjection: overrides.publicProjection ?? recordProjection(input),
  };
}

async function asRole<T>(
  role: (typeof GENERIC_ROLES)[number],
  callback: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const client = await database.connect();
  try {
    await client.query(`SET ROLE ${identifier(role)}`);
    return await callback(client);
  } finally {
    await client.query('RESET ROLE').catch(() => undefined);
    client.release();
  }
}

async function createRecord(
  input: CreateInput,
  role: (typeof GENERIC_ROLES)[number] = 'service_role',
): Promise<CreatedRecord> {
  return asRole(role, async (client) => {
    const result = await client.query<{ result: CreatedRecord }>(
      `SELECT public.create_agent_record(
         $1::uuid, $2, $3, $4::uuid, $5, $6, $7, $8, $9,
         $10::timestamptz, $11::timestamptz, $12::timestamptz, $13::jsonb
       ) AS result`,
      [
        input.adoptionId,
        input.sessionToken,
        input.recordId,
        input.bondId,
        input.bondDigest,
        input.arenaShareId,
        input.sourceArtifactDigest,
        input.actionDigest,
        input.refusalDigest,
        input.refusedAt,
        input.observedAt,
        input.retentionExpiresAt,
        JSON.stringify(input.publicProjection),
      ],
    );
    return result.rows[0].result;
  });
}

async function insertArenaShare(input: {
  arenaShareId: string;
  actionDigest: string;
  refusalDigest: string;
  refusedAt: string;
  decision?: 'refuse' | 'permit';
}): Promise<void> {
  await database.query(
    `INSERT INTO public.arena_shares (share_id, public_projection)
     VALUES ($1, $2::jsonb)`,
    [input.arenaShareId, JSON.stringify(sourceProjection(input))],
  );
}

async function readPublic(
  recordId: string,
): Promise<{ record_id: string; public_projection: JsonObject }> {
  return asRole('anon', async (client) => {
    const result = await client.query<{
      result: { record_id: string; public_projection: JsonObject };
    }>('SELECT public.read_agent_record_public($1) AS result', [recordId]);
    return result.rows[0].result;
  });
}

async function revoke(
  recordId: string,
  ownerToken: string,
  nonce = `earv1_${'7'.repeat(64)}`,
): Promise<JsonObject> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ result: JsonObject }>(
      'SELECT public.revoke_agent_record($1, $2, $3) AS result',
      [recordId, ownerToken, nonce],
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

async function cleanup(): Promise<void> {
  if (database) await database.end();
  await terminateTestDatabaseConnections();
  await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
  for (const role of [...GLOBAL_ROLES].reverse()) {
    if (!initiallyPresentRoles.has(role)) {
      await admin.query(`DROP ROLE IF EXISTS ${identifier(role)}`);
    }
  }
}

suite('Agent Record v1 RPC lifecycle on PostgreSQL 17', () => {
  beforeAll(async () => {
    admin = new pg.Client({ ...baseConnection, database: controlDatabase });
    await admin.connect();
    adminConnected = true;

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

    const roles = await admin.query<{ rolname: string }>(
      'SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])',
      [GLOBAL_ROLES],
    );
    initiallyPresentRoles = new Set(roles.rows.map(({ rolname }) => rolname));

    await terminateTestDatabaseConnections();
    await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
    for (const role of GENERIC_ROLES) {
      await admin.query(`
        DO $role$ BEGIN
          CREATE ROLE ${identifier(role)} NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $role$
      `);
    }
    await admin.query(`CREATE DATABASE ${identifier(DATABASE)} TEMPLATE template0`);
    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 10 });

    // Minimal, database-local Supabase predecessor surface. The adoption reader
    // is deliberately exact and bounded; every other pair receives P0002.
    await database.query(`
      CREATE SCHEMA extensions;
      CREATE EXTENSION pgcrypto WITH SCHEMA extensions;

      CREATE TABLE public.arena_shares (
        share_id TEXT COLLATE "C" PRIMARY KEY,
        public_projection JSONB NOT NULL,
        revoked_at TIMESTAMPTZ
      );
      ALTER TABLE public.arena_shares ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.arena_shares FORCE ROW LEVEL SECURITY;
      REVOKE ALL ON TABLE public.arena_shares
        FROM PUBLIC, anon, authenticated, service_role;

      CREATE FUNCTION public.read_agent_adoption_session(
        p_adoption_id UUID,
        p_session_token TEXT
      ) RETURNS JSONB
      LANGUAGE plpgsql
      STABLE
      SECURITY DEFINER
      SET search_path = ''
      AS $stub$
      BEGIN
        IF p_adoption_id IS DISTINCT FROM '${ADOPTION_ID}'::uuid
          OR p_session_token IS DISTINCT FROM '${SESSION_TOKEN}'
        THEN
          RAISE EXCEPTION 'agent adoption session not found'
            USING ERRCODE = 'P0002';
        END IF;
        RETURN pg_catalog.jsonb_build_object(
          'status', 'active',
          'adoption_id', '${ADOPTION_ID}',
          'bond_count', 1,
          'latest_bond_id', '${BOND_ID}',
          'bond_digest', '${BOND_DIGEST}',
          'latest_bond_digest', '${BOND_DIGEST}'
        );
      END
      $stub$;
      REVOKE ALL ON FUNCTION public.read_agent_adoption_session(UUID, TEXT)
        FROM PUBLIC, anon, authenticated, service_role;
    `);

    const refusedAt = instant(-3_000);
    await insertArenaShare({
      arenaShareId: ARENA_SHARE_ID,
      actionDigest: ACTION_DIGEST,
      refusalDigest: REFUSAL_DIGEST,
      refusedAt,
    });
    await database.query(migration);
  }, 30_000);

  afterAll(async () => {
    if (!adminConnected) return;
    try {
      await cleanup();
      const gone = await admin.query<{ exists: boolean }>(
        'SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1) AS exists',
        [DATABASE],
      );
      expect(gone.rows).toEqual([{ exists: false }]);
    } finally {
      await admin.end();
    }
  });

  it('creates one refusal-bound record and returns an unstored owner token once', async () => {
    const source = await database.query<{ public_projection: JsonObject }>(
      'SELECT public_projection FROM public.arena_shares WHERE share_id = $1',
      [ARENA_SHARE_ID],
    );
    const refusedAt = String(
      (source.rows[0].public_projection.attempt as JsonObject).created_at,
    );
    const input = createInput({ refusedAt });
    const created = await createRecord(input);

    expect(created).toMatchObject({
      record_id: RECORD_ID,
      owner_token: expect.stringMatching(/^ear1_[0-9a-f]{64}$/),
      created_at: input.observedAt,
      retention_expires_at: input.retentionExpiresAt,
      public_projection: input.publicProjection,
    });

    const stored = await database.query<{
      owner_token_hash: string;
      public_projection: JsonObject;
      row_text: string;
    }>(`
      SELECT
        owner_token_hash,
        public_projection,
        pg_catalog.row_to_json(record)::text AS row_text
      FROM agent_record_private.records AS record
      WHERE record_id = $1
    `, [RECORD_ID]);
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0].owner_token_hash).toBe(
      createHash('sha256').update(created.owner_token, 'utf8').digest('hex'),
    );
    expect(stored.rows[0].row_text).not.toContain(created.owner_token);
    expect(JSON.stringify(stored.rows[0].public_projection)).not.toContain(
      created.owner_token,
    );
  });

  it('accepts a rotated safe key id and rejects key ids outside the closed set', async () => {
    const safeShareId = `arena_share_${'7'.repeat(40)}`;
    const safeRefusalDigest = digest('7');
    const safeActionDigest = digest('8');
    const safeRefusedAt = instant(-2_000);
    await insertArenaShare({
      arenaShareId: safeShareId,
      actionDigest: safeActionDigest,
      refusalDigest: safeRefusalDigest,
      refusedAt: safeRefusedAt,
    });
    const safeInput = createInput({
      recordId: `agent_record_${'7'.repeat(40)}`,
      arenaShareId: safeShareId,
      sourceArtifactDigest: safeRefusalDigest,
      refusalDigest: safeRefusalDigest,
      actionDigest: safeActionDigest,
      refusedAt: safeRefusedAt,
    });
    const safeProjection = structuredClone(safeInput.publicProjection);
    (safeProjection.signature as JsonObject).key_id = 'agent-record-key:2026.08-b';

    await expect(createRecord({
      ...safeInput,
      publicProjection: safeProjection,
    })).resolves.toMatchObject({
      record_id: safeInput.recordId,
      public_projection: safeProjection,
    });

    const unsafeShareId = `arena_share_${'0'.repeat(40)}`;
    const unsafeRefusalDigest = digest('0');
    const unsafeActionDigest = digest('f');
    const unsafeRefusedAt = instant(-2_000);
    await insertArenaShare({
      arenaShareId: unsafeShareId,
      actionDigest: unsafeActionDigest,
      refusalDigest: unsafeRefusalDigest,
      refusedAt: unsafeRefusedAt,
    });
    const unsafeInput = createInput({
      recordId: `agent_record_${'8'.repeat(40)}`,
      arenaShareId: unsafeShareId,
      sourceArtifactDigest: unsafeRefusalDigest,
      refusalDigest: unsafeRefusalDigest,
      actionDigest: unsafeActionDigest,
      refusedAt: unsafeRefusedAt,
    });
    for (const keyId of ['unsafe/key', 'constructor']) {
      const unsafeProjection = structuredClone(unsafeInput.publicProjection);
      (unsafeProjection.signature as JsonObject).key_id = keyId;

      await expect(createRecord({
        ...unsafeInput,
        publicProjection: unsafeProjection,
      }), keyId).rejects.toMatchObject({ code: '22023' });
    }
  });

  it('serializes same-source creation so exactly one concurrent replay wins', async () => {
    const arenaShareId = `arena_share_${'8'.repeat(40)}`;
    const refusalDigest = digest('9');
    const actionDigest = digest('a');
    const refusedAt = instant(-2_000);
    await insertArenaShare({ arenaShareId, actionDigest, refusalDigest, refusedAt });

    const first = createInput({
      recordId: `agent_record_${'b'.repeat(40)}`,
      arenaShareId,
      sourceArtifactDigest: refusalDigest,
      refusalDigest,
      actionDigest,
      refusedAt,
    });
    const secondValues = {
      ...first,
      recordId: `agent_record_${'c'.repeat(40)}`,
    };
    const second = {
      ...secondValues,
      publicProjection: recordProjection(secondValues),
    };

    const results = await Promise.allSettled([
      createRecord(first),
      createRecord(second),
    ]);
    const fulfilled = results.filter((result) => result.status === 'fulfilled');
    const rejected = results.filter((result) => result.status === 'rejected');
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({
      code: '23505',
    });

    const count = await database.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM agent_record_private.records
        WHERE arena_share_id = $1 OR source_artifact_digest = $2`,
      [arenaShareId, refusalDigest],
    );
    expect(count.rows).toEqual([{ count: '1' }]);
  });

  it('refuses cross-boundary and permit substitutions before persistence', async () => {
    const cases: Array<{
      name: string;
      input: CreateInput;
      code: string;
    }> = [];
    const source = await database.query<{ public_projection: JsonObject }>(
      'SELECT public_projection FROM public.arena_shares WHERE share_id = $1',
      [ARENA_SHARE_ID],
    );
    const base = createInput({
      recordId: `agent_record_${'d'.repeat(40)}`,
      refusedAt: String(
        (source.rows[0].public_projection.attempt as JsonObject).created_at,
      ),
    });

    const wrongBondValues = {
      ...base,
      recordId: `agent_record_${'e'.repeat(40)}`,
      bondId: '33333333-3333-4333-8333-333333333333',
    };
    cases.push({
      name: 'cross-bond',
      input: {
        ...wrongBondValues,
        publicProjection: recordProjection(wrongBondValues),
      },
      code: '55000',
    });

    const sourceValues = {
      ...base,
      recordId: `agent_record_${'f'.repeat(40)}`,
      sourceArtifactDigest: digest('f'),
      refusalDigest: digest('f'),
    };
    cases.push({
      name: 'source substitution',
      input: {
        ...sourceValues,
        publicProjection: recordProjection(sourceValues),
      },
      code: '55000',
    });

    const actionValues = {
      ...base,
      recordId: `agent_record_${'0'.repeat(40)}`,
      actionDigest: digest('0'),
    };
    cases.push({
      name: 'action substitution',
      input: {
        ...actionValues,
        publicProjection: recordProjection(actionValues),
      },
      code: '55000',
    });

    const permitShareId = `arena_share_${'1'.repeat(40)}`;
    const permitDigest = digest('1');
    const permitActionDigest = digest('3');
    const permitRefusedAt = instant(-2_000);
    await insertArenaShare({
      arenaShareId: permitShareId,
      actionDigest: permitActionDigest,
      refusalDigest: permitDigest,
      refusedAt: permitRefusedAt,
      decision: 'permit',
    });
    const permitValues = createInput({
      recordId: `agent_record_${'1'.repeat(40)}`,
      arenaShareId: permitShareId,
      sourceArtifactDigest: permitDigest,
      refusalDigest: permitDigest,
      actionDigest: permitActionDigest,
      refusedAt: permitRefusedAt,
    });
    cases.push({ name: 'permit substitution', input: permitValues, code: '55000' });

    for (const testCase of cases) {
      try {
        await createRecord(testCase.input);
        throw new Error(`${testCase.name} unexpectedly created an Agent Record`);
      } catch (error) {
        if ((error as { code?: string }).code !== testCase.code) {
          throw new Error(
            `${testCase.name} failed with ${(error as { code?: string }).code}: ${String((error as { message?: string }).message)}`,
            { cause: error },
          );
        }
        expect(error, testCase.name).toMatchObject({ code: testCase.code });
      }
    }

    const count = await database.query<{ count: string }>(
      `SELECT count(*)::text AS count
         FROM agent_record_private.records
        WHERE record_id = ANY($1::text[])`,
      [cases.map(({ input }) => input.recordId)],
    );
    expect(count.rows).toEqual([{ count: '0' }]);
  });

  it('exposes only exact public lookup and no enumerable or direct table surface', async () => {
    const publicRecord = await readPublic(RECORD_ID);
    expect(publicRecord).toMatchObject({
      record_id: RECORD_ID,
      public_projection: {
        '@version': 'EP-AGENT-RECORD-OBSERVATION-v1',
      },
    });

    const functions = await database.query<{ proname: string }>(`
      SELECT procedure.proname
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
       WHERE namespace.nspname = 'public'
         AND procedure.proname LIKE '%agent_record%'
       ORDER BY procedure.proname
    `);
    expect(functions.rows.map(({ proname }) => proname)).toEqual([
      'create_agent_record',
      'read_agent_record_public',
      'revoke_agent_record',
    ]);
    expect(functions.rows.map(({ proname }) => proname).join(' ')).not.toMatch(
      /list|search|feed|sitemap|enumerate/,
    );

    for (const role of ['anon', 'authenticated', 'service_role'] as const) {
      await expect(asRole(role, (client) => client.query(
        'SELECT * FROM agent_record_private.records',
      ))).rejects.toMatchObject({ code: '42501' });
    }
  });

  it('requires the owner token and makes unknown and revoked reads indistinguishable', async () => {
    const stored = await database.query<{ row_text: string }>(`
      SELECT pg_catalog.row_to_json(record)::text AS row_text
        FROM agent_record_private.records AS record
       WHERE record_id = $1
    `, [RECORD_ID]);
    const ownerHash = JSON.parse(stored.rows[0].row_text).owner_token_hash as string;

    // The plaintext owner token was deliberately returned only by the creation
    // test, so recover it from that test is impossible. Create a second record
    // here and retain its one-time return solely for the revocation ceremony.
    const shareId = `arena_share_${'2'.repeat(40)}`;
    const sourceDigest = digest('4');
    const actionDigest = digest('5');
    const refusedAt = instant(-2_000);
    await insertArenaShare({
      arenaShareId: shareId,
      actionDigest,
      refusalDigest: sourceDigest,
      refusedAt,
    });
    const input = createInput({
      recordId: `agent_record_${'6'.repeat(40)}`,
      arenaShareId: shareId,
      sourceArtifactDigest: sourceDigest,
      refusalDigest: sourceDigest,
      actionDigest,
      refusedAt,
    });
    const created = await createRecord(input);
    expect(ownerHash).toMatch(/^[0-9a-f]{64}$/);

    await expect(revoke(
      input.recordId,
      `ear1_${'f'.repeat(64)}`,
    )).rejects.toMatchObject({ code: 'P0002', message: 'agent record not found' });

    let unknownError: unknown;
    let revokedError: unknown;
    try {
      await readPublic(`agent_record_${'9'.repeat(40)}`);
    } catch (error) {
      unknownError = error;
    }

    await expect(revoke(input.recordId, created.owner_token)).resolves.toMatchObject({
      record_id: input.recordId,
      revoked: true,
    });
    try {
      await readPublic(input.recordId);
    } catch (error) {
      revokedError = error;
    }
    expect(unknownError).toMatchObject({ code: 'P0002', message: 'agent record not found' });
    expect(revokedError).toMatchObject({ code: 'P0002', message: 'agent record not found' });
  });

  it('forces RLS and rejects direct service-role access and immutable mutations', async () => {
    const relations = await database.query<{
      relname: string;
      relrowsecurity: boolean;
      relforcerowsecurity: boolean;
    }>(`
      SELECT class.relname, class.relrowsecurity, class.relforcerowsecurity
        FROM pg_catalog.pg_class AS class
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = class.relnamespace
       WHERE namespace.nspname = 'agent_record_private'
         AND class.relname = ANY($1::text[])
       ORDER BY class.relname
    `, [['records', 'revocations']]);
    expect(relations.rows).toEqual([
      { relname: 'records', relrowsecurity: true, relforcerowsecurity: true },
      { relname: 'revocations', relrowsecurity: true, relforcerowsecurity: true },
    ]);

    const direct = await database.query<{
      table_name: string;
      can_select: boolean;
      can_update: boolean;
      can_delete: boolean;
    }>(`
      SELECT table_name,
             has_table_privilege('service_role',
               'agent_record_private.' || table_name, 'SELECT') AS can_select,
             has_table_privilege('service_role',
               'agent_record_private.' || table_name, 'UPDATE') AS can_update,
             has_table_privilege('service_role',
               'agent_record_private.' || table_name, 'DELETE') AS can_delete
        FROM (VALUES ('records'), ('revocations')) AS tables(table_name)
       ORDER BY table_name
    `);
    expect(direct.rows).toEqual([
      { table_name: 'records', can_select: false, can_update: false, can_delete: false },
      { table_name: 'revocations', can_select: false, can_update: false, can_delete: false },
    ]);

    await expect(asRole('service_role', (client) => client.query(
      'SELECT * FROM agent_record_private.records',
    ))).rejects.toMatchObject({ code: '42501' });
    await expect(database.query(
      'UPDATE agent_record_private.records SET bond_digest = bond_digest WHERE record_id = $1',
      [RECORD_ID],
    )).rejects.toMatchObject({ code: '55000' });
    await expect(database.query(
      'DELETE FROM agent_record_private.records WHERE record_id = $1',
      [RECORD_ID],
    )).rejects.toMatchObject({ code: '55000' });

    const revoked = await database.query<{ record_id: string }>(
      'SELECT record_id FROM agent_record_private.revocations LIMIT 1',
    );
    expect(revoked.rows).toHaveLength(1);
    await expect(database.query(
      'UPDATE agent_record_private.revocations SET revoked_at = revoked_at WHERE record_id = $1',
      [revoked.rows[0].record_id],
    )).rejects.toMatchObject({ code: '55000' });
    await expect(database.query(
      'DELETE FROM agent_record_private.revocations WHERE record_id = $1',
      [revoked.rows[0].record_id],
    )).rejects.toMatchObject({ code: '55000' });
  });
});
