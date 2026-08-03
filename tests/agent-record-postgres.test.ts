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
import { spawnSync } from 'node:child_process';
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
const ARENA_SESSION_ID = `arena_session_${'4'.repeat(32)}`;
const ARENA_TOKEN_HASH = '4'.repeat(64);
const ARENA_ATTEMPT_ID = `arena_attempt_${'4'.repeat(32)}`;
const ACTION_DIGEST = `sha256:${'5'.repeat(64)}`;
const REFUSAL_DIGEST = `sha256:${'6'.repeat(64)}`;
const OWNER_TOKEN = `ear1_${'a'.repeat(64)}`;
const SIGNATURE = 'A'.repeat(86);
const CLAIM_BOUNDARY =
  'one_operator_observation_of_one_verified_signed_arena_refusal_only';

type JsonObject = Record<string, unknown>;
type CreatedRecord = {
  record_id: string;
  created_at: string;
  retention_expires_at: string;
  public_projection: JsonObject;
};

let admin: pg.Client;
let database: pg.Pool;
let adminConnected = false;
let initiallyPresentRoles = new Set<string>();
let initialServiceRoleBypassRls: boolean | undefined;
let deploymentRollbackProof: {
  psqlExitStatus: number | null;
  psqlReportedInjectedFailure: boolean;
  currentUser: string;
  sessionUser: string;
  ownerRoleUnchanged: boolean;
  ownerMembershipUnchanged: boolean;
  privateSchemas: string[];
  publicFunctions: string[];
  serviceRoleCanSelect: boolean;
  serviceRoleCanInsert: boolean;
  serviceRoleCanUpdate: boolean;
  serviceRoleCanDelete: boolean;
};

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function instant(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function recordProjection(input: {
  recordId: string;
  bondId: string;
  bondDigest: string;
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
  ownerToken: string;
  bondId: string;
  bondDigest: string;
  arenaSessionId: string;
  arenaTokenHash: string;
  arenaAttemptId: string;
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
  const recordId = overrides.recordId ?? RECORD_ID;
  const retentionExpiresAt = overrides.retentionExpiresAt
    ?? new Date(Date.parse(observedAt) + 365 * 24 * 60 * 60 * 1_000).toISOString();
  const input = {
    adoptionId: ADOPTION_ID,
    sessionToken: SESSION_TOKEN,
    recordId,
    ownerToken: overrides.ownerToken
      ?? `ear1_${createHash('sha256').update(recordId, 'utf8').digest('hex')}`,
    bondId: BOND_ID,
    bondDigest: BOND_DIGEST,
    arenaSessionId: ARENA_SESSION_ID,
    arenaTokenHash: ARENA_TOKEN_HASH,
    arenaAttemptId: ARENA_ATTEMPT_ID,
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

async function inRollbackAsRole<T>(
  role: (typeof GENERIC_ROLES)[number],
  callback: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const client = await database.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL ROLE ${identifier(role)}`);
    return await callback(client);
  } finally {
    await client.query('ROLLBACK').catch(() => undefined);
    client.release();
  }
}

async function rolledBackRoleOutcome(
  callback: (client: pg.PoolClient) => Promise<unknown>,
): Promise<string> {
  try {
    await inRollbackAsRole('service_role', callback);
    return 'SUCCEEDED';
  } catch (error) {
    return (error as { code?: string }).code ?? 'UNKNOWN_ERROR';
  }
}

async function createRecord(
  input: CreateInput,
  role: (typeof GENERIC_ROLES)[number] = 'service_role',
): Promise<CreatedRecord> {
  return asRole(role, async (client) => {
    const result = await client.query<{ result: CreatedRecord }>(
      `SELECT public.create_agent_record(
         $1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10,
         $11, $12, $13::timestamptz, $14::timestamptz, $15::timestamptz, $16::jsonb
       ) AS result`,
      [
        input.adoptionId,
        input.sessionToken,
        input.recordId,
        input.ownerToken,
        input.bondId,
        input.bondDigest,
        input.arenaSessionId,
        input.arenaTokenHash,
        input.arenaAttemptId,
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

async function insertArenaRefusal(input: {
  attemptId: string;
  actionDigest: string;
  refusalDigest: string;
  refusedAt: string;
  decision?: 'refuse' | 'permit';
}): Promise<void> {
  await database.query(
    `INSERT INTO public.arena_attempts (
       tenant_id, session_row_id, session_id, challenge_id, challenge_version,
       attempt_id, attempt_nonce, action, action_digest, caid, decision, reason,
       evidence_status, refusal_artifact, refusal_digest, created_at
     )
     SELECT session.tenant_id, session.id, session.session_id,
            session.challenge_id, session.challenge_version,
            $1, $2, $3::jsonb, $4,
            $5, $6, $7, $8, $9::jsonb, $10, $11::timestamptz
       FROM public.arena_sessions AS session
      WHERE session.session_id = $12`,
    [
      input.attemptId,
      `nonce_${input.attemptId.slice(-32)}`,
      JSON.stringify({ operation_id: `adopt:${input.attemptId}` }),
      input.actionDigest,
      `caid:1:arena.resource.allocate.1:jcs-sha256:${'A'.repeat(43)}`,
      input.decision ?? 'refuse',
      input.decision === 'permit' ? null : 'allowance_per_action_limit_exceeded',
      input.decision === 'permit' ? 'not_applicable' : 'complete',
      input.decision === 'permit' ? null : JSON.stringify({
        '@version': 'EP-ACTION-REFUSAL-STATEMENT-v1',
      }),
      input.decision === 'permit' ? null : input.refusalDigest,
      input.refusedAt,
      ARENA_SESSION_ID,
    ],
  );
}

async function readPublic(
  recordId: string,
): Promise<{ record_id: string; public_projection: JsonObject }> {
  return asRole('service_role', async (client) => {
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
  if (
    initiallyPresentRoles.has('service_role')
    && initialServiceRoleBypassRls !== undefined
  ) {
    await admin.query(
      `ALTER ROLE service_role ${initialServiceRoleBypassRls ? 'BYPASSRLS' : 'NOBYPASSRLS'}`,
    );
  }
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

    const roles = await admin.query<{ rolname: string; rolbypassrls: boolean }>(
      'SELECT rolname, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])',
      [GLOBAL_ROLES],
    );
    initiallyPresentRoles = new Set(roles.rows.map(({ rolname }) => rolname));
    initialServiceRoleBypassRls = roles.rows.find(
      ({ rolname }) => rolname === 'service_role',
    )?.rolbypassrls;

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
    await admin.query('ALTER ROLE service_role BYPASSRLS');
    await admin.query(`CREATE DATABASE ${identifier(DATABASE)} TEMPLATE template0`);
    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 10 });

    // Minimal, database-local Supabase predecessor surface. The adoption reader
    // is deliberately exact and bounded; every other pair receives P0002.
    await database.query(`
      CREATE SCHEMA extensions;
      CREATE EXTENSION pgcrypto WITH SCHEMA extensions;

      CREATE TABLE public.arena_sessions (
        id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
        tenant_id UUID NOT NULL DEFAULT extensions.gen_random_uuid(),
        session_id TEXT NOT NULL UNIQUE,
        token_hash TEXT NOT NULL UNIQUE,
        challenge_id TEXT NOT NULL,
        challenge_version BIGINT NOT NULL,
        issuer_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        status TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL
      );
      CREATE TABLE public.arena_attempts (
        tenant_id UUID NOT NULL,
        session_row_id UUID NOT NULL,
        session_id TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        challenge_version BIGINT NOT NULL,
        attempt_id TEXT PRIMARY KEY,
        attempt_nonce TEXT NOT NULL,
        action JSONB NOT NULL,
        action_digest TEXT NOT NULL,
        caid TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT,
        evidence_status TEXT NOT NULL,
        refusal_artifact JSONB,
        refusal_digest TEXT,
        created_at TIMESTAMPTZ NOT NULL
      );
      CREATE TABLE public.arena_shares (
        share_id TEXT COLLATE "C" PRIMARY KEY,
        tenant_id UUID NOT NULL,
        session_row_id UUID NOT NULL,
        session_id TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        challenge_version BIGINT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        attempt_nonce TEXT NOT NULL,
        public_projection JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        revoked_at TIMESTAMPTZ
      );
      ALTER TABLE public.arena_shares ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.arena_shares FORCE ROW LEVEL SECURITY;
      REVOKE ALL ON TABLE public.arena_shares
        FROM PUBLIC, anon, authenticated;
      GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.arena_shares
        TO service_role;

      CREATE FUNCTION public.publish_arena_refusal(
        p_token_hash TEXT,
        p_attempt_id TEXT
      ) RETURNS JSONB
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = ''
      AS $arena_publish$
      DECLARE
        v_attempt public.arena_attempts%ROWTYPE;
        v_session public.arena_sessions%ROWTYPE;
        v_share_id TEXT;
        v_projection JSONB;
      BEGIN
        SELECT attempt.* INTO v_attempt
          FROM public.arena_attempts AS attempt
          JOIN public.arena_sessions AS session
            ON session.id = attempt.session_row_id
         WHERE attempt.attempt_id = p_attempt_id
           AND session.token_hash = p_token_hash;
        IF NOT FOUND THEN
          RETURN pg_catalog.jsonb_build_object('ok', false, 'status', 404);
        END IF;
        SELECT session.* INTO v_session
          FROM public.arena_sessions AS session
         WHERE session.id = v_attempt.session_row_id;
        IF v_attempt.decision <> 'refuse'
          OR v_attempt.evidence_status <> 'complete'
        THEN
          RETURN pg_catalog.jsonb_build_object('ok', false, 'status', 409);
        END IF;
        SELECT share.share_id INTO v_share_id
          FROM public.arena_shares AS share
         WHERE share.attempt_id = p_attempt_id;
        IF FOUND THEN
          RETURN pg_catalog.jsonb_build_object(
            'ok', true, 'idempotent', true, 'share_id', v_share_id
          );
        END IF;
        v_share_id := 'arena_share_' ||
          pg_catalog.encode(extensions.gen_random_bytes(20), 'hex');
        v_projection := pg_catalog.jsonb_build_object(
          'profile', 'EP-ARENA-PUBLIC-REFUSAL-v1',
          'challenge_id', v_session.challenge_id,
          'challenge_version', v_session.challenge_version,
          'attempt', pg_catalog.jsonb_build_object(
            'attempt_id', v_attempt.attempt_id,
            'action', v_attempt.action,
            'caid', v_attempt.caid,
            'action_digest', v_attempt.action_digest,
            'decision', v_attempt.decision,
            'reason', v_attempt.reason,
            'created_at', pg_catalog.to_char(
              v_attempt.created_at AT TIME ZONE 'UTC',
              'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            )
          ),
          'refusal_artifact', v_attempt.refusal_artifact,
          'refusal_digest', v_attempt.refusal_digest,
          'issuer', pg_catalog.jsonb_build_object(
            'issuer_id', v_session.issuer_id,
            'key_id', v_session.key_id,
            'public_key', v_session.public_key
          ),
          'claim_boundary',
            'synthetic_challenge_not_identity_competence_certification_money_or_production_authority'
        );
        INSERT INTO public.arena_shares (
          share_id, tenant_id, session_row_id, session_id, challenge_id,
          challenge_version, attempt_id, attempt_nonce, public_projection
        ) VALUES (
          v_share_id, v_session.tenant_id, v_session.id, v_session.session_id,
          v_session.challenge_id, v_session.challenge_version,
          v_attempt.attempt_id, v_attempt.attempt_nonce, v_projection
        );
        RETURN pg_catalog.jsonb_build_object(
          'ok', true, 'idempotent', false, 'share_id', v_share_id
        );
      END
      $arena_publish$;
      REVOKE ALL ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)
        FROM PUBLIC, anon, authenticated;
      GRANT EXECUTE ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)
        TO service_role;

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

    await database.query(
      `INSERT INTO public.arena_sessions (
         session_id, token_hash, challenge_id, challenge_version,
         issuer_id, key_id, public_key, status, expires_at
       ) VALUES ($1, $2, 'emilia.arena.allowance', 1,
                 'arena:test', 'arena:test:key', 'test-public-key',
                 'active', $3::timestamptz)`,
      [ARENA_SESSION_ID, ARENA_TOKEN_HASH, instant(60_000)],
    );
    const refusedAt = instant(-3_000);
    await insertArenaRefusal({
      attemptId: ARENA_ATTEMPT_ID,
      actionDigest: ACTION_DIGEST,
      refusalDigest: REFUSAL_DIGEST,
      refusedAt,
    });

    const cleanupMarker = '\nDO $restore_migration_role$';
    if (!migration.includes(cleanupMarker)) {
      throw new Error('Agent Record migration cleanup marker is missing');
    }
    const failingMigration = migration.replace(
      cleanupMarker,
      `
DO $agent_record_injected_deployment_failure$
BEGIN
  RAISE EXCEPTION 'injected pre-cleanup deployment failure'
    USING ERRCODE = 'XX000';
END
$agent_record_injected_deployment_failure$;
${cleanupMarker}`,
    );
    const migrationClient = await database.connect();
    try {
      const rollbackBaseline = await migrationClient.query<{
        ownerRoleExists: boolean;
        ownerMembershipExists: boolean;
      }>(`
        SELECT
          EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles
             WHERE rolname = 'agent_record_store_owner'
          ) AS "ownerRoleExists",
          EXISTS (
            SELECT 1
              FROM pg_catalog.pg_auth_members AS membership
              JOIN pg_catalog.pg_roles AS granted_role
                ON granted_role.oid = membership.roleid
              JOIN pg_catalog.pg_roles AS member_role
                ON member_role.oid = membership.member
             WHERE granted_role.rolname = 'agent_record_store_owner'
               AND member_role.rolname = SESSION_USER
          ) AS "ownerMembershipExists"
      `);
      const directPostgresFailure = spawnSync(
        'psql',
        [
          '--single-transaction',
          '--set=ON_ERROR_STOP=1',
          '--file=-',
        ],
        {
          encoding: 'utf8',
          env: {
            ...process.env,
            PGHOST: baseConnection.host,
            PGPORT: String(baseConnection.port),
            PGUSER: baseConnection.user,
            PGPASSWORD: baseConnection.password,
            PGDATABASE: DATABASE,
          },
          input: failingMigration,
        },
      );

      const rollbackState = await migrationClient.query<{
        currentUser: string;
        sessionUser: string;
        ownerRoleExists: boolean;
        ownerMembershipExists: boolean;
        privateSchemas: string[];
        publicFunctions: string[];
        serviceRoleCanSelect: boolean;
        serviceRoleCanInsert: boolean;
        serviceRoleCanUpdate: boolean;
        serviceRoleCanDelete: boolean;
      }>(`
        SELECT
          CURRENT_USER::TEXT AS "currentUser",
          SESSION_USER::TEXT AS "sessionUser",
          EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles
             WHERE rolname = 'agent_record_store_owner'
          ) AS "ownerRoleExists",
          EXISTS (
            SELECT 1
              FROM pg_catalog.pg_auth_members AS membership
              JOIN pg_catalog.pg_roles AS granted_role
                ON granted_role.oid = membership.roleid
              JOIN pg_catalog.pg_roles AS member_role
                ON member_role.oid = membership.member
             WHERE granted_role.rolname = 'agent_record_store_owner'
               AND member_role.rolname = SESSION_USER
          ) AS "ownerMembershipExists",
          ARRAY(
            SELECT namespace.nspname
              FROM pg_catalog.pg_namespace AS namespace
             WHERE namespace.nspname IN (
               'agent_record_private',
               'agent_record_control_private'
             )
             ORDER BY namespace.nspname
          )::TEXT[] AS "privateSchemas",
          ARRAY(
            SELECT procedure.proname
              FROM pg_catalog.pg_proc AS procedure
              JOIN pg_catalog.pg_namespace AS namespace
                ON namespace.oid = procedure.pronamespace
             WHERE namespace.nspname = 'public'
               AND procedure.proname LIKE '%agent_record%'
             ORDER BY procedure.proname
          )::TEXT[] AS "publicFunctions",
          pg_catalog.has_table_privilege(
            'service_role', 'public.arena_shares', 'SELECT'
          ) AS "serviceRoleCanSelect",
          pg_catalog.has_table_privilege(
            'service_role', 'public.arena_shares', 'INSERT'
          ) AS "serviceRoleCanInsert",
          pg_catalog.has_table_privilege(
            'service_role', 'public.arena_shares', 'UPDATE'
          ) AS "serviceRoleCanUpdate",
          pg_catalog.has_table_privilege(
            'service_role', 'public.arena_shares', 'DELETE'
          ) AS "serviceRoleCanDelete"
      `);
      deploymentRollbackProof = {
        psqlExitStatus: directPostgresFailure.status,
        psqlReportedInjectedFailure:
          directPostgresFailure.stderr.includes(
            'injected pre-cleanup deployment failure',
          ),
        currentUser: rollbackState.rows[0].currentUser,
        sessionUser: rollbackState.rows[0].sessionUser,
        ownerRoleUnchanged:
          rollbackState.rows[0].ownerRoleExists
          === rollbackBaseline.rows[0].ownerRoleExists,
        ownerMembershipUnchanged:
          rollbackState.rows[0].ownerMembershipExists
          === rollbackBaseline.rows[0].ownerMembershipExists,
        privateSchemas: rollbackState.rows[0].privateSchemas,
        publicFunctions: rollbackState.rows[0].publicFunctions,
        serviceRoleCanSelect: rollbackState.rows[0].serviceRoleCanSelect,
        serviceRoleCanInsert: rollbackState.rows[0].serviceRoleCanInsert,
        serviceRoleCanUpdate: rollbackState.rows[0].serviceRoleCanUpdate,
        serviceRoleCanDelete: rollbackState.rows[0].serviceRoleCanDelete,
      };

      await migrationClient.query('BEGIN');
      try {
        await migrationClient.query(migration);
        await migrationClient.query('COMMIT');
      } catch (error) {
        await migrationClient.query('ROLLBACK').catch(() => undefined);
        throw error;
      }
    } finally {
      migrationClient.release();
    }
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

  it('rolls back every schema, grant, role, and function after a pre-cleanup deployment failure', () => {
    expect(deploymentRollbackProof).toEqual({
      psqlExitStatus: 3,
      psqlReportedInjectedFailure: true,
      currentUser: baseConnection.user,
      sessionUser: baseConnection.user,
      ownerRoleUnchanged: true,
      ownerMembershipUnchanged: true,
      privateSchemas: [],
      publicFunctions: [],
      serviceRoleCanSelect: true,
      serviceRoleCanInsert: true,
      serviceRoleCanUpdate: true,
      serviceRoleCanDelete: true,
    });
  });

  it('atomically publishes one refusal and creates one record without returning the owner token', async () => {
    const source = await database.query<{ refused_at: string }>(
      `SELECT pg_catalog.to_char(
         created_at AT TIME ZONE 'UTC',
         'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
       ) AS refused_at
       FROM public.arena_attempts WHERE attempt_id = $1`,
      [ARENA_ATTEMPT_ID],
    );
    const refusedAt = source.rows[0].refused_at;
    const input = createInput({ refusedAt });
    const before = await database.query<{ shares: string; records: string }>(`
      SELECT
        (SELECT count(*)::text FROM public.arena_shares WHERE attempt_id = $1) AS shares,
        (SELECT count(*)::text FROM agent_record_private.records WHERE record_id = $2) AS records
    `, [ARENA_ATTEMPT_ID, RECORD_ID]);
    expect(before.rows).toEqual([{ shares: '0', records: '0' }]);
    const created = await createRecord(input);

    expect(created).toMatchObject({
      record_id: RECORD_ID,
      created_at: input.observedAt,
      retention_expires_at: input.retentionExpiresAt,
      public_projection: input.publicProjection,
    });

    const stored = await database.query<{
      owner_token_hash: string;
      arena_share_id: string;
      public_projection: JsonObject;
      row_text: string;
    }>(`
      SELECT
        owner_token_hash,
        arena_share_id,
        public_projection,
        pg_catalog.row_to_json(record)::text AS row_text
      FROM agent_record_private.records AS record
      WHERE record_id = $1
    `, [RECORD_ID]);
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0].arena_share_id).toMatch(/^arena_share_[0-9a-f]{40}$/);
    const published = await database.query<{ share_id: string }>(
      'SELECT share_id FROM public.arena_shares WHERE attempt_id = $1',
      [ARENA_ATTEMPT_ID],
    );
    expect(published.rows).toEqual([{ share_id: stored.rows[0].arena_share_id }]);
    expect(stored.rows[0].owner_token_hash).toBe(
      createHash('sha256').update(input.ownerToken, 'utf8').digest('hex'),
    );
    expect(stored.rows[0].row_text).not.toContain(input.ownerToken);
    expect(JSON.stringify(stored.rows[0].public_projection)).not.toContain(
      input.ownerToken,
    );
    expect(JSON.stringify(stored.rows[0].public_projection)).not.toMatch(
      /arena_share_id|arena_share_|\/arena\/|\/api\/arena\/refusals/,
    );
  });

  it('strips stale BYPASSRLS service-role writes while preserving reads and approved RPCs', async () => {
    const privileges = await database.query<{
      bypass_rls: boolean;
      can_select: boolean;
      can_insert: boolean;
      can_update: boolean;
      can_delete: boolean;
      can_publish: boolean;
      can_create_record: boolean;
      can_read_record: boolean;
      can_revoke_record: boolean;
    }>(`
      SELECT
        role.rolbypassrls AS bypass_rls,
        pg_catalog.has_table_privilege(
          'service_role', 'public.arena_shares', 'SELECT'
        ) AS can_select,
        pg_catalog.has_table_privilege(
          'service_role', 'public.arena_shares', 'INSERT'
        ) AS can_insert,
        pg_catalog.has_table_privilege(
          'service_role', 'public.arena_shares', 'UPDATE'
        ) AS can_update,
        pg_catalog.has_table_privilege(
          'service_role', 'public.arena_shares', 'DELETE'
        ) AS can_delete,
        pg_catalog.has_function_privilege(
          'service_role', 'public.publish_arena_refusal(text,text)', 'EXECUTE'
        ) AS can_publish,
        pg_catalog.has_function_privilege(
          'service_role',
          'public.create_agent_record(uuid,text,text,text,uuid,text,text,text,text,text,text,text,timestamptz,timestamptz,timestamptz,jsonb)',
          'EXECUTE'
        ) AS can_create_record,
        pg_catalog.has_function_privilege(
          'service_role', 'public.read_agent_record_public(text)', 'EXECUTE'
        ) AS can_read_record,
        pg_catalog.has_function_privilege(
          'service_role', 'public.revoke_agent_record(text,text,text)', 'EXECUTE'
        ) AS can_revoke_record
      FROM pg_catalog.pg_roles AS role
      WHERE role.rolname = 'service_role'
    `);
    expect(privileges.rows).toEqual([{
      bypass_rls: true,
      can_select: true,
      can_insert: false,
      can_update: false,
      can_delete: false,
      can_publish: true,
      can_create_record: true,
      can_read_record: true,
      can_revoke_record: true,
    }]);

    const share = await database.query<{ share_id: string }>(
      'SELECT share_id FROM public.arena_shares WHERE attempt_id = $1',
      [ARENA_ATTEMPT_ID],
    );
    const shareId = share.rows[0].share_id;
    const writeOutcomes = {
      insert: await rolledBackRoleOutcome((client) => client.query(
        `INSERT INTO public.arena_shares (
           share_id, tenant_id, session_row_id, session_id, challenge_id,
           challenge_version, attempt_id, attempt_nonce, public_projection
         )
         SELECT $1, session.tenant_id, session.id, session.session_id,
                session.challenge_id, session.challenge_version,
                $2, $3, '{}'::jsonb
           FROM public.arena_sessions AS session
          WHERE session.session_id = $4`,
        [
          `arena_share_${'f'.repeat(40)}`,
          `arena_attempt_${'f'.repeat(32)}`,
          `nonce_${'f'.repeat(32)}`,
          ARENA_SESSION_ID,
        ],
      )),
      update: await rolledBackRoleOutcome((client) => client.query(
        'UPDATE public.arena_shares SET revoked_at = clock_timestamp() WHERE share_id = $1',
        [shareId],
      )),
      gucAssistedRevocation: await rolledBackRoleOutcome(async (client) => {
        await client.query(
          `SELECT pg_catalog.set_config(
             'ep.agent_record_arena_share_revoke', $1, TRUE
           )`,
          [shareId],
        );
        return client.query(
          'UPDATE public.arena_shares SET revoked_at = clock_timestamp() WHERE share_id = $1',
          [shareId],
        );
      }),
      delete: await rolledBackRoleOutcome((client) => client.query(
        'DELETE FROM public.arena_shares WHERE share_id = $1',
        [shareId],
      )),
    };
    expect(writeOutcomes).toEqual({
      insert: '42501',
      update: '42501',
      gucAssistedRevocation: '42501',
      delete: '42501',
    });

    const directRead = await asRole('service_role', (client) => client.query<{
      share_id: string;
    }>('SELECT share_id FROM public.arena_shares WHERE share_id = $1', [shareId]));
    expect(directRead.rows).toEqual([{ share_id: shareId }]);
    const preparedSource = await asRole('service_role', (client) => client.query<{
      source: JsonObject;
    }>(
      'SELECT public.read_agent_record_arena_source($1, $2, $3) AS source',
      [ARENA_TOKEN_HASH, ARENA_SESSION_ID, ARENA_ATTEMPT_ID],
    ));
    expect(preparedSource.rows[0].source).toMatchObject({
      arena_session_id: ARENA_SESSION_ID,
      attempt_id: ARENA_ATTEMPT_ID,
    });
    const published = await asRole('service_role', (client) => client.query<{
      result: JsonObject;
    }>(
      'SELECT public.publish_arena_refusal($1, $2) AS result',
      [ARENA_TOKEN_HASH, ARENA_ATTEMPT_ID],
    ));
    expect(published.rows[0].result).toMatchObject({
      ok: true,
      idempotent: true,
      share_id: shareId,
    });
    await expect(readPublic(RECORD_ID)).resolves.toMatchObject({
      record_id: RECORD_ID,
    });
  });

  it('rolls back the public share when an injected record insert failure follows publication', async () => {
    const attemptId = `arena_attempt_${'9'.repeat(32)}`;
    const recordId = `agent_record_${'9'.repeat(40)}`;
    const refusalDigest = digest('e');
    const actionDigest = digest('d');
    const refusedAt = instant(-2_000);
    await insertArenaRefusal({ attemptId, actionDigest, refusalDigest, refusedAt });
    const input = createInput({
      arenaAttemptId: attemptId,
      recordId,
      sourceArtifactDigest: refusalDigest,
      refusalDigest,
      actionDigest,
      refusedAt,
    });

    await database.query(`
      CREATE FUNCTION public.agent_record_injected_insert_failure()
      RETURNS TRIGGER
      LANGUAGE plpgsql
      SET search_path = ''
      AS $failure$
      BEGIN
        RAISE EXCEPTION 'injected Agent Record insert failure'
          USING ERRCODE = 'XX000';
      END
      $failure$;
      CREATE TRIGGER agent_record_injected_insert_failure_trigger
        BEFORE INSERT ON agent_record_private.records
        FOR EACH ROW EXECUTE FUNCTION public.agent_record_injected_insert_failure();
    `);
    try {
      await expect(createRecord(input)).rejects.toMatchObject({ code: 'XX000' });
    } finally {
      await database.query(`
        DROP TRIGGER agent_record_injected_insert_failure_trigger
          ON agent_record_private.records;
        DROP FUNCTION public.agent_record_injected_insert_failure();
      `);
    }

    const counts = await database.query<{ shares: string; records: string }>(`
      SELECT
        (SELECT count(*)::text FROM public.arena_shares WHERE attempt_id = $1) AS shares,
        (SELECT count(*)::text FROM agent_record_private.records WHERE record_id = $2) AS records
    `, [attemptId, recordId]);
    expect(counts.rows).toEqual([{ shares: '0', records: '0' }]);
  });

  it('replays the exact creation idempotently after a lost response', async () => {
    const attemptId = `arena_attempt_${'a'.repeat(32)}`;
    const sourceDigest = digest('b');
    const actionDigest = digest('c');
    const refusedAt = instant(-2_000);
    await insertArenaRefusal({
      attemptId,
      actionDigest,
      refusalDigest: sourceDigest,
      refusedAt,
    });
    const input = createInput({
      recordId: `agent_record_${'a'.repeat(40)}`,
      ownerToken: `ear1_${'b'.repeat(64)}`,
      arenaAttemptId: attemptId,
      sourceArtifactDigest: sourceDigest,
      refusalDigest: sourceDigest,
      actionDigest,
      refusedAt,
    });

    const first = await createRecord(input);
    const retryValues = {
      ...input,
      observedAt: instant(1),
      retentionExpiresAt: instant(1 + 365 * 24 * 60 * 60 * 1_000),
    };
    const retried = await createRecord({
      ...retryValues,
      publicProjection: recordProjection(retryValues),
    });
    expect(retried).toEqual(first);

    await expect(createRecord({
      ...input,
      ownerToken: `ear1_${'c'.repeat(64)}`,
    })).rejects.toMatchObject({ code: '23505' });
    const replayCounts = await database.query<{ shares: string; records: string }>(`
      SELECT
        (SELECT count(*)::text FROM public.arena_shares WHERE attempt_id = $1) AS shares,
        (SELECT count(*)::text FROM agent_record_private.records WHERE source_artifact_digest = $2) AS records
    `, [attemptId, sourceDigest]);
    expect(replayCounts.rows).toEqual([{ shares: '1', records: '1' }]);
  });

  it('rejects a dereferenceable Arena source in the public projection', async () => {
    const arenaShareId = `arena_share_${'3'.repeat(40)}`;
    const refusalDigest = digest('6');
    const actionDigest = digest('7');
    const refusedAt = instant(-2_000);
    const attemptId = `arena_attempt_${'3'.repeat(32)}`;
    await insertArenaRefusal({ attemptId, actionDigest, refusalDigest, refusedAt });
    const input = createInput({
      recordId: `agent_record_${'4'.repeat(40)}`,
      arenaAttemptId: attemptId,
      sourceArtifactDigest: refusalDigest,
      refusalDigest,
      actionDigest,
      refusedAt,
    });
    const unsafeProjection = structuredClone(input.publicProjection);
    (unsafeProjection.record as JsonObject).source = {
      ...((unsafeProjection.record as JsonObject).source as JsonObject),
      arena_share_id: arenaShareId,
    };

    await expect(createRecord({
      ...input,
      publicProjection: unsafeProjection,
    })).rejects.toMatchObject({ code: '22023' });

    const stored = await database.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM agent_record_private.records WHERE record_id = $1',
      [input.recordId],
    );
    expect(stored.rows).toEqual([{ count: '0' }]);
  });

  it('accepts a rotated safe key id and rejects key ids outside the closed set', async () => {
    const safeAttemptId = `arena_attempt_${'7'.repeat(32)}`;
    const safeRefusalDigest = digest('7');
    const safeActionDigest = digest('8');
    const safeRefusedAt = instant(-2_000);
    await insertArenaRefusal({
      attemptId: safeAttemptId,
      actionDigest: safeActionDigest,
      refusalDigest: safeRefusalDigest,
      refusedAt: safeRefusedAt,
    });
    const safeInput = createInput({
      recordId: `agent_record_${'7'.repeat(40)}`,
      arenaAttemptId: safeAttemptId,
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

    const unsafeAttemptId = `arena_attempt_${'0'.repeat(32)}`;
    const unsafeRefusalDigest = digest('0');
    const unsafeActionDigest = digest('f');
    const unsafeRefusedAt = instant(-2_000);
    await insertArenaRefusal({
      attemptId: unsafeAttemptId,
      actionDigest: unsafeActionDigest,
      refusalDigest: unsafeRefusalDigest,
      refusedAt: unsafeRefusedAt,
    });
    const unsafeInput = createInput({
      recordId: `agent_record_${'8'.repeat(40)}`,
      arenaAttemptId: unsafeAttemptId,
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
    const attemptId = `arena_attempt_${'8'.repeat(32)}`;
    const refusalDigest = digest('9');
    const actionDigest = digest('a');
    const refusedAt = instant(-2_000);
    await insertArenaRefusal({ attemptId, actionDigest, refusalDigest, refusedAt });

    const first = createInput({
      recordId: `agent_record_${'b'.repeat(40)}`,
      arenaAttemptId: attemptId,
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

    const count = await database.query<{ shares: string; records: string }>(
      `SELECT
         (SELECT count(*)::text FROM public.arena_shares WHERE attempt_id = $1) AS shares,
         (SELECT count(*)::text FROM agent_record_private.records
           WHERE source_artifact_digest = $2) AS records`,
      [attemptId, refusalDigest],
    );
    expect(count.rows).toEqual([{ shares: '1', records: '1' }]);
  });

  it('refuses cross-boundary and permit substitutions before persistence', async () => {
    const cases: Array<{
      name: string;
      input: CreateInput;
      code: string;
    }> = [];
    const source = await database.query<{ refused_at: string }>(
      `SELECT pg_catalog.to_char(
         created_at AT TIME ZONE 'UTC',
         'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
       ) AS refused_at
       FROM public.arena_attempts WHERE attempt_id = $1`,
      [ARENA_ATTEMPT_ID],
    );
    const base = createInput({
      recordId: `agent_record_${'d'.repeat(40)}`,
      refusedAt: source.rows[0].refused_at,
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

    const permitAttemptId = `arena_attempt_${'1'.repeat(32)}`;
    const permitDigest = digest('1');
    const permitActionDigest = digest('3');
    const permitRefusedAt = instant(-2_000);
    await insertArenaRefusal({
      attemptId: permitAttemptId,
      actionDigest: permitActionDigest,
      refusalDigest: permitDigest,
      refusedAt: permitRefusedAt,
      decision: 'permit',
    });
    const permitValues = createInput({
      recordId: `agent_record_${'1'.repeat(40)}`,
      arenaAttemptId: permitAttemptId,
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
    const publicBytes = JSON.stringify(publicRecord);
    expect(publicBytes).not.toMatch(
      /arena_share_id|arena_share_|\/arena\/|\/api\/arena\/refusals/,
    );
    expect(publicBytes).toContain(REFUSAL_DIGEST);
    expect(publicBytes).toContain(ACTION_DIGEST);

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
      'read_agent_record_arena_source',
      'read_agent_record_public',
      'revoke_agent_record',
    ]);
    expect(functions.rows.map(({ proname }) => proname).join(' ')).not.toMatch(
      /list|search|feed|sitemap|enumerate/,
    );

    for (const role of ['anon', 'authenticated'] as const) {
      await expect(asRole(role, (client) => client.query(
        'SELECT public.read_agent_record_public($1)',
        [RECORD_ID],
      ))).rejects.toMatchObject({ code: '42501' });
    }

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

    // The caller generates and retains the plaintext owner token. Create a
    // second record here so this test has an independent revocation ceremony.
    const attemptId = `arena_attempt_${'2'.repeat(32)}`;
    const sourceDigest = digest('4');
    const actionDigest = digest('5');
    const refusedAt = instant(-2_000);
    await insertArenaRefusal({
      attemptId,
      actionDigest,
      refusalDigest: sourceDigest,
      refusedAt,
    });
    const input = createInput({
      recordId: `agent_record_${'6'.repeat(40)}`,
      arenaAttemptId: attemptId,
      sourceArtifactDigest: sourceDigest,
      refusalDigest: sourceDigest,
      actionDigest,
      refusedAt,
    });
    const created = await createRecord(input);
    const published = await database.query<{ share_id: string }>(
      'SELECT share_id FROM public.arena_shares WHERE attempt_id = $1',
      [attemptId],
    );
    const shareId = published.rows[0].share_id;
    expect(ownerHash).toMatch(/^[0-9a-f]{64}$/);
    const sourceBefore = await database.query<{
      public_projection: JsonObject;
      revoked_at: string | null;
    }>(
      'SELECT public_projection, revoked_at FROM public.arena_shares WHERE share_id = $1',
      [shareId],
    );
    expect(sourceBefore.rows[0].revoked_at).toBeNull();

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

    await expect(revoke(input.recordId, input.ownerToken)).resolves.toMatchObject({
      record_id: input.recordId,
      revoked: true,
    });
    const sourceAfter = await database.query<{
      public_projection: JsonObject;
      revoked_at: string | null;
    }>(
      'SELECT public_projection, revoked_at FROM public.arena_shares WHERE share_id = $1',
      [shareId],
    );
    expect(sourceAfter.rows[0].revoked_at).not.toBeNull();
    expect(sourceAfter.rows[0].public_projection).toEqual(
      sourceBefore.rows[0].public_projection,
    );
    const publicArenaSource = await database.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.arena_shares WHERE share_id = $1 AND revoked_at IS NULL',
      [shareId],
    );
    expect(publicArenaSource.rows).toEqual([{ count: '0' }]);
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
