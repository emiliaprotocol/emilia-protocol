// SPDX-License-Identifier: Apache-2.0
/**
 * Real PostgreSQL 17 proof for 20260926120000_agent_record_acl_repair and
 * 20260926120100_drop_foreign_activation_definers under a Supabase-shaped,
 * non-superuser migration role.
 *
 * The migration operator mirrors the production postgres role: NOSUPERUSER
 * CREATEROLE, owner of the database (and therefore of schema public through
 * pg_database_owner), an inheriting member of anon, authenticated, and
 * service_role, and subject to Supabase's default EXECUTE grants on functions
 * it creates in public. Applied that way, 20260803020000 leaves the exact ACLs
 * observed in production, and only the forward repair corrects them.
 */
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createArenaAllowance } from '../lib/arena/core';
import { signArenaRefusal } from '../lib/arena/refusal';
import {
  AGENT_RECORD_RETENTION_MS,
  signAgentRecordObservation,
} from '../lib/agent-record/core';

function readMigration(name: string): string {
  return readFileSync(
    new URL(`../supabase/migrations/${name}`, import.meta.url),
    'utf8',
  );
}

const AGENT_RECORD_MIGRATION = readMigration('20260803020000_agent_record_v1.sql');
const ACL_REPAIR_MIGRATION = readMigration('20260926120000_agent_record_acl_repair.sql');
const FOREIGN_DEFINER_MIGRATION = readMigration(
  '20260926120100_drop_foreign_activation_definers.sql',
);

const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe
  : describe.skip;

const DATABASE = 'ep_agent_record_acl_repair_test';
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};
const controlDatabase = process.env.PGDATABASE ?? 'ep_test';
const GENERIC_ROLES = ['anon', 'authenticated', 'service_role'] as const;
const OPERATOR = 'agent_record_acl_repair_operator_test';
// The Supabase CLI connects as a wire login that may only SET ROLE to postgres;
// SET ROLE inside a migration is authorized against that session identity.
const CLI_LOGIN = 'agent_record_acl_repair_cli_login_test';
const STORE_ROLES = [
  'agent_adoption_store_owner',
  'agent_record_store_bootstrap',
  'agent_record_store_owner',
  'agent_record_source_reader',
  OPERATOR,
  CLI_LOGIN,
] as const;
const GLOBAL_ROLES = [...GENERIC_ROLES, ...STORE_ROLES] as const;

const SOURCE_FN = 'public.read_agent_record_refusal_source(text,text,text)';
const ADOPTION_FN = 'public.read_agent_adoption_session(uuid,text)';
const SOURCE_SQL = 'SELECT public.read_agent_record_refusal_source($1, $2, $3) AS source';
const NO_PRIVILEGE_WARNING = /^WARNING: no privileges (could be revoked|were granted) for /;

// The ACLs the EMILIA production catalog reported on 2026-09-26. Element order
// carries no meaning, so comparisons use the sorted set of aclitems.
const PRODUCTION_SOURCE_ACL = '{=X/agent_record_store_owner,'
  + 'agent_record_store_owner=X/agent_record_store_owner,'
  + 'anon=X/agent_record_store_owner,'
  + 'authenticated=X/agent_record_store_owner,'
  + 'service_role=X/agent_record_store_owner}';
const PRODUCTION_ADOPTION_ACL = '{agent_adoption_store_owner=X/agent_adoption_store_owner,'
  + 'service_role=X/agent_adoption_store_owner}';

function aclItems(acl: string): string[] {
  return acl.replace(/^\{|\}$/g, '').split(',').filter(Boolean).sort();
}

const ADOPTION_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_TOKEN = `eaa1_${'1'.repeat(64)}`;
const BOND_ID = '22222222-2222-4222-8222-222222222222';
const BOND_DIGEST = `sha256:${'2'.repeat(64)}`;
const ARENA_SESSION_ID = `arena_session_${'4'.repeat(32)}`;
const ARENA_TOKEN = `ep_arena_${'4'.repeat(64)}`;
const ARENA_TOKEN_HASH = crypto.createHash('sha256').update(ARENA_TOKEN).digest('hex');
const UNKNOWN_ATTEMPT_ID = `arena_attempt_${'f'.repeat(32)}`;
const OWNER_TOKEN = `ear1_${'a'.repeat(64)}`;
const CREATION_CAPABILITY = `earc1_${'d'.repeat(64)}`;
const SIGNING_SEED = Buffer.alloc(32, 9).toString('base64');
const BASE_NOW = Date.now();
const SESSION_EXPIRES_AT = new Date(BASE_NOW + 24 * 60 * 60 * 1_000).toISOString();
const ARENA_KEYS = crypto.generateKeyPairSync('ed25519');
const ARENA_ISSUER_ID = 'arena:session:agent-record-acl-repair';
const ARENA_KEY_ID = 'arena-session-key-agent-record-acl-repair';

type JsonObject = Record<string, any>;
type Fingerprint = Readonly<{
  body_md5: string;
  config: string[];
  arguments: string;
  result: string;
  volatility: string;
  security_definer: boolean;
}>;

const priorEnvironment = Object.freeze({
  NODE_ENV: process.env.NODE_ENV,
  EP_COMMIT_SIGNING_KEY: process.env.EP_COMMIT_SIGNING_KEY,
  EP_COMMIT_SIGNING_KEYS: process.env.EP_COMMIT_SIGNING_KEYS,
  EP_AGENT_RECORD_SIGNING_KEY_ID: process.env.EP_AGENT_RECORD_SIGNING_KEY_ID,
});

let admin: pg.Client | undefined;
let operator: pg.Client | undefined;
let database: pg.Pool | undefined;
let initiallyPresentRoles = new Set<string>();
let initialServiceRoleBypassRls: boolean | undefined;
let originalNotices: string[] = [];
let originalFingerprint: Fingerprint;
let originalSource: JsonObject;

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function restoreEnvironment(): void {
  for (const [name, value] of Object.entries(priorEnvironment)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

const ATTEMPT = (() => {
  const attemptId = `arena_attempt_${'a'.repeat(32)}`;
  const refusedAt = new Date(BASE_NOW - 120_000).toISOString();
  const allowance = createArenaAllowance({
    sessionId: ARENA_SESSION_ID,
    agentName: 'PostgreSQL ACL repair proof',
    totalAmount: 1_000,
    maxAmountPerAction: 250,
    allowedTargets: ['vendor.demo'],
    issuedAt: new Date(BASE_NOW - 60 * 60 * 1_000).toISOString(),
    expiresAt: SESSION_EXPIRES_AT,
  });
  const action = {
    operation_id: 'operation-acl-repair',
    action_type: 'arena.resource.allocate.1' as const,
    target: 'vendor.demo',
    amount: 900,
    currency: 'CREDITS' as const,
    purpose: 'raw-action-parameters-acl-repair',
  };
  const signed = signArenaRefusal({
    allowance,
    action,
    reason: 'allowance_per_action_limit_exceeded',
    attemptId,
    attemptNonce: Buffer.alloc(32, 0x61).toString('base64url'),
    refusedAt,
    expiresAt: new Date(BASE_NOW + 60 * 60 * 1_000).toISOString(),
    signer: {
      issuer_id: ARENA_ISSUER_ID,
      key_id: ARENA_KEY_ID,
      private_key: ARENA_KEYS.privateKey,
    },
  });
  return Object.freeze({
    attemptId,
    refusedAt,
    action,
    actionDigest: signed.binding.action_digest,
    refusalDigest: signed.refusal_digest,
    refusalArtifact: signed.statement as JsonObject,
    publicKey: ARENA_KEYS.publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64url'),
  });
})();

async function applyAsOperator(sql: string): Promise<string[]> {
  if (!operator) throw new Error('migration operator is unavailable');
  const notices: string[] = [];
  const collect = (notice: pg.NoticeMessage) => {
    notices.push(`${notice.severity}: ${notice.message}`);
  };
  operator.on('notice', collect);
  try {
    await operator.query(sql);
  } finally {
    operator.off('notice', collect);
  }
  return notices;
}

async function asRole<T>(
  role: (typeof GENERIC_ROLES)[number],
  callback: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  if (!database) throw new Error('database is unavailable');
  const client = await database.connect();
  try {
    await client.query(`SET ROLE ${identifier(role)}`);
    return await callback(client);
  } finally {
    await client.query('RESET ROLE').catch(() => undefined);
    client.release();
  }
}

async function readSourceAs(
  role: (typeof GENERIC_ROLES)[number],
  attemptId = ATTEMPT.attemptId,
): Promise<JsonObject> {
  return asRole(role, async (client) => {
    const result = await client.query<{ source: JsonObject }>(
      SOURCE_SQL,
      [ARENA_TOKEN, ARENA_SESSION_ID, attemptId],
    );
    return result.rows[0].source;
  });
}

async function bindTrialSource(): Promise<boolean> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ bound: boolean }>(
      `SELECT public.bind_agent_record_trial_source(
         $1::uuid, $2, $3::uuid, $4, $5, $6
       ) AS bound`,
      [ADOPTION_ID, SESSION_TOKEN, BOND_ID, BOND_DIGEST, ARENA_SESSION_ID, ARENA_TOKEN],
    );
    return result.rows[0].bound;
  });
}

async function functionAcl(signature: string): Promise<string[]> {
  const result = await database!.query<{ acl: string }>(
    'SELECT proacl::text AS acl FROM pg_catalog.pg_proc WHERE oid = $1::regprocedure',
    [signature],
  );
  return aclItems(result.rows[0].acl);
}

async function aclEntries(signature: string): Promise<string[]> {
  const result = await database!.query<{ entry: string }>(`
    SELECT pg_catalog.format(
             '%s=%s/%s',
             CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE acl.grantee::regrole::text END,
             acl.privilege_type,
             acl.grantor::regrole::text
           ) AS entry
      FROM pg_catalog.pg_proc AS proc
     CROSS JOIN LATERAL pg_catalog.aclexplode(proc.proacl) AS acl
     WHERE proc.oid = $1::regprocedure
  `, [signature]);
  return result.rows.map(({ entry }) => entry).sort();
}

async function canExecute(role: string, signature: string): Promise<boolean> {
  const result = await database!.query<{ allowed: boolean }>(
    `SELECT pg_catalog.has_function_privilege($1, $2::regprocedure, 'EXECUTE') AS allowed`,
    [role, signature],
  );
  return result.rows[0].allowed;
}

async function sourceFingerprint(): Promise<Fingerprint & { owner: string }> {
  const result = await database!.query<Fingerprint & { owner: string }>(`
    SELECT pg_catalog.md5(proc.prosrc) AS body_md5,
           proc.proconfig AS config,
           pg_catalog.pg_get_function_arguments(proc.oid) AS arguments,
           pg_catalog.pg_get_function_result(proc.oid) AS result,
           proc.provolatile::text AS volatility,
           proc.prosecdef AS security_definer,
           proc.proowner::regrole::text AS owner
      FROM pg_catalog.pg_proc AS proc
     WHERE proc.oid = $1::regprocedure
  `, [SOURCE_FN]);
  return result.rows[0];
}

async function operatorMemberships(): Promise<JsonObject[]> {
  const result = await database!.query(`
    SELECT granted.rolname AS role,
           membership.admin_option,
           membership.inherit_option,
           membership.set_option
      FROM pg_catalog.pg_auth_members AS membership
      JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
      JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
     WHERE member.rolname = $1
       AND granted.rolname = ANY($2::text[])
     ORDER BY 1
  `, [OPERATOR, STORE_ROLES]);
  return result.rows;
}

async function terminateTestDatabaseConnections(): Promise<void> {
  if (!admin) return;
  await admin.query(
    `SELECT pg_catalog.pg_terminate_backend(pid)
       FROM pg_catalog.pg_stat_activity
      WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()`,
    [DATABASE],
  );
}

async function cleanup(): Promise<void> {
  if (operator) {
    await operator.end();
    operator = undefined;
  }
  if (database) {
    await database.end();
    database = undefined;
  }
  if (!admin) return;
  await terminateTestDatabaseConnections();
  await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
  if (initiallyPresentRoles.has('service_role')
      && initialServiceRoleBypassRls !== undefined) {
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

suite('Agent Record ACL repair on a Supabase-shaped PostgreSQL 17', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.EP_COMMIT_SIGNING_KEY = SIGNING_SEED;
    process.env.EP_COMMIT_SIGNING_KEYS = '';
    process.env.EP_AGENT_RECORD_SIGNING_KEY_ID = 'agent-record-acl-repair-key';

    admin = new pg.Client({ ...baseConnection, database: controlDatabase });
    await admin.connect();
    const environment = await admin.query<{
      server_version_num: string;
      is_superuser: boolean;
    }>(`
      SELECT pg_catalog.current_setting('server_version_num') AS server_version_num,
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
    const leftovers = STORE_ROLES.filter((role) => initiallyPresentRoles.has(role));
    expect(leftovers, 'store roles left behind by another suite').toEqual([]);

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
    await admin.query(`
      CREATE ROLE ${identifier(OPERATOR)} NOLOGIN
        NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS
    `);
    // Production's postgres role inherits the three API roles.
    await admin.query(
      `GRANT anon, authenticated, service_role TO ${identifier(OPERATOR)}
         WITH INHERIT TRUE, SET TRUE`,
    );
    await admin.query(`CREATE ROLE ${identifier(CLI_LOGIN)} NOLOGIN NOINHERIT`);
    await admin.query(
      `GRANT ${identifier(OPERATOR)} TO ${identifier(CLI_LOGIN)} WITH INHERIT FALSE, SET TRUE`,
    );
    await admin.query(
      `CREATE DATABASE ${identifier(DATABASE)} OWNER ${identifier(OPERATOR)} TEMPLATE template0`,
    );

    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 8 });
    // Platform-owned setup a Supabase project already has: pgcrypto in
    // extensions with grantable EXECUTE for the migration role, and the
    // production default ACL for functions the migration role creates in
    // public ({postgres,anon,authenticated,service_role}=X/postgres).
    await database.query(`
      CREATE SCHEMA extensions AUTHORIZATION ${identifier(OPERATOR)};
      CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
      GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA extensions
        TO ${identifier(OPERATOR)} WITH GRANT OPTION;
      GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
      ALTER DEFAULT PRIVILEGES FOR ROLE ${identifier(OPERATOR)} IN SCHEMA public
        GRANT ALL ON FUNCTIONS
        TO ${identifier(OPERATOR)}, anon, authenticated, service_role;
    `);

    operator = new pg.Client({ ...baseConnection, database: DATABASE });
    await operator.connect();
    await operator.query(`SET SESSION AUTHORIZATION ${identifier(OPERATOR)}`);
    const operatorEnvironment = await operator.query<{
      is_superuser: boolean;
      owns_public: boolean;
    }>(`
      SELECT pg_catalog.current_setting('is_superuser')::boolean AS is_superuser,
             pg_catalog.has_schema_privilege(CURRENT_USER, 'public', 'CREATE') AS owns_public
    `);
    expect(operatorEnvironment.rows).toEqual([{ is_superuser: false, owns_public: true }]);

    await operator.query(`
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

      -- As in production, the adoption-session reader belongs to its own store
      -- owner and is executable only by service_role.
      CREATE ROLE agent_adoption_store_owner NOLOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
      GRANT agent_adoption_store_owner TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
      GRANT CREATE ON SCHEMA public TO agent_adoption_store_owner;
      SET ROLE agent_adoption_store_owner;
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
          RAISE EXCEPTION 'adoption not found' USING ERRCODE = 'P0002';
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
      GRANT EXECUTE ON FUNCTION public.read_agent_adoption_session(UUID, TEXT)
        TO service_role;
      RESET ROLE;
      REVOKE CREATE ON SCHEMA public FROM agent_adoption_store_owner;
      REVOKE agent_adoption_store_owner FROM CURRENT_USER;

      -- Foreign definers of the shape production holds.
      CREATE FUNCTION public.complete_verified_activation(
        p_email TEXT,
        p_token_hash TEXT,
        p_session_hash TEXT,
        p_session_expires_at TIMESTAMPTZ
      ) RETURNS JSONB
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = public
      AS $foreign$
      BEGIN
        PERFORM 1 FROM rk_users WHERE email = p_email;
        RETURN pg_catalog.jsonb_build_object('ok', false);
      END
      $foreign$;
      CREATE FUNCTION public.complete_verified_activation(
        p_user_id UUID,
        p_verification_id UUID,
        p_vendor TEXT,
        p_raw_status TEXT
      ) RETURNS JSONB
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = public
      AS $foreign$
      BEGIN
        PERFORM 1 FROM hc_profiles WHERE user_id = p_user_id;
        RETURN pg_catalog.jsonb_build_object('success', false);
      END
      $foreign$;
      CREATE FUNCTION public.create_profile_on_user_insert()
      RETURNS TRIGGER
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = public
      AS $foreign$
      BEGIN
        INSERT INTO hc_profiles (user_id, verification_status)
        VALUES (NEW.id, 'unverified')
        ON CONFLICT (user_id) DO NOTHING;
        RETURN NEW;
      END
      $foreign$;
      CREATE FUNCTION public.rls_auto_enable()
      RETURNS event_trigger
      LANGUAGE plpgsql
      SECURITY DEFINER
      SET search_path = pg_catalog
      AS $auto_rls$
      DECLARE
        cmd RECORD;
      BEGIN
        FOR cmd IN
          SELECT *
          FROM pg_event_trigger_ddl_commands()
          WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
            AND object_type IN ('table', 'partitioned table')
            AND schema_name = 'public'
        LOOP
          EXECUTE format(
            'ALTER TABLE IF EXISTS %s ENABLE ROW LEVEL SECURITY',
            cmd.object_identity
          );
        END LOOP;
      END
      $auto_rls$;
    `);
    await database.query(`
      CREATE EVENT TRIGGER ensure_rls ON ddl_command_end
        EXECUTE FUNCTION public.rls_auto_enable();
    `);

    await operator.query(
      `INSERT INTO public.arena_sessions (
         session_id, token_hash, challenge_id, challenge_version,
         issuer_id, key_id, public_key, status, expires_at
       ) VALUES ($1, $2, 'emilia.arena.allowance', 1, $3, $4, $5, 'active', $6)`,
      [
        ARENA_SESSION_ID,
        ARENA_TOKEN_HASH,
        ARENA_ISSUER_ID,
        ARENA_KEY_ID,
        ATTEMPT.publicKey,
        SESSION_EXPIRES_AT,
      ],
    );
    await operator.query(
      `INSERT INTO public.arena_attempts (
         tenant_id, session_row_id, session_id, challenge_id, challenge_version,
         attempt_id, attempt_nonce, action, action_digest, caid, decision, reason,
         evidence_status, refusal_artifact, refusal_digest, created_at
       )
       SELECT session.tenant_id, session.id, session.session_id,
              session.challenge_id, session.challenge_version,
              $1, $2, $3::jsonb, $4, $5, 'refuse',
              'allowance_per_action_limit_exceeded', 'complete', $6::jsonb, $7,
              $8::timestamptz
         FROM public.arena_sessions AS session WHERE session.session_id = $9`,
      [
        ATTEMPT.attemptId,
        `nonce_${ATTEMPT.attemptId.slice(-32)}`,
        JSON.stringify(ATTEMPT.action),
        ATTEMPT.actionDigest,
        ATTEMPT.refusalArtifact.caid,
        JSON.stringify(ATTEMPT.refusalArtifact),
        ATTEMPT.refusalDigest,
        ATTEMPT.refusedAt,
        ARENA_SESSION_ID,
      ],
    );
    await operator.query(`
      ALTER TABLE public.arena_sessions ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.arena_sessions FORCE ROW LEVEL SECURITY;
      ALTER TABLE public.arena_attempts ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.arena_attempts FORCE ROW LEVEL SECURITY;
    `);

    originalNotices = await applyAsOperator(AGENT_RECORD_MIGRATION);
    const { owner, ...fingerprint } = await sourceFingerprint();
    expect(owner).toBe('agent_record_store_owner');
    originalFingerprint = fingerprint;
    originalSource = await readSourceAs('service_role');
  }, 60_000);

  afterAll(async () => {
    try {
      await cleanup();
    } finally {
      if (admin) await admin.end();
      restoreEnvironment();
    }
  }, 60_000);

  it('reproduces the production ACLs when 20260803020000 runs as a non-superuser', async () => {
    expect(originalNotices.filter((notice) => NO_PRIVILEGE_WARNING.test(notice)).sort())
      .toEqual([
        'WARNING: no privileges could be revoked for "read_agent_record_refusal_source"',
        'WARNING: no privileges were granted for "read_agent_adoption_session"',
        'WARNING: no privileges were granted for "read_agent_record_refusal_source"',
      ]);
    expect(await functionAcl(SOURCE_FN)).toEqual(aclItems(PRODUCTION_SOURCE_ACL));
    expect(await functionAcl(ADOPTION_FN)).toEqual(aclItems(PRODUCTION_ADOPTION_ACL));
    expect(originalFingerprint.body_md5).toBe('12d5b8bdfbe8d29b3c6edafbc27d7b32');

    // anon reaches the bearer-token-gated reader directly.
    expect(await canExecute('anon', SOURCE_FN)).toBe(true);
    expect(await canExecute('authenticated', SOURCE_FN)).toBe(true);
    await expect(readSourceAs('anon', UNKNOWN_ATTEMPT_ID))
      .rejects.toMatchObject({ code: 'P0002' });
    expect(await readSourceAs('anon')).toEqual(originalSource);

    // The Agent Record owner cannot call the adoption-session reader, so the
    // trial binding fails before it binds anything.
    expect(await canExecute('agent_record_store_owner', ADOPTION_FN)).toBe(false);
    await expect(bindTrialSource()).rejects.toMatchObject({
      code: '42501',
      message: 'permission denied for function read_agent_adoption_session',
    });
  });

  it('cannot be corrected in place by the non-superuser migration role', async () => {
    expect((await operatorMemberships()).map(({ role }) => role))
      .not.toContain('agent_record_store_owner');
    await expect(operator!.query('SET ROLE agent_record_store_owner'))
      .rejects.toMatchObject({ code: '42501' });

    const notices = await applyAsOperator(`
      REVOKE ALL ON FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT)
        FROM PUBLIC, anon, authenticated;
    `);
    expect(notices).toEqual([
      'WARNING: no privileges could be revoked for "read_agent_record_refusal_source"',
    ]);
    expect(await functionAcl(SOURCE_FN)).toEqual(aclItems(PRODUCTION_SOURCE_ACL));

    // A superuser is treated as the owner, which is why a superuser-run
    // migration never shows the defect.
    const client = await database!.connect();
    try {
      await client.query('BEGIN');
      await client.query(`
        REVOKE ALL ON FUNCTION public.read_agent_record_refusal_source(TEXT, TEXT, TEXT)
          FROM PUBLIC, anon, authenticated
      `);
      const acl = await client.query<{ acl: string }>(
        'SELECT proacl::text AS acl FROM pg_catalog.pg_proc WHERE oid = $1::regprocedure',
        [SOURCE_FN],
      );
      expect(aclItems(acl.rows[0].acl)).toEqual([
        'agent_record_store_owner=X/agent_record_store_owner',
        'service_role=X/agent_record_store_owner',
      ]);
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    expect(await functionAcl(SOURCE_FN)).toEqual(aclItems(PRODUCTION_SOURCE_ACL));
  });

  it('repairs both privileges as the non-superuser migration role', async () => {
    await operator!.query(
      `SET SESSION AUTHORIZATION ${identifier(CLI_LOGIN)}; SET ROLE ${identifier(OPERATOR)}`,
    );
    let notices: string[];
    try {
      notices = await applyAsOperator(ACL_REPAIR_MIGRATION);
      const identity = await operator!.query<{ session_user: string; current_user: string }>(
        'SELECT SESSION_USER AS session_user, CURRENT_USER AS current_user',
      );
      expect(identity.rows).toEqual([{ session_user: CLI_LOGIN, current_user: OPERATOR }]);
    } finally {
      await operator!.query(`RESET ROLE; SET SESSION AUTHORIZATION ${identifier(OPERATOR)}`);
    }
    expect(notices.filter((notice) => NO_PRIVILEGE_WARNING.test(notice))).toEqual([]);

    const { owner, ...fingerprint } = await sourceFingerprint();
    expect(owner).toBe('agent_record_source_reader');
    expect(fingerprint).toEqual(originalFingerprint);

    expect(await aclEntries(SOURCE_FN)).toEqual([
      'agent_record_store_owner=EXECUTE/agent_record_source_reader',
      'service_role=EXECUTE/agent_record_source_reader',
    ]);
    expect(await aclEntries(ADOPTION_FN)).toEqual([
      'agent_adoption_store_owner=EXECUTE/agent_adoption_store_owner',
      'agent_record_store_owner=EXECUTE/agent_adoption_store_owner',
      'service_role=EXECUTE/agent_adoption_store_owner',
    ]);
    for (const role of ['anon', 'authenticated'] as const) {
      expect(await canExecute(role, SOURCE_FN)).toBe(false);
      await expect(readSourceAs(role)).rejects.toMatchObject({ code: '42501' });
    }
    expect(await readSourceAs('service_role')).toEqual(originalSource);

    // The migration role keeps only ADMIN on both owners: no temporary SET
    // edge survives, so it still cannot act as either without a new grant.
    expect(await operatorMemberships()).toEqual([
      {
        role: 'agent_adoption_store_owner',
        admin_option: true,
        inherit_option: false,
        set_option: false,
      },
      {
        role: 'agent_record_source_reader',
        admin_option: true,
        inherit_option: false,
        set_option: false,
      },
    ]);
    await expect(operator!.query('SET ROLE agent_record_source_reader'))
      .rejects.toMatchObject({ code: '42501' });
    const reader = await database!.query(`
      SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
             role.rolreplication, role.rolbypassrls,
             pg_catalog.has_schema_privilege(role.oid, 'public', 'CREATE') AS creates_in_public,
             (SELECT pg_catalog.count(*)::int
                FROM pg_catalog.pg_auth_members AS membership
               WHERE membership.member = role.oid) AS memberships
        FROM pg_catalog.pg_roles AS role
       WHERE role.rolname = 'agent_record_source_reader'
    `);
    expect(reader.rows).toEqual([{
      rolcanlogin: false,
      rolsuper: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolreplication: false,
      rolbypassrls: false,
      creates_in_public: false,
      memberships: 0,
    }]);
  });

  it('restores the Agent Record bind and create path', async () => {
    await operator!.query(
      'SELECT public.configure_agent_record_creation_capability($1)',
      [CREATION_CAPABILITY],
    );
    expect(await bindTrialSource()).toBe(true);

    const recordId = `agent_record_${crypto.createHash('sha256')
      .update(`emilia-agent-record-owner-token-v1\0${OWNER_TOKEN}`, 'utf8')
      .digest('hex')
      .slice(0, 40)}`;
    const observedAt = new Date(
      Math.max(BASE_NOW - 30_000, Date.parse(originalSource.refused_at)),
    ).toISOString();
    const retentionExpiresAt = new Date(
      Date.parse(observedAt) + AGENT_RECORD_RETENTION_MS,
    ).toISOString();
    const publicProjection = signAgentRecordObservation({
      recordId,
      bondId: BOND_ID,
      bondDigest: BOND_DIGEST,
      sourceArtifactDigest: originalSource.source_artifact_digest,
      actionDigest: originalSource.action_digest,
      refusalDigest: originalSource.refusal_digest,
      refusedAt: originalSource.refused_at,
      observedAt,
      retentionExpiresAt,
    });
    const created = await asRole('service_role', async (client) => {
      const result = await client.query<{ result: JsonObject; storage: boolean }>(
        `SELECT public.create_agent_record_with_capability(
           $1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13,
           $14::timestamptz, $15::timestamptz, $16::timestamptz, $17::jsonb, $18
         ) AS result,
         public.check_agent_record_storage_contract() AS storage`,
        [
          ADOPTION_ID,
          SESSION_TOKEN,
          recordId,
          OWNER_TOKEN,
          BOND_ID,
          BOND_DIGEST,
          ARENA_SESSION_ID,
          ARENA_TOKEN,
          ATTEMPT.attemptId,
          originalSource.source_commitment,
          originalSource.source_artifact_digest,
          originalSource.action_digest,
          originalSource.refusal_digest,
          originalSource.refused_at,
          observedAt,
          retentionExpiresAt,
          JSON.stringify(publicProjection),
          CREATION_CAPABILITY,
        ],
      );
      return result.rows[0];
    });
    expect(created.storage).toBe(true);
    expect(created.result).toMatchObject({
      record_id: recordId,
      public_projection: publicProjection,
    });
  });

  it('drops only the foreign activation definers', async () => {
    const foreign = [
      'public.complete_verified_activation(text,text,text,timestamp with time zone)',
      'public.complete_verified_activation(uuid,uuid,text,text)',
      'public.create_profile_on_user_insert()',
    ];
    const present = async (signature: string) => {
      const result = await database!.query<{ present: boolean }>(
        'SELECT pg_catalog.to_regprocedure($1) IS NOT NULL AS present',
        [signature],
      );
      return result.rows[0].present;
    };
    for (const signature of foreign) {
      expect(await present(signature)).toBe(true);
    }
    expect(await canExecute('anon', foreign[0])).toBe(true);

    // Where the tables they write exist, they are not orphans: refuse.
    await operator!.query('CREATE TABLE public.hc_profiles (user_id UUID PRIMARY KEY)');
    await expect(applyAsOperator(FOREIGN_DEFINER_MIGRATION))
      .rejects.toMatchObject({ code: '55000' });
    for (const signature of foreign) {
      expect(await present(signature)).toBe(true);
    }
    await operator!.query('DROP TABLE public.hc_profiles');

    await applyAsOperator(FOREIGN_DEFINER_MIGRATION);
    for (const signature of foreign) {
      expect(await present(signature)).toBe(false);
    }
    await applyAsOperator(FOREIGN_DEFINER_MIGRATION);

    // rls_auto_enable stays behind its event trigger, and PostgreSQL refuses
    // any direct call to it.
    expect(await present('public.rls_auto_enable()')).toBe(true);
    const trigger = await database!.query<{ evtfoid: string }>(
      `SELECT evtfoid::regprocedure::text AS evtfoid
         FROM pg_catalog.pg_event_trigger WHERE evtname = 'ensure_rls'`,
    );
    expect(trigger.rows).toEqual([{ evtfoid: 'rls_auto_enable()' }]);
    await expect(asRole('anon', (client) => client.query('SELECT public.rls_auto_enable()')))
      .rejects.toMatchObject({ code: '0A000' });
  });
});
