// SPDX-License-Identifier: Apache-2.0
/**
 * Real PostgreSQL 17 proof for the Agent Record privacy, identity, and
 * capability-gated creation contracts.
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
  verifyAgentRecordObservation,
} from '../lib/agent-record/core';

const migration = readFileSync(
  new URL('../supabase/migrations/20260803020000_agent_record_v1.sql', import.meta.url),
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
const ARENA_SESSION_ID = `arena_session_${'4'.repeat(32)}`;
const ARENA_TOKEN_HASH = '4'.repeat(64);
const OWNER_TOKEN = `ear1_${'a'.repeat(64)}`;
const SECOND_OWNER_TOKEN = `ear1_${'b'.repeat(64)}`;
const THIRD_OWNER_TOKEN = `ear1_${'c'.repeat(64)}`;
const CREATION_CAPABILITY = `earc1_${'d'.repeat(64)}`;
const WRONG_CAPABILITY = `earc1_${'e'.repeat(64)}`;
const SIGNING_SEED = Buffer.alloc(32, 7).toString('base64');
const BASE_NOW = Date.now();
const SESSION_EXPIRES_AT = new Date(BASE_NOW + 24 * 60 * 60 * 1_000).toISOString();
const ARENA_KEYS = crypto.generateKeyPairSync('ed25519');
const ARENA_ISSUER_ID = 'arena:session:agent-record-pg';
const ARENA_KEY_ID = 'arena-session-key-agent-record-pg';

type JsonObject = Record<string, any>;
type PreparedSource = Readonly<{
  source_commitment: string;
  source_artifact_digest: string;
  action_digest: string;
  refusal_digest: string;
  refused_at: string;
  refusal_artifact: JsonObject;
  issuer: JsonObject;
}>;
type CreateInput = Readonly<{
  adoptionId: string;
  sessionToken: string;
  recordId: string;
  ownerToken: string;
  bondId: string;
  bondDigest: string;
  sourceSessionId: string;
  sourceTokenHash: string;
  sourceAttemptId: string;
  sourceCommitment: string;
  sourceArtifactDigest: string;
  actionDigest: string;
  refusalDigest: string;
  refusedAt: string;
  observedAt: string;
  retentionExpiresAt: string;
  publicProjection: JsonObject;
}>;

const priorEnvironment = Object.freeze({
  NODE_ENV: process.env.NODE_ENV,
  EP_COMMIT_SIGNING_KEY: process.env.EP_COMMIT_SIGNING_KEY,
  EP_COMMIT_SIGNING_KEYS: process.env.EP_COMMIT_SIGNING_KEYS,
  EP_AGENT_RECORD_SIGNING_KEY_ID: process.env.EP_AGENT_RECORD_SIGNING_KEY_ID,
});

let admin: pg.Client | undefined;
let database: pg.Pool | undefined;
let initiallyPresentRoles = new Set<string>();
let initialServiceRoleBypassRls: boolean | undefined;
let primarySource: PreparedSource;
let secondarySource: PreparedSource;
let primaryInput: CreateInput;

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function ownerRecordId(ownerToken: string): string {
  const digest = crypto.createHash('sha256')
    .update(`emilia-agent-record-owner-token-v1\0${ownerToken}`, 'utf8')
    .digest('hex');
  return `agent_record_${digest.slice(0, 40)}`;
}

function restoreEnvironment(): void {
  for (const [name, value] of Object.entries(priorEnvironment)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

function makeAttempt(character: string, refusedAtOffsetMs: number) {
  const attemptId = `arena_attempt_${character.repeat(32)}`;
  const refusedAt = new Date(BASE_NOW + refusedAtOffsetMs).toISOString();
  const expiresAt = new Date(BASE_NOW + 60 * 60 * 1_000).toISOString();
  const allowance = createArenaAllowance({
    sessionId: ARENA_SESSION_ID,
    agentName: 'PostgreSQL privacy proof',
    totalAmount: 1_000,
    maxAmountPerAction: 250,
    allowedTargets: ['vendor.demo'],
    issuedAt: new Date(BASE_NOW - 60 * 60 * 1_000).toISOString(),
    expiresAt: SESSION_EXPIRES_AT,
  });
  const action = {
    operation_id: `operation-private-${character}`,
    action_type: 'arena.resource.allocate.1' as const,
    target: 'vendor.demo',
    amount: 900,
    currency: 'CREDITS' as const,
    purpose: `raw-action-parameters-${character}`,
  };
  const signed = signArenaRefusal({
    allowance,
    action,
    reason: 'allowance_per_action_limit_exceeded',
    attemptId,
    attemptNonce: Buffer.alloc(32, character.charCodeAt(0)).toString('base64url'),
    refusedAt,
    expiresAt,
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
    refusalArtifact: signed.statement,
    issuerId: ARENA_ISSUER_ID,
    keyId: ARENA_KEY_ID,
    publicKey: ARENA_KEYS.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  });
}

const ATTEMPTS = Object.freeze([
  makeAttempt('a', -120_000),
  makeAttempt('b', -110_000),
  makeAttempt('c', -100_000),
]);

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

async function configureCapability(capability: string): Promise<void> {
  if (!database) throw new Error('database is unavailable');
  const client = await database.connect();
  try {
    await client.query('SET ROLE agent_record_store_owner');
    await client.query(
      'SELECT agent_record_private.configure_creation_capability($1)',
      [capability],
    );
  } finally {
    await client.query('RESET ROLE').catch(() => undefined);
    client.release();
  }
}

async function readSource(attemptId: string): Promise<PreparedSource> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ source: PreparedSource }>(
      'SELECT public.read_agent_record_refusal_source($1, $2, $3) AS source',
      [ARENA_TOKEN_HASH, ARENA_SESSION_ID, attemptId],
    );
    return result.rows[0].source;
  });
}

function createInput(
  source: PreparedSource,
  sourceAttemptId: string,
  ownerToken: string,
  overrides: Partial<CreateInput> = {},
): CreateInput {
  const recordId = overrides.recordId ?? ownerRecordId(ownerToken);
  const observedAt = overrides.observedAt
    ?? new Date(Math.max(BASE_NOW - 30_000, Date.parse(source.refused_at))).toISOString();
  const retentionExpiresAt = overrides.retentionExpiresAt
    ?? new Date(Date.parse(observedAt) + AGENT_RECORD_RETENTION_MS).toISOString();
  const values = {
    adoptionId: ADOPTION_ID,
    sessionToken: SESSION_TOKEN,
    recordId,
    ownerToken,
    bondId: BOND_ID,
    bondDigest: BOND_DIGEST,
    sourceSessionId: ARENA_SESSION_ID,
    sourceTokenHash: ARENA_TOKEN_HASH,
    sourceAttemptId,
    sourceCommitment: source.source_commitment,
    sourceArtifactDigest: source.source_artifact_digest,
    actionDigest: source.action_digest,
    refusalDigest: source.refusal_digest,
    refusedAt: source.refused_at,
    observedAt,
    retentionExpiresAt,
    ...overrides,
  };
  return Object.freeze({
    ...values,
    publicProjection: overrides.publicProjection ?? signAgentRecordObservation({
      recordId: values.recordId,
      bondId: values.bondId,
      bondDigest: values.bondDigest,
      sourceArtifactDigest: values.sourceArtifactDigest,
      actionDigest: values.actionDigest,
      refusalDigest: values.refusalDigest,
      refusedAt: values.refusedAt,
      observedAt: values.observedAt,
      retentionExpiresAt: values.retentionExpiresAt,
    }),
  });
}

function createParameters(input: CreateInput): unknown[] {
  return [
    input.adoptionId,
    input.sessionToken,
    input.recordId,
    input.ownerToken,
    input.bondId,
    input.bondDigest,
    input.sourceSessionId,
    input.sourceTokenHash,
    input.sourceAttemptId,
    input.sourceCommitment,
    input.sourceArtifactDigest,
    input.actionDigest,
    input.refusalDigest,
    input.refusedAt,
    input.observedAt,
    input.retentionExpiresAt,
    JSON.stringify(input.publicProjection),
  ];
}

const BASE_CREATE_SQL = `SELECT public.create_agent_record(
  $1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13,
  $14::timestamptz, $15::timestamptz, $16::timestamptz, $17::jsonb
) AS result`;

const CAPABILITY_CREATE_SQL = `SELECT public.create_agent_record_with_capability(
  $1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13,
  $14::timestamptz, $15::timestamptz, $16::timestamptz, $17::jsonb, $18
) AS result`;

async function createRecord(
  input: CreateInput,
  capability = CREATION_CAPABILITY,
): Promise<JsonObject> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ result: JsonObject }>(
      CAPABILITY_CREATE_SQL,
      [...createParameters(input), capability],
    );
    return result.rows[0].result;
  });
}

async function readPublic(recordId: string): Promise<JsonObject> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ result: JsonObject }>(
      'SELECT public.read_agent_record_public($1) AS result',
      [recordId],
    );
    return result.rows[0].result;
  });
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

suite('Agent Record v1 on PostgreSQL 17', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.EP_COMMIT_SIGNING_KEY = SIGNING_SEED;
    process.env.EP_COMMIT_SIGNING_KEYS = '';
    process.env.EP_AGENT_RECORD_SIGNING_KEY_ID = 'agent-record-pg-test-key';

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
    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 8 });

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
        share_id TEXT PRIMARY KEY,
        public_projection JSONB NOT NULL
      );
      GRANT SELECT, INSERT ON TABLE public.arena_shares TO service_role;

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
    `);

    for (const attempt of ATTEMPTS) {
      await database.query(
        `INSERT INTO public.arena_sessions (
           session_id, token_hash, challenge_id, challenge_version,
           issuer_id, key_id, public_key, status, expires_at
         ) VALUES ($1, $2, 'emilia.arena.allowance', 1, $3, $4, $5, 'active', $6)
         ON CONFLICT (session_id) DO UPDATE SET
           issuer_id = EXCLUDED.issuer_id,
           key_id = EXCLUDED.key_id,
           public_key = EXCLUDED.public_key`,
        [
          ARENA_SESSION_ID,
          ARENA_TOKEN_HASH,
          attempt.issuerId,
          attempt.keyId,
          attempt.publicKey,
          SESSION_EXPIRES_AT,
        ],
      );
      await database.query(
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
          attempt.attemptId,
          `nonce_${attempt.attemptId.slice(-32)}`,
          JSON.stringify(attempt.action),
          attempt.actionDigest,
          (attempt.refusalArtifact as JsonObject).caid,
          JSON.stringify(attempt.refusalArtifact),
          attempt.refusalDigest,
          attempt.refusedAt,
          ARENA_SESSION_ID,
        ],
      );
    }

    await database.query(migration);
    await configureCapability(CREATION_CAPABILITY);
    primarySource = await readSource(ATTEMPTS[0].attemptId);
    secondarySource = await readSource(ATTEMPTS[1].attemptId);
    primaryInput = createInput(primarySource, ATTEMPTS[0].attemptId, OWNER_TOKEN);
  }, 60_000);

  afterAll(async () => {
    try {
      await cleanup();
    } finally {
      if (admin) await admin.end();
      restoreEnvironment();
    }
  }, 60_000);

  it('denies direct service_role creation while the verified application path remains possible', async () => {
    expect(verifyAgentRecordObservation(
      primaryInput.publicProjection,
      Date.parse(primaryInput.observedAt),
    )).toMatchObject({ verified: true, within_retention: true });

    await expect(asRole('service_role', (client) => client.query(
      BASE_CREATE_SQL,
      createParameters(primaryInput),
    ))).rejects.toMatchObject({ code: '42501' });

    await expect(createRecord(primaryInput, WRONG_CAPABILITY))
      .rejects.toMatchObject({ code: '42501' });
    const before = await database!.query<{ records: string; shares: string }>(`
      SELECT (SELECT count(*)::text FROM agent_record_private.records) AS records,
             (SELECT count(*)::text FROM public.arena_shares) AS shares
    `);
    expect(before.rows).toEqual([{ records: '0', shares: '0' }]);

    const created = await createRecord(primaryInput);
    expect(created).toMatchObject({
      record_id: primaryInput.recordId,
      public_projection: primaryInput.publicProjection,
    });
    const after = await database!.query<{ records: string; shares: string }>(`
      SELECT (SELECT count(*)::text FROM agent_record_private.records) AS records,
             (SELECT count(*)::text FROM public.arena_shares) AS shares
    `);
    expect(after.rows).toEqual([{ records: '1', shares: '0' }]);
  });

  it('keeps capability configuration private and provides a boolean readiness proof', async () => {
    const privileges = await database!.query<{
      base_create: boolean;
      capability_create: boolean;
      capability_configure: boolean;
    }>(`
      SELECT
        has_function_privilege(
          'service_role',
          'public.create_agent_record(uuid,text,text,text,uuid,text,text,text,text,text,text,text,text,timestamptz,timestamptz,timestamptz,jsonb)',
          'EXECUTE'
        ) AS base_create,
        has_function_privilege(
          'service_role',
          'public.create_agent_record_with_capability(uuid,text,text,text,uuid,text,text,text,text,text,text,text,text,timestamptz,timestamptz,timestamptz,jsonb,text)',
          'EXECUTE'
        ) AS capability_create,
        has_function_privilege(
          'service_role',
          'agent_record_private.configure_creation_capability(text)',
          'EXECUTE'
        ) AS capability_configure
    `);
    expect(privileges.rows).toEqual([{
      base_create: false,
      capability_create: true,
      capability_configure: false,
    }]);

    await expect(asRole('service_role', (client) => client.query(
      'SELECT agent_record_private.configure_creation_capability($1)',
      [WRONG_CAPABILITY],
    ))).rejects.toMatchObject({ code: '42501' });
    const readiness = await asRole('service_role', async (client) => {
      const result = await client.query<{ valid: boolean; invalid: boolean }>(
        `SELECT public.check_agent_record_creation_capability($1) AS valid,
                public.check_agent_record_creation_capability($2) AS invalid`,
        [CREATION_CAPABILITY, WRONG_CAPABILITY],
      );
      return result.rows[0];
    });
    expect(readiness).toEqual({ valid: true, invalid: false });
  });

  it('enforces the exact owner-derived record id in SQL for create and revoke', async () => {
    const expected = ownerRecordId(SECOND_OWNER_TOKEN);
    const derived = await database!.query<{ record_id: string }>(
      'SELECT agent_record_private.owner_record_id($1) AS record_id',
      [SECOND_OWNER_TOKEN],
    );
    expect(derived.rows).toEqual([{ record_id: expected }]);

    const mismatched = createInput(
      secondarySource,
      ATTEMPTS[1].attemptId,
      SECOND_OWNER_TOKEN,
      { recordId: ownerRecordId(THIRD_OWNER_TOKEN) },
    );
    await expect(createRecord(mismatched)).rejects.toMatchObject({ code: '22023' });
    const mismatchCount = await database!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM agent_record_private.records WHERE record_id = $1',
      [mismatched.recordId],
    );
    expect(mismatchCount.rows).toEqual([{ count: '0' }]);

    await expect(asRole('service_role', (client) => client.query(
      'SELECT public.revoke_agent_record($1, $2, $3)',
      [primaryInput.recordId, SECOND_OWNER_TOKEN, `earv1_${'7'.repeat(64)}`],
    ))).rejects.toMatchObject({ code: '22023' });
    await expect(readPublic(primaryInput.recordId)).resolves.toMatchObject({
      record_id: primaryInput.recordId,
    });
  });

  it('preserves atomicity and never creates or mutates an Arena share', async () => {
    await expect(createRecord(primaryInput)).resolves.toMatchObject({
      record_id: primaryInput.recordId,
    });

    const secondaryInput = createInput(
      secondarySource,
      ATTEMPTS[1].attemptId,
      SECOND_OWNER_TOKEN,
    );
    await database!.query(`
      CREATE FUNCTION public.agent_record_injected_insert_failure()
      RETURNS TRIGGER LANGUAGE plpgsql SET search_path = ''
      AS $failure$
      BEGIN
        RAISE EXCEPTION 'injected Agent Record insert failure' USING ERRCODE = 'XX000';
      END
      $failure$;
      CREATE TRIGGER agent_record_injected_insert_failure_trigger
        BEFORE INSERT ON agent_record_private.records
        FOR EACH ROW EXECUTE FUNCTION public.agent_record_injected_insert_failure();
    `);
    try {
      await expect(createRecord(secondaryInput)).rejects.toMatchObject({ code: 'XX000' });
    } finally {
      await database!.query(`
        DROP TRIGGER agent_record_injected_insert_failure_trigger
          ON agent_record_private.records;
        DROP FUNCTION public.agent_record_injected_insert_failure();
      `);
    }

    const counts = await database!.query<{ records: string; shares: string }>(`
      SELECT
        (SELECT count(*)::text FROM agent_record_private.records
          WHERE record_id = $1) AS records,
        (SELECT count(*)::text FROM public.arena_shares) AS shares
    `, [secondaryInput.recordId]);
    expect(counts.rows).toEqual([{ records: '0', shares: '0' }]);
  });

  it('serializes a refusal source so only one independently owned record can consume it', async () => {
    const first = createInput(secondarySource, ATTEMPTS[1].attemptId, SECOND_OWNER_TOKEN);
    const second = createInput(secondarySource, ATTEMPTS[1].attemptId, THIRD_OWNER_TOKEN);
    const results = await Promise.allSettled([createRecord(first), createRecord(second)]);
    expect(results.filter(({ status }) => status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find(({ status }) => status === 'rejected') as PromiseRejectedResult;
    expect(rejected.reason).toMatchObject({ code: '23505' });
    const counts = await database!.query<{ records: string; shares: string }>(`
      SELECT
        (SELECT count(*)::text FROM agent_record_private.records
          WHERE source_commitment = $1) AS records,
        (SELECT count(*)::text FROM public.arena_shares) AS shares
    `, [secondarySource.source_commitment]);
    expect(counts.rows).toEqual([{ records: '1', shares: '0' }]);
  });

  it('stores and returns only digest bindings, never raw action parameters or a share id', async () => {
    const sourceBytes = JSON.stringify(primarySource);
    expect(sourceBytes).not.toContain('raw-action-parameters-a');
    expect(sourceBytes).not.toContain('operation-private-a');
    expect(sourceBytes).not.toMatch(/arena_share_|share_id|public_projection/);

    const stored = await database!.query<{ row_text: string }>(
      `SELECT pg_catalog.row_to_json(record)::text AS row_text
         FROM agent_record_private.records AS record WHERE record_id = $1`,
      [primaryInput.recordId],
    );
    expect(stored.rows[0].row_text).not.toContain('raw-action-parameters-a');
    expect(stored.rows[0].row_text).not.toContain('operation-private-a');
    expect(stored.rows[0].row_text).not.toMatch(/arena_share_|share_id/);
    expect(stored.rows[0].row_text).not.toContain(OWNER_TOKEN);
    expect(stored.rows[0].row_text).toContain(primarySource.source_commitment);
    expect(stored.rows[0].row_text).toContain(primarySource.source_artifact_digest);

    const publicRecord = await readPublic(primaryInput.recordId);
    expect(publicRecord).toMatchObject({
      record_id: primaryInput.recordId,
      public_projection: primaryInput.publicProjection,
    });
    expect(JSON.stringify(publicRecord)).not.toMatch(
      /raw-action|action_parameters|arena_share_|share_id|session_id|owner_token/,
    );
  });

  it('forces RLS and keeps service_role out of every private table', async () => {
    const relations = await database!.query<{
      relname: string;
      relrowsecurity: boolean;
      relforcerowsecurity: boolean;
    }>(`
      SELECT class.relname, class.relrowsecurity, class.relforcerowsecurity
        FROM pg_catalog.pg_class AS class
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
       WHERE namespace.nspname = 'agent_record_private'
         AND class.relname = ANY($1::text[])
       ORDER BY class.relname
    `, [['creation_capability', 'records', 'revocations']]);
    expect(relations.rows).toEqual([
      { relname: 'creation_capability', relrowsecurity: true, relforcerowsecurity: true },
      { relname: 'records', relrowsecurity: true, relforcerowsecurity: true },
      { relname: 'revocations', relrowsecurity: true, relforcerowsecurity: true },
    ]);
    for (const table of ['creation_capability', 'records', 'revocations']) {
      await expect(asRole('service_role', (client) => client.query(
        `SELECT * FROM agent_record_private.${table}`,
      )), table).rejects.toMatchObject({ code: '42501' });
    }
    await expect(database!.query(
      'UPDATE agent_record_private.records SET bond_digest = bond_digest WHERE record_id = $1',
      [primaryInput.recordId],
    )).rejects.toMatchObject({ code: '55000' });
    await expect(database!.query(
      'DELETE FROM agent_record_private.records WHERE record_id = $1',
      [primaryInput.recordId],
    )).rejects.toMatchObject({ code: '55000' });
  });

  it('keeps unknown and owner-revoked public records indistinguishable', async () => {
    let unknownError: unknown;
    let revokedError: unknown;
    try {
      await readPublic(`agent_record_${'9'.repeat(40)}`);
    } catch (error) {
      unknownError = error;
    }

    await expect(asRole('service_role', async (client) => {
      const result = await client.query<{ result: JsonObject }>(
        'SELECT public.revoke_agent_record($1, $2, $3) AS result',
        [primaryInput.recordId, OWNER_TOKEN, `earv1_${'8'.repeat(64)}`],
      );
      return result.rows[0].result;
    })).resolves.toMatchObject({ record_id: primaryInput.recordId, revoked: true });
    try {
      await readPublic(primaryInput.recordId);
    } catch (error) {
      revokedError = error;
    }
    expect(unknownError).toMatchObject({ code: 'P0002', message: 'agent record not found' });
    expect(revokedError).toMatchObject({ code: 'P0002', message: 'agent record not found' });
    const shares = await database!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.arena_shares',
    );
    expect(shares.rows).toEqual([{ count: '0' }]);
    await expect(database!.query(
      'UPDATE agent_record_private.revocations SET revoked_at = revoked_at WHERE record_id = $1',
      [primaryInput.recordId],
    )).rejects.toMatchObject({ code: '55000' });
  });
});
