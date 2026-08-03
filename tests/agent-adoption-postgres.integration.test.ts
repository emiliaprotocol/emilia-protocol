// SPDX-License-Identifier: Apache-2.0
/**
 * Real PostgreSQL 17 proof for Agent Adoption and the restored SCIM directory
 * anchor. Local focused runs skip unless INTEGRATION_POSTGRES=1 is explicit;
 * the integration-postgres CI job always sets it and therefore cannot skip.
 */
import { readFileSync } from 'node:fs';

import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createOperatingBond } from '../lib/agent-adoption/core';

const adoptionMigration = readFileSync(
  new URL('../supabase/migrations/20260802230000_agent_adoption_v1.sql', import.meta.url),
  'utf8',
);
const directoryMigration = readFileSync(
  new URL('../supabase/migrations/20260802231000_restore_webauthn_directory_anchor.sql', import.meta.url),
  'utf8',
);
const scimAuthorityMigration = readFileSync(
  new URL('../supabase/migrations/20260802232000_scim_authority_atomic.sql', import.meta.url),
  'utf8',
);

const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;

const DATABASE = 'ep_agent_adoption_test';
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};
const controlDatabase = process.env.PGDATABASE ?? 'ep_test';
const GENERIC_ROLES = ['anon', 'authenticated', 'service_role'] as const;
const GLOBAL_ROLES = [...GENERIC_ROLES, 'agent_adoption_store_owner'] as const;
const WRONG_SESSION_TOKEN = `eaa1_${'f'.repeat(64)}`;
const REGISTRATION_DIGEST = `sha256:${'1'.repeat(64)}`;
const ASSERTION_DIGEST = `sha256:${'2'.repeat(64)}`;

type JsonObject = Record<string, unknown>;
type AdoptionSession = {
  tenant_id: string;
  adoption_id: string;
  session_token: string;
  expires_at: string;
  candidate_digest: string;
  bond_digest: string;
  operating_bond: JsonObject;
  public_projection: JsonObject;
};

let admin: pg.Client;
let database: pg.Pool;
let initiallyPresentRoles = new Set<string>();
let adminConnected = false;

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
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

async function rpc<T extends JsonObject = JsonObject>(
  role: (typeof GENERIC_ROLES)[number],
  sql: string,
  params: unknown[],
): Promise<T> {
  return asRole(role, async (client) => {
    const result = await client.query<{ result: T }>(sql, params);
    return result.rows[0].result;
  });
}

async function createSession(label = 'Atlas'): Promise<AdoptionSession> {
  const built = createOperatingBond({
    label,
    source_kind: 'local',
    job_template_id: 'job_vendor_intake_v1',
    allowance_template_id: 'allowance_cautious_v1',
  });
  return rpc<AdoptionSession>(
    'service_role',
    `SELECT public.create_agent_adoption_session(
       $1, $2, $3, $4::jsonb, $5::jsonb
     ) AS result`,
    [
      label,
      built.candidate_digest,
      built.bond_digest,
      JSON.stringify(built.bond),
      JSON.stringify(built.public_projection),
    ],
  );
}

async function registrationChallenge(session: AdoptionSession): Promise<JsonObject> {
  return rpc(
    'service_role',
    'SELECT public.create_agent_adoption_registration_challenge($1, $2) AS result',
    [session.adoption_id, session.session_token],
  );
}

async function completeRegistration(
  session: AdoptionSession,
  challengeToken: string,
  credentialId: string,
): Promise<JsonObject> {
  return rpc(
    'service_role',
    `SELECT public.complete_agent_adoption_registration(
       $1, $2, $3, $4, $5, $6, 'ES256', 'P-256', $7::text[],
       'multiDevice', true, 0, false, 'www.emiliaprotocol.ai',
       'https://www.emiliaprotocol.ai', $8
     ) AS result`,
    [
      session.adoption_id,
      session.session_token,
      challengeToken,
      credentialId,
      'AQID',
      'BAUG',
      ['internal'],
      REGISTRATION_DIGEST,
    ],
  );
}

async function waitForBlockedQuery(fragment: string, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const observed = await database.query<{ blocked: boolean }>(`
      SELECT COALESCE(pg_catalog.bool_or(wait_event_type = 'Lock'), false) AS blocked
      FROM pg_catalog.pg_stat_activity
      WHERE datname = pg_catalog.current_database()
        AND pid <> pg_catalog.pg_backend_pid()
        AND query LIKE '%' || $1 || '%'
    `, [fragment]);
    if (observed.rows[0].blocked) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`query did not reach a lock wait: ${fragment}`);
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
  // Pool.end() is the orderly custody boundary for this suite's clients.
  // Terminating those backends immediately afterward races node-postgres' socket
  // shutdown and can surface an unhandled 57P01 even after every assertion has
  // passed. Forced termination remains in beforeAll to recover stale clients
  // left by an interrupted prior run; a healthy afterAll never needs it.
  if (database) await database.end();
  await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
  for (const role of [...GLOBAL_ROLES].reverse()) {
    if (!initiallyPresentRoles.has(role)) {
      await admin.query(`DROP ROLE IF EXISTS ${identifier(role)}`);
    }
  }
}

suite('Agent Adoption migrations on clean PostgreSQL 17', () => {
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
    database = new pg.Pool({ ...baseConnection, database: DATABASE, max: 12 });

    // Minimal predecessors required by the two migrations. These are not mocks:
    // both migrations execute unchanged against real PostgreSQL objects/ACLs.
    await database.query(`
      CREATE SCHEMA extensions;
      CREATE EXTENSION pgcrypto WITH SCHEMA extensions;

      CREATE TABLE public.scim_provisioning_tokens (
        id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
        tenant_id TEXT NOT NULL,
        organization_id TEXT,
        token_hash TEXT NOT NULL UNIQUE,
        token_prefix TEXT NOT NULL,
        revoked_at TIMESTAMPTZ
      );
      CREATE TABLE public.scim_users (
        id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
        tenant_id TEXT NOT NULL,
        external_id TEXT,
        user_name TEXT NOT NULL,
        active BOOLEAN NOT NULL DEFAULT true,
        formatted_name TEXT,
        given_name TEXT,
        family_name TEXT,
        display_name TEXT,
        emails JSONB NOT NULL DEFAULT '[]'::jsonb,
        phone_numbers JSONB NOT NULL DEFAULT '[]'::jsonb,
        title TEXT,
        raw JSONB NOT NULL DEFAULT '{}'::jsonb,
        version INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
        UNIQUE (tenant_id, user_name)
      );
      CREATE TABLE public.audit_events (
        id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
        event_type TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_type TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        action TEXT NOT NULL,
        before_state JSONB,
        after_state JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp()
      );
      CREATE TABLE public.approver_credentials (
        id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
        organization_id TEXT NOT NULL,
        approver_id TEXT NOT NULL,
        approver_name TEXT,
        credential_id TEXT NOT NULL UNIQUE,
        public_key_cose TEXT NOT NULL,
        public_key_spki TEXT NOT NULL,
        key_class TEXT NOT NULL DEFAULT 'A',
        sign_count BIGINT NOT NULL DEFAULT 0,
        transports TEXT[],
        attestation_fmt TEXT,
        attested_by TEXT,
        enrollment_basis TEXT NOT NULL DEFAULT 'operator_attested'
          CHECK (enrollment_basis IN ('directory', 'operator_attested')),
        directory_user_id UUID,
        revoked_at TIMESTAMPTZ
      );
      CREATE TABLE public.webauthn_challenges (
        id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
        kind TEXT NOT NULL CHECK (kind IN ('registration', 'signoff')),
        organization_id TEXT,
        approver_id TEXT NOT NULL,
        challenge TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        consumed_at TIMESTAMPTZ
      );
    `);
    await database.query(adoptionMigration);
    await database.query(directoryMigration);
    await database.query(scimAuthorityMigration);
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

  it('enforces runtime ACLs on private state and every public RPC', async () => {
    const serviceExecutors = await database.query<{ function_name: string }>(`
      SELECT p.oid::regprocedure::text AS function_name
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
       WHERE n.nspname = 'public'
         AND (p.proname LIKE '%agent_adoption%' OR p.proname = 'read_agent_operating_bond')
         AND has_function_privilege('service_role', p.oid, 'EXECUTE')
       ORDER BY p.oid::regprocedure::text
    `);
    expect(serviceExecutors.rows.length).toBe(12);

    for (const role of ['anon', 'authenticated'] as const) {
      const executors = await database.query<{ count: string }>(`
        SELECT count(*)::text AS count
          FROM pg_catalog.pg_proc AS p
          JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND (p.proname LIKE '%agent_adoption%' OR p.proname = 'read_agent_operating_bond')
           AND has_function_privilege($1, p.oid, 'EXECUTE')
      `, [role]);
      expect(executors.rows).toEqual([{ count: '0' }]);
      await expect(asRole(role, (client) => client.query(
        'SELECT * FROM agent_adoption_private.adoption_sessions',
      ))).rejects.toMatchObject({ code: '42501' });
    }
  });

  it('completes the adoption lifecycle and refuses cross-token and replay attempts', async () => {
    const session = await createSession();
    expect(Date.parse(session.expires_at)).toBeGreaterThan(Date.now());

    await expect(rpc(
      'service_role',
      'SELECT public.read_agent_adoption_session($1, $2) AS result',
      [session.adoption_id, WRONG_SESSION_TOKEN],
    )).rejects.toMatchObject({ code: 'P0002' });

    const registration = await registrationChallenge(session);
    await expect(rpc(
      'service_role',
      `SELECT public.complete_agent_adoption_registration(
         $1, $2, $3, 'credential-cross-token', 'AQID', 'BAUG',
         'ES256', 'P-256', ARRAY['internal']::text[], 'multiDevice',
         true, 0, false, 'www.emiliaprotocol.ai',
         'https://www.emiliaprotocol.ai', $4
       ) AS result`,
      [session.adoption_id, WRONG_SESSION_TOKEN, registration.challenge_token, REGISTRATION_DIGEST],
    )).rejects.toMatchObject({ code: 'P0002' });

    const credentialId = 'credential_atlas';
    await expect(completeRegistration(
      session,
      String(registration.challenge_token),
      credentialId,
    )).resolves.toMatchObject({ registered: true, credential_id: credentialId });
    await expect(registrationChallenge(session)).rejects.toMatchObject({
      code: '55000',
      message: 'adoption credential is already registered',
    });
    await expect(completeRegistration(
      session,
      String(registration.challenge_token),
      credentialId,
    )).rejects.toMatchObject({ code: '55000' });

    const assertion = await rpc(
      'service_role',
      'SELECT public.create_agent_adoption_assertion_challenge($1, $2, $3) AS result',
      [session.adoption_id, session.session_token, credentialId],
    );
    const completed = await rpc(
      'service_role',
      `SELECT public.complete_agent_adoption_assertion(
         $1, $2, $3, $4, 0, false, 'multiDevice', true, $5
       ) AS result`,
      [
        session.adoption_id,
        session.session_token,
        assertion.challenge_token,
        credentialId,
        ASSERTION_DIGEST,
      ],
    );
    expect(completed).toMatchObject({
      adoption_id: session.adoption_id,
      bond_digest: session.bond_digest,
    });
    await expect(rpc(
      'service_role',
      `SELECT public.complete_agent_adoption_assertion(
         $1, $2, $3, $4, 0, false, 'multiDevice', true, $5
       ) AS result`,
      [
        session.adoption_id,
        session.session_token,
        assertion.challenge_token,
        credentialId,
        ASSERTION_DIGEST,
      ],
    )).rejects.toMatchObject({ code: '55000' });

    const published = await rpc(
      'service_role',
      'SELECT public.publish_agent_adoption_share($1, $2, $3) AS result',
      [session.adoption_id, session.session_token, completed.bond_id],
    );
    expect(published).toMatchObject({ published: true });
    const shareId = String(published.share_id);

    for (const role of ['anon', 'authenticated'] as const) {
      await expect(rpc(
        role,
        'SELECT public.read_agent_adoption_share($1) AS result',
        [shareId],
      )).rejects.toMatchObject({ code: '42501' });
    }
    await expect(rpc(
      'service_role',
      'SELECT public.read_agent_adoption_share($1) AS result',
      [shareId],
    )).resolves.toMatchObject({ revoked: false, projection: { share_id: shareId } });

    await expect(rpc(
      'service_role',
      'SELECT public.revoke_agent_adoption_share($1, $2, $3, $4, $5) AS result',
      [
        session.adoption_id,
        session.session_token,
        shareId,
        'user requested withdrawal',
        `easrv1_${'a'.repeat(48)}`,
      ],
    )).resolves.toMatchObject({ revoked: true, share_id: shareId });
    await expect(rpc(
      'service_role',
      'SELECT public.publish_agent_adoption_share($1, $2, $3) AS result',
      [session.adoption_id, session.session_token, completed.bond_id],
    )).rejects.toMatchObject({
      code: '55000',
      message: 'public share was revoked and cannot be republished',
    });

    const counts = await database.query<{ credentials: string; bonds: string; shares: string }>(`
      SELECT
        (SELECT count(*)::text FROM agent_adoption_private.adoption_credentials
          WHERE adoption_id = $1) AS credentials,
        (SELECT count(*)::text FROM agent_adoption_private.operating_bonds
          WHERE adoption_id = $1) AS bonds,
        (SELECT count(*)::text FROM agent_adoption_private.public_shares
          WHERE adoption_id = $1) AS shares
    `, [session.adoption_id]);
    expect(counts.rows).toEqual([{ credentials: '1', bonds: '1', shares: '1' }]);
  });

  it('bounds pending and lifetime challenge creation durably', async () => {
    const pendingSession = await createSession('Pending cap');
    for (let index = 0; index < 4; index += 1) {
      await expect(registrationChallenge(pendingSession)).resolves.toMatchObject({
        purpose: 'registration',
      });
    }
    await expect(registrationChallenge(pendingSession)).rejects.toMatchObject({
      code: '55000',
      message: 'too many pending registration challenges',
    });

    const lifetimeSession = await createSession('Lifetime cap');
    await database.query(`
      INSERT INTO agent_adoption_private.adoption_challenges (
        tenant_id, adoption_id, challenge_id, candidate_digest, bond_digest,
        purpose, nonce_hash, created_at, expires_at, consumed_at,
        completion_digest
      )
      SELECT
        $1::uuid, $2::uuid, extensions.gen_random_uuid(), $3, $4,
        'registration',
        pg_catalog.encode(extensions.digest(
          pg_catalog.convert_to('lifetime-' || sequence::text, 'UTF8'), 'sha256'
        ), 'hex'),
        pg_catalog.clock_timestamp() - interval '10 minutes',
        pg_catalog.clock_timestamp() - interval '5 minutes',
        pg_catalog.clock_timestamp() - interval '6 minutes',
        'sha256:' || pg_catalog.repeat('a', 64)
      FROM pg_catalog.generate_series(1, 32) AS sequence
    `, [
      lifetimeSession.tenant_id,
      lifetimeSession.adoption_id,
      lifetimeSession.candidate_digest,
      lifetimeSession.bond_digest,
    ]);
    await expect(registrationChallenge(lifetimeSession)).rejects.toMatchObject({
      code: '55000',
      message: 'adoption challenge lifetime limit reached',
    });
  });

  it('refuses expired sessions and expired challenge completion', async () => {
    const built = createOperatingBond({
      label: 'Expired session',
      source_kind: 'local',
      job_template_id: 'job_vendor_intake_v1',
      allowance_template_id: 'allowance_cautious_v1',
    });
    const expiredToken = `eaa1_${'e'.repeat(64)}`;
    const expiredId = '00000000-0000-4000-8000-0000000000e1';
    const expiredTenant = '00000000-0000-4000-8000-0000000000e2';
    await database.query(`
      INSERT INTO agent_adoption_private.adoption_sessions (
        tenant_id, adoption_id, session_token_hash, agent_label,
        candidate_digest, bond_digest, operating_bond, public_projection,
        created_at, expires_at
      ) VALUES (
        $1, $2,
        pg_catalog.encode(extensions.digest(pg_catalog.convert_to($3, 'UTF8'), 'sha256'), 'hex'),
        'Expired session', $4, $5, $6::jsonb, $7::jsonb,
        pg_catalog.clock_timestamp() - interval '2 days',
        pg_catalog.clock_timestamp() - interval '1 day'
      )
    `, [
      expiredTenant,
      expiredId,
      expiredToken,
      built.candidate_digest,
      built.bond_digest,
      JSON.stringify(built.bond),
      JSON.stringify(built.public_projection),
    ]);
    await expect(rpc(
      'service_role',
      'SELECT public.read_agent_adoption_session($1, $2) AS result',
      [expiredId, expiredToken],
    )).rejects.toMatchObject({ code: 'P0002' });

    const session = await createSession('Expired challenge');
    const expiredChallengeToken = `ear1_${'d'.repeat(64)}`;
    await database.query(`
      INSERT INTO agent_adoption_private.adoption_challenges (
        tenant_id, adoption_id, challenge_id, candidate_digest, bond_digest,
        purpose, nonce_hash, created_at, expires_at
      ) VALUES (
        $1, $2, extensions.gen_random_uuid(), $3, $4, 'registration',
        pg_catalog.encode(extensions.digest(pg_catalog.convert_to($5, 'UTF8'), 'sha256'), 'hex'),
        pg_catalog.clock_timestamp() - interval '10 minutes',
        pg_catalog.clock_timestamp() - interval '5 minutes'
      )
    `, [
      session.tenant_id,
      session.adoption_id,
      session.candidate_digest,
      session.bond_digest,
      expiredChallengeToken,
    ]);
    await expect(completeRegistration(
      session,
      expiredChallengeToken,
      'credential_expired_challenge',
    )).rejects.toMatchObject({ code: '55000', message: 'registration challenge expired' });
  });

  it('purges only expired sessions through the bounded service-role RPC', async () => {
    const active = await createSession('Retention survivor');
    const expired = await database.query<{ adoption_id: string }>(`
      SELECT adoption_id::text
      FROM agent_adoption_private.adoption_sessions
      WHERE expires_at <= pg_catalog.clock_timestamp()
      ORDER BY expires_at
      LIMIT 1
    `);
    expect(expired.rowCount).toBe(1);

    await expect(database.query(
      'DELETE FROM agent_adoption_private.adoption_sessions WHERE adoption_id = $1',
      [expired.rows[0].adoption_id],
    )).rejects.toMatchObject({ code: '55000' });
    await expect(rpc(
      'anon',
      'SELECT public.purge_expired_agent_adoptions(100) AS result',
      [],
    )).rejects.toMatchObject({ code: '42501' });
    await expect(rpc(
      'service_role',
      'SELECT public.purge_expired_agent_adoptions(100) AS result',
      [],
    )).resolves.toBeGreaterThanOrEqual(1);

    const remaining = await database.query<{ expired: string; active: string }>(`
      SELECT
        (SELECT count(*)::text FROM agent_adoption_private.adoption_sessions
          WHERE adoption_id = $1) AS expired,
        (SELECT count(*)::text FROM agent_adoption_private.adoption_sessions
          WHERE adoption_id = $2) AS active
    `, [expired.rows[0].adoption_id, active.adoption_id]);
    expect(remaining.rows).toEqual([{ expired: '0', active: '1' }]);
  });

  it('rechecks the exact active SCIM user under lock before directory enrollment', async () => {
    const organizationId = 'org-directory-proof';
    const approverId = 'alex@example.com';
    await database.query(`
      INSERT INTO public.scim_provisioning_tokens (
        tenant_id, organization_id, token_hash, token_prefix
      ) VALUES ($1, $1, 'token-hash-directory-proof', 'scim_proof')
    `, [organizationId]);

    const active = await database.query<{ id: string }>(`
      INSERT INTO public.scim_users (tenant_id, user_name, active)
      VALUES ($1, $2, true)
      RETURNING id
    `, [organizationId, approverId]);
    const activeChallenge = await database.query<{ id: string }>(`
      INSERT INTO public.webauthn_challenges (
        kind, organization_id, approver_id, challenge, expires_at
      ) VALUES ('registration', $1, $2, 'active-challenge', clock_timestamp() + interval '5 minutes')
      RETURNING id
    `, [organizationId, approverId]);
    const activeResult = await rpc(
      'service_role',
      `SELECT public.complete_webauthn_registration_atomic(
         $1, $2, $3, $4::jsonb
       ) AS result`,
      [
        activeChallenge.rows[0].id,
        organizationId,
        approverId,
        JSON.stringify({
          credential_id: 'directory-credential-active',
          public_key_cose: 'AQID',
          public_key_spki: 'BAUG',
          key_class: 'A',
          sign_count: 0,
          transports: ['internal'],
          enrollment_basis: 'directory',
          directory_user_id: active.rows[0].id,
        }),
      ],
    );
    expect(activeResult).toMatchObject({
      consumed: true,
      enrollment_basis: 'directory',
      directory_user_id: active.rows[0].id,
    });

    const blockedApprover = 'blocked@example.com';
    const blocked = await database.query<{ id: string }>(`
      INSERT INTO public.scim_users (tenant_id, user_name, active)
      VALUES ($1, $2, true)
      RETURNING id
    `, [organizationId, blockedApprover]);
    const blockedChallenge = await database.query<{ id: string }>(`
      INSERT INTO public.webauthn_challenges (
        kind, organization_id, approver_id, challenge, expires_at
      ) VALUES ('registration', $1, $2, 'blocked-challenge', clock_timestamp() + interval '5 minutes')
      RETURNING id
    `, [organizationId, blockedApprover]);

    const deprovisioner = await database.connect();
    await deprovisioner.query('BEGIN');
    await deprovisioner.query(
      'UPDATE public.scim_users SET active = false WHERE id = $1',
      [blocked.rows[0].id],
    );
    const completion = rpc(
      'service_role',
      `SELECT public.complete_webauthn_registration_atomic(
         $1, $2, $3, $4::jsonb
       ) AS result`,
      [
        blockedChallenge.rows[0].id,
        organizationId,
        blockedApprover,
        JSON.stringify({
          credential_id: 'directory-credential-blocked',
          public_key_cose: 'AQID',
          public_key_spki: 'BAUG',
          key_class: 'A',
          sign_count: 0,
          transports: ['internal'],
          enrollment_basis: 'directory',
          directory_user_id: blocked.rows[0].id,
        }),
      ],
    );
    await waitForBlockedQuery('complete_webauthn_registration_atomic');
    await deprovisioner.query('COMMIT');
    deprovisioner.release();

    await expect(completion).resolves.toEqual({ error: 'directory_user_inactive' });
    const durable = await database.query<{ credentials: string; consumed: string }>(`
      SELECT
        (SELECT count(*)::text FROM public.approver_credentials
          WHERE credential_id = 'directory-credential-blocked') AS credentials,
        (SELECT count(*)::text FROM public.webauthn_challenges
          WHERE id = $1 AND consumed_at IS NOT NULL) AS consumed
    `, [blockedChallenge.rows[0].id]);
    expect(durable.rows).toEqual([{ credentials: '0', consumed: '0' }]);
  });

  it('atomically deprovisions a SCIM user and every matching approver credential', async () => {
    const organizationId = 'org-atomic-deprovision';
    const approverId = 'leave-now@example.com';
    const user = await database.query<{ id: string; version: number }>(`
      INSERT INTO public.scim_users (tenant_id, user_name, active)
      VALUES ($1, $2, true)
      RETURNING id, version
    `, [organizationId, approverId]);
    await database.query(`
      INSERT INTO public.approver_credentials (
        organization_id, approver_id, credential_id, public_key_cose,
        public_key_spki, enrollment_basis
      ) VALUES ($1, $2, 'atomic-deprovision-credential', 'AQID', 'BAUG', 'directory')
    `, [organizationId, approverId]);

    const fields = {
      user_name: approverId,
      external_id: null,
      active: false,
      formatted_name: null,
      given_name: null,
      family_name: null,
      display_name: null,
      title: null,
      emails: [],
      phone_numbers: [],
      raw: {},
    };
    await expect(rpc(
      'anon',
      'SELECT public.apply_scim_user_and_authority_atomic($1,$2,$3,$4,$5::jsonb,false,$6) AS result',
      [organizationId, organizationId, user.rows[0].id, user.rows[0].version, JSON.stringify(fields), 'test'],
    )).rejects.toMatchObject({ code: '42501' });
    const result = await rpc(
      'service_role',
      'SELECT public.apply_scim_user_and_authority_atomic($1,$2,$3,$4,$5::jsonb,false,$6) AS result',
      [organizationId, organizationId, user.rows[0].id, user.rows[0].version, JSON.stringify(fields), 'scim_deactivate'],
    );
    expect(result).toMatchObject({ status: 'updated', credentials_revoked: 1 });

    const durable = await database.query<{ active: boolean; revoked: boolean; audit: string }>(`
      SELECT
        (SELECT active FROM public.scim_users WHERE id = $1) AS active,
        (SELECT revoked_at IS NOT NULL FROM public.approver_credentials
          WHERE credential_id = 'atomic-deprovision-credential') AS revoked,
        (SELECT count(*)::text FROM public.audit_events
          WHERE event_type = 'scim.approver.deprovisioned'
            AND target_id = $2) AS audit
    `, [user.rows[0].id, approverId]);
    expect(durable.rows).toEqual([{ active: false, revoked: true, audit: '1' }]);
  });

  it('revokes operator-attested credentials when a directory is enabled and refuses stale operator enrollment', async () => {
    const organizationId = 'org-directory-transition';
    const approverId = 'operator-era@example.com';
    await database.query(`
      INSERT INTO public.approver_credentials (
        organization_id, approver_id, credential_id, public_key_cose,
        public_key_spki, enrollment_basis
      ) VALUES ($1, $2, 'operator-era-credential', 'AQID', 'BAUG', 'operator_attested')
    `, [organizationId, approverId]);
    await database.query(`
      INSERT INTO public.scim_provisioning_tokens (
        tenant_id, organization_id, token_hash, token_prefix
      ) VALUES ($1, $1, 'directory-transition-token', 'scim_transition')
    `, [organizationId]);

    const revoked = await database.query<{ revoked: boolean }>(`
      SELECT revoked_at IS NOT NULL AS revoked
      FROM public.approver_credentials
      WHERE credential_id = 'operator-era-credential'
    `);
    expect(revoked.rows).toEqual([{ revoked: true }]);

    const challenge = await database.query<{ id: string }>(`
      INSERT INTO public.webauthn_challenges (
        kind, organization_id, approver_id, challenge, expires_at
      ) VALUES ('registration', $1, $2, 'stale-operator-challenge', clock_timestamp() + interval '5 minutes')
      RETURNING id
    `, [organizationId, approverId]);
    await expect(rpc(
      'service_role',
      'SELECT public.complete_webauthn_registration_atomic($1,$2,$3,$4::jsonb) AS result',
      [challenge.rows[0].id, organizationId, approverId, JSON.stringify({
        credential_id: 'stale-operator-credential',
        public_key_cose: 'AQID',
        public_key_spki: 'BAUG',
        key_class: 'A',
        sign_count: 0,
        transports: ['internal'],
        enrollment_basis: 'operator_attested',
      })],
    )).resolves.toEqual({ error: 'directory_required' });
  });
});
