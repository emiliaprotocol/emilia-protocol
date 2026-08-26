// SPDX-License-Identifier: Apache-2.0
/**
 * Real PostgreSQL proof for continuity challenge role derivation, locking,
 * transaction rollback, and RPC exposure. CI sets INTEGRATION_POSTGRES=1.
 */
import { readFileSync } from 'node:fs';

import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260826130000_continuity_challenge_atomic.sql', import.meta.url),
  'utf8',
);
const residualClosureMigration = readFileSync(
  new URL(
    '../supabase/migrations/20260826160000_continuity_and_pairing_residual_closure.sql',
    import.meta.url,
  ),
  'utf8',
);

const suite = process.env.INTEGRATION_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;

const DATABASE = 'ep_continuity_atomic_test';
const baseConnection = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number.parseInt(process.env.PGPORT ?? '5433', 10),
  user: process.env.PGUSER ?? 'ep_test',
  password: process.env.PGPASSWORD ?? 'ep_test',
};
const controlDatabase = process.env.PGDATABASE ?? 'ep_test';
const ROLES = ['anon', 'authenticated', 'service_role'] as const;

let admin: pg.Client;
let database: pg.Pool;
let initiallyPresentRoles = new Set<string>();

function identifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function asRole<T>(role: (typeof ROLES)[number], callback: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await database.connect();
  try {
    await client.query(`SET ROLE ${identifier(role)}`);
    return await callback(client);
  } finally {
    await client.query('RESET ROLE').catch(() => undefined);
    client.release();
  }
}

async function challenge(input: {
  continuityId: string;
  challengeId: string;
  challengerId: string;
  enterpriseAdmin?: boolean;
}): Promise<Record<string, any>> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ result: Record<string, any> }>(`
      SELECT public.challenge_continuity_atomic(
        $1, $2, $3, 'evidence contradicts the continuity claim',
        '{"source":"postgres-regression"}'::jsonb, $4
      ) AS result
    `, [input.continuityId, input.challengeId, input.challengerId, input.enterpriseAdmin === true]);
    return result.rows[0].result;
  });
}

async function fileClaim(input: {
  continuityId: string;
  principalId: string;
  oldEntityId: string;
  newEntityId: string;
  reason?: string;
  actorEntityId?: string;
  continuityMode?: 'linear' | 'fission' | 'merger';
  transferBudget?: number;
}): Promise<Record<string, any>> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ result: Record<string, any> }>(`
      SELECT public.file_continuity_claim_atomic(
        $1, $2, $3, $4, $5, $6, $7, '[]'::jsonb, $8
      ) AS result
    `, [
      input.continuityId,
      input.principalId,
      input.actorEntityId ?? input.newEntityId,
      input.oldEntityId,
      input.newEntityId,
      input.reason ?? 'key_rotation',
      input.continuityMode ?? 'linear',
      input.transferBudget ?? 1.0,
    ]);
    return result.rows[0].result;
  });
}

async function withdrawClaim(input: {
  continuityId: string;
  actorEntityId: string;
  reason?: string;
}): Promise<Record<string, any>> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ result: Record<string, any> }>(`
      SELECT public.withdraw_continuity_claim_atomic($1, $2, $3) AS result
    `, [input.continuityId, input.actorEntityId, input.reason ?? null]);
    return result.rows[0].result;
  });
}

async function resolveClaim(input: {
  continuityId: string;
  decision?: string;
  operatorId?: string;
}): Promise<Record<string, any>> {
  return asRole('service_role', async (client) => {
    const result = await client.query<{ result: Record<string, any> }>(`
      SELECT public.resolve_continuity_atomic(
        $1, $2, '["postgres identity proof"]'::jsonb, $3
      ) AS result
    `, [
      input.continuityId,
      input.decision ?? 'approved_full',
      input.operatorId ?? 'operator-postgres',
    ]);
    return result.rows[0].result;
  });
}

async function seedClaim(label: string): Promise<{
  claimId: string;
  oldEntityDbId: string;
  challengerDbId: string;
  principalId: string;
  oldEntityId: string;
  newEntityId: string;
  selfEntityId: string;
  challengerId: string;
}> {
  const principalId = `00000000-0000-4000-8000-${label.padStart(12, '0')}`;
  const challengerPrincipalId = `10000000-0000-4000-8000-${label.padStart(12, '0')}`;
  const oldEntityDbId = `20000000-0000-4000-8000-${label.padStart(12, '0')}`;
  const newEntityDbId = `30000000-0000-4000-8000-${label.padStart(12, '0')}`;
  const selfEntityDbId = `40000000-0000-4000-8000-${label.padStart(12, '0')}`;
  const challengerDbId = `50000000-0000-4000-8000-${label.padStart(12, '0')}`;
  const claimId = `ep_ix_${label}`;
  const selfEntityId = `self-${label}`;
  const challengerId = `counterparty-${label}`;

  await database.query(`
    INSERT INTO public.principals (id, principal_id) VALUES
      ($1, $2), ($3, $4)
  `, [
    principalId, `principal-${label}`,
    challengerPrincipalId, `challenger-principal-${label}`,
  ]);
  await database.query(`
    INSERT INTO public.entities (
      id, entity_id, principal_id, organization_id, status
    ) VALUES
      ($1, $2, $3, 'org-owner', 'active'),
      ($4, $5, $3, 'org-owner', 'active'),
      ($6, $7, $3, 'org-owner', 'active'),
      ($8, $9, $10, 'org-counterparty', 'active')
  `, [
    oldEntityDbId, `old-${label}`, principalId,
    newEntityDbId, `new-${label}`,
    selfEntityDbId, selfEntityId,
    challengerDbId, challengerId, challengerPrincipalId,
  ]);
  await database.query(`
    INSERT INTO public.continuity_claims (
      continuity_id, principal_id, old_entity_id, new_entity_id,
      status, challenge_deadline
    ) VALUES ($1, $2, $3, $4, 'pending', now() + interval '1 hour')
  `, [claimId, principalId, `old-${label}`, `new-${label}`]);
  await database.query(`
    INSERT INTO public.audit_events (
      event_type, actor_id, actor_type, target_type, target_id, action, after_state
    ) VALUES (
      'continuity.successor_control_verified', $2::text, 'entity', 'continuity', $1::text,
      'verify_successor_control', jsonb_build_object(
        'successor_control', 'verified',
        'subject_principal', $3::text,
        'old_entity', $4::text,
        'new_entity', $2::text
      )
    )
  `, [claimId, `new-${label}`, `principal-${label}`, `old-${label}`]);
  await database.query(`
    INSERT INTO public.disputes (
      dispute_id, entity_id, filed_by, status
    ) VALUES ($1, $2, $3, 'upheld')
  `, [`dispute-${label}`, oldEntityDbId, challengerDbId]);

  return {
    claimId,
    oldEntityDbId,
    challengerDbId,
    principalId: `principal-${label}`,
    oldEntityId: `old-${label}`,
    newEntityId: `new-${label}`,
    selfEntityId,
    challengerId,
  };
}

async function seedFiling(label: string): Promise<Awaited<ReturnType<typeof seedClaim>>> {
  const fixture = await seedClaim(label);
  await database.query('DELETE FROM public.disputes WHERE dispute_id = $1', [`dispute-${label}`]);
  await database.query('DELETE FROM public.audit_events WHERE target_id = $1', [fixture.claimId]);
  await database.query('DELETE FROM public.continuity_claims WHERE continuity_id = $1', [fixture.claimId]);
  return fixture;
}

async function seedFissionPair(
  label: string,
  budgets: readonly [number, number],
): Promise<{
  fixture: Awaited<ReturnType<typeof seedClaim>>;
  firstClaimId: string;
  secondClaimId: string;
  secondEntityId: string;
}> {
  const fixture = await seedFiling(label);
  const secondEntityId = `new-secondary-${label}`;
  const secondClaimId = `ep_ix_${label}_secondary`;
  await database.query(`
    INSERT INTO public.entities (id, entity_id, principal_id, organization_id, status)
    VALUES ($1, $2, $3, 'org-owner', 'active')
  `, [
    `60000000-0000-4000-8000-${label.padStart(12, '0')}`,
    secondEntityId,
    `00000000-0000-4000-8000-${label.padStart(12, '0')}`,
  ]);

  const filings = await Promise.all([
    fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
      continuityMode: 'fission',
      transferBudget: budgets[0],
    }),
    fileClaim({
      continuityId: secondClaimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: secondEntityId,
      continuityMode: 'fission',
      transferBudget: budgets[1],
    }),
  ]);
  expect(filings.every((result) => result.continuity?.status === 'pending')).toBe(true);

  return {
    fixture,
    firstClaimId: fixture.claimId,
    secondClaimId,
    secondEntityId,
  };
}

suite('continuity challenge atomic RPC on PostgreSQL', () => {
  beforeAll(async () => {
    admin = new pg.Client({ ...baseConnection, database: controlDatabase });
    await admin.connect();
    const roles = await admin.query<{ rolname: string }>(
      `SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])`,
      [ROLES],
    );
    initiallyPresentRoles = new Set(roles.rows.map((row) => row.rolname));
    for (const role of ROLES) {
      if (!initiallyPresentRoles.has(role)) await admin.query(`CREATE ROLE ${identifier(role)} NOLOGIN`);
    }
    await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
    await admin.query(`CREATE DATABASE ${identifier(DATABASE)}`);

    database = new pg.Pool({ ...baseConnection, database: DATABASE });
    await database.query(`
      CREATE EXTENSION IF NOT EXISTS pgcrypto;
      CREATE TABLE public.principals (
        id UUID PRIMARY KEY,
        principal_id TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'active'
      );
      CREATE TABLE public.entities (
        id UUID PRIMARY KEY,
        entity_id TEXT UNIQUE NOT NULL,
        principal_id UUID REFERENCES public.principals(id),
        organization_id TEXT,
        website_url TEXT,
        principal_linked_at TIMESTAMPTZ,
        status TEXT NOT NULL DEFAULT 'active'
      );
      CREATE TABLE public.continuity_claims (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        continuity_id TEXT UNIQUE NOT NULL,
        principal_id UUID NOT NULL REFERENCES public.principals(id),
        old_entity_id TEXT NOT NULL,
        new_entity_id TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT 'key_rotation',
        continuity_mode TEXT NOT NULL DEFAULT 'linear',
        proofs JSONB NOT NULL DEFAULT '[]',
        status TEXT NOT NULL,
        challenge_deadline TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        transfer_budget NUMERIC NOT NULL DEFAULT 1.0,
        transfer_policy TEXT,
        frozen_due_to TEXT,
        frozen_dispute_id TEXT,
        withdrawn_at TIMESTAMPTZ,
        withdrawn_by TEXT,
        withdrawn_reason TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE public.continuity_challenges (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        challenge_id TEXT UNIQUE NOT NULL,
        continuity_id TEXT NOT NULL REFERENCES public.continuity_claims(continuity_id),
        challenger_type TEXT NOT NULL CHECK (challenger_type IN (
          'old_entity_controller', 'principal_owner', 'bound_host',
          'dispute_counterparty', 'operator', 'enterprise_admin'
        )),
        challenger_id TEXT,
        reason TEXT NOT NULL,
        evidence JSONB NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'open',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE public.continuity_decisions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        continuity_id TEXT NOT NULL REFERENCES public.continuity_claims(continuity_id),
        decision TEXT NOT NULL,
        transfer_policy TEXT NOT NULL,
        allocation_rule JSONB,
        reasoning JSONB NOT NULL DEFAULT '[]',
        decided_by TEXT NOT NULL,
        decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE public.disputes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        dispute_id TEXT UNIQUE NOT NULL,
        entity_id UUID NOT NULL REFERENCES public.entities(id),
        filed_by UUID NOT NULL REFERENCES public.entities(id),
        status TEXT NOT NULL
      );
      CREATE TABLE public.identity_bindings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        principal_id UUID NOT NULL REFERENCES public.principals(id),
        binding_type TEXT NOT NULL,
        binding_target TEXT NOT NULL,
        status TEXT NOT NULL,
        expires_at TIMESTAMPTZ
      );
      CREATE TABLE public.audit_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        event_type TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_type TEXT NOT NULL CHECK (actor_type IN ('entity', 'principal', 'operator', 'system', 'human')),
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        action TEXT NOT NULL,
        before_state JSONB,
        after_state JSONB
      );

      INSERT INTO public.principals (id, principal_id) VALUES
        ('00000000-0000-4000-8000-000000000099', 'principal-backfill'),
        ('10000000-0000-4000-8000-000000000099', 'challenger-backfill');
      INSERT INTO public.entities (
        id, entity_id, principal_id, organization_id, status
      ) VALUES
        ('20000000-0000-4000-8000-000000000099', 'old-backfill',
          '00000000-0000-4000-8000-000000000099', 'org-backfill', 'active'),
        ('30000000-0000-4000-8000-000000000099', 'new-backfill',
          '00000000-0000-4000-8000-000000000099', 'org-backfill', 'active'),
        ('50000000-0000-4000-8000-000000000099', 'counterparty-backfill',
          '10000000-0000-4000-8000-000000000099', 'org-counterparty', 'active');
      INSERT INTO public.continuity_claims (
        continuity_id, principal_id, old_entity_id, new_entity_id,
        status, challenge_deadline, expires_at
      ) VALUES (
        'ep_ix_backfill', '00000000-0000-4000-8000-000000000099',
        'old-backfill', 'new-backfill', 'pending',
        now() + interval '1 day', now() + interval '30 days'
      );
      INSERT INTO public.disputes (dispute_id, entity_id, filed_by, status)
      VALUES (
        'appealed-dispute-backfill',
        '20000000-0000-4000-8000-000000000099',
        '50000000-0000-4000-8000-000000000099',
        'appealed'
      );
    `);
    await database.query(migration);
    // A second application proves the reconciliation backfill is idempotent.
    await database.query(migration);
    await database.query(residualClosureMigration);
  });

  afterAll(async () => {
    if (database) await database.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${identifier(DATABASE)}`);
      for (const role of [...ROLES].reverse()) {
        if (!initiallyPresentRoles.has(role)) await admin.query(`DROP ROLE IF EXISTS ${identifier(role)}`);
      }
      await admin.end();
    }
  });

  it('backfills pre-existing appealed disputes exactly once', async () => {
    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims
          WHERE continuity_id = 'ep_ix_backfill') AS claim_status,
        (SELECT frozen_dispute_id FROM public.continuity_claims
          WHERE continuity_id = 'ep_ix_backfill') AS blocker,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = 'ep_ix_backfill' AND event_type = 'continuity.frozen') AS freeze_audits
    `);
    expect(state.rows[0]).toEqual({
      claim_status: 'frozen_pending_dispute',
      blocker: 'appealed-dispute-backfill',
      freeze_audits: 1,
    });
  });

  it('derives dispute_counterparty and commits challenge, claim state, and audit together', async () => {
    const fixture = await seedClaim('1');
    const result = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_success',
      challengerId: fixture.challengerId,
    });

    expect(result.challenge).toMatchObject({
      challenge_id: 'ep_ch_success',
      challenger_type: 'dispute_counterparty',
      challenger_id: fixture.challengerId,
    });
    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_challenges WHERE continuity_id = $1) AS challenges,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.challenged') AS audits
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({ claim_status: 'under_challenge', challenges: 1, audits: 1 });
  });

  it('files an owned continuity claim and its audit in one transaction', async () => {
    const fixture = await seedFiling('8');
    const result = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });

    expect(result.continuity).toMatchObject({
      continuity_id: fixture.claimId,
      status: 'pending',
      transfer_budget: 1,
    });
    expect(result.challenge_deadline).toEqual(expect.any(String));
    expect(result.expires_at).toEqual(expect.any(String));
    const state = await database.query(`
      SELECT
        (SELECT count(*)::int FROM public.continuity_claims WHERE continuity_id = $1) AS claims,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.filed') AS audits,
        (SELECT actor_id FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.filed') AS audit_actor
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({
      claims: 1,
      audits: 1,
      audit_actor: fixture.newEntityId,
    });
    const successorProof = await database.query(
      `SELECT count(*)::int AS count FROM public.audit_events
        WHERE target_id = $1 AND event_type = 'continuity.successor_control_verified'`,
      [fixture.claimId],
    );
    expect(successorProof.rows[0].count).toBe(1);
  });

  it('denies an unlinked filing actor that does not identify the subject principal', async () => {
    const fixture = await seedFiling('20');
    await database.query(`
      INSERT INTO public.entities (id, entity_id, principal_id, organization_id, status)
      VALUES ('60000000-0000-4000-8000-000000000020', 'unlinked-actor-20', NULL, NULL, 'active')
    `);

    const result = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      actorEntityId: 'unlinked-actor-20',
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });

    expect(result).toMatchObject({ status: 403 });
    const state = await database.query(
      'SELECT count(*)::int AS count FROM public.continuity_claims WHERE continuity_id = $1',
      [fixture.claimId],
    );
    expect(state.rows[0].count).toBe(0);
  });

  it('refuses a NULL-principal successor even when the old endpoint is owned', async () => {
    const fixture = await seedFiling('30');
    await database.query(
      'UPDATE public.entities SET principal_id = NULL WHERE entity_id = $1',
      [fixture.newEntityId],
    );

    const result = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });

    expect(result).toMatchObject({ status: 403 });
    expect(result.error).toMatch(/successor is not bound/i);
    const state = await database.query(
      `SELECT
         (SELECT count(*)::int FROM public.continuity_claims WHERE continuity_id = $1) AS claims,
         (SELECT count(*)::int FROM public.audit_events WHERE target_id = $1) AS audits`,
      [fixture.claimId],
    );
    expect(state.rows[0]).toEqual({ claims: 0, audits: 0 });
  });

  it('rejects the legacy entity-id-equals-principal compatibility shortcut', async () => {
    const fixture = await seedFiling('21');
    await database.query(`
      INSERT INTO public.entities (id, entity_id, principal_id, organization_id, status)
      VALUES ('60000000-0000-4000-8000-000000000021', $1, NULL, NULL, 'active')
    `, [fixture.principalId]);

    const result = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      actorEntityId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });

    expect(result).toMatchObject({ status: 403 });
    const count = await database.query(
      'SELECT count(*)::int AS count FROM public.continuity_claims WHERE continuity_id = $1',
      [fixture.claimId],
    );
    expect(count.rows[0].count).toBe(0);
  });

  it('serializes filing and resolution when the authenticated actor is the successor endpoint', async () => {
    const fixture = await seedClaim('26');
    const [filing, resolution] = await Promise.all([
      fileClaim({
        continuityId: 'ep_ix_26_parallel',
        principalId: fixture.principalId,
        actorEntityId: fixture.newEntityId,
        oldEntityId: fixture.oldEntityId,
        newEntityId: fixture.newEntityId,
      }),
      resolveClaim({ continuityId: fixture.claimId }),
    ]);

    expect(filing.continuity).toMatchObject({
      continuity_id: 'ep_ix_26_parallel',
      status: 'pending',
    });
    expect(resolution).toMatchObject({
      continuity_id: fixture.claimId,
      decision: 'approved_full',
    });
    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS resolved_claim,
        (SELECT status FROM public.continuity_claims WHERE continuity_id = 'ep_ix_26_parallel') AS filed_claim,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({
      resolved_claim: 'approved_full',
      filed_claim: 'pending',
      decisions: 1,
    });
  });

  it('keeps recovery claims frozen behind a pre-existing active dispute', async () => {
    const fixture = await seedFiling('9');
    await database.query(`
      INSERT INTO public.disputes (dispute_id, entity_id, filed_by, status)
      VALUES ('dispute-active-9', $1, $2, 'open')
    `, [fixture.oldEntityDbId, fixture.challengerDbId]);

    const result = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
      reason: 'recovery_after_compromise',
    });
    expect(result).toMatchObject({ status: 409, frozen: true, active_disputes: 1 });
    const count = await database.query(
      'SELECT count(*)::int AS count FROM public.continuity_claims WHERE continuity_id = $1',
      [fixture.claimId],
    );
    expect(count.rows[0].count).toBe(0);
  });

  it('never leaves a pending claim beside a concurrently created active dispute', async () => {
    const fixture = await seedFiling('10');
    const [filingResult] = await Promise.all([
      fileClaim({
        continuityId: fixture.claimId,
        principalId: fixture.principalId,
        oldEntityId: fixture.oldEntityId,
        newEntityId: fixture.newEntityId,
      }),
      database.query(`
        INSERT INTO public.disputes (dispute_id, entity_id, filed_by, status)
        VALUES ('dispute-race-10', $1, $2, 'open')
      `, [fixture.oldEntityDbId, fixture.challengerDbId]),
    ]);

    expect(Boolean(filingResult.continuity) || filingResult.status === 409).toBe(true);
    const invariant = await database.query(`
      SELECT
        (SELECT count(*)::int FROM public.disputes
          WHERE entity_id = $1
            AND public.is_active_continuity_dispute_status(status)) AS active_disputes,
        (SELECT count(*)::int FROM public.continuity_claims
          WHERE continuity_id = $2 AND status IN ('pending', 'under_challenge')) AS unsafe_claims,
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $2) AS final_claim_status
    `, [fixture.oldEntityDbId, fixture.claimId]);
    expect(invariant.rows[0].active_disputes).toBe(1);
    expect(invariant.rows[0].unsafe_claims).toBe(0);
    if (filingResult.continuity) {
      expect(invariant.rows[0].final_claim_status).toBe('frozen_pending_dispute');
    }
  });

  it('freezes an existing claim when a dispute transitions into an active state', async () => {
    const fixture = await seedFiling('11');
    const filed = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });
    expect(filed.continuity).toMatchObject({ status: 'pending' });
    await database.query(`
      INSERT INTO public.disputes (dispute_id, entity_id, filed_by, status)
      VALUES ('dispute-transition-11', $1, $2, 'upheld')
    `, [fixture.oldEntityDbId, fixture.challengerDbId]);
    await database.query(
      "UPDATE public.disputes SET status = 'open' WHERE dispute_id = 'dispute-transition-11'",
    );

    const claim = await database.query(
      'SELECT status, frozen_dispute_id FROM public.continuity_claims WHERE continuity_id = $1',
      [fixture.claimId],
    );
    expect(claim.rows[0]).toEqual({
      status: 'frozen_pending_dispute',
      frozen_dispute_id: 'dispute-transition-11',
    });
  });

  it('atomically resolves the claim, records the decision, links the entity, and appends audit', async () => {
    const fixture = await seedClaim('12');

    const result = await resolveClaim({ continuityId: fixture.claimId });
    expect(result).toMatchObject({
      continuity_id: fixture.claimId,
      decision: 'approved_full',
    });

    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions,
        (SELECT principal_linked_at IS NOT NULL FROM public.entities WHERE entity_id = $2) AS linked,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.resolved') AS audits
    `, [fixture.claimId, fixture.newEntityId]);
    expect(state.rows[0]).toEqual({
      claim_status: 'approved_full',
      decisions: 1,
      linked: true,
      audits: 1,
    });
  });

  it('rolls resolution, decision, and entity link back when its audit append fails', async () => {
    const fixture = await seedClaim('13');
    await database.query(`
      CREATE OR REPLACE FUNCTION public.reject_resolution_audit()
      RETURNS TRIGGER LANGUAGE plpgsql AS $rollback$
      BEGIN
        IF NEW.target_id = '${fixture.claimId}' AND NEW.event_type = 'continuity.resolved' THEN
          RAISE EXCEPTION 'forced resolution audit failure';
        END IF;
        RETURN NEW;
      END;
      $rollback$;
      CREATE TRIGGER reject_resolution_audit
      BEFORE INSERT ON public.audit_events
      FOR EACH ROW EXECUTE FUNCTION public.reject_resolution_audit();
    `);

    await expect(resolveClaim({ continuityId: fixture.claimId }))
      .rejects.toThrow(/forced resolution audit failure/);

    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions,
        (SELECT principal_linked_at IS NULL FROM public.entities WHERE entity_id = $2) AS link_rolled_back,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.resolved') AS audits
    `, [fixture.claimId, fixture.newEntityId]);
    expect(state.rows[0]).toEqual({
      claim_status: 'pending',
      decisions: 0,
      link_rolled_back: true,
      audits: 0,
    });
    await database.query('DROP TRIGGER reject_resolution_audit ON public.audit_events');
    await database.query('DROP FUNCTION public.reject_resolution_audit()');
  });

  it('refuses approval of a legacy claim without immutable successor-control proof', async () => {
    const fixture = await seedClaim('31');
    await database.query(
      `DELETE FROM public.audit_events
        WHERE target_id = $1 AND event_type = 'continuity.successor_control_verified'`,
      [fixture.claimId],
    );

    const result = await resolveClaim({ continuityId: fixture.claimId });

    expect(result).toMatchObject({ status: 409 });
    expect(result.error).toMatch(/successor control was not proven/i);
    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({ claim_status: 'pending', decisions: 0 });
  });

  it('serializes concurrent fission approvals and refuses cumulative budget above one', async () => {
    const pair = await seedFissionPair('32', [0.6, 0.6]);

    const results = await Promise.all([
      resolveClaim({ continuityId: pair.firstClaimId, decision: 'approved_partial' }),
      resolveClaim({ continuityId: pair.secondClaimId, decision: 'approved_partial' }),
    ]);

    expect(results.filter((result) => result.decision === 'approved_partial')).toHaveLength(1);
    expect(results.filter((result) => result.status === 409)).toHaveLength(1);
    expect(results.find((result) => result.status === 409)?.error).toMatch(/budget exhausted/i);
    const state = await database.query(`
      SELECT
        count(*)::int AS decisions,
        COALESCE(sum((decision.allocation_rule ->> 'budget')::numeric), 0)::float8 AS allocated,
        (SELECT count(*)::int FROM public.continuity_claims AS claim
          WHERE claim.continuity_id IN ($1, $2) AND claim.status = 'approved_partial') AS approved,
        (SELECT count(*)::int FROM public.continuity_claims AS claim
          WHERE claim.continuity_id IN ($1, $2) AND claim.status = 'pending') AS pending
      FROM public.continuity_decisions AS decision
      WHERE decision.continuity_id IN ($1, $2)
    `, [pair.firstClaimId, pair.secondClaimId]);
    expect(state.rows[0]).toEqual({ decisions: 1, allocated: 0.6, approved: 1, pending: 1 });
  });

  it('admits concurrent fission approvals whose conserved budgets total exactly one', async () => {
    const pair = await seedFissionPair('33', [0.6, 0.4]);

    const results = await Promise.all([
      resolveClaim({ continuityId: pair.firstClaimId, decision: 'approved_partial' }),
      resolveClaim({ continuityId: pair.secondClaimId, decision: 'approved_partial' }),
    ]);

    expect(results.every((result) => result.decision === 'approved_partial')).toBe(true);
    const state = await database.query(`
      SELECT
        count(*)::int AS decisions,
        COALESCE(sum((allocation_rule ->> 'budget')::numeric), 0)::float8 AS allocated
      FROM public.continuity_decisions
      WHERE continuity_id IN ($1, $2)
    `, [pair.firstClaimId, pair.secondClaimId]);
    expect(state.rows[0]).toEqual({ decisions: 2, allocated: 1 });

    await expect(database.query(
      `UPDATE public.continuity_decisions SET allocation_rule = '{}'::jsonb
        WHERE continuity_id = $1`,
      [pair.firstClaimId],
    )).rejects.toThrow(/continuity decisions are append-only/i);
  });

  it('rolls withdrawal state back when its audit append fails, then withdraws atomically', async () => {
    const fixture = await seedFiling('34');
    const filed = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });
    expect(filed.continuity).toMatchObject({ status: 'pending' });

    await database.query(`
      CREATE OR REPLACE FUNCTION public.reject_withdrawal_audit()
      RETURNS TRIGGER LANGUAGE plpgsql AS $rollback$
      BEGIN
        IF NEW.target_id = '${fixture.claimId}' AND NEW.event_type = 'continuity.withdrawn' THEN
          RAISE EXCEPTION 'forced withdrawal audit failure';
        END IF;
        RETURN NEW;
      END;
      $rollback$;
      CREATE TRIGGER reject_withdrawal_audit
      BEFORE INSERT ON public.audit_events
      FOR EACH ROW EXECUTE FUNCTION public.reject_withdrawal_audit();
    `);
    await expect(withdrawClaim({
      continuityId: fixture.claimId,
      actorEntityId: fixture.newEntityId,
    })).rejects.toThrow(/forced withdrawal audit failure/);
    let state = await database.query(`
      SELECT status, withdrawn_at,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.withdrawn') AS withdrawal_audits
      FROM public.continuity_claims WHERE continuity_id = $1
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({ status: 'pending', withdrawn_at: null, withdrawal_audits: 0 });
    await database.query('DROP TRIGGER reject_withdrawal_audit ON public.audit_events');
    await database.query('DROP FUNCTION public.reject_withdrawal_audit()');

    const withdrawal = await withdrawClaim({
      continuityId: fixture.claimId,
      actorEntityId: fixture.newEntityId,
      reason: 'successor abandoned',
    });
    expect(withdrawal).toMatchObject({
      continuity_id: fixture.claimId,
      status: 'withdrawn',
    });
    state = await database.query(`
      SELECT status, withdrawn_by, withdrawn_reason,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.withdrawn') AS withdrawal_audits
      FROM public.continuity_claims WHERE continuity_id = $1
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({
      status: 'withdrawn',
      withdrawn_by: fixture.newEntityId,
      withdrawn_reason: 'successor abandoned',
      withdrawal_audits: 1,
    });
  });

  it('serializes withdrawal against approval so exactly one terminal transition commits', async () => {
    const fixture = await seedFiling('35');
    await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });

    const results = await Promise.all([
      withdrawClaim({ continuityId: fixture.claimId, actorEntityId: fixture.newEntityId }),
      resolveClaim({ continuityId: fixture.claimId }),
    ]);
    expect(results.filter((result) => result.status === 409)).toHaveLength(1);
    expect(results.filter((result) => result.status === 'withdrawn'
      || result.decision === 'approved_full')).toHaveLength(1);

    const state = await database.query(`
      SELECT status,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.withdrawn') AS withdrawals,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.resolved') AS resolutions
      FROM public.continuity_claims WHERE continuity_id = $1
    `, [fixture.claimId]);
    expect(['withdrawn', 'approved_full']).toContain(state.rows[0].status);
    expect(state.rows[0].decisions + state.rows[0].withdrawals).toBe(1);
    expect(state.rows[0].withdrawals + state.rows[0].resolutions).toBe(1);
  });

  it('refuses resolution after the new endpoint is reassigned', async () => {
    const fixture = await seedClaim('24');
    await database.query(`
      UPDATE public.entities
         SET principal_id = (SELECT principal_id FROM public.entities WHERE id = $1)
       WHERE entity_id = $2
    `, [fixture.challengerDbId, fixture.newEntityId]);

    const result = await resolveClaim({ continuityId: fixture.claimId });
    expect(result).toMatchObject({ status: 409 });
    expect(result.error).toMatch(/ownership is not currently proven/i);
    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.resolved') AS audits
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({ claim_status: 'pending', decisions: 0, audits: 0 });
  });

  it('revalidates endpoint ownership after a concurrent reassignment wins the row lock', async () => {
    const fixture = await seedClaim('25');
    const reassignClient = await database.connect();
    try {
      await reassignClient.query('BEGIN');
      await reassignClient.query(
        `UPDATE public.entities
            SET principal_id = (SELECT principal_id FROM public.entities WHERE id = $1)
          WHERE entity_id = $2`,
        [fixture.challengerDbId, fixture.newEntityId],
      );

      const resolution = resolveClaim({ continuityId: fixture.claimId });
      await new Promise((resolve) => setTimeout(resolve, 50));
      await reassignClient.query('COMMIT');

      const result = await resolution;
      expect(result).toMatchObject({ status: 409 });
      expect(result.error).toMatch(/ownership is not currently proven/i);
    } finally {
      await reassignClient.query('ROLLBACK').catch(() => undefined);
      reassignClient.release();
    }

    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.resolved') AS audits
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({ claim_status: 'pending', decisions: 0, audits: 0 });
  });

  it('cannot overwrite a freeze when an active dispute wins the resolution race', async () => {
    const fixture = await seedFiling('14');
    const filed = await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });
    expect(filed.continuity).toMatchObject({ status: 'pending' });

    const disputeClient = await database.connect();
    try {
      await disputeClient.query('BEGIN');
      await disputeClient.query(`
        INSERT INTO public.disputes (dispute_id, entity_id, filed_by, status)
        VALUES ('dispute-resolution-race-14', $1, $2, 'open')
      `, [fixture.oldEntityDbId, fixture.challengerDbId]);

      const resolution = resolveClaim({ continuityId: fixture.claimId });
      await new Promise((resolve) => setTimeout(resolve, 50));
      await disputeClient.query('COMMIT');

      const result = await resolution;
      expect(result).toMatchObject({ status: 409, frozen: true, active_disputes: 1 });
    } finally {
      await disputeClient.query('ROLLBACK').catch(() => undefined);
      disputeClient.release();
    }

    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_decisions WHERE continuity_id = $1) AS decisions,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.resolved') AS resolution_audits
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({
      claim_status: 'frozen_pending_dispute',
      decisions: 0,
      resolution_audits: 0,
    });
  });

  it('keeps a claim frozen until every active dispute has resolved', async () => {
    const fixture = await seedFiling('15');
    await fileClaim({
      continuityId: fixture.claimId,
      principalId: fixture.principalId,
      oldEntityId: fixture.oldEntityId,
      newEntityId: fixture.newEntityId,
    });
    await database.query(`
      INSERT INTO public.disputes (dispute_id, entity_id, filed_by, status) VALUES
        ('a-dispute-15', $1, $2, 'open'),
        ('b-dispute-15', $1, $2, 'appealed')
    `, [fixture.oldEntityDbId, fixture.challengerDbId]);

    const blockedResolution = await resolveClaim({ continuityId: fixture.claimId });
    expect(blockedResolution).toMatchObject({ status: 409, frozen: true, active_disputes: 2 });

    await database.query("UPDATE public.disputes SET status = 'upheld' WHERE dispute_id = 'a-dispute-15'");
    const oneRemaining = await database.query(
      'SELECT status, frozen_dispute_id FROM public.continuity_claims WHERE continuity_id = $1',
      [fixture.claimId],
    );
    expect(oneRemaining.rows[0]).toEqual({
      status: 'frozen_pending_dispute',
      frozen_dispute_id: 'b-dispute-15',
    });

    await database.query("UPDATE public.disputes SET status = 'dismissed' WHERE dispute_id = 'b-dispute-15'");
    const noneRemaining = await database.query(
      'SELECT status, frozen_dispute_id FROM public.continuity_claims WHERE continuity_id = $1',
      [fixture.claimId],
    );
    expect(noneRemaining.rows[0]).toEqual({
      status: 'pending',
      frozen_dispute_id: null,
    });

    const challenged = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_after_unfreeze_15',
      challengerId: fixture.challengerId,
    });
    expect(challenged.challenge).toMatchObject({
      challenge_id: 'ep_ch_after_unfreeze_15',
      status: 'open',
    });
  });

  it('rejects a delegate of the filing principal as a self-challenge', async () => {
    const fixture = await seedClaim('2');
    const result = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_self',
      challengerId: fixture.selfEntityId,
    });

    expect(result).toMatchObject({ status: 403 });
    expect(result.error).toMatch(/own continuity claim/i);
    const state = await database.query(`
      SELECT status,
        (SELECT count(*)::int FROM public.continuity_challenges WHERE continuity_id = $1) AS challenges
      FROM public.continuity_claims WHERE continuity_id = $1
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({ status: 'pending', challenges: 0 });
  });

  it('rejects the direct filing identity even when its entity row is unlinked', async () => {
    const fixture = await seedClaim('22');
    await database.query(`
      INSERT INTO public.entities (id, entity_id, principal_id, organization_id, status)
      VALUES ('60000000-0000-4000-8000-000000000022', $1, NULL, NULL, 'active')
    `, [fixture.principalId]);

    const result = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_direct_self',
      challengerId: fixture.principalId,
    });

    expect(result).toMatchObject({ status: 403 });
    expect(result.error).toMatch(/own continuity claim/i);
    const count = await database.query(
      'SELECT count(*)::int AS count FROM public.continuity_challenges WHERE continuity_id = $1',
      [fixture.claimId],
    );
    expect(count.rows[0].count).toBe(0);
  });

  it('rolls every earlier write back if audit append fails', async () => {
    const fixture = await seedClaim('3');
    await database.query(`
      CREATE OR REPLACE FUNCTION public.reject_continuity_audit()
      RETURNS TRIGGER LANGUAGE plpgsql AS $rollback$
      BEGIN
        IF NEW.target_id = '${fixture.claimId}' THEN
          RAISE EXCEPTION 'forced audit failure';
        END IF;
        RETURN NEW;
      END;
      $rollback$;
      CREATE TRIGGER reject_continuity_audit
      BEFORE INSERT ON public.audit_events
      FOR EACH ROW EXECUTE FUNCTION public.reject_continuity_audit();
    `);

    await expect(challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_rollback',
      challengerId: fixture.challengerId,
    })).rejects.toThrow(/forced audit failure/);

    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_challenges WHERE continuity_id = $1) AS challenges,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.challenged') AS audits
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({ claim_status: 'pending', challenges: 0, audits: 0 });
    await database.query('DROP TRIGGER reject_continuity_audit ON public.audit_events');
    await database.query('DROP FUNCTION public.reject_continuity_audit()');
  });

  it('serializes concurrent challengers while preserving the multi-challenger state', async () => {
    const fixture = await seedClaim('4');
    const results = await Promise.all([
      challenge({ continuityId: fixture.claimId, challengeId: 'ep_ch_race_a', challengerId: fixture.challengerId }),
      challenge({ continuityId: fixture.claimId, challengeId: 'ep_ch_race_b', challengerId: fixture.challengerId }),
    ]);

    expect(results.filter((result) => result.challenge)).toHaveLength(2);
    const counts = await database.query(`
      SELECT
        (SELECT count(*)::int FROM public.continuity_challenges WHERE continuity_id = $1) AS challenges,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.challenged') AS audits
    `, [fixture.claimId]);
    expect(counts.rows[0]).toEqual({ challenges: 2, audits: 2 });
  });

  it('admits five concurrent open challenges and refuses the sixth', async () => {
    const fixture = await seedClaim('23');
    const results = await Promise.all(Array.from({ length: 6 }, (_, index) => challenge({
      continuityId: fixture.claimId,
      challengeId: `ep_ch_cap_${index + 1}`,
      challengerId: fixture.challengerId,
    })));

    expect(results.filter((result) => result.challenge)).toHaveLength(5);
    expect(results.filter((result) => result.status === 429)).toHaveLength(1);
    const state = await database.query(`
      SELECT
        (SELECT status FROM public.continuity_claims WHERE continuity_id = $1) AS claim_status,
        (SELECT count(*)::int FROM public.continuity_challenges
          WHERE continuity_id = $1 AND status IN ('open', 'reviewed')) AS open_challenges,
        (SELECT count(*)::int FROM public.audit_events
          WHERE target_id = $1 AND event_type = 'continuity.challenged') AS audits
    `, [fixture.claimId]);
    expect(state.rows[0]).toEqual({
      claim_status: 'under_challenge',
      open_challenges: 5,
      audits: 5,
    });
  });

  it('requires both authenticated admin permission and endpoint organization match', async () => {
    const fixture = await seedClaim('5');
    await database.query('DELETE FROM public.disputes WHERE filed_by = $1', [fixture.challengerDbId]);
    await database.query(
      'UPDATE public.entities SET organization_id = $1 WHERE id = $2',
      ['org-owner', fixture.challengerDbId],
    );

    const withoutPermission = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_admin_denied',
      challengerId: fixture.challengerId,
    });
    expect(withoutPermission).toMatchObject({ status: 403 });

    const authorized = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_admin',
      challengerId: fixture.challengerId,
      enterpriseAdmin: true,
    });
    expect(authorized.challenge).toMatchObject({ challenger_type: 'enterprise_admin' });
  });

  it('derives operator only from the server-managed entity flag', async () => {
    const fixture = await seedClaim('6');
    await database.query('DELETE FROM public.disputes WHERE filed_by = $1', [fixture.challengerDbId]);
    await database.query('UPDATE public.entities SET is_operator = true WHERE id = $1', [fixture.challengerDbId]);

    const result = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_operator',
      challengerId: fixture.challengerId,
    });
    expect(result.challenge).toMatchObject({ challenger_type: 'operator' });
    const audit = await database.query(
      `SELECT actor_type, after_state FROM public.audit_events
        WHERE target_id = $1 AND event_type = 'continuity.challenged'`,
      [fixture.claimId],
    );
    expect(audit.rows[0]).toMatchObject({
      actor_type: 'operator',
      after_state: { challenger_role: 'operator' },
    });
  });

  it('derives bound_host only from a live verified host binding', async () => {
    const fixture = await seedClaim('7');
    await database.query('DELETE FROM public.disputes WHERE filed_by = $1', [fixture.challengerDbId]);
    await database.query(`
      INSERT INTO public.identity_bindings (
        principal_id, binding_type, binding_target, status, expires_at
      )
      SELECT principal_id, 'domain_control', 'old-7', 'verified', now() + interval '1 hour'
      FROM public.entities WHERE id = $1
    `, [fixture.challengerDbId]);

    const result = await challenge({
      continuityId: fixture.claimId,
      challengeId: 'ep_ch_bound_host',
      challengerId: fixture.challengerId,
    });
    expect(result.challenge).toMatchObject({ challenger_type: 'bound_host' });
  });

  it('does not expose any SECURITY DEFINER continuity mutation to public API roles', async () => {
    const overloads = await database.query(`
      SELECT
        to_regprocedure(
          'public.file_continuity_claim_atomic(text,text,text,text,text,text,jsonb,numeric)'
        ) AS weak_filing,
        to_regprocedure(
          'public.file_continuity_claim_atomic(text,text,text,text,text,text,text,jsonb,numeric)'
        ) IS NOT NULL AS actor_bound_filing,
        has_function_privilege(
          'service_role',
          'public.file_continuity_claim_atomic_pre_successor_proof(text,text,text,text,text,text,text,jsonb,numeric)',
          'EXECUTE'
        ) AS service_can_call_weak_filing_core,
        has_function_privilege(
          'service_role',
          'public.resolve_continuity_atomic_pre_budget_conservation(text,text,jsonb,text)',
          'EXECUTE'
        ) AS service_can_call_unconserved_resolution_core
    `);
    expect(overloads.rows[0]).toEqual({
      weak_filing: null,
      actor_bound_filing: true,
      service_can_call_weak_filing_core: false,
      service_can_call_unconserved_resolution_core: false,
    });

    for (const role of ['anon', 'authenticated'] as const) {
      const forbiddenCalls = [
        `SELECT public.file_continuity_claim_atomic(
          'missing', 'principal', 'actor', 'old', 'new', 'key_rotation', 'linear', '[]'::jsonb, 1.0
        )`,
        `SELECT public.challenge_continuity_atomic(
          'missing', 'ep_ch_forbidden', 'entity', 'reason', '{}'::jsonb, false
        )`,
        `SELECT public.resolve_continuity_atomic(
          'missing', 'rejected', '[]'::jsonb, 'operator'
        )`,
        `SELECT public.withdraw_continuity_claim_atomic(
          'missing', 'entity', NULL
        )`,
        `SELECT public.reconcile_continuity_dispute_atomic(
          'missing', NULL
        )`,
      ];
      for (const statement of forbiddenCalls) {
        await expect(asRole(role, (client) => client.query(statement)))
          .rejects.toThrow(/permission denied/i);
      }
    }
  });
});
