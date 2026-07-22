// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const databaseUrl = process.env.APPROVAL_ACQUISITION_TEST_DATABASE_URL;
const suite = databaseUrl ? describe.sequential : describe.skip;
const original = readFileSync(new URL(
  '../supabase/migrations/20260721171500_ep_approval_acquisition.sql', import.meta.url,
), 'utf8');
const closure = readFileSync(new URL(
  '../supabase/migrations/20260722023000_approval_acquisition_hostile_closure.sql', import.meta.url,
), 'utf8');

const tenant = '00000000-0000-4000-8000-000000000001';
const keyA = '00000000-0000-4000-8000-00000000000a';
const keyB = '00000000-0000-4000-8000-00000000000b';
const caid = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const digest = (character: string) => `sha256:${character.repeat(64)}`;
let pool: pg.Pool;

async function reserve(input: {
  requestId: string; requesterKeyId: string; idempotency: string;
  requestDigest: string; amount: number; tokenHash: string;
}) {
  const result = await pool.query<{ result: any }>(`
    SELECT public.reserve_approval_acquisition_request(
      $1, $2::uuid, 'production', $3, $4, $5, $6, $7, $8,
      jsonb_build_object('amount', $9::int), 'approver@example.test',
      $10, 'key-v2', 'epat1.key-v2.${'B'.repeat(32)}',
      '${'i'.repeat(16)}', '${'t'.repeat(20)}',
      statement_timestamp() + interval '15 minutes'
    ) AS result
  `, [
    input.requestId, tenant, input.requesterKeyId, input.idempotency,
    input.requestDigest, digest('4'), digest('3'), caid, input.amount, input.tokenHash,
  ]);
  return result.rows[0].result;
}

async function appendEvidence(input: {
  requestId: string; requestDigest: string; producerKeyId: string;
  receiptId: string; signoffId: string; receiptActionHash: string;
}) {
  await pool.query(`
    INSERT INTO public.audit_events
      (id, event_type, actor_id, target_type, target_id, after_state)
    VALUES
      (gen_random_uuid(), 'guard.trust_receipt.created', $1, 'trust_receipt', $2,
       jsonb_build_object(
         'organization_id', $3::text, 'action_type', 'large_payment_release',
         'action_hash', $4::text, 'acquisition_request_id', $5::text,
         'acquisition_request_digest', $6::text, 'acquisition_action_hash', $7::text,
         'acquisition_action_caid', $8::text, 'acquisition_challenge_hash', $9::text,
         'acquisition_tenant_id', $3::text, 'acquisition_environment', 'production',
         'canonical_action', jsonb_build_object('acquisition_scope', jsonb_build_object(
           'tenant_id', $3::text, 'environment', 'production', 'request_id', $5::text,
           'request_digest', $6::text)))),
      (gen_random_uuid(), 'guard.signoff.requested', $1, 'trust_receipt', $2,
       jsonb_build_object(
         'signoff_id', $10::text, 'approver_id', 'approver@example.test',
         'action_hash', $4::text, 'acquisition_request_id', $5::text,
         'acquisition_request_digest', $6::text, 'acquisition_tenant_id', $3::text,
         'acquisition_environment', 'production'))
  `, [
    `ep:cloud-key:${input.producerKeyId}`, input.receiptId, tenant,
    input.receiptActionHash, input.requestId, input.requestDigest,
    digest('3'), caid, digest('4'), input.signoffId,
  ]);
}

suite('EP-APPROVAL-v1 forward migration on PostgreSQL', () => {
  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: databaseUrl, max: 4 });
    const database = await pool.query<{ current_database: string }>('SELECT current_database()');
    expect(database.rows[0].current_database).toMatch(/^emilia_approval_test_/);
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS pgcrypto;
      DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
      DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
      DO $$ BEGIN CREATE ROLE service_role NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
      CREATE TABLE public.tenants (tenant_id uuid PRIMARY KEY);
      CREATE TABLE public.tenant_environments (
        tenant_id uuid NOT NULL REFERENCES public.tenants(tenant_id), name text NOT NULL,
        PRIMARY KEY (tenant_id, name));
      CREATE TABLE public.tenant_api_keys (
        key_id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES public.tenants(tenant_id),
        environment text NOT NULL, created_at timestamptz NOT NULL,
        expires_at timestamptz, revoked_at timestamptz);
      CREATE TABLE public.audit_events (
        id uuid PRIMARY KEY, event_type text NOT NULL, actor_id text NOT NULL,
        actor_type text NOT NULL DEFAULT 'principal', target_type text NOT NULL,
        target_id text NOT NULL, action text NOT NULL DEFAULT 'create', before_state jsonb,
        after_state jsonb, metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
        created_at timestamptz NOT NULL DEFAULT statement_timestamp());
      INSERT INTO public.tenants VALUES ('${tenant}');
      INSERT INTO public.tenant_environments VALUES ('${tenant}', 'production');
      INSERT INTO public.tenant_api_keys VALUES
        ('${keyA}', '${tenant}', 'production', now()-interval '1 day', NULL, now()-interval '1 hour'),
        ('${keyB}', '${tenant}', 'production', now()-interval '1 hour', NULL, NULL);
    `);
    await pool.query(original);
    await pool.query(closure);
  });

  afterAll(async () => pool?.end());

  it('separates immutable requester provenance from the rotated producer and completes exact evidence', async () => {
    const requestId = `apr_${'a'.repeat(32)}`;
    const requestDigest = digest('2');
    expect((await reserve({
      requestId, requesterKeyId: keyA, idempotency: digest('1'), requestDigest,
      amount: 200, tokenHash: digest('5'),
    })).outcome).toBe('created');
    const entered = await pool.query<{ ok: boolean }>(
      'SELECT public.enter_approval_acquisition_boundary($1,$2,$3) AS ok',
      [requestId, requestDigest, keyB],
    );
    expect(entered.rows[0].ok).toBe(true);
    await appendEvidence({
      requestId, requestDigest, producerKeyId: keyB,
      receiptId: `tr_${'c'.repeat(32)}`, signoffId: `sig_${'d'.repeat(32)}`,
      receiptActionHash: 'e'.repeat(64),
    });
    const completed = await pool.query<{ ok: boolean }>(`
      SELECT public.complete_approval_acquisition_request(
        $1,$2,$3,$4,$5,statement_timestamp()+interval '10 minutes') AS ok
    `, [requestId, requestDigest, `tr_${'c'.repeat(32)}`, `sig_${'d'.repeat(32)}`, 'e'.repeat(64)]);
    expect(completed.rows[0].ok).toBe(true);
    const row = await pool.query(`SELECT requester_key_id, producer_key_id, status
      FROM public.approval_acquisition_requests WHERE request_id=$1`, [requestId]);
    expect(row.rows[0]).toEqual({ requester_key_id: keyA, producer_key_id: keyB, status: 'pending' });
  });

  it('records deterministic refusal, permits corrected retry, and preserves indeterminate recovery', async () => {
    const refusedId = `apr_${'b'.repeat(32)}`;
    const refusedDigest = digest('7');
    await reserve({ requestId: refusedId, requesterKeyId: keyB, idempotency: digest('6'),
      requestDigest: refusedDigest, amount: 201, tokenHash: digest('8') });
    await pool.query('SELECT public.enter_approval_acquisition_boundary($1,$2,$3)',
      [refusedId, refusedDigest, keyB]);
    const refused = await pool.query<{ ok: boolean }>(
      'SELECT public.refuse_approval_acquisition_request($1,$2,$3) AS ok',
      [refusedId, refusedDigest, 'upstream_validation_refused'],
    );
    expect(refused.rows[0].ok).toBe(true);

    const retryId = `apr_${'f'.repeat(32)}`;
    const retryDigest = digest('9');
    expect((await reserve({ requestId: retryId, requesterKeyId: keyB, idempotency: digest('6'),
      requestDigest: retryDigest, amount: 202, tokenHash: digest('a') })).outcome).toBe('created');
    await pool.query('SELECT public.enter_approval_acquisition_boundary($1,$2,$3)',
      [retryId, retryDigest, keyB]);
    const reconciled = await pool.query<{ result: any }>(
      'SELECT public.reconcile_approval_acquisition_request($1,$2) AS result',
      [retryId, retryDigest],
    );
    expect(reconciled.rows[0].result.outcome).toBe('indeterminate');
    const recovered = await pool.query<{ ok: boolean }>(`
      SELECT public.recover_approval_acquisition_poll_token(
        $1,$2,$3::uuid,'production',$4,$5,$6,'key-v2',$7,'key-v3',$8,$9,$10) AS ok
    `, [retryId, retryDigest, tenant, keyB, digest('6'), digest('a'), digest('b'),
      `epat1.key-v3.${'E'.repeat(32)}`, 'l'.repeat(16), 'w'.repeat(20)]);
    expect(recovered.rows[0].ok).toBe(true);
  });
});
