// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationPath = path.resolve(
  process.cwd(),
  'supabase/migrations/20260721171500_ep_approval_acquisition.sql',
);
const hardeningMigrationPath = path.resolve(
  process.cwd(),
  'supabase/migrations/20260722023000_approval_acquisition_hostile_closure.sql',
);

describe('EP-APPROVAL-v1 durable acquisition schema', () => {
  const committedSql = fs.readFileSync(migrationPath, 'utf8');
  const hardeningSql = fs.readFileSync(hardeningMigrationPath, 'utf8');
  const sql = `${committedSql}\n${hardeningSql}`;

  it('pins the already-committed migration byte-for-byte and carries changes only forward', () => {
    expect(crypto.createHash('sha256').update(committedSql).digest('hex'))
      .toBe('79055930b69d7a446d2ab18186b0f708a93af6067da76fd49c637e63e309f478');
    expect(committedSql).not.toContain('poll_token_key_id');
    expect(committedSql).not.toContain('reconcile_approval_acquisition_request');
    expect(hardeningSql).toContain('ALTER TABLE public.approval_acquisition_requests');
  });

  it('uses a service-only, force-RLS table without plaintext poll tokens', () => {
    expect(sql).toContain('CREATE TABLE public.approval_acquisition_requests');
    expect(sql).toContain('tenant_id uuid NOT NULL');
    expect(sql).toContain('REFERENCES public.tenants(tenant_id)');
    expect(sql).toContain('ENABLE ROW LEVEL SECURITY');
    expect(sql).toContain('FORCE ROW LEVEL SECURITY');
    expect(sql).toMatch(/REVOKE ALL[\s\S]+FROM PUBLIC, anon, authenticated, service_role/);
    expect(sql).toContain('GRANT SELECT ON TABLE public.approval_acquisition_requests TO service_role');
    expect(sql).toContain('poll_token_hash text NOT NULL');
    expect(hardeningSql).toContain('ADD COLUMN poll_token_key_id text');
    expect(hardeningSql).toContain('ADD COLUMN producer_key_id text');
    expect(sql).toContain('poll_token_ciphertext text NOT NULL');
    expect(hardeningSql).toContain("poll_token_ciphertext ~ '^epat1[.]");
    expect(sql).not.toMatch(/\bpoll_token\s+text\b/);
  });

  it('makes idempotency and request/token identities authoritative in PostgreSQL', () => {
    expect(hardeningSql).toContain('(tenant_id, environment, idempotency_digest)');
    expect(hardeningSql).toContain("WHERE status <> 'refused'");
    expect(hardeningSql).toContain("constraint_row.contype = 'u'");
    expect(sql).toContain('UNIQUE (poll_token_hash)');
    expect(sql).toContain('reserve_approval_acquisition_request');
    expect(hardeningSql).toContain('ON CONFLICT (tenant_id, environment, idempotency_digest)');
    expect(sql).toContain("'conflict'");
    expect(sql).toContain("'existing'");
    expect(sql).toContain("'created'");
  });

  it('allows mutations only through service-role-only SECURITY DEFINER RPCs', () => {
    for (const fn of [
      'reserve_approval_acquisition_request',
      'enter_approval_acquisition_boundary',
      'complete_approval_acquisition_request',
      'reconcile_approval_acquisition_request',
      'refuse_approval_acquisition_request',
      'recover_approval_acquisition_poll_token',
    ]) {
      expect(sql).toContain(`FUNCTION public.${fn}`);
    }
    expect(sql).toMatch(/REVOKE ALL ON FUNCTION public\.reserve_approval_acquisition_request[\s\S]+FROM PUBLIC, anon, authenticated/);
    expect(sql).toMatch(/GRANT EXECUTE ON FUNCTION public\.reserve_approval_acquisition_request[\s\S]+TO service_role/);
  });

  it('recovers only from one exact append-only receipt and signoff pair', () => {
    expect(sql).toContain('guard_approval_acquisition_receipt_once');
    expect(sql).toContain("event.after_state ->> 'acquisition_request_id' = v_row.request_id");
    expect(sql).toContain("event.after_state ->> 'acquisition_action_hash' = v_row.action_hash");
    expect(sql).toContain("event.after_state ->> 'acquisition_action_caid' = v_row.action_caid");
    expect(sql).toContain("event.after_state ->> 'acquisition_challenge_hash' = v_row.challenge_hash");
    expect(sql).toContain("event.after_state ->> 'approver_id' = v_row.approver_id");
    expect(sql).toContain('v_created_count <> 1 OR v_request_count <> 1');
    expect(sql).not.toContain('fail_approval_acquisition_request');
  });

  it('freezes an entered upstream boundary as indeterminate and reconciles without replay', () => {
    expect(hardeningSql).toContain("status IN ('initializing', 'invoking', 'indeterminate', 'pending', 'refused')");
    expect(hardeningSql).toContain('p_producer_key_id text');
    expect(hardeningSql).toContain("producer_key_id = p_producer_key_id");
    expect(hardeningSql).toContain("WHERE request_id = p_request_id AND status = 'initializing'");
    expect(hardeningSql).toContain("SET status = 'invoking'");
    expect(hardeningSql).toContain("SET status = 'refused'");
    expect(hardeningSql).toContain('v_created_count = 0');
    expect(sql).toContain("CHECK (reconciliation_state IN ('not_required', 'required', 'reconciled'))");
    expect(sql).toContain("SET status = 'indeterminate'");
    expect(sql).toContain("reconciliation_state = 'required'");
    expect(sql).toContain("SET status = 'pending'");
    expect(sql).toContain("reconciliation_state = 'reconciled'");
    expect(sql).toContain("event.after_state ->> 'acquisition_request_digest' = v_row.request_digest");
    expect(sql).toContain("event.after_state ->> 'acquisition_action_caid' = v_row.action_caid");
    expect(sql).toContain("jsonb_build_object('outcome', 'indeterminate'");
    expect(sql).toContain("jsonb_build_object('outcome', 'reconciled'");
  });

  it('accepts the real Guard producer bare action hash while keeping acquisition hashes prefixed', () => {
    expect(hardeningSql).toContain("receipt_action_hash ~ '^[a-f0-9]{64}$'");
    expect(hardeningSql).toContain("event.after_state ->> 'action_hash' ~ '^[a-f0-9]{64}$'");
    expect(hardeningSql).toContain("event.actor_id = 'ep:cloud-key:' || v_row.producer_key_id");
    expect(sql).toContain("action_hash ~ '^sha256:[a-f0-9]{64}$'");
  });
});
