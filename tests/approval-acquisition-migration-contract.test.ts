// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationPath = path.resolve(
  process.cwd(),
  'supabase/migrations/20260721171500_ep_approval_acquisition.sql',
);

describe('EP-APPROVAL-v1 durable acquisition schema', () => {
  const sql = fs.readFileSync(migrationPath, 'utf8');

  it('uses a service-only, force-RLS table without plaintext poll tokens', () => {
    expect(sql).toContain('CREATE TABLE public.approval_acquisition_requests');
    expect(sql).toContain('tenant_id uuid NOT NULL');
    expect(sql).toContain('REFERENCES public.tenants(tenant_id)');
    expect(sql).toContain('ENABLE ROW LEVEL SECURITY');
    expect(sql).toContain('FORCE ROW LEVEL SECURITY');
    expect(sql).toMatch(/REVOKE ALL[\s\S]+FROM PUBLIC, anon, authenticated, service_role/);
    expect(sql).toContain('GRANT SELECT ON TABLE public.approval_acquisition_requests TO service_role');
    expect(sql).toContain('poll_token_hash text NOT NULL');
    expect(sql).toContain('poll_token_ciphertext text NOT NULL');
    expect(sql).not.toMatch(/\bpoll_token\s+text\b/);
  });

  it('makes idempotency and request/token identities authoritative in PostgreSQL', () => {
    expect(sql).toContain('UNIQUE (tenant_id, environment, requester_key_id, idempotency_digest)');
    expect(sql).toContain('UNIQUE (poll_token_hash)');
    expect(sql).toContain('reserve_approval_acquisition_request');
    expect(sql).toContain('ON CONFLICT (tenant_id, environment, requester_key_id, idempotency_digest) DO NOTHING');
    expect(sql).toContain("'conflict'");
    expect(sql).toContain("'existing'");
    expect(sql).toContain("'created'");
  });

  it('allows mutations only through service-role-only SECURITY DEFINER RPCs', () => {
    for (const fn of [
      'reserve_approval_acquisition_request',
      'complete_approval_acquisition_request',
    ]) {
      expect(sql).toContain(`FUNCTION public.${fn}`);
    }
    expect(sql.match(/SECURITY DEFINER/g)?.length).toBe(2);
    expect(sql.match(/SET search_path = ''/g)?.length).toBe(2);
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
});
