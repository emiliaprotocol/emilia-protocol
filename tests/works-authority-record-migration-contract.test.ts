// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationPath = path.join(
  process.cwd(), 'supabase/migrations/20260814070000_works_authority_records.sql',
);

describe('Authority Record PostgreSQL contract', () => {
  it('defines immutable versions, private credentials, lifecycle events, demand, and billing state', () => {
    const sql = fs.readFileSync(migrationPath, 'utf8');
    for (const table of [
      'works_authority_records',
      'works_authority_record_versions',
      'works_authority_invitations',
      'works_authority_events',
      'works_authority_demand_requests',
      'works_authority_entitlements',
      'works_authority_stripe_events',
    ]) expect(sql).toContain(`public.${table}`);
    expect(sql).toContain('owner_token_digest');
    expect(sql).toContain('invitation_token_digest');
    expect(sql).not.toContain('owner_token TEXT');
    expect(sql).not.toContain('invitation_token TEXT');
    expect(sql).toMatch(/ENABLE ROW LEVEL SECURITY/g);
    expect(sql).toMatch(/FORCE ROW LEVEL SECURITY/g);
  });

  it('keeps lifecycle transitions atomic and grants no browser role direct table access', () => {
    const sql = fs.readFileSync(migrationPath, 'utf8');
    for (const rpc of [
      'create_works_authority_record_draft',
      'inspect_works_authority_record_invitation',
      'claim_works_authority_record',
      'read_works_authority_record_owner',
      'append_works_authority_record_version',
      'approve_works_authority_record_version',
      'withdraw_works_authority_record',
      'read_works_authority_record_public',
      'list_works_authority_records_public',
      'create_works_authority_demand_request',
      'verify_works_authority_demand_request',
      'read_works_authority_demand_counts',
      'apply_works_authority_stripe_event',
      'read_works_authority_entitlement',
      'reconcile_works_authority_entitlement',
    ]) expect(sql).toContain(`public.${rpc}`);
    expect(sql).toMatch(/REVOKE ALL ON TABLE[\s\S]+FROM PUBLIC, anon, authenticated/);
    expect(sql).toContain("status = 'PUBLISHED'");
    expect(sql).toContain('current_digest IS DISTINCT FROM p_record_digest');
    expect(sql).toContain('FOR UPDATE');
  });

  it('makes versions and lifecycle events append-only', () => {
    const sql = fs.readFileSync(migrationPath, 'utf8');
    expect(sql).toContain('works_authority_immutable_row');
    expect(sql).toContain('works_authority_record_versions_immutable');
    expect(sql).toContain('works_authority_events_immutable');
    expect(sql).toContain("RAISE EXCEPTION 'works authority history is immutable'");
  });

  it('counts only verified independent request events and reconciles billing without fake Stripe events', () => {
    const sql = fs.readFileSync(migrationPath, 'utf8');
    expect(sql).toContain("status = 'VERIFIED' AND test_event = FALSE");
    expect(sql).toContain("organization_domain <> 'emiliaprotocol.ai'");
    expect(sql).toContain('verification_token_digest');
    expect(sql).toContain("jsonb_build_object('status', 'ALREADY_VERIFIED')");
    expect(sql).not.toContain('requester_email');
    expect(sql).toContain('ON CONFLICT (stripe_event_id) DO NOTHING');
    expect(sql).toContain('v_entitlement.stripe_subscription_id IS DISTINCT FROM p_stripe_subscription_id');
    expect(sql).toContain("p_event_type IN ('customer.subscription.updated', 'customer.subscription.deleted')");
    const demandCounts = sql.slice(
      sql.indexOf('CREATE FUNCTION public.read_works_authority_demand_counts'),
      sql.indexOf('CREATE FUNCTION public.apply_works_authority_stripe_event'),
    );
    expect(demandCounts).toContain("(version.projection -> 'provenance' ->> 'expires_at')::TIMESTAMPTZ");
    const reconcile = sql.slice(sql.indexOf('CREATE FUNCTION public.reconcile_works_authority_entitlement'));
    expect(reconcile).not.toContain('INSERT INTO public.works_authority_stripe_events');
  });
});
