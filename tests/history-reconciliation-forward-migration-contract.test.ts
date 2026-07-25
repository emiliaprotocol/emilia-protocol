// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260725180000_reconcile_unjournaled_security_invariants.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('unjournaled security-invariant forward reconciliation', () => {
  it('makes guarded inquiry storage reproducible without public table access', () => {
    for (const table of ['partner_inquiries', 'investor_inquiries']) {
      expect(migration).toContain(`CREATE TABLE IF NOT EXISTS public.${table}`);
      expect(migration).toContain(`REVOKE ALL ON TABLE public.${table}`);
    }
    expect(migration).toContain('DROP POLICY IF EXISTS anon_insert');
  });

  it('closes the legacy fraud-review table behind RLS and server-only ACLs', () => {
    expect(migration).toContain('ALTER TABLE public.fraud_flags ENABLE ROW LEVEL SECURITY');
    expect(migration).toMatch(
      /REVOKE ALL ON TABLE public\.fraud_flags[\s\S]+FROM PUBLIC, anon, authenticated/,
    );
    expect(migration).toContain('CREATE POLICY service_role_bypass ON public.fraud_flags');
  });

  it('restores both append-only chain fork guards', () => {
    expect(migration).toContain('idx_security_events_single_child_per_parent');
    expect(migration).toContain('idx_receipts_single_child_per_parent');
    expect(migration).toContain("COALESCE(previous_hash, 'root')");
  });

  it('makes scoped authority and its freshness epoch reproducible', () => {
    for (const column of [
      'action_scopes',
      'max_amount_usd',
      'currency',
      'delegation_parent',
      'policy_hash',
    ]) {
      expect(migration).toContain(`ADD COLUMN IF NOT EXISTS ${column}`);
    }
    expect(migration).toContain('CREATE TABLE IF NOT EXISTS public.authority_registry_epoch');
    expect(migration).toContain('CREATE OR REPLACE FUNCTION public.bump_authority_registry_epoch()');
    expect(migration).toContain('SET search_path =');
    expect(migration).toContain('REVOKE EXECUTE ON FUNCTION public.bump_authority_registry_epoch()');
  });

  it('restores kid-bound atomic consumption and revocation without mutable search paths', () => {
    expect(migration).toContain("ADD COLUMN IF NOT EXISTS kid TEXT NOT NULL DEFAULT 'ep-signing-key-1'");
    expect(migration).toContain('CREATE OR REPLACE FUNCTION public.consume_gate_ref_atomic(');
    expect(migration).toContain('CREATE OR REPLACE FUNCTION public.revoke_commit_key_atomic(');
    expect(migration.match(/SET search_path = ''/g)).toHaveLength(3);
    expect(migration).toContain('pg_catalog.pg_advisory_xact_lock');
    expect(migration).toContain('FROM PUBLIC, anon, authenticated');
  });

  it('does not convert credential possession into permission', () => {
    expect(migration).not.toMatch(/INSERT INTO public\.authorities/);
    expect(migration).not.toContain('backfilled_from');
  });

  it('invalidates both registry epochs when an authority changes organization', () => {
    expect(migration).toContain("IF TG_OP <> 'INSERT'");
    expect(migration).toContain("IF TG_OP <> 'DELETE'");
    expect(migration).toContain('v_new_org IS DISTINCT FROM v_old_org');
  });

  it('closes table ACLs independently of RLS', () => {
    expect(migration).toMatch(
      /REVOKE ALL ON TABLE public\.authority_registry_epoch[\s\S]+FROM PUBLIC, anon, authenticated/,
    );
    expect(migration).toMatch(
      /REVOKE ALL ON TABLE public\.authorities FROM PUBLIC, anon, authenticated/,
    );
    expect(migration).toContain(
      'REVOKE ALL ON TABLE public.ep_capability_state',
    );
    expect(migration).toContain(
      'REVOKE ALL ON TABLE public.ep_capability_operations',
    );
    expect(migration).toMatch(
      /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public\.authorities[\s\S]+FROM service_role/,
    );
    expect(migration).not.toMatch(
      /GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public\.authorities/,
    );
  });
});
