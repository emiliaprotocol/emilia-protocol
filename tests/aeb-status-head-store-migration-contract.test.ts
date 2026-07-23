// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260723143000_aeb_status_head_store.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('AEB accepted status-head store migration', () => {
  it('scopes each durable head by tenant, relying party, and the complete target', () => {
    expect(migration).toContain('CREATE TABLE public.ep_aeb_status_heads');
    expect(migration).toMatch(
      /PRIMARY KEY \(\s*tenant_id,\s*relying_party_id,\s*target_type,\s*target_id,\s*target_digest,\s*target_usage\s*\)/,
    );
    expect(migration).toMatch(
      /status_state\s+TEXT NOT NULL CHECK \(status_state IN \('not_revoked', 'revoked'\)\)/,
    );
    expect(migration).toMatch(/predecessor_status_json\s+TEXT NULL/);
  });

  it('serializes absent and existing heads before comparison and advancement', () => {
    expect(migration).toContain('pg_catalog.pg_advisory_xact_lock');
    expect(migration).toContain('FOR UPDATE');
    expect(migration).toContain('p_expected_status_digest');
    expect(migration).toContain('current_head.status_digest IS DISTINCT FROM p_expected_status_digest');
    expect(migration).toContain('p_sequence <> current_head.sequence + 1');
    expect(migration).toContain('p_previous_status_digest IS DISTINCT FROM current_head.status_digest');
    expect(migration).toContain("current_head.status_state = 'revoked'");
  });

  it('uses the existing tenant-principal boundary and denies direct table access', () => {
    expect(migration).toContain(
      'PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);',
    );
    expect(migration).toContain(
      'ALTER TABLE public.ep_aeb_status_heads FORCE ROW LEVEL SECURITY;',
    );
    expect(migration).toMatch(
      /REVOKE ALL ON public\.ep_aeb_status_heads[\s\S]+FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION ep_aeb_private\.get_status_head[\s\S]+TO ep_aeb_executor;/,
    );
    expect(migration).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[\s\S]+ep_aeb_status_heads[\s\S]+TO (?:service_role|authenticated|anon)/,
    );
  });

  it('is forward-only and never rewrites the prior consumption migration', () => {
    expect(migration).not.toMatch(/\bDROP TABLE\b/i);
    expect(migration).not.toContain('20260722200000_aeb_consumption_store');
  });
});
