// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260722230000_fortress_db_security_invariants.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('consequence-control forward-only database fortress', () => {
  const tables = [
    'public.ep_aeb_consumption_operations',
    'public.ep_aeb_consumption_replay_fences',
    'public.ep_remedy_case_sets',
    'public.ep_remedy_case_set_events',
  ];

  for (const table of tables) {
    it(`${table} stays forced-RLS and has no generic runtime table authority`, () => {
      expect(migration).toContain(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`);
      expect(migration).toMatch(new RegExp(
        `REVOKE ALL ON TABLE ${table.replace('.', '\\.')}[\\s\\S]+service_role`,
      ));
      expect(migration).not.toMatch(new RegExp(
        `GRANT (?:ALL|SELECT|INSERT|UPDATE|DELETE|TRUNCATE)[^;]+${table.replace('.', '\\.')}`,
      ));
    });
  }

  it('reasserts tenant-principal custody and keeps service_role outside both RPC schemas', () => {
    expect(migration).toContain('ALTER TABLE ep_aeb_private.tenant_principals FORCE ROW LEVEL SECURITY;');
    expect(migration).toContain('ALTER TABLE ep_remedy_private.tenant_principals FORCE ROW LEVEL SECURITY;');
    expect(migration).toContain(
      'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private\n  FROM PUBLIC, anon, authenticated, service_role;',
    );
    expect(migration).toContain(
      'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_remedy_private\n  FROM PUBLIC, anon, authenticated, service_role;',
    );
    expect(migration).not.toMatch(/GRANT EXECUTE[\s\S]+TO service_role/);
    expect(migration).toContain('TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);');
    expect(migration).toContain('TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE);');
    expect(migration).toContain('REVOKE ep_aeb_store_owner, ep_remedy_store_owner FROM CURRENT_USER;');
  });

  it('restores only explicit execution and recovery function grants', () => {
    expect(migration).toContain('TO ep_aeb_executor;');
    expect(migration).toContain('TO ep_aeb_recovery;');
    expect(migration).toContain('TO ep_remedy_executor;');
    expect(migration).not.toContain('GRANT EXECUTE ON ALL FUNCTIONS');
  });
});
