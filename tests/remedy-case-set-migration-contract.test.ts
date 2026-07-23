// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  REMEDY_CASE_SET_EVENT_TABLE,
  REMEDY_CASE_SET_TABLE,
} from '../packages/gate/src/remedy-case-set-postgres.ts';

const migration = readFileSync(
  new URL('../supabase/migrations/20260722210000_remedy_case_set_store.sql', import.meta.url),
  'utf8',
);

describe('remedy case-set production migration', () => {
  for (const table of [REMEDY_CASE_SET_TABLE, REMEDY_CASE_SET_EVENT_TABLE]) {
    it(`${table} is tenant-scoped, forced-RLS, and RPC-only`, () => {
      expect(migration).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
      expect(migration).toContain(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);
      expect(migration).toContain(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`);
      expect(migration).toMatch(new RegExp(
        `REVOKE ALL ON ${table}[\\s\\S]+service_role[\\s\\S]+ep_remedy_executor`,
      ));
      expect(migration).not.toContain(`GRANT ALL ON ${table} TO service_role`);
    });
  }

  it('uses a tenant-bound no-bypass executor and narrow security-definer functions', () => {
    expect(migration).toContain('CREATE ROLE ep_remedy_executor NOLOGIN');
    expect(migration).toContain('CREATE ROLE ep_remedy_store_owner NOLOGIN');
    expect(migration).toContain('NOBYPASSRLS');
    expect(migration).toContain('ALTER TABLE public.ep_remedy_case_sets OWNER TO ep_remedy_store_owner');
    expect(migration).toContain('TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE)');
    expect(migration).toContain('CREATE TABLE IF NOT EXISTS ep_remedy_private.tenant_principals');
    expect(migration).toContain("pg_catalog.pg_has_role(SESSION_USER, 'ep_remedy_executor', 'MEMBER')");
    expect(migration).toContain('principals.principal_name = SESSION_USER');
    expect(migration).toContain('principals.tenant_id = p_tenant_id');
    expect(migration).toMatch(/LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''/);
    expect(migration).toContain('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_remedy_private');
    expect(migration).toContain('FROM PUBLIC, anon, authenticated, service_role;');
    expect(migration).toContain('TO ep_remedy_executor;');
  });

  it('grants the no-login owner only the public-schema privileges its tables require', () => {
    expect(migration).toContain(
      'GRANT USAGE, CREATE ON SCHEMA public TO ep_remedy_store_owner',
    );
    expect(migration).toContain(
      'REVOKE CREATE ON SCHEMA public FROM ep_remedy_store_owner',
    );
    expect(migration.indexOf('REVOKE CREATE ON SCHEMA public FROM ep_remedy_store_owner'))
      .toBeGreaterThan(migration.indexOf('COMMENT ON TABLE ep_remedy_case_set_events'));
    expect(migration.indexOf('REVOKE ep_remedy_store_owner FROM CURRENT_USER'))
      .toBeGreaterThan(migration.indexOf('REVOKE CREATE ON SCHEMA public FROM ep_remedy_store_owner'));
  });

  it('makes current manifests, terminal states, and history immutable', () => {
    expect(migration).toContain('remedy case-set identity, owner, and manifest are immutable');
    expect(migration).toContain('completed remedy case sets are immutable');
    expect(migration).toContain('remedy case-set events are immutable');
    expect(migration).toContain('PRIMARY KEY (tenant_id, case_set_id, revision)');
  });
});
