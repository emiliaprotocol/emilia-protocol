// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  AEB_CONSUMPTION_OPERATION_TABLE,
  AEB_CONSUMPTION_REPLAY_TABLE,
} from '../packages/gate/src/aeb-consumption-store.ts';

const migration = readFileSync(
  new URL('../supabase/migrations/20260722200000_aeb_consumption_store.sql', import.meta.url),
  'utf8',
);

describe('AEB consumption production migration', () => {
  for (const table of [AEB_CONSUMPTION_OPERATION_TABLE, AEB_CONSUMPTION_REPLAY_TABLE]) {
    it(`${table} is RPC-only and forced-RLS protected`, () => {
      expect(migration).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
      expect(migration).toContain(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY`);
      expect(migration).toContain(`ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`);
      expect(migration).toMatch(new RegExp(
        `REVOKE ALL ON public\\.${table}[\\s\\S]+service_role[\\s\\S]+ep_aeb_executor[\\s\\S]+ep_aeb_recovery`,
      ));
      expect(migration).not.toContain(`GRANT ALL ON ${table} TO service_role`);
    });
  }

  it('separates execution and recovery credentials and tenant-binds each principal', () => {
    expect(migration).toContain('CREATE ROLE ep_aeb_executor NOLOGIN');
    expect(migration).toContain('CREATE ROLE ep_aeb_recovery NOLOGIN');
    expect(migration).toContain('CREATE ROLE ep_aeb_store_owner NOLOGIN');
    expect(migration.match(/NOBYPASSRLS/g)?.length).toBe(3);
    expect(migration).toContain('ALTER TABLE public.ep_aeb_consumption_operations OWNER TO ep_aeb_store_owner');
    expect(migration).toContain('TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE)');
    expect(migration).toContain('CREATE TABLE IF NOT EXISTS ep_aeb_private.tenant_principals');
    expect(migration).toContain("pg_catalog.pg_has_role(SESSION_USER, 'ep_aeb_executor', 'MEMBER')");
    expect(migration).toContain("pg_catalog.pg_has_role(SESSION_USER, 'ep_aeb_recovery', 'MEMBER')");
    expect(migration).toContain('principals.principal_name = SESSION_USER');
    expect(migration).toContain('principals.tenant_id = p_tenant_id');
  });

  it('exposes only narrow security-definer mutations and gives service_role no authority', () => {
    expect(migration).toMatch(/LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''/);
    expect(migration).toContain('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private');
    expect(migration).toContain('FROM PUBLIC, anon, authenticated, service_role;');
    expect(migration).toContain('TO ep_aeb_executor;');
    expect(migration).toContain('TO ep_aeb_recovery;');
    expect(migration).not.toMatch(/GRANT (?:ALL|SELECT|INSERT|UPDATE|DELETE)[\s\S]+service_role/);
  });

  it('binds native replay fences to the exact tenant, relying party, and operation', () => {
    expect(migration).toContain('PRIMARY KEY (tenant_id, relying_party_id, replay_key)');
    expect(migration).toContain('FOREIGN KEY (tenant_id, relying_party_id, operation_key)');
    expect(migration).toContain('ON DELETE CASCADE');
  });
});
