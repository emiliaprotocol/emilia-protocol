// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260723140000_aeb_consumption_status_lookup.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('AEB authenticated replay status lookup migration', () => {
  it('temporarily assumes the private-schema owner and revokes that membership', () => {
    expect(migration).toContain(
      'GRANT ep_aeb_store_owner TO CURRENT_USER\n  WITH INHERIT FALSE, SET TRUE;\nSET ROLE ep_aeb_store_owner;',
    );
    expect(migration).toContain(
      'RESET ROLE;\nREVOKE ep_aeb_store_owner FROM CURRENT_USER;',
    );
  });

  it('exposes only a tenant-bound exact replay-fence observation', () => {
    expect(migration).toContain(
      'CREATE OR REPLACE FUNCTION ep_aeb_private.has_replay_fence(',
    );
    expect(migration).toContain(
      'PERFORM ep_aeb_private.assert_tenant_principal(p_tenant_id, FALSE);',
    );
    expect(migration).toContain(
      'WHERE fences.tenant_id = p_tenant_id',
    );
    expect(migration).toContain(
      'AND fences.relying_party_id = p_relying_party_id',
    );
    expect(migration).toContain(
      'AND fences.replay_key = p_replay_key',
    );
    expect(migration).toContain(
      'SECURITY DEFINER SET search_path =',
    );
  });

  it('keeps the function away from public API roles and grants only the executor role', () => {
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION ep_aeb_private.has_replay_fence(TEXT, TEXT, TEXT)',
    );
    expect(migration).toContain(
      'FROM PUBLIC, anon, authenticated, service_role, ep_aeb_recovery;',
    );
    expect(migration).toContain(
      'TO ep_aeb_executor;',
    );
    expect(migration).not.toMatch(
      /GRANT EXECUTE[\s\S]+has_replay_fence[\s\S]+(?:service_role|authenticated|anon)/,
    );
  });
});
