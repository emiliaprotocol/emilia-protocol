// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260725210000_schema_contract_identity_arguments.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('schema-contract function identity introspection', () => {
  it('emits overload identity types without deployment-specific argument names', () => {
    expect(migration).toContain("'args', oidvectortypes(p.proargtypes)");
    expect(migration).not.toContain("'args', pg_get_function_identity_arguments(p.oid)");
  });

  it('preserves the metadata-only definer and least-privilege ACL', () => {
    expect(migration).toContain(
      'CREATE OR REPLACE FUNCTION public.gov_schema_contract_introspect()',
    );
    expect(migration).toContain("SET search_path TO 'pg_catalog', 'public'");
    expect(migration).toMatch(
      /REVOKE EXECUTE ON FUNCTION public\.gov_schema_contract_introspect\(\)[\s\S]+FROM PUBLIC, anon, authenticated/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.gov_schema_contract_introspect\(\)[\s\S]+TO service_role, schema_gate/,
    );
  });
});
