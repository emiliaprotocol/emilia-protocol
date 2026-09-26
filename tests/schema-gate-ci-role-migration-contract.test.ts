// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260926035734_schema_gate_ci_role.sql', import.meta.url),
  'utf8',
);
const sql = migration.replace(/--[^\n]*/g, '');
const grants = [...sql.matchAll(/\bGRANT\s+[^;]+;/gi)]
  .map(([statement]) => statement.replace(/\s+/g, ' ').trim());

describe('schema CI role migration', () => {
  it('creates only a credential-free, non-elevated group role and is repeatable', () => {
    expect(sql).toMatch(/IF gate_role_oid IS NULL THEN\s+CREATE ROLE schema_gate_ci NOLOGIN\s+NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;/);
    expect(sql).toMatch(/rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole\s+OR rolreplication OR rolbypassrls/);
    expect(sql).toMatch(/pg_auth_members\s+WHERE member = gate_role_oid/);
    expect(sql).not.toMatch(/\bPASSWORD\b|\bCREATE USER\b|\bALTER ROLE\b/);
  });

  it('grants exactly public-schema usage and the two metadata RPCs', () => {
    expect(grants).toEqual([
      'GRANT USAGE ON SCHEMA public TO schema_gate_ci;',
      'GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect() TO schema_gate_ci;',
      'GRANT EXECUTE ON FUNCTION public.gov_schema_reconcile_introspect() TO schema_gate_ci;',
    ]);
    expect(sql).not.toMatch(/\bALTER DEFAULT PRIVILEGES\b/);
    expect(sql).toMatch(/pg_class AS relation[\s\S]+relation\.relowner = gate_role_oid/);
  });
});
