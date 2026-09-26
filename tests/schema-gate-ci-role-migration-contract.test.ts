// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260926035734_schema_gate_ci_role.sql', import.meta.url),
  'utf8',
);
const runbook = readFileSync(new URL('../docs/operations/SCHEMA-GATE-CI.md', import.meta.url), 'utf8');
const sql = migration.replace(/--[^\n]*/g, '');
const grants = [...sql.matchAll(/\bGRANT\s+[^;]+;/gi)]
  .map(([statement]) => statement.replace(/\s+/g, ' ').trim());

describe('schema CI role migration', () => {
  it('creates only a credential-free, non-elevated group role', () => {
    expect(sql).toMatch(/IF gate_role_oid IS NULL THEN\s+CREATE ROLE schema_gate_ci NOLOGIN\s+NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;/);
    expect(sql.match(/\bCREATE ROLE\b/gi)).toHaveLength(1);
    expect(sql).not.toMatch(/\bPASSWORD\b|\bCREATE USER\b|\bALTER ROLE\b|\bSECURITY DEFINER\b/i);
  });

  it('refuses a preexisting or drifted role before granting anything', () => {
    const refusals = [...sql.matchAll(/RAISE EXCEPTION '(schema_gate_ci refused: [^']+)'/g)].map(([, reason]) => reason);
    expect(refusals).toHaveLength(4);
    expect(sql).toMatch(/rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole\s+OR rolreplication OR rolbypassrls/);
    expect(sql).toMatch(/FROM pg_catalog\.pg_auth_members\s+WHERE member = gate_role_oid/);
    expect(sql).toMatch(/FROM pg_catalog\.pg_shdepend AS dependency[\s\S]+refobjid = gate_role_oid/);
    expect(sql.indexOf('END\n$schema_gate_ci_role$;')).toBeLessThan(sql.indexOf('GRANT USAGE'));
  });

  it('grants exactly public-schema usage and the two metadata RPCs', () => {
    expect(grants).toEqual([
      'GRANT USAGE ON SCHEMA public TO schema_gate_ci;',
      'GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect() TO schema_gate_ci;',
      'GRANT EXECUTE ON FUNCTION public.gov_schema_reconcile_introspect() TO schema_gate_ci;',
    ]);
    expect(sql).not.toMatch(/\bALTER DEFAULT PRIVILEGES\b|\bREVOKE\b/i);
  });

  it('keeps the runbook login provisioning credential-free', () => {
    const provisioning = runbook.match(/```sql\n-- runbook: provision login\n([\s\S]*?)```/);
    expect(provisioning?.[1]).toMatch(/CREATE ROLE schema_gate_ci_gha LOGIN INHERIT\s+NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\s+GRANT schema_gate_ci TO schema_gate_ci_gha;/);
    expect(provisioning?.[1]).not.toMatch(/\bPASSWORD\b/i);
  });
});
