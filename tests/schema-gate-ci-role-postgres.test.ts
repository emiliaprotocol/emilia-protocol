// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260926035734_schema_gate_ci_role.sql', import.meta.url),
  'utf8',
);
const suite = process.env.SCHEMA_GATE_ROLE_TEST_POSTGRES === '1'
  ? describe.sequential
  : describe.skip;

suite('schema CI role in a disposable PostgreSQL test database', () => {
  it('passes direct RPC grants to an inheriting login while exposing PUBLIC function grants', async () => {
    const database = process.env.PGDATABASE;
    if (!database?.endsWith('_test')) {
      throw new Error('Set PGDATABASE to a disposable *_test database');
    }

    const client = new pg.Client({
      host: process.env.PGHOST ?? 'localhost',
      port: Number(process.env.PGPORT ?? '5433'),
      database,
      user: process.env.PGUSER,
      password: process.env.PGPASSWORD,
    });
    await client.connect();
    try {
      await client.query('BEGIN');
      const occupied = await client.query<{ occupied: boolean }>(`
        SELECT EXISTS (
          SELECT 1 FROM pg_catalog.pg_roles
          WHERE rolname IN ('schema_gate_ci', 'schema_gate_ci_gha')
        ) OR to_regprocedure('public.gov_schema_contract_introspect()') IS NOT NULL
          OR to_regprocedure('public.gov_schema_reconcile_introspect()') IS NOT NULL
          AS occupied
      `);
      if (occupied.rows[0].occupied) {
        throw new Error('Use a fresh disposable database for this role test');
      }

      await client.query(`
        CREATE FUNCTION public.gov_schema_contract_introspect()
          RETURNS jsonb LANGUAGE sql SECURITY DEFINER
          AS $$ SELECT jsonb_build_object() $$;
        CREATE FUNCTION public.gov_schema_reconcile_introspect()
          RETURNS jsonb LANGUAGE sql SECURITY DEFINER
          AS $$ SELECT jsonb_build_object() $$;
        CREATE FUNCTION public.schema_gate_public_probe()
          RETURNS integer LANGUAGE sql SECURITY DEFINER
          AS $$ SELECT 1 $$;
        REVOKE EXECUTE ON FUNCTION public.gov_schema_contract_introspect() FROM PUBLIC;
        REVOKE EXECUTE ON FUNCTION public.gov_schema_reconcile_introspect() FROM PUBLIC;
        CREATE TABLE public.schema_gate_app_table (id integer);
      `);
      await client.query(migration);
      await client.query(migration);
      await client.query(`
        CREATE ROLE schema_gate_ci_gha LOGIN INHERIT
          NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        GRANT schema_gate_ci TO schema_gate_ci_gha;
      `);

      const group = await client.query<{
        rolcanlogin: boolean;
        rolsuper: boolean;
        rolcreatedb: boolean;
        rolcreaterole: boolean;
        rolreplication: boolean;
        rolbypassrls: boolean;
      }>(`
        SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
          rolreplication, rolbypassrls
        FROM pg_catalog.pg_roles WHERE rolname = 'schema_gate_ci'
      `);
      expect(Object.values(group.rows[0])).toEqual([false, false, false, false, false, false]);

      await client.query('SET ROLE schema_gate_ci_gha');
      const access = await client.query<{
        actor: string;
        schema_usage: boolean;
        contract_execute: boolean;
        reconcile_execute: boolean;
        public_execute: boolean;
        table_select: boolean;
        table_insert: boolean;
        table_update: boolean;
        table_delete: boolean;
      }>(`
        SELECT current_user AS actor,
          has_schema_privilege('public', 'USAGE') AS schema_usage,
          has_function_privilege('public.gov_schema_contract_introspect()', 'EXECUTE') AS contract_execute,
          has_function_privilege('public.gov_schema_reconcile_introspect()', 'EXECUTE') AS reconcile_execute,
          has_function_privilege('public.schema_gate_public_probe()', 'EXECUTE') AS public_execute,
          has_table_privilege('public.schema_gate_app_table', 'SELECT') AS table_select,
          has_table_privilege('public.schema_gate_app_table', 'INSERT') AS table_insert,
          has_table_privilege('public.schema_gate_app_table', 'UPDATE') AS table_update,
          has_table_privilege('public.schema_gate_app_table', 'DELETE') AS table_delete
      `);
      expect(access.rows[0]).toEqual({
        actor: 'schema_gate_ci_gha',
        schema_usage: true,
        contract_execute: true,
        reconcile_execute: true,
        public_execute: true,
        table_select: false,
        table_insert: false,
        table_update: false,
        table_delete: false,
      });
      const calls = await client.query(`
        SELECT public.gov_schema_contract_introspect() AS contract,
          public.gov_schema_reconcile_introspect() AS reconcile,
          public.schema_gate_public_probe() AS public_probe
      `);
      expect(calls.rows[0]).toEqual({ contract: {}, reconcile: {}, public_probe: 1 });
    } finally {
      try {
        await client.query('ROLLBACK');
      } finally {
        await client.end();
      }
    }
  });
});
