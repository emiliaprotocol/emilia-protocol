// SPDX-License-Identifier: Apache-2.0
//
// Shared schema-snapshot fetch for the schema-security gate (db-contract.mjs,
// migration-reconcile.mjs).
//
// Least-privilege by default: when SCHEMA_GATE_DB_URL is set (CI), connect as the
// dedicated `schema_gate` Postgres role — which can EXECUTE only the two
// metadata introspection functions and read NO table rows — over the Supabase
// pooler. The god-mode service-role key never enters CI.
//
// Local fallback: if SCHEMA_GATE_DB_URL is absent, use supabase-js with the
// service-role key from .env.local (developer convenience only).

export async function fetchSchemaSnapshot(): Promise<Record<string, any>> {
  const dbUrl = process.env.SCHEMA_GATE_DB_URL;
  if (dbUrl) {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const here = path.dirname(fileURLToPath(import.meta.url));
    // Pin Supabase's published Root 2021 CA and VERIFY against it. The pooler
    // cert chains to this self-signed root (not a public CA), so we supply the
    // root explicitly and keep rejectUnauthorized ON — full verification, no
    // MITM exposure (never set rejectUnauthorized:false; CWE-319).
    const ca = (fs as any).readFileSync(path.join(here, 'supabase-pooler-ca.pem'), 'utf8') as string;
    const { default: pg } = await import('pg');
    const client = new (pg as any).Client({ connectionString: dbUrl, ssl: { ca, rejectUnauthorized: true } });
    await client.connect();
    try {
      const { rows } = await client.query(`
        select
          public.gov_schema_contract_introspect() as snap,
          public.gov_schema_reconcile_introspect() as reconcile
      `);
      const row = rows[0 as any] as any;
      return {
        ...(row.snap as Record<string, any>),
        reconcile_tables: row.reconcile.tables,
        reconcile_functions: row.reconcile.functions,
      };
    } finally {
      await client.end();
    }
  }
  const { createClient } = await import('@supabase/supabase-js');
  const URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY;
  if (!URL || !KEY) {
    throw new Error('Set SCHEMA_GATE_DB_URL (preferred) or NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY');
  }
  const sb = (createClient as any)(URL, KEY, { auth: { persistSession: false } });
  const [contractResult, reconcileResult] = await Promise.all([
    sb.rpc('gov_schema_contract_introspect'),
    sb.rpc('gov_schema_reconcile_introspect'),
  ]);
  if (contractResult.error) {
    throw new Error(`contract introspection RPC failed (migration 115 applied?): ${contractResult.error.message}`);
  }
  if (reconcileResult.error) {
    throw new Error(`reconciliation introspection RPC failed (migration 20260722050000 applied?): ${reconcileResult.error.message}`);
  }
  return {
    ...(contractResult.data as Record<string, any>),
    reconcile_tables: reconcileResult.data.tables,
    reconcile_functions: reconcileResult.data.functions,
  };
}
