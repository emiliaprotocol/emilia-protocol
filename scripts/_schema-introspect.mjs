// SPDX-License-Identifier: Apache-2.0
// Generated from _schema-introspect.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Shared schema-snapshot fetch for the schema-security gate (db-contract.mjs,
// migration-reconcile.mjs).
//
// Least-privilege by default: when SCHEMA_GATE_DB_URL is set (CI), connect as the
// dedicated `schema_gate` Postgres role — which can EXECUTE only
// gov_schema_contract_introspect() and read NO table rows — over the Supabase
// pooler. The god-mode service-role key never enters CI.
//
// Local fallback: if SCHEMA_GATE_DB_URL is absent, use supabase-js with the
// service-role key from .env.local (developer convenience only).
export async function fetchSchemaSnapshot() {
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
        const ca = fs.readFileSync(path.join(here, 'supabase-pooler-ca.pem'), 'utf8');
        const { default: pg } = await import('pg');
        const client = new pg.Client({ connectionString: dbUrl, ssl: { ca, rejectUnauthorized: true } });
        await client.connect();
        try {
            const { rows } = await client.query('select public.gov_schema_contract_introspect() as snap');
            return rows[0].snap;
        }
        finally {
            await client.end();
        }
    }
    const { createClient } = await import('@supabase/supabase-js');
    const URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY;
    if (!URL || !KEY) {
        throw new Error('Set SCHEMA_GATE_DB_URL (preferred) or NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY');
    }
    const sb = createClient(URL, KEY, { auth: { persistSession: false } });
    const { data, error } = await sb.rpc('gov_schema_contract_introspect');
    if (error)
        throw new Error(`introspection RPC failed (migration 115 applied?): ${error.message}`);
    return data;
}
