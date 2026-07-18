#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Executable schema-security contract checker.
//
// Verifies that security-critical DB objects EXIST WITH THE EXPECTED SHAPE in
// the live database — tables, columns, RLS, policy role-scoping, and RPC ACLs —
// rather than trusting the migration journal (which has been shown to lie:
// migrations journaled-as-applied whose objects never existed).
//
// Usage:  node scripts/db-contract.mjs        (npm run gov:db-contract)
// Needs:  NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY (reads .env.local)
// Exit:   0 = contract satisfied (known gaps allowed); 1 = hard failure/regression.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchSchemaSnapshot } from './_schema-introspect.mjs';
import { contract } from './db-contract.manifest.mjs';
import { evaluateContract } from './db-contract-audit.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Match the repo's other scripts: load .env.local if vars aren't already set.
for (const file of ['.env.local', '.env']) {
  const p = path.join(ROOT, file);
  if (!fs.existsSync(p)) continue;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

// Credential check: least-privilege SCHEMA_GATE_DB_URL (preferred) or, for local
// dev, the service-role key. The actual fetch + fallback lives in fetchSchemaSnapshot.
if (!process.env.SCHEMA_GATE_DB_URL && !(process.env.NEXT_PUBLIC_SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY))) {
  console.error('FATAL: set SCHEMA_GATE_DB_URL (preferred) or NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY.');
  process.exit(2);
}
const PROJECT_LABEL = (process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SCHEMA_GATE_DB_URL || '')
  .replace(/^[a-z]+:\/\//, '').replace(/^[^@]*@/, '').split(/[.:]/)[0] || 'prod';

const main = async () => {
  let snap;
  try {
    snap = await fetchSchemaSnapshot();
  } catch (e) {
    console.error('FATAL: introspection failed:', e.message);
    process.exit(2);
  }

  const { passCount, gaps, failures } = evaluateContract(snap, contract);

  // ---- report ----
  console.log(`\nEP schema-security contract — ${new Date().toISOString()}`);
  console.log(`Project: ${PROJECT_LABEL}`);
  console.log(`\n  ${passCount} assertions passed`);
  if (gaps.length) {
    console.log(`\n  KNOWN GAPS (${gaps.length}) — tracked, non-fatal:`);
    for (const g of gaps) console.log(`    • ${g}`);
  }
  if (failures.length) {
    console.log(`\n  FAILURES (${failures.length}):`);
    for (const f of failures) console.log(`    ✗ ${f}`);
    console.log('\nCONTRACT VIOLATED — prod schema does not match the security contract.\n');
    process.exit(1);
  }
  console.log('\nCONTRACT SATISFIED.\n');
  process.exit(0);
};

main().catch((e) => { console.error('FATAL:', e); process.exit(2); });
