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

const UNTRUSTED = new Set(['anon', 'authenticated', 'PUBLIC']);
const WRITE_CMDS = new Set(['INSERT', 'UPDATE', 'DELETE', 'ALL']);
const READ_CMDS = new Set(['SELECT', 'ALL']);

// Postgres grants EXECUTE to PUBLIC by default (empty grantee in aclitem). An
// empty acl string therefore means PUBLIC can execute.
const aclAnon = (acl) => /(^|[,{])anon=[A-Za-z]*X/.test(acl);
const aclAuth = (acl) => /(^|[,{])authenticated=[A-Za-z]*X/.test(acl);
const aclPublic = (acl) => acl === '' || /(^|[,{])=[A-Za-z]*X/.test(acl);
const aclUntrusted = (acl) => aclAnon(acl) || aclAuth(acl) || aclPublic(acl);

const fails = [];
const gaps = [];
let passCount = 0;
const pass = (m) => { passCount++; };
const fail = (m) => fails.push(m);

const main = async () => {
  let snap;
  try {
    snap = await fetchSchemaSnapshot();
  } catch (e) {
    console.error('FATAL: introspection failed:', e.message);
    process.exit(2);
  }

  const tables = new Set(snap.tables);
  const cols = new Map(); // table -> Set(col)
  for (const c of snap.columns) {
    if (!cols.has(c.t)) cols.set(c.t, new Set());
    cols.get(c.t).add(c.c);
  }
  const rls = new Map(snap.rls.map((r) => [r.t, r.enabled]));
  const policiesByTable = new Map();
  for (const p of snap.policies) {
    if (!policiesByTable.has(p.t)) policiesByTable.set(p.t, []);
    policiesByTable.get(p.t).push(p);
  }
  const fnsByName = new Map();
  for (const f of snap.functions) {
    if (!fnsByName.has(f.name)) fnsByName.set(f.name, []);
    fnsByName.get(f.name).push(f);
  }

  // 1. Required tables
  for (const t of contract.requiredTables) {
    if (tables.has(t)) pass(); else fail(`TABLE missing: ${t}`);
  }

  // 2. Known-gap tables (non-fatal, but tracked + must be reported)
  for (const g of contract.knownGapTables) {
    if (tables.has(g.name)) {
      // It appeared — the gap is closed; tell the operator to promote it.
      gaps.push(`KNOWN GAP NOW PRESENT (promote to requiredTables): ${g.name}`);
    } else {
      gaps.push(`KNOWN GAP (tracked, not fixed): ${g.name} — ${g.why}`);
    }
  }

  // 3. Required columns
  for (const [t, want] of Object.entries(contract.requiredColumns)) {
    const have = cols.get(t) || new Set();
    for (const c of want) {
      if (have.has(c)) pass(); else fail(`COLUMN missing: ${t}.${c}`);
    }
  }

  // 4. RLS enabled
  for (const t of contract.rlsRequired) {
    if (!tables.has(t)) { fail(`RLS-required table missing: ${t}`); continue; }
    if (rls.get(t) === true) pass(); else fail(`RLS NOT enabled: ${t}`);
  }

  // 5. No anon/authenticated/PUBLIC READ policy on sensitive tables
  for (const t of contract.noAnonRead) {
    const bad = (policiesByTable.get(t) || []).filter(
      (p) => READ_CMDS.has(p.cmd) && (p.roles || []).some((r) => UNTRUSTED.has(r))
    );
    if (bad.length === 0) pass();
    else fail(`ANON-READ exposure on ${t}: ${bad.map((p) => `${p.name}[${p.cmd}→${p.roles.join(',')}]`).join('; ')}`);
  }

  // 6. No anon/authenticated/PUBLIC WRITE policy on sensitive tables
  for (const t of contract.noAnonWrite) {
    const bad = (policiesByTable.get(t) || []).filter(
      (p) => WRITE_CMDS.has(p.cmd) && (p.roles || []).some((r) => UNTRUSTED.has(r))
    );
    if (bad.length === 0) pass();
    else fail(`ANON-WRITE exposure on ${t}: ${bad.map((p) => `${p.name}[${p.cmd}→${p.roles.join(',')}]`).join('; ')}`);
  }

  // 7. SECURITY DEFINER RPCs exist + not anon/auth/PUBLIC-executable (all overloads)
  for (const name of contract.definerRpcsServiceRoleOnly) {
    const overloads = fnsByName.get(name) || [];
    if (overloads.length === 0) { fail(`RPC missing: ${name}()`); continue; }
    const exposed = overloads.filter((f) => aclUntrusted(f.acl));
    if (exposed.length === 0) pass();
    else fail(`RPC executable by untrusted role: ${name} (${exposed.length}/${overloads.length} overloads) acl=${exposed.map((f) => f.acl).join(' | ')}`);
  }

  // 8. Required RPCs exist
  for (const name of contract.requiredRpcs) {
    if (fnsByName.has(name)) pass(); else fail(`RPC missing: ${name}()`);
  }

  // ---- report ----
  console.log(`\nEP schema-security contract — ${new Date().toISOString()}`);
  console.log(`Project: ${PROJECT_LABEL}`);
  console.log(`\n  ${passCount} assertions passed`);
  if (gaps.length) {
    console.log(`\n  KNOWN GAPS (${gaps.length}) — tracked, non-fatal:`);
    for (const g of gaps) console.log(`    • ${g}`);
  }
  if (fails.length) {
    console.log(`\n  FAILURES (${fails.length}):`);
    for (const f of fails) console.log(`    ✗ ${f}`);
    console.log('\nCONTRACT VIOLATED — prod schema does not match the security contract.\n');
    process.exit(1);
  }
  console.log('\nCONTRACT SATISFIED.\n');
  process.exit(0);
};

main().catch((e) => { console.error('FATAL:', e); process.exit(2); });
