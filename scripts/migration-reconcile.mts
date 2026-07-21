#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Migration journal vs reality reconciliation.
//
// The invariant: prod schema truth comes from objects that ACTUALLY EXIST, not
// from the migration journal. This session found migrations journaled-as-applied
// (033 authorities, 022 operator_applications, 068 policy_rollouts, 098, 102)
// whose objects never existed in prod. This script makes that class loud:
// it diffs every object the repo migrations DECLARE against what the live
// database actually has (via the gov_schema_contract_introspect RPC).
//
// Any "declared but missing" object is drift → exit 1 (blocker).
//
// Usage: node scripts/migration-reconcile.mjs   (npm run schema:reconcile)
// Needs: NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY (reads .env.local)

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fetchSchemaSnapshot } from './_schema-introspect.mjs';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIG_DIR: string = path.join(ROOT, 'supabase', 'migrations');

for (const file of ['.env.local', '.env']) {
  const p: string = path.join(ROOT, file);
  if (!fs.existsSync(p)) continue;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const m: RegExpMatchArray | null = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}
if (!process.env.SCHEMA_GATE_DB_URL && !(process.env.NEXT_PUBLIC_SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY))) {
  console.error('FATAL: set SCHEMA_GATE_DB_URL (preferred) or NEXT_PUBLIC_SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY');
  process.exit(2);
}
const PROJECT_LABEL = (process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SCHEMA_GATE_DB_URL || '')
  .replace(/^[a-z]+:\/\//, '').replace(/^[^@]*@/, '').split(/[.:]/)[0] || 'prod';

// ── Parse what the deployed migration baseline declares ─────────────────────
// A pull request may introduce schema that cannot exist in production before
// merge. On PRs, CI pins this to the base commit. Main, scheduled, and manual
// runs leave the variable unset and reconcile the current tree strictly.
const reconcileRef: string = process.env.MIGRATION_RECONCILE_REF?.trim() || '';
let migrationFiles: string[];
let sql: string;
if (reconcileRef) {
  if (!/^[0-9a-f]{40}$/i.test(reconcileRef)) {
    console.error('FATAL: MIGRATION_RECONCILE_REF must be an exact 40-character commit SHA');
    process.exit(2);
  }
  try {
    migrationFiles = execFileSync(
      'git',
      ['ls-tree', '-r', '--name-only', reconcileRef, '--', 'supabase/migrations'],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
    ).split('\n').filter((file) => file.endsWith('.sql'));
    if (migrationFiles.length === 0) throw new Error('no migration files found at pinned commit');
    sql = migrationFiles.map((file) => execFileSync(
      'git',
      ['show', `${reconcileRef}:${file}`],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
    )).join('\n');
  } catch (error) {
    console.error(`FATAL: could not read migrations at ${reconcileRef}: ${(error as any).message}`);
    process.exit(2);
  }
} else {
  migrationFiles = fs.readdirSync(MIG_DIR).filter((file) => file.endsWith('.sql')).sort();
  sql = migrationFiles.map((file) => fs.readFileSync(path.join(MIG_DIR, file), 'utf8')).join('\n');
}

const lc: string = sql; // keep case for identifiers; regexes are case-insensitive
const grab = (re: RegExp): Set<string> => { const s: Set<string> = new Set(); let m: RegExpExecArray | null; while ((m = re.exec(lc))) s.add(m[1].toLowerCase().replace(/^public\./, '')); return s; };

const createdTables = grab(/create\s+table\s+(?:if\s+not\s+exists\s+)?["']?([a-z_][a-z0-9_."]*)/gi);
const droppedTables = grab(/drop\s+table\s+(?:if\s+exists\s+)?["']?([a-z_][a-z0-9_."]*)/gi);
const createdFns = grab(/create\s+(?:or\s+replace\s+)?function\s+["']?([a-z_][a-z0-9_."]*)\s*\(/gi);
const droppedFns = grab(/drop\s+function\s+(?:if\s+exists\s+)?["']?([a-z_][a-z0-9_."]*)\s*\(/gi);

const declaredTables = [...createdTables].filter((t) => !droppedTables.has(t));
const declaredFns = [...createdFns].filter((f) => !droppedFns.has(f));

// ── What actually exists in prod ────────────────────────────────────────────
let snap: any;
try { snap = await fetchSchemaSnapshot(); }
catch (e) { console.error('FATAL: introspection failed:', (e as any).message); process.exit(2); }

const prodTables: Set<string> = new Set(snap.tables);
const prodFns: Set<string> = new Set(snap.functions.map((f: any) => f.name));

const missingTables: string[] = declaredTables.filter((t) => !prodTables.has(t));
const missingFns: string[] = declaredFns.filter((f) => !prodFns.has(f));

console.log(`\nMigration journal vs reality — ${new Date().toISOString()}`);
console.log(`Project: ${PROJECT_LABEL}`);
console.log(`  migration source: ${reconcileRef ? `base commit ${reconcileRef}` : 'current tree'}`);
console.log(`  migration files: ${migrationFiles.length}`);
console.log(`  declared tables: ${declaredTables.length} | prod tables: ${prodTables.size}`);
console.log(`  declared funcs:  ${declaredFns.length} | prod funcs: ${prodFns.size}`);

if (missingTables.length === 0 && missingFns.length === 0) {
  console.log('\nRECONCILED — every object the migrations declare exists in prod.\n');
  process.exit(0);
}
console.log('\n  DRIFT — declared by a migration but ABSENT in prod (journal lied):');
for (const t of missingTables) console.log(`    ✗ TABLE   ${t}`);
for (const f of missingFns) console.log(`    ✗ FUNCTION ${f}()`);
console.log('\nMIGRATION DRIFT DETECTED — open a blocker issue and reconcile before deploy.\n');
process.exit(1);
