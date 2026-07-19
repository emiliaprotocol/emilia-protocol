// SPDX-License-Identifier: Apache-2.0
//
// Schema secret-disclosure contract — static, CI-safe regression guard.
//
// The 2026-07 authorization sweep found secret-bearing columns reachable two ways:
//   1. an auth RPC that row_to_json'd a whole entity row (fixed: migration 125);
//   2. column/table GRANTs letting anon/authenticated read/write sealed material
//      across entities + adjacent infra tables (fixed: migrations 126/127/128).
//
// This guard encodes the invariants against the migration set (no DB needed) so
// they cannot silently regress:
//   A. Every declared sensitive column is REVOKEd from anon AND authenticated.
//   B. No statement GRANTs a declared sensitive column to a public role.
//   C. No function row_to_json's a var populated by SELECT * FROM a secret-bearing
//      table without stripping the sensitive columns.
//
// Checks A/B are STATEMENT-SCOPED (split on ';') so a GRANT/REVOKE in one
// statement can't be stitched to a column name in another. Live grant-drift
// enforcement lives in scripts/db-contract.mjs (gov:db-contract); this is the
// always-on, zero-dependency floor.

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { contract } from '../scripts/db-contract.manifest.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIG_DIR = path.join(ROOT, 'supabase/migrations');

const migrations = fs
  .readdirSync(MIG_DIR)
  .filter((f) => f.endsWith('.sql'))
  .sort()
  .map((f) => ({ file: f, sql: fs.readFileSync(path.join(MIG_DIR, f), 'utf8') }));

function filesUnder(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...filesUnder(target));
    else if (entry.isFile() && /\.(?:js|mjs)$/.test(entry.name)) files.push(target);
  }
  return files;
}

const runtimeSources = ['app', 'lib']
  .flatMap((directory) => filesUnder(path.join(ROOT, directory)))
  .map((file) => fs.readFileSync(file, 'utf8'))
  .join('\n');
const referencedAtomicRpcs = new Set(
  [...runtimeSources.matchAll(/\.rpc\(\s*['"]([a-z][a-z0-9_]*_atomic)['"]/g)].map((match) => match[1]),
);

// Coarse statement split. Adequate for GRANT/REVOKE (no embedded ';'); we do NOT
// use this for function-body checks (those scan whole files). Strip `-- ...` line
// comments first so a statement's leading comment block doesn't shadow the verb.
const stripComments = (sql) => sql.replace(/--[^\n]*/g, '');
const statements = migrations.flatMap((m) => stripComments(m.sql).split(';').map((s) => s.trim()).filter(Boolean));

const pairs = Object.entries(contract.sensitiveColumnsNoPublicGrant).flatMap(
  ([table, cols]) => cols.map((col) => ({ table, col })),
);

function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// Does a single statement REVOKE/GRANT `col` on `table` (or the whole table)
// to/from `role`? Column-list form `(... col ...)` OR table-wide (no column list).
function stmtActsOn(stmt, verb, table, col, role) {
  const s = stmt.replace(/\s+/g, ' ');
  if (!new RegExp(`^${verb}\\b`, 'i').test(s)) return false;
  if (!new RegExp(`\\bON\\s+(?:public\\.)?${esc(table)}\\b`, 'i').test(s)) return false;
  const dir = verb === 'REVOKE' ? 'FROM' : 'TO';
  if (!new RegExp(`\\b${dir}\\b[^]*\\b${esc(role)}\\b`, 'i').test(s)) return false;
  // Column named explicitly, OR a table-wide grant/revoke (no parenthesised list
  // before ON) which necessarily covers the column too.
  const namesCol = new RegExp(`\\(([^)]*\\b${esc(col)}\\b[^)]*)\\)`, 'i').test(s);
  const tableWide = !/\([^)]*\)\s*ON\b/i.test(s); // no "(cols) ON" => privilege applies table-wide
  return namesCol || tableWide;
}

describe('schema secret-disclosure contract (static)', () => {
  it('guards every runtime atomic RPC in the live service-role-only contract', () => {
    expect(referencedAtomicRpcs.size).toBeGreaterThan(0);
    for (const name of referencedAtomicRpcs) {
      expect(contract.definerRpcsServiceRoleOnly, `${name} is absent from the live schema contract`)
        .toContain(name);
    }
  });

  it('declares sensitive columns to protect', () => {
    expect(contract.sensitiveColumnsNoPublicGrant).toBeTruthy();
    expect(pairs.length).toBeGreaterThanOrEqual(6);
  });

  // A. Each declared sensitive column is revoked from BOTH anon and authenticated.
  it.each(pairs)('$table.$col is REVOKEd from anon+authenticated', ({ table, col }) => {
    const anon = statements.some((s) => stmtActsOn(s, 'REVOKE', table, col, 'anon'));
    const authed = statements.some((s) => stmtActsOn(s, 'REVOKE', table, col, 'authenticated'));
    expect(anon, `no REVOKE of ${table}.${col} from anon`).toBe(true);
    expect(authed, `no REVOKE of ${table}.${col} from authenticated`).toBe(true);
  });

  // B. No statement GRANTs a sensitive column to a public role (statement-scoped).
  it.each(pairs)('$table.$col is never GRANTed to anon/authenticated', ({ table, col }) => {
    const granted = statements.find(
      (s) => stmtActsOn(s, 'GRANT', table, col, 'anon') || stmtActsOn(s, 'GRANT', table, col, 'authenticated'),
    );
    expect(granted, `a statement GRANTs ${table}.${col} to a public role: ${granted}`).toBeUndefined();
  });

  // C. No function row_to_json's a SELECT * of a secret-bearing table unstripped.
  it('no function returns an unstripped row_to_json of a secret-bearing table', () => {
    const offenders = [];
    for (const { table, col } of pairs) {
      // Latest migration that binds `SELECT * INTO <var> FROM <table>` AND row_to_json(<var>).
      for (const m of migrations) {
        const bind = new RegExp(`SELECT\\s+\\*\\s+INTO\\s+(\\w+)\\s+FROM\\s+(?:public\\.)?${esc(table)}\\b`, 'i').exec(m.sql);
        if (!bind) continue;
        const varName = bind[1];
        if (!new RegExp(`row_to_json\\(\\s*${esc(varName)}\\s*\\)`, 'i').test(m.sql)) continue;
        // A binding+row_to_json exists in a LATER migration? then this one is superseded.
        const laterSupersedes = migrations.some(
          (n) => n.file > m.file
            && new RegExp(`SELECT\\s+\\*\\s+INTO\\s+\\w+\\s+FROM\\s+(?:public\\.)?${esc(table)}\\b`, 'i').test(n.sql)
            && /row_to_json/i.test(n.sql),
        );
        if (laterSupersedes) continue;
        if (!m.sql.includes(`- '${col}'`)) {
          offenders.push(`${m.file}: row_to_json over ${table} without stripping '${col}'`);
        }
      }
    }
    expect(offenders, offenders.join('; ')).toEqual([]);
  });
});
