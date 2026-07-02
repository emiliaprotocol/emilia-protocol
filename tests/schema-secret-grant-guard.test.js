// SPDX-License-Identifier: Apache-2.0
//
// Schema secret-disclosure contract — static, CI-safe regression guard.
//
// The 2026-07 authorization sweep found two ways secret columns
// (entities.private_key_encrypted, entities.api_key_hash) reached a boundary:
//   1. an auth RPC that row_to_json'd the whole entity row (fixed: migration 125), and
//   2. column-level GRANTs letting anon/authenticated SELECT the sealed key
//      (fixed: migration 126 REVOKE).
//
// This guard encodes BOTH invariants against the migration set, with no DB
// connection required, so they cannot silently regress:
//   A. Every declared sensitive column is REVOKED from anon+authenticated in the
//      migration set (so a from-scratch replay reproduces the least-privilege
//      posture, and deleting the revoke fails CI).
//   B. No migration's LATEST function definition row_to_json's a table that has a
//      declared sensitive column without stripping those columns.
//
// The LIVE column-grant assertion (against a running DB) lives in
// scripts/db-contract.mjs (gov:db-contract); this test is the always-on,
// zero-dependency floor.

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { contract } from '../scripts/db-contract.manifest.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIG_DIR = path.join(ROOT, 'supabase/migrations');

function allMigrationSql() {
  return fs
    .readdirSync(MIG_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((f) => ({ file: f, sql: fs.readFileSync(path.join(MIG_DIR, f), 'utf8') }));
}

const migrations = allMigrationSql();
const allSql = migrations.map((m) => m.sql).join('\n');

describe('schema secret-disclosure contract (static)', () => {
  it('declares sensitive columns to protect', () => {
    expect(contract.sensitiveColumnsNoPublicGrant).toBeTruthy();
    expect(Object.keys(contract.sensitiveColumnsNoPublicGrant).length).toBeGreaterThan(0);
  });

  // A. Each declared sensitive column is revoked from anon + authenticated.
  const pairs = Object.entries(contract.sensitiveColumnsNoPublicGrant).flatMap(
    ([table, cols]) => cols.map((col) => ({ table, col })),
  );

  it.each(pairs)('$table.$col is REVOKEd from anon+authenticated in the migration set', ({ table, col }) => {
    // Look for a REVOKE ... (col) ON [public.]table FROM ... anon ... authenticated.
    // Tolerant of column lists, whitespace, and privilege ordering.
    const revokeRe = new RegExp(
      `REVOKE[\\s\\S]*?\\(${escapeRe(col)}[\\s\\S]*?\\)[\\s\\S]*?ON\\s+(?:public\\.)?${escapeRe(table)}[\\s\\S]*?FROM[\\s\\S]*?(anon|authenticated)`,
      'i',
    );
    const revokesAnon = new RegExp(
      `REVOKE[\\s\\S]*?\\(${escapeRe(col)}[\\s\\S]*?\\)[\\s\\S]*?ON\\s+(?:public\\.)?${escapeRe(table)}[\\s\\S]*?FROM[^;]*anon`,
      'i',
    ).test(allSql);
    const revokesAuthed = new RegExp(
      `REVOKE[\\s\\S]*?\\(${escapeRe(col)}[\\s\\S]*?\\)[\\s\\S]*?ON\\s+(?:public\\.)?${escapeRe(table)}[\\s\\S]*?FROM[^;]*authenticated`,
      'i',
    ).test(allSql);
    expect(revokeRe.test(allSql), `no REVOKE of ${table}.${col} from public roles found in migrations`).toBe(true);
    expect(revokesAnon && revokesAuthed, `${table}.${col} must be revoked from BOTH anon and authenticated`).toBe(true);
  });

  // B. No migration re-grants a sensitive column to a public role AFTER (or without) a revoke.
  it.each(pairs)('$table.$col is never GRANTed to anon/authenticated', ({ table, col }) => {
    const grantRe = new RegExp(
      `GRANT[\\s\\S]*?\\(${escapeRe(col)}[\\s\\S]*?\\)[\\s\\S]*?ON\\s+(?:public\\.)?${escapeRe(table)}[\\s\\S]*?TO[^;]*(anon|authenticated)`,
      'i',
    );
    expect(grantRe.test(allSql), `a migration GRANTs ${table}.${col} to a public role — remove it`).toBe(false);
  });

  // C. Generalized secret-projection guard: the LATEST definition of any function
  // that row_to_json's a variable populated by SELECT * FROM <sensitive table>
  // must strip each sensitive column. (Subsumes the auth-RPC-specific guard for
  // any future function over a secret-bearing table.)
  it('no function returns an unstripped row_to_json of a secret-bearing table', () => {
    const offenders = [];
    for (const table of Object.keys(contract.sensitiveColumnsNoPublicGrant)) {
      const cols = contract.sensitiveColumnsNoPublicGrant[table];
      // Consider only the LATEST migration that mentions both a SELECT * of the
      // table and row_to_json — earlier definitions are superseded by CREATE OR
      // REPLACE, so scanning the last one reflects what actually runs.
      const relevant = migrations.filter(
        (m) => new RegExp(`SELECT\\s+\\*[\\s\\S]*?FROM\\s+(?:public\\.)?${escapeRe(table)}`, 'i').test(m.sql)
          && /row_to_json/i.test(m.sql),
      );
      const latest = relevant[relevant.length - 1];
      if (!latest) continue;
      for (const col of cols) {
        if (!latest.sql.includes(`- '${col}'`)) {
          offenders.push(`${latest.file}: row_to_json over ${table} without stripping '${col}'`);
        }
      }
    }
    expect(offenders, offenders.join('; ')).toEqual([]);
  });
});

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
