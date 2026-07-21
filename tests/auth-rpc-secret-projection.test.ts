// SPDX-License-Identifier: Apache-2.0
//
// Auth RPC — least-disclosure invariant (regression guard for the sweep finding).
//
// resolve_authenticated_actor() returns the entity that becomes `auth.entity` on
// EVERY authenticated request. The `entities` table carries sealed private-key
// material (`private_key_encrypted`, migration 078). The RPC MUST NOT return that
// material: no consumer reads it, but shipping it into every request's auth
// context (and into protocol-write telemetry logs) is a latent key-exposure whose
// only backstop would be name-pattern log redaction.
//
// This is a STATIC guard on the migration set, because the real control lives in
// SQL, not JS (the JS auth tests mock the RPC). It asserts the latest definition
// of resolve_authenticated_actor strips the sensitive keys, so a future migration
// that reintroduces a bare `row_to_json(v_entity)` for the entity fails CI.

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MIGRATIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../supabase/migrations',
);

const SENSITIVE_COLUMNS = ['private_key_encrypted', 'api_key_hash'];

// The latest migration file that (re)defines resolve_authenticated_actor wins —
// CREATE OR REPLACE means the highest-numbered definition is what runs.
function latestAuthRpcDefinition() {
  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort(); // numeric-prefixed names sort lexically in creation order
  let latest = null;
  for (const f of files) {
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, f), 'utf8');
    if (/FUNCTION\s+public\.resolve_authenticated_actor/i.test(sql)) {
      latest = { file: f, sql };
    }
  }
  return latest;
}

describe('auth RPC least-disclosure invariant', () => {
  const def = latestAuthRpcDefinition();

  it('a resolve_authenticated_actor definition exists in the migration set', () => {
    expect(def, 'no migration defines resolve_authenticated_actor').not.toBeNull();
  });

  it('the entity projection strips every sensitive column', () => {
    // Isolate the RETURN ... jsonb_build_object(...) that assembles the entity.
    // Whatever form it takes (row_to_json minus keys, explicit column list, a
    // safe view), the sensitive columns MUST NOT survive into the returned JSON.
    const sql = def.sql;

    // If the definition emits a raw row_to_json(v_entity) for the 'entity' key,
    // it MUST strip each sensitive column with jsonb `-`.
    const rawRowToJson = /'entity'\s*,\s*row_to_json\(\s*v_entity\s*\)/i.test(sql);
    if (rawRowToJson) {
      for (const col of SENSITIVE_COLUMNS) {
        expect(
          sql.includes(`- '${col}'`),
          `resolve_authenticated_actor returns row_to_json(v_entity) without stripping '${col}' (${def.file})`,
        ).toBe(true);
      }
    }
  });

  it('the sealed private key is never exposed by the auth RPC', () => {
    // The decisive assertion, independent of projection style: the returned
    // 'entity' object must not carry private_key_encrypted. Either the column is
    // stripped from row_to_json, or an explicit projection omits it.
    const sql = def.sql;
    const emitsRawRow = /'entity'\s*,\s*row_to_json\(\s*v_entity\s*\)(?!.*-\s*'private_key_encrypted')/is.test(sql);
    const stripsPrivateKey = sql.includes("- 'private_key_encrypted'");
    const selectsAllColumns = /SELECT\s+\*\s+INTO\s+v_entity/i.test(sql);

    // If it SELECT *s the entity AND emits row_to_json, it must strip the key.
    if (selectsAllColumns) {
      expect(
        stripsPrivateKey,
        `auth RPC SELECT *s the entity but does not strip private_key_encrypted (${def.file})`,
      ).toBe(true);
    }
    expect(emitsRawRow, `auth RPC emits an unstripped row_to_json(v_entity) (${def.file})`).toBe(false);
  });
});
