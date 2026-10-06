// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  'supabase/migrations/20261005090000_canactid_scheme_transition.sql',
  'utf8',
);
const guide = readFileSync('docs/CANACTID-MIGRATION.md', 'utf8');

describe('CANACTID production cutover', () => {
  it('keeps Phase A backward compatible for a mixed-version deployment', () => {
    expect(migration).toContain('Phase A');
    expect(migration).toContain('Do not collapse the two phases into one batch');
    expect(migration.match(/\^\(caid\|canactid\):1:/gu)?.length).toBeGreaterThanOrEqual(8);
    expect(migration).toContain(
      "pg_catalog.replace(v_definition, '^caid:1:', '^(caid|canactid):1:')",
    );
    expect(migration).not.toContain('CREATE TRIGGER');
    expect(migration).not.toContain('require_current_canactid_on_write');
    expect(migration).toContain("'ep.canactid_migration_role'");
    expect(migration).toContain('GRANT ep_open_exposure_store_owner TO CURRENT_USER');
    expect(migration).toContain('SET ROLE ep_open_exposure_store_owner');
    expect(migration).toContain("'SET ROLE %I'");
    expect(migration).toContain('REVOKE ep_open_exposure_store_owner FROM CURRENT_USER');
  });

  it('requires a separately observed Phase B instead of an atomicity fiction', () => {
    expect(guide).toContain('separate protected-main Phase B migration');
    expect(guide).toMatch(/Do not put both phases in one migration\s+batch/);
    expect(guide).toMatch(/application-first would\s+fail against the old constraints/);
    expect(guide).toContain('planned write freeze');
  });
});
