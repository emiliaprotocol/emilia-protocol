// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { auditMigrationBundle, readMigrationBundle } from '../scripts/schema-security-audit.mjs';

describe('static schema-security migration audit', () => {
  it('passes the checked-in migration bundle and emits bounded source evidence', () => {
    const result = auditMigrationBundle(readMigrationBundle());

    expect(result.status).toBe('passed');
    expect(result.source).toBe('checked-in supabase/migrations SQL');
    expect(result.source_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.migration_files.length).toBeGreaterThan(100);
    expect(result.checks.length).toBeGreaterThan(100);
    expect(result.limitations.some((line) => line.includes('not proof that production applied'))).toBe(true);
  });

  it('fails if a public table grant is appended to a secret/RPC-only table', () => {
    const migrations = readMigrationBundle();
    migrations.push({
      file: 'zzzz_test_public_grant.sql',
      sql: 'GRANT SELECT ON TABLE public.release_locks TO anon;',
    });

    const result = auditMigrationBundle(migrations);

    expect(result.status).toBe('failed');
    expect(result.failures.some((failure) => failure.name === 'no direct public table GRANT: release_locks')).toBe(true);
  });

  it('fails if the current source no longer reasserts a Release Lock public ACL revoke', () => {
    const migrations = readMigrationBundle();
    const target = migrations.find((migration) => migration.file.endsWith('_fortress_db_security_invariants.sql'));
    target.sql = target.sql.replace(
      'REVOKE ALL ON TABLE public.release_locks FROM PUBLIC, anon, authenticated, service_role;',
      '-- deliberately removed in fixture',
    );

    const result = auditMigrationBundle(migrations);

    expect(result.status).toBe('failed');
    expect(result.failures.some((failure) => failure.name === 'public table ACL revoked: release_locks')).toBe(true);
  });
});
