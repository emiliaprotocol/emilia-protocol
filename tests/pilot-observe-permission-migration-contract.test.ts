// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migrationUrl = new URL(
  '../supabase/migrations/20260826010000_pilot_observe_permission.sql',
  import.meta.url,
);
const historyUrl = new URL('../supabase/migration-history.v1.json', import.meta.url);

describe('pilot observe permission forward migration', () => {
  it('exists as a forward-only migration', () => {
    expect(existsSync(migrationUrl)).toBe(true);
  });

  it('upgrades only active, server-marked pilot keys with an empty permission set', () => {
    const migration = readFileSync(migrationUrl, 'utf8');

    expect(migration).toContain("SET permissions = '[\"observe\"]'::jsonb");
    expect(migration).toContain('FROM public.entities AS e');
    expect(migration).toContain('k.entity_id = e.id');
    expect(migration).toContain('k.revoked_at IS NULL');
    expect(migration).toContain("COALESCE(k.permissions, '[]'::jsonb) = '[]'::jsonb");
    expect(migration).toContain("e.metadata->>'pilot_sandbox' = 'true'");
    expect(migration).toContain("e.metadata->>'scope' = 'observe'");
    expect(migration).not.toMatch(/SET\s+revoked_at/i);
  });

  it('pins the migration in the pending deployment history', () => {
    const migrationBytes = readFileSync(migrationUrl);
    const history = JSON.parse(readFileSync(historyUrl, 'utf8'));
    const hash = crypto.createHash('sha256').update(migrationBytes).digest('hex');

    expect(history.as_of).toBe('2026-08-26');
    expect(history.forward_pending_versions).toContain('20260826010000');
    expect(history.deployment_sequence).toContain('20260826010000');
    expect(history.public_files['20260826010000_pilot_observe_permission.sql']).toBe(hash);
  });
});
