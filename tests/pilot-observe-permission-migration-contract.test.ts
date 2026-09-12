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

  it('pins the migration in the deployed remote history', () => {
    const migrationBytes = readFileSync(migrationUrl);
    const history = JSON.parse(readFileSync(historyUrl, 'utf8'));
    const hash = crypto.createHash('sha256').update(migrationBytes).digest('hex');

    // Later confirmed deployments may advance the registry without changing
    // this pilot migration's identity, contents, or applied status.
    expect(history.as_of).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    const observedDate = Date.parse(`${history.as_of}T00:00:00.000Z`);
    expect(Number.isFinite(observedDate)).toBe(true);
    expect(new Date(observedDate).toISOString().slice(0, 10)).toBe(history.as_of);
    expect(observedDate).toBeGreaterThanOrEqual(Date.parse('2026-08-26T00:00:00.000Z'));

    expect(history.remote_head).toMatch(/^\d{14}$/);
    expect(BigInt(history.remote_head)).toBeGreaterThanOrEqual(20260826130000n);
    expect(Array.isArray(history.remote_versions)).toBe(true);
    const remoteVersions = history.remote_versions as string[];
    expect(remoteVersions.length).toBeGreaterThan(0);
    for (const version of remoteVersions) expect(version).toMatch(/^\d+$/);
    // Legacy versions are short numeric IDs, so compare numerically rather
    // than assuming every remote migration has a fourteen-digit timestamp.
    const largestRemoteVersion = remoteVersions.reduce((largest, version) =>
      BigInt(version) > BigInt(largest) ? version : largest);
    expect(history.remote_head).toBe(largestRemoteVersion);
    expect(history.remote_versions).toContain(history.remote_head);
    expect(history.remote_versions).toContain('20260826010000');
    expect(history.forward_pending_versions).not.toContain('20260826010000');
    expect(history.retroactive_pending_versions).not.toContain('20260826010000');
    expect(history.deployment_sequence).not.toContain('20260826010000');
    expect(history.public_files['20260826010000_pilot_observe_permission.sql']).toBe(hash);
  });
});
