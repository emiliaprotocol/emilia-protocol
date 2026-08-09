// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260808233000_github_deployment_delivery_queue.sql', import.meta.url),
  'utf8',
).toLowerCase();

describe('GitHub deployment delivery queue migration', () => {
  it('persists exact bytes behind a tenant-bound RPC-only boundary', () => {
    expect(migration).toContain('create table consequence_actuator_private.github_deployment_deliveries');
    expect(migration).toContain('body bytea not null');
    expect(migration).toContain('force row level security');
    expect(migration).toContain('assert_tenant_principal(p_tenant_id)');
    expect(migration).toMatch(/revoke all on consequence_actuator_private\.github_deployment_deliveries[\s\S]*service_role/);
  });

  it('claims one due delivery with a lease and skip-locked concurrency', () => {
    expect(migration).toContain('claim_github_deployment_delivery');
    expect(migration).toContain('for update skip locked');
    expect(migration).toContain("state = 'processing'");
    expect(migration).toContain('lease_token = p_lease_token');
    expect(migration).toContain('lease_expires_at');
  });

  it('requires the live lease for terminal completion and retry', () => {
    expect(migration).toContain('complete_github_deployment_delivery');
    expect(migration).toContain('retry_github_deployment_delivery');
    expect(migration).toMatch(/where[\s\S]*lease_token = p_lease_token/);
    expect(migration).toContain("p_state not in ('approved', 'refused', 'indeterminate')");
    expect(migration).toMatch(/grant execute on function[\s\S]*to consequence_actuator_executor/);
  });
});
