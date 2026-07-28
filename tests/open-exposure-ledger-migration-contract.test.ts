// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migrationUrl = new URL(
  '../supabase/migrations/20260728210700_open_exposure_ledger.sql',
  import.meta.url,
);
const migration = readFileSync(migrationUrl, 'utf8');
const history = JSON.parse(readFileSync(
  new URL('../supabase/migration-history.v1.json', import.meta.url),
  'utf8',
));
const migrationHash = crypto.createHash('sha256')
  .update(readFileSync(migrationUrl))
  .digest('hex');

describe('Open Exposure Ledger PostgreSQL contract', () => {
  it('is pinned as a forward-pending migration in exact deployment order', () => {
    expect(history.forward_pending_versions).toContain('20260728210700');
    expect(history.deployment_sequence).toContain('20260728210700');
    expect(history.public_files['20260728210700_open_exposure_ledger.sql'])
      .toBe(migrationHash);
  });

  it('forces RLS and removes direct generic/runtime table authority', () => {
    for (const table of [
      'tenant_principals',
      'ceilings',
      'exposures',
      'history',
      'reconciliation_tokens',
    ]) {
      expect(migration).toContain(
        `ALTER TABLE open_exposure_private.${table} FORCE ROW LEVEL SECURITY`,
      );
    }
    expect(migration).toMatch(
      /REVOKE ALL ON ALL TABLES IN SCHEMA open_exposure_private[\s\S]+service_role/,
    );
    expect(migration).not.toMatch(/GRANT[^;]+ON TABLE[^;]+TO service_role/);
  });

  it('grants only role-specific mutation RPCs', () => {
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION open_exposure_private\.reserve\(JSONB\)[\s\S]+TO ep_open_exposure_origin/,
    );
    expect(migration).toMatch(
      /open_exposure_private\.begin_invocation\(JSONB\),[\s\S]+open_exposure_private\.mark_indeterminate\(JSONB\)[\s\S]+TO ep_open_exposure_executor/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION open_exposure_private\.reconcile\(JSONB\)[\s\S]+TO ep_open_exposure_reconciler/,
    );
    expect(migration).not.toMatch(/open_exposure_(?:blind_)?release/i);
  });

  it('locks all hierarchical ceilings before summing every open custody state', () => {
    expect(migration).toMatch(
      /ORDER BY ceilings\.scope, ceilings\.scope_value[\s\S]+FOR UPDATE/,
    );
    expect(migration).toContain(
      "exposures.status IN ('RESERVED', 'INVOKING', 'INDETERMINATE')",
    );
    expect(migration).toContain(
      'COALESCE(SUM(exposures.amount_minor), 0)',
    );
    expect(migration).toContain('v_ceiling_count <> 4');
  });

  it('makes history and idempotency responses immutable', () => {
    expect(migration).toMatch(
      /BEFORE UPDATE OR DELETE ON open_exposure_private\.history/,
    );
    expect(migration).toMatch(
      /BEFORE UPDATE OR DELETE ON open_exposure_private\.reconciliation_tokens/,
    );
    expect(migration).toContain("'reconciliation_token_conflict'");
    expect(migration).toContain("'operation_token_conflict'");
  });
});

