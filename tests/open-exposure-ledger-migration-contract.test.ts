// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { contract } from '../scripts/db-contract.manifest.mjs';

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

  it('grants tenant-wide query RPCs only to the reader role', () => {
    const grants = migration.match(/GRANT EXECUTE ON FUNCTION[\s\S]*?;/g) ?? [];
    for (const functionName of [
      'read_exposure',
      'read_history',
      'sum_open',
      'list_aging',
      'list_deadlines',
    ]) {
      const grant = grants.find((statement) => statement.includes(`.${functionName}(JSONB)`));
      expect(grant, `missing grant for ${functionName}`).toBeDefined();
      expect(grant).toMatch(/TO ep_open_exposure_reader/);
      expect(grant).not.toMatch(/ep_open_exposure_(?:origin|executor|reconciler)/);
    }
  });

  it('publishes the exact live contract without widening schema-gate authority', () => {
    expect(contract.requiredQualifiedTables).toEqual(expect.arrayContaining([
      'open_exposure_private.tenant_principals',
      'open_exposure_private.ceilings',
      'open_exposure_private.exposures',
      'open_exposure_private.history',
      'open_exposure_private.reconciliation_tokens',
    ]));
    expect(contract.requiredQualifiedRpcs).toEqual(expect.arrayContaining([
      'open_exposure_private.register_ceiling(jsonb)',
      'open_exposure_private.reserve(jsonb)',
      'open_exposure_private.begin_invocation(jsonb)',
      'open_exposure_private.mark_indeterminate(jsonb)',
      'open_exposure_private.reconcile(jsonb)',
      'open_exposure_private.read_exposure(jsonb)',
      'open_exposure_private.read_history(jsonb)',
      'open_exposure_private.sum_open(jsonb)',
      'open_exposure_private.list_aging(jsonb)',
      'open_exposure_private.list_deadlines(jsonb)',
    ]));
    expect(contract.requiredReconcileAssertions.filter(
      (value) => value.includes(':open_exposure_private.')
        || value === 'contract:roles:open-exposure:least-privilege-membership-disjoint',
    )).toHaveLength(26);

    expect(migration).toMatch(
      /CREATE OR REPLACE FUNCTION public\.gov_open_exposure_security_assertions\(\)[\s\S]+SECURITY DEFINER[\s\S]+SET search_path = ''/,
    );
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION public\.gov_open_exposure_security_assertions\(\)[^;]+FROM PUBLIC, anon, authenticated, schema_gate/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.gov_open_exposure_security_assertions\(\)[^;]+TO service_role/,
    );
    expect(migration).toMatch(
      /FROM public\.gov_consequence_control_security_assertions\(\)[\s\S]+FROM public\.gov_open_exposure_security_assertions\(\)/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.gov_schema_reconcile_introspect\(\)[\s\S]+TO service_role, schema_gate/,
    );
    expect(migration).not.toMatch(
      /GRANT EXECUTE ON FUNCTION public\.gov_open_exposure_security_assertions\(\)[^;]+TO schema_gate/,
    );
    const privateGrants = migration.match(
      /GRANT[^;]+(?:SCHEMA open_exposure_private|open_exposure_private\.)[^;]+;/g,
    ) ?? [];
    for (const grant of privateGrants) {
      expect(grant).not.toMatch(/TO[^;]*\bservice_role\b/);
    }
  });

  it('pins effect entry to trusted time, immutable admission inputs, and one permit digest', () => {
    for (const field of [
      'program_version',
      'program_source_digest',
      'program_digest',
      'caid',
      'action_digest',
      'admission_snapshot_digest',
      'authorization_digest',
      'authorization_expires_at',
      'invocation_permit_digest',
    ]) {
      expect(migration).toMatch(new RegExp(`\\b${field}\\b`));
    }
    expect(migration).toContain('invoke_by <= window_end');
    expect(migration).toContain('invoke_by <= authorization_expires_at');
    expect(migration).toContain('extensions.gen_random_bytes(INTEGER)');
    expect(migration).toMatch(/begin_invocation[\s\S]+transaction_timestamp\(\)/);
    expect(migration).toMatch(/status = 'INVOKING'[\s\S]+reconciliation_required/);
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
