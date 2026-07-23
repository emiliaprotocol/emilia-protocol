// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PROPOSAL_TO_EFFECT_POSTGRES_DDL } from '../packages/gate/src/proposal-to-effect-postgres.ts';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260722220000_proposal_to_effect_attempt_store.sql',
    import.meta.url,
  ),
  'utf8',
);
const fkIndexMigration = readFileSync(
  new URL(
    '../supabase/migrations/20260722231500_proposal_to_effect_provider_evidence_fk_index.sql',
    import.meta.url,
  ),
  'utf8',
);
const recoveryTimestampPrecisionMigration = readFileSync(
  new URL(
    '../supabase/migrations/20260723201346_proposal_to_effect_recovery_timestamp_precision.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('Proposal-to-Effect consequence-attempt production migration', () => {
  it('installs the governed store DDL and forward-patches the current read contract', () => {
    const historicalInstallerDdl = PROPOSAL_TO_EFFECT_POSTGRES_DDL.replaceAll(
      'HH24:MI:SS.US"Z"',
      'HH24:MI:SS.MS"Z"',
    );
    expect(migration).toContain(historicalInstallerDdl);

    const readAttemptStart = PROPOSAL_TO_EFFECT_POSTGRES_DDL.indexOf(
      'CREATE OR REPLACE FUNCTION proposal_to_effect_private.read_attempt(',
    );
    const readAttemptEnd = PROPOSAL_TO_EFFECT_POSTGRES_DDL.indexOf(
      'CREATE OR REPLACE FUNCTION proposal_to_effect_private.recover_attempt(',
      readAttemptStart,
    );
    expect(readAttemptStart).toBeGreaterThanOrEqual(0);
    expect(readAttemptEnd).toBeGreaterThan(readAttemptStart);
    expect(recoveryTimestampPrecisionMigration).toContain(
      PROPOSAL_TO_EFFECT_POSTGRES_DDL.slice(
        readAttemptStart,
        readAttemptEnd,
      ).trim(),
    );
    expect(recoveryTimestampPrecisionMigration).not.toContain(
      'HH24:MI:SS.MS"Z"',
    );
  });

  it('keeps private custody tables forced-RLS and RPC-only', () => {
    for (const table of [
      'tenant_principals',
      'consequence_attempts',
      'provider_evidence',
    ]) {
      expect(migration).toContain(
        `ALTER TABLE proposal_to_effect_private.${table}\n  FORCE ROW LEVEL SECURITY`,
      );
    }
    expect(migration).toMatch(
      /REVOKE ALL ON ALL TABLES IN SCHEMA proposal_to_effect_private\s+FROM anon, authenticated, PUBLIC, service_role/,
    );
    expect(migration).not.toContain(
      'GRANT ALL ON TABLE proposal_to_effect_private.consequence_attempts TO service_role',
    );
  });

  it('uses dedicated executor and recovery roles instead of service_role RPC authority', () => {
    expect(migration).toContain('CREATE ROLE proposal_to_effect_executor NOLOGIN');
    expect(migration).toContain('CREATE ROLE proposal_to_effect_recovery NOLOGIN');
    expect(migration).not.toContain('TO service_role');
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION proposal_to_effect_private\.recover_attempt[\s\S]* TO proposal_to_effect_recovery;/,
    );
    expect(migration).not.toMatch(
      /GRANT EXECUTE ON FUNCTION proposal_to_effect_private\.recover_attempt[\s\S]* TO proposal_to_effect_executor;/,
    );
  });

  it('checks database-role tenant principals inside every callable RPC', () => {
    for (const fn of [
      'reserve_attempt',
      'transition_attempt',
      'heartbeat_attempt',
      'reconcile_attempt',
      'read_attempt',
      'recover_attempt',
    ]) {
      expect(migration).toContain(
        `CREATE OR REPLACE FUNCTION proposal_to_effect_private.${fn}`,
      );
    }
    expect(migration).toContain(
      'proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE)',
    );
    expect(migration).toContain(
      'proposal_to_effect_private.assert_tenant_principal(p_tenant_id, TRUE)',
    );
    expect(migration).toContain('SESSION_USER');
    expect(migration).toContain("'proposal_to_effect_executor'");
    expect(migration).toContain("'proposal_to_effect_recovery'");
    expect(migration).toMatch(
      /REVOKE EXECUTE ON FUNCTION proposal_to_effect_private\.guard_attempt_mutation\(\)\s+FROM anon, authenticated, PUBLIC, service_role;/,
    );
    expect(migration).toMatch(
      /REVOKE EXECUTE ON FUNCTION proposal_to_effect_private\.guard_evidence_mutation\(\)\s+FROM anon, authenticated, PUBLIC, service_role;/,
    );
  });

  it('fences ownership, terminals, evidence, leases, and replay identities in SQL', () => {
    expect(migration).toContain('PTE_TERMINAL_ATTEMPT_IMMUTABLE');
    expect(migration).toContain('PTE_OWNER_GENERATION_REFUSED');
    expect(migration).toContain('PTE_PROVIDER_EVIDENCE_IMMUTABLE');
    expect(migration).toContain('PTE_LEASE_REWIND_REFUSED');
    expect(migration).toContain('last_heartbeat_at');
    expect(migration).toContain('lease_expires_at');
    expect(migration).toContain('lease_expires_at <= pg_catalog.clock_timestamp()');
    expect(migration).toContain('p_expected_lease_expires_at');
    expect(migration).toContain(
      'UNIQUE (\n    tenant_id, provider_id, provider_account_id, environment, request_digest\n  )',
    );
    expect(migration).toContain(
      "WHEN state = 'RESERVED' THEN 'RESERVED'\n        ELSE 'INDETERMINATE'",
    );
    expect(migration).toContain(
      "state IN ('RESERVED', 'INVOKING', 'INDETERMINATE')",
    );
  });

  it('persists the complete authenticated provider-evidence binding', () => {
    for (const column of ['operation_id', 'caid', 'action_digest']) {
      expect(migration).toMatch(
        new RegExp(`CREATE TABLE[\\s\\S]*provider_evidence[\\s\\S]*\\b${column}\\b`),
      );
    }
  });

  it('covers the provider-evidence foreign key used by reconciliation maintenance', () => {
    expect(fkIndexMigration).toContain(
      'CREATE INDEX IF NOT EXISTS proposal_to_effect_provider_evidence_attempt_fk_idx',
    );
    expect(fkIndexMigration).toContain(
      'tenant_id,\n    provider_id,\n    provider_account_id,\n    environment,\n    attempt_id,\n    attempt_digest',
    );
  });

  it('makes mutation acknowledgements safely retryable after an ambiguous COMMIT', () => {
    expect(migration).toContain('idempotent_reservation');
    expect(migration).toContain('idempotent_transition');
    expect(migration).toContain('idempotent_reconciliation');
    expect(migration).toContain('idempotent_recovery');
  });
});
