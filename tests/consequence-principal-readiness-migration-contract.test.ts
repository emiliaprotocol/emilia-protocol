// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260723143500_consequence_principal_readiness.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('consequence-control database principal readiness migration', () => {
  it('uses the AEB owner only for AEB-owned DDL, then resets before PTE DDL', () => {
    expect(migration).toMatch(
      /GRANT ep_aeb_store_owner TO CURRENT_USER\s+WITH INHERIT FALSE, SET TRUE;\s+SET ROLE ep_aeb_store_owner;\s+DO \$aeb_preflight\$/,
    );
    expect(migration).toMatch(
      /SET ROLE ep_aeb_store_owner;[\s\S]+DO \$aeb_preflight\$[\s\S]+DO \$aeb_constraints\$[\s\S]+CREATE OR REPLACE FUNCTION ep_aeb_private\.principal_readiness\([\s\S]+RESET ROLE;\s+REVOKE ep_aeb_store_owner FROM CURRENT_USER;\s+DO \$pte_preflight\$[\s\S]+DO \$pte_constraints\$[\s\S]+CREATE OR REPLACE FUNCTION proposal_to_effect_private\.principal_readiness\(/,
    );
  });

  it('makes execute and recover mutually exclusive in both tenant maps', () => {
    expect(migration).toContain(
      'CONSTRAINT ep_aeb_tenant_principal_one_capability',
    );
    expect(migration).toContain(
      'CONSTRAINT proposal_to_effect_tenant_principal_one_capability',
    );
    expect(migration.match(/CHECK \(can_execute <> can_recover\)/g)).toHaveLength(2);
    expect(migration).toContain('AEB_PRINCIPAL_CAPABILITY_OVERLAP_PRESENT');
    expect(migration).toContain('PTE_PRINCIPAL_CAPABILITY_OVERLAP_PRESENT');
    expect(migration).toContain(
      'VALIDATE CONSTRAINT ep_aeb_tenant_principal_one_capability',
    );
    expect(migration).toContain(
      'VALIDATE CONSTRAINT proposal_to_effect_tenant_principal_one_capability',
    );
  });

  it('adds tenant-bound readiness RPCs that inspect SESSION_USER', () => {
    expect(migration).toContain(
      'CREATE OR REPLACE FUNCTION ep_aeb_private.principal_readiness(',
    );
    expect(migration).toContain(
      'CREATE OR REPLACE FUNCTION proposal_to_effect_private.principal_readiness(',
    );
    expect(migration.match(/principal_name = SESSION_USER/g)).toHaveLength(2);
    expect(migration.match(/SECURITY DEFINER/g)).toHaveLength(2);
    expect(migration.match(/SET search_path = ''/g)).toHaveLength(2);
    expect(migration).toContain("'20260723143500'::TEXT");
    expect(migration).toContain("'20260723150000'::TEXT");
  });

  it('checks exact role separation, RPC grants, and required schema objects', () => {
    for (const role of [
      'ep_aeb_executor',
      'ep_aeb_recovery',
      'proposal_to_effect_executor',
      'proposal_to_effect_recovery',
    ]) {
      expect(migration).toContain(`'${role}'`);
    }
    for (const rpc of [
      'ep_aeb_private.has_replay_fence(text,text,text)',
      'ep_aeb_private.get_status_head(text,text,text,text,text,text)',
      'ep_aeb_private.compare_and_advance_status_head(',
      'ep_aeb_private.claim_operation(text,text,text,text)',
      'proposal_to_effect_private.reserve_attempt(',
      'proposal_to_effect_private.recover_attempt(',
      'proposal_to_effect_private.lookup_attempt(',
    ]) {
      expect(migration).toContain(rpc);
    }
    expect(migration).toContain(
      "'proposal_to_effect_provider_evidence_attempt_fk_idx'",
    );
    expect(migration).toContain('convalidated');
  });

  it('keeps readiness unavailable to Supabase API roles', () => {
    expect(migration).toContain(
      'FROM PUBLIC, anon, authenticated, service_role;',
    );
    expect(migration).toContain(
      'TO ep_aeb_executor, ep_aeb_recovery;',
    );
    expect(migration).toContain(
      'TO proposal_to_effect_executor, proposal_to_effect_recovery;',
    );
  });
});
