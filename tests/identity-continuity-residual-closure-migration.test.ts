// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260826160000_continuity_and_pairing_residual_closure.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('STRIX continuity residual closure migration', () => {
  it('requires the authenticated actor to be the active principal-bound successor', () => {
    expect(migration).toContain('p_actor_entity_id IS DISTINCT FROM p_new_entity_id');
    expect(migration).toContain("actor.entity_id = p_actor_entity_id");
    expect(migration).toContain("actor.status = 'active'");
    expect(migration).toContain('v_actor.principal_id IS DISTINCT FROM v_principal.id');
    expect(migration).toContain("'continuity.successor_control_verified'");
    expect(migration).toContain("proof.actor_id = v_claim.new_entity_id");
    expect(migration).not.toContain('v_actor.entity_id <> v_principal.principal_id');
  });

  it('serializes and conserves one immutable transfer budget per old identity', () => {
    expect(migration).toContain("'ep-continuity-dispute:' || v_old_entity.id::TEXT");
    expect(migration).toContain('FOR UPDATE;');
    expect(migration).toContain('ux_continuity_decisions_one_per_claim');
    expect(migration).toContain("'EP-IX-TRANSFER-LEDGER-v1'");
    expect(migration).toContain('v_allocated_budget + v_requested_budget > 1.0');
    expect(migration).toContain('continuity_decisions_append_only');
    expect(migration).toContain('REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.continuity_decisions');
  });

  it('withdraws state and appends audit inside one owner-only RPC', () => {
    const start = migration.indexOf('CREATE OR REPLACE FUNCTION public.withdraw_continuity_claim_atomic');
    const end = migration.indexOf('$continuity_withdrawal$;', start);
    const withdrawal = migration.slice(start, end);

    expect(withdrawal).toContain('FOR UPDATE');
    expect(withdrawal).toContain("SET status = 'withdrawn'");
    expect(withdrawal).toContain("'continuity.withdrawn'");
    expect(withdrawal).toContain('v_actor.principal_id IS DISTINCT FROM v_claim.principal_id');
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION public.withdraw_continuity_claim_atomic(TEXT, TEXT, TEXT)',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.withdraw_continuity_claim_atomic(TEXT, TEXT, TEXT)',
    );
  });

  it('keeps the pre-closure cores owner-only', () => {
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION public.file_continuity_claim_atomic_pre_successor_proof(',
    );
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION public.resolve_continuity_atomic_pre_budget_conservation(',
    );
    expect(migration).toMatch(/pre_successor_proof\([\s\S]*?FROM PUBLIC, anon, authenticated, service_role;/);
    expect(migration).toMatch(/pre_budget_conservation\([\s\S]*?FROM PUBLIC, anon, authenticated, service_role;/);
  });
});
