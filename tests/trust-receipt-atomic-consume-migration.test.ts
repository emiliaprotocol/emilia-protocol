// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260719125500_trust_receipt_atomic_consume.sql', import.meta.url),
  'utf8',
);
const closure = readFileSync(
  new URL(
    '../supabase/migrations/20260826140000_strix_rls_and_lifecycle_fortress_db_security_invariants.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('generic Trust Receipt atomic consume migration', () => {
  it('locks registry facts and appends consume in one security-definer transaction', () => {
    expect(migration).toContain('p_registry_bindings JSONB');
    expect(migration).toContain('FROM public.approver_credentials ac');
    expect(migration).toContain('FROM public.authorities a');
    expect(migration).toContain("a.subject_ref = binding ->> 'approver_id'");
    expect(migration).toContain("count(DISTINCT binding ->> 'approver_id')");
    expect(migration).toContain('FOR UPDATE');
    expect(migration).toContain("'guard.trust_receipt.consumed'");
    expect(migration).toContain("v_created ->> 'action_type' = 'policy_rollout'");
    expect(migration).toMatch(/LANGUAGE plpgsql\s+SECURITY DEFINER\s+SET search_path = ''/);
  });

  it('is service-role only', () => {
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION public\.consume_trust_receipt_authorized[\s\S]+FROM PUBLIC, anon, authenticated;/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.consume_trust_receipt_authorized[\s\S]+TO service_role;/,
    );
  });

  it('serializes decision and consume events on the immutable creation row', () => {
    const triggerStart = closure.indexOf(
      'CREATE OR REPLACE FUNCTION public.serialize_guard_receipt_lifecycle_event()',
    );
    const triggerEnd = closure.indexOf(
      'ALTER FUNCTION public.consume_signoff_atomic(',
      triggerStart,
    );
    const trigger = closure.slice(triggerStart, triggerEnd);
    const creationLock = trigger.indexOf('FOR UPDATE OF created_event');
    const consumedCheck = trigger.indexOf("'guard.trust_receipt.consumed'", creationLock);
    const rejectionCheck = trigger.indexOf(
      'public.guard_receipt_has_bound_rejection(',
      creationLock,
    );

    expect(triggerStart).toBeGreaterThanOrEqual(0);
    expect(creationLock).toBeGreaterThanOrEqual(0);
    expect(consumedCheck).toBeGreaterThan(creationLock);
    expect(rejectionCheck).toBeGreaterThan(creationLock);
    expect(trigger).toContain("NEW.event_type IN ('guard.signoff.approved', 'guard.signoff.rejected')");
    expect(trigger).toContain("RAISE EXCEPTION 'trust_receipt_already_consumed'");
    expect(trigger).toContain("RAISE EXCEPTION 'trust_receipt_signoff_rejected'");
    expect(trigger).toContain('pg_catalog.clock_timestamp()');
    expect(closure).toContain('CREATE TRIGGER serialize_guard_receipt_lifecycle');
  });

  it('binds the durable rejection to creator, request, approver, and exact action', () => {
    expect(closure).toContain("request_event.actor_id = p_creator_actor_id");
    expect(closure).toContain(
      "rejection_event.after_state ->> 'approved_action_hash' = p_action_hash",
    );
    expect(closure).toMatch(
      /rejection_event\.after_state ->> 'signoff_id'\s+= request_event\.after_state ->> 'signoff_id'/,
    );
    expect(closure).toContain("request_event.after_state #>> '{quorum,approver_id}'");
    expect(closure).toMatch(
      /REVOKE ALL ON FUNCTION public\.guard_receipt_has_bound_rejection\([\s\S]+service_role;/,
    );
  });

  it('rechecks receipt, authority, and credential windows with post-lock wall-clock time', () => {
    const start = closure.indexOf(
      'CREATE OR REPLACE FUNCTION public.consume_trust_receipt_authorized(',
    );
    const end = closure.indexOf(
      'ALTER FUNCTION public.activate_policy_rollout_authorized(',
      start,
    );
    const wrapper = closure.slice(start, end);
    const lockedStateMachine = wrapper.indexOf(
      'public.consume_trust_receipt_authorized_state_locked_v1(',
    );
    const wallClock = wrapper.indexOf('pg_catalog.clock_timestamp()');
    const authorityRead = wrapper.indexOf('JOIN public.authorities AS authority');
    const credentialRead = wrapper.indexOf(
      'LEFT JOIN public.approver_credentials AS credential',
    );

    expect(closure).toContain(
      'RENAME TO consume_trust_receipt_authorized_state_locked_v1',
    );
    expect(lockedStateMachine).toBeGreaterThanOrEqual(0);
    expect(wallClock).toBeGreaterThan(lockedStateMachine);
    expect(authorityRead).toBeGreaterThan(wallClock);
    expect(credentialRead).toBeGreaterThan(authorityRead);
    expect(wrapper).toContain('authority.valid_to > v_checked_at');
    expect(wrapper).toContain('credential.valid_to > v_checked_at');
    expect(wrapper).toContain("'guard.trust_receipt.consume_validity_checked'");
    expect(wrapper).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.consume_trust_receipt_authorized\([\s\S]+TO service_role;/,
    );
    expect(closure).toMatch(
      /REVOKE ALL ON FUNCTION public\.consume_trust_receipt_authorized_state_locked_v1\([\s\S]+service_role;/,
    );
  });
});
