// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migrationUrl = new URL(
  '../supabase/migrations/20260826120000_signoff_atomic_state_locks.sql',
  import.meta.url,
);

function functionBody(sql: string, name: string): string {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION public.${name}(`);
  expect(start, `${name} definition missing`).toBeGreaterThanOrEqual(0);
  const next = sql.indexOf('CREATE OR REPLACE FUNCTION public.', start + 1);
  return sql.slice(start, next < 0 ? sql.length : next);
}

describe('signoff atomic state-lock migration', () => {
  it('exists as one forward replacement for the complete lifecycle', () => {
    expect(existsSync(migrationUrl)).toBe(true);
  });

  it('replaces every trust-changing signoff RPC with canonical event names', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const expectedEvents = new Map([
      ['issue_challenge_atomic', 'challenge_issued'],
      ['approve_attestation_atomic', 'signoff_approved'],
      ['deny_challenge_atomic', 'signoff_denied'],
      ['revoke_challenge_atomic', 'challenge_revoked'],
      ['revoke_attestation_atomic', 'signoff_revoked'],
      ['expire_challenge_atomic', 'challenge_expired'],
      ['expire_attestation_atomic', 'signoff_expired'],
      ['consume_signoff_atomic', 'signoff_consumed'],
    ]);

    for (const [name, eventType] of expectedEvents) {
      const body = functionBody(sql, name);
      expect(body).toContain('FOR UPDATE');
      expect(body).toContain(`'${eventType}'`);
      expect(body).toMatch(/SECURITY DEFINER\s+SET search_path = ''/);
      expect(body).toMatch(/REVOKE ALL ON FUNCTION[\s\S]+FROM PUBLIC, anon, authenticated;/);
      expect(body).toMatch(/GRANT EXECUTE ON FUNCTION[\s\S]+TO service_role;/);
    }
  });

  it('locks and revalidates authoritative handshake policy, parties, authority, and expiry before issuing', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const body = functionBody(sql, 'issue_challenge_atomic');
    const handshakeLock = body.indexOf('FROM public.handshakes');
    const bindingLock = body.indexOf('FROM public.handshake_bindings');
    const policyLock = body.indexOf('FROM public.handshake_policies');
    const partyLock = body.indexOf('FROM public.handshake_parties');
    const authorityLock = body.indexOf('FROM public.authorities');
    const challengeInsert = body.indexOf('INSERT INTO public.signoff_challenges');
    const eventInsert = body.indexOf('INSERT INTO public.signoff_events');

    expect(handshakeLock).toBeGreaterThanOrEqual(0);
    expect(body.indexOf('FOR UPDATE', handshakeLock)).toBeGreaterThan(handshakeLock);
    expect(bindingLock).toBeGreaterThan(handshakeLock);
    expect(body.indexOf('FOR UPDATE', bindingLock)).toBeGreaterThan(bindingLock);
    expect(body).toContain('SIGNOFF_HANDSHAKE_NOT_VERIFIED');
    expect(body).toContain('SIGNOFF_BINDING_HASH_MISMATCH');
    expect(body).toContain('SIGNOFF_BINDING_EXPIRED');
    expect(body).toContain('SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED');
    expect(body).toContain("'handshake_verified:' || v_handshake.handshake_id::TEXT");
    expect(body).toContain('SIGNOFF_AUTHORITY_ALREADY_CONSUMED');
    expect(body).toContain('FROM public.handshake_consumptions');
    expect(policyLock).toBeGreaterThan(bindingLock);
    expect(body.indexOf('FOR UPDATE', policyLock)).toBeGreaterThan(policyLock);
    expect(body).toContain('public.signoff_policy_rules_hash(v_policy.rules)');
    expect(body).toContain('SIGNOFF_POLICY_HASH_MISMATCH');
    expect(body).toContain("v_policy.rules -> 'accountable_signoff'");
    expect(body).toContain('SIGNOFF_POLICY_BLOCK_INVALID');
    expect(body).toContain('SIGNOFF_POLICY_SCOPE_MISMATCH');
    expect(partyLock).toBeGreaterThan(policyLock);
    expect(body.indexOf('FOR UPDATE', partyLock)).toBeGreaterThan(partyLock);
    expect(body).toContain('SIGNOFF_CALLER_NOT_HANDSHAKE_PARTY');
    expect(body).toContain('SIGNOFF_ACCOUNTABLE_PARTY_AMBIGUOUS');
    expect(body).toContain('SIGNOFF_ACCOUNTABLE_PARTY_NOT_VERIFIED');
    expect(authorityLock).toBeGreaterThan(partyLock);
    expect(body.indexOf('FOR UPDATE', authorityLock)).toBeGreaterThan(authorityLock);
    expect(body).toContain('SIGNOFF_ACCOUNTABLE_AUTHORITY_UNAVAILABLE');
    expect(body).toContain('v_expires_at := LEAST(');
    expect(body).toContain('SIGNOFF_CHALLENGE_EXPIRY_INVALID');
    for (const forbidden of [
      'p_accountable_actor_ref',
      'p_signoff_policy_id',
      'p_signoff_policy_hash',
      'p_required_assurance',
      'p_allowed_methods',
    ]) {
      expect(body).not.toContain(forbidden);
    }
    expect(challengeInsert).toBeGreaterThan(authorityLock);
    // The challenge row must exist before the event's immediate challenge_id FK.
    expect(eventInsert).toBeGreaterThan(challengeInsert);
  });

  it('pins policy bytes and requires one-time server-side ceremony evidence', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const approve = functionBody(sql, 'approve_attestation_atomic');
    const consume = functionBody(sql, 'consume_signoff_atomic');

    expect(sql).toContain('CREATE OR REPLACE FUNCTION public.signoff_policy_rules_hash');
    expect(sql).toContain('CREATE TRIGGER enforce_pinned_handshake_policy_immutable');
    expect(sql).toContain('SIGNOFF_PINNED_POLICY_IMMUTABLE');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS public.signoff_ceremony_evidence');
    expect(sql).toContain('CREATE UNIQUE INDEX IF NOT EXISTS uq_signoff_attestation_ceremony_evidence');
    expect(sql).toContain('CREATE TRIGGER enforce_signoff_ceremony_evidence_immutable');

    for (const body of [approve, consume]) {
      expect(body).toContain('public.signoff_policy_rules_hash(v_policy.rules)');
      expect(body).toContain('SIGNOFF_POLICY_HASH_MISMATCH');
      expect(body).toContain('FROM public.authorities');
      expect(body).toContain('FROM public.signoff_ceremony_evidence');
      expect(body).toContain('SIGNOFF_CEREMONY_EVIDENCE_INVALID');
    }
    expect(approve).toContain('SIGNOFF_CEREMONY_EVIDENCE_REQUIRED');
    expect(approve).toContain('UPDATE public.signoff_ceremony_evidence');
    expect(approve).toContain('consumed_at = v_now');
  });

  it('replaces rank guards with exact edges, immutable authority facts, and RPC-only writes', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const challengeGuard = functionBody(sql, 'prevent_signoff_challenge_backward_status');
    const attestationGuard = functionBody(sql, 'prevent_signoff_attestation_backward_status');

    expect(challengeGuard).toContain('SIGNOFF_CHALLENGE_TRUST_FIELDS_IMMUTABLE');
    expect(challengeGuard).toContain('SIGNOFF_CHALLENGE_TRANSITION_INVALID');
    expect(challengeGuard).toContain("OLD.status = 'approved' AND NEW.status = 'consumed'");
    expect(challengeGuard).not.toContain('old_rank');
    expect(attestationGuard).toContain('SIGNOFF_ATTESTATION_TRUST_FIELDS_IMMUTABLE');
    expect(attestationGuard).toContain('SIGNOFF_ATTESTATION_TRANSITION_INVALID');
    expect(attestationGuard).toContain("OLD.status = 'approved'");
    expect(attestationGuard).not.toContain('old_rank');
    expect(sql).toContain('CREATE TRIGGER enforce_signoff_challenge_exact_transitions');
    expect(sql).toContain('CREATE TRIGGER enforce_signoff_attestation_exact_transitions');
    expect(sql).toContain('CREATE TRIGGER enforce_signoff_challenges_no_delete');
    expect(sql).toContain('CREATE TRIGGER enforce_signoff_attestations_no_delete');
    expect(sql).toContain('SIGNOFF_CHALLENGE_DELETE_FORBIDDEN');
    expect(sql).toContain('SIGNOFF_ATTESTATION_DELETE_FORBIDDEN');
    expect(sql).toMatch(/REVOKE INSERT, UPDATE, DELETE ON TABLE public\.signoff_challenges[\s\S]+service_role;/);
    expect(sql).toMatch(/REVOKE INSERT, UPDATE, DELETE ON TABLE public\.signoff_attestations[\s\S]+service_role;/);
    expect(sql).toMatch(/REVOKE INSERT, UPDATE, DELETE ON TABLE public\.signoff_consumptions[\s\S]+service_role;/);
    expect(sql).toContain('GRANT SELECT ON TABLE public.signoff_challenges, public.signoff_attestations');
  });

  it('locks and validates a challenge before any approval write', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const body = functionBody(sql, 'approve_attestation_atomic');
    const handshakeLock = body.indexOf('FROM public.handshakes');
    const bindingLock = body.indexOf('FROM public.handshake_bindings');
    const lock = body.indexOf('FROM public.signoff_challenges', bindingLock);
    const forUpdate = body.indexOf('FOR UPDATE', lock);
    const stateGuard = body.indexOf("v_challenge.status NOT IN ('challenge_issued', 'challenge_viewed')");
    const expiryGuard = body.indexOf('v_challenge.expires_at <= v_now');
    const bindingExpiryGuard = body.indexOf('SIGNOFF_BINDING_EXPIRED');
    const bindingWindowGuard = body.indexOf('SIGNOFF_CHALLENGE_OUTLIVES_BINDING');
    const bindingGuard = body.indexOf('SIGNOFF_CHALLENGE_BINDING_MISMATCH');
    const actorGuard = body.indexOf('SIGNOFF_CHALLENGE_ACTOR_MISMATCH');
    const methodGuard = body.indexOf('SIGNOFF_CHALLENGE_METHOD_NOT_ALLOWED');
    const assuranceGuard = body.indexOf('SIGNOFF_CHALLENGE_ASSURANCE_INSUFFICIENT');
    const attestationExpiryGuard = body.indexOf('SIGNOFF_ATTESTATION_EXPIRY_INVALID');
    const attestationInsert = body.indexOf('INSERT INTO public.signoff_attestations');
    const eventInsert = body.indexOf('INSERT INTO public.signoff_events');
    const challengeUpdate = body.indexOf('UPDATE public.signoff_challenges');

    expect(handshakeLock).toBeGreaterThanOrEqual(0);
    expect(body.indexOf('FOR UPDATE', handshakeLock)).toBeGreaterThan(handshakeLock);
    expect(bindingLock).toBeGreaterThan(handshakeLock);
    expect(body.indexOf('FOR UPDATE', bindingLock)).toBeGreaterThan(bindingLock);
    expect(body).toContain('SIGNOFF_HANDSHAKE_NOT_VERIFIED');
    expect(body).toContain('SIGNOFF_HANDSHAKE_EXPIRED');
    expect(body).toContain('SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED');
    expect(body).toContain("'handshake_verified:' || v_handshake.handshake_id::TEXT");
    expect(body).toContain('SIGNOFF_AUTHORITY_ALREADY_CONSUMED');
    expect(body).toContain('FROM public.handshake_consumptions');
    expect(lock).toBeGreaterThan(bindingLock);
    expect(forUpdate).toBeGreaterThan(lock);
    expect(body).toContain('SIGNOFF_CHALLENGE_NOT_FOUND');
    expect(stateGuard).toBeGreaterThan(forUpdate);
    expect(body).toContain('SIGNOFF_CHALLENGE_NOT_ATTESTABLE');
    expect(expiryGuard).toBeGreaterThan(stateGuard);
    expect(body).toContain('SIGNOFF_CHALLENGE_EXPIRED');
    expect(bindingGuard).toBeGreaterThan(bindingLock);
    expect(bindingExpiryGuard).toBeGreaterThan(bindingGuard);
    expect(bindingWindowGuard).toBeGreaterThan(bindingExpiryGuard);
    for (const guard of [actorGuard, methodGuard, assuranceGuard, attestationExpiryGuard]) {
      expect(guard).toBeGreaterThan(bindingWindowGuard);
    }
    for (const write of [attestationInsert, eventInsert, challengeUpdate]) {
      expect(write).toBeGreaterThan(attestationExpiryGuard);
    }
    expect(body).toContain('v_challenge.handshake_id, v_challenge.binding_hash');
    expect(body).toContain('pg_catalog.transaction_timestamp()');
  });

  it('locks and validates an attestation before any consume write', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const body = functionBody(sql, 'consume_signoff_atomic');
    const handshakeLock = body.indexOf('FROM public.handshakes');
    const bindingLock = body.indexOf('FROM public.handshake_bindings');
    const challengeLock = body.indexOf('FROM public.signoff_challenges', bindingLock);
    const lock = body.indexOf('FROM public.signoff_attestations');
    const forUpdate = body.indexOf('FOR UPDATE', lock);
    const stateGuard = body.indexOf("v_attestation.status <> 'approved'");
    const expiryGuard = body.indexOf('v_attestation.expires_at <= v_now');
    const authorityBindingGuard = body.indexOf('SIGNOFF_ATTESTATION_BINDING_MISMATCH');
    const bindingExpiryGuard = body.indexOf('SIGNOFF_BINDING_EXPIRED');
    const bindingWindowGuard = body.indexOf('SIGNOFF_CHALLENGE_OUTLIVES_BINDING');
    const bindingGuard = body.indexOf(
      'SIGNOFF_ATTESTATION_BINDING_MISMATCH',
      expiryGuard,
    );
    const actorGuard = body.indexOf('SIGNOFF_ATTESTATION_ACTOR_MISMATCH');
    const executionRefGuard = body.indexOf('SIGNOFF_EXECUTION_REF_REQUIRED');
    const eventInsert = body.indexOf('INSERT INTO public.signoff_events');
    const consumptionInsert = body.indexOf('INSERT INTO public.signoff_consumptions');
    const attestationUpdate = body.indexOf('UPDATE public.signoff_attestations');

    expect(handshakeLock).toBeGreaterThanOrEqual(0);
    expect(body.indexOf('FOR UPDATE', handshakeLock)).toBeGreaterThan(handshakeLock);
    expect(bindingLock).toBeGreaterThan(handshakeLock);
    expect(body.indexOf('FOR UPDATE', bindingLock)).toBeGreaterThan(bindingLock);
    expect(body).toContain('SIGNOFF_HANDSHAKE_NOT_VERIFIED');
    expect(body).toContain('SIGNOFF_HANDSHAKE_EXPIRED');
    expect(body).toContain('SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED');
    expect(body).toContain("'handshake_verified:' || v_handshake.handshake_id::TEXT");
    expect(body).toContain('SIGNOFF_AUTHORITY_ALREADY_CONSUMED');
    expect(challengeLock).toBeGreaterThan(bindingLock);
    expect(body.indexOf('FOR UPDATE', challengeLock)).toBeGreaterThan(challengeLock);
    expect(authorityBindingGuard).toBeGreaterThan(bindingLock);
    expect(bindingExpiryGuard).toBeGreaterThan(authorityBindingGuard);
    expect(bindingWindowGuard).toBeGreaterThan(bindingExpiryGuard);
    expect(lock).toBeGreaterThan(bindingLock);
    expect(forUpdate).toBeGreaterThan(lock);
    expect(body).toContain('SIGNOFF_ATTESTATION_NOT_FOUND');
    expect(body).toContain('SIGNOFF_CHALLENGE_NOT_CONSUMABLE');
    expect(stateGuard).toBeGreaterThan(forUpdate);
    expect(body).toContain('SIGNOFF_ATTESTATION_NOT_CONSUMABLE');
    expect(expiryGuard).toBeGreaterThan(stateGuard);
    expect(body).toContain('SIGNOFF_ATTESTATION_EXPIRED');
    expect(body).toContain('SIGNOFF_ATTESTATION_OUTLIVES_BINDING');
    for (const guard of [bindingGuard, actorGuard, executionRefGuard]) {
      expect(guard).toBeGreaterThan(expiryGuard);
    }
    for (const write of [eventInsert, consumptionInsert, attestationUpdate]) {
      expect(write).toBeGreaterThan(executionRefGuard);
    }
    expect(body).toContain('v_attestation.signoff_id, v_attestation.binding_hash');
    expect(body).toContain('INSERT INTO public.handshake_consumptions');
    expect(body).toContain("'signoff_execution'");
    expect(body).not.toMatch(/UPDATE public\.handshake_bindings[\s\S]+consumed_at = v_now/);
    expect(body).toContain('immutable verification marker');
    expect(body).toContain('RETURNING signoff_consumption_id INTO v_consumption_id');
    expect(body).toContain("'signoff_consumed'");
    expect(body).toContain('pg_catalog.transaction_timestamp()');
  });

  it('makes expiry an atomic locked state transition rather than telemetry', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const challenge = functionBody(sql, 'expire_challenge_atomic');
    const attestation = functionBody(sql, 'expire_attestation_atomic');

    const challengeLock = challenge.indexOf('FROM public.signoff_challenges');
    const challengeEvent = challenge.indexOf('INSERT INTO public.signoff_events');
    const challengeUpdate = challenge.indexOf('UPDATE public.signoff_challenges');
    expect(challengeLock).toBeGreaterThanOrEqual(0);
    expect(challenge.indexOf('FOR UPDATE', challengeLock)).toBeGreaterThan(challengeLock);
    expect(challenge).toContain("v_challenge.status NOT IN ('challenge_issued', 'challenge_viewed')");
    expect(challenge).toContain('SIGNOFF_CHALLENGE_NOT_EXPIRED');
    expect(challengeEvent).toBeGreaterThan(challengeLock);
    expect(challengeUpdate).toBeGreaterThan(challengeEvent);

    const challengeParentLock = attestation.indexOf('FROM public.signoff_challenges');
    const attestationLock = attestation.indexOf('FROM public.signoff_attestations', challengeParentLock);
    const attestationEvent = attestation.indexOf('INSERT INTO public.signoff_events');
    const attestationUpdate = attestation.indexOf('UPDATE public.signoff_attestations');
    expect(challengeParentLock).toBeGreaterThanOrEqual(0);
    expect(attestation.indexOf('FOR UPDATE', challengeParentLock)).toBeGreaterThan(challengeParentLock);
    expect(attestationLock).toBeGreaterThan(challengeParentLock);
    expect(attestation.indexOf('FOR UPDATE', attestationLock)).toBeGreaterThan(attestationLock);
    expect(attestation).toContain('SIGNOFF_ATTESTATION_BINDING_MISMATCH');
    expect(attestation).toContain('SIGNOFF_ATTESTATION_NOT_EXPIRABLE');
    expect(attestation).toContain('SIGNOFF_ATTESTATION_NOT_EXPIRED');
    expect(attestationEvent).toBeGreaterThan(attestationLock);
    expect(attestationUpdate).toBeGreaterThan(attestationEvent);
  });

  it('serializes handshake revocation on the same handshake then binding lock order', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const body = functionBody(sql, 'revoke_handshake_atomic');
    const handshakeLock = body.indexOf('FROM public.handshakes');
    const bindingLock = body.indexOf('FROM public.handshake_bindings');
    const eventInsert = body.indexOf('INSERT INTO public.handshake_events');
    const update = body.indexOf('UPDATE public.handshakes');

    expect(handshakeLock).toBeGreaterThanOrEqual(0);
    expect(body.indexOf('FOR UPDATE', handshakeLock)).toBeGreaterThan(handshakeLock);
    expect(bindingLock).toBeGreaterThan(handshakeLock);
    expect(body.indexOf('FOR UPDATE', bindingLock)).toBeGreaterThan(bindingLock);
    expect(body).toContain('FROM public.handshake_consumptions');
    expect(body).toContain('HANDSHAKE_ALREADY_CONSUMED');
    expect(body).not.toContain('HANDSHAKE_BINDING_ALREADY_CONSUMED');
    expect(body).toContain('HANDSHAKE_REVOCATION_ACTOR_UNAUTHORIZED');
    expect(eventInsert).toBeGreaterThan(bindingLock);
    expect(update).toBeGreaterThan(eventInsert);
    expect(body).toMatch(/SECURITY DEFINER\s+SET search_path = ''/);
    expect(body).toMatch(/REVOKE ALL ON FUNCTION[\s\S]+FROM PUBLIC, anon, authenticated;/);
    expect(body).toMatch(/GRANT EXECUTE ON FUNCTION[\s\S]+TO service_role;/);
  });

  it('keeps every lifecycle SECURITY DEFINER RPC service-role-only', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    for (const name of [
      'issue_challenge_atomic',
      'approve_attestation_atomic',
      'deny_challenge_atomic',
      'revoke_challenge_atomic',
      'revoke_attestation_atomic',
      'expire_challenge_atomic',
      'expire_attestation_atomic',
      'consume_signoff_atomic',
    ]) {
      const body = functionBody(sql, name);
      expect(body).toMatch(/SECURITY DEFINER\s+SET search_path = ''/);
      expect(body).toMatch(/REVOKE ALL ON FUNCTION[\s\S]+FROM PUBLIC, anon, authenticated;/);
      expect(body).toMatch(/GRANT EXECUTE ON FUNCTION[\s\S]+TO service_role;/);
    }
  });
});
