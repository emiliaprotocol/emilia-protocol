// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationPath = path.resolve(
  process.cwd(),
  'supabase/migrations/20260718050000_release_lock.sql',
);
const sql = fs.readFileSync(migrationPath, 'utf8');

const tables = [
  'release_locks',
  'release_lock_versions',
  'release_lock_draw_actions',
  'release_lock_round_acceptances',
  'release_lock_contact_bindings',
  'release_lock_invitations',
  'release_lock_sessions',
  'release_lock_pairings',
  'release_lock_registration_challenges',
  'release_lock_credentials',
  'release_lock_action_challenges',
  'release_lock_decisions',
  'release_lock_decision_invalidations',
  'release_lock_effects',
];

function functionBody(name) {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION public.${name}(`);
  expect(start, `${name} must exist`).toBeGreaterThanOrEqual(0);
  const end = sql.indexOf('\n$$;', start);
  expect(end, `${name} must have a body terminator`).toBeGreaterThan(start);
  return sql.slice(start, end);
}

describe('Release Lock migration contract', () => {
  it('keeps every table service-only behind forced RLS', () => {
    for (const table of tables) {
      expect(sql).toContain(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;`);
      expect(sql).toContain(`ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY;`);
      expect(sql).toContain(
        `REVOKE ALL ON TABLE public.${table} FROM PUBLIC, anon, authenticated, service_role;`,
      );
    }
    expect(sql).not.toMatch(/GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL).*ON TABLE/i);
  });

  it('locks every SECURITY DEFINER search path and grants RPCs only to service_role', () => {
    const functions = [...sql.matchAll(
      /CREATE OR REPLACE FUNCTION public\.([a-z0-9_]+)\(/g,
    )].map((match) => match[1]);
    expect(functions.length).toBeGreaterThan(10);
    for (const name of functions) {
      const body = functionBody(name);
      if (name !== 'release_lock_refuse_immutable_mutation') {
        expect(body).toContain('SECURITY DEFINER');
      }
      expect(body).toContain('SET search_path = pg_catalog, public, pg_temp');
    }
    expect(sql).not.toMatch(/GRANT EXECUTE .* TO (?:PUBLIC|anon|authenticated)/);
  });

  it('stores only capability digests and one-time consumption timestamps', () => {
    expect(sql).toContain('token_digest            TEXT NOT NULL UNIQUE');
    expect(sql).toContain('exchanged_at            TIMESTAMPTZ');
    expect(sql).toContain('consumed_at             TIMESTAMPTZ');
    expect(sql).not.toMatch(/\braw_(?:token|contact|identifier)\b/i);
    expect(functionBody('release_lock_exchange_invitation')).toContain(
      'SET exchanged_at = clock_timestamp()',
    );
    expect(functionBody('release_lock_exchange_invitation')).toContain(
      'v_contact.verification_expires_at',
    );
    expect(functionBody('release_lock_create_pending')).toContain(
      "(v_contact->>'verification_expires_at')::TIMESTAMPTZ < p_max_expires_at",
    );
    const createPairing = functionBody('release_lock_create_pairing');
    const exchangePairing = functionBody('release_lock_exchange_pairing');
    expect(createPairing).toContain("p_expires_at > clock_timestamp() + INTERVAL '5 minutes'");
    expect(createPairing).toContain('v_session.scope_round');
    expect(createPairing).toContain('FOR UPDATE');
    expect(createPairing).toContain('v_lock.current_version');
    expect(createPairing).toContain('v_action_hash');
    expect(createPairing).toContain('v_lock.status');
    expect(exchangePairing).toContain('FOR UPDATE');
    expect(exchangePairing).toContain('SET exchanged_at = clock_timestamp()');
    expect(exchangePairing).toContain('v_pairing.round IS DISTINCT FROM p_expected_round');
    expect(exchangePairing).toContain(
      'v_lock.current_version IS DISTINCT FROM v_pairing.version',
    );
    expect(exchangePairing).toContain(
      'v_lock.status IS DISTINCT FROM v_pairing.lock_status',
    );
    expect(exchangePairing).toContain(
      'v_current_action_hash IS DISTINCT FROM v_pairing.action_hash',
    );
    expect(exchangePairing).toContain('scope_round');
    expect(exchangePairing).toContain('scope_version');
    expect(exchangePairing).toContain('scope_action_hash');
    expect(sql).toContain('release_lock_pairings_one_live_idx');
    expect(sql).toContain(
      'ON public.release_lock_pairings (source_session_id, role, round, version)',
    );
    expect(sql).toContain(
      'WHERE exchanged_at IS NULL AND revoked_at IS NULL',
    );
    for (const name of [
      'release_lock_action_check_context',
      'release_lock_store_action_challenge',
      'release_lock_load_action_challenge',
      'release_lock_record_approval',
    ]) {
      const body = functionBody(name);
      expect(body).toContain('v_session.scope_round IS DISTINCT FROM p_round');
      expect(body).toContain('v_session.scope_version IS NOT NULL');
      expect(body).toContain('v_session.scope_action_hash IS DISTINCT FROM');
    }
  });

  it('persists invitations disabled and atomically activates or revokes them', () => {
    expect(sql).toContain('activated_at            TIMESTAMPTZ');
    expect(sql).toContain('delivery_receipt_digest TEXT');
    expect(sql).toContain('revoked_at              TIMESTAMPTZ');
    const create = functionBody('release_lock_create_pending');
    const activate = functionBody('release_lock_activate_invitations');
    const cancel = functionBody('release_lock_cancel_pending');
    const exchange = functionBody('release_lock_exchange_invitation');
    expect(create).toContain("'invitation_state', 'pending_activation'");
    expect(activate).toContain('jsonb_array_length(p_invitation_ids) <> 2');
    expect(activate).toContain('jsonb_array_length(p_delivery_receipts) <> 2');
    expect(activate).toContain('FOR UPDATE');
    expect(activate).toContain('SET activated_at = clock_timestamp()');
    expect(activate).toContain('delivery_receipt_digest');
    expect(activate).toContain(
      "'EP-RELEASE-LOCK-INVITATION-DELIVERY-v1'",
    );
    expect(activate).toContain("RAISE EXCEPTION 'RL_INVITATION_INACTIVE'");
    expect(cancel).toContain('SET revoked_at = clock_timestamp()');
    expect(cancel).toContain('AND exchanged_at IS NULL');
    expect(cancel).toContain("SET status = 'expired'");
    expect(exchange).toContain('v_invitation.activated_at IS NULL');
    expect(exchange).toContain('v_invitation.revoked_at IS NOT NULL');
    expect(exchange).toContain('v_invitation.delivery_receipt_digest IS NULL');
  });

  it('requires two externally verified and distinct authority subjects', () => {
    expect(sql).toContain('authority_subject_digest TEXT NOT NULL');
    expect(sql).toContain('UNIQUE (lock_id, authority_subject_digest)');
    expect(sql).toContain('authority_provider      TEXT NOT NULL');
    expect(sql).toContain('authority_key_id        TEXT NOT NULL');
    expect(sql).toContain('authority_reference     TEXT NOT NULL');
    expect(sql).toContain('authority_assertion     JSONB NOT NULL');
    expect(sql).toContain('authority_signature     TEXT NOT NULL');
    expect(sql).toContain('authority_assertion_digest TEXT NOT NULL');
    expect(sql).toContain('authority_contact_binding_digest TEXT NOT NULL');
    expect(sql).toContain("'EP-RELEASE-LOCK-AUTHORITY-ASSERTION-v1'");
    const create = functionBody('release_lock_create_pending');
    expect(create).toContain(
      "count(DISTINCT value->>'authority_subject_digest')",
    );
    expect(create).toContain("RAISE EXCEPTION 'RL_AUTHORITY_REUSED'");
    expect(create).toContain(
      "(v_contact->>'authority_expires_at')::TIMESTAMPTZ < p_max_expires_at",
    );
  });

  it('separates CO acceptance from draw release and reserves no CO effect', () => {
    expect(sql).toContain("co_action->>'payment_authorization' = 'false'");
    expect(sql).toContain("draw_action->>'custodian_eligibility' = 'after_complete_draw_release_round'");
    const approval = functionBody('release_lock_record_approval');
    const coBranch = approval.slice(
      approval.indexOf("IF p_round = 'CO_ACCEPTED' THEN", approval.indexOf('v_acceptance_digest')),
      approval.indexOf("IF v_draw.draw_action->>'custodian_eligibility'"),
    );
    expect(coBranch).toContain("SET status = 'co_accepted'");
    expect(coBranch).toContain("'payment_authorized', false");
    expect(coBranch).toContain("'invoke_effect', false");
    expect(coBranch).not.toContain('INSERT INTO public.release_lock_effects');
    expect(approval).toContain('INSERT INTO public.release_lock_effects');
    expect(approval).toContain("'invoke_effect', true");
  });

  it('atomically consumes challenge, updates counter, inserts decision, and transitions', () => {
    const approval = functionBody('release_lock_record_approval');
    expect(approval).toContain('FROM public.release_locks');
    expect(approval).toContain('FOR UPDATE;');
    expect(approval).toContain('SET consumed_at = clock_timestamp()');
    expect(approval).toContain('SET sign_count = p_new_sign_count');
    expect(approval).toContain('INSERT INTO public.release_lock_decisions');
    expect(approval).toContain(
      'p_submitted_answer_digest IS DISTINCT FROM v_challenge.answer_digest',
    );
    expect(approval).toContain('p_challenge_id');
    expect(approval).toContain('RL_CREDENTIAL_REUSED');
    expect(approval).toContain('RL_CONTACT_REUSED');
    expect(approval).toContain('RL_APPROVAL_LIMIT');
  });

  it('invalidates both rounds on amendment and requires a fresh draw', () => {
    const amendment = functionBody('release_lock_amend');
    expect(amendment).toContain('invalidated_round');
    expect(amendment).toContain('d.round');
    expect(amendment).not.toContain("d.round = 'CO_ACCEPTED'");
    expect(amendment).toContain('UPDATE public.release_lock_action_challenges');
    expect(amendment).toContain('UPDATE public.release_lock_pairings');
    const pairingRevocation = amendment.slice(
      amendment.indexOf('UPDATE public.release_lock_pairings'),
      amendment.indexOf('UPDATE public.release_lock_sessions'),
    );
    expect(pairingRevocation).toContain('WHERE lock_id = p_lock_id');
    expect(pairingRevocation).toContain('AND exchanged_at IS NULL');
    expect(pairingRevocation).toContain('AND revoked_at IS NULL');
    expect(pairingRevocation).not.toContain('version = p_expected_version');
    expect(amendment).toContain('UPDATE public.release_lock_sessions');
    expect(amendment).toContain('scope_version IS NOT NULL');
    expect(amendment).toContain("status = 'co_pending'");
    expect(amendment).toContain("'draw_staged', false");
  });

  it('bounds effect reservation retries and never retries a claimed effect', () => {
    expect(sql).toContain('reservation_expires_at  TIMESTAMPTZ NOT NULL');
    expect(sql).toContain('reservation_attempts    INTEGER NOT NULL DEFAULT 1');
    expect(sql).toContain('CHECK (reservation_attempts BETWEEN 1 AND 3)');
    expect(sql).toContain('claim_attempts          INTEGER NOT NULL DEFAULT 0');
    const claim = functionBody('release_lock_claim_effect_binding');
    const recover = functionBody('release_lock_recover_effect');
    const outcome = functionBody('release_lock_record_effect_outcome');
    expect(claim).toContain(
      "'EP-RELEASE-LOCK-EFFECT-CONTRACT-v1'",
    );
    expect(claim).toContain(
      "p_effect_contract->'payees' @> v_draw.draw_action->'payees'",
    );
    expect(claim).toContain(
      "p_effect_contract#>'{evidence,lien_waivers}'",
    );
    expect(claim).toContain(
      'v_effect.reservation_expires_at <= clock_timestamp()',
    );
    expect(claim).toContain('v_effect.claimed_at IS NOT NULL');
    expect(claim).toContain('claim_attempts = claim_attempts + 1');
    expect(recover).toContain("'mode', 'execute'");
    expect(recover).toContain("'mode', 'reconcile'");
    expect(recover).toContain("'mode', 'terminal'");
    expect(recover).toContain('v_effect.claimed_at IS NOT NULL');
    expect(recover).toContain('v_effect.reservation_attempts >= 3');
    expect(recover).toContain(
      "v_retry_expires_at := clock_timestamp() + INTERVAL '2 minutes'",
    );
    expect(recover).toContain("SET status = 'released'");
    expect(outcome).toContain("'no_effect'");
    expect(outcome).toContain("'unknown_effect'");
    expect(outcome).toContain("SET status = 'indeterminate'");
    expect(outcome).toContain("SET status = 'effect_refused'");
    expect(outcome).toContain('claimed_at = NULL');
  });

  it('leaves legacy reconciliation helpers uncallable by the application role', () => {
    const load = functionBody('release_lock_reconciliation_context');
    const record = functionBody('release_lock_record_reconciliation');
    expect(load).toContain("v_effect.status NOT IN ('claimed', 'indeterminate')");
    expect(record).toContain("v_effect.status NOT IN ('claimed', 'indeterminate')");
    expect(sql).not.toContain(
      'GRANT EXECUTE ON FUNCTION public.release_lock_reconciliation_context(TEXT)',
    );
    expect(sql).not.toContain(
      'GRANT EXECUTE ON FUNCTION public.release_lock_record_reconciliation(TEXT, TEXT, JSONB)',
    );
  });

  it('exports checkable binding metadata without invitation or session capabilities', () => {
    const evidence = functionBody('release_lock_evidence');
    expect(evidence).not.toContain('release_lock_invitations');
    expect(evidence).not.toContain('release_lock_sessions');
    expect(evidence).toContain("'identifier_digest', c.identifier_digest");
    expect(evidence).toContain(
      "'verification_proof_digest', c.verification_proof_digest",
    );
    expect(evidence).toContain("'authority_assertion', c.authority_assertion");
    expect(evidence).toContain("'authority_signature', c.authority_signature");
    expect(evidence).toContain(
      "'authority_assertion_digest', c.authority_assertion_digest",
    );
    expect(evidence).toContain(
      "'authority_subject_digest', c.authority_subject_digest",
    );
    expect(evidence).toContain("'external_identity_proof_required', true");
    expect(evidence).not.toMatch(/'identifier',\s*c\./);
    expect(evidence).not.toContain('public_key_cose');
    expect(evidence).toContain('round_acceptances');
    expect(evidence).toContain('draw_release_actions');
    expect(evidence).toContain(
      "'reservation_expires_at', e.reservation_expires_at",
    );
    expect(evidence).toContain(
      "'effect_contract_digest', e.effect_contract_digest",
    );
    expect(evidence).toContain("'recovery_evidence', e.recovery_evidence");
  });

  it('enforces round scope in participant views and portable evidence', () => {
    const view = functionBody('release_lock_participant_view');
    expect(view).toContain('v_session.lock_id IS DISTINCT FROM p_lock_id');
    expect(view).toContain('v_session.revoked_at IS NOT NULL');
    expect(view).toContain('v_session.expires_at <= clock_timestamp()');
    const response = view.slice(view.indexOf('RETURN jsonb_build_object'));
    expect(response).not.toContain('identifier_digest');
    expect(response).not.toContain('token_digest');
    expect(view).toContain(
      'v_session.scope_round IS NULL OR d.round = v_session.scope_round',
    );
    expect(view).toContain(
      'v_session.scope_round IS NULL OR a.round = v_session.scope_round',
    );
    expect(view).toContain(
      "WHEN v_session.scope_round = 'CO_ACCEPTED' OR v_draw.lock_id IS NULL THEN NULL",
    );
    expect(view).toContain(
      "IF v_session.scope_round IS NULL OR v_session.scope_round = 'DRAW_RELEASE' THEN",
    );
    expect(view).toContain("'co_scope_complete'");
    expect(sql).toContain(
      'REVOKE ALL ON FUNCTION public.release_lock_participant_view(TEXT, TEXT)',
    );
    expect(sql).toContain(
      'GRANT EXECUTE ON FUNCTION public.release_lock_participant_view(TEXT, TEXT)',
    );
    const evidence = functionBody('release_lock_participant_evidence');
    expect(evidence).toContain('v_session.lock_id IS DISTINCT FROM p_lock_id');
    expect(evidence).toContain(
      'v_evidence := public.release_lock_evidence(p_lock_id, v_lock.organization_id)',
    );
    expect(evidence).toContain("'draw_release_actions', '[]'::JSONB");
    expect(evidence).toContain("'effects', '[]'::JSONB");
    expect(evidence).toContain(
      "WHERE value->>'round' = v_session.scope_round",
    );
    expect(evidence).toContain(
      'v_current_action_hash IS DISTINCT FROM v_session.scope_action_hash',
    );
  });
});
