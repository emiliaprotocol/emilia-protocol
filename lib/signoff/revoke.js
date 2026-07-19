/**
 * EP Signoff — Revocation logic for challenges and attestations.
 *
 * revokeChallenge() revokes a pending challenge.
 * revokeAttestation() revokes an approved attestation.
 *
 * Both verify current status allows revocation, use getServiceClient()
 * for writes (lib-only), and emit required signoff events.
 * Event-first ordering: log event BEFORE state change.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';
import { VALID_TERMINAL_STATES } from './invariants.js';
import { requireSignoffEvent } from './events.js';

/**
 * Revoke a pending signoff challenge.
 *
 * Only challenges in 'challenge_issued' or 'challenge_viewed' status
 * can be revoked. Challenges in terminal states cannot be revoked.
 *
 * @param {object} params
 * @param {string} params.challengeId - The challenge to revoke
 * @param {string} params.reason - Reason for revocation
 * @param {{ entity_id: string }} params.actor - The actor requesting revocation
 * @returns {Promise<object>} The updated challenge record
 */
export async function revokeChallenge({ challengeId, reason, actor }) {
  if (!challengeId) {
    throw new SignoffError('challengeId is required', 400, 'MISSING_CHALLENGE_ID');
  }
  if (!reason) {
    throw new SignoffError('reason is required', 400, 'MISSING_REASON');
  }
  if (!actor?.entity_id) {
    throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
  }

  const supabase = getServiceClient();

  // ── Verify challenge exists and status allows revocation ──
  const { data: challenge, error: chError } = await supabase
    .from('signoff_challenges')
    .select('*')
    .eq('challenge_id', challengeId)
    .maybeSingle();

  if (chError) {
    throw new SignoffError(`Failed to fetch challenge: ${chError.message}`, 500, 'DB_ERROR');
  }
  if (!challenge) {
    throw new SignoffError('Challenge not found', 404, 'CHALLENGE_NOT_FOUND');
  }

  // ── Authorization: only the accountable actor may revoke ──
  if (actor.entity_id !== challenge.accountable_actor_ref) {
    throw new SignoffError('Only the accountable actor may revoke this challenge', 403, 'FORBIDDEN');
  }

  // Cannot revoke challenges already in terminal states
  if (VALID_TERMINAL_STATES.has(challenge.status)) {
    throw new SignoffError(
      `Cannot revoke challenge in terminal state '${challenge.status}'`,
      409, 'INVALID_STATE_FOR_REVOCATION',
    );
  }

  // Only allow revocation from pre-approval states
  const revocableStatuses = new Set(['challenge_issued', 'challenge_viewed']);
  if (!revocableStatuses.has(challenge.status)) {
    throw new SignoffError(
      `Cannot revoke challenge in '${challenge.status}' status`,
      409, 'INVALID_STATE_FOR_REVOCATION',
    );
  }

  const now = new Date().toISOString();

  // ── Event-first ordering: log event BEFORE state change ──
  await requireSignoffEvent({
    handshakeId: challenge.handshake_id,
    challengeId,
    eventType: 'revoked',
    detail: { reason },
    actorEntityRef: actor.entity_id,
  });

  // ── Update challenge status to 'revoked' (AFTER event is durably recorded) ──
  const { data: updated, error: updateError } = await supabase
    .from('signoff_challenges')
    .update({
      status: 'revoked',
      revoked_at: now,
      revocation_reason: reason,
    })
    .eq('challenge_id', challengeId)
    .select()
    .single();

  if (updateError) {
    throw new SignoffError(`Failed to revoke challenge: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return updated;
}

/**
 * Resolve the caller's own attestation on a challenge to its signoff_id.
 *
 * A challenge does NOT have "an" attestation: EP-QUORUM-v1 (migration 098)
 * deliberately reuses the one-challenge-many-attestations model, so a quorum
 * challenge carries one row per approver. challenge_id is indexed but NOT
 * unique. Resolution is therefore scoped to (challenge_id, human_entity_ref)
 * — the caller's own signature — which is the only attestation they are
 * authorized to revoke anyway.
 *
 * This resolves an identifier only. Every authorization and state guard stays
 * in revokeAttestation() below, so there is exactly one authorization path.
 *
 * Deliberately NOT status-filtered: selecting only 'approved' rows would turn
 * "your attestation is already consumed" into a 404, hiding a real 409 from
 * the caller. Status is judged by the guards, on the row this returns.
 *
 * @param {object} supabase - Service client
 * @param {string} challengeId - The challenge whose attestation to resolve
 * @param {string} humanEntityRef - The caller's entity ref
 * @returns {Promise<string>} The resolved signoff_id
 */
async function resolveSignoffIdForActor(supabase, challengeId, humanEntityRef) {
  const { data: rows, error } = await supabase
    .from('signoff_attestations')
    .select('signoff_id')
    .eq('challenge_id', challengeId)
    .eq('human_entity_ref', humanEntityRef);

  if (error) {
    throw new SignoffError(`Failed to resolve attestation: ${error.message}`, 500, 'DB_ERROR');
  }
  if (!rows || rows.length === 0) {
    throw new SignoffError('Attestation not found', 404, 'ATTESTATION_NOT_FOUND');
  }
  // Fail closed on ambiguity. One-attestation-per-human is enforced in
  // application logic (quorum-session canAccept → 'duplicate_human'), never by
  // a DB constraint, so multiple rows are possible in principle. Revoking an
  // arbitrary one of a human's signatures would silently under-revoke; make the
  // caller name the signoff_id instead.
  if (rows.length > 1) {
    throw new SignoffError(
      'Multiple attestations match this challenge and actor; specify signoffId explicitly',
      409, 'AMBIGUOUS_ATTESTATION',
    );
  }
  return rows[0].signoff_id;
}

/**
 * Revoke an approved signoff attestation.
 *
 * Only attestations in 'approved' status can be revoked. Attestations
 * in terminal states (consumed, revoked, expired) cannot be revoked.
 *
 * Identify the attestation by `signoffId`, or by `challengeId` — in which case
 * the caller's own attestation on that challenge is resolved (see
 * resolveSignoffIdForActor). When both are supplied, the attestation must
 * belong to that challenge or it is treated as not found.
 *
 * @param {object} params
 * @param {string} [params.signoffId] - The attestation to revoke
 * @param {string} [params.challengeId] - Challenge to resolve the caller's attestation from
 * @param {string} params.reason - Reason for revocation
 * @param {{ entity_id: string }} params.actor - The actor requesting revocation
 * @returns {Promise<object>} The updated attestation record
 */
export async function revokeAttestation({ signoffId, challengeId, reason, actor }) {
  if (!signoffId && !challengeId) {
    throw new SignoffError('signoffId or challengeId is required', 400, 'MISSING_SIGNOFF_ID');
  }
  if (!reason) {
    throw new SignoffError('reason is required', 400, 'MISSING_REASON');
  }
  if (!actor?.entity_id) {
    throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
  }

  const supabase = getServiceClient();

  const resolvedSignoffId = signoffId
    || await resolveSignoffIdForActor(supabase, challengeId, actor.entity_id);

  // ── Verify attestation exists and status allows revocation ──
  const { data: attestation, error: attError } = await supabase
    .from('signoff_attestations')
    .select('*')
    .eq('signoff_id', resolvedSignoffId)
    .maybeSingle();

  if (attError) {
    throw new SignoffError(`Failed to fetch attestation: ${attError.message}`, 500, 'DB_ERROR');
  }
  if (!attestation) {
    throw new SignoffError('Attestation not found', 404, 'ATTESTATION_NOT_FOUND');
  }

  // ── Scope integrity: an explicit signoffId must belong to the named challenge ──
  // The route takes challengeId from the URL and signoffId from the body. Without
  // this check the URL segment would be decorative: a caller could POST to one
  // challenge's revoke endpoint and revoke their attestation on a different one.
  // Reported as not-found rather than a mismatch so the endpoint does not confirm
  // that some other challenge holds that signoff_id.
  if (challengeId && attestation.challenge_id !== challengeId) {
    throw new SignoffError('Attestation not found', 404, 'ATTESTATION_NOT_FOUND');
  }

  // ── Authorization: only the accountable actor may revoke ──
  if (actor.entity_id !== attestation.human_entity_ref) {
    throw new SignoffError('Only the accountable actor may revoke this attestation', 403, 'FORBIDDEN');
  }

  // Cannot revoke attestations in terminal states
  if (VALID_TERMINAL_STATES.has(attestation.status)) {
    throw new SignoffError(
      `Cannot revoke attestation in terminal state '${attestation.status}'`,
      409, 'INVALID_STATE_FOR_REVOCATION',
    );
  }

  // Only 'approved' attestations can be revoked
  if (attestation.status !== 'approved') {
    throw new SignoffError(
      `Cannot revoke attestation in '${attestation.status}' status`,
      409, 'INVALID_STATE_FOR_REVOCATION',
    );
  }

  const now = new Date().toISOString();

  // ── Event-first ordering: log event BEFORE state change ──
  await requireSignoffEvent({
    handshakeId: attestation.handshake_id,
    challengeId: attestation.challenge_id,
    signoffId: resolvedSignoffId,
    eventType: 'attestation_revoked',
    detail: { reason },
    actorEntityRef: attestation.human_entity_ref,
  });

  // ── Update attestation status to 'revoked' (AFTER event is durably recorded) ──
  const { data: updated, error: updateError } = await supabase
    .from('signoff_attestations')
    .update({
      status: 'revoked',
      revoked_at: now,
      revocation_reason: reason,
    })
    .eq('signoff_id', resolvedSignoffId)
    .select()
    .single();

  if (updateError) {
    throw new SignoffError(`Failed to revoke attestation: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return updated;
}
