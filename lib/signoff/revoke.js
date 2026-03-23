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
    actorEntityRef: 'system',
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
 * Revoke an approved signoff attestation.
 *
 * Only attestations in 'approved' status can be revoked. Attestations
 * in terminal states (consumed, revoked, expired) cannot be revoked.
 *
 * @param {object} params
 * @param {string} params.signoffId - The attestation to revoke
 * @param {string} params.reason - Reason for revocation
 * @returns {Promise<object>} The updated attestation record
 */
export async function revokeAttestation({ signoffId, reason, actor }) {
  if (!signoffId) {
    throw new SignoffError('signoffId is required', 400, 'MISSING_SIGNOFF_ID');
  }
  if (!reason) {
    throw new SignoffError('reason is required', 400, 'MISSING_REASON');
  }
  if (!actor?.entity_id) {
    throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
  }

  const supabase = getServiceClient();

  // ── Verify attestation exists and status allows revocation ──
  const { data: attestation, error: attError } = await supabase
    .from('signoff_attestations')
    .select('*')
    .eq('signoff_id', signoffId)
    .maybeSingle();

  if (attError) {
    throw new SignoffError(`Failed to fetch attestation: ${attError.message}`, 500, 'DB_ERROR');
  }
  if (!attestation) {
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
    signoffId,
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
    .eq('signoff_id', signoffId)
    .select()
    .single();

  if (updateError) {
    throw new SignoffError(`Failed to revoke attestation: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return updated;
}
