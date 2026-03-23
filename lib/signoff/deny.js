/**
 * EP Signoff — Deny logic for challenges.
 *
 * denyChallenge() records a human denial of a signoff challenge.
 * Only challenges in 'challenge_issued' or 'challenge_viewed' status
 * can be denied. Event-first ordering: log event BEFORE state change.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';
import { VALID_TERMINAL_STATES } from './invariants.js';
import { requireSignoffEvent } from './events.js';

/**
 * Deny a pending signoff challenge.
 *
 * The accountable human entity declines the requested action.
 * Updates challenge status to 'denied' and emits a protocol event.
 *
 * @param {object} params
 * @param {string} params.challengeId - The challenge to deny
 * @param {string} [params.reason] - Optional reason for denial
 * @returns {Promise<object>} The updated challenge record
 */
export async function denyChallenge({ challengeId, reason, actor }) {
  if (!challengeId) {
    throw new SignoffError('challengeId is required', 400, 'MISSING_CHALLENGE_ID');
  }
  if (!actor?.entity_id) {
    throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
  }

  const supabase = getServiceClient();

  // ── Verify challenge exists and status allows denial ──
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

  // ── Authorization: only the accountable actor may deny ──
  if (actor.entity_id !== challenge.accountable_actor_ref) {
    throw new SignoffError('Only the accountable actor may deny this challenge', 403, 'FORBIDDEN');
  }

  // Cannot deny challenges already in terminal states
  if (VALID_TERMINAL_STATES.has(challenge.status)) {
    throw new SignoffError(
      `Cannot deny challenge in terminal state '${challenge.status}'`,
      409, 'INVALID_STATE_FOR_DENIAL',
    );
  }

  // Only allow denial from pre-approval states
  const deniableStatuses = new Set(['challenge_issued', 'challenge_viewed']);
  if (!deniableStatuses.has(challenge.status)) {
    throw new SignoffError(
      `Cannot deny challenge in '${challenge.status}' status`,
      409, 'INVALID_STATE_FOR_DENIAL',
    );
  }

  // ── Event-first ordering: log event BEFORE state change ──
  await requireSignoffEvent({
    handshakeId: challenge.handshake_id,
    challengeId,
    eventType: 'denied',
    detail: { reason: reason || 'Human denied the action' },
    actorEntityRef: challenge.accountable_actor_ref,
  });

  // ── Update challenge status to 'denied' (AFTER event is durably recorded) ──
  const { data: updated, error: updateError } = await supabase
    .from('signoff_challenges')
    .update({ status: 'denied' })
    .eq('challenge_id', challengeId)
    .select()
    .single();

  if (updateError) {
    throw new SignoffError(`Failed to deny challenge: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return updated;
}
