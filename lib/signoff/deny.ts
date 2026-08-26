/**
 * EP Signoff — Deny logic for challenges.
 *
 * denyChallenge() records a human denial of a signoff challenge.
 * Only challenges in 'challenge_issued' or 'challenge_viewed' status can be
 * denied. The required event and state change commit in one transaction.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';
import { VALID_TERMINAL_STATES } from './invariants.js';

/**
 * Deny a pending signoff challenge.
 *
 * The accountable human entity declines the requested action.
 * Updates challenge status to 'denied' and emits a protocol event.
 */
export async function denyChallenge({
  challengeId,
  reason,
  actor,
}: {
  challengeId: string;
  reason?: string;
  actor: { entity_id: string };
}): Promise<any> {
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

  // The preflight above produces fast, specific errors. The RPC repeats every
  // actor/state/expiry predicate under a row lock, then commits the canonical
  // event and state transition in one transaction.
  const { data: denied, error: rpcError } = await supabase.rpc('deny_challenge_atomic', {
    p_challenge_id: challengeId,
    p_actor_entity_ref: actor.entity_id,
    p_reason: reason || 'Human denied the action',
  });

  if (rpcError) {
    const rpcMessage = [rpcError.message, rpcError.details, rpcError.hint, rpcError.code]
      .filter((value) => typeof value === 'string')
      .join(' ');
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_NOT_FOUND')) {
      throw new SignoffError('Challenge not found', 404, 'CHALLENGE_NOT_FOUND');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_ACTOR_MISMATCH')) {
      throw new SignoffError('Only the accountable actor may deny this challenge', 403, 'FORBIDDEN');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_NOT_DENIABLE')) {
      throw new SignoffError('Challenge is no longer deniable', 409, 'INVALID_STATE_FOR_DENIAL');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_EXPIRED')) {
      throw new SignoffError('Challenge has expired', 410, 'SIGNOFF_CHALLENGE_EXPIRED');
    }
    throw new SignoffError(`Failed to deny challenge: ${rpcError.message}`, 500, 'DB_ERROR');
  }

  return denied;
}
