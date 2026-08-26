/**
 * EP Signoff — Atomic expiry transitions for challenges and attestations.
 *
 * Expiry is a trust-changing state transition, not telemetry. These wrappers
 * call service-role-only database functions that lock the authoritative row,
 * recheck its state and clock deadline, and commit the canonical event and
 * status update together.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';

function errorText(error: any): string {
  return [error?.message, error?.details, error?.hint, error?.code]
    .filter((value) => typeof value === 'string')
    .join(' ');
}

function requireActor(actor: { entity_id: string } | undefined): string {
  if (!actor?.entity_id?.trim()) {
    throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
  }
  return actor.entity_id.trim();
}

/** Expire an issued/viewed challenge only after its authoritative deadline. */
export async function expireChallenge({
  challengeId,
  actor,
}: {
  challengeId: string;
  actor: { entity_id: string };
}): Promise<any> {
  if (!challengeId?.trim()) {
    throw new SignoffError('challengeId is required', 400, 'MISSING_CHALLENGE_ID');
  }
  const actorEntityRef = requireActor(actor);
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('expire_challenge_atomic', {
    p_challenge_id: challengeId,
    p_actor_entity_ref: actorEntityRef,
  });

  if (error) {
    const message = errorText(error);
    if (message.includes('SIGNOFF_CHALLENGE_NOT_FOUND')) {
      throw new SignoffError('Challenge not found', 404, 'CHALLENGE_NOT_FOUND');
    }
    if (message.includes('SIGNOFF_CHALLENGE_NOT_EXPIRABLE')) {
      throw new SignoffError('Challenge is no longer expirable', 409, 'INVALID_STATE_FOR_EXPIRY');
    }
    if (message.includes('SIGNOFF_CHALLENGE_NOT_EXPIRED')) {
      throw new SignoffError('Challenge deadline has not elapsed', 409, 'SIGNOFF_CHALLENGE_NOT_EXPIRED');
    }
    if (message.includes('SIGNOFF_ACTOR_REQUIRED')) {
      throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
    }
    throw new SignoffError(`Failed to expire challenge: ${error.message}`, 500, 'DB_ERROR');
  }

  return data;
}

/** Expire an approved attestation only after its authoritative deadline. */
export async function expireAttestation({
  signoffId,
  actor,
}: {
  signoffId: string;
  actor: { entity_id: string };
}): Promise<any> {
  if (!signoffId?.trim()) {
    throw new SignoffError('signoffId is required', 400, 'MISSING_SIGNOFF_ID');
  }
  const actorEntityRef = requireActor(actor);
  const supabase = getServiceClient();
  const { data, error } = await supabase.rpc('expire_attestation_atomic', {
    p_signoff_id: signoffId,
    p_actor_entity_ref: actorEntityRef,
  });

  if (error) {
    const message = errorText(error);
    if (message.includes('SIGNOFF_ATTESTATION_NOT_FOUND')) {
      throw new SignoffError('Attestation not found', 404, 'ATTESTATION_NOT_FOUND');
    }
    if (message.includes('SIGNOFF_ATTESTATION_NOT_EXPIRABLE')) {
      throw new SignoffError('Attestation is no longer expirable', 409, 'INVALID_STATE_FOR_EXPIRY');
    }
    if (message.includes('SIGNOFF_ATTESTATION_NOT_EXPIRED')) {
      throw new SignoffError('Attestation deadline has not elapsed', 409, 'SIGNOFF_ATTESTATION_NOT_EXPIRED');
    }
    if (message.includes('SIGNOFF_ATTESTATION_BINDING_MISMATCH')) {
      throw new SignoffError('Attestation does not match its challenge binding', 409, 'SIGNOFF_ATTESTATION_BINDING_MISMATCH');
    }
    if (message.includes('SIGNOFF_ACTOR_REQUIRED')) {
      throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
    }
    throw new SignoffError(`Failed to expire attestation: ${error.message}`, 500, 'DB_ERROR');
  }

  return data;
}
