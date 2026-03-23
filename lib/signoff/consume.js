/**
 * EP Signoff — One-time consumption enforcement.
 *
 * consumeSignoff() atomically consumes an approved attestation for a
 * downstream execution action. Uses a unique constraint on signoff_id
 * in signoff_consumptions to prevent double-consumption.
 *
 * All writes go through getServiceClient() (lib-only).
 * Event-first ordering: log event BEFORE state change.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';
import { requireSignoffEvent } from './events.js';

/**
 * Atomically consume an approved signoff attestation for a downstream action.
 * Returns the consumption record if successful.
 * Throws if already consumed or attestation is not in approved state.
 *
 * Belt-and-suspenders: catches unique constraint violation and returns
 * ALREADY_CONSUMED error rather than a generic DB error.
 *
 * @param {object} params
 * @param {string} params.signoffId - The attestation to consume
 * @param {string} params.bindingHash - Binding hash for integrity check
 * @param {string} params.executionRef - Reference to the downstream action consuming this signoff
 * @returns {Promise<object>} The consumption record
 */
export async function consumeSignoff({
  signoffId,
  bindingHash,
  executionRef,
  actor,
}) {
  // ── Validate inputs ──
  if (!signoffId) {
    throw new SignoffError('signoffId is required', 400, 'MISSING_SIGNOFF_ID');
  }
  if (!bindingHash) {
    throw new SignoffError('bindingHash is required', 400, 'MISSING_BINDING_HASH');
  }
  if (!executionRef) {
    throw new SignoffError('executionRef is required', 400, 'MISSING_EXECUTION_REF');
  }
  if (!actor?.entity_id) {
    throw new SignoffError('actor with entity_id is required', 400, 'MISSING_ACTOR');
  }

  const supabase = getServiceClient();

  // ── Verify attestation exists and is in 'approved' status ──
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

  // ── Authorization: only the human entity on the attestation may consume it ──
  if (actor.entity_id !== attestation.human_entity_ref) {
    throw new SignoffError('Only the authorized human entity may consume this attestation', 403, 'FORBIDDEN');
  }
  if (attestation.status !== 'approved') {
    throw new SignoffError(
      `Attestation must be in 'approved' status to consume (current: ${attestation.status})`,
      409, 'INVALID_ATTESTATION_STATE',
    );
  }

  // ── Verify attestation has not expired ──
  if (attestation.expires_at && new Date(attestation.expires_at) < new Date()) {
    throw new SignoffError('Attestation has expired', 410, 'SIGNOFF_ATTESTATION_EXPIRED');
  }

  // ── Verify binding_hash matches ──
  if (attestation.binding_hash !== bindingHash) {
    throw new SignoffError(
      'binding_hash does not match the attestation binding',
      409, 'BINDING_HASH_MISMATCH',
    );
  }

  // ── Event-first ordering: log event BEFORE state change ──
  await requireSignoffEvent({
    handshakeId: attestation.handshake_id,
    challengeId: attestation.challenge_id,
    signoffId,
    eventType: 'consumed',
    detail: {
      execution_ref: executionRef,
      human_entity_ref: attestation.human_entity_ref,
    },
    actorEntityRef: attestation.human_entity_ref,
  });

  // ── Atomic insert into signoff_consumptions (unique constraint on signoff_id) ──
  const now = new Date().toISOString();
  const consumptionRecord = {
    signoff_id: signoffId,
    binding_hash: bindingHash,
    execution_ref: executionRef,
    consumed_at: now,
    created_at: now,
  };

  const { data: consumption, error: insertError } = await supabase
    .from('signoff_consumptions')
    .insert(consumptionRecord)
    .select()
    .single();

  if (insertError) {
    // Belt-and-suspenders: catch unique constraint violation
    if (insertError.code === '23505') {
      throw new SignoffError(
        'Signoff has already been consumed',
        409, 'ALREADY_CONSUMED',
      );
    }
    throw new SignoffError(`Failed to consume signoff: ${insertError.message}`, 500, 'DB_ERROR');
  }

  // ── Update attestation status to 'consumed' (AFTER event and consumption) ──
  const { error: updateError } = await supabase
    .from('signoff_attestations')
    .update({
      status: 'consumed',
      consumed_at: now,
    })
    .eq('signoff_id', signoffId);

  if (updateError) {
    throw new SignoffError(`Failed to update attestation status: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return consumption;
}

/**
 * Check if a signoff attestation has been consumed without consuming it.
 *
 * @param {string} signoffId
 * @returns {Promise<boolean>}
 */
export async function isSignoffConsumed(signoffId) {
  const supabase = getServiceClient();
  const { data } = await supabase
    .from('signoff_consumptions')
    .select('signoff_id')
    .eq('signoff_id', signoffId)
    .maybeSingle();
  return !!data;
}
