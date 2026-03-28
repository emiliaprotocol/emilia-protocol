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

  // Derive bindingHash from attestation if not provided
  const resolvedBindingHash = bindingHash || attestation.binding_hash;

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

  // ── Verify binding_hash matches (if explicitly provided) ──
  if (bindingHash && attestation.binding_hash !== bindingHash) {
    throw new SignoffError(
      'binding_hash does not match the attestation binding',
      409, 'BINDING_HASH_MISMATCH',
    );
  }

  // ── Single RPC: event + consumption + status update in one transaction ──
  // Replaces 3 serial writes with 1 roundtrip.
  const { data: rpcResult, error: rpcError } = await supabase.rpc('consume_signoff_atomic', {
    p_signoff_id: signoffId,
    p_binding_hash: resolvedBindingHash,
    p_execution_ref: executionRef,
    p_handshake_id: String(attestation.handshake_id),
    p_challenge_id: String(attestation.challenge_id),
    p_human_entity_ref: attestation.human_entity_ref,
  });

  if (rpcError) {
    // Belt-and-suspenders: catch unique constraint violation
    if (rpcError.message?.includes('23505') || rpcError.message?.includes('unique')) {
      throw new SignoffError(
        'Signoff has already been consumed',
        409, 'ALREADY_CONSUMED',
      );
    }
    throw new SignoffError(`Failed to consume signoff: ${rpcError.message}`, 500, 'DB_ERROR');
  }

  return {
    signoff_id: signoffId,
    binding_hash: bindingHash,
    execution_ref: executionRef,
    consumed_at: rpcResult.consumed_at,
    id: rpcResult.consumption_id,
  };
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
