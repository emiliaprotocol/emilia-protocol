/**
 * EP Signoff — One-time consumption enforcement.
 *
 * consumeSignoff() atomically consumes an approved attestation for a
 * downstream execution action. The atomic RPC also inserts the parent
 * handshake's unique downstream-consumption row, so authority and signoff
 * cannot diverge. The binding consumed_at field remains the earlier
 * verification-finalization marker.
 *
 * All writes go through getServiceClient() (lib-only).
 * All authority, event, and state writes commit in one transaction.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';

interface ConsumeSignoffParams {
  signoffId: string;
  bindingHash?: string | null;
  executionRef: string;
  actor: { entity_id?: string };
}

/**
 * Atomically consume an approved signoff attestation for a downstream action.
 * Returns the consumption record if successful.
 * Throws if already consumed or attestation is not in approved state.
 *
 * Belt-and-suspenders: catches unique constraint violation and returns
 * ALREADY_CONSUMED error rather than a generic DB error.
 *
 * @param params
 * @param params.signoffId - The attestation to consume
 * @param params.bindingHash - Binding hash for integrity check
 * @param params.executionRef - Reference to the downstream action consuming this signoff
 * @param params.actor - The entity attempting to consume this signoff
 * @returns The consumption record
 */
export async function consumeSignoff({
  signoffId,
  bindingHash,
  executionRef,
  actor,
}: ConsumeSignoffParams): Promise<any> {
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
  if (!attestation.expires_at || new Date(attestation.expires_at) <= new Date()) {
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
    const rpcMessage = [rpcError.message, rpcError.details, rpcError.hint, rpcError.code]
      .filter((value) => typeof value === 'string')
      .join(' ');
    if (rpcMessage.includes('SIGNOFF_ATTESTATION_NOT_FOUND')) {
      throw new SignoffError('Attestation not found', 404, 'ATTESTATION_NOT_FOUND');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_NOT_FOUND')) {
      throw new SignoffError('Signoff challenge not found', 404, 'CHALLENGE_NOT_FOUND');
    }
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_NOT_FOUND')) {
      throw new SignoffError('Handshake not found', 404, 'HANDSHAKE_NOT_FOUND');
    }
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_NOT_VERIFIED')) {
      throw new SignoffError('Handshake is no longer verified', 409, 'INVALID_HANDSHAKE_STATE');
    }
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_NOT_VERIFICATION_FINALIZED')) {
      throw new SignoffError('Handshake verification was not finalized', 409, 'HANDSHAKE_NOT_VERIFICATION_FINALIZED');
    }
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_EXPIRED')) {
      throw new SignoffError('Handshake has expired', 410, 'SIGNOFF_HANDSHAKE_EXPIRED');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_NOT_CONSUMABLE')) {
      throw new SignoffError('Signoff challenge is no longer consumable', 409, 'INVALID_CHALLENGE_STATE');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_EXPIRED')) {
      throw new SignoffError('Signoff challenge has expired', 410, 'SIGNOFF_CHALLENGE_EXPIRED');
    }
    if (rpcMessage.includes('SIGNOFF_BINDING_NOT_FOUND')) {
      throw new SignoffError('Handshake binding not found', 404, 'BINDING_NOT_FOUND');
    }
    if (rpcMessage.includes('SIGNOFF_BINDING_EXPIRED')) {
      throw new SignoffError('Handshake binding has expired', 410, 'BINDING_EXPIRED');
    }
    if (rpcMessage.includes('SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED')) {
      throw new SignoffError('Handshake binding was not finalized by verification', 409, 'BINDING_NOT_VERIFICATION_FINALIZED');
    }
    if (rpcMessage.includes('SIGNOFF_AUTHORITY_ALREADY_CONSUMED')) {
      throw new SignoffError('Handshake authority has already been consumed', 409, 'AUTHORITY_ALREADY_CONSUMED');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_OUTLIVES_BINDING')) {
      throw new SignoffError('Challenge exceeds its authority binding window', 409, 'CHALLENGE_OUTLIVES_BINDING');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_POLICY_MISMATCH')) {
      throw new SignoffError('Challenge no longer matches its pinned policy', 409, 'SIGNOFF_CHALLENGE_POLICY_MISMATCH');
    }
    if (rpcMessage.includes('SIGNOFF_PINNED_POLICY_UNAVAILABLE')) {
      throw new SignoffError('Pinned signoff policy is unavailable', 409, 'SIGNOFF_PINNED_POLICY_UNAVAILABLE');
    }
    if (rpcMessage.includes('SIGNOFF_POLICY_HASH_UNVERIFIABLE')) {
      throw new SignoffError('Pinned policy rules cannot be hashed in the protocol profile', 409, 'SIGNOFF_POLICY_HASH_UNVERIFIABLE');
    }
    if (rpcMessage.includes('SIGNOFF_POLICY_HASH_MISMATCH')) {
      throw new SignoffError('Pinned policy rules changed after handshake verification', 409, 'SIGNOFF_POLICY_HASH_MISMATCH');
    }
    if (rpcMessage.includes('SIGNOFF_AUTHORITY_INVALID_OR_REVOKED')) {
      throw new SignoffError('Accountable approver authority is invalid or revoked', 403, 'SIGNOFF_AUTHORITY_INVALID_OR_REVOKED');
    }
    if (rpcMessage.includes('SIGNOFF_CEREMONY_EVIDENCE_INVALID')) {
      throw new SignoffError('Approval has no valid server-verified ceremony evidence', 409, 'SIGNOFF_CEREMONY_EVIDENCE_INVALID');
    }
    if (rpcMessage.includes('SIGNOFF_ATTESTATION_NOT_CONSUMABLE')) {
      throw new SignoffError('Attestation is no longer consumable', 409, 'INVALID_ATTESTATION_STATE');
    }
    if (rpcMessage.includes('SIGNOFF_ATTESTATION_EXPIRED')) {
      throw new SignoffError('Attestation has expired', 410, 'SIGNOFF_ATTESTATION_EXPIRED');
    }
    if (rpcMessage.includes('SIGNOFF_ATTESTATION_OUTLIVES_BINDING')) {
      throw new SignoffError('Attestation exceeds its authority binding window', 409, 'ATTESTATION_OUTLIVES_BINDING');
    }
    if (rpcMessage.includes('SIGNOFF_ATTESTATION_BINDING_MISMATCH')) {
      throw new SignoffError('Attestation authorization binding changed', 409, 'BINDING_HASH_MISMATCH');
    }
    if (rpcMessage.includes('SIGNOFF_ATTESTATION_ACTOR_MISMATCH')) {
      throw new SignoffError('Only the authorized human entity may consume this attestation', 403, 'FORBIDDEN');
    }
    if (rpcMessage.includes('SIGNOFF_EXECUTION_REF_REQUIRED')) {
      throw new SignoffError('executionRef is required', 400, 'MISSING_EXECUTION_REF');
    }
    // Belt-and-suspenders: catch unique constraint violation
    if (rpcMessage.includes('23505') || rpcMessage.includes('unique')) {
      throw new SignoffError(
        'Signoff has already been consumed',
        409, 'ALREADY_CONSUMED',
      );
    }
    throw new SignoffError(`Failed to consume signoff: ${rpcError.message}`, 500, 'DB_ERROR');
  }

  return {
    signoff_id: signoffId,
    binding_hash: resolvedBindingHash,
    execution_ref: executionRef,
    consumed_at: rpcResult.consumed_at,
    id: rpcResult.consumption_id,
  };
}

/**
 * Check if a signoff attestation has been consumed without consuming it.
 *
 * @param signoffId
 */
export async function isSignoffConsumed(signoffId: string): Promise<boolean> {
  const supabase = getServiceClient();
  const { data } = await supabase
    .from('signoff_consumptions')
    .select('signoff_id')
    .eq('signoff_id', signoffId)
    .maybeSingle();
  return !!data;
}
