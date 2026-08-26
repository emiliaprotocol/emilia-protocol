/**
 * EP Handshake — Finalization and revocation logic.
 *
 * revokeHandshake() and _handleRevokeHandshake() handle terminal
 * state transitions.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { HandshakeError } from './errors.js';

/**
 * Revoke an accepted handshake.
 * @param {string} handshakeId
 * @param {string} reason
 * @param {string|object} [actor='system']
 */
export async function revokeHandshake(handshakeId, reason, actor = 'system') {
  if (!handshakeId) {
    throw new HandshakeError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }
  if (!reason) {
    throw new HandshakeError('reason is required for revocation', 400, 'MISSING_REASON');
  }

  const result = await protocolWrite({
    type: COMMAND_TYPES.REVOKE_HANDSHAKE,
    actor,
    input: {
      handshake_id: handshakeId,
      reason,
    },
  });

  return result;
}

/**
 * Handler: revoke_handshake
 * @param {{ actor: string|object, input: { handshake_id: string, reason: string } }} command
 */
export async function _handleRevokeHandshake(command) {
  const { handshake_id, reason } = command.input;
  const supabase = getServiceClient();

  const { data: handshake, error: hsError } = await supabase
    .from('handshakes')
    .select('handshake_id, status')
    .eq('handshake_id', handshake_id)
    .maybeSingle();

  if (hsError) {
    throw new HandshakeError(`Failed to fetch handshake: ${hsError.message}`, 500, 'DB_ERROR');
  }
  if (!handshake) {
    throw new HandshakeError('Handshake not found', 404, 'NOT_FOUND');
  }

  // Actor must be a party to the handshake or system
  const authenticatedEntity = typeof command.actor === 'object'
    ? ((/** @type {Record<string, any>} */ (command.actor)).entity_id
      || (/** @type {Record<string, any>} */ (command.actor)).id
      || command.actor)
    : command.actor;

  if (authenticatedEntity !== 'system') {
    const { data: memberCheck } = await supabase
      .from('handshake_parties')
      .select('id')
      .eq('handshake_id', handshake_id)
      .eq('entity_ref', authenticatedEntity)
      .limit(1);

    if (!memberCheck || memberCheck.length === 0) {
      throw new HandshakeError(
        'Only handshake parties may revoke',
        403, 'UNAUTHORIZED_REVOCATION',
      );
    }
  }

  if (handshake.status === 'revoked' || handshake.status === 'expired') {
    throw new HandshakeError(
      `Cannot revoke handshake in '${handshake.status}' state`,
      409, 'INVALID_STATE',
    );
  }

  // The preflight above provides fast errors. The RPC repeats actor and state
  // authorization while holding handshake -> binding locks, then records the
  // canonical event and state transition in one transaction. A verified
  // binding's consumed_at is only its verification-finalization marker;
  // revocation is blocked by a downstream handshake_consumptions row.
  const { data: revoked, error: rpcError } = await supabase.rpc('revoke_handshake_atomic', {
    p_handshake_id: handshake_id,
    p_reason: reason,
    p_actor_entity_ref: String(authenticatedEntity),
  });

  if (rpcError) {
    const rpcMessage = [rpcError.message, rpcError.details, rpcError.hint, rpcError.code]
      .filter((value) => typeof value === 'string')
      .join(' ');
    if (rpcMessage.includes('HANDSHAKE_NOT_FOUND')) {
      throw new HandshakeError('Handshake not found', 404, 'NOT_FOUND');
    }
    if (rpcMessage.includes('HANDSHAKE_REVOCATION_ACTOR_UNAUTHORIZED')) {
      throw new HandshakeError('Only handshake parties may revoke', 403, 'UNAUTHORIZED_REVOCATION');
    }
    if (rpcMessage.includes('HANDSHAKE_NOT_REVOCABLE')
        || rpcMessage.includes('HANDSHAKE_ALREADY_CONSUMED')) {
      throw new HandshakeError('Handshake is no longer revocable', 409, 'INVALID_STATE');
    }
    if (rpcMessage.includes('HANDSHAKE_REVOCATION_REASON_REQUIRED')) {
      throw new HandshakeError('reason is required for revocation', 400, 'MISSING_REASON');
    }
    if (rpcMessage.includes('HANDSHAKE_REVOCATION_ACTOR_REQUIRED')) {
      throw new HandshakeError('actor is required for revocation', 400, 'MISSING_ACTOR');
    }
    throw new HandshakeError(`Failed to revoke handshake: ${rpcError.message}`, 500, 'DB_ERROR');
  }

  return {
    result: {
      handshake_id,
      status: revoked?.status || 'revoked',
      reason,
    },
    aggregateId: handshake_id,
  };
}
