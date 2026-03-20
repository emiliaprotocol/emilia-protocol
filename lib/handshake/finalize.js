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

  if (handshake.status === 'revoked' || handshake.status === 'expired') {
    throw new HandshakeError(
      `Cannot revoke handshake in '${handshake.status}' state`,
      409, 'INVALID_STATE',
    );
  }

  const { error: updateError } = await supabase
    .from('handshakes')
    .update({ status: 'revoked', decision_ref: reason })
    .eq('handshake_id', handshake_id);

  if (updateError) {
    throw new HandshakeError(`Failed to revoke handshake: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return {
    result: {
      handshake_id,
      status: 'revoked',
      reason,
    },
    aggregateId: handshake_id,
  };
}
