/**
 * EP Handshake — One-time consumption enforcement.
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { HandshakeError } from './errors.js';

/**
 * Atomically consume a verified handshake for a downstream action.
 * Returns the consumption record if successful.
 * Throws if already consumed or handshake is not in accepted state.
 *
 * @param {object} opts
 * @param {string} opts.handshake_id - The handshake to consume
 * @param {string} opts.binding_hash - Binding hash for integrity check
 * @param {string} opts.consumed_by_type - Type of consuming artifact (e.g., 'commit_issue')
 * @param {string} opts.consumed_by_id - ID of the consuming artifact
 * @param {string|object} opts.actor - Authenticated actor performing consumption
 * @param {string} [opts.consumed_by_action] - WHAT action the consumption is for (LOCK 100 B.1)
 */
export async function consumeHandshake({
  handshake_id,
  binding_hash,
  consumed_by_type,
  consumed_by_id,
  actor,
  consumed_by_action = null,
}) {
  if (!handshake_id) throw new HandshakeError('handshake_id is required', 400, 'MISSING_HANDSHAKE_ID');
  if (!binding_hash) throw new HandshakeError('binding_hash is required', 400, 'MISSING_BINDING_HASH');
  if (!consumed_by_type) throw new HandshakeError('consumed_by_type is required', 400, 'MISSING_CONSUMED_BY_TYPE');
  if (!consumed_by_id) throw new HandshakeError('consumed_by_id is required', 400, 'MISSING_CONSUMED_BY_ID');

  const supabase = getServiceClient();
  const actorRef = typeof actor === 'object'
    ? (actor.entity_id || actor.id || 'system')
    : (actor || 'system');

  // Check handshake is verified
  const { data: handshake } = await supabase
    .from('handshakes')
    .select('status')
    .eq('handshake_id', handshake_id)
    .single();

  if (!handshake || handshake.status !== 'verified') {
    throw new HandshakeError(
      `Handshake must be in verified state to consume (current: ${handshake?.status || 'not found'})`,
      409, 'INVALID_STATE_FOR_CONSUMPTION',
    );
  }

  // Atomic insert — unique constraint prevents double consumption
  const { data: consumption, error } = await supabase
    .from('handshake_consumptions')
    .insert({
      handshake_id,
      binding_hash,
      consumed_by_type,
      consumed_by_id,
      actor_entity_ref: actorRef,
      consumed_by_action,
    })
    .select()
    .single();

  if (error) {
    if (error.code === '23505') { // unique violation
      throw new HandshakeError(
        'Handshake has already been consumed',
        409, 'ALREADY_CONSUMED',
      );
    }
    throw new HandshakeError(`Failed to consume handshake: ${error.message}`, 500, 'DB_ERROR');
  }

  // Belt AND suspenders: also mark the binding's consumed_at atomically.
  // Only updates if consumed_at is not already set (idempotent, no race).
  await supabase
    .from('handshake_bindings')
    .update({
      consumed_at: consumption.created_at || new Date().toISOString(),
      consumed_by: actorRef,
      consumed_for: `${consumed_by_type}:${consumed_by_id}`,
    })
    .eq('handshake_id', handshake_id)
    .is('consumed_at', null);

  return consumption;
}

/**
 * Check if a handshake has been consumed without consuming it.
 */
export async function isHandshakeConsumed(handshake_id) {
  const supabase = getServiceClient();
  const { data } = await supabase
    .from('handshake_consumptions')
    .select('id')
    .eq('handshake_id', handshake_id)
    .maybeSingle();
  return !!data;
}
