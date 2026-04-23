/**
 * EP Handshake — One-time consumption enforcement.
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { resolveActorRef } from '@/lib/actor';
import { siemEvent } from '@/lib/siem';
import { HandshakeError } from './errors.js';

/**
 * @typedef {Object} HandshakeConsumptionRecord
 * @property {string} id - Auto-generated consumption record ID
 * @property {string} handshake_id - The consumed handshake UUID
 * @property {string} binding_hash - Binding hash verified at consumption time
 * @property {string} consumed_by_type - Type of consuming artifact (e.g. 'commit_issue')
 * @property {string} consumed_by_id - ID of the consuming artifact
 * @property {string} actor_entity_ref - Entity reference of the consuming actor
 * @property {string|null} consumed_by_action - Action label for the consumption
 * @property {string} created_at - ISO-8601 creation timestamp
 */

/**
 * Atomically consume a verified handshake for a downstream action.
 * Returns the consumption record if successful.
 * Throws if already consumed or handshake is not in accepted state.
 *
 * Uses a unique constraint on handshake_id in handshake_consumptions
 * to prevent double-consumption at the database level.
 *
 * @param {object} opts
 * @param {string} opts.handshake_id - The handshake to consume
 * @param {string} opts.binding_hash - Binding hash for integrity check
 * @param {string} opts.consumed_by_type - Type of consuming artifact (e.g., 'commit_issue')
 * @param {string} opts.consumed_by_id - ID of the consuming artifact
 * @param {string|object} opts.actor - Authenticated actor performing consumption
 * @param {string} [opts.consumed_by_action=null] - WHAT action the consumption is for (LOCK 100 B.1)
 * @returns {Promise<HandshakeConsumptionRecord>} The created consumption record
 * @throws {HandshakeError} MISSING_HANDSHAKE_ID if handshake_id is not provided
 * @throws {HandshakeError} MISSING_BINDING_HASH if binding_hash is not provided
 * @throws {HandshakeError} MISSING_CONSUMED_BY_TYPE if consumed_by_type is not provided
 * @throws {HandshakeError} MISSING_CONSUMED_BY_ID if consumed_by_id is not provided
 * @throws {HandshakeError} INVALID_STATE_FOR_CONSUMPTION if handshake is not in 'verified' state
 * @throws {HandshakeError} ALREADY_CONSUMED if the handshake was already consumed (unique constraint violation)
 * @throws {HandshakeError} DB_ERROR on database failures
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
  const actorRef = resolveActorRef(actor);

  // Atomic status check + insert via RPC (migration 074).
  // Uses FOR UPDATE on the handshake row to prevent TOCTOU race between
  // a revocation and this consumption. The unique constraint on handshake_id
  // in handshake_consumptions prevents double-consumption at the DB level.
  const { data: rows, error } = await supabase
    .rpc('consume_handshake_atomic', {
      p_handshake_id:       handshake_id,
      p_binding_hash:       binding_hash,
      p_consumed_by_type:   consumed_by_type,
      p_consumed_by_id:     consumed_by_id,
      p_actor_entity_ref:   actorRef,
      p_consumed_by_action: consumed_by_action,
    });

  if (error) {
    if (error.code === '23505' || error.message?.includes('unique')) {
      throw new HandshakeError('Handshake has already been consumed', 409, 'ALREADY_CONSUMED');
    }
    if (error.code === 'P0001' || error.message?.includes('INVALID_STATE_FOR_CONSUMPTION')) {
      const detail = error.message || '';
      throw new HandshakeError(
        `Handshake must be in verified state to consume (${detail})`,
        409, 'INVALID_STATE_FOR_CONSUMPTION',
      );
    }
    if (error.code === 'P0002' || error.message?.includes('HANDSHAKE_NOT_FOUND') || error.message?.includes('BINDING_NOT_FOUND')) {
      throw new HandshakeError('Handshake or binding not found', 404, 'INVALID_STATE_FOR_CONSUMPTION');
    }
    // Audit-fix (C1): migration 080 raises P0003 BINDING_HASH_MISMATCH if the
    // caller's binding_hash doesn't match the stored server-truth value.
    // This is an integrity failure — either the caller has stale state or is
    // attempting to forge the audit trail. Fail loud, log, and do not retry.
    if (error.code === 'P0003' || error.message?.includes('BINDING_HASH_MISMATCH')) {
      throw new HandshakeError(
        'Supplied binding_hash does not match stored binding',
        409, 'BINDING_HASH_MISMATCH',
      );
    }
    throw new HandshakeError(`Failed to consume handshake: ${error.message}`, 500, 'DB_ERROR');
  }

  const consumption = rows?.[0];
  if (!consumption) {
    throw new HandshakeError('Consumption record not returned by DB', 500, 'DB_ERROR');
  }

  // Belt AND suspenders: also mark the binding's consumed_at atomically.
  // Only updates if consumed_at is not already set (idempotent, no race).
  //
  // Audit-fix (H5): the return value was previously never inspected. A
  // transient failure would leave handshake_consumptions populated but
  // handshake_bindings.consumed_at NULL, weakening the HARD GATE short-circuit
  // in verify.js. The RPC already serialized one-time-use; we throw so ops
  // can reconcile the mismatched state rather than silently degrading.
  const { error: markError } = await supabase
    .from('handshake_bindings')
    .update({
      consumed_at: consumption.created_at || new Date().toISOString(),
      consumed_by: actorRef,
      consumed_for: `${consumed_by_type}:${consumed_by_id}`,
    })
    .eq('handshake_id', handshake_id)
    .is('consumed_at', null);
  if (markError) {
    throw new HandshakeError(
      `Consumption succeeded but binding mark failed: ${markError.message}`,
      500, 'BINDING_MARK_FAILED',
    );
  }

  // SIEM: forward consumption event for audit trail (fire-and-forget)
  siemEvent('HANDSHAKE_CONSUMED', {
    handshake_id,
    consumed_by_type,
    consumed_by_id,
    actor_entity_ref: actorRef,
    consumed_by_action: consumed_by_action ?? null,
  });

  return consumption;
}

/**
 * Check if a handshake has been consumed without consuming it.
 *
 * @param {string} handshake_id - The handshake UUID to check
 * @returns {Promise<boolean>} True if a consumption record exists for this handshake
 */
export async function isHandshakeConsumed(handshake_id) {
  const supabase = getServiceClient();
  const { data, error } = await supabase
    .from('handshake_consumptions')
    .select('id')
    .eq('handshake_id', handshake_id)
    .maybeSingle();
  // Audit-fix (H5, part 2): previously ignored `error` and returned false on
  // any DB failure. A caller using this helper to gate action execution would
  // then permit double-execution on a transient error. Fail closed: on DB
  // failure, throw so the caller MUST handle it explicitly.
  if (error) {
    throw new HandshakeError(
      `Failed to check consumption state: ${error.message}`,
      500, 'DB_ERROR',
    );
  }
  return !!data;
}
