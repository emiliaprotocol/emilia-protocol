/**
 * Handshake Event Sourcing — Append-only event recording for handshakes.
 *
 * Provides an immutable audit trail of every state change in a handshake's
 * lifecycle. Events are stored in the `handshake_events` table and are
 * never updated or deleted.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { resolveActorRef } from '@/lib/actor';
import { sha256 } from '@/lib/crypto';

// ── Event Types ─────────────────────────────────────────────────────────────

/**
 * Canonical event-type vocabulary used by all event-recording APIs.
 *
 * These are unprefixed, action-oriented names that match the values
 * passed to requireHandshakeEvent() throughout the codebase
 * (create.js, present.js, verify.js, finalize.js).
 *
 * History: an earlier revision used prefixed names like 'handshake_created'.
 * Those were never consumed by the newer APIs and have been removed to
 * eliminate the vocabulary mismatch.
 */
export const HANDSHAKE_EVENT_TYPES = [
  'initiated',
  'presentation_added',
  'status_changed',
  'verified',
  'rejected',
  'expired',
  'revoked',
];

const VALID_EVENT_TYPES = new Set(HANDSHAKE_EVENT_TYPES);

// ── Error Class ─────────────────────────────────────────────────────────────

export class HandshakeEventError extends Error {
  constructor(message, code = 'HANDSHAKE_EVENT_ERROR') {
    super(message);
    this.name = 'HandshakeEventError';
    this.code = code;
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Generate a deterministic idempotency key from handshake_id, event_type,
 * and a discriminator (e.g., actor_id or timestamp).
 */
export function generateIdempotencyKey(handshake_id, event_type, discriminator = '') {
  const input = `${handshake_id}:${event_type}:${discriminator}`;
  return sha256(input);
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Record a handshake event to the append-only event log.
 *
 * @param {object} supabase - Supabase service client
 * @param {object} params
 * @param {string} params.handshake_id - The handshake this event belongs to
 * @param {string} params.event_type - One of HANDSHAKE_EVENT_TYPES
 * @param {object} [params.event_payload={}] - Arbitrary event data
 * @param {string} [params.actor_id='system'] - Who triggered this event
 * @param {string} [params.idempotency_key] - Optional; auto-generated if omitted
 * @returns {Promise<object>} The stored event record
 * @throws {HandshakeEventError} On validation failure or DB error
 */
export async function recordHandshakeEvent(supabase, {
  handshake_id,
  event_type,
  event_payload = {},
  actor_id = 'system',
  idempotency_key,
}) {
  // ── Validate ──
  if (!handshake_id) {
    throw new HandshakeEventError('handshake_id is required', 'MISSING_HANDSHAKE_ID');
  }
  if (!event_type) {
    throw new HandshakeEventError('event_type is required', 'MISSING_EVENT_TYPE');
  }
  if (!VALID_EVENT_TYPES.has(event_type)) {
    throw new HandshakeEventError(
      `Invalid event_type "${event_type}". Must be one of: ${HANDSHAKE_EVENT_TYPES.join(', ')}`,
      'INVALID_EVENT_TYPE',
    );
  }

  // ── Idempotency key ──
  const resolvedKey = idempotency_key || generateIdempotencyKey(handshake_id, event_type, actor_id);

  // ── Check for existing event with same idempotency key ──
  const { data: existing, error: checkError } = await supabase
    .from('handshake_events')
    .select('*')
    .eq('idempotency_key', resolvedKey)
    .maybeSingle();

  if (checkError) {
    throw new HandshakeEventError(
      `Failed to check idempotency: ${checkError.message}`,
      'DB_ERROR',
    );
  }

  // Return existing record if idempotency key already used
  if (existing) {
    return existing;
  }

  // ── Insert ──
  const record = {
    handshake_id,
    event_type,
    event_payload,
    actor_id,
    idempotency_key: resolvedKey,
    created_at: new Date().toISOString(),
  };

  const { data: stored, error: insertError } = await supabase
    .from('handshake_events')
    .insert(record)
    .select()
    .single();

  if (insertError) {
    throw new HandshakeEventError(
      `Failed to record event: ${insertError.message}`,
      'DB_ERROR',
    );
  }

  return stored;
}

/**
 * Retrieve the ordered event history for a handshake.
 *
 * @param {object} supabase - Supabase service client
 * @param {string} handshake_id
 * @returns {Promise<object[]>} Events ordered by created_at ascending
 * @throws {HandshakeEventError} On validation failure or DB error
 */
export async function getHandshakeEvents(supabase, handshake_id) {
  if (!handshake_id) {
    throw new HandshakeEventError('handshake_id is required', 'MISSING_HANDSHAKE_ID');
  }

  const { data, error } = await supabase
    .from('handshake_events')
    .select('*')
    .eq('handshake_id', handshake_id)
    .order('created_at', { ascending: true });

  if (error) {
    throw new HandshakeEventError(
      `Failed to fetch events: ${error.message}`,
      'DB_ERROR',
    );
  }

  return data || [];
}

// ── Mandatory Event Recording ────────────────────────────────────────────────

// Actor resolution delegated to shared resolveActorRef from @/lib/actor
const resolveActorId = resolveActorRef;

/**
 * Record a handshake event — REQUIRED. If this fails, the caller MUST
 * roll back or reject the operation. This function throws on failure.
 *
 * This is the MANDATORY event recorder for state-transition events.
 * Every trust-changing transition in a handshake lifecycle MUST use this
 * function. If the event cannot be written, the entire operation must fail
 * to guarantee: "every transition logged or system rejects."
 *
 * @param {object} params
 * @param {string} params.handshake_id
 * @param {string} params.event_type - e.g. 'initiated', 'presentation_added', 'status_changed', 'verified', 'rejected', 'revoked', 'expired'
 * @param {string|object} params.actor - who triggered the event
 * @param {object} [params.detail] - event-specific metadata
 * @returns {Promise<object>} The inserted event record
 * @throws {Error} If event write fails — caller must NOT proceed with state change
 */
export async function requireHandshakeEvent({ handshake_id, event_type, actor, detail = {} }) {
  const supabase = getServiceClient();
  const actorId = resolveActorId(actor);

  const record = {
    event_id: crypto.randomUUID(),
    handshake_id,
    event_type,
    actor_entity_ref: actorId,
    detail: detail,
    created_at: new Date().toISOString(),
  };

  const { data, error } = await supabase
    .from('handshake_events')
    .insert(record)
    .select()
    .single();

  if (error) {
    throw new Error(
      `EVENT_WRITE_REQUIRED: Failed to record mandatory event "${event_type}" ` +
      `for handshake ${handshake_id}: ${error.message}. ` +
      `State transition REJECTED — every transition must be logged.`
    );
  }

  return data;
}
