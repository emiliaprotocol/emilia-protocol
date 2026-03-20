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

// ── Event Types ─────────────────────────────────────────────────────────────

export const HANDSHAKE_EVENT_TYPES = [
  'handshake_created',
  'handshake_presented',
  'handshake_verification_started',
  'handshake_verified',
  'handshake_rejected',
  'handshake_expired',
  'handshake_cancelled',
  'handshake_revoked',
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
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
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
