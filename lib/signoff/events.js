/**
 * EP Signoff — Append-only event recording for accountable signoffs.
 *
 * Provides an immutable audit trail of every state change in a signoff's
 * lifecycle. Events are stored in the `signoff_events` table and are
 * never updated or deleted.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { resolveActorRef } from '@/lib/actor';

// ── Event Types ─────────────────────────────────────────────────────────────

export const SIGNOFF_EVENT_TYPES = [
  'challenge_issued',
  'challenge_viewed',
  'challenge_expired',
  'approved',
  'denied',
  'revoked',
  'consumed',
  'attestation_expired',
  'attestation_revoked',
];

const VALID_EVENT_TYPES = new Set(SIGNOFF_EVENT_TYPES);

// ── Error Class ─────────────────────────────────────────────────────────────

export class SignoffEventError extends Error {
  constructor(message, code = 'SIGNOFF_EVENT_ERROR') {
    super(message);
    this.name = 'SignoffEventError';
    this.code = code;
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// Actor resolution delegated to shared resolveActorRef from @/lib/actor
const resolveActorId = resolveActorRef;

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Emit a signoff event to the signoff_events table.
 * Degrades gracefully if table doesn't exist (pre-migration).
 *
 * NOTE: For state-transition events that MUST be logged, use
 * requireSignoffEvent() instead. This function is for non-critical
 * telemetry and informational events only.
 *
 * @param {object} params
 * @param {string} [params.handshakeId] - The originating handshake (optional)
 * @param {string} [params.challengeId] - The signoff challenge ID
 * @param {string} [params.signoffId] - The signoff attestation ID
 * @param {string} params.eventType - One of SIGNOFF_EVENT_TYPES
 * @param {object} [params.detail] - Event-specific metadata
 * @param {string|object} [params.actorEntityRef] - Who triggered the event
 */
export async function emitSignoffEvent({
  handshakeId = null,
  challengeId = null,
  signoffId = null,
  eventType,
  detail = {},
  actorEntityRef = 'system',
}) {
  try {
    const supabase = getServiceClient();
    const actorId = resolveActorId(actorEntityRef);

    await supabase.from('signoff_events').insert({
      event_id: crypto.randomUUID(),
      handshake_id: handshakeId,
      challenge_id: challengeId,
      signoff_id: signoffId,
      event_type: eventType,
      actor_entity_ref: actorId,
      detail: detail,
      created_at: new Date().toISOString(),
    });
  } catch (e) {
    // Degrade gracefully if table doesn't exist
    const isMissingTable = e.message?.includes('does not exist') || e.message?.includes('relation');
    if (!isMissingTable) {
      console.warn('[signoff-events] Event emission failed:', e.message);
    }
  }
}

/**
 * Record a signoff event — REQUIRED. If this fails, the caller MUST
 * roll back or reject the operation. Unlike emitSignoffEvent(), this
 * throws on failure.
 *
 * This is the MANDATORY event recorder for state-transition events.
 * Every trust-changing transition in a signoff lifecycle MUST use this
 * function. If the event cannot be written, the entire operation must fail
 * to guarantee: "every transition logged or system rejects."
 *
 * @param {object} params
 * @param {string} [params.handshakeId] - The originating handshake (optional)
 * @param {string} [params.challengeId] - The signoff challenge ID
 * @param {string} [params.signoffId] - The signoff attestation ID
 * @param {string} params.eventType - One of SIGNOFF_EVENT_TYPES
 * @param {object} [params.detail] - Event-specific metadata
 * @param {string|object} [params.actorEntityRef] - Who triggered the event
 * @returns {Promise<object>} The inserted event record
 * @throws {Error} If event write fails — caller must NOT proceed with state change
 */
export async function requireSignoffEvent({
  handshakeId = null,
  challengeId = null,
  signoffId = null,
  eventType,
  detail = {},
  actorEntityRef = 'system',
}) {
  if (!eventType) {
    throw new SignoffEventError('eventType is required', 'MISSING_EVENT_TYPE');
  }
  if (!VALID_EVENT_TYPES.has(eventType)) {
    throw new SignoffEventError(
      `Invalid eventType "${eventType}". Must be one of: ${SIGNOFF_EVENT_TYPES.join(', ')}`,
      'INVALID_EVENT_TYPE',
    );
  }

  const supabase = getServiceClient();
  const actorId = resolveActorId(actorEntityRef);

  const record = {
    event_id: crypto.randomUUID(),
    handshake_id: handshakeId,
    challenge_id: challengeId,
    signoff_id: signoffId,
    event_type: eventType,
    actor_entity_ref: actorId,
    detail: detail,
    created_at: new Date().toISOString(),
  };

  const { data, error } = await supabase
    .from('signoff_events')
    .insert(record)
    .select()
    .single();

  if (error) {
    throw new Error(
      `SIGNOFF_EVENT_WRITE_REQUIRED: Failed to record mandatory event "${eventType}" ` +
      `for challenge ${challengeId || 'n/a'}, signoff ${signoffId || 'n/a'}: ${error.message}. ` +
      `State transition REJECTED — every transition must be logged.`
    );
  }

  return data;
}

/**
 * Retrieve the ordered event history for a signoff challenge or attestation.
 *
 * @param {string} challengeId - The challenge to fetch events for
 * @returns {Promise<object[]>} Events ordered by created_at ascending
 */
export async function getSignoffEvents(challengeId) {
  if (!challengeId) {
    throw new SignoffEventError('challengeId is required', 'MISSING_CHALLENGE_ID');
  }

  const supabase = getServiceClient();

  const { data, error } = await supabase
    .from('signoff_events')
    .select('*')
    .eq('challenge_id', challengeId)
    .order('created_at', { ascending: true });

  if (error) {
    throw new SignoffEventError(
      `Failed to fetch events: ${error.message}`,
      'DB_ERROR',
    );
  }

  return data || [];
}
