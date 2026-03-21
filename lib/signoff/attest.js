/**
 * EP Signoff — Attestation creation logic.
 *
 * createAttestation() validates the challenge state, verifies binding
 * integrity, checks authentication method and assurance level compliance,
 * creates the attestation record, and updates the challenge status.
 *
 * All writes go through getServiceClient() (lib-only).
 * Event-first ordering: log event BEFORE state change.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';
import {
  SIGNOFF_ASSURANCE_RANK,
  VALID_ALLOWED_METHODS,
  VALID_ASSURANCE_LEVELS,
  SIGNOFF_ALLOWED_METHODS,
  SIGNOFF_ASSURANCE_LEVELS,
} from './invariants.js';
import { requireSignoffEvent } from './events.js';

/**
 * Create an attestation for a signoff challenge.
 *
 * @param {object} params
 * @param {string} params.challengeId - The challenge being attested to
 * @param {string} params.handshakeId - The originating handshake
 * @param {string} params.bindingHash - Binding hash for integrity verification
 * @param {string} params.humanEntityRef - The human entity providing attestation
 * @param {string} params.authMethod - Authentication method used
 * @param {string} params.assuranceLevel - Assurance level achieved
 * @param {string} [params.channel] - Channel through which attestation was made
 * @param {string} [params.expiresAt] - ISO-8601 attestation expiry deadline
 * @param {string} [params.attestationHash] - Hash of the attestation payload
 * @param {object} [params.metadata] - Additional metadata
 * @returns {Promise<object>} The created attestation record
 */
export async function createAttestation({
  challengeId,
  handshakeId,
  bindingHash,
  humanEntityRef,
  authMethod,
  assuranceLevel,
  channel = null,
  expiresAt = null,
  attestationHash = null,
  metadata = {},
}) {
  // ── Validate inputs ──
  if (!challengeId) {
    throw new SignoffError('challengeId is required', 400, 'MISSING_CHALLENGE_ID');
  }
  if (!handshakeId) {
    throw new SignoffError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }
  if (!bindingHash) {
    throw new SignoffError('bindingHash is required', 400, 'MISSING_BINDING_HASH');
  }
  if (!humanEntityRef) {
    throw new SignoffError('humanEntityRef is required', 400, 'MISSING_HUMAN_ENTITY_REF');
  }
  if (!authMethod || !VALID_ALLOWED_METHODS.has(authMethod)) {
    throw new SignoffError(
      `authMethod must be one of: ${SIGNOFF_ALLOWED_METHODS.join(', ')}`,
      400, 'INVALID_AUTH_METHOD',
    );
  }
  if (!assuranceLevel || !VALID_ASSURANCE_LEVELS.has(assuranceLevel)) {
    throw new SignoffError(
      `assuranceLevel must be one of: ${SIGNOFF_ASSURANCE_LEVELS.join(', ')}`,
      400, 'INVALID_ASSURANCE_LEVEL',
    );
  }

  const supabase = getServiceClient();

  // ── Verify challenge exists and is in valid status ──
  const { data: challenge, error: chError } = await supabase
    .from('signoff_challenges')
    .select('*')
    .eq('challenge_id', challengeId)
    .maybeSingle();

  if (chError) {
    throw new SignoffError(`Failed to fetch challenge: ${chError.message}`, 500, 'DB_ERROR');
  }
  if (!challenge) {
    throw new SignoffError('Challenge not found', 404, 'CHALLENGE_NOT_FOUND');
  }

  const validChallengeStatuses = new Set(['challenge_issued', 'challenge_viewed']);
  if (!validChallengeStatuses.has(challenge.status)) {
    throw new SignoffError(
      `Challenge must be in 'challenge_issued' or 'challenge_viewed' status to attest (current: ${challenge.status})`,
      409, 'INVALID_CHALLENGE_STATE',
    );
  }

  // ── Verify binding_hash matches ──
  if (challenge.binding_hash !== bindingHash) {
    throw new SignoffError(
      'binding_hash does not match the challenge binding',
      409, 'BINDING_HASH_MISMATCH',
    );
  }

  // ── Verify authMethod is in the challenge's allowed_methods ──
  const challengeAllowedMethods = Array.isArray(challenge.allowed_methods)
    ? challenge.allowed_methods
    : [];
  if (!challengeAllowedMethods.includes(authMethod)) {
    throw new SignoffError(
      `authMethod "${authMethod}" is not in the challenge's allowed_methods: ${challengeAllowedMethods.join(', ')}`,
      403, 'METHOD_NOT_ALLOWED',
    );
  }

  // ── Verify assuranceLevel meets required_assurance ──
  const achievedRank = SIGNOFF_ASSURANCE_RANK[assuranceLevel];
  const requiredRank = SIGNOFF_ASSURANCE_RANK[challenge.required_assurance];

  if (achievedRank === undefined || requiredRank === undefined) {
    throw new SignoffError(
      'Unable to compare assurance levels',
      400, 'ASSURANCE_COMPARISON_FAILED',
    );
  }
  if (achievedRank < requiredRank) {
    throw new SignoffError(
      `Assurance level "${assuranceLevel}" does not meet required "${challenge.required_assurance}"`,
      403, 'ASSURANCE_BELOW_MINIMUM',
    );
  }

  // ── Build attestation record ──
  const signoffId = crypto.randomUUID();
  const now = new Date().toISOString();

  const attestationRecord = {
    signoff_id: signoffId,
    challenge_id: challengeId,
    handshake_id: handshakeId,
    binding_hash: bindingHash,
    human_entity_ref: humanEntityRef,
    auth_method: authMethod,
    assurance_level: assuranceLevel,
    channel: channel,
    status: 'approved',
    expires_at: expiresAt,
    attestation_hash: attestationHash,
    metadata_json: metadata,
    attested_at: now,
    created_at: now,
  };

  // ── Event-first ordering: log event BEFORE state change ──
  await requireSignoffEvent({
    handshakeId,
    challengeId,
    signoffId,
    eventType: 'approved',
    detail: {
      human_entity_ref: humanEntityRef,
      auth_method: authMethod,
      assurance_level: assuranceLevel,
      channel,
    },
    actorEntityRef: humanEntityRef,
  });

  // ── Insert attestation (AFTER event is durably recorded) ──
  const { data: attestation, error: insertError } = await supabase
    .from('signoff_attestations')
    .insert(attestationRecord)
    .select()
    .single();

  if (insertError) {
    throw new SignoffError(`Failed to create attestation: ${insertError.message}`, 500, 'DB_ERROR');
  }

  // ── Update challenge status to 'approved' (AFTER event and attestation) ──
  const { error: updateError } = await supabase
    .from('signoff_challenges')
    .update({
      status: 'approved',
      approved_at: now,
    })
    .eq('challenge_id', challengeId);

  if (updateError) {
    throw new SignoffError(`Failed to update challenge status: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return attestation;
}
