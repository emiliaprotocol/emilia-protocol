/**
 * EP Signoff — Challenge issuance logic.
 *
 * issueChallenge() validates request, verifies the handshake is in
 * 'verified' status with matching binding_hash, creates the challenge
 * record, and emits the required signoff event.
 *
 * All writes go through protocolWrite() or getServiceClient() (lib-only).
 * Event-first ordering: log event BEFORE state change.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';
import {
  VALID_ALLOWED_METHODS,
  VALID_ASSURANCE_LEVELS,
  SIGNOFF_ALLOWED_METHODS,
  SIGNOFF_ASSURANCE_LEVELS,
} from './invariants.js';
import { requireSignoffEvent } from './events.js';

/**
 * @typedef {Object} SignoffChallengeRecord
 * @property {string} challenge_id - UUID of the created challenge
 * @property {string} handshake_id - The bound handshake UUID
 * @property {string} binding_hash - Binding hash for integrity verification
 * @property {string} accountable_actor_ref - Entity who must sign off
 * @property {string} signoff_policy_id - Policy governing this signoff
 * @property {string|null} signoff_policy_hash - SHA-256 of policy rules at issuance time
 * @property {string} required_assurance - Minimum assurance level required
 * @property {string[]} allowed_methods - Authentication methods permitted
 * @property {string} status - Always 'challenge_issued' on creation
 * @property {string} expires_at - ISO-8601 challenge expiry deadline
 * @property {object} metadata_json - Additional metadata
 * @property {string} created_at - ISO-8601 creation timestamp
 */

/**
 * Issue a new signoff challenge linked to a verified handshake.
 *
 * Validates that the handshake exists and is in 'verified' status,
 * verifies the binding_hash matches, logs a signoff event (event-first),
 * and creates the challenge record.
 *
 * @param {object} params
 * @param {string} params.handshakeId - The handshake this challenge is bound to
 * @param {string} params.bindingHash - Binding hash for integrity verification
 * @param {string} params.accountableActorRef - The entity who must sign off
 * @param {string} params.signoffPolicyId - Policy governing this signoff
 * @param {string|null} [params.signoffPolicyHash=null] - SHA-256 of policy rules at issuance time
 * @param {string} params.requiredAssurance - Minimum assurance level required (e.g. 'low', 'medium', 'high', 'very_high')
 * @param {string[]} params.allowedMethods - Authentication methods permitted (e.g. ['password', 'totp', 'webauthn'])
 * @param {string} params.expiresAt - ISO-8601 challenge expiry deadline
 * @param {object} [params.metadata={}] - Additional metadata
 * @returns {Promise<SignoffChallengeRecord>} The created challenge record
 * @throws {SignoffError} MISSING_HANDSHAKE_ID if handshakeId is not provided
 * @throws {SignoffError} MISSING_BINDING_HASH if bindingHash is not provided
 * @throws {SignoffError} MISSING_ACTOR_REF if accountableActorRef is not provided
 * @throws {SignoffError} MISSING_POLICY_ID if signoffPolicyId is not provided
 * @throws {SignoffError} INVALID_ASSURANCE_LEVEL if requiredAssurance is not recognized
 * @throws {SignoffError} MISSING_ALLOWED_METHODS if allowedMethods is empty
 * @throws {SignoffError} INVALID_METHOD if any method in allowedMethods is not recognized
 * @throws {SignoffError} MISSING_EXPIRES_AT if expiresAt is not provided
 * @throws {SignoffError} HANDSHAKE_NOT_FOUND if the handshake does not exist
 * @throws {SignoffError} INVALID_HANDSHAKE_STATE if handshake is not in 'verified' state
 * @throws {SignoffError} BINDING_NOT_FOUND if the handshake binding does not exist
 * @throws {SignoffError} BINDING_HASH_MISMATCH if bindingHash does not match
 * @throws {SignoffError} DB_ERROR on database failures
 */
export async function issueChallenge({
  handshakeId,
  bindingHash,
  accountableActorRef,
  signoffPolicyId,
  signoffPolicyHash = null,
  requiredAssurance,
  allowedMethods,
  expiresAt,
  metadata = {},
}) {
  // ── Validate inputs ──
  if (!handshakeId) {
    throw new SignoffError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }
  if (!bindingHash) {
    throw new SignoffError('bindingHash is required', 400, 'MISSING_BINDING_HASH');
  }
  if (!accountableActorRef) {
    throw new SignoffError('accountableActorRef is required', 400, 'MISSING_ACTOR_REF');
  }
  if (!signoffPolicyId) {
    throw new SignoffError('signoffPolicyId is required', 400, 'MISSING_POLICY_ID');
  }
  if (!requiredAssurance || !VALID_ASSURANCE_LEVELS.has(requiredAssurance)) {
    throw new SignoffError(
      `requiredAssurance must be one of: ${SIGNOFF_ASSURANCE_LEVELS.join(', ')}`,
      400, 'INVALID_ASSURANCE_LEVEL',
    );
  }
  if (!Array.isArray(allowedMethods) || allowedMethods.length === 0) {
    throw new SignoffError('allowedMethods must be a non-empty array', 400, 'MISSING_ALLOWED_METHODS');
  }
  for (const method of allowedMethods) {
    if (!VALID_ALLOWED_METHODS.has(method)) {
      throw new SignoffError(
        `Invalid method "${method}". Must be one of: ${SIGNOFF_ALLOWED_METHODS.join(', ')}`,
        400, 'INVALID_METHOD',
      );
    }
  }
  if (!expiresAt) {
    throw new SignoffError('expiresAt is required', 400, 'MISSING_EXPIRES_AT');
  }

  const supabase = getServiceClient();

  // ── Verify handshake exists and is in 'verified' status ──
  const { data: handshake, error: hsError } = await supabase
    .from('handshakes')
    .select('handshake_id, status')
    .eq('handshake_id', handshakeId)
    .maybeSingle();

  if (hsError) {
    throw new SignoffError(`Failed to fetch handshake: ${hsError.message}`, 500, 'DB_ERROR');
  }
  if (!handshake) {
    throw new SignoffError('Handshake not found', 404, 'HANDSHAKE_NOT_FOUND');
  }
  if (handshake.status !== 'verified') {
    throw new SignoffError(
      `Handshake must be in 'verified' status to issue a challenge (current: ${handshake.status})`,
      409, 'INVALID_HANDSHAKE_STATE',
    );
  }

  // ── Verify binding_hash matches the handshake's binding_hash ──
  const { data: binding, error: bindError } = await supabase
    .from('handshake_bindings')
    .select('binding_hash')
    .eq('handshake_id', handshakeId)
    .maybeSingle();

  if (bindError) {
    throw new SignoffError(`Failed to fetch handshake binding: ${bindError.message}`, 500, 'DB_ERROR');
  }
  if (!binding) {
    throw new SignoffError('Handshake binding not found', 404, 'BINDING_NOT_FOUND');
  }
  if (binding.binding_hash !== bindingHash) {
    throw new SignoffError(
      'binding_hash does not match the handshake binding',
      409, 'BINDING_HASH_MISMATCH',
    );
  }

  // ── Build challenge record ──
  const challengeId = crypto.randomUUID();
  const now = new Date().toISOString();

  const challengeRecord = {
    challenge_id: challengeId,
    handshake_id: handshakeId,
    binding_hash: bindingHash,
    accountable_actor_ref: accountableActorRef,
    signoff_policy_id: signoffPolicyId,
    signoff_policy_hash: signoffPolicyHash,
    required_assurance: requiredAssurance,
    allowed_methods: allowedMethods,
    status: 'challenge_issued',
    expires_at: expiresAt,
    metadata_json: metadata,
    created_at: now,
  };

  // ── Event-first ordering: log event BEFORE state change ──
  await requireSignoffEvent({
    handshakeId,
    challengeId,
    eventType: 'challenge_issued',
    detail: {
      accountable_actor_ref: accountableActorRef,
      signoff_policy_id: signoffPolicyId,
      required_assurance: requiredAssurance,
      allowed_methods: allowedMethods,
      expires_at: expiresAt,
    },
    actorEntityRef: accountableActorRef,
  });

  // ── Insert challenge (AFTER event is durably recorded) ──
  const { data: challenge, error: insertError } = await supabase
    .from('signoff_challenges')
    .insert(challengeRecord)
    .select()
    .single();

  if (insertError) {
    throw new SignoffError(`Failed to create signoff challenge: ${insertError.message}`, 500, 'DB_ERROR');
  }

  return challenge;
}
