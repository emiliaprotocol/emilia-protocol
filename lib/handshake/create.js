/**
 * EP Handshake — Initiation logic.
 *
 * initiateHandshake() validates request, enforces idempotency, creates
 * pending records, calls protocolWrite.
 *
 * _handleInitiateHandshake() is the protocol-write handler.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { HandshakeError } from './errors.js';
import {
  HANDSHAKE_MODES,
  ASSURANCE_LEVELS,
  VALID_MODES,
  VALID_PARTY_ROLES,
  ASSURANCE_RANK,
  sha256,
  newNonce,
} from './invariants.js';

/**
 * Initiate a new handshake.
 */
export async function initiateHandshake({
  mode,
  policy_id,
  policy_version = null,
  interaction_id = null,
  parties,
  payload = {},
  binding_ttl_ms = 10 * 60 * 1000,
  metadata = {},
  actor = 'system',
}) {
  if (!mode || !VALID_MODES.has(mode)) {
    throw new HandshakeError(
      `mode must be one of: ${HANDSHAKE_MODES.join(', ')}`,
      400, 'INVALID_MODE',
    );
  }
  if (!policy_id) {
    throw new HandshakeError('policy_id is required', 400, 'MISSING_POLICY');
  }
  if (!Array.isArray(parties) || parties.length === 0) {
    throw new HandshakeError('At least one party is required', 400, 'MISSING_PARTIES');
  }

  for (const party of parties) {
    if (!party.role || !VALID_PARTY_ROLES.has(party.role)) {
      throw new HandshakeError(
        `party_role must be one of: ${[...VALID_PARTY_ROLES].join(', ')}`,
        400, 'INVALID_PARTY_ROLE',
      );
    }
    if (!party.entity_ref) {
      throw new HandshakeError('party.entity_ref is required', 400, 'MISSING_ENTITY_REF');
    }
    if (party.assurance_level && !ASSURANCE_RANK[party.assurance_level]) {
      throw new HandshakeError(
        `assurance_level must be one of: ${ASSURANCE_LEVELS.join(', ')}`,
        400, 'INVALID_ASSURANCE_LEVEL',
      );
    }
  }

  const hasInitiator = parties.some((p) => p.role === 'initiator');
  if (!hasInitiator) {
    throw new HandshakeError('At least one party must have role "initiator"', 400, 'NO_INITIATOR');
  }

  if (mode === 'mutual') {
    const hasResponder = parties.some((p) => p.role === 'responder');
    if (!hasResponder) {
      throw new HandshakeError('Mutual mode requires at least one responder party', 400, 'MUTUAL_REQUIRES_RESPONDER');
    }
  }

  if (mode === 'delegated') {
    const hasDelegate = parties.some((p) => p.role === 'delegate');
    if (!hasDelegate) {
      throw new HandshakeError('Delegated mode requires at least one delegate party', 400, 'DELEGATED_REQUIRES_DELEGATE');
    }
  }

  const nonce = newNonce();
  const canonicalPayload = JSON.stringify(payload, Object.keys(payload).sort());
  const payload_hash = sha256(canonicalPayload);
  const now = new Date();
  const clampedTtl = Math.max(60_000, Math.min(30 * 60_000, binding_ttl_ms));
  const expires_at = new Date(now.getTime() + clampedTtl);

  const result = await protocolWrite({
    type: COMMAND_TYPES.INITIATE_HANDSHAKE,
    actor,
    input: {
      mode,
      policy_id,
      policy_version,
      interaction_id,
      parties,
      payload_hash,
      nonce,
      expires_at: expires_at.toISOString(),
      metadata,
    },
  });

  return result;
}

/**
 * Handler: initiate_handshake
 */
export async function _handleInitiateHandshake(command) {
  const {
    mode, policy_id, policy_version, interaction_id,
    parties, payload_hash, nonce, expires_at, metadata,
  } = command.input;

  const supabase = getServiceClient();

  const handshakeRecord = {
    mode, policy_id, policy_version, interaction_id,
    status: 'initiated',
    metadata_json: metadata || {},
    initiated_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
  };

  const { data: handshake, error: hsError } = await supabase
    .from('handshakes')
    .insert(handshakeRecord)
    .select()
    .single();

  if (hsError) {
    throw new HandshakeError(`Failed to create handshake: ${hsError.message}`, 500, 'DB_ERROR');
  }

  const handshake_id = handshake.handshake_id;

  const partyRecords = parties.map((p) => ({
    handshake_id,
    party_role: p.role,
    entity_ref: p.entity_ref,
    assurance_level: p.assurance_level || null,
    verified_status: 'pending',
    delegation_chain: p.delegation_chain || null,
  }));

  const { error: partiesError } = await supabase
    .from('handshake_parties')
    .insert(partyRecords);

  if (partiesError) {
    throw new HandshakeError(`Failed to create handshake parties: ${partiesError.message}`, 500, 'DB_ERROR');
  }

  const bindingRecord = {
    handshake_id,
    payload_hash,
    nonce,
    expires_at,
    bound_at: new Date().toISOString(),
  };

  const { error: bindingError } = await supabase
    .from('handshake_bindings')
    .insert(bindingRecord);

  if (bindingError) {
    throw new HandshakeError(`Failed to create handshake binding: ${bindingError.message}`, 500, 'DB_ERROR');
  }

  return {
    result: {
      handshake_id,
      mode,
      policy_id,
      policy_version,
      status: 'initiated',
      parties: partyRecords,
      binding: bindingRecord,
    },
    aggregateId: handshake_id,
  };
}
