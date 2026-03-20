/**
 * EP Handshake — Presentation logic.
 *
 * addPresentation() accepts party presentation, normalizes, encrypts
 * if policy allows, records.
 *
 * _handleAddPresentation() is the protocol-write handler.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { HandshakeError } from './errors.js';
import {
  VALID_PARTY_ROLES,
  VALID_DISCLOSURE_MODES,
  sha256,
} from './invariants.js';

/**
 * Add a presentation (identity proof) to a handshake.
 */
export async function addPresentation(handshakeId, partyRole, presentation, actor = 'system') {
  if (!handshakeId) {
    throw new HandshakeError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }
  if (!partyRole || !VALID_PARTY_ROLES.has(partyRole)) {
    throw new HandshakeError(
      `partyRole must be one of: ${[...VALID_PARTY_ROLES].join(', ')}`,
      400, 'INVALID_PARTY_ROLE',
    );
  }
  if (!presentation || !presentation.type || !presentation.data) {
    throw new HandshakeError('presentation must include type and data', 400, 'INVALID_PRESENTATION');
  }
  if (presentation.disclosure_mode && !VALID_DISCLOSURE_MODES.has(presentation.disclosure_mode)) {
    throw new HandshakeError(
      `disclosure_mode must be one of: ${[...VALID_DISCLOSURE_MODES].join(', ')}`,
      400, 'INVALID_DISCLOSURE_MODE',
    );
  }

  const presentation_hash = sha256(
    typeof presentation.data === 'string'
      ? presentation.data
      : JSON.stringify(presentation.data),
  );

  const result = await protocolWrite({
    type: COMMAND_TYPES.ADD_PRESENTATION,
    actor,
    input: {
      handshake_id: handshakeId,
      party_role: partyRole,
      presentation_type: presentation.type,
      issuer_ref: presentation.issuer_ref || null,
      presentation_hash,
      disclosure_mode: presentation.disclosure_mode || 'full',
    },
  });

  return result;
}

/**
 * Handler: add_presentation
 */
export async function _handleAddPresentation(command) {
  const {
    handshake_id, party_role, presentation_type,
    issuer_ref, presentation_hash, disclosure_mode,
  } = command.input;

  const supabase = getServiceClient();

  const { data: handshake, error: hsError } = await supabase
    .from('handshakes')
    .select('handshake_id, status, policy_id')
    .eq('handshake_id', handshake_id)
    .maybeSingle();

  if (hsError) {
    throw new HandshakeError(`Failed to fetch handshake: ${hsError.message}`, 500, 'DB_ERROR');
  }
  if (!handshake) {
    throw new HandshakeError('Handshake not found', 404, 'NOT_FOUND');
  }
  if (handshake.status !== 'initiated' && handshake.status !== 'pending_verification') {
    throw new HandshakeError(
      `Cannot add presentation to handshake in '${handshake.status}' state`,
      409, 'INVALID_STATE',
    );
  }

  const { data: party, error: partyError } = await supabase
    .from('handshake_parties')
    .select('id, party_role')
    .eq('handshake_id', handshake_id)
    .eq('party_role', party_role)
    .maybeSingle();

  if (partyError) {
    throw new HandshakeError(`Failed to fetch party: ${partyError.message}`, 500, 'DB_ERROR');
  }
  if (!party) {
    throw new HandshakeError(
      `No party with role '${party_role}' in this handshake`,
      404, 'PARTY_NOT_FOUND',
    );
  }

  // Default: unknown issuers are UNTRUSTED (fail-closed).
  // Only mark trusted if issuer_ref is absent (self-asserted, policy-dependent)
  // or if a valid, non-revoked authority is found.
  let issuerTrusted = !issuer_ref; // self-asserted = trust determination deferred to policy
  if (issuer_ref) {
    const { data: authority, error: authError } = await supabase
      .from('authorities')
      .select('authority_id, status, valid_from, valid_to')
      .eq('key_id', issuer_ref)
      .maybeSingle();

    if (authError) {
      const isMissingTable =
        authError.message?.includes('does not exist') ||
        authError.message?.includes('relation');
      if (!isMissingTable) {
        throw new HandshakeError(
          `Failed to check issuer authority: ${authError.message}`,
          500, 'DB_ERROR',
        );
      }
      // Table missing = no authority registry = untrusted (issuerTrusted stays false)
    } else if (authority) {
      // Found an authority — check validity
      const now = new Date();
      const isRevoked = authority.status === 'revoked';
      const isExpired = authority.valid_to && new Date(authority.valid_to) < now;
      const isNotYetValid = new Date(authority.valid_from) > now;
      issuerTrusted = !isRevoked && !isExpired && !isNotYetValid;
    }
    // else: no authority found for this issuer_ref = untrusted (issuerTrusted stays false)
  }

  const revocation_checked = issuer_ref ? true : false;
  const revocation_status = issuerTrusted ? 'good' : 'revoked';

  const presentationRecord = {
    handshake_id,
    party_role,
    presentation_type,
    issuer_ref,
    presentation_hash,
    disclosure_mode: disclosure_mode || 'full',
    verified: issuerTrusted,
    verified_at: issuerTrusted ? new Date().toISOString() : null,
    revocation_checked,
    revocation_status,
  };

  const { data: stored, error: insertError } = await supabase
    .from('handshake_presentations')
    .insert(presentationRecord)
    .select()
    .single();

  if (insertError) {
    throw new HandshakeError(`Failed to store presentation: ${insertError.message}`, 500, 'DB_ERROR');
  }

  if (handshake.status === 'initiated') {
    await supabase
      .from('handshakes')
      .update({ status: 'pending_verification' })
      .eq('handshake_id', handshake_id)
      .eq('status', 'initiated');
  }

  return {
    result: stored,
    aggregateId: handshake_id,
  };
}
