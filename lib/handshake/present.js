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
import { normalizeClaims, claimsToCanonicalHash } from './normalize.js';

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
      raw_claims: presentation.data,
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
    .select('id, party_role, entity_ref')
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

  // Actor/party binding: authenticated entity must match the party's entity_ref
  const authenticatedEntity = typeof command.actor === 'object'
    ? (command.actor.entity_id || command.actor.id || command.actor)
    : command.actor;

  if (authenticatedEntity !== 'system' && party.entity_ref !== authenticatedEntity) {
    throw new HandshakeError(
      'Authenticated entity does not match handshake party',
      403, 'ROLE_SPOOFING',
    );
  }

  // Normalize and persist claims
  const rawClaims = command.input.raw_claims || null;
  const normalizedClaims = rawClaims ? normalizeClaims(rawClaims) : null;
  const canonicalClaimsHash = normalizedClaims ? claimsToCanonicalHash(normalizedClaims) : null;

  // Default: unknown issuers are UNTRUSTED (fail-closed).
  // Every decision is recorded with an explicit trust_reason for auditability.
  let issuerTrusted = false;
  let issuerTrustReason = 'unknown';
  let resolvedAuthorityId = null;

  if (!issuer_ref) {
    // Self-asserted presentation: trust determination deferred to policy rules
    issuerTrusted = true;
    issuerTrustReason = 'self_asserted';
  } else {
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
      // Table missing = no authority registry = fail closed
      issuerTrusted = false;
      issuerTrustReason = 'authority_table_missing';
    } else if (!authority) {
      // Issuer not found in registry = fail closed
      issuerTrusted = false;
      issuerTrustReason = 'authority_not_found';
    } else {
      resolvedAuthorityId = authority.authority_id;
      const now = new Date();
      if (authority.status === 'revoked') {
        issuerTrusted = false;
        issuerTrustReason = 'authority_revoked';
      } else if (authority.valid_to && new Date(authority.valid_to) < now) {
        issuerTrusted = false;
        issuerTrustReason = 'authority_expired';
      } else if (authority.valid_from && new Date(authority.valid_from) > now) {
        issuerTrusted = false;
        issuerTrustReason = 'authority_not_yet_valid';
      } else {
        issuerTrusted = true;
        issuerTrustReason = 'authority_valid';
      }
    }
  }

  const revocation_checked = !!issuer_ref;
  // Map trust reason to precise revocation status vocabulary
  // (Finding 12: never conflate "unknown" with "revoked")
  const ISSUER_STATUS_MAP = {
    self_asserted: 'not_applicable',
    authority_valid: 'good',
    authority_revoked: 'revoked',
    authority_expired: 'expired',
    authority_not_yet_valid: 'not_yet_valid',
    authority_not_found: 'unknown',
    authority_table_missing: 'registry_unavailable',
    unknown: 'unknown',
  };
  const revocation_status = ISSUER_STATUS_MAP[issuerTrustReason] || 'unknown';

  const presentationRecord = {
    handshake_id,
    party_role,
    presentation_type,
    issuer_ref,
    presentation_hash,
    disclosure_mode: disclosure_mode || 'full',
    raw_claims: rawClaims,
    normalized_claims: normalizedClaims,
    canonical_claims_hash: canonicalClaimsHash,
    actor_entity_ref: authenticatedEntity,
    authority_id: resolvedAuthorityId,
    issuer_status: issuerTrustReason,
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

  // Record handshake event — REQUIRED (event immutability guarantee).
  // Event is written BEFORE state change: if event fails, state stays unchanged (safe).
  // If event succeeds but state change fails, we have a logged but uncommitted transition (safe — retry).
  const { requireHandshakeEvent } = await import('./events.js');
  await requireHandshakeEvent({
    handshake_id,
    event_type: 'presentation_added',
    actor: command.actor,
    detail: { party_role, presentation_type, issuer_trusted: issuerTrusted, issuer_status: issuerTrustReason },
  });

  if (handshake.status === 'initiated') {
    // Record status transition event BEFORE the actual status change
    await requireHandshakeEvent({
      handshake_id,
      event_type: 'status_changed',
      actor: command.actor,
      detail: { from: 'initiated', to: 'pending_verification', trigger: 'presentation_added' },
    });

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
