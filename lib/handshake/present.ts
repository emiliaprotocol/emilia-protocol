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
import { resolveActorRef } from '@/lib/actor';

// Declared locally (rather than imported as a type from '@/lib/actor') because
// tsconfig.core.json's scoped handshake type-check treats '@/lib/*' as an
// opaque ambient module (see _external-modules.d.ts) — a named type import
// across that boundary fails with "Cannot use namespace 'ActorRef' as a type".
type ActorRef = string | { entity_id?: string; id?: string } | null | undefined;
import { HandshakeError } from './errors.js';
import {
  VALID_PARTY_ROLES,
  VALID_DISCLOSURE_MODES,
} from './invariants.js';
import { normalizeClaims, claimsToCanonicalHash } from './normalize.js';
import {
  type HandshakeIssuerProof,
  handshakeAuthorityKeyDigest,
  handshakeIssuerProofDigest,
  handshakeIssuerProofStatement,
  handshakePresentationHash,
  verifyHandshakeIssuerProof,
} from './issuer-proof.js';

interface Presentation {
  type: string;
  data: unknown;
  issuer_ref?: string;
  disclosure_mode?: string;
  issuer_proof?: HandshakeIssuerProof;
}

/**
 * Add a presentation (identity proof) to a handshake.
 * @param {string} handshakeId
 * @param {string} partyRole
 * @param {{ type: string, data: unknown, issuer_ref?: string, disclosure_mode?: string }} presentation
 * @param {string|object} [actor='system']
 */
export async function addPresentation(
  handshakeId: string,
  partyRole: string,
  presentation: Presentation,
  actor: ActorRef = 'system',
): Promise<any> {
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

  const presentation_hash = handshakePresentationHash(presentation.data);

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
      issuer_proof: presentation.issuer_proof || null,
    },
  });

  return result;
}

interface AddPresentationCommand {
  actor: ActorRef;
  input: {
    handshake_id: string;
    party_role: string;
    presentation_type: string;
    issuer_ref: string | null;
    presentation_hash: string;
    disclosure_mode: string;
    raw_claims: unknown;
    issuer_proof: HandshakeIssuerProof | null;
  };
}

/**
 * Handler: add_presentation
 * @param {{ actor: string|object, input: Record<string, unknown> }} command
 */
export async function _handleAddPresentation(command: AddPresentationCommand): Promise<{
  _protocolEventWritten: boolean;
  result: any;
  aggregateId: string;
}> {
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
    ? ((command.actor as Record<string, any>).entity_id
      || (command.actor as Record<string, any>).id
      || command.actor)
    : command.actor;

  if (authenticatedEntity !== 'system' && party.entity_ref !== authenticatedEntity) {
    throw new HandshakeError(
      'Authenticated entity does not match handshake party',
      403, 'ROLE_SPOOFING',
    );
  }

  // Normalize and persist claims
  const rawClaims = (command.input.raw_claims || null) as Record<string, unknown> | null;
  const normalizedClaims = rawClaims ? normalizeClaims(rawClaims) : null;
  const canonicalClaimsHash = normalizedClaims ? claimsToCanonicalHash(normalizedClaims) : null;
  const issuerProofStatement = issuer_ref ? {
    handshakeId: handshake_id,
    partyRole: party_role,
    presentationType: presentation_type,
    issuerRef: issuer_ref,
    actorEntityRef: String(authenticatedEntity),
    disclosureMode: disclosure_mode || 'full',
    presentationHash: presentation_hash,
    canonicalClaimsHash,
  } : null;

  // Default: unknown issuers are UNTRUSTED (fail-closed).
  // Every decision is recorded with an explicit trust_reason for auditability.
  let issuerTrusted = false;
  let issuerTrustReason: string = 'unknown';
  let resolvedAuthorityId: any = null;
  let resolvedAuthorityKeyDigest: string | null = null;

  if (!issuer_ref) {
    // Audit-fix (H4): a self-asserted presentation (no issuer_ref) is
    // untrusted by default. The prior behavior set issuerTrusted = true,
    // which flowed into the verification gate as `verified: true` and let
    // a presentation pass with no backing authority unless the policy had
    // explicit required_claims for the role. For roles without claims
    // requirements, the presentation was effectively free-pass.
    //
    // New policy: self-asserted presentations are persisted with
    // verified = false and issuer_status = 'self_asserted'. Accepting a
    // self-asserted presentation MUST be an explicit, per-role opt-in in
    // the policy (rules.required_parties.<role>.allow_self_asserted = true);
    // verify.js checks that flag against this status.
    issuerTrusted = false;
    issuerTrustReason = 'self_asserted';
  } else {
    const { data: authority, error: authError } = await supabase
      .from('authorities')
      .select('authority_id, key_id, public_key, algorithm, status, valid_from, valid_to, revoked_at')
      .eq('key_id', issuer_ref)
      .maybeSingle();

    if (authError) {
      // Audit-fix (silent-failure-hunter HIGH-3): previously this classified
      // "table missing" by substring-matching the error message ("does not
      // exist" || "relation"). That's fragile — any future Supabase error
      // message containing either substring (e.g., RLS policy complaints,
      // join-relation references) would be silently reclassified as
      // authority_table_missing, masking a real failure.
      //
      // Now we pin to PostgreSQL SQLSTATE 42P01 (undefined_table) and
      // supabase-js's sqlstate-like codes. Any other error is a real failure.
      const isMissingTable =
        authError.code === '42P01' ||
        authError.details?.includes?.('42P01');
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
      if (authority.status !== 'active' || authority.revoked_at) {
        issuerTrusted = false;
        issuerTrustReason = 'authority_revoked';
      } else if (authority.valid_to && new Date(authority.valid_to) < now) {
        issuerTrusted = false;
        issuerTrustReason = 'authority_expired';
      } else if (authority.valid_from && new Date(authority.valid_from) > now) {
        issuerTrusted = false;
        issuerTrustReason = 'authority_not_yet_valid';
      } else if (!command.input.issuer_proof) {
        issuerTrusted = false;
        issuerTrustReason = 'issuer_proof_missing';
      } else {
        resolvedAuthorityKeyDigest = handshakeAuthorityKeyDigest(authority.public_key);
        const proofValid = verifyHandshakeIssuerProof({
          proof: command.input.issuer_proof,
          authority,
          statement: issuerProofStatement!,
        });
        issuerTrusted = proofValid;
        issuerTrustReason = proofValid ? 'authority_signature_valid' : 'issuer_proof_invalid';
      }
    }
  }

  const revocation_checked = !!issuer_ref;
  // Map trust reason to precise revocation status vocabulary
  // (Finding 12: never conflate "unknown" with "revoked")
  const ISSUER_STATUS_MAP: Record<string, string> = {
    self_asserted: 'not_applicable',
    authority_signature_valid: 'good',
    issuer_proof_missing: 'unproven',
    issuer_proof_invalid: 'invalid_proof',
    authority_revoked: 'revoked',
    authority_expired: 'expired',
    authority_not_yet_valid: 'not_yet_valid',
    authority_not_found: 'unknown',
    authority_table_missing: 'registry_unavailable',
    unknown: 'unknown',
  };
  const revocation_status = ISSUER_STATUS_MAP[issuerTrustReason] || 'unknown';

  const actorRef = resolveActorRef(command.actor);
  const eventDetail = {
    party_role,
    presentation_type,
    issuer_trusted: issuerTrusted,
    issuer_status: issuerTrustReason,
    authority_key_digest: resolvedAuthorityKeyDigest,
    issuer_proof_profile: command.input.issuer_proof?.profile || null,
    issuer_proof_digest: command.input.issuer_proof
      ? handshakeIssuerProofDigest(command.input.issuer_proof)
      : null,
    // Proofs are public verification material, not bearer secrets. Retain both
    // the proof and exact canonical statement projection so an auditor can
    // independently reperform verification from the durable event.
    issuer_proof: command.input.issuer_proof || null,
    issuer_proof_statement: issuerProofStatement
      ? handshakeIssuerProofStatement(issuerProofStatement)
      : null,
  };

  // Single RPC: presentation + events + status update + protocol event in one transaction.
  // Replaces 3-4 serial writes with 1 roundtrip.
  const { data: rpcResult, error: rpcError } = await supabase.rpc('present_handshake_writes', {
    p_handshake_id: handshake_id,
    p_party_role: party_role,
    p_presentation_type: presentation_type,
    p_issuer_ref: issuer_ref || null,
    p_presentation_hash: presentation_hash,
    p_disclosure_mode: disclosure_mode || 'full',
    p_raw_claims: rawClaims,
    p_normalized_claims: normalizedClaims,
    p_canonical_claims_hash: canonicalClaimsHash,
    p_actor_entity_ref: authenticatedEntity,
    p_authority_id: resolvedAuthorityId,
    p_authority_key_digest: resolvedAuthorityKeyDigest,
    p_issuer_status: issuerTrustReason,
    p_verified: issuerTrusted,
    p_revocation_checked: revocation_checked,
    p_revocation_status: revocation_status,
    p_actor_id: actorRef,
    p_issuer_trusted: issuerTrusted,
    p_event_detail: eventDetail,
  });

  if (rpcError) {
    throw new HandshakeError(`Failed to write presentation: ${rpcError.message}`, 500, 'DB_ERROR');
  }
  if (rpcResult?.error === 'invalid_state') {
    throw new HandshakeError('Handshake no longer accepts presentations', 409, 'INVALID_STATE');
  }
  if (rpcResult?.error === 'party_binding_invalid') {
    throw new HandshakeError('Handshake party binding changed before presentation write', 403, 'ROLE_SPOOFING');
  }

  return {
    _protocolEventWritten: true, // Signal to protocolWrite: event already in DB via RPC
    result: rpcResult,
    aggregateId: handshake_id,
  };
}
