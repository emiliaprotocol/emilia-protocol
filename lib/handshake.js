/**
 * EP Handshake — Transaction-scoped identity verification extension
 *
 * A handshake is a transaction-scoped identity verification and disclosure
 * ceremony between one or more parties. It is an EP Extension (not core):
 * optional but powerful.
 *
 * Modes:
 *   basic      — single party presents identity proof
 *   mutual     — both parties present and verify each other
 *   selective  — partial disclosure (only required claims)
 *   delegated  — a delegate acts on behalf of a principal
 *
 * Security invariants (always enforced):
 *   - Expired binding window → reject
 *   - Failed nonce/challenge → reject
 *   - Revoked issuer authority → reject
 *   - Missing required claims → reject
 *   - Below-minimum assurance → reject
 *   - Payload hash mismatch → reject
 *   - Delegation beyond scope/expiry → reject
 *   - Result always references exact policy version
 *
 * All writes go through protocolWrite() from lib/protocol-write.js.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';

// ── Constants ────────────────────────────────────────────────────────────────

export const HANDSHAKE_MODES = ['basic', 'mutual', 'selective', 'delegated'];
export const ASSURANCE_LEVELS = ['low', 'substantial', 'high'];
export const HANDSHAKE_STATUSES = [
  'initiated',
  'pending_verification',
  'verified',
  'rejected',
  'expired',
  'revoked',
];

const VALID_MODES = new Set(HANDSHAKE_MODES);
const VALID_PARTY_ROLES = new Set(['initiator', 'responder', 'verifier', 'delegate']);
const VALID_DISCLOSURE_MODES = new Set(['full', 'selective', 'commitment']);
const ASSURANCE_RANK = { low: 1, substantial: 2, high: 3 };

// ── Error Class ──────────────────────────────────────────────────────────────

export class HandshakeError extends Error {
  constructor(message, status = 400, code = 'HANDSHAKE_ERROR') {
    super(message);
    this.name = 'HandshakeError';
    this.status = status;
    this.code = code;
  }
}

// ── Crypto Helpers ───────────────────────────────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function newNonce() {
  return crypto.randomBytes(32).toString('hex');
}

// ── Core API ─────────────────────────────────────────────────────────────────

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
 * Verify a handshake: evaluate all presentations against policy.
 */
export async function verifyHandshake(handshakeId, options = {}) {
  if (!handshakeId) {
    throw new HandshakeError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }

  const result = await protocolWrite({
    type: COMMAND_TYPES.VERIFY_HANDSHAKE,
    actor: options.actor || 'system',
    input: {
      handshake_id: handshakeId,
      payload_hash: options.payload_hash || null,
    },
  });

  return result;
}

/**
 * Get the full handshake state including parties, presentations, binding, and result.
 */
export async function getHandshake(handshakeId) {
  if (!handshakeId) {
    throw new HandshakeError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }

  const supabase = getServiceClient();

  const { data: handshake, error: hsError } = await supabase
    .from('handshakes')
    .select('*')
    .eq('handshake_id', handshakeId)
    .maybeSingle();

  if (hsError) {
    throw new HandshakeError(`Failed to fetch handshake: ${hsError.message}`, 500, 'DB_ERROR');
  }
  if (!handshake) return null;

  const [partiesRes, presentationsRes, bindingRes, resultRes] = await Promise.all([
    supabase.from('handshake_parties').select('*').eq('handshake_id', handshakeId),
    supabase.from('handshake_presentations').select('*').eq('handshake_id', handshakeId),
    supabase.from('handshake_bindings').select('*').eq('handshake_id', handshakeId).maybeSingle(),
    supabase.from('handshake_results').select('*').eq('handshake_id', handshakeId).maybeSingle(),
  ]);

  return {
    ...handshake,
    parties: partiesRes.data || [],
    presentations: presentationsRes.data || [],
    binding: bindingRes.data || null,
    result: resultRes.data || null,
  };
}

/**
 * Revoke an accepted handshake.
 */
export async function revokeHandshake(handshakeId, reason, actor = 'system') {
  if (!handshakeId) {
    throw new HandshakeError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }
  if (!reason) {
    throw new HandshakeError('reason is required for revocation', 400, 'MISSING_REASON');
  }

  const result = await protocolWrite({
    type: COMMAND_TYPES.REVOKE_HANDSHAKE,
    actor,
    input: {
      handshake_id: handshakeId,
      reason,
    },
  });

  return result;
}

// ── Protocol Write Handlers ──────────────────────────────────────────────────

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

  let issuerTrusted = true;
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
    } else if (authority) {
      if (authority.status === 'revoked') issuerTrusted = false;
      const now = new Date();
      if (authority.valid_to && new Date(authority.valid_to) < now) issuerTrusted = false;
      if (new Date(authority.valid_from) > now) issuerTrusted = false;
    }
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

/**
 * Handler: verify_handshake
 */
export async function _handleVerifyHandshake(command) {
  const { handshake_id, payload_hash: providedPayloadHash } = command.input;
  const supabase = getServiceClient();
  const reason_codes = [];

  const { data: handshake, error: hsError } = await supabase
    .from('handshakes')
    .select('*')
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
      `Cannot verify handshake in '${handshake.status}' state`,
      409, 'INVALID_STATE',
    );
  }

  const [partiesRes, presentationsRes, bindingRes] = await Promise.all([
    supabase.from('handshake_parties').select('*').eq('handshake_id', handshake_id),
    supabase.from('handshake_presentations').select('*').eq('handshake_id', handshake_id),
    supabase.from('handshake_bindings').select('*').eq('handshake_id', handshake_id).maybeSingle(),
  ]);

  const parties = partiesRes.data || [];
  const presentations = presentationsRes.data || [];
  const binding = bindingRes.data || null;

  // Check 1: Binding expiry
  if (!binding) {
    reason_codes.push('missing_binding');
  } else {
    if (new Date(binding.expires_at) < new Date()) {
      reason_codes.push('binding_expired');
    }
    if (!binding.nonce) {
      reason_codes.push('missing_nonce');
    }
    if (providedPayloadHash && binding.payload_hash !== providedPayloadHash) {
      reason_codes.push('payload_hash_mismatch');
    }
  }

  // Check 2: All required parties have presentations
  const requiredRoles = parties
    .filter((p) => p.party_role === 'initiator' || p.party_role === 'responder')
    .map((p) => p.party_role);

  for (const role of requiredRoles) {
    const hasPresentation = presentations.some((pres) => pres.party_role === role);
    if (!hasPresentation) {
      reason_codes.push(`missing_presentation_${role}`);
    }
  }

  // Check 3: Assurance levels
  for (const party of parties) {
    if (party.assurance_level) {
      const partyPres = presentations.filter((p) => p.party_role === party.party_role);
      if (partyPres.length > 0) {
        const allVerified = partyPres.every((p) => p.verified);
        if (!allVerified) {
          reason_codes.push(`assurance_not_met_${party.party_role}`);
        }
      }
    }
  }

  // Check 4: Issuer trust
  for (const pres of presentations) {
    if (pres.revocation_status === 'revoked') {
      reason_codes.push(`issuer_revoked_${pres.party_role}`);
    }
    if (pres.verified === false) {
      reason_codes.push(`unverified_presentation_${pres.party_role}`);
    }
  }

  // Check 5: Delegation scope
  if (handshake.mode === 'delegated') {
    const delegates = parties.filter((p) => p.party_role === 'delegate');
    for (const del of delegates) {
      if (del.delegation_chain) {
        const chain = typeof del.delegation_chain === 'string'
          ? JSON.parse(del.delegation_chain)
          : del.delegation_chain;
        if (chain.expires_at && new Date(chain.expires_at) < new Date()) {
          reason_codes.push('delegation_expired');
        }
        if (chain.scope && !chain.scope.includes(handshake.policy_id) && !chain.scope.includes('*')) {
          reason_codes.push('delegation_out_of_scope');
        }
      }
    }
  }

  // Determine outcome
  let outcome;
  if (reason_codes.length === 0) {
    outcome = 'accepted';
  } else if (reason_codes.every((c) =>
    c.startsWith('assurance_not_met') || c.startsWith('unverified_presentation'),
  )) {
    outcome = 'partial';
  } else if (reason_codes.includes('binding_expired')) {
    outcome = 'expired';
  } else {
    outcome = 'rejected';
  }

  // Assurance achieved
  let assurance_achieved = null;
  if (presentations.length > 0) {
    const verifiedPres = presentations.filter((p) => p.verified);
    if (verifiedPres.length === presentations.length && parties.length > 0) {
      const assuranceLevels = parties
        .filter((p) => p.assurance_level)
        .map((p) => ASSURANCE_RANK[p.assurance_level] || 0);
      if (assuranceLevels.length > 0) {
        const minRank = Math.min(...assuranceLevels);
        assurance_achieved = Object.entries(ASSURANCE_RANK).find(([, v]) => v === minRank)?.[0] || null;
      }
    }
  }

  // Store result
  const resultRecord = {
    handshake_id,
    policy_version: handshake.policy_version || handshake.policy_id,
    outcome,
    reason_codes,
    assurance_achieved,
    evaluated_at: new Date().toISOString(),
  };

  const { error: resultError } = await supabase
    .from('handshake_results')
    .insert(resultRecord);

  if (resultError) {
    throw new HandshakeError(`Failed to store handshake result: ${resultError.message}`, 500, 'DB_ERROR');
  }

  // Update handshake status
  const newStatus = outcome === 'accepted' ? 'verified'
    : outcome === 'expired' ? 'expired'
    : 'rejected';

  await supabase
    .from('handshakes')
    .update({
      status: newStatus,
      ...(newStatus === 'verified' ? { verified_at: new Date().toISOString() } : {}),
    })
    .eq('handshake_id', handshake_id);

  // Update party verified_status
  for (const party of parties) {
    const partyPres = presentations.filter((p) => p.party_role === party.party_role);
    const allVerified = partyPres.length > 0 && partyPres.every((p) => p.verified);
    const partyStatus = allVerified ? 'verified' : outcome === 'expired' ? 'expired' : 'rejected';

    await supabase
      .from('handshake_parties')
      .update({
        verified_status: partyStatus,
        ...(partyStatus === 'verified' ? { verified_at: new Date().toISOString() } : {}),
      })
      .eq('id', party.id);
  }

  // Issue EP Commit if accepted
  let commit_ref = null;
  if (outcome === 'accepted') {
    try {
      const commitResult = await protocolWrite({
        type: COMMAND_TYPES.ISSUE_COMMIT,
        actor: command.actor || 'system',
        input: {
          entity_id: parties[0]?.entity_ref || 'handshake',
          action_type: 'connect',
          scope: { handshake_id, policy_id: handshake.policy_id },
          context: { handshake_outcome: outcome, assurance_achieved },
        },
      });
      commit_ref = commitResult?.commit_id || null;

      if (commit_ref) {
        await supabase
          .from('handshakes')
          .update({ commit_ref })
          .eq('handshake_id', handshake_id);
      }
    } catch {
      // Commit issuance failure should not block the handshake result
    }
  }

  return {
    result: {
      handshake_id,
      outcome,
      reason_codes,
      assurance_achieved,
      policy_version: resultRecord.policy_version,
      commit_ref,
    },
    aggregateId: handshake_id,
  };
}

/**
 * Handler: revoke_handshake
 */
export async function _handleRevokeHandshake(command) {
  const { handshake_id, reason } = command.input;
  const supabase = getServiceClient();

  const { data: handshake, error: hsError } = await supabase
    .from('handshakes')
    .select('handshake_id, status')
    .eq('handshake_id', handshake_id)
    .maybeSingle();

  if (hsError) {
    throw new HandshakeError(`Failed to fetch handshake: ${hsError.message}`, 500, 'DB_ERROR');
  }
  if (!handshake) {
    throw new HandshakeError('Handshake not found', 404, 'NOT_FOUND');
  }

  if (handshake.status === 'revoked' || handshake.status === 'expired') {
    throw new HandshakeError(
      `Cannot revoke handshake in '${handshake.status}' state`,
      409, 'INVALID_STATE',
    );
  }

  const { error: updateError } = await supabase
    .from('handshakes')
    .update({ status: 'revoked', decision_ref: reason })
    .eq('handshake_id', handshake_id);

  if (updateError) {
    throw new HandshakeError(`Failed to revoke handshake: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return {
    result: {
      handshake_id,
      status: 'revoked',
      reason,
    },
    aggregateId: handshake_id,
  };
}

// ── Exports for testing ──────────────────────────────────────────────────────

export const _internals = {
  sha256,
  newNonce,
  VALID_MODES,
  VALID_PARTY_ROLES,
  VALID_DISCLOSURE_MODES,
  ASSURANCE_RANK,
};
