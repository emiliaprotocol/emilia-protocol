/**
 * EP Handshake — Re-export barrel.
 *
 * This module re-exports everything from the handshake sub-modules so that
 * existing imports from `@/lib/handshake` or `../lib/handshake` continue
 * to work with identical signatures.
 *
 * @license Apache-2.0
 */

// ── Error Class ──────────────────────────────────────────────────────────────
export { HandshakeError } from './errors.js';

// ── Constants & Crypto Helpers ───────────────────────────────────────────────
export {
  HANDSHAKE_MODES,
  ASSURANCE_LEVELS,
  HANDSHAKE_STATUSES,
  sha256,
  newNonce,
  VALID_MODES,
  VALID_PARTY_ROLES,
  VALID_DISCLOSURE_MODES,
  ASSURANCE_RANK,
} from './invariants.js';

// ── Canonical Binding Module ─────────────────────────────────────────────────
export {
  buildBindingMaterial,
  canonicalizeBinding,
  hashBinding,
  validateBindingCompleteness,
  computePartySetHash,
  computeContextHash,
  computePayloadHash,
  computePolicyHash,
} from './binding.js';

// ── Core API ─────────────────────────────────────────────────────────────────
export { initiateHandshake, _handleInitiateHandshake } from './create.js';
export { addPresentation, _handleAddPresentation } from './present.js';
export { verifyHandshake, _handleVerifyHandshake } from './verify.js';
export { revokeHandshake, _handleRevokeHandshake } from './finalize.js';
export { consumeHandshake, isHandshakeConsumed } from './consume.js';

// ── getHandshake + listHandshakes (read-only queries) ───────────────────────
import { getServiceClient } from '@/lib/supabase';
import { resolveActorRef } from '@/lib/actor';
import { HandshakeError } from './errors.js';

/**
 * Get the full handshake state including parties, presentations, binding, and result.
 * Single-record getter — requires a handshakeId.
 */
export async function getHandshake(handshakeId, actor = null) {
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

  // Scope read access to party members (Finding 11)
  if (actor && actor !== 'system') {
    const actorId = resolveActorRef(actor, actor);
    const { data: memberCheck } = await supabase
      .from('handshake_parties')
      .select('id')
      .eq('handshake_id', handshakeId)
      .eq('entity_ref', actorId)
      .limit(1);
    if (!memberCheck || memberCheck.length === 0) {
      throw new HandshakeError('Not authorized to view this handshake', 403, 'UNAUTHORIZED_HANDSHAKE_ACCESS');
    }
  }

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
 * List handshakes with optional filters.
 * Explicit list endpoint — separate from single-record getHandshake.
 */
export async function listHandshakes(filters = {}, actor = null) {
  const supabase = getServiceClient();

  // Scope reads to actor membership (Finding 11)
  const actorId = actor
    ? resolveActorRef(actor, actor)
    : null;

  // Force entity_ref filter to match authenticated actor (unless system)
  if (actorId && actorId !== 'system') {
    filters.entity_ref = actorId;
  } else if (!actorId) {
    // No actor = no results (fail closed)
    return { handshakes: [] };
  }

  let query = supabase
    .from('handshakes')
    .select('handshake_id, mode, policy_id, status, interaction_id, created_at')
    .order('created_at', { ascending: false })
    .limit(100);

  if (filters.entity_ref) {
    // Filter by party entity_ref — requires a subquery via handshake_parties
    const { data: partyRows } = await supabase
      .from('handshake_parties')
      .select('handshake_id')
      .eq('entity_ref', filters.entity_ref);
    const ids = (partyRows || []).map((r) => r.handshake_id);
    if (ids.length === 0) return { handshakes: [] };
    query = query.in('handshake_id', ids);
  }
  if (filters.status) {
    query = query.eq('status', filters.status);
  }
  if (filters.mode) {
    query = query.eq('mode', filters.mode);
  }

  const { data, error } = await query;

  if (error) {
    throw new HandshakeError(`Failed to list handshakes: ${error.message}`, 500, 'DB_ERROR');
  }

  return { handshakes: data || [] };
}

// ── _internals (testing) ─────────────────────────────────────────────────────
import {
  sha256 as _sha256,
  newNonce as _newNonce,
  VALID_MODES as _VALID_MODES,
  VALID_PARTY_ROLES as _VALID_PARTY_ROLES,
  VALID_DISCLOSURE_MODES as _VALID_DISCLOSURE_MODES,
  ASSURANCE_RANK as _ASSURANCE_RANK,
} from './invariants.js';

export const _internals = {
  sha256: _sha256,
  newNonce: _newNonce,
  VALID_MODES: _VALID_MODES,
  VALID_PARTY_ROLES: _VALID_PARTY_ROLES,
  VALID_DISCLOSURE_MODES: _VALID_DISCLOSURE_MODES,
  ASSURANCE_RANK: _ASSURANCE_RANK,
};
