/**
 * EP Signoff — Challenge issuance logic.
 *
 * issueChallenge() validates request, verifies the handshake is in
 * 'verified' status with matching binding_hash, creates the challenge
 * record, and emits the required signoff event.
 *
 * All writes go through protocolWrite() or getServiceClient() (lib-only) and
 * commit through one state-locking database transaction.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { SignoffError } from './errors.js';
import { resolveAuthEntityId } from '@/lib/handshake-auth';
// requireSignoffEvent no longer called directly — batched into issue_challenge_atomic RPC

/**
 * Shape of the row returned by the issue_challenge_atomic RPC.
 */
export interface SignoffChallengeRecord {
  challenge_id: string;
  handshake_id: string;
  binding_hash: string;
  accountable_actor_ref: string;
  signoff_policy_id: string;
  signoff_policy_hash: string | null;
  required_assurance: string;
  allowed_methods: string[];
  status: string;
  expires_at: string;
  metadata_json: Record<string, unknown>;
  created_at: string;
}

interface IssueChallengeParams {
  actor?: any;
  handshakeId: string;
  bindingHash: string;
  expiresAt: string;
  metadata?: Record<string, unknown>;
  // Legacy callers may still carry these fields. They are deliberately not
  // read or forwarded: the database derives every trust-bearing value from
  // the handshake's pinned policy and current authority registry.
  accountableActorRef?: unknown;
  signoffPolicyId?: unknown;
  signoffPolicyHash?: unknown;
  requiredAssurance?: unknown;
  allowedMethods?: unknown;
}

/**
 * Issue a new signoff challenge linked to a verified handshake.
 *
 * Validates that the handshake exists and is in 'verified' status,
 * verifies the binding_hash matches, logs a signoff event (event-first),
 * and creates the challenge record.
 *
 * @param params
 * @param params.actor - The authenticated caller (resolved via resolveAuthEntityId)
 * @param params.handshakeId - The handshake this challenge is bound to
 * @param params.bindingHash - Binding hash for integrity verification
 * @param params.expiresAt - Requested ISO-8601 upper-bound expiry. The
 * database clamps it to the pinned policy, handshake, and binding windows.
 * @param params.metadata - Additional metadata
 * @returns The created challenge record
 * @throws {SignoffError} MISSING_HANDSHAKE_ID if handshakeId is not provided
 * @throws {SignoffError} MISSING_BINDING_HASH if bindingHash is not provided
 * @throws {SignoffError} MISSING_EXPIRES_AT if expiresAt is not provided
 * @throws {SignoffError} HANDSHAKE_NOT_FOUND if the handshake does not exist
 * @throws {SignoffError} INVALID_HANDSHAKE_STATE if handshake is not in 'verified' state
 * @throws {SignoffError} BINDING_NOT_FOUND if the handshake binding does not exist
 * @throws {SignoffError} BINDING_HASH_MISMATCH if bindingHash does not match
 * @throws {SignoffError} DB_ERROR on database failures
 */
export async function issueChallenge({
  actor,
  handshakeId,
  bindingHash,
  expiresAt,
  metadata = {},
}: IssueChallengeParams): Promise<any> {
  // ── Validate inputs ──
  if (!handshakeId) {
    throw new SignoffError('handshakeId is required', 400, 'MISSING_HANDSHAKE_ID');
  }
  if (!bindingHash) {
    throw new SignoffError('bindingHash is required', 400, 'MISSING_BINDING_HASH');
  }
  if (!expiresAt) {
    throw new SignoffError('expiresAt is required', 400, 'MISSING_EXPIRES_AT');
  }

  const supabase = getServiceClient();
  const actorEntityId = resolveAuthEntityId(actor);
  if (!actorEntityId) {
    throw new SignoffError('Authenticated actor is required to issue a signoff challenge', 401, 'MISSING_ACTOR');
  }

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

  // ── Verify caller is a party to the handshake ──
  // A challenge is not an open write against a known handshake id. The caller
  // must already be a party. The database derives the accountable actor as the
  // unique verified party in the policy-pinned role while holding row locks.
  const { data: parties, error: partyError } = await supabase
    .from('handshake_parties')
    .select('entity_ref, party_role')
    .eq('handshake_id', handshakeId);

  if (partyError) {
    throw new SignoffError(`Failed to fetch handshake parties: ${partyError.message}`, 500, 'DB_ERROR');
  }

  const partyRefs = new Set((parties || []).map((p) => p.entity_ref).filter(Boolean));
  if (!partyRefs.has(actorEntityId)) {
    throw new SignoffError('Caller is not a party on this handshake', 403, 'CALLER_NOT_HANDSHAKE_PARTY');
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

  // ── Atomic write: event + challenge in one transaction via RPC ──
  const challengeId = crypto.randomUUID();

  const { data: challenge, error: rpcError } = await supabase.rpc(
    'issue_challenge_atomic',
    {
      p_challenge_id: challengeId,
      p_handshake_id: handshakeId,
      p_binding_hash: bindingHash,
      p_actor_entity_ref: actorEntityId,
      p_requested_expires_at: expiresAt,
      p_metadata_json: metadata,
    },
  );

  if (rpcError) {
    const rpcMessage = [rpcError.message, rpcError.details, rpcError.hint, rpcError.code]
      .filter((value) => typeof value === 'string')
      .join(' ');
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_NOT_FOUND')) {
      throw new SignoffError('Handshake not found', 404, 'HANDSHAKE_NOT_FOUND');
    }
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_NOT_VERIFIED')) {
      throw new SignoffError('Handshake is no longer verified', 409, 'INVALID_HANDSHAKE_STATE');
    }
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_NOT_VERIFICATION_FINALIZED')) {
      throw new SignoffError('Handshake verification was not finalized', 409, 'HANDSHAKE_NOT_VERIFICATION_FINALIZED');
    }
    if (rpcMessage.includes('SIGNOFF_HANDSHAKE_EXPIRED')) {
      throw new SignoffError('Handshake has expired', 410, 'SIGNOFF_HANDSHAKE_EXPIRED');
    }
    if (rpcMessage.includes('SIGNOFF_BINDING_NOT_FOUND')) {
      throw new SignoffError('Handshake binding not found', 404, 'BINDING_NOT_FOUND');
    }
    if (rpcMessage.includes('SIGNOFF_BINDING_HASH_MISMATCH')) {
      throw new SignoffError('Handshake authorization binding changed', 409, 'BINDING_HASH_MISMATCH');
    }
    if (rpcMessage.includes('SIGNOFF_BINDING_EXPIRED')) {
      throw new SignoffError('Handshake binding has expired', 410, 'BINDING_EXPIRED');
    }
    if (rpcMessage.includes('SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED')) {
      throw new SignoffError('Handshake binding was not finalized by verification', 409, 'BINDING_NOT_VERIFICATION_FINALIZED');
    }
    if (rpcMessage.includes('SIGNOFF_AUTHORITY_ALREADY_CONSUMED')) {
      throw new SignoffError('Handshake authority has already been consumed', 409, 'AUTHORITY_ALREADY_CONSUMED');
    }
    if (rpcMessage.includes('SIGNOFF_CALLER_NOT_HANDSHAKE_PARTY')) {
      throw new SignoffError('Caller is not a party on this handshake', 403, 'CALLER_NOT_HANDSHAKE_PARTY');
    }
    if (rpcMessage.includes('SIGNOFF_POLICY_NOT_PINNED')) {
      throw new SignoffError('Handshake has no exact pinned signoff policy', 409, 'SIGNOFF_POLICY_NOT_PINNED');
    }
    if (rpcMessage.includes('SIGNOFF_PINNED_POLICY_UNAVAILABLE')) {
      throw new SignoffError('Pinned signoff policy is unavailable', 409, 'SIGNOFF_PINNED_POLICY_UNAVAILABLE');
    }
    if (rpcMessage.includes('SIGNOFF_POLICY_BLOCK_INVALID')) {
      throw new SignoffError('Pinned policy has no valid accountable signoff block', 409, 'SIGNOFF_POLICY_BLOCK_INVALID');
    }
    if (rpcMessage.includes('SIGNOFF_POLICY_HASH_UNVERIFIABLE')) {
      throw new SignoffError('Pinned policy rules cannot be hashed in the protocol profile', 409, 'SIGNOFF_POLICY_HASH_UNVERIFIABLE');
    }
    if (rpcMessage.includes('SIGNOFF_POLICY_HASH_MISMATCH')) {
      throw new SignoffError('Pinned policy rules changed after handshake verification', 409, 'SIGNOFF_POLICY_HASH_MISMATCH');
    }
    if (rpcMessage.includes('SIGNOFF_POLICY_SCOPE_MISMATCH')) {
      throw new SignoffError('Pinned signoff policy does not cover this action', 409, 'SIGNOFF_POLICY_SCOPE_MISMATCH');
    }
    if (rpcMessage.includes('SIGNOFF_ACCOUNTABLE_PARTY_AMBIGUOUS')) {
      throw new SignoffError('Pinned accountable role resolves to more than one verified party', 409, 'SIGNOFF_ACCOUNTABLE_PARTY_AMBIGUOUS');
    }
    if (rpcMessage.includes('SIGNOFF_ACCOUNTABLE_PARTY_NOT_VERIFIED')) {
      throw new SignoffError('Pinned accountable role has no verified party', 409, 'SIGNOFF_ACCOUNTABLE_PARTY_NOT_VERIFIED');
    }
    if (rpcMessage.includes('SIGNOFF_SELF_APPROVAL_FORBIDDEN')) {
      throw new SignoffError('Challenge issuer cannot be its accountable approver', 403, 'SIGNOFF_SELF_APPROVAL_FORBIDDEN');
    }
    if (rpcMessage.includes('SIGNOFF_ACCOUNTABLE_AUTHORITY_UNAVAILABLE')) {
      throw new SignoffError('Accountable party has no current authority grant for this action', 403, 'SIGNOFF_ACCOUNTABLE_AUTHORITY_UNAVAILABLE');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_REQUEST_INVALID')) {
      throw new SignoffError('Challenge request or requested expiry is invalid', 400, 'INVALID_CHALLENGE_REQUEST');
    }
    if (rpcMessage.includes('SIGNOFF_CHALLENGE_EXPIRY_INVALID')) {
      throw new SignoffError('Challenge expiry must be in the future', 400, 'INVALID_EXPIRES_AT');
    }
    throw new SignoffError(`Failed to create signoff challenge: ${rpcError.message}`, 500, 'DB_ERROR');
  }

  return { ...challenge, _protocolEventWritten: true };
}
