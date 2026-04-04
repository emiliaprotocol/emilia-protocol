/**
 * EP Handshake — Verification pipeline.
 *
 * verifyHandshake() runs the full verification pipeline: load state,
 * check invariants, resolve authority, compute assurance, produce outcome.
 *
 * _handleVerifyHandshake() is the protocol-write handler.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { resolveActorRef } from '@/lib/actor';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { HandshakeError } from './errors.js';
import { ASSURANCE_RANK, checkAssuranceLevel } from './invariants.js';
import { checkBinding, checkDelegation } from './bind.js';
import { resolvePolicy, checkClaimsAgainstPolicy, getRequiredPartiesForMode } from './policy.js';
import { computePolicyHash, hashBinding, canonicalizeBinding, computePayloadHash } from './binding.js';

/**
 * @typedef {Object} VerifyHandshakeResult
 * @property {string} handshake_id - The verified handshake UUID
 * @property {'accepted'|'rejected'|'partial'|'expired'} outcome - Verification outcome
 * @property {string[]} reason_codes - Array of reason codes explaining the outcome
 * @property {string|null} assurance_achieved - Minimum assurance level achieved across all parties
 * @property {string} policy_version - Policy version used for verification
 */

/**
 * Verify a handshake: evaluate all presentations against policy.
 *
 * Runs the full verification pipeline: loads handshake state, checks binding
 * integrity (expiry, nonce, payload_hash), validates presentations for all
 * required parties, evaluates assurance levels, checks delegation scope,
 * and evaluates policy-defined requirements (claims + assurance per role).
 *
 * @param {string} handshakeId - UUID of the handshake to verify
 * @param {object} [options={}] - Verification options
 * @param {string|object} [options.actor='system'] - Authenticated actor performing verification
 * @param {object|null} [options.payload=null] - Raw payload to re-hash server-side for binding integrity
 * @param {string|null} [options.nonce=null] - Expected nonce for binding integrity
 * @param {string|null} [options.action_hash=null] - Expected action hash for integrity check
 * @param {string|null} [options.policy_hash=null] - Expected policy hash for tamper detection
 * @returns {Promise<VerifyHandshakeResult>}
 * @throws {HandshakeError} MISSING_HANDSHAKE_ID if handshakeId is falsy
 * @throws {HandshakeError} NOT_FOUND if the handshake does not exist
 * @throws {HandshakeError} INVALID_STATE if handshake is not in 'initiated' or 'pending_verification' state
 * @throws {HandshakeError} DB_ERROR on database failures
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
      payload: options.payload || null,
      nonce: options.nonce || null,
      action_hash: options.action_hash || null,
      policy_hash: options.policy_hash || null,
    },
  });

  return result;
}

/**
 * Internal protocol-write handler for verify_handshake commands.
 * Called by protocolWrite() — not intended for direct use.
 *
 * Runs the full verification pipeline, stores the result, updates handshake
 * status and party verified_status, and consumes the binding on acceptance.
 *
 * @param {{ actor: string|object, input: { handshake_id: string, payload?: object|null, nonce?: string|null, action_hash?: string|null, policy_hash?: string|null } }} command
 * @returns {Promise<{ result: VerifyHandshakeResult, aggregateId: string }>}
 * @throws {HandshakeError} DB_ERROR on database failures
 * @throws {HandshakeError} NOT_FOUND if handshake does not exist
 * @throws {HandshakeError} INVALID_STATE if handshake is not in a verifiable state
 */
export async function _handleVerifyHandshake(command) {
  const { handshake_id, payload: providedPayload, nonce: providedNonce, action_hash: providedActionHash, policy_hash: providedPolicyHash } = command.input;
  // Server-side recomputation: hash is derived from the raw payload the caller presents,
  // never accepted as a caller-provided value. If no payload is provided, the check in
  // checkBinding will enforce payload_hash_required when binding.payload_hash is set.
  const serverComputedPayloadHash = providedPayload ? computePayloadHash(providedPayload) : null;
  const supabase = getServiceClient();
  const reason_codes = [];

  // HARD GATE: reject already-consumed bindings before any processing
  const { data: existingBinding } = await supabase
    .from('handshake_bindings')
    .select('consumed_at')
    .eq('handshake_id', handshake_id)
    .maybeSingle();

  if (existingBinding?.consumed_at) {
    return {
      result: {
        outcome: 'rejected',
        reason_codes: ['binding_already_consumed'],
        consumed_at: existingBinding.consumed_at,
        handshake_id: handshake_id,
      },
      aggregateId: handshake_id,
    };
  }

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

  // Check action_hash: if handshake has an action_hash, verify it matches
  if (handshake.action_hash) {
    if (!providedActionHash) {
      reason_codes.push('action_hash_required');
    } else if (providedActionHash !== handshake.action_hash) {
      reason_codes.push('action_hash_mismatch');
    }
  }

  // Check policy_hash: if handshake has a policy_hash, verify it matches
  if (handshake.policy_hash) {
    if (!providedPolicyHash) {
      reason_codes.push('policy_hash_required');
    } else if (providedPolicyHash !== handshake.policy_hash) {
      reason_codes.push('policy_hash_mismatch');
    }
  }

  // Check 1: Binding expiry, nonce match, payload_hash
  // serverComputedPayloadHash is derived from the caller-provided raw payload —
  // never from a caller-provided hash string. This closes the hash-echo vulnerability.
  reason_codes.push(...checkBinding(binding, serverComputedPayloadHash, providedNonce));

  // Check 2: All required parties have presentations.
  // Only initiator and responder are mandatory; verifier and delegate are
  // optional (policy may add them via required_parties — see Check 6 below).
  const requiredRoles = parties
    .filter((p) => p.party_role === 'initiator' || p.party_role === 'responder')
    .map((p) => p.party_role);

  for (const role of requiredRoles) {
    const hasPresentation = presentations.some((pres) => pres.party_role === role);
    if (!hasPresentation) {
      reason_codes.push(`missing_presentation_${role}`);
    }
  }

  // Check 3: Assurance levels.
  // `party.assurance_level` is the *minimum required* level for this party's role.
  // We require ALL presentations for a role to be `verified: true` — a single
  // unverified presentation fails the whole role, regardless of others.
  // (Assurance rank comparison against the required threshold is in Check 6.)
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
    reason_codes.push(...checkDelegation(parties, handshake.policy_id));
  }

  // Check 6: Policy-defined requirements (claims + assurance per role)
  // Resolve policy — fail closed if policy is required but cannot be loaded
  let policy = null;
  if (handshake.policy_id) {
    try {
      policy = await resolvePolicy(supabase, { policy_id: handshake.policy_id });
    } catch (policyErr) {
      // Policy load failure is fatal for handshake verification
      reason_codes.push('policy_load_failed');
    }

    if (!policy) {
      reason_codes.push('policy_not_found');
    }

    // Policy tamper detection: re-compute hash from the live policy rules and
    // compare against the hash snapshotted at handshake initiation.
    // If they differ, the policy was mutated after the handshake was bound —
    // a condition the TLA+ spec calls POLICY_HASH_MISMATCH and rejects as
    // a safety violation (see formal/ep_handshake.tla: PolicyHashMismatchDetection).
    if (policy && policy.rules && handshake.policy_hash) {
      const currentPolicyHash = computePolicyHash(policy.rules);
      if (currentPolicyHash !== handshake.policy_hash) {
        reason_codes.push('policy_hash_mismatch');
      }
    }

    // Policy version pin: the handshake recorded the integer version at initiation.
    // If the live policy has a different version number, the policy was silently
    // replaced (new row, potentially different hash) — reject as a version mismatch.
    if (policy && handshake.policy_version_number != null) {
      if (policy.version !== handshake.policy_version_number) {
        reason_codes.push('policy_version_pin_mismatch');
      }
    }
  }

  if (policy && policy.rules && policy.rules.required_parties) {
    const requiredRoles = getRequiredPartiesForMode(policy);
    for (const role of requiredRoles) {
      const roleReqs = policy.rules.required_parties[role];
      if (!roleReqs) continue;

      // Find the party for this role
      const party = parties.find((p) => p.party_role === role);
      // Find presentations for this role
      const rolePresentations = presentations.filter((p) => p.party_role === role);

      // 6a: Check required claims against policy
      if (Array.isArray(roleReqs.required_claims) && roleReqs.required_claims.length > 0) {
        // Merge normalized_claims from all presentations for this role
        const mergedClaims = {};
        for (const pres of rolePresentations) {
          if (pres.normalized_claims && typeof pres.normalized_claims === 'object') {
            Object.assign(mergedClaims, pres.normalized_claims);
          }
        }
        const claimResult = checkClaimsAgainstPolicy(mergedClaims, roleReqs);
        if (!claimResult.satisfied) {
          reason_codes.push(`policy_claims_missing_${role}`);
        }
      }

      // 6b: Check assurance level against policy minimum
      if (roleReqs.minimum_assurance && party && party.assurance_level) {
        const assuranceResult = checkAssuranceLevel(
          party.assurance_level,
          roleReqs.minimum_assurance,
          ASSURANCE_RANK,
        );
        if (!assuranceResult.ok) {
          reason_codes.push(`policy_assurance_below_minimum_${role}`);
        }
      }
    }
  }

  // Deduplicate reason codes (e.g. policy_hash_mismatch can be pushed by
  // both the provided-hash check and the policy-tamper-detection check)
  const deduped = [...new Set(reason_codes)];
  reason_codes.length = 0;
  reason_codes.push(...deduped);

  // Determine outcome
  let outcome;
  if (reason_codes.length === 0) {
    outcome = 'accepted';
  } else if (reason_codes.every((c) =>
    c.startsWith('assurance_not_met') || c.startsWith('unverified_presentation') || c.startsWith('policy_assurance_below_minimum'),
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

  // Determine status and event type
  const newStatus = outcome === 'accepted' ? 'verified'
    : outcome === 'expired' ? 'expired'
    : 'rejected';
  const eventType = outcome === 'accepted' ? 'handshake_verified'
    : outcome === 'expired' ? 'handshake_expired'
    : 'handshake_rejected';
  const policyVersion = handshake.policy_version || handshake.policy_id;
  const eventDetail = { outcome, reason_codes, assurance_achieved, policy_version: policyVersion };

  // Build party updates
  const partyUpdates = parties.map((party) => {
    const partyPres = presentations.filter((p) => p.party_role === party.party_role);
    const allVerified = partyPres.length > 0 && partyPres.every((p) => p.verified);
    return {
      id: party.id,
      verified_status: allVerified ? 'verified' : outcome === 'expired' ? 'expired' : 'rejected',
    };
  });

  const actorRef = resolveActorRef(command.actor);

  // Single RPC: result + event + status + party updates + binding consume in one transaction.
  // The RPC locks the binding row before writing so concurrent verify calls for the same
  // handshake are serialized. If the race is lost (binding already consumed by a concurrent
  // call), the RPC returns {ok: false, already_consumed: true} without writing any records.
  const { data: rpcResult, error: writeError } = await supabase.rpc('verify_handshake_writes', {
    p_handshake_id: handshake_id,
    p_outcome: outcome,
    p_reason_codes: reason_codes,
    p_assurance_achieved: assurance_achieved,
    p_policy_version: policyVersion,
    p_binding_hash: binding?.binding_hash || null,
    p_policy_hash: handshake.policy_hash || null,
    p_new_status: newStatus,
    p_actor_id: actorRef,
    p_actor_entity_ref: actorRef,
    p_event_type: eventType,
    p_event_detail: eventDetail,
    p_party_updates: partyUpdates,
    p_consume_binding: outcome === 'accepted' && !!binding,
  });

  if (writeError) {
    throw new HandshakeError(`Failed to write verification result: ${writeError.message}`, 500, 'DB_ERROR');
  }

  // Lost the consumption race: a concurrent verify call consumed the binding between
  // our HARD GATE check and the RPC call. Treat as rejected — the binding is gone.
  if (rpcResult?.already_consumed) {
    return {
      result: {
        outcome: 'rejected',
        reason_codes: ['binding_already_consumed'],
        consumed_at: rpcResult.consumed_at,
        handshake_id,
      },
      aggregateId: handshake_id,
    };
  }

  // Binding expired under the DB clock (authoritative). The JS-side check at
  // bind.js:25 may have passed if the node clock was ahead of the DB clock.
  // The RPC re-checks using Postgres now() to eliminate clock-skew divergence.
  if (rpcResult?.binding_expired) {
    return {
      result: {
        outcome: 'rejected',
        reason_codes: ['binding_expired'],
        expires_at: rpcResult.expires_at,
        server_now: rpcResult.server_now,
        handshake_id,
      },
      aggregateId: handshake_id,
    };
  }

  return {
    _protocolEventWritten: true,
    result: {
      handshake_id,
      outcome,
      reason_codes,
      assurance_achieved,
      policy_version: policyVersion,
    },
    aggregateId: handshake_id,
  };
}
