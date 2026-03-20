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
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { HandshakeError } from './errors.js';
import { ASSURANCE_RANK } from './invariants.js';
import { checkBinding, checkDelegation } from './bind.js';

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

  // Check 1: Binding expiry, nonce, payload_hash
  reason_codes.push(...checkBinding(binding, providedPayloadHash));

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
    reason_codes.push(...checkDelegation(parties, handshake.policy_id));
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
