/**
 * EP Handshake — Binding verification logic.
 *
 * Pure functions that check payload_hash, nonce, expiry,
 * session/document references.
 *
 * @license Apache-2.0
 */

/**
 * Check binding invariants and return an array of reason_codes for failures.
 *
 * @param {object} binding - The stored binding record
 * @param {string|null} providedPayloadHash - Payload hash provided at verification time
 * @param {string|null} providedNonce - Nonce provided at verification time for match validation
 */
export function checkBinding(binding, providedPayloadHash = null, providedNonce = null) {
  const reason_codes = [];

  if (!binding) {
    reason_codes.push('missing_binding');
    return reason_codes;
  }

  if (new Date(binding.expires_at) < new Date()) {
    reason_codes.push('binding_expired');
  }

  if (binding.consumed_at) {
    reason_codes.push('binding_already_consumed');
  }

  if (!binding.nonce) {
    reason_codes.push('missing_nonce');
  }

  // Nonce validation: two symmetric guards, matching the payload_hash pattern.
  //   (a) If a nonce is provided it MUST match the stored nonce — prevents forged nonces.
  //   (b) If the binding has a nonce, one MUST be provided — prevents omission bypass
  //       where an attacker skips the nonce to sidestep the mismatch check entirely.
  if (providedNonce && binding.nonce && providedNonce !== binding.nonce) {
    reason_codes.push('nonce_mismatch');
  }
  if (binding.nonce && !providedNonce) {
    reason_codes.push('nonce_required');
  }

  if (providedPayloadHash && binding.payload_hash !== providedPayloadHash) {
    reason_codes.push('payload_hash_mismatch');
  }

  // Payload hash is mandatory when binding has one (not optional anymore)
  if (binding.payload_hash && !providedPayloadHash) {
    reason_codes.push('payload_hash_required');
  }

  return reason_codes;
}

/**
 * Check delegation scope and expiry. Returns an array of reason_codes for failures.
 *
 * Audit-fix (C5): fail closed on absent scope / expires_at and on malformed
 * delegation_chain JSON. The previous version treated missing fields as
 * vacuously-satisfied (universal scope, infinite expiry) which made the
 * delegation model trivially bypassable — a delegate could submit
 * `{ delegate_id: "x" }` with no scope and no expiry and be accepted as
 * permanent, unscoped. Malformed JSON also escaped unwrapped and 500'd
 * instead of producing a reason_code.
 */
export function checkDelegation(parties, policyId) {
  const reason_codes = [];
  const delegates = parties.filter((p) => p.party_role === 'delegate');

  for (const del of delegates) {
    if (!del.delegation_chain) {
      reason_codes.push('delegation_chain_missing');
      continue;
    }

    let chain;
    if (typeof del.delegation_chain === 'string') {
      try {
        chain = JSON.parse(del.delegation_chain);
      } catch {
        reason_codes.push('delegation_chain_malformed');
        continue;
      }
    } else if (typeof del.delegation_chain === 'object' && del.delegation_chain !== null) {
      chain = del.delegation_chain;
    } else {
      reason_codes.push('delegation_chain_malformed');
      continue;
    }

    // expires_at MUST be present. Missing = trust nothing.
    if (!chain.expires_at) {
      reason_codes.push('delegation_missing_expiry');
    } else if (new Date(chain.expires_at) < new Date()) {
      reason_codes.push('delegation_expired');
    }

    // scope MUST be present. Missing = trust nothing.
    // Accept either an array of policy_ids, the wildcard '*' as a string in
    // the array, or the string '*' meaning "universal" (explicitly declared).
    if (chain.scope === undefined || chain.scope === null) {
      reason_codes.push('delegation_missing_scope');
    } else if (Array.isArray(chain.scope)) {
      if (!chain.scope.includes(policyId) && !chain.scope.includes('*')) {
        reason_codes.push('delegation_out_of_scope');
      }
    } else if (chain.scope !== '*') {
      // Scope present but neither an array nor the explicit wildcard — malformed.
      reason_codes.push('delegation_chain_malformed');
    }
  }

  return reason_codes;
}
