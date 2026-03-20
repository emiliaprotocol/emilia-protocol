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

  // Nonce match validation: if a nonce is provided at verification time,
  // it MUST match the stored nonce. This prevents replay with forged nonces.
  if (providedNonce && binding.nonce && providedNonce !== binding.nonce) {
    reason_codes.push('nonce_mismatch');
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
 */
export function checkDelegation(parties, policyId) {
  const reason_codes = [];
  const delegates = parties.filter((p) => p.party_role === 'delegate');

  for (const del of delegates) {
    if (del.delegation_chain) {
      const chain = typeof del.delegation_chain === 'string'
        ? JSON.parse(del.delegation_chain)
        : del.delegation_chain;

      if (chain.expires_at && new Date(chain.expires_at) < new Date()) {
        reason_codes.push('delegation_expired');
      }
      if (chain.scope && !chain.scope.includes(policyId) && !chain.scope.includes('*')) {
        reason_codes.push('delegation_out_of_scope');
      }
    }
  }

  return reason_codes;
}
