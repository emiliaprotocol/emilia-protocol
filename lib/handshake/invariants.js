/**
 * EP Handshake — Pure invariant check functions.
 *
 * One function per security invariant from CTO plan Section 19.
 * Every function is pure (no side effects, no DB calls) and returns
 * { ok: boolean, code: string, message: string }.
 *
 * Error codes reference Section 18 of the CTO plan.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

// ── Constants ────────────────────────────────────────────────────────────────

export const HANDSHAKE_MODES = ['basic', 'mutual', 'selective', 'delegated'];
export const ASSURANCE_LEVELS = ['low', 'medium', 'substantial', 'high'];
export const HANDSHAKE_STATUSES = [
  'initiated',
  'pending_verification',
  'verified',
  'rejected',
  'expired',
  'revoked',
];

export const VALID_MODES = new Set(HANDSHAKE_MODES);
export const VALID_PARTY_ROLES = new Set(['initiator', 'responder', 'verifier', 'delegate']);
export const VALID_DISCLOSURE_MODES = new Set(['full', 'selective', 'commitment']);
export const ASSURANCE_RANK = { low: 1, medium: 2, substantial: 3, high: 4 };

/**
 * Canonical binding envelope fields — every field listed here MUST be
 * included in binding_hash computation. Adding or removing a field
 * requires incrementing BINDING_MATERIAL_VERSION.
 *
 * Reviewer note: These map to the protocol specification requirements:
 *   action      → action_type
 *   target      → resource_ref
 *   policy_hash → policy_hash (SHA-256 of policy.rules at bind time)
 *   party set   → party_set_hash (SHA-256 of sorted role:entity_ref pairs)
 *   payload     → payload_hash (SHA-256 of canonicalized payload)
 *   nonce       → nonce (32-byte random hex, unique per binding)
 *   expiry      → expires_at (binding TTL deadline)
 */
export const CANONICAL_BINDING_FIELDS = Object.freeze([
  'action_type',
  'resource_ref',
  'policy_id',
  'policy_version',
  'policy_hash',
  'interaction_id',
  'party_set_hash',
  'payload_hash',
  'context_hash',
  'nonce',
  'expires_at',
  'binding_material_version',
]);

export const BINDING_MATERIAL_VERSION = 1;

// ── Crypto Helpers ───────────────────────────────────────────────────────────

export function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

export function newNonce() {
  return crypto.randomBytes(32).toString('hex');
}

// ── Invariant Result Helper ──────────────────────────────────────────────────

function pass(code) {
  return { ok: true, code, message: 'ok' };
}

function fail(code, message) {
  return { ok: false, code, message };
}

// ── Invariant 1: Must not finalize after expiry ─────────────────────────────

/**
 * Check that the handshake binding has not expired.
 * @param {{ binding?: { expires_at: string } }} handshake
 */
export function checkNotExpired(handshake) {
  const code = 'BINDING_EXPIRED';
  if (!handshake || !handshake.binding || !handshake.binding.expires_at) {
    return fail(code, 'Handshake binding or expiry is missing');
  }
  const expiresAt = new Date(handshake.binding.expires_at);
  if (new Date() >= expiresAt) {
    return fail(code, 'Handshake binding has expired');
  }
  return pass(code);
}

// ── Invariant 2: All required parties must be present ───────────────────────

/**
 * Check that every party role required by policy has a corresponding
 * presentation.
 * @param {object} handshake
 * @param {Array<{ party_role: string }>} parties
 * @param {Array<{ party_role: string }>} presentations
 * @param {{ rules?: { required_parties?: Record<string, unknown> } }} policy
 */
export function checkAllPartiesPresent(handshake, parties, presentations, policy) {
  const code = 'MISSING_REQUIRED_PARTY';
  if (!policy || !policy.rules || !policy.rules.required_parties) {
    // No policy requirements — vacuously true
    return pass(code);
  }

  const requiredRoles = Object.keys(policy.rules.required_parties);
  const presentedRoles = new Set((presentations || []).map((p) => p.party_role));
  const missingRoles = requiredRoles.filter((role) => !presentedRoles.has(role));

  if (missingRoles.length > 0) {
    return fail(code, `Missing presentations for required roles: ${missingRoles.join(', ')}`);
  }
  return pass(code);
}

// ── Invariant 3: Binding verification ───────────────────────────────────────

/**
 * Check that the binding payload hash matches the verification payload hash.
 * @param {{ payload_hash?: string, nonce?: string }} binding
 * @param {string|null} verificationPayloadHash
 */
export function checkBindingValid(binding, verificationPayloadHash) {
  const code = 'BINDING_INVALID';
  if (!binding) {
    return fail(code, 'Binding is missing');
  }
  if (!binding.nonce) {
    return fail(code, 'Binding nonce is missing');
  }
  if (verificationPayloadHash && binding.payload_hash !== verificationPayloadHash) {
    return fail(code, 'Payload hash mismatch');
  }
  return pass(code);
}

// ── Invariant 4: Issuer / authority trust ───────────────────────────────────

/**
 * Check that the presentation's issuer is in the list of trusted authorities.
 * @param {{ issuer_ref?: string }} presentation
 * @param {Array<{ key_id: string, status?: string }>} authorities
 */
export function checkIssuerTrusted(presentation, authorities) {
  const code = 'ISSUER_NOT_TRUSTED';
  if (!presentation || !presentation.issuer_ref) {
    // No issuer declared — cannot verify trust, treat as unknown
    return fail(code, 'Presentation has no issuer_ref');
  }
  if (!authorities || !Array.isArray(authorities) || authorities.length === 0) {
    return fail(code, 'No authorities provided for trust verification');
  }
  const authority = authorities.find((a) => a.key_id === presentation.issuer_ref);
  if (!authority) {
    return fail(code, `Issuer "${presentation.issuer_ref}" not found in authorities`);
  }
  return pass(code);
}

// ── Invariant 5: Revoked authority check ────────────────────────────────────

/**
 * Check that the authority has not been revoked.
 * @param {{ status?: string }} authority
 */
export function checkAuthorityNotRevoked(authority) {
  const code = 'AUTHORITY_REVOKED';
  if (!authority) {
    return fail(code, 'Authority is missing');
  }
  if (authority.status === 'revoked') {
    return fail(code, 'Authority has been revoked');
  }
  return pass(code);
}

// ── Invariant 6: Minimum assurance level ────────────────────────────────────

/**
 * Check that the achieved assurance level meets or exceeds the required level.
 * @param {string} achievedLevel
 * @param {string} requiredLevel
 * @param {Record<string, number>} assuranceRank — rank mapping (higher = better)
 */
export function checkAssuranceLevel(achievedLevel, requiredLevel, assuranceRank) {
  const code = 'ASSURANCE_BELOW_MINIMUM';
  const rank = assuranceRank || ASSURANCE_RANK;
  const achievedRank = rank[achievedLevel];
  const requiredRank = rank[requiredLevel];

  if (achievedRank === undefined) {
    return fail(code, `Unknown achieved assurance level: ${achievedLevel}`);
  }
  if (requiredRank === undefined) {
    return fail(code, `Unknown required assurance level: ${requiredLevel}`);
  }
  if (achievedRank < requiredRank) {
    return fail(code, `Assurance level "${achievedLevel}" is below required "${requiredLevel}"`);
  }
  return pass(code);
}

// ── Invariant 7: No duplicate accepted results ──────────────────────────────

/**
 * Check that no existing accepted result already has the same binding hash.
 * @param {Array<{ outcome?: string, binding_hash?: string }>} existingResults
 * @param {string} bindingHash
 */
export function checkNoDuplicateResult(existingResults, bindingHash) {
  const code = 'DUPLICATE_RESULT';
  if (!existingResults || existingResults.length === 0) {
    return pass(code);
  }
  const duplicate = existingResults.find(
    (r) => r.outcome === 'accepted' && r.binding_hash === bindingHash,
  );
  if (duplicate) {
    return fail(code, 'An accepted result with the same binding hash already exists');
  }
  return pass(code);
}

// ── Invariant 8: Must have subject interaction reference ────────────────────

/**
 * Check that the handshake has an interaction_id linking it to a subject
 * interaction.
 * @param {{ interaction_id?: string }} handshake
 */
export function checkInteractionBound(handshake) {
  const code = 'MISSING_INTERACTION_REF';
  if (!handshake || !handshake.interaction_id) {
    return fail(code, 'Handshake has no interaction_id');
  }
  return pass(code);
}

// ── Invariant 9: Actor-role match — no role spoofing ────────────────────────

/**
 * Check that the presentation's authenticated entity matches the party's
 * entity_ref, preventing one actor from presenting on behalf of another.
 * @param {{ entity_ref?: string }} presentation
 * @param {string} authenticatedEntity — the entity_ref from authentication
 * @param {{ entity_ref?: string }} party
 */
export function checkNoRoleSpoofing(presentation, authenticatedEntity, party) {
  const code = 'ROLE_SPOOFING';
  if (!party || !party.entity_ref) {
    return fail(code, 'Party has no entity_ref');
  }
  if (!authenticatedEntity) {
    return fail(code, 'Authenticated entity is missing');
  }
  if (party.entity_ref !== authenticatedEntity) {
    return fail(code, `Authenticated entity "${authenticatedEntity}" does not match party entity "${party.entity_ref}"`);
  }
  return pass(code);
}

// ── Invariant 10: Finalized state is immutable ──────────────────────────────

/**
 * Check that no existing result prevents further modification (immutability).
 * @param {{ outcome?: string }} existingResult
 */
export function checkResultImmutability(existingResult) {
  const code = 'RESULT_IMMUTABLE';
  if (!existingResult) {
    return pass(code);
  }
  if (existingResult.outcome === 'accepted' || existingResult.outcome === 'rejected') {
    return fail(code, `Result is finalized with outcome "${existingResult.outcome}" and cannot be modified`);
  }
  return pass(code);
}

// ── Run All Invariants ──────────────────────────────────────────────────────

/**
 * Run all applicable invariants against a verification context.
 *
 * @param {{
 *   handshake: object,
 *   parties: Array,
 *   presentations: Array,
 *   binding: object,
 *   policy: object,
 *   authorities: Array,
 *   existingResults: Array,
 *   existingResult: object,
 *   verificationPayloadHash: string,
 *   authenticatedEntity: string,
 * }} context
 * @returns {{ passed: boolean, violations: Array<{ ok: boolean, code: string, message: string }> }}
 */
export function runAllInvariants(context) {
  const {
    handshake = {},
    parties = [],
    presentations = [],
    binding = null,
    policy = null,
    authorities = [],
    existingResults = [],
    existingResult = null,
    verificationPayloadHash = null,
    authenticatedEntity = null,
  } = context || {};

  // Build handshake-with-binding for checkNotExpired
  const handshakeWithBinding = { ...handshake, binding };

  const results = [];

  // Invariant 1: Expiry
  results.push(checkNotExpired(handshakeWithBinding));

  // Invariant 2: All required parties present
  results.push(checkAllPartiesPresent(handshake, parties, presentations, policy));

  // Invariant 3: Binding valid
  results.push(checkBindingValid(binding, verificationPayloadHash));

  // Invariant 4: Issuer trust — run for each presentation that has an issuer_ref
  for (const pres of presentations) {
    if (pres.issuer_ref) {
      results.push(checkIssuerTrusted(pres, authorities));
    }
  }

  // Invariant 5: Authority not revoked — run for each matched authority
  for (const pres of presentations) {
    if (pres.issuer_ref && authorities) {
      const authority = authorities.find((a) => a.key_id === pres.issuer_ref);
      if (authority) {
        results.push(checkAuthorityNotRevoked(authority));
      }
    }
  }

  // Invariant 7: No duplicate result
  if (binding && binding.payload_hash) {
    results.push(checkNoDuplicateResult(existingResults, binding.payload_hash));
  }

  // Invariant 8: Interaction bound
  results.push(checkInteractionBound(handshake));

  // Invariant 10: Result immutability
  results.push(checkResultImmutability(existingResult));

  const violations = results.filter((r) => !r.ok);

  return {
    passed: violations.length === 0,
    violations,
  };
}
