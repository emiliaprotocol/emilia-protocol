/**
 * EP Handshake — Route-level schema validation.
 *
 * Strict input validation at the API boundary. Every field is validated
 * before reaching lib/ code. Unknown fields are ignored (not passed through).
 *
 * @license Apache-2.0
 */

const VALID_MODES = new Set(['basic', 'mutual', 'selective', 'delegated']);
const VALID_PARTY_ROLES = new Set(['initiator', 'responder', 'verifier', 'delegate']);
const VALID_PRESENTATION_TYPES = new Set([
  'self_asserted', 'verifiable_credential', 'certificate', 'attestation', 'delegation_proof',
]);
const VALID_DISCLOSURE_MODES = new Set(['full', 'selective', 'commitment']);
const VALID_ACTION_TYPES = new Set(['install', 'connect', 'delegate', 'transact']);

/**
 * Validate initiate handshake request body.
 * Returns { valid: true, sanitized } or { valid: false, error }.
 */
export function validateInitiateBody(body) {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Request body must be a JSON object' };
  }

  if (!body.mode || !VALID_MODES.has(body.mode)) {
    return { valid: false, error: `mode must be one of: ${[...VALID_MODES].join(', ')}` };
  }
  if (!body.policy_id || typeof body.policy_id !== 'string') {
    return { valid: false, error: 'policy_id is required and must be a string' };
  }
  if (!Array.isArray(body.parties) || body.parties.length < 2) {
    return { valid: false, error: 'parties is required and must contain at least 2 entries' };
  }

  for (let i = 0; i < body.parties.length; i++) {
    const p = body.parties[i];
    if (!p || typeof p !== 'object') {
      return { valid: false, error: `parties[${i}] must be an object` };
    }
    if (!p.role || !VALID_PARTY_ROLES.has(p.role)) {
      return { valid: false, error: `parties[${i}].role must be one of: ${[...VALID_PARTY_ROLES].join(', ')}` };
    }
    if (!p.entity_ref || typeof p.entity_ref !== 'string') {
      return { valid: false, error: `parties[${i}].entity_ref is required and must be a string` };
    }
  }

  if (body.action_type && !VALID_ACTION_TYPES.has(body.action_type)) {
    return { valid: false, error: `action_type must be one of: ${[...VALID_ACTION_TYPES].join(', ')}` };
  }
  if (body.resource_ref && typeof body.resource_ref !== 'string') {
    return { valid: false, error: 'resource_ref must be a string' };
  }
  if (body.intent_ref && typeof body.intent_ref !== 'string') {
    return { valid: false, error: 'intent_ref must be a string' };
  }
  if (body.binding_ttl_ms !== undefined && (typeof body.binding_ttl_ms !== 'number' || body.binding_ttl_ms <= 0)) {
    return { valid: false, error: 'binding_ttl_ms must be a positive number' };
  }

  return {
    valid: true,
    sanitized: {
      mode: body.mode,
      policy_id: body.policy_id,
      parties: body.parties,
      payload: body.payload || {},
      interaction_id: body.interaction_id || null,
      binding: body.binding || null,
      binding_ttl_ms: body.binding_ttl_ms || undefined,
      idempotency_key: body.idempotency_key || null,
      action_type: body.action_type || null,
      resource_ref: body.resource_ref || null,
      intent_ref: body.intent_ref || null,
    },
  };
}

/**
 * Validate presentation request body.
 */
export function validatePresentBody(body) {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Request body must be a JSON object' };
  }
  if (!body.party_role || !VALID_PARTY_ROLES.has(body.party_role)) {
    return { valid: false, error: `party_role must be one of: ${[...VALID_PARTY_ROLES].join(', ')}` };
  }
  if (!body.presentation_type || !VALID_PRESENTATION_TYPES.has(body.presentation_type)) {
    return { valid: false, error: `presentation_type must be one of: ${[...VALID_PRESENTATION_TYPES].join(', ')}` };
  }
  if (!body.claims || typeof body.claims !== 'object' || Array.isArray(body.claims)) {
    return { valid: false, error: 'claims is required and must be a non-array object' };
  }
  if (body.disclosure_mode && !VALID_DISCLOSURE_MODES.has(body.disclosure_mode)) {
    return { valid: false, error: `disclosure_mode must be one of: ${[...VALID_DISCLOSURE_MODES].join(', ')}` };
  }
  if (body.issuer_ref && typeof body.issuer_ref !== 'string') {
    return { valid: false, error: 'issuer_ref must be a string' };
  }

  return {
    valid: true,
    sanitized: {
      party_role: body.party_role,
      presentation_type: body.presentation_type,
      claims: body.claims,
      issuer_ref: body.issuer_ref || null,
      disclosure_mode: body.disclosure_mode || null,
    },
  };
}

/**
 * Validate revoke request body.
 */
export function validateRevokeBody(body) {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Request body must be a JSON object' };
  }
  if (!body.reason || typeof body.reason !== 'string' || body.reason.trim().length === 0) {
    return { valid: false, error: 'reason is required and must be a non-empty string' };
  }
  if (body.reason.length > 1000) {
    return { valid: false, error: 'reason must be 1000 characters or fewer' };
  }

  return {
    valid: true,
    sanitized: { reason: body.reason.trim() },
  };
}
