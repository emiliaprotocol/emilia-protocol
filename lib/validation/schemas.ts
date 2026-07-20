/**
 * EP Validation Schemas — Pre-built schemas for common EP operations.
 *
 * Each function takes a request body and returns
 * { valid: true, data } or { valid: false, errors: [...] }.
 *
 * @license Apache-2.0
 */

import { validate, validateBody } from './index.js';
import { VALID_MODES, VALID_PARTY_ROLES, VALID_DISCLOSURE_MODES } from '@/lib/handshake/invariants';

// ── Shared allowed-value sets ─────────────────────────────────────────────
// VALID_MODES, VALID_PARTY_ROLES, VALID_DISCLOSURE_MODES imported from invariants — single source of truth.
const VALID_PRESENTATION_TYPES = new Set([
  'self_asserted', 'verifiable_credential', 'certificate', 'attestation', 'delegation_proof',
]);
const VALID_ACTION_TYPES = new Set(['install', 'connect', 'delegate', 'transact']);

// ── Handshake: Initiate ───────────────────────────────────────────────────

/**
 * Validate POST /api/handshake — initiate a new handshake.
 * @param {Record<string, any>} body
 */
export function validateHandshakeCreate(body) {
  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }

  // Validate top-level fields via validateBody
  const result = validateBody(body, {
    mode:       (/** @type {*} */ v) => validate(v, 'mode').required().string().oneOf(VALID_MODES).result,
    policy_id:  (/** @type {*} */ v) => validate(v, 'policy_id').required().string().result,
    parties:    (/** @type {*} */ v) => validate(v, 'parties').required().isArray().result,
  });

  if (!result.valid) return result;
  // result.valid === true guarantees validateBody() set `data` (see index.js);
  // the two are set together and the type just isn't discriminated by TS here.
  /** @type {any} */
  const data = result.data;

  // Validate parties array entries
  const errors = [];
  const parties = data.parties;

  if (parties.length < 2) {
    errors.push('parties must contain at least 2 entries');
  }

  for (let i = 0; i < parties.length; i++) {
    const p = parties[i];
    if (!p || typeof p !== 'object') {
      errors.push(`parties[${i}] must be an object`);
      continue;
    }
    try { validate(p.role, `parties[${i}].role`).required().string().oneOf(VALID_PARTY_ROLES).result; }
    catch (e) { errors.push(...e.errors); }
    try { validate(p.entity_ref, `parties[${i}].entity_ref`).required().string().result; }
    catch (e) { errors.push(...e.errors); }
  }

  // Optional fields
  if (body.action_type !== undefined && body.action_type !== null) {
    try { validate(body.action_type, 'action_type').string().oneOf(VALID_ACTION_TYPES).result; }
    catch (e) { errors.push(...e.errors); }
  }
  if (body.resource_ref !== undefined && body.resource_ref !== null) {
    try { validate(body.resource_ref, 'resource_ref').string().result; }
    catch (e) { errors.push(...e.errors); }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      mode: data.mode,
      policy_id: data.policy_id,
      parties: data.parties,
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

// ── Handshake: Present ────────────────────────────────────────────────────

/**
 * Validate POST /api/handshake/[id]/present — add identity presentation.
 * @param {Record<string, any>} body
 */
export function validatePresent(body) {
  const result = validateBody(body, {
    party_role:        (/** @type {*} */ v) => validate(v, 'party_role').required().string().oneOf(VALID_PARTY_ROLES).result,
    presentation_type: (/** @type {*} */ v) => validate(v, 'presentation_type').required().string().oneOf(VALID_PRESENTATION_TYPES).result,
    claims:            (/** @type {*} */ v) => validate(v, 'claims').required().isObject().result,
  });

  if (!result.valid) return result;
  // result.valid === true guarantees validateBody() set `data` (see index.js);
  // the two are set together and the type just isn't discriminated by TS here.
  /** @type {any} */
  const data = result.data;

  // Optional fields — validate only if present
  const errors = [];
  if (body.disclosure_mode !== undefined && body.disclosure_mode !== null) {
    try { validate(body.disclosure_mode, 'disclosure_mode').string().oneOf(VALID_DISCLOSURE_MODES).result; }
    catch (e) { errors.push(...e.errors); }
  }
  if (body.issuer_ref !== undefined && body.issuer_ref !== null) {
    try { validate(body.issuer_ref, 'issuer_ref').string().result; }
    catch (e) { errors.push(...e.errors); }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      party_role: data.party_role,
      presentation_type: data.presentation_type,
      claims: data.claims,
      issuer_ref: body.issuer_ref || null,
      disclosure_mode: body.disclosure_mode || null,
    },
  };
}

// ── Signoff: Challenge ────────────────────────────────────────────────────

/**
 * Validate POST /api/signoff/challenge — issue a signoff challenge.
 * @param {Record<string, any>} body
 */
export function validateSignoffChallenge(body) {
  return validateBody(body, {
    handshakeId:         (/** @type {*} */ v) => validate(v, 'handshakeId').required().string().result,
    accountableActorRef: (/** @type {*} */ v) => validate(v, 'accountableActorRef').required().string().result,
    bindingHash:         (/** @type {*} */ v) => validate(v, 'bindingHash').required().string().result,
    signoffPolicyId:     (/** @type {*} */ v) => validate(v, 'signoffPolicyId').required().string().result,
    requiredAssurance:   (/** @type {*} */ v) => validate(v, 'requiredAssurance').required().string().result,
    allowedMethods:      (/** @type {*} */ v) => validate(v, 'allowedMethods').required().result,
    expiresAt:           (/** @type {*} */ v) => validate(v, 'expiresAt').required().string().matches(/^\d{4}-\d{2}-\d{2}T/).result,
  });
}

// ── Signoff: Attest ───────────────────────────────────────────────────────

/**
 * Validate POST /api/signoff/[challengeId]/attest — create attestation.
 * @param {Record<string, any>} body
 */
export function validateSignoffAttest(body) {
  return validateBody(body, {
    humanEntityRef:  (/** @type {*} */ v) => validate(v, 'humanEntityRef').required().string().result,
    authMethod:      (/** @type {*} */ v) => validate(v, 'authMethod').required().string().result,
    assuranceLevel:  (/** @type {*} */ v) => validate(v, 'assuranceLevel').required().string().result,
    channel:         (/** @type {*} */ v) => validate(v, 'channel').required().string().result,
    attestationHash: (/** @type {*} */ v) => validate(v, 'attestationHash').required().string().result,
  });
}

// ── Policy: Create ────────────────────────────────────────────────────────

/**
 * Validate POST /api/policies — register a custom trust policy.
 * @param {Record<string, any>} body
 */
export function validatePolicyCreate(body) {
  const result = validateBody(body, {
    name:            (/** @type {*} */ v) => validate(v, 'name').required().string().minLength(1).maxLength(255).result,
    description:     (/** @type {*} */ v) => validate(v, 'description').required().string().maxLength(1000).result,
    min_score:       (/** @type {*} */ v) => validate(v, 'min_score').required().isNumber().result,
    min_confidence:  (/** @type {*} */ v) => validate(v, 'min_confidence').required().isNumber().result,
    min_receipts:    (/** @type {*} */ v) => validate(v, 'min_receipts').required().isNumber().result,
    max_dispute_rate:(/** @type {*} */ v) => validate(v, 'max_dispute_rate').required().isNumber().result,
  });

  if (!result.valid) return result;

  // Optional nested object
  const errors = [];
  if (body.software_requirements !== undefined && body.software_requirements !== null) {
    try { validate(body.software_requirements, 'software_requirements').isObject().result; }
    catch (e) { errors.push(...e.errors); }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      ...result.data,
      family: body.family || 'custom',
      software_requirements: body.software_requirements || null,
    },
  };
}
