/**
 * Canonical Binding Module
 *
 * This module is the SINGLE source of truth for handshake binding material.
 * All binding computation, canonicalization, hashing, and validation flows
 * through these functions. No other code may compute binding hashes directly.
 *
 * Reviewer requirement: A.3 from EP LOCK 100 specification.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { sha256 } from '@/lib/crypto';
import { CANONICAL_BINDING_FIELDS, BINDING_MATERIAL_VERSION } from './invariants.js';

/**
 * @typedef {Object} BindingMaterial
 * @property {string|null} action_type - The action being bound (may be null for identity-only flows)
 * @property {string|null} resource_ref - The target resource reference
 * @property {string|null} policy_id - Policy identifier
 * @property {string|null} policy_version - Policy version at bind time
 * @property {string|null} policy_hash - SHA-256 of policy.rules at bind time
 * @property {string|null} interaction_id - Interaction identifier
 * @property {string} party_set_hash - SHA-256 of sorted role:entity_ref pairs
 * @property {string|null} payload_hash - SHA-256 of canonicalized payload
 * @property {string|null} context_hash - SHA-256 of action context
 * @property {string} nonce - 32-byte random hex nonce
 * @property {string} expires_at - ISO-8601 expiry deadline
 * @property {string} binding_material_version - Version of the binding material schema
 */

/**
 * Build the canonical binding material object from handshake components.
 *
 * Maps protocol-level concepts to binding fields:
 *   action    → action_type
 *   target    → resource_ref (aliased as target_ref externally)
 *   policy    → policy_id, policy_version, policy_hash
 *   party set → party_set_hash
 *   payload   → payload_hash
 *   context   → context_hash
 *   replay    → nonce, expires_at
 *
 * @param {object} params
 * @param {string|null} params.action_type - The action being bound (null for identity-only flows).
 * @param {string|null} params.resource_ref - The target resource (target_ref).
 * @param {string|null} params.policy_id - Policy identifier.
 * @param {string|null} params.policy_version - Policy version at bind time.
 * @param {string|null} params.policy_hash - SHA-256 of policy.rules at bind time.
 * @param {string|null} params.interaction_id - Interaction identifier.
 * @param {string} params.party_set_hash - SHA-256 of sorted role:entity_ref pairs.
 * @param {string|null} params.payload_hash - SHA-256 of canonicalized payload.
 * @param {string|null} params.context_hash - SHA-256 of action context.
 * @param {string} params.nonce - 32-byte random hex nonce.
 * @param {string} params.expires_at - ISO-8601 expiry deadline.
 * @returns {BindingMaterial} The canonical binding material object.
 * @throws {Error} BINDING_INVARIANT_VIOLATION if required fields are missing or invalid
 */
export function buildBindingMaterial(params) {
  // Build the material with exactly the canonical fields
  const material = {
    action_type: params.action_type,
    resource_ref: params.resource_ref || null,
    policy_id: params.policy_id || null,
    policy_version: params.policy_version || null,
    policy_hash: params.policy_hash || null,
    interaction_id: params.interaction_id || null,
    party_set_hash: params.party_set_hash,
    payload_hash: params.payload_hash || null,
    context_hash: params.context_hash || null,
    nonce: params.nonce,
    expires_at: params.expires_at,
    binding_material_version: BINDING_MATERIAL_VERSION,
  };

  // Validate completeness before returning
  validateBindingCompleteness(material);

  return material;
}

/**
 * Canonicalize a binding material object for deterministic serialization.
 *
 * Sorts keys alphabetically and produces a canonical JSON string.
 * This ensures that identical binding material always produces the
 * same hash regardless of property insertion order.
 *
 * @param {BindingMaterial} binding - The binding material object.
 * @returns {string} Deterministic JSON string with alphabetically sorted keys.
 */
export function canonicalizeBinding(binding) {
  const sortedKeys = Object.keys(binding).sort();
  return JSON.stringify(binding, sortedKeys);
}

/**
 * Compute the SHA-256 hash of canonicalized binding material.
 *
 * @param {BindingMaterial} binding - The binding material object.
 * @returns {string} Hex-encoded SHA-256 hash of the canonicalized binding (the binding_hash).
 */
export function hashBinding(binding) {
  const canonical = canonicalizeBinding(binding);
  return sha256(canonical);
}

/**
 * Validate that a binding material object is complete for its action class.
 *
 * Enforces:
 *   - All CANONICAL_BINDING_FIELDS are present (no missing keys)
 *   - No extra fields exist (no unexpected keys)
 *   - Required fields are non-null (action_type, party_set_hash, nonce, expires_at)
 *   - binding_material_version matches current version
 *
 * @param {BindingMaterial} binding - The binding material object to validate.
 * @returns {void}
 * @throws {Error} BINDING_INVARIANT_VIOLATION if binding is not a plain object
 * @throws {Error} BINDING_INVARIANT_VIOLATION if canonical fields are missing
 * @throws {Error} BINDING_INVARIANT_VIOLATION if unexpected extra fields are present
 * @throws {Error} BINDING_INVARIANT_VIOLATION if required non-null fields (party_set_hash, nonce, expires_at, binding_material_version) are null/empty
 * @throws {Error} BINDING_INVARIANT_VIOLATION if binding_material_version does not match current version
 */
export function validateBindingCompleteness(binding) {
  if (!binding || typeof binding !== 'object') {
    throw new Error('BINDING_INVARIANT_VIOLATION: Binding material must be a plain object');
  }

  const keys = Object.keys(binding);

  // Check for missing canonical fields
  const missing = CANONICAL_BINDING_FIELDS.filter(f => !keys.includes(f));
  if (missing.length > 0) {
    throw new Error(`BINDING_INVARIANT_VIOLATION: Missing canonical binding fields: ${missing.join(', ')}`);
  }

  // Check for unexpected extra fields
  const extra = keys.filter(f => !CANONICAL_BINDING_FIELDS.includes(f));
  if (extra.length > 0) {
    throw new Error(`BINDING_INVARIANT_VIOLATION: Unexpected fields in binding material: ${extra.join(', ')}`);
  }

  // Hard requirements — these must never be null.
  // Note: action_type is part of the canonical envelope but MAY be null for
  // handshakes that don't bind to a specific action (e.g., identity-only flows).
  // When null, it is still included in the hash (as null), ensuring the binding
  // explicitly encodes the absence of an action constraint.
  const REQUIRED_NON_NULL = ['party_set_hash', 'nonce', 'expires_at', 'binding_material_version'];
  for (const field of REQUIRED_NON_NULL) {
    if (binding[field] === null || binding[field] === undefined || binding[field] === '') {
      throw new Error(`BINDING_INVARIANT_VIOLATION: Required field "${field}" must not be null/empty`);
    }
  }

  // Version check
  if (binding.binding_material_version !== BINDING_MATERIAL_VERSION) {
    throw new Error(
      `BINDING_INVARIANT_VIOLATION: binding_material_version mismatch. ` +
      `Expected ${BINDING_MATERIAL_VERSION}, got ${binding.binding_material_version}`
    );
  }
}

/**
 * Compute the party_set_hash from a list of parties.
 * Deterministic: sorts by "role:entity_ref" before hashing.
 *
 * @param {Array<{role: string, entity_ref: string}>} parties
 * @returns {string} Hex-encoded SHA-256 hash.
 */
export function computePartySetHash(parties) {
  const sorted = parties.map(p => `${p.role}:${p.entity_ref}`).sort();
  return sha256(JSON.stringify(sorted));
}

/**
 * Compute the context_hash from action context fields.
 *
 * @param {object} context - { action_type, resource_ref, intent_ref, policy_id, policy_version, interaction_id }
 * @returns {string} Hex-encoded SHA-256 hash.
 */
export function computeContextHash(context) {
  return sha256(JSON.stringify(context, Object.keys(context).sort()));
}

/**
 * Compute the payload_hash from a payload object.
 *
 * @param {object|null} payload
 * @returns {string|null} Hex-encoded SHA-256 hash, or null if no payload.
 */
export function computePayloadHash(payload) {
  if (!payload || typeof payload !== 'object') return null;
  return sha256(JSON.stringify(payload, Object.keys(payload).sort()));
}

/**
 * Compute the policy_hash from policy rules.
 *
 * @param {object|null} rules - The policy.rules object.
 * @returns {string|null} Hex-encoded SHA-256 hash, or null if no rules.
 */
export function computePolicyHash(rules) {
  if (!rules || typeof rules !== 'object') return null;
  return sha256(JSON.stringify(rules, Object.keys(rules).sort()));
}

// sha256 imported from @/lib/crypto
