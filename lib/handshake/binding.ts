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
 * Canonical handshake binding material — the single, exhaustive envelope
 * hashed to produce a binding_hash. See CANONICAL_BINDING_FIELDS.
 */
export interface BindingMaterial {
  /** The action being bound (may be null for identity-only flows) */
  action_type: string | null;
  /** The target resource reference */
  resource_ref: string | null;
  /** Policy identifier */
  policy_id: string | null;
  /** Policy version at bind time */
  policy_version: string | null;
  /** SHA-256 of policy.rules at bind time */
  policy_hash: string | null;
  /** Interaction identifier */
  interaction_id: string | null;
  /** SHA-256 of sorted role:entity_ref pairs */
  party_set_hash: string;
  /** SHA-256 of canonicalized payload */
  payload_hash: string | null;
  /** SHA-256 of action context */
  context_hash: string | null;
  /** 32-byte random hex nonce */
  nonce: string;
  /** ISO-8601 expiry deadline */
  expires_at: string;
  /** Version of the binding material schema */
  binding_material_version: number;
}

/** Input to {@link buildBindingMaterial} — same fields as BindingMaterial, minus the version stamp. */
export interface BindingMaterialParams {
  action_type: string | null;
  resource_ref?: string | null;
  policy_id?: string | null;
  policy_version?: string | null;
  policy_hash?: string | null;
  interaction_id?: string | null;
  party_set_hash: string;
  payload_hash?: string | null;
  context_hash?: string | null;
  nonce: string;
  expires_at: string;
}

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
 * @param params
 * @returns The canonical binding material object.
 * @throws {Error} BINDING_INVARIANT_VIOLATION if required fields are missing or invalid
 */
export function buildBindingMaterial(params: BindingMaterialParams): BindingMaterial {
  // Build the material with exactly the canonical fields
  const material: BindingMaterial = {
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
 * Sorts keys alphabetically, NFC-normalizes strings, rejects non-finite
 * numbers. Produces a canonical JSON string such that identical binding
 * material always hashes identically regardless of insertion order,
 * Unicode encoding, or other surface variation.
 *
 * Audit-fix (MEDIUM): previously used
 *   JSON.stringify(binding, Object.keys(binding).sort())
 * which sorts only top-level keys and does no NFC normalization. Today all
 * binding fields are hex/UUID/timestamp — ASCII only — so the live hash
 * matches. But any future field that could contain Unicode (e.g., a
 * resource_ref with a non-ASCII entity name in a federated setup) would
 * produce different hashes for the same semantic value across counterparties.
 * Using deepSortKeys here matches what computePayloadHash / computeContextHash
 * / computePolicyHash already do.
 *
 * @param binding - The binding material object.
 * @returns Deterministic JSON string.
 */
export function canonicalizeBinding(binding: BindingMaterial): string {
  return JSON.stringify(deepSortKeys(binding));
}

/**
 * Compute the SHA-256 hash of canonicalized binding material.
 *
 * @param binding - The binding material object.
 * @returns Hex-encoded SHA-256 hash of the canonicalized binding (the binding_hash).
 */
export function hashBinding(binding: BindingMaterial): string {
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
 * @param binding - The binding material object to validate.
 * @throws {Error} BINDING_INVARIANT_VIOLATION if binding is not a plain object
 * @throws {Error} BINDING_INVARIANT_VIOLATION if canonical fields are missing
 * @throws {Error} BINDING_INVARIANT_VIOLATION if unexpected extra fields are present
 * @throws {Error} BINDING_INVARIANT_VIOLATION if required non-null fields (party_set_hash, nonce, expires_at, binding_material_version) are null/empty
 * @throws {Error} BINDING_INVARIANT_VIOLATION if binding_material_version does not match current version
 */
export function validateBindingCompleteness(binding: BindingMaterial): void {
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
  const REQUIRED_NON_NULL: (keyof BindingMaterial)[] = ['party_set_hash', 'nonce', 'expires_at', 'binding_material_version'];
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
export function computePartySetHash(parties: Array<{ role: string; entity_ref: string }>): string {
  const sorted = parties.map(p => `${p.role}:${p.entity_ref}`).sort();
  return sha256(JSON.stringify(sorted));
}

/**
 * Recursively canonicalize a value for deterministic hashing.
 *
 * This is the single source of canonicalization for all hashed material.
 * It does four things:
 *
 *  1. Sort object keys alphabetically at every nesting level.
 *  2. Unicode-normalize every string key and string value to NFC, so
 *     visually-identical strings in different normalization forms
 *     ("café" NFC vs NFD) produce the same hash.
 *  3. Reject non-finite numbers (NaN, Infinity) — they have no stable
 *     JSON representation.
 *  4. Reject `undefined` and function values — they are stripped by
 *     JSON.stringify and cannot be safely canonicalized.
 *
 * Audit-fix (H2): without NFC normalization, a federated counterparty
 * using a different Unicode encoding for the same visible string would
 * hash differently, breaking "both sides hash to the same value" for
 * cross-domain trust. A full RFC 8785 / JCS implementation is future
 * work; this covers the immediate threat surface.
 *
 * @param value
 * @returns The canonicalized value.
 * @throws {Error} on non-finite numbers, undefined, or functions.
 */
export function deepSortKeys(value: unknown): unknown {
  if (value === null) return null;
  if (value === undefined) {
    throw new Error('CANONICALIZATION_ERROR: undefined cannot be canonicalized');
  }
  if (typeof value === 'function') {
    throw new Error('CANONICALIZATION_ERROR: functions cannot be canonicalized');
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`CANONICALIZATION_ERROR: non-finite number ${value}`);
    }
    return value;
  }
  if (typeof value === 'string') {
    return value.normalize('NFC');
  }
  if (Array.isArray(value)) {
    return value.map(deepSortKeys);
  }
  if (typeof value === 'object') {
    // Normalize keys to NFC BEFORE sorting. Sorting the raw (pre-normalization)
    // keys and normalizing after made two Unicode-equivalent objects serialize in
    // a different key order, diverging their hashes. Normalize, then sort on the
    // normalized form, so canonically identical objects canonicalize identically.
    const object = value as Record<string, unknown>;
    const entries = Object.keys(object).map((k): [string, unknown] => [k.normalize('NFC'), deepSortKeys(object[k])]);
    entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const out: Record<string, unknown> = {};
    for (const [k, v] of entries) out[k] = v;
    return out;
  }
  return value;
}

/**
 * Compute the context_hash from action context fields.
 *
 * @param context - { action_type, resource_ref, intent_ref, policy_id, policy_version, interaction_id }
 * @returns Hex-encoded SHA-256 hash.
 */
export function computeContextHash(context: Record<string, unknown>): string {
  return sha256(JSON.stringify(deepSortKeys(context)));
}

/**
 * Compute the payload_hash from a payload object.
 *
 * @param payload
 * @returns Hex-encoded SHA-256 hash, or null if no payload.
 */
export function computePayloadHash(payload: Record<string, unknown> | null | undefined): string | null {
  if (!payload || typeof payload !== 'object') return null;
  return sha256(JSON.stringify(deepSortKeys(payload)));
}

/**
 * Compute the policy_hash from policy rules.
 *
 * @param rules - The policy.rules object.
 * @returns Hex-encoded SHA-256 hash, or null if no rules.
 */
export function computePolicyHash(rules: Record<string, unknown> | null | undefined): string | null {
  if (!rules || typeof rules !== 'object') return null;
  return sha256(JSON.stringify(deepSortKeys(rules)));
}

// sha256 imported from @/lib/crypto
