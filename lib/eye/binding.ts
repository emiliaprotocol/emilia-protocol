/**
 * EP Eye — Scope binding and hash computation.
 *
 * Canonical hash functions for scope bindings, advisories, and evidence.
 * All hash computation flows through this module. No other Eye code may
 * compute hashes directly.
 *
 * @license Apache-2.0
 */

import { sha256 } from '@/lib/crypto';
import { EYE_SCOPE_BINDING_FIELDS } from './invariants.js';

/**
 * Compute the canonical scope_binding_hash from binding parameters.
 *
 * Takes the EYE_SCOPE_BINDING_FIELDS, builds a canonical JSON object
 * with alphabetically sorted keys, and returns its SHA-256 hash.
 *
 * @param {object} params
 * @param {string} params.actor_ref
 * @param {string} params.subject_ref
 * @param {string} params.action_type
 * @param {string|null} params.target_ref
 * @param {string|null} params.issuer_ref
 * @param {string|null} params.context_hash
 * @param {string} params.issued_at - ISO-8601 timestamp
 * @param {string} params.expires_at - ISO-8601 timestamp
 * @returns {string} Hex-encoded SHA-256 scope_binding_hash
 */
export function computeScopeBinding(params) {
  const material = {};
  for (const field of EYE_SCOPE_BINDING_FIELDS) {
    material[field] = params[field] ?? null;
  }
  const sortedKeys = Object.keys(material).sort();
  const canonical = JSON.stringify(material, sortedKeys);
  return sha256(canonical);
}

/**
 * Compute the advisory_hash from advisory fields.
 *
 * Takes the full advisory object, canonicalizes it with sorted keys,
 * and returns its SHA-256 hash.
 *
 * @param {object} advisory - Full advisory fields
 * @returns {string} Hex-encoded SHA-256 advisory_hash
 */
export function computeAdvisoryHash(advisory) {
  const sortedKeys = Object.keys(advisory).sort();
  const canonical = JSON.stringify(advisory, sortedKeys);
  return sha256(canonical);
}

/**
 * Compute the evidence_hash from an evidence payload.
 *
 * @param {object|string} evidence - Evidence payload
 * @returns {string} Hex-encoded SHA-256 evidence_hash
 */
export function computeEvidenceHash(evidence) {
  if (typeof evidence === 'string') {
    return sha256(evidence);
  }
  const sortedKeys = Object.keys(evidence).sort();
  const canonical = JSON.stringify(evidence, sortedKeys);
  return sha256(canonical);
}
