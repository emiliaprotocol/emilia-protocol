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

/** Parameters used to compute a scope_binding_hash. See EYE_SCOPE_BINDING_FIELDS. */
export interface ScopeBindingParams {
  actor_ref: string;
  subject_ref: string;
  action_type: string;
  target_ref: string | null;
  issuer_ref: string | null;
  context_hash: string | null;
  /** ISO-8601 timestamp */
  issued_at: string;
  /** ISO-8601 timestamp */
  expires_at: string;
  [key: string]: unknown;
}

/**
 * Compute the canonical scope_binding_hash from binding parameters.
 *
 * Takes the EYE_SCOPE_BINDING_FIELDS, builds a canonical JSON object
 * with alphabetically sorted keys, and returns its SHA-256 hash.
 *
 * @returns Hex-encoded SHA-256 scope_binding_hash
 */
export function computeScopeBinding(params: ScopeBindingParams): string {
  const material: Record<string, unknown> = {};
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
 * @param advisory - Full advisory fields
 * @returns Hex-encoded SHA-256 advisory_hash
 */
export function computeAdvisoryHash(advisory: Record<string, unknown>): string {
  const sortedKeys = Object.keys(advisory).sort();
  const canonical = JSON.stringify(advisory, sortedKeys);
  return sha256(canonical);
}

/**
 * Compute the evidence_hash from an evidence payload.
 *
 * @param evidence - Evidence payload
 * @returns Hex-encoded SHA-256 evidence_hash
 */
export function computeEvidenceHash(evidence: Record<string, unknown> | string): string {
  if (typeof evidence === 'string') {
    return sha256(evidence);
  }
  const sortedKeys = Object.keys(evidence).sort();
  const canonical = JSON.stringify(evidence, sortedKeys);
  return sha256(canonical);
}
