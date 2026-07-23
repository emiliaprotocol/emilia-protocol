// SPDX-License-Identifier: Apache-2.0
/**
 * EP-SURFACE-BINDING-v1, on WHICH surface the human approved (possession-row join).
 *
 * A receipt records that a named human approved an exact action. It does not, on
 * its own, record WHICH approval surface (endpoint, platform, condition-bounded
 * credential session) the ceremony ran on. This module defines a small,
 * canonicalizable binding that references the possession-row evidence for that
 * surface, a WIMSE condition-bounded credential presentation, a LIT assertion,
 * a platform attestation, as an opaque digest bound into the SIGNED action
 * object, so the two rows join on evidence the human's signature covers.
 *
 *   { "@version": "EP-SURFACE-BINDING-v1",
 *     surface_kind:        "wimse-condition-bounded",  // WHICH kind of possession-row evidence
 *     attestation_digest:  "sha256:<hex>",             // digest of that evidence's bytes (opaque to EP)
 *     verifier_hint:       "<optional string>" }       // where the relying party verifies that row
 *
 * ──────────────────────────────────────────────────────────────────────────
 * HONEST BOUNDARY, READ THIS. EP does NOT verify the possession-row evidence.
 * That evidence is verified by the possession row's own verifier, in its own
 * trust boundary, under keys and conditions EP knows nothing about. What THIS
 * binding proves, once inside the signed action object, is narrower and exact:
 * the human's signature covered WHICH surface evidence was claimed for the
 * ceremony, so a later party cannot silently swap the claimed surface, and a
 * relying party can join the two rows by digest equality. It does NOT prove the
 * referenced attestation is valid, current, or honest, and it does NOT prove
 * what reached the human's eyes. A surface attestation is evidence about the
 * display environment, never proof of perception.
 *
 * THE SUBSTITUTION GUARD. Possession-row evidence NEVER substitutes for the
 * authorization row. A live key, a present human, an attested endpoint, none
 * of these are an approval. The approval is the human's device-bound signature
 * over the exact action, and the conformance suite refuses the substitution
 * (see attribution_substituted_for_authorization in vectors/boundary.v1.json
 * and possession_substituted_for_authorization in vectors/surface-binding.v1.json).
 * The rows join; they never merge.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * FAIL CLOSED. validateSurfaceBinding() refuses on any missing required field,
 * any wrong type, any unknown member, and any malformed attestation_digest. It
 * never repairs a malformed binding into a passing one, and it never infers a
 * default surface, a missing surface identity is a rejection, not a blank.
 * verifySurfaceBinding() refuses with a distinct reason for every failure mode
 * and only reports digest_match on byte-exact SHA-256 equality.
 */

import crypto from 'node:crypto';
import { canonicalize } from './index.js';

export const SURFACE_BINDING_VERSION = 'EP-SURFACE-BINDING-v1';

/** The action-object member under which a bound surface binding is placed (bindSurfaceInto). */
export const SURFACE_BINDING_FIELD = 'approval_surface';

/** The closed set of members a valid binding may carry. Unknown members => reject. */
const BINDING_MEMBERS = Object.freeze([
  '@version',
  'surface_kind',
  'attestation_digest',
  'verifier_hint',
]);
const BINDING_MEMBER_SET = new Set(BINDING_MEMBERS);

const sha256hex = (b: Buffer | string): string =>
  crypto.createHash('sha256').update(b).digest('hex');

/**
 * Normalize a claimed SHA-256 digest to bare lowercase hex, or '' when malformed.
 * Same fail-closed convention as the sibling modules (initiator-attestation.js,
 * time-attestation.js, provenance.js): a bad digest can never compare-equal to a
 * real one. Accepts an OPTIONAL "sha256:" prefix; the canonical stored form
 * re-adds it.
 *
 * @param {unknown} h
 * @returns {string} 64-char lowercase hex, or '' if not a well-formed SHA-256.
 */
export function normalizeSurfaceDigest(h: unknown): string {
  const s = String(h ?? '').replace(/^sha256:/i, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
}

/**
 * validateSurfaceBinding(binding), FAIL-CLOSED structural validation.
 *
 * Enforces: object shape; only the closed member set (unknown member => reject);
 * surface_kind present and a non-empty string; @version, when present, equals
 * SURFACE_BINDING_VERSION; attestation_digest present and a well-formed SHA-256;
 * verifier_hint, when present, a non-empty string. The `normalized` binding
 * carries the canonical stored form with a "sha256:"-prefixed lowercase digest.
 * On any error, `ok:false` and `normalized:null`, a malformed binding is never
 * repaired into a passing one.
 *
 * @param {unknown} binding
 * @returns {{ ok: boolean, normalized: object|null, errors: string[] }}
 */
export function validateSurfaceBinding(binding: unknown): { ok: boolean; normalized: Record<string, unknown> | null; errors: string[] } {
  const errors: string[] = [];
  const fail = () => ({ ok: false, normalized: null, errors });

  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) {
    errors.push('surface binding must be a non-array object');
    return fail();
  }
  // Post-guard: an indexable view of the same object (no runtime change) so the
  // closed-member checks below read typed members off the validated shape.
  const b = binding as Record<string, any>;

  // Closed member set, unknown members are rejected, not ignored, so a producer
  // cannot smuggle unbound side-channel content past a permissive verifier.
  for (const key of Object.keys(binding)) {
    if (!BINDING_MEMBER_SET.has(key)) {
      errors.push(`unknown member "${key}" (allowed: ${BINDING_MEMBERS.join(', ')})`);
    }
  }

  if (b['@version'] !== undefined && b['@version'] !== SURFACE_BINDING_VERSION) {
    errors.push(`@version must be ${SURFACE_BINDING_VERSION} when present`);
  }

  if (typeof b.surface_kind !== 'string' || b.surface_kind.length === 0) {
    errors.push('surface_kind is required and must be a non-empty string');
  }

  // attestation_digest is checked for TYPE first (parity with surface_kind), so a
  // Buffer or a {toString:()=>hex} object can never coerce into a passing digest.
  if (b.attestation_digest === undefined || b.attestation_digest === null) {
    errors.push('attestation_digest is required');
  } else if (typeof b.attestation_digest !== 'string') {
    errors.push('attestation_digest must be a string');
  } else if (normalizeSurfaceDigest(b.attestation_digest) === '') {
    errors.push('attestation_digest must be a well-formed SHA-256 (optionally "sha256:"-prefixed 64-hex)');
  }

  if (b.verifier_hint !== undefined &&
      (typeof b.verifier_hint !== 'string' || b.verifier_hint.length === 0)) {
    errors.push('verifier_hint, when present, must be a non-empty string');
  }

  if (errors.length) return fail();

  const normalized: Record<string, unknown> = {
    '@version': SURFACE_BINDING_VERSION,
    surface_kind: b.surface_kind,
    attestation_digest: `sha256:${normalizeSurfaceDigest(b.attestation_digest)}`,
  };
  if (b.verifier_hint !== undefined) normalized.verifier_hint = b.verifier_hint;

  return { ok: true, normalized, errors };
}

/**
 * bindSurfaceInto(action, binding), bind a validated surface binding into the
 * ACTION digest domain so the claimed approval surface is covered by the human's
 * signature.
 *
 * COMPOSITION WITH THE FROZEN action hash (does NOT change actionHash()): same
 * contract as initiator-attestation.js bindInto(). Returns a NEW action object
 * with the normalized binding under the reserved member SURFACE_BINDING_FIELD
 * ("approval_surface"). canonicalize() includes every member and sorts keys, so
 * the UNCHANGED actionHash() over the returned object covers the binding.
 * Callers hash and sign via the existing path; this module supplies only the
 * field placement, never a second hasher.
 *
 * FAIL CLOSED: throws if `action` is not a plain object, if the binding does not
 * validate, or if the action already carries a DIFFERENT value under the
 * reserved member.
 *
 * @param {object} action - the canonical Action Object (I-D §3), pre-hash.
 * @param {unknown} binding - a surface binding (validated here).
 * @returns {{ action: object, binding: object, digest_preview: string }}
 */
export function bindSurfaceInto(action: Record<string, unknown> | null | undefined, binding: unknown) {
  if (!action || typeof action !== 'object' || Array.isArray(action)) {
    throw new TypeError('bindSurfaceInto requires the canonical Action Object');
  }
  const v = validateSurfaceBinding(binding);
  if (!v.ok) {
    throw new Error(`bindSurfaceInto: invalid surface binding: ${v.errors.join('; ')}`);
  }
  const existing = action[SURFACE_BINDING_FIELD];
  if (existing !== undefined && canonicalize(existing) !== canonicalize(v.normalized)) {
    throw new Error(
      `bindSurfaceInto: action already carries a different ${SURFACE_BINDING_FIELD}; refusing to overwrite`,
    );
  }
  const bound = { ...action, [SURFACE_BINDING_FIELD]: v.normalized };
  const digest_preview = `sha256:${sha256hex(canonicalize(bound))}`;
  return { action: bound, binding: v.normalized, digest_preview };
}

/**
 * receiptSurfaceBinding(receipt), report whether, and how strongly, a receipt
 * claims an approval surface.
 *
 *   - 'signed_action' : receipt.action.approval_surface validates, the claim is
 *                       inside the signed Action Object, covered by the human's
 *                       signature. The STRONG binding.
 *   - 'none'          : absent, or present but malformed. A malformed binding is
 *                       reported as 'none' with its errors, it never upgrades.
 *
 * This mirrors receiptGrantBindingStrength() in consent-grant.js: strength is a
 * top-level report for the relying party to price, never a silent default.
 *
 * @param {unknown} receipt
 * @returns {{ strength: 'signed_action'|'none', binding: object|null, errors: string[] }}
 */
export function receiptSurfaceBinding(receipt: unknown) {
  let raw: unknown;
  try {
    const action = receipt && typeof receipt === 'object' ? (receipt as Record<string, any>).action : undefined;
    // OWN property only. A binding reachable via the prototype chain is NOT an own
    // member of the action object, so canonicalize() never sees it and the human's
    // signature never covers it. Honoring an inherited member would upgrade an
    // unsigned binding to 'signed_action', the exact laundering this join guards
    // against. Object.hasOwn is the whole fix.
    raw = action && typeof action === 'object' && Object.hasOwn(action, SURFACE_BINDING_FIELD)
      ? action[SURFACE_BINDING_FIELD]
      : undefined;
  } catch {
    // A hostile getter that throws is treated as no usable binding: fail closed,
    // never crash. verifySurfaceBinding maps the non-empty errors to a malformed
    // refusal.
    return { strength: 'none', binding: null, errors: ['surface binding read threw'] };
  }
  if (raw === undefined) return { strength: 'none', binding: null, errors: [] };
  const v = validateSurfaceBinding(raw);
  if (!v.ok) return { strength: 'none', binding: null, errors: v.errors };
  return { strength: 'signed_action', binding: v.normalized, errors: [] };
}

/**
 * verifySurfaceBinding(receipt, evidence, opts), the JOIN CHECK between the
 * authorization row (this receipt) and the possession row (the presented
 * surface evidence), each verified in its own trust boundary.
 *
 * What this checks, and ONLY this:
 *   - present:      the receipt carries a valid surface binding inside the
 *                   signed action object (strength 'signed_action').
 *   - digest_match: sha256(the presented evidence BYTES) equals the bound
 *                   attestation_digest, byte-exact.
 *
 * EVIDENCE IS ALWAYS HASHED. We never accept a precomputed digest. The bound
 * digest is PUBLIC, it sits in the receipt, so echoing it back would prove
 * nothing about possession. The relying party must present the actual evidence
 * bytes the possession row produced; we hash them and compare. This is what
 * makes digest_match a real demonstration rather than a replay of a public value.
 *
 * What this NEVER checks: the validity of the possession-row evidence itself.
 * Run the possession row's own verifier for that, and the base EP verifier for
 * the receipt's signature. This function is the seam, not either verifier.
 *
 * Refusal reasons (distinct, fail-closed):
 *   - 'surface_binding_absent'    : no binding where the caller requires one.
 *   - 'surface_binding_malformed' : a binding is present but does not validate.
 *   - 'surface_digest_mismatch'   : presented evidence does not hash to the
 *                                   bound digest.
 *
 * @param {unknown} receipt - an EP receipt whose action may carry approval_surface.
 * @param {unknown} evidence - the possession-row evidence BYTES (string hashed as
 *   UTF-8, or Uint8Array/Buffer). Always hashed; a precomputed digest is not
 *   accepted (see above).
 * @param {{ require?: boolean }} [opts] - require:true (default) refuses when no
 *   binding is present; require:false admits on the receipt alone and marks the
 *   result admitted_without_possession_row so an integrator cannot misread it as
 *   a verified possession row.
 * @returns {{ valid: boolean, checks: { present: boolean, digest_match: boolean|null },
 *             binding: object|null, reason?: string, admitted_without_possession_row?: boolean }}
 */
export function verifySurfaceBinding(receipt: unknown, evidence: unknown, opts?: { require?: boolean } | null) {
  // opts may be null/undefined (a plausible integrator call): default to
  // require:true rather than throwing. Only literal require:false relaxes it.
  const require = (opts ?? {}).require !== false;
  const report = receiptSurfaceBinding(receipt);

  if (report.strength !== 'signed_action') {
    if (report.errors.length) {
      return {
        valid: false,
        checks: { present: false, digest_match: null },
        binding: null,
        reason: 'surface_binding_malformed',
      };
    }
    if (require) {
      return {
        valid: false,
        checks: { present: false, digest_match: null },
        binding: null,
        reason: 'surface_binding_absent',
      };
    }
    return {
      valid: true,
      checks: { present: false, digest_match: null },
      binding: null,
      admitted_without_possession_row: true,
    };
  }

  const binding = report.binding as Record<string, any>;
  const boundHex = normalizeSurfaceDigest(binding.attestation_digest);
  // Always hash the presented evidence bytes. No precomputed-digest path exists:
  // the bound digest is public, so a caller who echoes it proves nothing.
  // (Buffer is a Uint8Array subclass, so the second branch catches it too.)
  let presentedHex = '';
  if (typeof evidence === 'string') {
    presentedHex = sha256hex(Buffer.from(evidence, 'utf8'));
  } else if (evidence instanceof Uint8Array) {
    presentedHex = sha256hex(Buffer.from(evidence));
  }

  const digest_match = presentedHex !== '' && presentedHex === boundHex;
  if (!digest_match) {
    return {
      valid: false,
      checks: { present: true, digest_match: false },
      binding: report.binding,
      reason: 'surface_digest_mismatch',
    };
  }
  return { valid: true, checks: { present: true, digest_match: true }, binding: report.binding };
}
