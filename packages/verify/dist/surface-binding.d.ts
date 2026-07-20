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
export declare const SURFACE_BINDING_VERSION = "EP-SURFACE-BINDING-v1";
/** The action-object member under which a bound surface binding is placed (bindSurfaceInto). */
export declare const SURFACE_BINDING_FIELD = "approval_surface";
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
export declare function normalizeSurfaceDigest(h: unknown): string;
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
export declare function validateSurfaceBinding(binding: unknown): {
    ok: boolean;
    normalized: Record<string, unknown> | null;
    errors: string[];
};
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
export declare function bindSurfaceInto(action: Record<string, unknown> | null | undefined, binding: unknown): {
    action: {
        approval_surface: Record<string, unknown> | null;
    };
    binding: Record<string, unknown> | null;
    digest_preview: string;
};
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
export declare function receiptSurfaceBinding(receipt: unknown): {
    strength: string;
    binding: null;
    errors: string[];
} | {
    strength: string;
    binding: Record<string, unknown> | null;
    errors: never[];
};
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
export declare function verifySurfaceBinding(receipt: unknown, evidence: unknown, opts?: {
    require?: boolean;
} | null): {
    valid: boolean;
    checks: {
        present: boolean;
        digest_match: null;
    };
    binding: null;
    reason: string;
    admitted_without_possession_row?: undefined;
} | {
    valid: boolean;
    checks: {
        present: boolean;
        digest_match: null;
    };
    binding: null;
    admitted_without_possession_row: boolean;
    reason?: undefined;
} | {
    valid: boolean;
    checks: {
        present: boolean;
        digest_match: boolean;
    };
    binding: Record<string, unknown> | null;
    reason: string;
    admitted_without_possession_row?: undefined;
} | {
    valid: boolean;
    checks: {
        present: boolean;
        digest_match: boolean;
    };
    binding: Record<string, unknown> | null;
    reason?: undefined;
    admitted_without_possession_row?: undefined;
};
//# sourceMappingURL=surface-binding.d.ts.map