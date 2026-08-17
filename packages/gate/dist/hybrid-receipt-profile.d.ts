/**
 * EP-RECEIPT-HYBRID-v1 -- the Gate-side deployment profile for hybrid
 * classical + post-quantum authorization receipts.
 *
 * WHAT THIS IS. packages/issue/src/hybrid-issuance.ts can MINT a receipt
 * carrying both an Ed25519 and an ML-DSA-65 (FIPS 204) signature over one set
 * of canonical bytes, and can verify one. This module is the operator-facing
 * switch that decides whether a given Gate deployment does that, and what it
 * accepts. It is deliberately a thin, fail-closed policy layer: it makes no
 * cryptographic decisions of its own and never reimplements a check.
 *
 * OPT-IN, AND OFF BY DEFAULT. `disabled` is the default mode. EP-RECEIPT-v1
 * remains the Gate's receipt format unless an operator turns this on. Nothing
 * in this repository ships with hybrid issuance enabled.
 *
 * THE THREE MODES
 *   disabled  (default) The Gate issues and accepts EP-RECEIPT-v1 only. A
 *             request for a hybrid receipt is REFUSED (hybrid_issuance_disabled)
 *             rather than quietly answered with a classical receipt, and a
 *             hybrid receipt presented for acceptance is REFUSED
 *             (hybrid_receipt_not_accepted) rather than partially checked. A
 *             deployment that cannot check an ML-DSA leg must not pretend it
 *             checked one.
 *   enabled   Hybrid is available per request. A request that asks for it gets
 *             a hybrid receipt; everything else stays EP-RECEIPT-v1. Both
 *             profiles are accepted on the verification side.
 *   required  Every receipt this Gate issues is hybrid, and only hybrid
 *             receipts are accepted. A classical-only request or a classical
 *             receipt presented for acceptance is REFUSED
 *             (hybrid_required). This is the mode with teeth: there is no
 *             configuration in which `required` silently produces or accepts a
 *             single-signature receipt.
 *
 * NO SILENT DOWNGRADE, ANYWHERE. Every path where hybrid could not be produced
 * or could not be checked (missing keys, missing ML-DSA backend, missing
 * issuance module) is a refusal with a named reason. There is no fallback edge
 * in this file that turns a hybrid intent into a classical artifact.
 *
 * HONEST BOUNDARIES
 *   - This is an opt-in profile, not the default receipt format, and it is not
 *     enabled in any deployment shipped from this repository.
 *   - The ML-DSA implementation reached through EP-SIG-AGILITY-v1 is
 *     @noble/post-quantum, a pure-JS FIPS 204 implementation that is not a
 *     FIPS-validated module. Turning this profile on is not a certification.
 *   - `action-control-manifest.ts` still pins `authorization_receipt.profile`
 *     to EP-RECEIPT-v1. A relying party who wants hybrid receipts named in a
 *     manifest needs that contract extended; this module does not change it.
 *
 * @license Apache-2.0
 */
type AnyRecord = Record<string, any>;
export declare const HYBRID_RECEIPT_PROFILE_ID = "EP-RECEIPT-HYBRID-v1";
export declare const CLASSICAL_RECEIPT_PROFILE_ID = "EP-RECEIPT-v1";
/** Config values for the `hybrid_issuance` flag, in increasing strictness. */
export declare const HYBRID_ISSUANCE_MODES: readonly ["disabled", "enabled", "required"];
export type HybridIssuanceMode = (typeof HYBRID_ISSUANCE_MODES)[number];
export declare const HYBRID_PROFILE_REASONS: Readonly<{
    HYBRID_ISSUANCE_DISABLED: "hybrid_issuance_disabled";
    HYBRID_REQUIRED: "hybrid_required";
    HYBRID_RECEIPT_NOT_ACCEPTED: "hybrid_receipt_not_accepted";
    HYBRID_KEYS_MISSING: "hybrid_keys_missing";
    HYBRID_ISSUANCE_UNAVAILABLE: "hybrid_issuance_unavailable";
    CLASSICAL_ISSUER_MISSING: "classical_issuer_missing";
    CLASSICAL_VERIFIER_MISSING: "classical_verifier_missing";
    UNKNOWN_RECEIPT_PROFILE: "unknown_receipt_profile";
}>;
/**
 * The issuance/verification surface this module drives, structurally typed so
 * packages/gate gains no build-time dependency on packages/issue.
 */
export interface HybridIssuanceModule {
    createHybridReceipt: (args: AnyRecord) => Promise<AnyRecord>;
    verifyHybridReceipt: (doc: unknown, keys: unknown, options?: AnyRecord) => Promise<{
        verified: boolean;
        reason: string | null;
        failed_algorithm: string | null;
        checks: AnyRecord;
    }>;
}
export interface HybridReceiptProfile {
    profile_id: typeof HYBRID_RECEIPT_PROFILE_ID;
    mode: HybridIssuanceMode;
    /** True when the Gate may mint a hybrid receipt at all. */
    issues_hybrid: boolean;
    /** True when a hybrid receipt is the ONLY acceptable receipt. */
    requires_hybrid: boolean;
}
export interface HybridProfileRefusal {
    ok: false;
    reason: string;
    /** Present when the refusal came from the underlying verifier. */
    detail?: AnyRecord | null;
}
export type HybridIssueOutcome = {
    ok: true;
    profile: typeof HYBRID_RECEIPT_PROFILE_ID;
    receipt: AnyRecord;
} | {
    ok: true;
    profile: typeof CLASSICAL_RECEIPT_PROFILE_ID;
    receipt: AnyRecord;
} | HybridProfileRefusal;
export type HybridAcceptOutcome = {
    ok: true;
    profile: string;
    detail?: AnyRecord | null;
} | HybridProfileRefusal;
/**
 * Normalize a Gate deployment's `hybrid_issuance` setting into a frozen
 * profile. An unrecognized value THROWS: a misconfigured security flag must
 * stop a deployment, not be rounded down to the permissive default.
 *
 * Accepts either the flag itself or a config object carrying it:
 *   resolveHybridReceiptProfile('required')
 *   resolveHybridReceiptProfile({ hybrid_issuance: 'required' })
 *   resolveHybridReceiptProfile(undefined)            -> disabled
 */
export declare function resolveHybridReceiptProfile(config?: unknown): HybridReceiptProfile;
/** Resolve the hybrid issuance module. Returns null rather than throwing. */
export declare function loadHybridIssuanceModule(): Promise<HybridIssuanceModule | null>;
export interface HybridIssueArgs {
    profile: HybridReceiptProfile;
    payload: AnyRecord;
    metadata?: AnyRecord;
    /** Hybrid signing keys (see signingKeysFromHybridBundle in @emilia-protocol/issue). */
    hybridKeys?: AnyRecord | null;
    /** Did this request ask for a hybrid receipt? Ignored in `required` mode. */
    requestHybrid?: boolean;
    /** The Gate's existing EP-RECEIPT-v1 issuance, called for classical requests. */
    issueClassical?: (args: {
        payload: AnyRecord;
        metadata?: AnyRecord;
    }) => Promise<AnyRecord> | AnyRecord;
    /** Inject the issuance module instead of resolving it. */
    issuance?: HybridIssuanceModule | null;
    /** Passed through to EP-SIG-AGILITY-v1 (backend injection, deterministic mode). */
    agilityOptions?: AnyRecord;
}
/**
 * The wrapper a Gate's receipt-issuing call site adopts. One line at the call
 * site replaces a direct call to the classical issuer:
 *
 *   const outcome = await issueUnderHybridProfile({
 *     profile: resolveHybridReceiptProfile(config),
 *     payload, metadata, hybridKeys, requestHybrid,
 *     issueClassical: ({ payload, metadata }) => existingIssueReceipt(payload, metadata),
 *   });
 *   if (!outcome.ok) return refuse(outcome.reason);
 *
 * Every failure is a named refusal returned to the caller. This function never
 * substitutes a classical receipt for a hybrid one that could not be minted.
 */
export declare function issueUnderHybridProfile(args: HybridIssueArgs): Promise<HybridIssueOutcome>;
export interface HybridAcceptArgs {
    profile: HybridReceiptProfile;
    receipt: unknown;
    /** Hybrid verification keys (see verificationKeysFromHybridBundle). */
    hybridKeys?: AnyRecord | null;
    /** The Gate's existing EP-RECEIPT-v1 verification, for classical receipts. */
    verifyClassical?: (receipt: unknown) => Promise<AnyRecord> | AnyRecord;
    issuance?: HybridIssuanceModule | null;
    agilityOptions?: AnyRecord;
}
/**
 * The acceptance-side companion. Routes by the presented `@version`, enforces
 * the deployment's mode, and delegates the cryptography.
 *
 * The two enforcement points that matter:
 *   - `required` refuses a classical receipt (hybrid_required). A Gate that
 *     demands post-quantum evidence must not accept evidence that has none.
 *   - `disabled` refuses a hybrid receipt (hybrid_receipt_not_accepted)
 *     instead of handing it to a classical verifier, which would either refuse
 *     on the version anyway or, worse, check one leg of two.
 */
export declare function acceptUnderHybridProfile(args: HybridAcceptArgs): Promise<HybridAcceptOutcome>;
export {};
//# sourceMappingURL=hybrid-receipt-profile.d.ts.map