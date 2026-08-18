import { type AebDigest } from './aeb-adapter-contract.js';
import { type AgileSignature, type AgileSigningKey, type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, unknown>;
export declare const AUTHORIZATION_BUNDLE_VERSION = "EP-AUTHORIZATION-BUNDLE-v1";
export type AuthorizationBundleVerdict = 'SATISFIED' | 'REFUSE' | 'INDETERMINATE';
export interface AuthorizationBundleKeyEntry {
    approver_id: string;
    public_key: string;
    key_class: 'A' | 'B' | 'C';
    valid_from: string;
    valid_to: string;
    compromised_at?: string | null;
}
export interface AuthorizationBundleCurrentStatus {
    checked_at: string;
    expires_at: string;
    unavailable?: boolean;
    revoked_key_ids: readonly string[];
}
export interface AuthorizationBundleCurrentPolicy {
    policy_hash: AebDigest;
    decision: 'PERMIT' | 'REFUSE';
    checked_at: string;
    expires_at: string;
    unavailable?: boolean;
}
export interface AuthorizationBundleVerificationOptions {
    now: string | number | Date;
    audience: string;
    approverKeys: Record<string, AuthorizationBundleKeyEntry>;
    /** Approvers independently selected by the authorization server or policy. */
    expectedApprovers: readonly string[];
    /** Key custody classes accepted by the relying party for this action. */
    acceptedKeyClasses: readonly AuthorizationBundleKeyEntry['key_class'][];
    /** Current local policy evaluation; a bundle never freezes policy. */
    currentPolicy: AuthorizationBundleCurrentPolicy;
    /** Exact action independently derived by the relying party. */
    expectedAction: unknown;
    /**
     * Fresh authorization instance independently issued or registered by the
     * relying party or authorization server for this approval ceremony.
     * A presenter-selected value is not a trust input.
     */
    expectedAuthorizationInstance?: string;
    /**
     * Native-verified, profile-specific projection independently derived by the
     * relying party. Required when the contexts bind one. The Bundle verifier
     * compares canonical bytes; native verification belongs to the selected
     * profile implementation.
     */
    expectedAuthorizationBinding?: unknown;
    requireAuthorizationBinding?: boolean;
    /** Required when relying-party policy demands current revocation status. */
    currentStatus?: AuthorizationBundleCurrentStatus;
    requireCurrentStatus?: boolean;
    /** Class-A verification hook, normally backed by verifyWebAuthnSignoff. */
    verifyClassASignoff?: (input: {
        signoff: Obj;
        context: Obj;
        contextDigest: AebDigest;
        key: AuthorizationBundleKeyEntry;
    }) => boolean;
    /** Optional directory-proof verifier when keys are not accepted as direct pins. */
    verifyKeyProofs?: (proofs: readonly unknown[], keys: Record<string, AuthorizationBundleKeyEntry>) => boolean;
    /** Optional presentation-evidence verifier selected by relying-party policy. */
    verifyPresentationEvidence?: (evidence: readonly unknown[], contexts: readonly Obj[]) => boolean;
    requirePresentationEvidence?: boolean;
}
export interface AuthorizationBundleVerificationResult {
    verdict: AuthorizationBundleVerdict;
    evidence_satisfied: boolean;
    authorization_decision: false;
    bundle_digest: AebDigest | null;
    checks: Record<string, boolean>;
    reasons: string[];
}
/**
 * Fail-closed public wrapper. Hostile proxies, accessors, and malformed option
 * objects are protocol input and must produce a verdict instead of escaping as
 * an exception across an executor boundary.
 */
export declare function verifyAuthorizationBundle(bundle: unknown, options: AuthorizationBundleVerificationOptions): AuthorizationBundleVerificationResult;
export interface AuthorizationBundleGrantBindingState {
    bundle_digest: AebDigest;
    grant_id: string;
}
export interface AuthorizationBundleGrantBindingResult {
    outcome: 'BOUND' | 'IDEMPOTENT' | 'REFUSE';
    state: AuthorizationBundleGrantBindingState;
    reason: string | null;
}
/**
 * Deterministic compare-and-set transition for AS-side bundle-to-grant state.
 * The caller MUST execute this transition atomically in its authoritative
 * store; this pure helper does not claim distributed or cross-domain locking.
 */
export declare function bindAuthorizationBundleToGrant(current: AuthorizationBundleGrantBindingState | null, requested: AuthorizationBundleGrantBindingState): AuthorizationBundleGrantBindingResult;
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to Class B/C
 * approver signoffs inside the bundle:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature per signoff changes
 *    the SHAPE of the signoff's proof, a wire-format change, so the bundle
 *    takes a new `bundle_version` (EP-AUTHORIZATION-BUNDLE-v1 -> -v2).
 *    verifyAuthorizationBundle() above is untouched: it requires
 *    `bundle.bundle_version === AUTHORIZATION_BUNDLE_VERSION` (v1) as part of
 *    its closed-shape gate, so a v2 bundle refuses on `bundle_malformed`
 *    before any signature inspection, and never throws.
 * 2. SET SHAPE. Each Class B/C signoff's flat `signature` string is replaced
 *    by `proof`, carrying `required_algorithms` plus a `signatures` array
 *    shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (signoffV2SigningBytes below), alongside the context digest
 *    each signoff already binds. Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed.
 * 4. V1 COMPATIBILITY. v1 bundles keep verifying, unchanged, through
 *    verifyAuthorizationBundle (which stays synchronous internally, even
 *    though its public wrapper always returns a value directly). v2
 *    verification is a SEPARATE, ASYNC entry point (ML-DSA verification is
 *    async); verifyAuthorizationBundleAny() routes on `bundle_version` for
 *    callers holding a mixed bag. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure path is a reason string folded into the
 *    same `reasons` list v1 uses; nothing throws on caller input (mirrored by
 *    the same hostile-proxy try/catch wrapper v1 uses). An absent ML-DSA
 *    backend makes the affected signoff's signature check fail, which is
 *    surfaced through the existing 'signoff_signature_invalid' reason --
 *    never a skipped check and never a pass on the classical leg alone.
 *
 * SCOPE BOUNDARY (honest, not a hedge): Class A signoffs are UNCHANGED in v2.
 * verifyClassASignoff remains the sole authority for a Class A signoff exactly
 * as in v1 -- Class A is a hardware-authenticator (WebAuthn/passkey) ceremony.
 * What that boundary rests on, stated precisely, because these are two
 * different gates held by two different parties:
 *   - A POST-QUANTUM Class A signoff is gated on the ecosystem, on three
 *     dated, checkable components: the FIDO Registry of Predefined Values v2.3
 *     defines no ALG_SIGN constant for ML-DSA (so a certified authenticator
 *     cannot declare the capability), CTAP 2.3 carries no PQC text, and W3C
 *     WebAuthn PR 2437 is open and unmerged. It is NOT gated on EP's verifier:
 *     verifyWebAuthnSignoff already dispatches on the enrolled key's algorithm
 *     and verifies ML-DSA-65 via EP-SIG-AGILITY-v1.
 *   - A HYBRID Class A signoff is an EP DESIGN DECISION, not a FIDO
 *     dependency. Both live W3C proposals deliver SINGLE-algorithm PQ
 *     credentials and explicitly leave hybrid to the relying party, so hybrid
 *     at this layer is two enrolled credentials per approver plus a policy
 *     requiring a signoff from each (EP-QUORUM-v1 policy.required_algorithms,
 *     default off).
 * Only Class B/C signoffs -- EP-issued Ed25519 keys this module verifies
 * directly -- gain the ML-DSA-65 leg here. A v2 bundle's Class B/C approver
 * key entries carry BOTH
 * `public_key` and `pq_public_key`; a key entry missing the PQ half fails the
 * affected signoff, never a silent single-leg pass.
 *
 * HONEST BOUNDARIES carry over unchanged from v1: SATISFIED never means
 * AUTHORIZED. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * v2 does NOT retroactively protect bundles already issued under v1.
 */
export declare const AUTHORIZATION_BUNDLE_V2_VERSION = "EP-AUTHORIZATION-BUNDLE-v2";
/** The registered required algorithm set, in canonical order. */
export declare const AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface AuthorizationBundleSignoffV2Proof {
    required_algorithms: readonly string[];
    signatures: AgileSignature[];
}
/** v2 Class B/C approver key: BOTH public halves. Class A entries need not carry pq_public_key. */
export interface AuthorizationBundleKeyEntryV2 extends AuthorizationBundleKeyEntry {
    pq_public_key?: string;
}
export interface AuthorizationBundleVerificationOptionsV2 extends Omit<AuthorizationBundleVerificationOptions, 'approverKeys'> {
    approverKeys: Record<string, AuthorizationBundleKeyEntryV2>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}
/**
 * The bytes BOTH legs sign for one signoff: the context digest that signoff
 * binds, plus the committed `required_algorithms` set, under a dedicated v2
 * domain tag. This REPLACES v1's convention of signing the raw context-digest
 * bytes directly (crypto.sign over the bare 32-byte digest) -- v2 needs
 * structure to commit the algorithm set into, so it moves to the same
 * domain-separated canonical-JSON convention every other hybrid surface uses.
 * Recomputed independently by the verifier from the PRESENTED context digest
 * and the REGISTERED set.
 */
export declare function signoffV2SigningBytes(contextDigest: AebDigest, requiredAlgorithms?: readonly string[]): Buffer;
/** Mint a real hybrid Class B/C signoff proof over one context digest. Throws on issuer misuse. */
export declare function signAuthorizationBundleSignoffV2(contextDigest: AebDigest, signers: AgileSigningKey[], options?: AgilityOptions): Promise<AuthorizationBundleSignoffV2Proof>;
/**
 * Fail-closed public wrapper for EP-AUTHORIZATION-BUNDLE-v2. Hostile proxies,
 * accessors, and malformed option objects are protocol input and must produce
 * a verdict instead of escaping as an exception.
 */
export declare function verifyAuthorizationBundleV2(bundle: unknown, options: AuthorizationBundleVerificationOptionsV2): Promise<AuthorizationBundleVerificationResult>;
/** Route a bundle of EITHER version to its own verifier, on `bundle_version`. */
export declare function verifyAuthorizationBundleAny(bundle: unknown, options: AuthorizationBundleVerificationOptions | AuthorizationBundleVerificationOptionsV2): Promise<AuthorizationBundleVerificationResult>;
export {};
//# sourceMappingURL=authorization-bundle.d.ts.map