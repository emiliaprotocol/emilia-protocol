/**
 * EP-RECEIPT-HYBRID-v1 -- ISSUANCE of receipts carrying BOTH an Ed25519 and an
 * ML-DSA-65 (FIPS 204) signature over one set of canonical bytes.
 *
 * WHY THIS FILE EXISTS. Before it, hybrid classical + post-quantum signing in
 * this repository was verify-side only: packages/verify/src/pq-signature-agility.ts
 * (EP-SIG-AGILITY-v1) can check a signature set, and packages/verify/src/pq-hybrid.ts
 * (EP-HYBRID-v1) wraps EP INFRASTRUCTURE keys. Nothing ISSUED a hybrid RECEIPT.
 * This module is the issuance path, so "post-quantum receipts" names something
 * a Gate or issuer can actually mint, as an OPT-IN profile.
 *
 * --- THE PROFILE DECISION: WHY A DISTINCT @version --------------------------
 *
 * A hybrid receipt MUST NOT be silently downgradable to a single-signature
 * receipt. Two independent controls enforce that, and the version marker is the
 * second one.
 *
 * 1. CRYPTOGRAPHIC SET COMMITMENT (the anti-stripping property). The bytes both
 *    legs sign are NOT canonicalize(payload). They are:
 *
 *      signed_material = {
 *        "@version":            "EP-RECEIPT-HYBRID-v1",
 *        "payload":             <the receipt payload>,
 *        "required_algorithms": ["Ed25519", "ML-DSA-65"]
 *      }
 *      message_bytes   = UTF8(canonicalize(signed_material))
 *
 *    The required algorithm SET is inside the signed bytes. Delete the ML-DSA
 *    leg and narrow `required_algorithms` to ["Ed25519"] and the surviving
 *    Ed25519 signature no longer verifies: the bytes changed. Leave the set
 *    intact and the missing leg is a structural refusal. Either way, stripping
 *    is detected, not tolerated. This is a real byte-level commitment, the same
 *    class of control EP-HYBRID-v1 gets from its domain-separated signing
 *    input, and it is STRONGER than relying-party policy alone (see the honest
 *    boundary in pq-signature-agility.ts: `hybrid_all` with pinned
 *    requiredAlgorithms is verifier POLICY, not a commitment).
 *
 * 2. CLEAN REFUSAL BY EXISTING v1 VERIFIERS. EP-RECEIPT-v1 verifiers pin
 *    SUPPORTED_VERSIONS = ['EP-RECEIPT-v1'] and read a single `signature`
 *    object. Handed a hybrid receipt they refuse on the version check with
 *    `Unsupported version: EP-RECEIPT-HYBRID-v1` BEFORE any signature is
 *    inspected. That is the outcome we want: an old verifier must not accept a
 *    hybrid receipt on the strength of one leg it happens to understand, and it
 *    must not crash. Reusing `@version: EP-RECEIPT-v1` for hybrid receipts
 *    would have forced exactly that choice on every deployed verifier. So the
 *    profile takes its own version marker and old verifiers fail closed with a
 *    named, boring reason.
 *
 *    Belt and braces: because control 1 puts the profile id inside the signed
 *    bytes, lifting a hybrid receipt's Ed25519 leg into an EP-RECEIPT-v1
 *    envelope with the same payload ALSO fails the signature check. A v1
 *    verifier refuses a hybrid receipt twice over, at the version and at the
 *    signature. conformance/hybrid-receipts/ proves both.
 *
 * --- DOCUMENT SHAPE ---------------------------------------------------------
 *
 *   {
 *     "@version": "EP-RECEIPT-HYBRID-v1",
 *     "profile": {
 *       "id": "EP-RECEIPT-HYBRID-v1",
 *       "required_algorithms": ["Ed25519", "ML-DSA-65"]
 *     },
 *     "payload": { ... },
 *     "signatures": [
 *       { "alg": "Ed25519",   "sig": "<base64url>", "key_id": "..." },
 *       { "alg": "ML-DSA-65", "sig": "<base64url>", "key_id": "..." }
 *     ],
 *     "metadata": { ... }        // OPTIONAL, unsigned, same role as in v1
 *   }
 *
 * `metadata` is deliberately OUTSIDE the signed material, matching the
 * EP-RECEIPT-v1 envelope, where the Ed25519 signature covers `payload` only.
 * Nothing a relying party authorizes on may live there.
 *
 * --- HONEST BOUNDARIES (substance, not hedging) -----------------------------
 *   - OPT-IN PROFILE. EP-RECEIPT-v1 remains the default receipt format. This
 *     profile is not on by default in any deployment.
 *   - The ML-DSA backend (@noble/post-quantum) is a pure-JS FIPS 204
 *     implementation. Per its own README it is not independently audited and it
 *     is NOT a FIPS-validated module. Issuing under this profile is not a
 *     certification claim.
 *   - No backend means REFUSAL. createHybridReceipt THROWS rather than emit a
 *     receipt missing the PQ leg; verifyHybridReceipt REFUSES with
 *     `pq_backend_unavailable` rather than pass on the classical leg alone.
 *   - This profile protects receipts issued FROM NOW ON. It does not
 *     retroactively protect already-issued single-algorithm receipts; that
 *     needs re-attestation while the classical algorithm is still unbroken
 *     (EP-EVIDENCE-REATTESTATION-v1).
 *   - Merkle anchoring is OUT OF SCOPE for v1 of this profile. An
 *     EP-MERKLE-v2 anchor self-checks its leaf against `doc.payload`, which is
 *     NOT what a hybrid receipt commits to; emitting one would be a structure
 *     no verifier actually checks end to end. Anchor the hybrid signed material
 *     under a profile that says so, or do not anchor.
 *
 * --- DEPENDENCY POSTURE -----------------------------------------------------
 * @emilia-protocol/issue is zero-dependency and its core EP-RECEIPT-v1 /
 * EP-AUTHORIZATION-RECEIPT-v1 paths stay that way: this module imports NOTHING
 * statically beyond node:crypto and ./index.js. The EP-SIG-AGILITY-v1
 * implementation is resolved at call time, either injected by the caller
 * (`agility`) or lazily loaded from @emilia-protocol/verify. Absent, every
 * entry point refuses with `agility_module_unavailable`; it never degrades to
 * a single-signature receipt.
 *
 * @license Apache-2.0
 */
import type { KeyObject } from 'node:crypto';
type AnyRecord = Record<string, any>;
/** The profile id, used as both `@version` and `profile.id`. */
export declare const HYBRID_RECEIPT_PROFILE = "EP-RECEIPT-HYBRID-v1";
/**
 * The registered required algorithm set, in canonical order. v1 is a FIXED
 * two-algorithm hybrid. This array is what goes into the signed material, so
 * its exact contents and order are part of what every leg commits to.
 */
export declare const HYBRID_RECEIPT_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** FIPS 204 ML-DSA-65 fixed sizes (bytes); mirrored from the agility module. */
export declare const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export declare const ML_DSA_65_SECRET_KEY_BYTES = 4032;
/** Named refusals. Every failure path returns one of these; none throw. */
export declare const HYBRID_RECEIPT_REASONS: Readonly<{
    MALFORMED_RECEIPT: "malformed_receipt";
    MALFORMED_PAYLOAD: "malformed_payload";
    UNKNOWN_PROFILE: "unknown_profile";
    ALGORITHM_SET_MISMATCH: "algorithm_set_mismatch";
    HYBRID_LEG_MISSING: "hybrid_leg_missing";
    UNEXPECTED_ALGORITHM: "unexpected_algorithm";
    DUPLICATE_ALGORITHM: "duplicate_algorithm";
    MISSING_KEY: "missing_key";
    SIGNATURE_INVALID: "signature_invalid";
    PQ_BACKEND_UNAVAILABLE: "pq_backend_unavailable";
    AGILITY_MODULE_UNAVAILABLE: "agility_module_unavailable";
}>;
export interface HybridReceiptSignature {
    alg: string;
    sig: string;
    key_id?: string;
}
export interface HybridReceiptDocument {
    '@version': string;
    profile: {
        id: string;
        required_algorithms: string[];
    };
    payload: AnyRecord;
    signatures: HybridReceiptSignature[];
    metadata?: AnyRecord;
}
/** The EP-SIG-AGILITY-v1 surface this module consumes. */
export interface AgilityModule {
    signAgileSet: (messageBytes: Uint8Array, keys: Array<{
        alg: string;
        private_key: unknown;
        key_id?: string;
    }>, options?: AnyRecord) => Promise<HybridReceiptSignature[]>;
    verifyAgileSignatureSet: (messageBytes: Uint8Array, signatures: unknown, keys: unknown, options?: AnyRecord) => Promise<{
        policy: string;
        verified: boolean | null;
        reason: string | null;
        results: Array<{
            verified: boolean;
            reason: string | null;
            alg: string | null;
            key_id: string | null;
        }>;
    }>;
}
export interface HybridSigningKeys {
    /** Ed25519 private key as a node crypto KeyObject. */
    ed25519PrivateKey: KeyObject;
    ed25519KeyId?: string;
    /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
    mldsaSecretKey: Uint8Array | string;
    mldsaKeyId?: string;
}
export interface HybridVerificationKeys {
    /** Ed25519 public key: base64url SPKI DER, or a node crypto KeyObject. */
    ed25519PublicKey: string | KeyObject;
    ed25519KeyId?: string;
    /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
    mldsaPublicKey: Uint8Array | string;
    mldsaKeyId?: string;
}
export interface HybridOptions {
    /** Inject the EP-SIG-AGILITY-v1 module instead of resolving it. */
    agility?: AgilityModule | null;
    /** Passed straight through to the agility module. */
    mldsaBackend?: unknown;
    mldsaBackendLoader?: unknown;
    /** ML-DSA-65 FIPS 204 deterministic signing variant (conformance vectors). */
    deterministic?: boolean;
}
export interface HybridReceiptChecks {
    profile: boolean;
    algorithm_set: boolean | null;
    legs_present: boolean | null;
    signatures_valid: boolean | null;
}
export interface HybridReceiptVerifyResult {
    verified: boolean;
    reason: string | null;
    /** Which algorithm's leg failed, when the failure is attributable to one. */
    failed_algorithm: string | null;
    checks: HybridReceiptChecks;
    /** The raw EP-SIG-AGILITY-v1 set result, when the set verifier ran. */
    set_result: Awaited<ReturnType<AgilityModule['verifyAgileSignatureSet']>> | null;
}
/**
 * Resolve the EP-SIG-AGILITY-v1 implementation. Returns null rather than
 * throwing, so callers refuse with a named reason. Tries the published subpath
 * first, then the in-repo sibling build (packages/issue/{src,dist}/../../verify
 * both resolve to packages/verify).
 */
export declare function loadAgilityModule(): Promise<AgilityModule | null>;
/**
 * Build the exact object both legs sign. The required algorithm set and the
 * profile id are INSIDE it: that is the anti-stripping commitment. Exported so
 * a verifier, a conformance vector, or an independent implementation can
 * rebuild the bytes without reading this module's internals.
 *
 * @throws if the payload is outside the EP canonicalization profile, or if the
 *   algorithm set is not the registered one (a receipt committing to a set we
 *   do not recognize must never be minted).
 */
export declare function hybridSignedMaterial(payload: AnyRecord, requiredAlgorithms?: readonly string[]): AnyRecord;
/** UTF-8 canonical bytes of hybridSignedMaterial(). What every leg signs. */
export declare function hybridSignedBytes(payload: AnyRecord, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * The hybrid sibling of EP-ISSUER-KEYS-v1 (see generateIssuerKeyBundle in
 * ./index.ts): one bundle carrying BOTH signing keys plus their public halves,
 * so an issuer configures one artifact rather than two loose key files. The
 * bundle carries private material; share only verificationKeysFromHybridBundle().
 *
 * ML-DSA keygen is not in node:crypto, so it is injected or lazily loaded from
 * @noble/post-quantum. Absent, this THROWS: a "hybrid" bundle with no PQ key is
 * worse than no bundle.
 */
export declare function generateHybridIssuerKeyBundle({ ed25519KeyId, mldsaKeyId, seed, mldsaKeygen, }?: {
    ed25519KeyId?: string;
    mldsaKeyId?: string;
    /** 32 bytes. Supply a fixed seed for deterministic vectors ONLY. */
    seed?: Uint8Array;
    mldsaKeygen?: (seed: Uint8Array) => {
        publicKey: Uint8Array;
        secretKey: Uint8Array;
    };
}): Promise<AnyRecord>;
/** Signing keys (private material) from an EP-HYBRID-ISSUER-KEYS-v1 bundle. */
export declare function signingKeysFromHybridBundle(bundle: AnyRecord): HybridSigningKeys;
/** Public verification material from an EP-HYBRID-ISSUER-KEYS-v1 bundle. */
export declare function verificationKeysFromHybridBundle(bundle: AnyRecord): HybridVerificationKeys;
/**
 * Mint an EP-RECEIPT-HYBRID-v1 receipt: canonical bytes computed ONCE, signed
 * under Ed25519 AND ML-DSA-65 via EP-SIG-AGILITY-v1's signAgileSet.
 *
 * Issuer-side misuse is a programming error, so this THROWS (matching signAgile
 * and signHybrid). In particular it throws rather than emit a receipt missing
 * the PQ leg when no ML-DSA backend is available.
 *
 * @param payload  the receipt payload; the same object an EP-RECEIPT-v1 issuer
 *                 would put in `payload`, held to the same canonicalization
 *                 profile.
 * @param keys     both private keys (see signingKeysFromHybridBundle).
 * @param metadata OPTIONAL unsigned envelope metadata, as in EP-RECEIPT-v1.
 */
export declare function createHybridReceipt({ payload, keys, metadata, ...options }: {
    payload: AnyRecord;
    keys: HybridSigningKeys;
    metadata?: AnyRecord;
} & HybridOptions): Promise<HybridReceiptDocument>;
/**
 * A dual-signer's signSet(bytes) surface, structurally typed. Matches
 * HybridCustodySigner#signSet in lib/key-custody.ts and HybridSignSet in
 * ./index.ts; this module never imports either, so an issuer can hand it any
 * signer with that shape.
 */
export type HybridReceiptSignSet = (bytes: Uint8Array | Buffer, context?: Record<string, unknown>) => Promise<HybridReceiptSignature[]>;
/**
 * Mint an EP-RECEIPT-HYBRID-v1 receipt from a CUSTODY SIGNER rather than from
 * raw private key material.
 *
 * WHY BOTH ENTRY POINTS EXIST. createHybridReceipt() takes the secret bytes
 * and drives EP-SIG-AGILITY-v1 itself, which is right for an issuer that holds
 * its own keys. A deployment whose classical leg is behind a KMS/HSM boundary
 * has no secret bytes to hand over: it has a registered dual signer that will
 * sign(bytes) on request. Without this entry point such a deployment could not
 * mint a hybrid receipt at all, so a custody-resolved default would resolve to
 * a posture it could not execute.
 *
 * WHAT IS IDENTICAL, AND WHY THAT MATTERS. The bytes are built HERE by
 * hybridSignedBytes() from the REGISTERED algorithm set, exactly as
 * createHybridReceipt() builds them, so the anti-stripping commitment (profile
 * id + required-algorithm set inside the signed bytes) is a property of this
 * module and not of the signer. The signer chooses nothing about what it is
 * signing, and the emitted document is the same shape verifyHybridReceipt()
 * already checks. The set is never narrowed to what a signer returned: a signer
 * that answers with anything other than one signature per REGISTERED algorithm
 * is a THROW, never a receipt with a missing leg.
 *
 * Issuer-side misuse is a programming error, so this THROWS, matching
 * createHybridReceipt() and createLogCheckpointHybridProof(). A PQ signer with
 * no ML-DSA backend throws `pq_backend_unavailable` from its own sign(); that
 * propagates as a refusal to issue, never as a classical-only receipt.
 */
export declare function createHybridReceiptFromSignSet({ payload, signSet, metadata, context, }: {
    payload: AnyRecord;
    signSet: HybridReceiptSignSet;
    metadata?: AnyRecord;
    /** Passed to the signer as signing context (audit/keying hints only). */
    context?: Record<string, unknown>;
}): Promise<HybridReceiptDocument>;
/**
 * Verify an EP-RECEIPT-HYBRID-v1 receipt. FAIL-CLOSED: every malformed,
 * unknown, or stripped input returns a named refusal; nothing throws on caller
 * input.
 *
 * Order of checks, and why:
 *   1. Structure and profile marker. An unknown `@version` or `profile.id`
 *      refuses with `unknown_profile` -- this module is not a general receipt
 *      verifier and never guesses at another format.
 *   2. `profile.required_algorithms` must EXACTLY equal the registered set,
 *      order included (`algorithm_set_mismatch`). A narrowed set is the
 *      stripping attack's cover story, so it is refused structurally, before
 *      the (also failing) signature check.
 *   3. Exactly one signature per required algorithm: a missing leg is
 *      `hybrid_leg_missing`, an extra one `unexpected_algorithm`, a repeat
 *      `duplicate_algorithm`.
 *   4. The bytes are rebuilt from `doc.payload` and the REGISTERED set (never
 *      from anything the document could have narrowed), then handed to
 *      EP-SIG-AGILITY-v1's verifyAgileSignatureSet under policy `hybrid_all`
 *      with requiredAlgorithms pinned to the full set. Every leg must verify
 *      over identical bytes.
 */
export declare function verifyHybridReceipt(doc: unknown, keys: HybridVerificationKeys | null | undefined, options?: HybridOptions): Promise<HybridReceiptVerifyResult>;
export {};
//# sourceMappingURL=hybrid-issuance.d.ts.map