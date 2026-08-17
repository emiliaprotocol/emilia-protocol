/**
 * EP-SIG-AGILITY-v1 -- per-artifact signature-algorithm agility for EP
 * evidence (receipts, evidence records, and other canonicalized artifacts).
 *
 * WHY THIS EXISTS. Authorization evidence has a decades-long verification
 * horizon: disputes, statutes of limitations, and government retention
 * schedules (10-25+ years) mean an Ed25519 receipt signed today must still be
 * trustworthy testimony in 2035 and beyond. No single algorithm survives that
 * horizon on faith. This module makes the SIGNATURE ALGORITHM an explicit,
 * verifier-checked field over the SAME canonical bytes the existing
 * EP-RECEIPT-v1 path signs (the JCS-style canonicalization of the payload),
 * so a receipt can be signed and verified under Ed25519, under ML-DSA-65
 * (FIPS 204, module-lattice post-quantum), or under both at once, without
 * changing what is signed.
 *
 * CLOSED ALGORITHM REGISTRY. Exactly { Ed25519, ML-DSA-65 } in v1. An
 * algorithm outside the registry is a REFUSAL with reason
 * 'unknown_algorithm', never a pass-through: an INDETERMINATE algorithm never
 * authorizes anything.
 *
 * FAIL-CLOSED. verifyAgileSignature and verifyAgileSignatureSet never throw
 * on caller input: malformed message, signature, or key material returns a
 * structured refusal naming the reason. Signing functions throw (issuer-side
 * misuse is a programming error, not attacker input).
 *
 * HYBRID MODE. verifyAgileSignatureSet checks several signatures over the
 * SAME message bytes. Policy 'hybrid_all' requires every required algorithm
 * to be present and every presented signature to verify. Policy
 * 'per_algorithm' reports each algorithm's verdict separately and sets the
 * top-level verdict to null: VERIFIED stays per-algorithm and is never
 * collapsed; null never authorizes.
 *
 * HONEST BOUNDARIES (substance, not hedging):
 *   - This module does NOT cryptographically commit the signatures to the
 *     algorithm set. A stripped signature is detected only because the
 *     relying party pins requiredAlgorithms as verifier policy. For an
 *     envelope whose signatures themselves commit to the full set
 *     (anti-stripping), use EP-HYBRID-v1 (./pq-hybrid.js).
 *   - Algorithm agility protects artifacts signed FROM NOW ON under the new
 *     algorithm. It does not retroactively protect an already-issued
 *     single-algorithm artifact; that requires re-attestation while the old
 *     algorithm is still unbroken (see evidence-record.ts,
 *     EP-EVIDENCE-REATTESTATION-v1).
 *   - The default ML-DSA backend (@noble/post-quantum 0.7.0) is a pure-JS
 *     FIPS 204 implementation that is not a FIPS-validated module. No
 *     backend present means REFUSAL ('pq_backend_unavailable'), never a
 *     skipped check.
 *
 * KEY / SIGNATURE ENCODING (matches index.ts and pq-hybrid.ts conventions)
 *   - Ed25519 public key: base64url SPKI DER (or a node crypto KeyObject).
 *   - Ed25519 private key: node crypto KeyObject.
 *   - ML-DSA-65 public key: raw bytes (Uint8Array, 1952 bytes) or base64url.
 *   - ML-DSA-65 secret key: raw bytes (Uint8Array, 4032 bytes) or base64url.
 *   - Signatures: base64url strings (Ed25519 64 bytes, ML-DSA-65 3309 bytes).
 *
 * @license Apache-2.0
 */
import { type KeyObject } from 'node:crypto';
export declare const SIGNATURE_AGILITY_VERSION = "EP-SIG-AGILITY-v1";
/** The closed v1 algorithm registry, in canonical order. */
export declare const AGILE_SIGNATURE_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export type AgileAlgorithm = (typeof AGILE_SIGNATURE_ALGORITHMS)[number];
/** FIPS 204 ML-DSA-65 fixed sizes (bytes). */
export declare const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export declare const ML_DSA_65_SECRET_KEY_BYTES = 4032;
export declare const ML_DSA_65_SIGNATURE_BYTES = 3309;
export declare const AGILITY_REASONS: Readonly<{
    MALFORMED_INPUT: "malformed_input";
    UNKNOWN_ALGORITHM: "unknown_algorithm";
    UNKNOWN_POLICY: "unknown_policy";
    MALFORMED_KEY: "malformed_key";
    MALFORMED_SIGNATURE: "malformed_signature";
    ALGORITHM_KEY_MISMATCH: "algorithm_key_mismatch";
    SIGNATURE_INVALID: "signature_invalid";
    PQ_BACKEND_UNAVAILABLE: "pq_backend_unavailable";
    DUPLICATE_ALGORITHM: "duplicate_algorithm";
    MISSING_REQUIRED_ALGORITHM: "missing_required_algorithm";
    EMPTY_SIGNATURE_SET: "empty_signature_set";
}>;
/** One agile signature: the explicit alg field threaded through verification. */
export interface AgileSignature {
    alg: string;
    sig: string;
    key_id?: string;
}
/** One pinned verification key, tagged with the algorithm it belongs to. */
export interface AgileVerificationKey {
    alg: string;
    /** Ed25519: base64url SPKI DER or KeyObject. ML-DSA-65: raw bytes or base64url. */
    public_key: string | Uint8Array | KeyObject;
    key_id?: string;
}
export interface AgileSigningKey {
    alg: string;
    /** Ed25519: node crypto private KeyObject. ML-DSA-65: raw secret key bytes or base64url. */
    private_key: KeyObject | Uint8Array | string;
    key_id?: string;
}
/**
 * ML-DSA backend surface. `sign` MAY accept FIPS 204 signing options
 * (deterministic variant via { extraEntropy: false }); injected backends that
 * ignore the third argument still work (they sign hedged).
 */
export interface AgilityMldsaBackend {
    sign?: (messageBytes: Uint8Array, secretKeyBytes: Uint8Array, opts?: {
        extraEntropy?: Uint8Array | false;
    }) => Uint8Array;
    verify?: (signatureBytes: Uint8Array, messageBytes: Uint8Array, publicKeyBytes: Uint8Array) => boolean;
}
export interface AgilityOptions {
    mldsaBackend?: AgilityMldsaBackend | null;
    mldsaBackendLoader?: () => Promise<AgilityMldsaBackend | null> | AgilityMldsaBackend | null;
    /**
     * ML-DSA-65 only: sign with the FIPS 204 deterministic variant
     * (rnd fixed) so the same key + message always yields the same signature.
     * Used by the conformance vectors. Verification is unaffected.
     */
    deterministic?: boolean;
}
export interface AgileVerifyChecks {
    algorithm_known: boolean;
    key_wellformed: boolean | null;
    signature_wellformed: boolean | null;
    signature_valid: boolean | null;
}
export interface AgileVerifyResult {
    verified: boolean;
    reason: string | null;
    alg: string | null;
    key_id: string | null;
    checks: AgileVerifyChecks;
}
export type AgileSetPolicy = 'hybrid_all' | 'per_algorithm';
export interface AgileSetOptions extends AgilityOptions {
    policy?: AgileSetPolicy;
    /**
     * hybrid_all only: the algorithms the relying party REQUIRES to be present.
     * Defaults to the FULL registry (fail-closed): a presented set missing
     * either algorithm refuses with 'missing_required_algorithm'. Narrow this
     * deliberately; the default never narrows itself to what was presented.
     */
    requiredAlgorithms?: readonly string[];
}
export interface AgileSetResult {
    policy: AgileSetPolicy;
    /**
     * hybrid_all: true iff every required algorithm is present and every
     * presented signature verifies. per_algorithm: ALWAYS null -- the verdicts
     * live in `results` and are never collapsed; null never authorizes.
     */
    verified: boolean | null;
    reason: string | null;
    results: AgileVerifyResult[];
}
/**
 * Load the default ML-DSA-65 backend (@noble/post-quantum). Returns a backend
 * or null; NEVER throws. Absence yields null so callers refuse.
 */
export declare function loadDefaultAgilityMldsaBackend(): Promise<AgilityMldsaBackend | null>;
/**
 * Sign canonical artifact bytes under one registered algorithm.
 * The caller supplies the SAME canonical bytes the existing EP receipt path
 * signs: Buffer.from(canonicalize(payload), 'utf8').
 *
 * @throws on unknown algorithm, malformed key, or unavailable ML-DSA backend.
 */
export declare function signAgile(messageBytes: Uint8Array, key: AgileSigningKey, options?: AgilityOptions): Promise<AgileSignature>;
/**
 * Sign the SAME message bytes under several algorithms (hybrid issuance).
 * Duplicate algorithms are refused; each signature covers identical content,
 * which is the property the conformance vectors exercise.
 */
export declare function signAgileSet(messageBytes: Uint8Array, keys: AgileSigningKey[], options?: AgilityOptions): Promise<AgileSignature[]>;
/**
 * Verify one agile signature over canonical artifact bytes. FAIL-CLOSED:
 * every malformed or unknown input is a structured refusal with a reason;
 * an unknown algorithm NEVER verifies (INDETERMINATE never authorizes).
 */
export declare function verifyAgileSignature(messageBytes: Uint8Array, signature: unknown, key: unknown, options?: AgilityOptions): Promise<AgileVerifyResult>;
/**
 * Verify a SET of agile signatures over the same message bytes.
 *
 * policy 'hybrid_all' (default): verified:true iff
 *   - every algorithm in options.requiredAlgorithms (default: the FULL
 *     registry) is present exactly once, and
 *   - EVERY presented signature verifies.
 *   A missing required algorithm refuses ('missing_required_algorithm');
 *   this is relying-party policy, not a cryptographic set commitment --
 *   see the module header and EP-HYBRID-v1 for the distinction.
 *
 * policy 'per_algorithm': verified is ALWAYS null; each algorithm's verdict
 * is reported separately in results. VERIFIED stays per-algorithm; a null
 * top-level verdict never authorizes.
 */
export declare function verifyAgileSignatureSet(messageBytes: Uint8Array, signatures: unknown, keys: unknown, options?: AgileSetOptions): Promise<AgileSetResult>;
//# sourceMappingURL=pq-signature-agility.d.ts.map