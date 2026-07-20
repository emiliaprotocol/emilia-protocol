/**
 * @emilia-protocol/verify: HYBRID classical + post-quantum signature envelope
 * (EP-HYBRID-v1) for EP INFRASTRUCTURE keys (transparency-log, directory,
 * checkpoint signing keys).
 *
 * See docs/POST-QUANTUM-MIGRATION.md (section "EP-HYBRID-v1 hybrid envelope").
 *
 * ENVELOPE
 *   {
 *     alg: 'EP-HYBRID-v1',
 *     signature_algos: ['Ed25519', 'ML-DSA-65'],   // canonical order, exact set
 *     sigs: {
 *       'Ed25519':   '<base64url>',
 *       'ML-DSA-65': '<base64url>'
 *     }
 *   }
 *
 * ANTI-STRIPPING (the property this module exists for)
 *   BOTH signatures are computed over a domain-separated signing input that
 *   INCLUDES a canonical encoding of `signature_algos`:
 *
 *     signing_input = UTF8('emilia-protocol/pq-hybrid/v1') || 0x00
 *                  || UTF8(JSON.stringify(signature_algos)) || 0x00
 *                  || message
 *
 *   Therefore an attacker who strips the ML-DSA-65 signature and presents the
 *   Ed25519 signature as if it were a plain / classical-only signature fails:
 *   the Ed25519 signature does not verify over the bare message, nor over a
 *   signing input that commits to a reduced algorithm set. Removing an
 *   algorithm from the set changes what was signed, so every remaining
 *   signature fails. verifyHybrid() additionally requires the PRESENTED
 *   `signature_algos` to equal the registered EP-HYBRID-v1 set exactly
 *   (order-sensitive) and requires one signature per committed algorithm,
 *   no more, no fewer.
 *
 * FAIL-CLOSED
 *   - Missing / malformed envelope, message, or key material refuses.
 *   - Tampered or reduced `signature_algos` refuses (algo_set_mismatch).
 *   - A committed algorithm with no signature refuses (missing_signature).
 *   - Either signature invalid refuses (classical_signature_invalid /
 *     pq_signature_invalid).
 *   - If no ML-DSA backend is available, verifyHybrid REFUSES with
 *     reason 'pq_backend_unavailable'. It NEVER skips the PQ leg and never
 *     returns verified:true on the classical leg alone.
 *
 * ML-DSA BACKEND (honesty)
 *   packages/verify ships with ZERO runtime dependencies, so this module does
 *   not (and must not) import an ML-DSA implementation statically. The ML-DSA
 *   leg is cryptographically live only when a backend is present, via either:
 *     1. caller injection: pass { mldsaBackend } implementing
 *        sign(messageBytes, secretKeyBytes) -> Uint8Array and
 *        verify(signatureBytes, messageBytes, publicKeyBytes) -> boolean; or
 *     2. lazy dynamic import of '@noble/post-quantum/ml-dsa.js' (ml_dsa65),
 *        which resolves only if that package is installed by the consumer
 *        (it is a devDependency at this repo's root for tests, NOT a
 *        dependency of this package).
 *   If neither is available the module refuses; absence of the backend is a
 *   refusal, never a crash and never a pass. If a caller injects a bogus
 *   always-true backend, the PQ leg is only as strong as that backend (i.e.
 *   vacuous); the classical leg and the algo-set commitment are still
 *   enforced independently, but the caller owns the PQ leg's honesty.
 *
 *   @noble/post-quantum v0.6.1 is a pure-JS implementation of FIPS 204
 *   ML-DSA. Per its own README it is self-audited by its authors and has NOT
 *   been independently audited; it is not a FIPS-validated module. This envelope does NOT make EP
 *   post-quantum secure by itself; see docs/POST-QUANTUM-MIGRATION.md for the
 *   migration phases and the pre-CRQC historical re-anchoring requirement.
 *
 * KEY / SIGNATURE ENCODING (matches index.js conventions)
 *   - Ed25519 public key: base64url SPKI DER (or a node crypto KeyObject).
 *   - Ed25519 private key: node crypto KeyObject (from generateKeyPairSync /
 *     createPrivateKey).
 *   - ML-DSA-65 public key: raw bytes (Uint8Array, 1952 bytes) or base64url.
 *   - ML-DSA-65 secret key: raw bytes (Uint8Array, 4032 bytes).
 *   - Signatures in the envelope: base64url strings.
 *
 * @license Apache-2.0
 */
import type { KeyObject } from 'node:crypto';
export type HybridMessage = Uint8Array | string;
export interface MldsaBackend {
    sign?: (messageBytes: Uint8Array, secretKeyBytes: Uint8Array) => Uint8Array;
    verify?: (signatureBytes: Uint8Array, messageBytes: Uint8Array, publicKeyBytes: Uint8Array) => boolean;
}
export interface HybridSigningKeys {
    ed25519PrivateKey: KeyObject;
    mldsaSecretKey: Uint8Array | string;
}
export interface HybridVerificationKeys {
    ed25519PublicKey: KeyObject | string;
    mldsaPublicKey: Uint8Array | string;
}
export interface HybridOptions {
    mldsaBackend?: MldsaBackend | null;
    mldsaBackendLoader?: () => Promise<MldsaBackend | null> | MldsaBackend | null;
}
export interface HybridEnvelope {
    alg: string;
    signature_algos: string[];
    sigs: Record<string, string>;
}
export interface HybridChecks {
    envelope: boolean;
    algo_set: boolean;
    classical_signature: boolean | null;
    pq_signature: boolean | null;
}
export interface HybridVerifyResult {
    verified: boolean;
    reason: string | null;
    checks: HybridChecks;
}
export declare const HYBRID_ALG = "EP-HYBRID-v1";
/**
 * The registered algorithm set for EP-HYBRID-v1, in canonical order.
 * v1 is a FIXED two-algorithm hybrid: exactly Ed25519 + ML-DSA-65.
 */
export declare const HYBRID_SIGNATURE_ALGOS: readonly ["Ed25519", "ML-DSA-65"];
/**
 * Domain-separation label. Trailing 0x00 separators in the signing input keep
 * label / algo-set / message unambiguous (JSON never contains a raw 0x00).
 */
export declare const HYBRID_DOMAIN = "emilia-protocol/pq-hybrid/v1";
declare const REASONS: Readonly<{
    INVALID_INPUT: "invalid_input";
    INVALID_ENVELOPE: "invalid_envelope";
    ALGO_SET_MISMATCH: "algo_set_mismatch";
    MISSING_SIGNATURE: "missing_signature";
    MISSING_KEY: "missing_key";
    CLASSICAL_INVALID: "classical_signature_invalid";
    PQ_INVALID: "pq_signature_invalid";
    PQ_BACKEND_UNAVAILABLE: "pq_backend_unavailable";
}>;
export { REASONS as HYBRID_REASONS };
/**
 * Build the domain-separated signing input BOTH legs sign.
 * Commits to the full signature_algos array; changing the array in any way
 * (strip, reorder, substitute) changes these bytes.
 *
 * @param {Uint8Array} messageBytes
 * @param {string[]} signatureAlgos
 * @returns {Buffer}
 */
export declare function hybridSigningInput(messageBytes: Uint8Array, signatureAlgos: readonly string[]): Buffer;
/**
 * Try to load the default ML-DSA-65 backend (@noble/post-quantum). Returns a
 * backend object or null. NEVER throws; absence yields null so callers refuse.
 *
 * @returns {Promise<{sign: Function, verify: Function}|null>}
 */
export declare function loadDefaultMldsaBackend(): Promise<MldsaBackend | null>;
/**
 * Produce an EP-HYBRID-v1 envelope: Ed25519 AND ML-DSA-65 signatures, both
 * over the domain-separated signing input that commits to the full algo set.
 *
 * THROWS (fail-closed) if the ML-DSA backend is unavailable: this function
 * never silently emits a classical-only envelope.
 *
 * @param {Uint8Array|string} message
 * @param {object} keys
 * @param {import('crypto').KeyObject} keys.ed25519PrivateKey
 * @param {Uint8Array} keys.mldsaSecretKey - raw ML-DSA-65 secret key bytes
 * @param {object} [options]
 * @param {{sign:Function,verify:Function}} [options.mldsaBackend] - injected backend
 * @param {Function} [options.mldsaBackendLoader] - async () => backend|null
 * @returns {Promise<{alg:string, signature_algos:string[], sigs:Record<string,string>}>}
 */
export declare function signHybrid(message: HybridMessage, keys: HybridSigningKeys, options?: HybridOptions): Promise<HybridEnvelope>;
/**
 * Verify an EP-HYBRID-v1 envelope. verified:true requires ALL of:
 *   - well-formed envelope with alg 'EP-HYBRID-v1'
 *   - presented signature_algos EXACTLY equals the registered set
 *     ['Ed25519','ML-DSA-65'] (order-sensitive; this is also what both
 *     signatures commit to, so tampering fails twice)
 *   - exactly one signature per committed algorithm (no extras, none missing)
 *   - Ed25519 signature valid over the committed signing input
 *   - ML-DSA-65 signature valid over the committed signing input, checked by
 *     a REAL backend; if no backend is available the result is
 *     { verified:false, reason:'pq_backend_unavailable' } - the PQ leg is
 *     never skipped.
 *
 * @param {Uint8Array|string} message
 * @param {object} envelope - { alg, signature_algos, sigs }
 * @param {object} keys
 * @param {string|import('crypto').KeyObject} keys.ed25519PublicKey - base64url SPKI DER or KeyObject
 * @param {Uint8Array|string} keys.mldsaPublicKey - raw ML-DSA-65 public key bytes or base64url
 * @param {object} [options]
 * @param {{verify:Function}} [options.mldsaBackend] - injected backend
 * @param {Function} [options.mldsaBackendLoader] - async () => backend|null
 * @returns {Promise<{verified:boolean, reason:string|null, checks:object}>}
 */
export declare function verifyHybrid(message: HybridMessage, envelope: unknown, keys: HybridVerificationKeys | null | undefined, options?: HybridOptions): Promise<HybridVerifyResult>;
//# sourceMappingURL=pq-hybrid.d.ts.map