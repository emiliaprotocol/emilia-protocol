/**
 * EP-TIME-ATTESTATION-v1 — independent, offline-verifiable proof of WHEN.
 *
 * An EP signoff's `issued_at` is asserted by whoever stamped it. For the
 * absolute time of a signoff or receipt to be trustworthy to a third party, an
 * INDEPENDENT timestamping authority (TSA) — a party EP identifies but does not
 * trust — signs over (the hash of) the artifact plus the time. This is the
 * trusted-time analogue of everything else in EP: ASYMMETRIC, key-PINNED,
 * fail-closed. It composes with the strong ordered chain (which already proves
 * relative ORDER cryptographically): the chain proves sequence, a time
 * attestation bounds the absolute instant.
 *
 *   { "@version": "EP-TIME-ATTESTATION-v1",
 *     ts_authority_id: "ep:tsa:...",
 *     hashed: "sha256:<hex>",          // the artifact this attestation timestamps
 *     time:   "<RFC 3339>",            // the attested instant
 *     proof:  { algorithm:"Ed25519", ts_key_id, signature_b64u, public_key } }
 *
 * verifyTimeAttestation(att, opts) is FAIL-CLOSED: it accepts only when the
 * version matches, the TSA is PINNED (opts.tsaKeys[ts_authority_id], and the
 * proof key equals the pinned key), the Ed25519 proof verifies over the
 * verifier-recomputed canonical bytes, the time is a well-formed instant, and
 * (when supplied) the attested `hashed` equals opts.expectedHash and the time
 * falls within [opts.notBefore, opts.notAfter].
 *
 * HONEST BOUNDARY: this proves an independent authority attested this exact
 * content existed at time T. It does not prove the TSA's clock was correct, nor
 * that no EARLIER attestation exists. It bounds, it does not divine.
 */
import { type KeyObject } from 'node:crypto';
import { type AgilityOptions } from './pq-signature-agility.js';
export declare const TIME_ATTESTATION_VERSION = "EP-TIME-ATTESTATION-v1";
export interface TimeAttestation {
    '@version'?: unknown;
    ts_authority_id?: unknown;
    hashed?: unknown;
    time?: unknown;
    proof?: {
        public_key?: unknown;
        signature_b64u?: unknown;
        [key: string]: unknown;
    } | null;
    [key: string]: unknown;
}
export interface TimeAttestationOptions {
    tsaKeys?: Record<string, {
        public_key: string;
    }>;
    expectedHash?: string;
    notBefore?: string | number | Date;
    notAfter?: string | number | Date;
    [key: string]: unknown;
}
export interface TimeAttestationResult {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}
/**
 * The fixed bytes a TSA signature over this attestation is bound to,
 * recomputed independently of how the attestation was presented.
 *
 * Exported so an algorithm-agile verifier (see evidence-record.ts) checks a
 * ML-DSA-65 proof over the SAME bytes the Ed25519 path checks, rather than
 * carrying its own second definition of what a time attestation commits to.
 * One definition of the signed bytes, one place to change it.
 */
export declare function timeAttestationSignedBytes(att: TimeAttestation): Buffer;
/**
 * @param {object} att  the EP-TIME-ATTESTATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.tsaKeys]  pinned TSA keys by ts_authority_id.
 * @param {string} [opts.expectedHash]  the artifact hash this attestation MUST cover.
 * @param {string|number|Date} [opts.notBefore]  attested time must be >= this.
 * @param {string|number|Date} [opts.notAfter]   attested time must be <= this.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export declare function verifyTimeAttestation(att: TimeAttestation | null | undefined, opts?: TimeAttestationOptions): TimeAttestationResult;
/**
 * REFERENCE HYBRID MIGRATION, applied to the TSA attestation. This follows the
 * same five moves as EP-REVOCATION-v2 (packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `proof`, so the artifact takes a new `@version`
 *    (EP-TIME-ATTESTATION-v1 -> EP-TIME-ATTESTATION-v2) instead of growing an
 *    optional field on v1. verifyTimeAttestation() above is untouched: it
 *    still accepts exactly what it accepted before, and it refuses a v2
 *    attestation on the version marker without throwing -- every subsequent
 *    line in that function reaches v2's differently-shaped `proof` only
 *    through optional chaining (`proof?.public_key`, `proof?.signature_b64u`),
 *    which is safe against a `proof.signatures` array instead of a flat
 *    `signature_b64u` string.
 *
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm, in the registered
 *    order. Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65
 *    carries raw base64url public key bytes.
 *
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes (timeAttestationV2SignedBytes below), always rebuilt by the
 *    verifier from the REGISTERED set -- never from what the presented
 *    attestation claims. Narrowing `proof.required_algorithms` is refused
 *    structurally (algorithm_set), and independently, any signature actually
 *    minted over a narrowed-set commitment does not verify over the bytes the
 *    verifier recomputes from the full registered set.
 *
 * 4. V1 COMPATIBILITY. timeAttestationSignedBytes/timeSignedPayload above are
 *    UNTOUCHED: evidence-record.ts's algorithm-AGILE per-attestation path
 *    depends on those exact bytes, and this migration does not change them.
 *    v2 needs different bytes (v2 version string + committed algorithm set),
 *    so it gets its own, separate signed-bytes function, the same way
 *    revocation.ts keeps revocationSignedPayload (v1) and
 *    revocationV2SignedPayload (v2) as two independent functions. v2
 *    verification is ASYNC (ML-DSA verification is async), so it is a
 *    separate entry point rather than a signature change to
 *    verifyTimeAttestation; verifyTimeAttestationStatement() routes on
 *    `@version` for callers holding a mixed bag.
 *
 * 5. NAMED REFUSALS. Every failure path sets a named check to false and
 *    pushes a human-readable error; nothing throws on caller input. An
 *    absent ML-DSA backend is a refusal ('pq_backend_unavailable' surfaced
 *    through the agility result), never a skipped check and never a pass on
 *    the classical leg.
 *
 * HONEST BOUNDARIES. Everything the v1 header says about this profile still
 * holds: a verified v2 attestation proves an independent, pinned authority
 * attested this exact content existed at time T; it does not prove the TSA's
 * clock was correct, nor that no earlier attestation exists. The ML-DSA
 * backend is @noble/post-quantum's pure-JS FIPS 204 implementation, which is
 * not independently audited and is not a FIPS validated module; verifying
 * under this profile is not a certification claim. v2 does NOT retroactively
 * protect attestations already issued under v1.
 */
export declare const TIME_ATTESTATION_V2_VERSION = "EP-TIME-ATTESTATION-v2";
/** The registered required algorithm set, in canonical order. */
export declare const TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface TimeAttestationV2Signature {
    alg?: unknown;
    sig?: unknown;
    key_id?: unknown;
}
export interface TimeAttestationV2Proof {
    required_algorithms?: unknown;
    ts_key_id?: unknown;
    /** Ed25519: base64url SPKI DER. */
    public_key?: unknown;
    pq_key_id?: unknown;
    /** ML-DSA-65: base64url of the raw 1952-byte public key. */
    pq_public_key?: unknown;
    signatures?: unknown;
    [key: string]: unknown;
}
export interface TimeAttestationV2 {
    '@version'?: unknown;
    ts_authority_id?: unknown;
    hashed?: unknown;
    time?: unknown;
    proof?: TimeAttestationV2Proof | null;
    [key: string]: unknown;
}
/** A v2 TSA pin: BOTH public halves, pinned out of band. */
export interface TsaV2KeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key?: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key?: string;
    key_id?: string;
    pq_key_id?: string;
}
export interface TimeAttestationV2Options extends AgilityOptions {
    tsaKeys?: Record<string, TsaV2KeyPin>;
    expectedHash?: string;
    notBefore?: string | number | Date;
    notAfter?: string | number | Date;
    [key: string]: unknown;
}
export interface TimeAttestationV2Result {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}
/**
 * The bytes BOTH legs sign. Same fixed field set as v1
 * (hashed/time/ts_authority_id), plus the `required_algorithms` set and the
 * v2 `@version` marker, so the algorithm set is cryptographically committed.
 * Recomputed independently by the verifier from the PRESENTED artifact
 * fields and the REGISTERED algorithm set. canonicalize() sorts keys, so
 * field order here is irrelevant.
 *
 * This is a NEW, separate function from timeAttestationSignedBytes /
 * timeSignedPayload above -- it does not replace or delegate to them, and
 * evidence-record.ts's existing v1 agile-per-attestation path is unaffected.
 */
export declare function timeAttestationV2SignedBytes(att: TimeAttestationV2, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * verifyTimeAttestationV2 -- FAIL-CLOSED hybrid TSA attestation check. Never
 * throws on caller input. Every gating check must be true; a v2 attestation
 * never verifies on one leg alone.
 */
export declare function verifyTimeAttestationV2(att: TimeAttestationV2 | null | undefined, opts?: TimeAttestationV2Options): Promise<TimeAttestationV2Result>;
/**
 * Route an attestation of EITHER version to its verifier. v1 attestations
 * keep the exact v1 verdict; v2 attestations get the hybrid check. An
 * attestation whose `@version` is neither refuses on the version marker,
 * through the v1 verifier, which is the fail-closed answer.
 */
export declare function verifyTimeAttestationStatement(att: TimeAttestation | TimeAttestationV2 | null | undefined, opts?: TimeAttestationV2Options): Promise<TimeAttestationResult | TimeAttestationV2Result>;
export interface TimeAttestationV2Signer {
    /** Ed25519 private key. */
    privateKey: KeyObject;
    /** Ed25519 public key, base64url SPKI DER. */
    publicKeyB64u: string;
    /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
    pqSecretKey: Uint8Array | string;
    /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
    pqPublicKeyB64u: Uint8Array | string;
}
export interface BuildTimeAttestationV2Args {
    ts_authority_id?: unknown;
    hashed?: unknown;
    time?: unknown;
    signer?: TimeAttestationV2Signer | null;
    /** ML-DSA-65 FIPS 204 deterministic variant; conformance vectors only. */
    deterministic?: boolean;
}
/**
 * buildTimeAttestationV2 -- produce an EP-TIME-ATTESTATION-v2 attestation
 * over the exact (hashed, time, ts_authority_id), signed under BOTH
 * registered algorithms over one set of bytes that COMMITS to the required
 * algorithm set (see timeAttestationV2SignedBytes).
 *
 * THROWS rather than emit a half-hybrid attestation: issuer-side misuse is a
 * programming error, and an unavailable ML-DSA backend makes signAgileSet
 * throw, so an attestation missing the PQ leg is never produced.
 */
export declare function buildTimeAttestationV2({ ts_authority_id: tsAuthorityId, hashed, time, signer, deterministic, }?: BuildTimeAttestationV2Args): Promise<TimeAttestationV2>;
//# sourceMappingURL=time-attestation.d.ts.map