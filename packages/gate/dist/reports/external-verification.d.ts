/**
 * EP-EXTERNAL-VERIFICATION-STATEMENT-v1.
 *
 * A signed statement a NON-EMILIA verifier can issue after it re-performs an
 * evidence log, replays an admissibility profile, or runs a conformance harness.
 * This is the missing adoption rail between "our verifier works" and "an
 * outside party says exactly what they checked."
 *
 * Scope is intentionally narrow:
 *   - the statement signs a procedure, inputs, result, and limitations;
 *   - it does NOT authorize an action;
 *   - it does NOT certify business correctness;
 *   - acceptance is by a relying party pinning the external verifier key.
 */
import crypto from 'node:crypto';
import { type AgileSignature } from '@emilia-protocol/verify/pq-signature-agility';
export declare const EXTERNAL_VERIFICATION_STATEMENT_VERSION = "EP-EXTERNAL-VERIFICATION-STATEMENT-v1";
export declare const EXTERNAL_VERIFICATION_DOMAIN = "EP-EXTERNAL-VERIFICATION-STATEMENT-v1\0";
/** Digest of the signed statement body, excluding the signature envelope. */
export declare function externalVerificationDigest(statement: any): string;
/**
 * Build and sign an external-verifier statement.
 *
 * @param {object} args
 * @param {object} args.verifier {id, name?, organization?}
 * @param {object} args.subject  what was checked, e.g. {kind:'evidence_log', head:'sha256:...'}
 * @param {object} args.procedure {id, version?, tool?, command?}
 * @param {object} args.result {status, checks?, artifact_digest?}
 * @param {object} [args.inputs] stable digests/ids the procedure consumed
 * @param {string[]} [args.limitations] honest non-claims
 * @param {string|number} [args.generated_at] ISO or epoch millis
 * @param {crypto.KeyObject} privateKey Ed25519 private key
 */
export declare function signExternalVerificationStatement(args: any, privateKey: any): Readonly<{
    signature: {
        algorithm: string;
        key_id: string;
        public_key: string;
        statement_digest: string;
        signature_b64u: string;
    };
    '@version': string;
    generated_at: string;
    verifier: {
        organization?: any;
        name?: any;
        id: any;
    };
    subject: any;
    procedure: any;
    inputs: any;
    result: {
        artifact_digest?: any;
        status: string;
        checks: {
            detail?: any;
            id: string;
            ok: boolean;
        }[];
    };
    limitations: any;
}>;
/**
 * Verify a signed external-verifier statement against pinned verifier keys.
 *
 * @param {object} statement
 * @param {{pinnedVerifierKeys?:Array<{verifier_id?:string,key_id?:string,public_key:string}>}} [opts]
 */
export declare function verifyExternalVerificationStatement(statement: any, opts?: {
    pinnedVerifierKeys?: Array<{
        verifier_id?: string;
        key_id?: string;
        public_key: string;
    }>;
}): {
    verified: boolean;
    accepted: boolean;
    checks: Record<string, boolean>;
    reason?: string;
    statement_digest?: string;
    verifier_id?: string;
    key_id?: string;
};
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the external-verifier statement.
 *
 * 1. VERSION BUMP. `signature: {algorithm, key_id, public_key,
 *    statement_digest, signature_b64u}` becomes `signature: {profile,
 *    required_algorithms, key_id, public_key, pq_key_id, pq_public_key,
 *    statement_digest, signatures}`, a shape change, so this is a new
 *    `@version` (-v1 -> -v2). verifyExternalVerificationStatement above is
 *    UNCHANGED and refuses a v2 statement at `unsupported_version` before it
 *    ever inspects `signature`.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1
 *    AgileSignature array, one entry per required algorithm.
 * 3. ANTI-STRIPPING. `required_algorithms` is a field of the STATEMENT BODY
 *    (inside `unsigned(statement)`, alongside subject/procedure/result), so
 *    it is covered by BOTH signatures via the existing signingBytes()/
 *    externalVerificationDigest() machinery -- no new signing-bytes function
 *    is needed, because that machinery already signs "the statement minus
 *    `signature`" for whatever shape is presented. Narrowing
 *    required_algorithms after minting changes the signed bytes, so the
 *    surviving Ed25519 signature no longer verifies.
 * 4. V1 COMPATIBILITY. verifyExternalVerificationStatement stays synchronous
 *    and untouched. verifyExternalVerificationStatementV2 is a SEPARATE async
 *    entry point; verifyExternalVerificationStatementAnyVersion routes on
 *    `@version`.
 * 5. NAMED REFUSALS. Every failure path returns `{verified:false,
 *    accepted:false, reason}`; nothing throws. An absent ML-DSA backend
 *    surfaces through the agility module's own `pq_backend_unavailable`,
 *    never a silent pass on the Ed25519 leg alone.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: this statement signs a procedure,
 * inputs, result, and limitations. It does not authorize an action and does
 * not certify business correctness under either version. The ML-DSA-65
 * backend remains @noble/post-quantum's pure-JS FIPS 204 implementation, not
 * independently audited and not a FIPS validated module; issuing or
 * verifying under this profile is not a certification claim.
 */
export declare const EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION = "EP-EXTERNAL-VERIFICATION-STATEMENT-v2";
export declare const EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/**
 * Build and sign a hybrid external-verifier statement. Throws on invalid
 * input or an unavailable ML-DSA backend -- issuer-side misuse is a
 * programming error, and a statement missing the PQ leg must never be minted.
 *
 * Unlike the classical signer (which derives its own public key from
 * `privateKey`), ML-DSA-65 has no public-key-from-secret-key derivation this
 * module performs, so the caller supplies `keys.pq.publicKeyB64u` explicitly
 * (raw 1952-byte ML-DSA-65 public key, base64url) -- the same convention
 * `PqCustodySigner` uses in lib/key-custody.ts.
 */
export declare function signExternalVerificationStatementV2(args: Parameters<typeof signExternalVerificationStatement>[0], keys: {
    ed: {
        privateKey: crypto.KeyObject;
    };
    pq: {
        secretKey: Uint8Array | string;
        publicKeyB64u: string;
    };
}): Promise<Readonly<{
    signature: {
        profile: string;
        required_algorithms: ("Ed25519" | "ML-DSA-65")[];
        key_id: string;
        public_key: string;
        pq_key_id: string;
        pq_public_key: string;
        statement_digest: string;
        signatures: AgileSignature[];
    };
    '@version': string;
    generated_at: string;
    verifier: {
        organization?: any;
        name?: any;
        id: any;
    };
    subject: any;
    procedure: any;
    inputs: any;
    result: {
        artifact_digest?: any;
        status: string;
        checks: {
            detail?: any;
            id: string;
            ok: boolean;
        }[];
    };
    limitations: any;
    required_algorithms: ("Ed25519" | "ML-DSA-65")[];
}>>;
/**
 * Verify a hybrid external-verifier statement against pinned verifier keys.
 * NEVER throws. Every failure returns `{verified:false, accepted:false,
 * reason}`, mirroring verifyExternalVerificationStatement's v1 contract.
 *
 * @param pinnedVerifierKeys entries now carry BOTH halves:
 *   {verifier_id, key_id?, public_key, pq_key_id?, pq_public_key}. A pin that
 *   matches the classical key but has no pq_public_key does not accept a v2
 *   statement from that verifier -- identified but not trusted for a leg that
 *   was never pinned.
 */
export declare function verifyExternalVerificationStatementV2(statement: any, opts?: {
    pinnedVerifierKeys?: Array<{
        verifier_id?: string;
        key_id?: string;
        public_key: string;
        pq_key_id?: string;
        pq_public_key?: string;
    }>;
}): Promise<{
    verified: boolean;
    accepted: boolean;
    checks: Record<string, boolean>;
    reason?: string;
    statement_digest?: string;
    verifier_id?: string;
    key_id?: string;
    pq_key_id?: string;
}>;
/**
 * Route a statement of EITHER version to its verifier. A v1 statement keeps
 * the exact v1 verdict (wrapped in a resolved Promise for a uniform async
 * surface); a v2 statement gets the hybrid check.
 */
export declare function verifyExternalVerificationStatementAnyVersion(statement: any, opts?: {
    pinnedVerifierKeys?: Array<{
        verifier_id?: string;
        key_id?: string;
        public_key: string;
        pq_key_id?: string;
        pq_public_key?: string;
    }>;
}): Promise<{
    verified: boolean;
    accepted: boolean;
    checks: Record<string, boolean>;
    reason?: string;
    statement_digest?: string;
    verifier_id?: string;
    key_id?: string;
}>;
declare const _default: {
    EXTERNAL_VERIFICATION_STATEMENT_VERSION: string;
    EXTERNAL_VERIFICATION_DOMAIN: string;
    externalVerificationDigest: typeof externalVerificationDigest;
    signExternalVerificationStatement: typeof signExternalVerificationStatement;
    verifyExternalVerificationStatement: typeof verifyExternalVerificationStatement;
    EXTERNAL_VERIFICATION_STATEMENT_V2_VERSION: string;
    EXTERNAL_VERIFICATION_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    signExternalVerificationStatementV2: typeof signExternalVerificationStatementV2;
    verifyExternalVerificationStatementV2: typeof verifyExternalVerificationStatementV2;
    verifyExternalVerificationStatementAnyVersion: typeof verifyExternalVerificationStatementAnyVersion;
};
export default _default;
//# sourceMappingURL=external-verification.d.ts.map