import { type FipsPosture } from '@emilia-protocol/verify/fips-mode';
export declare const RECEIPT_PROGRAM_VERSION = "EP-RECEIPT-PROGRAM-v1";
export declare const RECEIPT_PROGRAM_CERTIFICATE_VERSION = "EP-RECEIPT-PROGRAM-CERTIFICATE-v1";
export declare const RECEIPT_PROGRAM_SIGNATURE_ALGORITHM = "Ed25519";
/**
 * Build a receipt-program kernel over an already configured Gate.
 * Trust configuration is constructor-pinned and cannot be supplied per run.
 *
 * options.gate: configured EMILIA Gate
 * options.resolveCaid: synchronous pinned CAID resolver, (action) => string|object
 * options.operationIdField: dot-path to the stable operation id in observed action
 * options.certificatePrivateKey: test/demo-only Ed25519 operator key
 * options.certificateSigner: external KMS/HSM signer
 * options.certificateContext: pinned issuer, tenant, environment, audience, and key id
 * options.projectResult: pinned disclosure projection, (result) => any|Promise<any>
 * options.effectTimeoutMs: provider deadline in milliseconds (default 30000)
 * options.allowEphemeralState: explicit test/demo opt-in (default false)
 * options.now: number|(() => number), default Date.now
 */
export declare function createReceiptProgramKernel({ gate, resolveCaid, operationIdField, certificatePrivateKey, certificateSigner, certificateContext, projectResult, effectTimeoutMs, allowEphemeralState, now, fipsPosture, }?: any): Readonly<{
    version: "EP-RECEIPT-PROGRAM-v1";
    signer_public_key: any;
    certificate_context: any;
    /**
     * Execute one consequential receipt instruction through Gate.
     * The effect MUST return a bounded canonical-JSON evidence projection, not
     * a raw provider object. A projection failure occurs after provider entry
     * and is therefore committed as indeterminate.
     */
    run(request: any | undefined, effect: any): Promise<any>;
    /**
     * Explicit crash-recovery path. It scans the durable evidence history only
     * when requested and returns every independently verified certificate for
     * one program digest; it never guesses which attempt a caller intended.
     */
    recoverCertificates(programDigest: any): Promise<any>;
}>;
/**
 * Verify the certificate's operator signature, content addresses, program
 * binding, and Gate evidence linkage. This proves exact certificate integrity
 * under a pinned operator key; it does not prove an external provider told the
 * truth or replace verification of the referenced receipt/capability artifacts.
 *
 * options.trustedCertificateKeys?: Record<string, string>
 * options.resolveCaid?: ((action: any) => any)|null
 * options.expectedContext?: object|null
 * options.certificateEvidence?: any
 * options.verifyCertificateInclusion?: (((record: any, expectation: any) => any)|null)
 * options.requireAtomicCertificateEvidence?: boolean
 */
export declare function verifyReceiptProgramCertificate(certificate: any, { trustedCertificateKeys, resolveCaid, expectedContext, certificateEvidence, verifyCertificateInclusion, requireAtomicCertificateEvidence, }?: any): any;
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the receipt-program execution
 * certificate, and moves the PROGRAM marker with the certificate: an
 * EP-RECEIPT-PROGRAM-CERTIFICATE-v2 certificate freezes an
 * EP-RECEIPT-PROGRAM-v2 program.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, public_key,
 *    value}` becomes `signature: {profile, required_algorithms, public_key,
 *    key_id, pq_public_key, pq_key_id, signatures}`, a wire-format change, so
 *    the certificate takes a new `@version` (-v1 -> -v2) and the program it
 *    embeds takes one too, because the program's own `@version` is inside the
 *    signed core. verifyReceiptProgramCertificate above is UNCHANGED and
 *    refuses a v2 certificate at `certificate_version_invalid`, on the version
 *    marker, as its FIRST check -- before it reads the signature at all, and
 *    without crashing.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim. Ed25519 keeps its base64url SPKI DER
 *    public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (receiptProgramCertificateV2SigningBytes), alongside the core and its
 *    state root. Drop the ML-DSA leg and narrow the set to ["Ed25519"] and the
 *    surviving Ed25519 signature no longer verifies. Leave the set intact and
 *    the missing leg is a structural refusal. The verifier rebuilds the bytes
 *    from the REGISTERED set and from the core it independently recomputed.
 * 4. V1 COMPATIBILITY. verifyReceiptProgramCertificate stays SYNCHRONOUS and
 *    untouched, and createReceiptProgramKernel still mints v1 certificates
 *    with byte-identical behavior. verifyReceiptProgramCertificateV2 is a
 *    SEPARATE async entry point (ML-DSA verification is inherently async);
 *    verifyReceiptProgramCertificateStatement routes on `@version`. Everything
 *    after the signature check is ONE shared body
 *    (verifyCertificateBodyAfterSignature), so the two versions cannot drift
 *    on state root, context, program binding, CAID reperformance, opcode
 *    trace, evidence linkage, or inclusion.
 * 5. NAMED REFUSALS. Verification never throws on caller input; every failure
 *    is `{ok:false, reason}`. An absent ML-DSA backend surfaces as
 *    `pq_backend_unavailable`, never a skipped check and never a pass on the
 *    classical leg.
 *
 * THE FIPS CONSULT, PRESERVED AND EXTENDED. The kernel's opt-in `fipsPosture`
 * consult (issueCertificate, above) is unchanged. The v2 issuer consults
 * checkOperationPolicy() for BOTH registered algorithms before the signer is
 * called. Under a posture that is not verifiably FIPS-inactive, ML-DSA-65's
 * policy is a REFUSAL unless the deployment explicitly acknowledges the
 * unvalidated implementation (`allowUnvalidatedMldsa: true`). Under a plainly
 * non-FIPS posture no acknowledgment is required. Left undefined, the consult
 * does not run.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: a verified certificate proves exact
 * certificate integrity under pinned operator keys. It does not prove an
 * external provider told the truth, and it does not replace verification of
 * the referenced receipt/capability artifacts. The ML-DSA-65 backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently
 * audited and not a FIPS validated module, and its secret key is
 * software-held: this profile does NOT satisfy a kms/hsm-only custody
 * requirement, and issuing under it is not a certification claim.
 */
export declare const RECEIPT_PROGRAM_V2_VERSION = "EP-RECEIPT-PROGRAM-v2";
export declare const RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION = "EP-RECEIPT-PROGRAM-CERTIFICATE-v2";
/** The registered required algorithm set, in canonical order. */
export declare const RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** A v2 certificate signer pin: BOTH public halves, pinned out of band. */
export interface ReceiptProgramV2KeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
/**
 * An injected hybrid signer. Structurally the `signSet()` contract of
 * lib/key-custody.ts's HybridCustodySigner: sign the SAME bytes under every
 * required algorithm, in canonical order. Accepted structurally rather than
 * imported because @emilia-protocol/gate does not depend on the app-tier lib/
 * tree; a HybridCustodySigner satisfies this shape as-is.
 */
export interface ReceiptProgramV2SignSetSigner {
    keyId: string;
    custody?: string;
    publicKeys: ReceiptProgramV2KeyPin;
    signSet(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<Array<{
        alg: string;
        sig: string;
        key_id?: string;
    }>>;
}
/**
 * The bytes BOTH legs sign: the certificate core plus its recomputed
 * state_root, under the v2 domain tag, plus the committed
 * `required_algorithms` set. Recomputed independently by the verifier from the
 * PRESENTED core and the REGISTERED set. See move 3 above.
 */
export declare function receiptProgramCertificateV2SigningBytes(signedCore: any, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Issue one hybrid execution certificate over an already assembled core. The
 * signer is either a local key pair (test/demo) or an injected signSet signer;
 * every returned signature set is verified against the configured public
 * halves before the certificate leaves this function.
 */
export declare function issueReceiptProgramCertificateV2(input: any, { keys, signer, fipsPosture, allowUnvalidatedMldsa, }?: {
    keys?: {
        ed: {
            privateKey: any;
            publicKey?: string;
        };
        pq: {
            secretKey: Uint8Array | string;
            publicKey: string;
        };
    };
    signer?: ReceiptProgramV2SignSetSigner;
    fipsPosture?: FipsPosture;
    allowUnvalidatedMldsa?: boolean;
}): Promise<any>;
/**
 * FAIL-CLOSED hybrid certificate verifier. Never throws on caller input; a v2
 * certificate NEVER verifies on one leg alone. Everything after the signature
 * is the same body the v1 verifier runs.
 */
export declare function verifyReceiptProgramCertificateV2(certificate: any, { trustedCertificateKeys, resolveCaid, expectedContext, certificateEvidence, verifyCertificateInclusion, requireAtomicCertificateEvidence, mldsaBackend, mldsaBackendLoader, }?: any): Promise<any>;
/**
 * Route a certificate of EITHER version to its verifier. v1 certificates keep
 * the exact v1 verdict; v2 certificates get the hybrid check. A certificate
 * whose `@version` is neither refuses through the v1 verifier, which is the
 * fail-closed answer.
 */
export declare function verifyReceiptProgramCertificateStatement(certificate: any, options?: any): Promise<any>;
declare const _default: {
    RECEIPT_PROGRAM_VERSION: string;
    RECEIPT_PROGRAM_CERTIFICATE_VERSION: string;
    RECEIPT_PROGRAM_SIGNATURE_ALGORITHM: string;
    RECEIPT_PROGRAM_V2_VERSION: string;
    RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION: string;
    RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    createReceiptProgramKernel: typeof createReceiptProgramKernel;
    verifyReceiptProgramCertificate: typeof verifyReceiptProgramCertificate;
    receiptProgramCertificateV2SigningBytes: typeof receiptProgramCertificateV2SigningBytes;
    issueReceiptProgramCertificateV2: typeof issueReceiptProgramCertificateV2;
    verifyReceiptProgramCertificateV2: typeof verifyReceiptProgramCertificateV2;
    verifyReceiptProgramCertificateStatement: typeof verifyReceiptProgramCertificateStatement;
};
export default _default;
//# sourceMappingURL=receipt-program.d.ts.map