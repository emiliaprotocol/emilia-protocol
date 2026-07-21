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
export declare function createReceiptProgramKernel({ gate, resolveCaid, operationIdField, certificatePrivateKey, certificateSigner, certificateContext, projectResult, effectTimeoutMs, allowEphemeralState, now, }?: any): Readonly<{
    version: string;
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
declare const _default: {
    RECEIPT_PROGRAM_VERSION: string;
    RECEIPT_PROGRAM_CERTIFICATE_VERSION: string;
    RECEIPT_PROGRAM_SIGNATURE_ALGORITHM: string;
    createReceiptProgramKernel: typeof createReceiptProgramKernel;
    verifyReceiptProgramCertificate: typeof verifyReceiptProgramCertificate;
};
export default _default;
//# sourceMappingURL=receipt-program.d.ts.map