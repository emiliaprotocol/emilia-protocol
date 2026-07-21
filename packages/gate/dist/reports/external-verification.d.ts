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
declare const _default: {
    EXTERNAL_VERIFICATION_STATEMENT_VERSION: string;
    EXTERNAL_VERIFICATION_DOMAIN: string;
    externalVerificationDigest: typeof externalVerificationDigest;
    signExternalVerificationStatement: typeof signExternalVerificationStatement;
    verifyExternalVerificationStatement: typeof verifyExternalVerificationStatement;
};
export default _default;
//# sourceMappingURL=external-verification.d.ts.map