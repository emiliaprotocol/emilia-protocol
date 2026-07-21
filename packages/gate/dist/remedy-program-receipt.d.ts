export declare const ACTION_REMEDY_RECEIPT_VERSION = "EP-ACTION-REMEDY-RECEIPT-v1";
export declare const REMEDY_PROGRAM_RECEIPT_VERSION = "EP-ACTION-REMEDY-RECEIPT-v1";
export declare const ACTION_REMEDY_RECEIPT_DOMAIN = "EP-ACTION-REMEDY-RECEIPT-v1\0";
type DataRecord = Record<string, any>;
export interface RemedyReceiptExpectedBindings extends Record<string, unknown> {
    original_operation_id: string;
    original_action_digest: string;
    original_terminal_evidence_digest: string;
    case_instance_id: string;
    case_revision: number;
    case_status: string;
    remedy_operation_id: string;
    remedy_action_digest: string;
    remedy_caid: string;
    destination_binding_digest: string;
    units: number;
    unit: string;
    owner_mode: string;
    owner_digest: string;
}
/** Derive every relying-party binding that must be independently expected. */
export declare function expectedRemedyProgramReceiptBindings(state: unknown, remedyOperationId: string): Readonly<RemedyReceiptExpectedBindings>;
/** Return the exact domain-separated canonical bytes signed by Ed25519. */
export declare function remedyProgramReceiptSigningBytes(receipt: unknown): Buffer;
/**
 * Issue one receipt. Local private keys require an explicit ephemeral/test
 * opt-in; production issuance requires an external signer declaring KMS/HSM
 * custody. Every returned signature is verified against the configured public
 * key before the receipt leaves this function.
 */
export declare function issueRemedyProgramReceipt(input?: {
    state?: unknown;
    remedyOperationId?: string;
}, options?: {
    context?: unknown;
    privateKey?: unknown;
    signer?: unknown;
    allowEphemeralState?: boolean;
}): Promise<Readonly<{
    signature: {
        algorithm: string;
        value: string;
    };
    content_digest: string;
    version: string;
    issuer: DataRecord;
    payload: DataRecord;
}>>;
export declare const signRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
export declare const createRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
/**
 * Verify a receipt without network access. Trust keys, all issuer fields, the
 * exact current state snapshot, and every material original/remedy binding are
 * relying-party inputs; none are accepted from the receipt itself.
 */
export declare function verifyRemedyProgramReceipt(receipt: unknown, { trustedKeys, expectedIssuer, state, expected, }?: {
    trustedKeys?: unknown;
    expectedIssuer?: unknown;
    state?: unknown;
    expected?: unknown;
}): Readonly<{
    valid: false;
    reason: string;
    checks: Readonly<{
        [x: string]: boolean;
    }>;
    content_digest: null;
    payload: null;
}> | Readonly<{
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        payload: boolean;
        content_digest: boolean;
        issuer_pin: boolean;
        key: boolean;
        signature: boolean;
        state_snapshot: boolean;
        expected_bindings: boolean;
    };
    content_digest: string;
    payload: DataRecord;
}>;
declare const _default: {
    ACTION_REMEDY_RECEIPT_VERSION: string;
    REMEDY_PROGRAM_RECEIPT_VERSION: string;
    ACTION_REMEDY_RECEIPT_DOMAIN: string;
    expectedRemedyProgramReceiptBindings: typeof expectedRemedyProgramReceiptBindings;
    remedyProgramReceiptSigningBytes: typeof remedyProgramReceiptSigningBytes;
    issueRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
    signRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
    createRemedyProgramReceipt: typeof issueRemedyProgramReceipt;
    verifyRemedyProgramReceipt: typeof verifyRemedyProgramReceipt;
};
export default _default;
//# sourceMappingURL=remedy-program-receipt.d.ts.map