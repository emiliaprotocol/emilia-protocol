/**
 * Bridge one currently claimed Remedy Program action into Gate admission.
 *
 * Remedy Program state and its signed receipt are qualification evidence. They
 * never grant an execution right. Only the injected AdmissionStore may create
 * that right, and this bridge intentionally exposes no invocation, provider,
 * retry, finalization, or reconciliation operation.
 */
import { type AdmissionReserveResult, type AdmissionSnapshot, type AdmissionSnapshotInput, type ExecutionProgramAdmissionStore, type ExecutionProgramReserveInput } from './admission-store.js';
import type { RemedyProgramStore } from './remedy-program.js';
type DataRecord = Record<string, any>;
export interface RecoveryAdmissionRemedyOwner {
    owner_mode: 'receipt-program' | 'action-escrow';
    owner_digest: string;
}
export interface RecoveryAdmissionRemedyBridgeOptions {
    remedyProgramStore: RemedyProgramStore;
    admissionStore: ExecutionProgramAdmissionStore;
    trustedReceiptKeys: Readonly<Record<string, unknown>>;
    expectedReceiptIssuer: Readonly<{
        issuer: string;
        tenant: string;
        environment: string;
        audience: string;
        key_id: string;
    }>;
    allowedRemedyOwners: readonly Readonly<RecoveryAdmissionRemedyOwner>[];
    /** Unit-test escape hatch. Production bridges require two durable stores. */
    allowEphemeralStoresForTests?: true;
}
export interface RecoveryAdmissionRemedyProgramInput extends Omit<ExecutionProgramReserveInput, 'admission'> {
}
export interface RecoveryAdmissionRemedyInput {
    tenant_id: string;
    remedy_case_instance_id: string;
    original_admission_id: string;
    claim_token: string;
    receipt: unknown;
    admission: AdmissionSnapshotInput | AdmissionSnapshot;
    execution_program?: RecoveryAdmissionRemedyProgramInput;
}
export type RecoveryAdmissionRemedyRefusalReason = 'recovery_admission_input_invalid' | 'remedy_current_state_unavailable' | 'remedy_case_not_found' | 'remedy_not_currently_claimed' | 'remedy_claim_owned' | 'remedy_claim_currentness_mismatch' | 'remedy_receipt_invalid' | 'remedy_receipt_state_mismatch' | 'remedy_receipt_binding_mismatch' | 'tenant_mismatch' | 'original_admission_not_found' | 'original_admission_binding_mismatch' | 'remedy_admission_binding_mismatch' | 'authorization_evidence_mismatch' | 'remedy_owner_not_allowed';
export type RecoveryAdmissionRemedyResult = {
    ok: true;
    receipt_content_digest: string;
    receipt_payload: Readonly<DataRecord>;
    reservation: Extract<AdmissionReserveResult, {
        ok: true;
    }>;
} | {
    ok: false;
    reason: RecoveryAdmissionRemedyRefusalReason | string;
};
export interface RecoveryAdmissionRemedyBridge {
    reserve(input: RecoveryAdmissionRemedyInput): Promise<RecoveryAdmissionRemedyResult>;
}
/**
 * Construct a server-pinned bridge. Configuration is copied so callers cannot
 * mutate owner or issuer policy after construction.
 */
export declare function createRecoveryAdmissionRemedyBridge(options: RecoveryAdmissionRemedyBridgeOptions): Readonly<RecoveryAdmissionRemedyBridge>;
export declare const createRemedyAdmissionBridge: typeof createRecoveryAdmissionRemedyBridge;
export default createRecoveryAdmissionRemedyBridge;
//# sourceMappingURL=recovery-admission-remedy.d.ts.map