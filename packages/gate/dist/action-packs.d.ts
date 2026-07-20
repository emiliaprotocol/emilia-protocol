export function createDefaultActionRiskManifest({ includePassThrough, extraActions }?: {
    includePassThrough?: boolean | undefined;
    extraActions?: never[] | undefined;
}): {
    '@version': string;
    actions: any[];
};
export function highRiskActionTypes(actions?: readonly (Readonly<{
    id: "money_movement.release";
    label: "Money movement";
    action_type: "payment.release";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Moves funds or releases value. Requires a named human signoff, not an agent-only key.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "money_movement.bank_details_change";
    label: "Bank-detail change";
    action_type: "payment.bank_details.change";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes where future money flows. Treats payee, beneficiary, vendor, and payroll account changes as high-risk by category.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "production.deploy";
    label: "Production deploy";
    action_type: "deploy.production";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes live production behavior. Quorum is the cryptographic two-person rule for hard operational cuts.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "permissions.admin_change";
    label: "Permission or admin change";
    action_type: "permission.admin.change";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes who can act next. Privilege changes deserve stronger proof than the session that requested them.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "data.bulk_export";
    label: "Bulk data export";
    action_type: "data.export";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Moves sensitive data out of its system of record. The recipient and purpose must be bound to the approval.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "records.delete";
    label: "Record deletion";
    action_type: "record.delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys or hides state. The record identity and pre-state must be bound before deletion.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "regulated.decision_override";
    label: "Regulated decision override";
    action_type: "regulated.decision.override";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes a decision with legal, benefit, credit, clinical, or safety impact. Requires named accountability.";
    execution_binding: {
        required_fields: string[];
    };
}>)[]): ("payment.release" | "payment.bank_details.change" | "deploy.production" | "permission.admin.change" | "data.export" | "record.delete" | "regulated.decision.override")[];
export const ACTION_RISK_MANIFEST_VERSION: "EP-ACTION-RISK-MANIFEST-v0.1";
export const HIGH_RISK_ACTION_PACKS: readonly (Readonly<{
    id: "money_movement.release";
    label: "Money movement";
    action_type: "payment.release";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Moves funds or releases value. Requires a named human signoff, not an agent-only key.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "money_movement.bank_details_change";
    label: "Bank-detail change";
    action_type: "payment.bank_details.change";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes where future money flows. Treats payee, beneficiary, vendor, and payroll account changes as high-risk by category.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "production.deploy";
    label: "Production deploy";
    action_type: "deploy.production";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes live production behavior. Quorum is the cryptographic two-person rule for hard operational cuts.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "permissions.admin_change";
    label: "Permission or admin change";
    action_type: "permission.admin.change";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes who can act next. Privilege changes deserve stronger proof than the session that requested them.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "data.bulk_export";
    label: "Bulk data export";
    action_type: "data.export";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Moves sensitive data out of its system of record. The recipient and purpose must be bound to the approval.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "records.delete";
    label: "Record deletion";
    action_type: "record.delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys or hides state. The record identity and pre-state must be bound before deletion.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "regulated.decision_override";
    label: "Regulated decision override";
    action_type: "regulated.decision.override";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes a decision with legal, benefit, credit, clinical, or safety impact. Requires named accountability.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export const DEFAULT_PASS_THROUGH_ACTIONS: readonly Readonly<{
    id: "observe.read_status";
    label: "Read-only status";
    action_type: "read.status";
    receipt_required: false;
    match: {
        protocol: string;
        tool: string;
    };
}>[];
export const DEFAULT_GATE_MANIFEST: Readonly<{
    '@version': string;
    actions: any[];
}>;
declare namespace _default {
    export { ACTION_RISK_MANIFEST_VERSION };
    export { HIGH_RISK_ACTION_PACKS };
    export { DEFAULT_PASS_THROUGH_ACTIONS };
    export { DEFAULT_GATE_MANIFEST };
    export { createDefaultActionRiskManifest };
    export { highRiskActionTypes };
}
export default _default;
//# sourceMappingURL=action-packs.d.ts.map