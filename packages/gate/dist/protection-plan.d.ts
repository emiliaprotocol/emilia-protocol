type Obj = Record<string, any>;
export declare const PROTECTION_PLAN_VERSION = "EMILIA-PROTECTION-PLAN-v1";
export declare const PROTECTION_COVERAGE_STATES: readonly ["protected", "connector_required", "observation_only", "not_protected", "verification_required"];
export type ProtectionCoverageState = typeof PROTECTION_COVERAGE_STATES[number];
export type ProtectionAssuranceClass = 'class_a' | 'quorum';
export type ProtectionPreset = Readonly<{
    id: string;
    label: string;
    consequence: string;
    action_type: string;
    action_control_id: string;
    assurance_floor: ProtectionAssuranceClass;
    connector: Readonly<{
        required: true;
        kind: string;
        label: string;
    }>;
    action: Readonly<Obj>;
}>;
export declare const PROTECTION_PRESETS: readonly ProtectionPreset[];
export declare function createProtectionPlan({ planId, ownerLabel, createdAt, selections, }: {
    planId: string;
    ownerLabel?: string;
    createdAt?: string;
    selections: Array<{
        presetId: string;
        assuranceClass?: ProtectionAssuranceClass;
    }>;
}): Obj;
export declare function evaluateProtectionCoverage(plan: Obj, verifiedCoverage?: Obj | null): Obj;
declare const _default: {
    PROTECTION_PLAN_VERSION: string;
    PROTECTION_COVERAGE_STATES: readonly ["protected", "connector_required", "observation_only", "not_protected", "verification_required"];
    PROTECTION_PRESETS: readonly Readonly<{
        id: string;
        label: string;
        consequence: string;
        action_type: string;
        action_control_id: string;
        assurance_floor: ProtectionAssuranceClass;
        connector: Readonly<{
            required: true;
            kind: string;
            label: string;
        }>;
        action: Readonly<Obj>;
    }>[];
    createProtectionPlan: typeof createProtectionPlan;
    evaluateProtectionCoverage: typeof evaluateProtectionCoverage;
};
export default _default;
//# sourceMappingURL=protection-plan.d.ts.map