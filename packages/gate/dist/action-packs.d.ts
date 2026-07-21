export declare const ACTION_RISK_MANIFEST_VERSION = "EP-ACTION-RISK-MANIFEST-v0.1";
/**
 * Shape of a single action-pack entry. `business_authorization` is not part
 * of the shipped defaults below but is a legitimate dynamic extension point:
 * callers (e.g. lib/gate/reference-lab.js) attach it to a manifest entry
 * after createDefaultActionRiskManifest() returns, before enforcement.
 */
type ActionPack = {
    id: string;
    label: string;
    action_type: string;
    risk?: string;
    receipt_required: boolean;
    assurance_class?: string;
    match: {
        protocol: string;
        tool: string;
    };
    why?: string;
    execution_binding?: {
        required_fields: string[];
        caid_selector?: {
            field: string;
        };
    };
    business_authorization?: Record<string, any>;
};
export declare const HIGH_RISK_ACTION_PACKS: readonly ActionPack[];
export declare const DEFAULT_PASS_THROUGH_ACTIONS: readonly ActionPack[];
export declare function createDefaultActionRiskManifest({ includePassThrough, extraActions, }?: {
    includePassThrough?: boolean;
    extraActions?: ActionPack[];
}): {
    '@version': string;
    actions: ActionPack[];
};
export declare const DEFAULT_GATE_MANIFEST: Readonly<{
    '@version': string;
    actions: ActionPack[];
}>;
export declare function highRiskActionTypes(actions?: readonly ActionPack[]): string[];
declare const _default: {
    ACTION_RISK_MANIFEST_VERSION: string;
    HIGH_RISK_ACTION_PACKS: readonly ActionPack[];
    DEFAULT_PASS_THROUGH_ACTIONS: readonly ActionPack[];
    DEFAULT_GATE_MANIFEST: Readonly<{
        '@version': string;
        actions: ActionPack[];
    }>;
    createDefaultActionRiskManifest: typeof createDefaultActionRiskManifest;
    highRiskActionTypes: typeof highRiskActionTypes;
};
export default _default;
//# sourceMappingURL=action-packs.d.ts.map