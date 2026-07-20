type Obj = Record<string, any>;
export declare const ACTION_CONTROL_MANIFEST_VERSION = "EP-ACTION-CONTROL-MANIFEST-v0.2";
export declare const ACTION_CONTROL_SCHEMA_URL = "https://www.emiliaprotocol.ai/docs/schemas/agent-action-control-manifest-v0.2.schema.json";
export declare const ACTION_CONTROL_CONFORMANCE_LEVEL = "EG-1";
export declare const ACTION_CONTROL_DEFAULTS: Readonly<{
    decision_point: "pre_effect_commit";
    missing_receipt: "refuse";
    invalid_receipt: "refuse";
    stale_receipt: "refuse";
    replay: "one_time_consumption";
    evidence_log: "strict";
}>;
export declare const ACTION_CONTROL_EVIDENCE_PROFILES: Readonly<{
    authorization_receipt: "EP-RECEIPT-v1";
    execution_attestation: "EP-EXECUTION-ATTESTATION-v1";
    reliance_packet: "EP-RELIANCE-PACKET-v1";
    transparency: "SCITT-compatible Signed Statement";
}>;
export declare const ACTION_CONTROL_CONFORMANCE_CHECKS: readonly string[];
export declare function toActionControl(action: Obj): Obj;
/**
 * @param {object} [o]
 * @param {{ name?: string, issuer?: string, manifest_url?: string }} [o.service]
 * @param {boolean} [o.includePassThrough]
 * @param {Array<object>} [o.extraActions]
 */
export declare function createDefaultActionControlManifest({ service, includePassThrough, extraActions, }?: {
    service?: Obj;
    includePassThrough?: boolean;
    extraActions?: Obj[];
}): Obj;
export declare function findActionControl(manifest: Obj, selector?: Obj): Obj | null;
export declare function validateActionControlManifest(manifest: Obj): Obj;
declare const _default: {
    ACTION_CONTROL_MANIFEST_VERSION: string;
    ACTION_CONTROL_SCHEMA_URL: string;
    ACTION_CONTROL_CONFORMANCE_LEVEL: string;
    ACTION_CONTROL_DEFAULTS: Readonly<{
        decision_point: "pre_effect_commit";
        missing_receipt: "refuse";
        invalid_receipt: "refuse";
        stale_receipt: "refuse";
        replay: "one_time_consumption";
        evidence_log: "strict";
    }>;
    ACTION_CONTROL_EVIDENCE_PROFILES: Readonly<{
        authorization_receipt: "EP-RECEIPT-v1";
        execution_attestation: "EP-EXECUTION-ATTESTATION-v1";
        reliance_packet: "EP-RELIANCE-PACKET-v1";
        transparency: "SCITT-compatible Signed Statement";
    }>;
    ACTION_CONTROL_CONFORMANCE_CHECKS: readonly string[];
    toActionControl: typeof toActionControl;
    createDefaultActionControlManifest: typeof createDefaultActionControlManifest;
    findActionControl: typeof findActionControl;
    validateActionControlManifest: typeof validateActionControlManifest;
};
export default _default;
//# sourceMappingURL=action-control-manifest.d.ts.map