/**
 * Machine-checked source map for the explicit formal-to-runtime bridge.
 *
 * This is a coverage binding, not a compiler: the monitor remains reviewed
 * JavaScript and the TLA+ model remains the source of the formal theorem.
 */
export declare const FORMAL_RUNTIME_BRIDGE_VERSION = "EP-FORMAL-RUNTIME-BRIDGE-v1";
export declare const FORMAL_RUNTIME_SPEC = "formal/ep_handshake.tla";
export declare const FORMAL_RUNTIME_CONFIG = "formal/ep_handshake.cfg";
export declare const FORMAL_RUNTIME_INVARIANT_MAP: readonly (Readonly<{
    runtime: "ConsumeOnceSafety";
    formal: "ConsumeOnceSafety";
    transition: "consumptionCommitted";
}> | Readonly<{
    runtime: "WriteBypassSafety";
    formal: "WriteBypassSafety";
    transition: "beginExecution";
}> | Readonly<{
    runtime: "SignoffBindingMatch";
    formal: "SignoffBindingMatch";
    transition: "recordDecision";
}>)[];
declare const _default: {
    FORMAL_RUNTIME_BRIDGE_VERSION: string;
    FORMAL_RUNTIME_SPEC: string;
    FORMAL_RUNTIME_CONFIG: string;
    FORMAL_RUNTIME_INVARIANT_MAP: readonly (Readonly<{
        runtime: "ConsumeOnceSafety";
        formal: "ConsumeOnceSafety";
        transition: "consumptionCommitted";
    }> | Readonly<{
        runtime: "WriteBypassSafety";
        formal: "WriteBypassSafety";
        transition: "beginExecution";
    }> | Readonly<{
        runtime: "SignoffBindingMatch";
        formal: "SignoffBindingMatch";
        transition: "recordDecision";
    }>)[];
};
export default _default;
//# sourceMappingURL=formal-runtime-map.d.ts.map