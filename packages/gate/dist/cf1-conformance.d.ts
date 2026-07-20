type Obj = Record<string, any>;
export declare const CF1_VERSION = "CF-1";
export declare const CF1_CHECKS: any;
/**
 * Drive a subject through the CF-1 checks and return a JSON report.
 * @param {object} [o]
 * @param {(scenario:object)=>Promise<object>} [o.invoke]   the gate under test
 * @param {(scenario:object)=>Promise<object>} [o.wrongInvoke] a sibling gate pinned to a DIFFERENT (wrong) issuer key
 * @param {object} [o.harness]      from createEg1Harness()
 * @param {object} [o.action]     the high-risk action (defaults to the harness action)
 * @param {object} [o.requirement] the manifest requirement resolved for this action (findActionRequirement)
 */
export declare function runCf1({ invoke, wrongInvoke, harness, action, requirement, }?: {
    invoke?: (scenario: Obj) => Promise<Obj>;
    wrongInvoke?: (scenario: Obj) => Promise<Obj>;
    harness?: {
        mint: (args: Obj) => any;
        action?: any;
        now?: () => number;
    };
    action?: Obj;
    requirement?: {
        receipt_required?: boolean;
        assurance_class?: any;
        action_type?: any;
    };
}): Promise<{
    standard: string;
    passed: boolean;
    badge: string;
    summary: {
        passed: any;
        total: any;
    };
    eg1: {
        passed: any;
        summary: any;
    };
    checks: any;
    generated_at: string;
}>;
declare const _default: {
    CF1_VERSION: string;
    CF1_CHECKS: any;
    runCf1: typeof runCf1;
};
export default _default;
//# sourceMappingURL=cf1-conformance.d.ts.map