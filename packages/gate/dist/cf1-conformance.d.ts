/**
 * CF-1 Consequence Firewall Conformance — the category badge above EG-1.
 *
 * EG-1 answers "does this integration ENFORCE the gate?" (eight runtime checks).
 * CF-1 answers the category question "is this a Consequence Firewall?" — EG-1's
 * eight checks PLUS the three that make the category claim honest:
 *
 *   - consequential_action_declared: the action is declared high-risk /
 *     receipt-required by policy or manifest, not gated only by default-deny.
 *   - wrong_authority_refused: a gate pinned to the WRONG issuer key cannot be
 *     talked into authorizing — trust is pinned by the relying party, never
 *     taken from the receipt-carried signer.
 *   - evidence_verifies_offline: an allowed run emits a reliance packet a third
 *     party can verify offline (verdict "rely" + the execution proof binds the
 *     authorization decision, recomputable without trusting the operator).
 *
 * Pure module: composes eg1-conformance.js only (no import of index.js, so no
 * cycle). `runCf1` is param-driven (an `invoke` for the gate under test, a
 * `wrongInvoke` for a sibling gate pinned to the wrong key, the harness, and the
 * resolved manifest requirement). `cf1Conformance` / `cf1ConformanceSelfTest`
 * in index.js wire real gates to it.
 */
import { runEg1 } from './eg1-conformance.js';
type Obj = Record<string, any>;
export declare const CF1_VERSION = "CF-1";
export declare const CF1_CHECKS: readonly {
    id: string;
    title: string;
}[];
/**
 * Drive a subject through the CF-1 checks and return a JSON report.
 * @param {object} [o]
 * @param {(scenario:object)=>Promise<object>} [o.invoke]   the gate under test
 * @param {(scenario:object)=>Promise<object>} [o.wrongInvoke] a sibling gate pinned to a DIFFERENT (wrong) issuer key
 * @param {object} [o.harness]      from createEg1Harness()
 * @param {object} [o.action]     the high-risk action (defaults to the harness action)
 * @param {object} [o.requirement] the manifest requirement resolved for this action (findActionRequirement)
 */
type Eg1Invoke = NonNullable<Parameters<typeof runEg1>[0]>['invoke'];
type Eg1Harness = NonNullable<Parameters<typeof runEg1>[0]>['harness'];
export declare function runCf1({ invoke, wrongInvoke, harness, action, requirement, }?: {
    invoke?: Eg1Invoke;
    wrongInvoke?: Eg1Invoke;
    harness?: Eg1Harness;
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
        passed: number;
        total: number;
    };
    eg1: {
        passed: boolean;
        summary: {
            passed: number;
            total: number;
        };
    };
    checks: {
        pass: boolean;
        observed: Obj;
        id: string;
        title: string;
    }[];
    generated_at: string;
}>;
declare const _default: {
    CF1_VERSION: string;
    CF1_CHECKS: readonly {
        id: string;
        title: string;
    }[];
    runCf1: typeof runCf1;
};
export default _default;
//# sourceMappingURL=cf1-conformance.d.ts.map