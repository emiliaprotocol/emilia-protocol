// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
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
import { EG1_CHECKS, runEg1 } from './eg1-conformance.js';
export const CF1_VERSION = 'CF-1';
// The nine CF-1 checks: the declaration bookend, the eight EG-1 runtime checks,
// then the two that distinguish a firewall from an enforced gate.
export const CF1_CHECKS = Object.freeze([
    { id: 'consequential_action_declared', title: 'action declared consequential (receipt required by policy/manifest)' },
    ...EG1_CHECKS.map((c) => ({ id: c.id, title: c.title })),
    { id: 'wrong_authority_refused', title: 'gate pinned to the wrong authority cannot authorize' },
    { id: 'evidence_verifies_offline', title: 'allowed run emits reliance evidence verifiable offline' },
]);
export async function runCf1({ invoke, wrongInvoke, harness, action, requirement, } = {}) {
    if (typeof invoke !== 'function')
        throw new Error('runCf1 requires an invoke(scenario) function');
    if (!harness || typeof harness.mint !== 'function')
        throw new Error('runCf1 requires a harness from createEg1Harness()');
    const act = action || harness.action;
    // The eight EG-1 runtime checks (missing / weak-assurance / execution-drift /
    // valid-runs / replay / tamper / execution-proof / reliance-packet).
    const eg1 = await runEg1({ invoke, harness, action: act });
    const results = {};
    for (const c of eg1.checks)
        results[c.id] = { pass: c.pass, observed: c.observed };
    // consequential_action_declared — policy/manifest classifies the action as
    // requiring a receipt (not merely caught by a default-deny fallback).
    results.consequential_action_declared = {
        pass: requirement ? requirement.receipt_required === true : false,
        observed: {
            receipt_required: requirement?.receipt_required ?? null,
            assurance_class: requirement?.assurance_class ?? null,
            action_type: requirement?.action_type ?? null,
        },
    };
    // wrong_authority_refused — a gate pinned to a different key rejects a valid
    // receipt. Proves trust is pinned by the relying party, not receipt-carried.
    let wrongPass = false;
    let wrongObserved = { skipped: true };
    if (typeof wrongInvoke === 'function') {
        const rr = await wrongInvoke({ receipt: harness.mint({ outcome: 'allow_with_signoff' }), observedAction: act });
        wrongPass = rr.allowed === false;
        wrongObserved = { allowed: !!rr.allowed, status: rr.status ?? null, reason: rr.reason ?? null };
    }
    results.wrong_authority_refused = { pass: wrongPass, observed: wrongObserved };
    // evidence_verifies_offline — a fresh valid run yields a "rely" reliance
    // packet whose execution proof binds the authorization decision. A third
    // party recomputes that binding offline; no operator trust required.
    const vr = await invoke({ receipt: harness.mint({ outcome: 'allow_with_signoff' }), observedAction: act });
    const binds = !!vr.execution?.authorizes_decision && !!vr.decisionHash
        && vr.execution.authorizes_decision === vr.decisionHash;
    const offlineOk = vr.allowed === true
        && String(vr.packet?.verdict || '').toLowerCase() === 'rely'
        && binds;
    results.evidence_verifies_offline = {
        pass: offlineOk,
        observed: { allowed: !!vr.allowed, verdict: vr.packet?.verdict ?? null, binds },
    };
    const checks = CF1_CHECKS.map((c) => ({ id: c.id, title: c.title, ...results[c.id] }));
    const passedCount = checks.filter((c) => c.pass).length;
    const passed = passedCount === checks.length;
    return {
        standard: CF1_VERSION,
        passed,
        badge: passed ? 'CF-1 Enforced' : 'CF-1 not earned',
        summary: { passed: passedCount, total: checks.length },
        eg1: { passed: eg1.passed, summary: eg1.summary },
        checks,
        generated_at: new Date(harness.now ? harness.now() : Date.now()).toISOString(),
    };
}
export default { CF1_VERSION, CF1_CHECKS, runCf1 };
//# sourceMappingURL=cf1-conformance.js.map