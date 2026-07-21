// SPDX-License-Identifier: Apache-2.0
// Generated from gate.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Stateful ACTA + EP composition at an executor-controlled boundary.
import { createAECExecutionGate } from '../../packages/gate/aec-execution.js';
import { createEvidenceLog } from '../../packages/gate/evidence.js';
import { MemoryConsumptionStore } from '../../packages/gate/store.js';
import { ACTA_COMPONENT_TYPE, artifactDigest, computeActaActionRef, createActaDecisionVerifier, } from './acta-profile.mjs';
export const ACTA_EP_REQUIREMENT = `${ACTA_COMPONENT_TYPE} AND ep-receipt`;
function componentsOfType(chain, type) {
    const c = chain;
    if (!Array.isArray(c?.components))
        return [];
    return c.components.filter((component) => component?.type === type);
}
function refusingVerifier(reason) {
    return () => ({ valid: false, action_digest: null, detail: { reason } });
}
/**
 * Build a stateful executor gate whose trust configuration is fixed at
 * construction. Per request, only the executor's expected action/evaluation and
 * presenter evidence vary. The same store is reused across calls, so replay of
 * an already executed action is refused by the underlying AEC gate.
 */
export function createActaEpExecutionGate({ actaIssuerKeys, actaPolicy, epReceiptProfile, store, log, allowEphemeralState = false, now = Date.now, } = {}) {
    const consumption = store ?? new MemoryConsumptionStore();
    const evidenceLog = log ?? createEvidenceLog({ strict: true });
    const pinnedActaPolicy = actaPolicy && typeof actaPolicy === 'object'
        ? structuredClone(actaPolicy) : null;
    const pinnedActaKeys = actaIssuerKeys && typeof actaIssuerKeys === 'object'
        ? structuredClone(actaIssuerKeys) : {};
    const pinnedEpProfile = epReceiptProfile && typeof epReceiptProfile === 'object'
        ? structuredClone(epReceiptProfile) : null;
    async function run(request = {}, effect) {
        const actaComponents = componentsOfType(request.chain, ACTA_COMPONENT_TYPE);
        const epComponents = componentsOfType(request.chain, 'ep-receipt');
        const exactPair = actaComponents.length === 1 && epComponents.length === 1;
        const expectedReceiptDigest = exactPair
            ? artifactDigest(epComponents[0].evidence) : null;
        const expectedActionRef = computeActaActionRef(request.expectedActaEvaluation);
        const actaVerifier = exactPair && expectedReceiptDigest && expectedActionRef
            ? createActaDecisionVerifier({
                expectedActionRef,
                expectedHumanAuthorizationDigest: expectedReceiptDigest,
                policy: pinnedActaPolicy,
            })
            : refusingVerifier('ACTA + EP join requires exactly one component of each type and a valid relying-party evaluation');
        const gate = createAECExecutionGate({
            requirement: ACTA_EP_REQUIREMENT,
            policiesByType: { 'ep-receipt': pinnedEpProfile },
            verifiers: { [ACTA_COMPONENT_TYPE]: actaVerifier },
            keysByType: { [ACTA_COMPONENT_TYPE]: pinnedActaKeys },
            humanFloor: 'class_a',
            store: consumption,
            log: evidenceLog,
            allowEphemeralState,
            now: now,
        });
        return gate.run({
            chain: request.chain,
            expectedAction: request.expectedAction,
        }, effect);
    }
    return { run, store: consumption, evidence: evidenceLog };
}
export default { createActaEpExecutionGate, ACTA_EP_REQUIREMENT };
