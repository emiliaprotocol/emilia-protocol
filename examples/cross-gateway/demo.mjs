#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Cross-Gateway Evidence Lab.
 *
 * Two agent gateways in separate administrative domains enforce policy over
 * one consequential action, with one human-approval artifact between them.
 * Gateway A (the sending organization's egress) validates the evidence and
 * records its own enforcement decision. Gateway B (the receiving
 * organization's ingress, in front of the executor) verifies the SAME
 * artifact itself, under its own pinned trust anchors and its own
 * consumption ledger, and records a separate enforcement decision.
 *
 * The property under test: the artifact travels; the trust does not have to.
 * Neither gateway ingests the other's decision or log into its own trust
 * boundary, and the two audit trails join by the shared action digest, not by
 * cross-reference to each other's verdicts.
 */
import {
  createGate,
  createEg1Harness,
  hashCanonical,
} from '../../packages/gate/index.js';
import { manifestFromPack } from '../../packages/gate/adapters/_kit.js';

export const LAB_VERSION = 'EP-CROSS-GATEWAY-EVIDENCE-LAB-v1';

export const EXACT_ACTION = Object.freeze({
  action_type: 'interorg.settlement.execute',
  settlement_id: 'stl-2026-07-4411',
  amount: '2500000.00',
  currency: 'USD',
  counterparty: 'org-b.example',
});

const SELECTOR = Object.freeze({ protocol: 'interorg', tool: 'execute_settlement' });

const ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'interorg.settlement.execute',
    label: 'Cross-organization settlement execution',
    action_type: 'interorg.settlement.execute',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'quorum',
    match: { protocol: SELECTOR.protocol, tool: SELECTOR.tool },
    why: 'Moves value across an administrative boundary. Bind the exact settlement; quorum.',
    execution_binding: {
      required_fields: ['action_type', 'settlement_id', 'amount', 'currency', 'counterparty'],
    },
  }),
]);

const QUORUM = Object.freeze({
  signers: ['ep:human:treasury-officer', 'ep:human:risk-officer'],
  threshold: 2,
});

/**
 * One gateway = one gate instance: its own trust anchors, its own consumption
 * ledger, its own evidence log. `pins` is what THIS gateway trusts out of
 * band; nothing else reaches its trust boundary.
 */
function makeGateway(rpId, pins) {
  return {
    rpId,
    gate: createGate({
      manifest: manifestFromPack([...ACTION_PACK]),
      trustedKeys: [pins.issuerKey],
      approverKeys: pins.approverKeys,
      rpId,
    }),
  };
}

function decisionRecord(gatewayId, decision) {
  return {
    gateway: gatewayId,
    allow: decision.allow,
    status: decision.status,
    reason: decision.reason ?? null,
    observed_action_hash: decision.evidence?.observed_action_hash ?? null,
    receipt_id: decision.evidence?.receipt_id ?? null,
  };
}

async function gatewayACheck(gatewayA, action, receipt) {
  // Gateway A enforces at egress but is not the executor: it validates and
  // records without consuming, leaving one-time execution semantics to the
  // enforcement point that fronts the effect.
  const decision = await gatewayA.gate.check({
    selector: { ...SELECTOR },
    receipt,
    observedAction: action,
    consumptionMode: 'none',
  });
  return decisionRecord(gatewayA.rpId, decision);
}

/** Run the cross-gateway lab and return a machine-readable result. */
export async function runCrossGatewayLab() {
  // The approving humans and the issuer live in the sending organization.
  const harness = createEg1Harness({ action: EXACT_ACTION, idPrefix: 'xgw' });
  const pins = { issuerKey: harness.publicKey, approverKeys: harness.approverKeys };

  // Both organizations pinned the issuer and approver keys OUT OF BAND.
  // The gate instances share nothing: not a store, not a log, not a registry.
  const gatewayA = makeGateway('gateway-a.org-a.example', pins);
  const gatewayB = makeGateway('gateway-b.org-b.example', pins);

  const executorCalls = [];
  const executor = async () => {
    executorCalls.push(structuredClone(EXACT_ACTION));
    return { settled: true, settlement_id: EXACT_ACTION.settlement_id };
  };

  async function gatewayBExecute(action, receipt) {
    const outcome = await gatewayB.gate.run(
      { selector: { ...SELECTOR }, receipt, observedAction: action },
      executor,
    );
    return {
      record: decisionRecord(gatewayB.rpId, outcome.authorization),
      outcome,
    };
  }

  const cases = [];

  // 1. Fail-closed at the first enforcement point: no artifact, no forward.
  const aWithoutEvidence = await gatewayACheck(gatewayA, EXACT_ACTION, null);
  cases.push({
    id: 'a-refuses-without-evidence',
    title: 'Gateway A refuses to forward a consequential action with no approval artifact',
    a: aWithoutEvidence,
    b: null,
    executor_called: false,
    verdict: 'refuse',
    reason: aWithoutEvidence.reason,
  });

  // 2. The through-case: one artifact, two independent verifications, one execution.
  const artifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
  const aDecision = await gatewayACheck(gatewayA, EXACT_ACTION, artifact);
  const before = executorCalls.length;
  const { record: bDecision, outcome } = await gatewayBExecute(EXACT_ACTION, artifact);
  cases.push({
    id: 'one-artifact-two-independent-verifications',
    title: 'Gateway A validates and records; Gateway B re-verifies the same artifact under its own anchors and executes once',
    a: aDecision,
    b: bDecision,
    executor_called: executorCalls.length === before + 1,
    verdict: 'execute',
    reason: null,
    audit_join: {
      shared_action_hash: hashCanonical(EXACT_ACTION),
      a_recorded: aDecision.observed_action_hash,
      b_recorded: bDecision.observed_action_hash,
      joined_by_action_digest:
        aDecision.observed_action_hash === bDecision.observed_action_hash
        && aDecision.observed_action_hash === hashCanonical(EXACT_ACTION),
    },
    execution_binds_authorization:
      outcome.execution?.authorizes_decision === outcome.packet?.summary?.decision_hash,
  });

  // 3. A gateway's verdict is not evidence. Forwarding Gateway A's allow
  //    decision without the artifact gets refused: decisions do not travel.
  const bFromVerdictOnly = await gatewayB.gate.check({
    selector: { ...SELECTOR },
    receipt: null,
    observedAction: EXACT_ACTION,
    consumptionMode: 'none',
  });
  cases.push({
    id: 'decision-does-not-travel',
    title: 'Gateway B refuses when offered Gateway A\'s allow verdict instead of the artifact',
    a: aDecision,
    b: decisionRecord(gatewayB.rpId, bFromVerdictOnly),
    executor_called: false,
    verdict: 'refuse',
    reason: bFromVerdictOnly.reason,
    note: 'Gateway A allowed the same action minutes earlier; that verdict is not presentable evidence at Gateway B.',
  });

  // 4. Tampered in transit: A saw the honest action, B is asked to execute an
  //    altered one with the same artifact. The binding refuses by name.
  const altered = { ...EXACT_ACTION, amount: '9500000.00' };
  const freshArtifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
  const aHonest = await gatewayACheck(gatewayA, EXACT_ACTION, freshArtifact);
  const bAltered = await gatewayB.gate.check({
    selector: { ...SELECTOR },
    receipt: freshArtifact,
    observedAction: altered,
    consumptionMode: 'none',
  });
  cases.push({
    id: 'tampered-in-transit-refused-at-b',
    title: 'The amount is altered between the gateways; Gateway B refuses the mismatched action',
    a: aHonest,
    b: decisionRecord(gatewayB.rpId, bAltered),
    executor_called: false,
    verdict: 'refuse',
    reason: bAltered.reason,
  });

  // 5. Gateway A allowing is not Gateway B accepting. A misconfigured Gateway
  //    A' pins a rogue issuer; Gateway B does not. Same artifact, two anchors,
  //    two verdicts.
  const rogue = createEg1Harness({ action: EXACT_ACTION, idPrefix: 'xgw_rogue' });
  const misconfiguredA = makeGateway('gateway-a2.org-a.example', {
    issuerKey: rogue.publicKey,
    approverKeys: rogue.approverKeys,
  });
  const rogueArtifact = rogue.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
  const aRogue = await gatewayACheck(misconfiguredA, EXACT_ACTION, rogueArtifact);
  const bRogue = await gatewayB.gate.check({
    selector: { ...SELECTOR },
    receipt: rogueArtifact,
    observedAction: EXACT_ACTION,
    consumptionMode: 'none',
  });
  cases.push({
    id: 'b-does-not-inherit-a-trust',
    title: 'A gateway that pins a rogue issuer allows; Gateway B, which does not pin it, refuses the same artifact',
    a: aRogue,
    b: decisionRecord(gatewayB.rpId, bRogue),
    executor_called: false,
    verdict: 'refuse',
    reason: bRogue.reason,
    note: 'VERIFIED under one set of anchors is never ACCEPTED under another; each gateway answers for its own pins.',
  });

  // 6. Replay at the executor's gateway: the consumed artifact cannot drive a
  //    second execution.
  const beforeReplay = executorCalls.length;
  const replay = await gatewayB.gate.run(
    { selector: { ...SELECTOR }, receipt: artifact, observedAction: EXACT_ACTION },
    executor,
  );
  cases.push({
    id: 'replay-refused-at-b',
    title: 'The already-consumed artifact cannot drive a second execution at Gateway B',
    a: null,
    b: decisionRecord(gatewayB.rpId, replay.authorization),
    executor_called: executorCalls.length > beforeReplay,
    verdict: 'refuse',
    reason: replay.authorization.reason,
  });

  return {
    '@version': LAB_VERSION,
    title: 'Cross-Gateway Evidence Lab',
    scenario: 'Gateway A (org-a egress) and Gateway B (org-b ingress, fronting the executor) enforce one consequential action with one human-approval artifact.',
    action: EXACT_ACTION,
    requirement: {
      assurance_class: 'quorum',
      exact_fields: [...ACTION_PACK[0].execution_binding.required_fields],
      verifier_trust: 'each gateway pins issuer and approver keys out of band; no gateway trusts another gateway\'s verdict',
      one_time_consumption: 'local to the enforcement point that fronts the effect',
    },
    cases,
    executor_call_count: executorCalls.length,
    invariant: 'one approval artifact, independently verified at each enforcement point, executes exactly once; decisions never travel as evidence',
  };
}

function print(result) {
  const width = 76;
  console.log('\nCROSS-GATEWAY EVIDENCE LAB');
  console.log('='.repeat(width));
  console.log(`Action: ${result.action.action_type} · ${result.action.amount} ${result.action.currency} -> ${result.action.counterparty}`);
  console.log('-'.repeat(width));
  for (const [index, item] of result.cases.entries()) {
    const verdict = item.verdict === 'execute' ? 'EXECUTE' : 'REFUSE ';
    console.log(`${index + 1}. ${verdict} · ${item.id}`);
    console.log(`   ${item.title}`);
    if (item.reason) console.log(`   refusal names: ${item.reason}`);
    if (item.audit_join) console.log(`   audit records join by action digest: ${item.audit_join.joined_by_action_digest ? 'yes' : 'NO'}`);
    console.log(`   executor called: ${item.executor_called ? 'yes' : 'no'}`);
  }
  console.log('-'.repeat(width));
  console.log(`Executor call count: ${result.executor_call_count} (expected exactly 1)`);
  console.log('The artifact travels; the trust does not have to.\n');
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const result = await runCrossGatewayLab();
  if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else print(result);
}
