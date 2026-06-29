// SPDX-License-Identifier: Apache-2.0
// GG-1 reference conformance harness for GovGuard's government-fraud control
// profile. This is intentionally small and deterministic: it exercises the
// same policy, hashing, evidence, and execution-binding primitives the API
// routes use, without needing a database fixture.

import {
  GUARD_ACTION_TYPES,
  evaluateGuardPolicy,
  hashCanonicalAction,
} from './guard-policies.js';
import {
  buildExecutionBindingContract,
  verifyExecutionBindingContract,
} from './execution/binding-contract.js';
import {
  GG1_CHECKS,
  buildGovGuardEvidencePacket,
} from './govguard-evidence-packet.js';

const BASE_ACTION = Object.freeze({
  organization_id: 'org_gov',
  actor_id: 'caseworker_1',
  action_type: GUARD_ACTION_TYPES.GOV_VENDOR_PAYMENT_DESTINATION_CHANGE,
  target_resource_id: 'vendor:VEND-9821',
  vendor_id: 'VEND-9821',
  amount: 25_000,
  currency: 'USD',
  bank_account: 'hash:new-bank',
  routing_number: 'hash:new-routing',
  target_changed_fields: ['bank_account', 'routing_number'],
  policy_id: 'policy_gov_vendor_payment_destination_change_v1',
  policy_hash: 'sha256:policy',
});

function makeReceipt(overrides = {}) {
  const decision = evaluateGuardPolicy({
    organizationId: BASE_ACTION.organization_id,
    actorId: BASE_ACTION.actor_id,
    actorRole: 'ap',
    actionType: BASE_ACTION.action_type,
    targetChangedFields: BASE_ACTION.target_changed_fields,
    amount: BASE_ACTION.amount,
    currency: BASE_ACTION.currency,
    riskFlags: [],
    authStrength: 'password',
  });
  const action = { ...BASE_ACTION, ...overrides.action };
  return {
    receipt_id: overrides.receipt_id || 'tr_gg1',
    organization_id: overrides.organization_id || action.organization_id,
    initiator_id: overrides.initiator_id || action.actor_id,
    approver_id: overrides.approver_id || 'controller_1',
    action,
    action_hash: hashCanonicalAction(action),
    decision,
    execution_binding: buildExecutionBindingContract({ canonicalAction: action, decision }),
    signoff: overrides.signoff || null,
    consumed: false,
  };
}

function approve(receipt, { authenticatedApproverId, keyClass = 'A' } = {}) {
  if (!receipt) return { ok: false, status: 404, reason: 'signoff_not_found' };
  if (authenticatedApproverId === receipt.initiator_id) {
    return { ok: false, status: 403, reason: 'self_approval_forbidden' };
  }
  if (authenticatedApproverId !== receipt.approver_id) {
    return { ok: false, status: 403, reason: 'approver_mismatch' };
  }
  if (receipt.decision.requiredAssurance === 'A' && keyClass !== 'A') {
    return { ok: false, status: 403, reason: 'insufficient_assurance' };
  }
  receipt.signoff = { approver_id: authenticatedApproverId, key_class: keyClass };
  return { ok: true, status: 200, reason: 'approved' };
}

function consume(receipt, {
  organizationId = 'org_gov',
  observedAction = BASE_ACTION,
  executedAction = observedAction,
} = {}) {
  if (!receipt) return { ok: false, status: 428, reason: 'missing_receipt' };
  if (receipt.organization_id !== organizationId) {
    return { ok: false, status: 403, reason: 'wrong_org' };
  }
  if (receipt.consumed) {
    return { ok: false, status: 409, reason: 'receipt_already_consumed' };
  }
  if (receipt.decision.signoffRequired && !receipt.signoff) {
    return { ok: false, status: 403, reason: 'signoff_required' };
  }
  if (hashCanonicalAction(executedAction) !== receipt.action_hash) {
    return { ok: false, status: 409, reason: 'action_hash_mismatch' };
  }
  const binding = verifyExecutionBindingContract({
    contract: receipt.execution_binding,
    observedAction,
    executedAction,
  });
  if (!binding.ok) {
    return { ok: false, status: 409, reason: 'execution_binding_mismatch', binding };
  }
  receipt.consumed = true;
  return { ok: true, status: 200, reason: 'consumed' };
}

function pass(id, ok, observed) {
  return { id, pass: !!ok, observed };
}

export function runGovGuardGg1Reference() {
  const checks = [];

  const missing = consume(null);
  checks.push(pass('missing_receipt_refused', !missing.ok && missing.status === 428, missing));

  const wrongOrg = makeReceipt({ organization_id: 'org_attacker' });
  approve(wrongOrg, { authenticatedApproverId: 'controller_1', keyClass: 'A' });
  const wrongOrgConsume = consume(wrongOrg);
  checks.push(pass('wrong_org_refused', !wrongOrgConsume.ok && wrongOrgConsume.reason === 'wrong_org', wrongOrgConsume));

  const wrongApprover = approve(makeReceipt(), { authenticatedApproverId: 'intruder_1', keyClass: 'A' });
  checks.push(pass('wrong_approver_refused', !wrongApprover.ok && wrongApprover.reason === 'approver_mismatch', wrongApprover));

  const self = makeReceipt({ approver_id: 'caseworker_1' });
  const selfApproval = approve(self, { authenticatedApproverId: 'caseworker_1', keyClass: 'A' });
  checks.push(pass('self_approval_refused', !selfApproval.ok && selfApproval.reason === 'self_approval_forbidden', selfApproval));

  const classC = approve(makeReceipt(), { authenticatedApproverId: 'controller_1', keyClass: 'C' });
  checks.push(pass('class_c_on_class_a_refused', !classC.ok && classC.reason === 'insufficient_assurance', classC));

  const replay = makeReceipt();
  approve(replay, { authenticatedApproverId: 'controller_1', keyClass: 'A' });
  const first = consume(replay);
  const second = consume(replay);
  checks.push(pass('replay_refused', first.ok && !second.ok && second.reason === 'receipt_already_consumed', second));

  const tampered = makeReceipt();
  approve(tampered, { authenticatedApproverId: 'controller_1', keyClass: 'A' });
  const tamperedAction = { ...BASE_ACTION, bank_account: 'hash:attacker-bank' };
  const tamperedResult = consume(tampered, { observedAction: tamperedAction, executedAction: tamperedAction });
  checks.push(pass('tampered_action_refused', !tamperedResult.ok && tamperedResult.status === 409, tamperedResult));

  const mismatch = makeReceipt();
  approve(mismatch, { authenticatedApproverId: 'controller_1', keyClass: 'A' });
  const executionMismatch = consume(mismatch, {
    observedAction: { ...BASE_ACTION, target_resource_id: 'vendor:ATTACKER' },
    executedAction: BASE_ACTION,
  });
  checks.push(pass('execution_mismatch_refused', !executionMismatch.ok && executionMismatch.reason === 'execution_binding_mismatch', executionMismatch));

  const packet = buildGovGuardEvidencePacket({
    pilotId: 'pilot_gov_1',
    events: [{
      target_id: 'tr_observe',
      created_at: '2026-06-29T00:00:00.000Z',
      after_state: {
        ...BASE_ACTION,
        enforcement_mode: 'observe',
        decision: 'observe',
        observed_decision: 'allow_with_signoff',
        signoff_required: true,
        required_assurance: 'A',
        action_hash: hashCanonicalAction(BASE_ACTION),
        execution_binding: makeReceipt().execution_binding,
      },
    }],
    generatedAt: '2026-06-29T00:00:00.000Z',
  });
  checks.push(pass('observe_evidence_exported', packet.high_risk_actions.length === 1 && packet.summary.would_require_signoff === 1, {
    packet_version: packet['@version'],
    high_risk_actions: packet.high_risk_actions.length,
  }));

  const ordered = GG1_CHECKS.map((c) => {
    const result = checks.find((x) => x.id === c.id) || pass(c.id, false, { reason: 'not_run' });
    return { ...c, ...result };
  });
  return {
    standard: 'GG-1',
    passed: ordered.every((c) => c.pass),
    badge: ordered.every((c) => c.pass) ? 'GG-1 Enforced' : 'GG-1 not earned',
    summary: { passed: ordered.filter((c) => c.pass).length, total: ordered.length },
    checks: ordered,
  };
}

const govGuardGg1 = { runGovGuardGg1Reference };

export default govGuardGg1;
