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

// The natural (wide) shape of a GG-1 canonical action. Declaring BASE_ACTION
// against this type (rather than leaving it to plain inference) keeps
// Object.freeze() from narrowing every field down to its literal value —
// without it, TS infers e.g. `bank_account: "hash:new-bank"` instead of
// `bank_account: string`, and every test case below that spreads BASE_ACTION
// with a different override value fails to type-check. It's a `type` alias
// rather than an `interface` so it keeps the implicit index signature that
// lets a plain object satisfy hashCanonicalAction's Record<string, unknown>
// parameter — an `interface` reference doesn't get that same compatibility.
type GuardActionRecord = {
  organization_id: string;
  actor_id: string;
  action_type: string;
  target_resource_id: string;
  vendor_id: string;
  amount: number;
  currency: string;
  bank_account: string;
  routing_number: string;
  target_changed_fields: string[];
  policy_id: string;
  policy_hash: string;
};

const BASE_ACTION: GuardActionRecord = Object.freeze({
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

interface MakeReceiptOverrides {
  receipt_id?: string;
  organization_id?: string;
  initiator_id?: string;
  approver_id?: string;
  action?: Record<string, any>;
  signoff?: any;
}

// evaluateGuardPolicy's real return shape, reused instead of re-declaring it
// so the receipt type can never drift from what the policy engine returns.
type GuardDecision = ReturnType<typeof evaluateGuardPolicy>;

interface GuardReceipt {
  receipt_id: string;
  organization_id: string;
  initiator_id: string;
  approver_id: string;
  action: GuardActionRecord;
  action_hash: string;
  decision: GuardDecision;
  execution_binding: ReturnType<typeof buildExecutionBindingContract>;
  // Left as `any`: the original JSDoc for this field was `signoff?: any`
  // and callers (approve()) legitimately build ad hoc signoff shapes.
  signoff: any;
  consumed: boolean;
}

function makeReceipt(overrides: MakeReceiptOverrides = {}): GuardReceipt {
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
    execution_binding: buildExecutionBindingContract(/** @type {any} */ ({ canonicalAction: action, decision })),
    signoff: overrides.signoff || null,
    consumed: false,
  };
}

function approve(
  receipt: GuardReceipt,
  { authenticatedApproverId, keyClass = 'A' }: { authenticatedApproverId?: string; keyClass?: string } = {},
) {
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

function consume(
  receipt: GuardReceipt | null,
  {
    organizationId = 'org_gov',
    observedAction = BASE_ACTION,
    executedAction = observedAction,
  }: {
    organizationId?: string;
    observedAction?: Record<string, any>;
    executedAction?: Record<string, any>;
  } = {},
) {
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

interface GuardCheckResult {
  id: string;
  pass: boolean;
  observed: unknown;
}

function pass(id: string, ok: boolean, observed: unknown): GuardCheckResult {
  return { id, pass: !!ok, observed };
}

export function runGovGuardGg1Reference() {
  const checks: GuardCheckResult[] = [];

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
  } as any);
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
