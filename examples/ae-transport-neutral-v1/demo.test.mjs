// SPDX-License-Identifier: Apache-2.0
// Proof harness for the AE-CHALLENGE transport-neutral demo. Every hostile
// case from the demo must land on its exact expected outcome, and a few
// extra mutation checks make sure the evaluator's guards are load-bearing
// rather than decorative.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ACTION_A,
  ACTION_B,
  OAUTH_EVIDENCE_FORM,
  RECEIPT_EVIDENCE_FORM,
  createRelyingParty,
  generateWorldKeys,
  issueHumanReceipt,
  runAeTransportNeutralDemo,
} from './demo.mjs';

const EITHER = 'transaction-authorization OR human-authorization-receipt';

const EXPECTED_CASES = [
  ['admit-oauth-evidence-for-action-a', 'ADMIT'],
  ['admit-human-receipt-for-action-a', 'ADMIT'],
  ['refuse-oauth-token-for-different-action', 'REFUSE'],
  ['refuse-receipt-replay-after-consume', 'REFUSE'],
  ['refuse-evidence-for-wrong-audience', 'REFUSE'],
  ['refuse-challenge-bound-to-other-audience', 'REFUSE'],
  ['refuse-oauth-when-policy-requires-human-key', 'REFUSE'],
  ['indeterminate-when-effect-response-lost', 'INDETERMINATE'],
  ['indeterminate-blind-retry-not-reexecuted', 'INDETERMINATE'],
];

test('AE-CHALLENGE transport-neutral demo: every case lands on its expected outcome', async () => {
  const result = await runAeTransportNeutralDemo();
  const byId = new Map(result.cases.map((item) => [item.id, item]));
  assert.equal(result.cases.length, EXPECTED_CASES.length, 'no missing or extra cases');
  for (const [id, expected] of EXPECTED_CASES) {
    const found = byId.get(id);
    assert.ok(found, `case ${id} ran`);
    assert.equal(found.outcome, expected, `${id}: expected ${expected}, got ${found.outcome} (${found.reason})`);
  }
});

test('both happy paths satisfy the SAME evaluator, one per evidence form', async () => {
  const result = await runAeTransportNeutralDemo();
  const admits = result.cases.filter((item) => item.outcome === 'ADMIT');
  assert.equal(admits.length, 2);
  assert.ok(admits.some((item) => item.id.includes('oauth')), 'OAuth form admitted');
  assert.ok(admits.some((item) => item.id.includes('receipt')), 'human-key receipt form admitted');
});

test('the three outcome states stay distinct and all occur', async () => {
  const result = await runAeTransportNeutralDemo();
  const outcomes = new Set(result.cases.map((item) => item.outcome));
  assert.deepEqual([...outcomes].sort(), ['ADMIT', 'INDETERMINATE', 'REFUSE']);
});

test('a lost effect response never re-executes the effect on blind retry', async () => {
  const result = await runAeTransportNeutralDemo();
  const retry = result.cases.find((item) => item.id === 'indeterminate-blind-retry-not-reexecuted');
  assert.ok(retry);
  assert.equal(retry.effects_started, 1, 'the effect ran exactly once across both attempts');
  assert.equal(retry.outcome, 'INDETERMINATE', 'the retry is reconciliation, not admission and not refusal');
});

test('mutation checks: the action fixtures and form identifiers are what the claims rely on', () => {
  // The hostile action differs from the exact action in one material field.
  assert.notEqual(ACTION_A.parameters.amount, ACTION_B.parameters.amount);
  assert.equal(ACTION_A.action_type, ACTION_B.action_type);
  // The two evidence forms are distinct identifiers; collapsing them would
  // let the policy check in hostile case 4 pass vacuously.
  assert.notEqual(OAUTH_EVIDENCE_FORM, RECEIPT_EVIDENCE_FORM);
});

test('the action digest is rederived from the action about to execute, before any evidence is inspected', async () => {
  const keys = generateWorldKeys();
  const rs = createRelyingParty({
    keys,
    acceptedForms: [OAUTH_EVIDENCE_FORM, RECEIPT_EVIDENCE_FORM],
    policyRequirement: EITHER,
  });
  // A challenge minted for action B cannot admit action A, even before the
  // (junk) evidence is looked at: the digest comes from the server's own
  // rederivation, never from the presenter.
  const { challenge } = rs.challengeFor(ACTION_B);
  const result = rs.evaluate(challenge, { form: RECEIPT_EVIDENCE_FORM, evidence: {} }, ACTION_A);
  assert.equal(result.outcome, 'REFUSE');
  assert.equal(result.reason, 'challenge_action_digest_mismatch');
});

test('a receipt whose signed action was tampered with after signing is refused', async () => {
  const keys = generateWorldKeys();
  const rs = createRelyingParty({
    keys,
    acceptedForms: [RECEIPT_EVIDENCE_FORM],
    policyRequirement: 'human-authorization-receipt',
  });
  const receipt = await issueHumanReceipt({ keys, action: ACTION_A });
  const tampered = structuredClone(receipt);
  tampered.action.parameters.amount = ACTION_B.parameters.amount;
  // Present the tampered receipt against a challenge for the tampered action,
  // so the failure must come from receipt verification itself (the signed
  // commitments no longer match the mutated action), not from the digest gate.
  const { challenge } = rs.challengeFor(tampered.action);
  const result = rs.evaluate(challenge, { form: RECEIPT_EVIDENCE_FORM, evidence: tampered }, tampered.action);
  assert.equal(result.outcome, 'REFUSE');
  assert.match(result.reason ?? '', /^receipt_refused:/);
});

test('refusal reasons name the failing check, not a generic error', async () => {
  const result = await runAeTransportNeutralDemo();
  const reasons = Object.fromEntries(result.cases.map((item) => [item.id, item.reason]));
  assert.match(reasons['refuse-oauth-token-for-different-action'] ?? '', /caid_mismatch/);
  assert.equal(reasons['refuse-receipt-replay-after-consume'], 'authority_already_consumed');
  assert.equal(reasons['refuse-oauth-when-policy-requires-human-key'], 'evidence_form_not_accepted_by_relying_party');
  assert.equal(reasons['refuse-challenge-bound-to-other-audience'], 'challenge_audience_mismatch');
  assert.equal(reasons['indeterminate-when-effect-response-lost'], 'effect_response_lost_authority_held');
});
