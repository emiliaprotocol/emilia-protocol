// SPDX-License-Identifier: Apache-2.0
// Proof harness for the AE-CHALLENGE transport-neutral demo. Every hostile
// case from the demo must land on its exact expected outcome, and a few
// extra mutation checks make sure the evaluator's guards are load-bearing
// rather than decorative.
import assert from 'node:assert/strict';
import test from 'node:test';

import { selectAuthorizationChallengeMechanism } from '../../lib/negotiate/evidence-challenge.js';

import {
  ACTION_AUTHORIZATION_REQUIREMENT,
  ACTION_A,
  ACTION_B,
  OAUTH_EVIDENCE_FORM,
  RECEIPT_EVIDENCE_FORM,
  createRelyingParty,
  generateWorldKeys,
  issueHumanReceipt,
  runAeTransportNeutralDemo,
} from './demo.mjs';

const EITHER = ACTION_AUTHORIZATION_REQUIREMENT;

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

const ABSOLUTE_URI = /^[A-Za-z][A-Za-z0-9+.-]*:/;

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

test('AE challenge state never substitutes for the native OAuth transaction', async () => {
  const result = await runAeTransportNeutralDemo();
  const oauth = result.cases.find((item) => item.id === 'admit-oauth-evidence-for-action-a');
  assert.ok(oauth, 'OAuth composition case ran');
  assert.equal(typeof oauth.ae_challenge_id, 'string');
  assert.equal(typeof oauth.oauth_txn, 'string');
  assert.notEqual(
    oauth.ae_challenge_id,
    oauth.oauth_txn,
    'AE challenge identifiers and OAuth transaction identifiers are separate protocol state',
  );
});

test('native OAuth remains primary and AE is allowed only for an additional evidence gap', () => {
  assert.deepEqual(selectAuthorizationChallengeMechanism({
    native_transaction_authorization_required: true,
    independent_evidence_insufficient: false,
    explicit_composition_profile: false,
  }), {
    primary: 'oauth-transaction-authorization',
    ae_challenge_allowed: false,
    substitution_allowed: false,
  });

  assert.deepEqual(selectAuthorizationChallengeMechanism({
    native_transaction_authorization_required: true,
    independent_evidence_insufficient: true,
    explicit_composition_profile: true,
  }), {
    primary: 'oauth-transaction-authorization',
    ae_challenge_allowed: true,
    substitution_allowed: false,
  });
});

test('challenge replay and presenter substitution are refused before a second admission', async () => {
  const keys = generateWorldKeys();
  const rs = createRelyingParty({
    keys,
    acceptedForms: [RECEIPT_EVIDENCE_FORM],
    policyRequirement: ACTION_AUTHORIZATION_REQUIREMENT,
  });
  const receipt = await issueHumanReceipt({ keys, action: ACTION_A });
  const { challenge } = rs.challengeFor(ACTION_A);

  const wrongPresenter = rs.evaluate(challenge, {
    form: RECEIPT_EVIDENCE_FORM,
    evidence: receipt,
    presenter: 'https://client.example/other-agent',
  }, ACTION_A);
  assert.equal(wrongPresenter.outcome, 'REFUSE');
  assert.equal(wrongPresenter.reason, 'challenge_presenter_mismatch');

  const presentation = {
    form: RECEIPT_EVIDENCE_FORM,
    evidence: receipt,
    presenter: 'https://client.example/agent-client-42',
  };
  assert.equal(rs.evaluate(challenge, presentation, ACTION_A).outcome, 'ADMIT');
  const replay = rs.evaluate(challenge, presentation, ACTION_A);
  assert.equal(replay.outcome, 'REFUSE');
  assert.equal(replay.reason, 'ae_challenge_replay');
});

test('the demo emits an AE-CHALLENGE-07-shaped negotiation object', () => {
  const keys = generateWorldKeys();
  const rs = createRelyingParty({
    keys,
    acceptedForms: [OAUTH_EVIDENCE_FORM, RECEIPT_EVIDENCE_FORM],
    policyRequirement: ACTION_AUTHORIZATION_REQUIREMENT,
  });
  const { challenge } = rs.challengeFor(ACTION_A);

  assert.equal(challenge.audience, 'https://client.example/agent-client-42');
  assert.ok(challenge.required_evidence.length > 0);
  for (const requirement of challenge.required_evidence) {
    assert.match(requirement.type, ABSOLUTE_URI);
    for (const profile of requirement.profiles ?? []) assert.match(profile, ABSOLUTE_URI);
  }
  for (const profile of challenge.present_as) assert.match(profile, ABSOLUTE_URI);
  for (const hint of challenge.obtain_hints) {
    assert.deepEqual(Object.keys(hint).sort(), ['mechanism', 'requirement_id', 'uri']);
    assert.match(hint.mechanism, ABSOLUTE_URI);
    assert.match(hint.uri, ABSOLUTE_URI);
    assert.ok(challenge.required_evidence.some((requirement) => requirement.requirement_id === hint.requirement_id));
  }
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
  assert.equal(retry.effects_started, 1, 'only one provider attempt started across both calls');
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
  const result = rs.evaluate(challenge, {
    form: RECEIPT_EVIDENCE_FORM,
    evidence: {},
    presenter: 'https://client.example/agent-client-42',
  }, ACTION_A);
  assert.equal(result.outcome, 'REFUSE');
  assert.equal(result.reason, 'challenge_action_digest_mismatch');
});

test('a receipt whose signed action was tampered with after signing is refused', async () => {
  const keys = generateWorldKeys();
  const rs = createRelyingParty({
    keys,
    acceptedForms: [RECEIPT_EVIDENCE_FORM],
    policyRequirement: ACTION_AUTHORIZATION_REQUIREMENT,
  });
  const receipt = await issueHumanReceipt({ keys, action: ACTION_A });
  const tampered = structuredClone(receipt);
  tampered.action.parameters.amount = ACTION_B.parameters.amount;
  // Present the tampered receipt against a challenge for the tampered action,
  // so the failure must come from receipt verification itself (the signed
  // commitments no longer match the mutated action), not from the digest gate.
  const { challenge } = rs.challengeFor(tampered.action);
  const result = rs.evaluate(challenge, {
    form: RECEIPT_EVIDENCE_FORM,
    evidence: tampered,
    presenter: 'https://client.example/agent-client-42',
  }, tampered.action);
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
