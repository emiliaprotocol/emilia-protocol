// SPDX-License-Identifier: Apache-2.0
// Real Trust Receipt + real executor signature tests for Outcome Binding.
import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { issueAuthorizationReceipt } from '../issue/index.js';
import {
  buildOutcomeAttestation,
  buildOutcomeObservation,
  OUTCOME_BINDING_RESULT_VERSION,
  outcomeBindingResultCore,
  outcomeBindingResultDigest,
  trustReceiptDigest,
  verifyOutcomeBinding,
  verifyOutcomeBindingSet,
  verifyOutcomeBindingResultDigest,
  verifyOutcomeObservationSet,
} from './index.js';
import {
  evaluatePredictedEffects,
  isDecimalString,
  predictedEffectsDigest,
  validatePredictedEffects,
} from './effect-predicates.js';

function keyFromByte(byte) {
  const seed = Buffer.alloc(32, byte);
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
const publicKey = (privateKey) => crypto.createPublicKey(privateKey)
  .export({ type: 'spki', format: 'der' }).toString('base64url');

const approverA = keyFromByte(0x51);
const approverB = keyFromByte(0x52);
const logPrivateKey = keyFromByte(0x53);
const executorPrivateKey = keyFromByte(0x54);
const executorPublicKey = publicKey(executorPrivateKey);
const meterPrivateKey = keyFromByte(0x55);
const meterPublicKey = publicKey(meterPrivateKey);
const ISSUED = '2026-07-19T16:00:00.000Z';
const EXECUTED = '2026-07-19T16:01:00.000Z';
const NOW = '2026-07-19T16:02:00.000Z';
const SIGNED_PREDICTIONS = [
  { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '10.00' } },
];

function signer(privateKey, approverKeyId, approverId) {
  return {
    keyEntry: {
      approver_id: approverId,
      public_key: publicKey(privateKey),
      key_class: 'B',
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_to: '2027-01-01T00:00:00.000Z',
    },
    signer: {
      approverKeyId,
      keyClass: 'B',
      signedAt: ISSUED,
      sign: (bytes) => crypto.sign(null, bytes, privateKey).toString('base64url'),
    },
  };
}

const a = signer(approverA, 'ep:key:approver-a#1', 'ep:approver:alice');
const b = signer(approverB, 'ep:key:approver-b#1', 'ep:approver:bob');
const receiptOptions = {
  approverKeys: {
    'ep:key:approver-a#1': a.keyEntry,
    'ep:key:approver-b#1': b.keyEntry,
  },
  logPublicKey: publicKey(logPrivateKey),
};
const executorKeys = {
  'ep:executor:payments-1': { public_key: executorPublicKey },
};

let receipt;
let multiSourceReceipt;

before(async () => {
  const multiSourceAction = {
    ep_version: '1.0',
    action_type: 'payment.release',
    target: { system: 'treasury.example', resource: 'payment/991' },
    parameters: { amount: '10.00', currency: 'USD' },
    initiator: 'ep:entity:agent-7',
    policy_id: 'ep:policy:payment@v1',
    requested_at: ISSUED,
    predicted_effects: SIGNED_PREDICTIONS,
    predicted_effects_digest: predictedEffectsDigest(SIGNED_PREDICTIONS),
  };
  receipt = await issueAuthorizationReceipt({
    receiptId: 'ep:receipt:outcome-1',
    action: multiSourceAction,
    policyHash: `sha256:${'77'.repeat(32)}`,
    approvers: ['ep:approver:alice', 'ep:approver:bob'],
    requiredApprovals: 2,
    issuedAt: ISSUED,
    expiresAt: '2026-07-19T17:00:00.000Z',
    committedAt: ISSUED,
    signers: [a.signer, b.signer],
    log: { privateKey: logPrivateKey, logKeyId: 'ep:log:test#1' },
  });
  const predictions = [
    {
      effect_type: 'controller_status',
      target: 'controller:plant-7',
      required_source_role: 'executor',
      required_source_class: 'cosa.actuator',
      predicate: { op: 'eq', value: 'accepted' },
    },
    {
      effect_type: 'delivered_mw',
      target: 'meter:plant-7',
      required_source_role: 'independent_observer',
      required_source_class: 'revenue_meter',
      predicate: { op: 'gte', value: '5.0' },
    },
  ];
  const action = {
    ep_version: '1.0',
    action_type: 'grid.curtail',
    action_caid: `caid:sha256:${'66'.repeat(32)}`,
    target: { system: 'plant.example', resource: 'plant/7' },
    parameters: { requested_mw: '5.0' },
    initiator: 'ep:entity:agent-7',
    policy_id: 'ep:policy:grid@v1',
    requested_at: ISSUED,
    predicted_effects: predictions,
    predicted_effects_digest: predictedEffectsDigest(predictions),
  };
  multiSourceReceipt = await issueAuthorizationReceipt({
    receiptId: 'ep:receipt:outcome-multi-source-1',
    action,
    policyHash: `sha256:${'88'.repeat(32)}`,
    approvers: ['ep:approver:alice', 'ep:approver:bob'],
    requiredApprovals: 2,
    issuedAt: ISSUED,
    expiresAt: '2026-07-19T17:00:00.000Z',
    committedAt: ISSUED,
    signers: [a.signer, b.signer],
    log: { privateKey: logPrivateKey, logKeyId: 'ep:log:test#1' },
  });
});

const sourceKeys = {
  'ep:executor:grid-1': {
    public_key: executorPublicKey,
    role: 'executor',
    source_class: 'cosa.actuator',
    facility_id: 'facility:plant-7',
    control_domain_id: 'operator:grid-plant-7',
    status: 'active',
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_to: '2027-01-01T00:00:00.000Z',
  },
  'ep:observer:meter-7': {
    public_key: meterPublicKey,
    role: 'independent_observer',
    source_class: 'revenue_meter',
    facility_id: 'facility:plant-7',
    control_domain_id: 'operator:revenue-meter-7',
    status: 'active',
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_to: '2027-01-01T00:00:00.000Z',
  },
};

function observation(source, observed_effects, privateKey = executorPrivateKey) {
  return buildOutcomeObservation({
    receipt_id: multiSourceReceipt.receipt_id,
    receipt_digest: trustReceiptDigest(multiSourceReceipt),
    action_hash: multiSourceReceipt.action_hash,
    action_caid: multiSourceReceipt.action.action_caid,
    consumption_nonce: multiSourceReceipt.consumption.nonce,
    operation_id: 'op:grid:plant-7:991',
    source,
    observed_from: EXECUTED,
    observed_until: '2026-07-19T16:01:30.000Z',
    attested_at: '2026-07-19T16:01:45.000Z',
    observed_effects,
    signer: { privateKey },
  });
}

function multiSourceObservations(meterValue = '5.2') {
  return [
    observation(
      {
        role: 'executor', source_id: 'ep:executor:grid-1',
        source_class: 'cosa.actuator', facility_id: 'facility:plant-7',
      },
      [{ effect_type: 'controller_status', target: 'controller:plant-7', value: 'accepted' }],
    ),
    observation(
      {
        role: 'independent_observer', source_id: 'ep:observer:meter-7',
        source_class: 'revenue_meter', facility_id: 'facility:plant-7',
      },
      [{ effect_type: 'delivered_mw', target: 'meter:plant-7', value: meterValue }],
      meterPrivateKey,
    ),
  ];
}

const verifySet = (observations, extra = {}) => verifyOutcomeBindingSet(multiSourceReceipt, observations, {
  receiptOptions,
  sourceKeys,
  now: NOW,
  expectedActionCaid: multiSourceReceipt?.action?.action_caid,
  expectedOperationId: 'op:grid:plant-7:991',
  expectedFacilityId: 'facility:plant-7',
  ...extra,
});

test('reconciles executor and independently signed meter observations', () => {
  const result = verifySet(multiSourceObservations());
  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(result.lifecycle_state, 'reconciled');
  assert.equal(result.outcome, 'in_bounds');
  assert.equal(result.observation_set.evaluations.length, 2);
});

test('missing required independent observation is indeterminate, not incomparable', () => {
  const result = verifySet(multiSourceObservations().slice(0, 1));
  assert.equal(result.valid, false);
  assert.equal(result.lifecycle_state, 'indeterminate');
  assert.equal(result.outcome, null);
  assert.ok(result.errors.some((error) => error.includes('required_outcome_source_missing:independent_observer')));
});

test('independent physical divergence defeats an executor pass', () => {
  const result = verifySet(multiSourceObservations('3.1'));
  assert.equal(result.valid, false);
  assert.equal(result.lifecycle_state, 'reconciled');
  assert.equal(result.outcome, 'divergent');
});

test('one Ed25519 key cannot fill executor and independent-observer roles', () => {
  const hostile = multiSourceObservations();
  hostile[1] = observation(
    {
      role: 'independent_observer', source_id: 'ep:observer:meter-7',
      source_class: 'revenue_meter', facility_id: 'facility:plant-7',
    },
    [{ effect_type: 'delivered_mw', target: 'meter:plant-7', value: '5.2' }],
    executorPrivateKey,
  );
  const result = verifySet(hostile, {
    sourceKeys: {
      ...sourceKeys,
      'ep:observer:meter-7': {
        ...sourceKeys['ep:observer:meter-7'],
        public_key: executorPublicKey,
      },
    },
  });
  assert.equal(result.valid, false);
  assert.equal(result.lifecycle_state, 'indeterminate');
  assert.match(result.errors.join(' '), /independent_source_key_reused/);
});

test('different keys in one control domain do not establish independence', () => {
  const result = verifySet(multiSourceObservations(), {
    sourceKeys: {
      ...sourceKeys,
      'ep:observer:meter-7': {
        ...sourceKeys['ep:observer:meter-7'],
        control_domain_id: sourceKeys['ep:executor:grid-1'].control_domain_id,
      },
    },
  });
  assert.equal(result.valid, false);
  assert.equal(result.lifecycle_state, 'indeterminate');
  assert.match(result.errors.join(' '), /independent_control_domain_reused/);
});

test('compromised and expired source keys fail at the attestation instant', () => {
  const compromised = verifySet(multiSourceObservations(), {
    sourceKeys: {
      ...sourceKeys,
      'ep:observer:meter-7': {
        ...sourceKeys['ep:observer:meter-7'],
        status: 'compromised',
        compromised_at: '2026-07-19T16:01:40.000Z',
      },
    },
  });
  assert.equal(compromised.valid, false);
  assert.match(compromised.errors.join(' '), /outcome_source_key_not_current/);

  const expired = verifySet(multiSourceObservations(), {
    sourceKeys: {
      ...sourceKeys,
      'ep:observer:meter-7': {
        ...sourceKeys['ep:observer:meter-7'],
        valid_to: '2026-07-19T16:01:44.000Z',
      },
    },
  });
  assert.equal(expired.valid, false);
  assert.match(expired.errors.join(' '), /outcome_source_key_not_current/);
});

test('relying-party observation windows and attestation delay are enforced', () => {
  const wrongWindow = verifySet(multiSourceObservations(), {
    observationWindows: [{
      role: 'independent_observer', source_class: 'revenue_meter', relation: 'exact',
      not_before: EXECUTED, not_after: '2026-07-19T16:02:00.000Z',
      max_attestation_delay_ms: 30_000,
    }],
  });
  assert.equal(wrongWindow.valid, false);
  assert.match(wrongWindow.errors.join(' '), /outcome_observation_window_mismatch/);

  const stale = verifySet(multiSourceObservations(), {
    observationWindows: [{
      role: 'independent_observer', source_class: 'revenue_meter', relation: 'within',
      not_before: EXECUTED, not_after: '2026-07-19T16:02:00.000Z',
      max_attestation_delay_ms: 10_000,
    }],
  });
  assert.equal(stale.valid, false);
  assert.match(stale.errors.join(' '), /outcome_observation_attestation_stale/);
});

test('a relying party can require a distinct-source quorum', () => {
  const result = verifySet(multiSourceObservations(), {
    sourceRequirements: [{
      role: 'independent_observer', source_class: 'revenue_meter',
      min_distinct_sources: 2, distinct_by: ['key', 'control_domain'],
    }],
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join(' '), /outcome_source_quorum_not_met/);
});

test('source substitution and exact operation binding fail closed', () => {
  const substituted = multiSourceObservations();
  substituted[1].source.source_id = 'ep:observer:attacker';
  assert.equal(verifySet(substituted).lifecycle_state, 'indeterminate');

  const wrongOperation = multiSourceObservations();
  wrongOperation[1].operation_id = 'op:grid:other';
  assert.equal(verifySet(wrongOperation).lifecycle_state, 'indeterminate');
});

function attestation(observed_effects = [
  { effect_type: 'payment', target: 'acct:vendor-9', value: '9.00' },
]) {
  return buildOutcomeAttestation({
    receipt_id: receipt.receipt_id,
    receipt_digest: trustReceiptDigest(receipt),
    action_hash: receipt.action_hash,
    consumption_nonce: receipt.consumption.nonce,
    execution_id: 'ep:execution:991',
    executor_id: 'ep:executor:payments-1',
    executed_at: EXECUTED,
    observed_effects,
    signer: { privateKey: executorPrivateKey },
  });
}

const verify = (att, extra = {}) => verifyOutcomeBinding(receipt, att, {
  receiptOptions,
  executorKeys,
  now: NOW,
  ...extra,
});

test('decimal parsing stays linear on a long zero run with a nonzero tail', () => {
  const adversarialDecimal = `0.${'0'.repeat(100_000)}1`;
  const startedAt = performance.now();

  assert.equal(isDecimalString(adversarialDecimal), true);

  const elapsedMs = performance.now() - startedAt;
  assert.ok(
    elapsedMs < 750,
    `decimal parsing took ${elapsedMs.toFixed(1)}ms; expected linear-time handling below 750ms`,
  );
});

test('accepts real signed receipt + pinned executor attestation + in-bounds outcome', () => {
  const result = verify(attestation());
  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(result.outcome_binding.outcome, 'in_bounds');
  assert.ok(Object.values(result.checks).every(Boolean));
  assert.match(result.result_digest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(result.commitments, {
    receipt_id: receipt.receipt_id,
    attested_receipt_id: receipt.receipt_id,
    receipt_digest: trustReceiptDigest(receipt),
    attested_receipt_digest: trustReceiptDigest(receipt),
    action_hash: receipt.action_hash,
    attested_action_hash: receipt.action_hash,
    consumption_nonce: receipt.consumption.nonce,
    attested_consumption_nonce: receipt.consumption.nonce,
    execution_id: 'ep:execution:991',
    executor_id: 'ep:executor:payments-1',
    executor_key_id: result.attestation.proof.key_id,
    observed_effects_digest: result.attestation.observed_effects_digest,
  });
  assert.deepEqual(result.receipt, receipt);
  assert.deepEqual(result.attestation, attestation());
});

test('publishes a deterministic canonical result core and verifies its digest', () => {
  const result = verify(attestation());
  const reordered = structuredClone(result);
  reordered.checks = Object.fromEntries(Object.entries(reordered.checks).reverse());

  assert.deepEqual(outcomeBindingResultCore(result), {
    '@version': OUTCOME_BINDING_RESULT_VERSION,
    input_commitments: result.input_commitments,
    exact_commitments: result.commitments,
    valid: result.valid,
    verdict: result.outcome_binding.outcome,
    checks: result.checks,
    errors: result.errors,
    outcome_binding: result.outcome_binding,
  });
  assert.equal(outcomeBindingResultDigest(result), result.result_digest);
  assert.deepEqual(
    outcomeBindingResultCore(outcomeBindingResultCore(result)),
    outcomeBindingResultCore(result),
  );
  assert.equal(outcomeBindingResultDigest(outcomeBindingResultCore(result)), result.result_digest);
  assert.equal(outcomeBindingResultDigest(reordered), result.result_digest);
  assert.equal(verifyOutcomeBindingResultDigest(result), true);
  assert.equal(verifyOutcomeBindingResultDigest(result, result.result_digest), true);
});

test('signed human prediction is always evaluated and divergence refuses', () => {
  const result = verify(attestation([
    { effect_type: 'payment', target: 'acct:vendor-9', value: '11.00' },
  ]));
  assert.equal(result.valid, false);
  assert.equal(result.outcome_binding.outcome, 'divergent');
  assert.match(result.outcome_binding.reasons.join(' '), /signed_receipt/);
});

test('relying-party policy can tighten but cannot replace or loosen signed intent', () => {
  const observed = attestation([
    { effect_type: 'payment', target: 'acct:vendor-9', value: '500.00' },
  ]);
  const result = verify(observed, {
    policyPredictedEffects: [
      { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '1000.00' } },
    ],
  });
  assert.equal(result.valid, false);
  assert.equal(result.outcome_binding.outcome, 'divergent');
  assert.equal(result.outcome_binding.evaluations[0].source, 'signed_receipt');
  assert.equal(result.outcome_binding.evaluations[0].outcome, 'divergent');
  assert.equal(result.outcome_binding.evaluations[1].outcome, 'in_bounds');
  assert.equal(verifyOutcomeBindingResultDigest(result), true);
});

test('policy tightening adds a second independent refusal', () => {
  const result = verify(attestation(), {
    policyPredictedEffects: [
      { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '5.00' } },
    ],
  });
  assert.equal(result.valid, false);
  assert.equal(result.outcome_binding.outcome, 'divergent');
  assert.equal(result.outcome_binding.evaluations[0].outcome, 'in_bounds');
  assert.equal(result.outcome_binding.evaluations[1].outcome, 'divergent');
});

test('a supplied non-array policy prediction is a fail-closed refusal', () => {
  const result = verify(attestation(), { policyPredictedEffects: { allow: true } });
  assert.equal(result.valid, false);
  assert.match(result.errors.join(' '), /policy_predictions_present_but_not_array/);
  assert.equal(result.receipt_result.valid, true);
  assert.equal(result.attestation_result, null);
  assert.deepEqual(result.receipt, receipt);
  assert.deepEqual(result.attestation, attestation());
});

test('a supplied policy array with malformed predicates fails before attestation credit', () => {
  const result = verify(attestation(), {
    policyPredictedEffects: [{
      effect_type: 'payment',
      target: 'acct:vendor-9',
      predicate: { op: 'lte', value: '10.00', ignored_tolerance: '999.00' },
    }],
  });
  assert.equal(result.valid, false);
  assert.match(result.errors.join(' '), /policy_predictions_malformed/);
  assert.match(result.errors.join(' '), /unknown member/);
  assert.equal(result.receipt_result.valid, true);
  assert.equal(result.attestation_result, null);
});

test('malformed verifier options fail closed instead of throwing', () => {
  const result = verifyOutcomeBinding(receipt, attestation(), null);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(' '), /receipt_verification_failed/);
});

test('result_digest binds the exact signed attestation, not only the verdict', () => {
  const first = verify(attestation([
    { effect_type: 'payment', target: 'acct:vendor-9', value: '11.00' },
  ]));
  const second = verify(attestation([
    { effect_type: 'payment', target: 'acct:vendor-9', value: '12.00' },
  ]));
  assert.equal(first.outcome_binding.outcome, 'divergent');
  assert.equal(second.outcome_binding.outcome, 'divergent');
  assert.notEqual(first.result_digest, second.result_digest);
});

test('result digest verification rejects a verdict-only replay with the old digest', () => {
  const replay = structuredClone(verify(attestation()));
  const originalDigest = replay.result_digest;
  const replayedCore = outcomeBindingResultCore(replay);

  replay.outcome_binding.outcome = 'divergent';
  replayedCore.verdict = 'divergent';

  assert.equal(replay.valid, true);
  assert.equal(replay.result_digest, originalDigest);
  assert.equal(verifyOutcomeBindingResultDigest(replay), false);
  assert.equal(verifyOutcomeBindingResultDigest(replayedCore, originalDigest), false);
});

test('result digest commits each verdict-relevant result-core component independently', () => {
  const base = verify(attestation());
  const hostileMutations = [
    ['input commitment', (value) => {
      value.input_commitments.attestation_digest = `sha256:${'11'.repeat(32)}`;
    }],
    ['exact binding', (value) => {
      value.commitments.action_hash = `sha256:${'22'.repeat(32)}`;
    }],
    ['acceptance bit', (value) => {
      value.valid = false;
    }],
    ['verification check', (value) => {
      value.checks.action_bound = false;
    }],
    ['refusal reason', (value) => {
      value.errors.push('hostile_reason');
    }],
    ['evaluation', (value) => {
      value.outcome_binding.evaluations[0].outcome = 'divergent';
    }],
  ];

  for (const [target, mutate] of hostileMutations) {
    const hostile = structuredClone(base);
    mutate(hostile);
    assert.equal(
      verifyOutcomeBindingResultDigest(hostile),
      false,
      `${target} mutation retained the old result digest`,
    );
  }
});

test('result digest verification fails closed on malformed claims', () => {
  const result = verify(attestation());
  assert.equal(verifyOutcomeBindingResultDigest(result, null), false);
  assert.equal(verifyOutcomeBindingResultDigest(result, 'sha256:not-a-digest'), false);
  assert.equal(verifyOutcomeBindingResultDigest(null), false);
});

test('the exported evaluator refuses unknown observed-effect members', () => {
  const result = evaluatePredictedEffects(SIGNED_PREDICTIONS, [{
    effect_type: 'payment',
    target: 'acct:vendor-9',
    value: '9.00',
    ignored_limit: '999999.00',
  }]);
  assert.equal(result.outcome, 'incomparable');
  assert.match(result.reasons.join(' '), /unknown member/);
});

for (const [name, mutate, reason] of [
  ['receipt swap', (value) => { value.receipt_id = 'ep:receipt:other'; }, 'receipt_id_mismatch'],
  ['receipt-byte swap', (value) => { value.receipt_digest = `sha256:${'bb'.repeat(32)}`; }, 'receipt_digest_mismatch'],
  ['action swap', (value) => { value.action_hash = `sha256:${'aa'.repeat(32)}`; }, 'action_hash_mismatch'],
  ['consumption swap', (value) => { value.consumption_nonce = 'other-nonce'; }, 'consumption_nonce_mismatch'],
]) {
  test(`rejects ${name} even after attacker re-signs the attestation`, () => {
    const base = attestation();
    const body = { ...base, proof: undefined };
    delete body.proof;
    mutate(body);
    const resigned = buildOutcomeAttestation({
      ...body,
      signer: { privateKey: executorPrivateKey },
    });
    const result = verify(resigned);
    assert.equal(result.valid, false);
    assert.match(result.errors.join(' '), new RegExp(reason));
    assert.equal(
      verifyOutcomeBindingResultDigest(result),
      true,
      'digest integrity must not be confused with successful exact-binding verification',
    );
  });
}

test('rejects tampered observations and an unpinned executor', () => {
  const tampered = attestation();
  tampered.observed_effects[0].value = '0.01';
  assert.equal(verify(tampered).valid, false);
  const unpinned = verify(attestation(), { executorKeys: {} });
  assert.equal(unpinned.valid, false);
  assert.match(unpinned.errors.join(' '), /executor_key_not_pinned/);
});

test('rejects presenter prediction fields in the exact attestation schema', () => {
  const hostile = { ...attestation(), predicted_effects: SIGNED_PREDICTIONS };
  const result = verify(hostile);
  assert.equal(result.valid, false);
  assert.match(result.errors.join(' '), /malformed_outcome_attestation/);
});

test('literal-target profile refuses wildcard intent instead of pretending to match it', () => {
  const wildcard = [
    { effect_type: 'account_close', target: 'acct:*', predicate: { op: 'absent' } },
  ];
  assert.equal(validatePredictedEffects(wildcard).ok, false);
  assert.throws(() => predictedEffectsDigest(wildcard) && buildOutcomeAttestation({
    receipt_id: receipt.receipt_id,
    receipt_digest: trustReceiptDigest(receipt),
    action_hash: receipt.action_hash,
    consumption_nonce: receipt.consumption.nonce,
    execution_id: 'ep:execution:wildcard',
    executor_id: 'ep:executor:payments-1',
    executed_at: EXECUTED,
    observed_effects: [{ effect_type: 'account_close', target: 'acct:*', value: 'acct:vendor-9' }],
    signer: { privateKey: executorPrivateKey },
  }), /literal identifier/);
});

test('resource limits refuse oversized predictions and observations', () => {
  const tooManyPredictions = Array.from({ length: 65 }, (_, index) => ({
    effect_type: 'payment',
    target: `acct:vendor-${index}`,
    predicate: { op: 'absent' },
  }));
  assert.equal(validatePredictedEffects(tooManyPredictions).ok, false);
  const oversizedValue = 'x'.repeat(513);
  assert.throws(() => attestation([
    { effect_type: 'payment', target: 'acct:vendor-9', value: oversizedValue },
  ]), /bounded string/);
  assert.throws(() => attestation(Array.from({ length: 257 }, () => ({
    effect_type: 'payment',
    target: 'acct:vendor-9',
    value: '1.00',
  }))), /256-entry limit/);
});

test('serialized real-crypto independent-verification suite exercises the full protocol', () => {
  const suite = JSON.parse(readFileSync(
    new URL('../../conformance/vectors/outcome-binding.exec.v1.json', import.meta.url),
    'utf8',
  ));
  assert.equal(suite.count, 10);
  for (const vector of suite.vectors) {
    const options = {
      receiptOptions: suite.common.receipt_options,
      executorKeys: Object.hasOwn(vector, 'executor_keys')
        ? vector.executor_keys
        : suite.common.executor_keys,
      now: suite.common.now,
      ...(Object.hasOwn(vector, 'policy_predicted_effects')
        ? { policyPredictedEffects: vector.policy_predicted_effects }
        : {}),
    };
    const result = verifyOutcomeBinding(suite.common.receipt, vector.attestation, options);
    assert.equal(result.valid, vector.expect.outcome === 'in_bounds', vector.id);
    assert.equal(result.outcome_binding.outcome, vector.expect.outcome, vector.id);
  }
});

test('serialized source-policy vectors exercise independence, freshness, windows, and quorum', () => {
  const suite = JSON.parse(readFileSync(
    new URL('../../conformance/vectors/outcome-binding.sources.v1.json', import.meta.url),
    'utf8',
  ));
  assert.equal(suite.count, 8);
  for (const vector of suite.vectors) {
    const result = verifyOutcomeObservationSet(
      suite.common.predicted_effects,
      vector.observations,
      {
        ...suite.common.options,
        ...(vector.options_override || {}),
      },
    );
    assert.equal(result.valid, vector.expect.valid, vector.id);
    assert.equal(result.lifecycle_state, vector.expect.lifecycle_state, vector.id);
    assert.equal(result.outcome, vector.expect.outcome, vector.id);
    assert.equal(result.result_digest, vector.expect.result_digest, vector.id);
  }
});
