// SPDX-License-Identifier: Apache-2.0
// Real Trust Receipt + real executor signature tests for Outcome Binding.
import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { issueAuthorizationReceipt } from '../issue/index.js';
import {
  buildOutcomeAttestation,
  trustReceiptDigest,
  verifyOutcomeBinding,
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

before(async () => {
  const action = {
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
    action,
    policyHash: `sha256:${'77'.repeat(32)}`,
    approvers: ['ep:approver:alice', 'ep:approver:bob'],
    requiredApprovals: 2,
    issuedAt: ISSUED,
    expiresAt: '2026-07-19T17:00:00.000Z',
    committedAt: ISSUED,
    signers: [a.signer, b.signer],
    log: { privateKey: logPrivateKey, logKeyId: 'ep:log:test#1' },
  });
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
