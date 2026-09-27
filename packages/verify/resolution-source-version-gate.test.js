// SPDX-License-Identifier: Apache-2.0
// The published -02 verifier must not silently accept a candidate -04 option.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyResolutionReceipt } from './resolution.js';

const suite = JSON.parse(readFileSync(
  new URL('../../conformance/vectors/resolution.v1.json', import.meta.url), 'utf8',
));
const approved = suite.vectors.find((vector) => vector.id === 'accept_approved');

test('unpublished option binding and profile relabel refuse under EP-RESOLUTION-v1', () => {
  assert.ok(approved);
  const vector = structuredClone(approved);
  const receipt = vector.resolution_receipt;
  const opts = {
    bindingMoment: vector.binding_moment,
    expectedActionHash: vector.expected_action_hash,
    expectedSelectedOption: vector.expected_selected_option,
    expectedNonce: vector.expected_nonce,
    expectedInitiator: vector.expected_initiator,
    evaluationTime: vector.evaluation_time,
    rpId: vector.rp_id,
    allowedOrigins: vector.allowed_origins,
    principalKeys: vector.principal_keys,
  };
  assert.equal(verifyResolutionReceipt(receipt, opts).authorizes_action, true);

  const relabeled = structuredClone(receipt);
  relabeled.profile = 'EP-RESOLUTION-BME04-CANDIDATE-v1';
  const downgrade = verifyResolutionReceipt(relabeled, opts);
  assert.equal(downgrade.valid, false);
  assert.equal(downgrade.reason, 'malformed_resolution_receipt');

  opts.bindingMoment.question.options[0].action_digest = vector.expected_action_hash;
  opts.bindingMoment.question.options[1].action_digest = `sha256:${'b'.repeat(64)}`;
  const result = verifyResolutionReceipt(receipt, opts);
  assert.equal(result.valid, false);
  assert.equal(result.authorizes_action, false);
  assert.equal(result.reason, 'malformed_binding_moment');
});
