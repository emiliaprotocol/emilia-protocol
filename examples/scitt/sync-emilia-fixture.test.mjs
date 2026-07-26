// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { runVectors } from './sync-emilia-fixture.mjs';

test('SYNC production profile reproduces the supplied positive signature', () => {
  const { results, positive } = runVectors();
  assert.equal(positive.status, 'PASS', positive.detail);
  assert.deepEqual(positive.createdAtResolution.matches, ['2026-07-25T08:42:52Z']);
  assert.equal(positive.createdAtResolution.selected, '2026-07-25T08:42:52Z');
  assert.equal(results.find((item) => item.id.endsWith('-positive')).actual, 'PASS');
});

test('SYNC content mutation is refused without relying on OpenVerifier', () => {
  const { results, contentMutation } = runVectors();
  assert.equal(contentMutation.status, 'REFUSE', contentMutation.detail);
  assert.equal(results.find((item) => item.id.endsWith('-content-mutation')).actual, 'REFUSE');
});

test('SYNC forged public key is refused while the original signature is retained', () => {
  const { results, forgedKey } = runVectors();
  assert.equal(forgedKey.status, 'REFUSE', forgedKey.detail);
  assert.equal(results.find((item) => item.id.endsWith('-forged-key')).actual, 'REFUSE');
});

test('missing SYNC chain context remains indeterminate', () => {
  const { results } = runVectors();
  assert.equal(results.find((item) => item.id.endsWith('-missing-chain-context')).actual, 'INDETERMINATE');
});
