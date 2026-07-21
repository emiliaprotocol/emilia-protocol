// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  authorityProgramDigest,
  authorityStageReceiptDigest,
  verifyAuthorityProgram,
} from '../packages/verify/authority-program.js';

const vector = JSON.parse(readFileSync(
  new URL('./vectors/authority-program.v1.json', import.meta.url),
  'utf8',
));

function options() {
  return {
    programPin: vector.program_pin,
    stageKeys: vector.stage_keys,
    verifyAec: ({ stage_id }: Record<string, any>) => vector.native_results.stages[stage_id]?.aec,
    verifyAom: ({ stage_id }: Record<string, any>) => vector.native_results.stages[stage_id]?.aom,
    verifyCapabilityNarrowing: ({ stage_id }: Record<string, any>) => (
      vector.native_results.stages[stage_id]?.capability
    ),
    verifyParallelAllocation: ({ parallel_id }: Record<string, any>) => (
      vector.native_results.parallel_allocations[parallel_id]
    ),
  };
}

test('private authority-program vector verifies exact program and cross-organization stage signatures', () => {
  assert.equal(vector.status, 'private-prepublication-test-vector');
  assert.equal(authorityProgramDigest(vector.program), vector.program_pin.digest);

  const result = verifyAuthorityProgram(vector.program, vector.stage_receipts, options());
  assert.equal(result.valid, true);
  assert.equal(result.execution_proven, false);
  assert.equal(result.parallel_allocation_status, 'verified');
  assert.deepEqual(result.stage_receipt_digests, Object.fromEntries(
    vector.stage_receipts
      .map((receipt: Record<string, any>) => [receipt.stage_id, authorityStageReceiptDigest(receipt)])
      .sort(([left]: [string], [right]: [string]) => left.localeCompare(right)),
  ));
});

for (const invalidCase of vector.invalid_cases) {
  test(`private authority-program vector rejects ${invalidCase.name}`, () => {
    const receipts = structuredClone(vector.stage_receipts);
    const index = receipts.findIndex((receipt: Record<string, any>) => (
      receipt.stage_id === invalidCase.replace_stage_id
    ));
    assert.notEqual(index, -1);
    receipts[index] = invalidCase.replacement_receipt;
    const result = verifyAuthorityProgram(vector.program, receipts, options());
    assert.equal(result.valid, false);
    assert.equal(result.reason, invalidCase.expected_reason);
  });
}

test('private authority-program vector cannot claim parallel conservation without native proof', () => {
  const withoutAllocation = { ...options(), verifyParallelAllocation: undefined };
  const result = verifyAuthorityProgram(vector.program, vector.stage_receipts, withoutAllocation);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'parallel_allocation_unproven');
  assert.equal(result.execution_proven, false);
});
