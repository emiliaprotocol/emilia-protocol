// SPDX-License-Identifier: Apache-2.0
// Generated from authority-program-profile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from '../packages/verify/index.js';
import { authorityProgramDigest, authorityStageReceiptDigest, verifyAuthorityProgram, } from '../packages/verify/authority-program.js';
const vector = JSON.parse(readFileSync(new URL('./vectors/authority-program.v1.json', import.meta.url), 'utf8'));
function options() {
    const rootActionHash = crypto.createHash('sha256')
        .update(canonicalize(vector.root_action), 'utf8')
        .digest();
    return {
        programPin: vector.program_pin,
        stageKeys: vector.stage_keys,
        verifyAec: ({ stage_id }) => vector.native_results.stages[stage_id]?.aec,
        verifyAom: ({ stage_id }) => vector.native_results.stages[stage_id]?.aom,
        verifyCapabilityNarrowing: ({ stage_id }) => (vector.native_results.stages[stage_id]?.capability),
        verifyParallelAllocation: ({ parallel_id }) => (vector.native_results.parallel_allocations[parallel_id]),
        verifyRootActionBinding: () => ({
            valid: true,
            root_caid: `caid:1:${vector.root_action.action_type}:jcs-sha256:${rootActionHash.toString('base64url')}`,
            root_action_digest: `sha256:${rootActionHash.toString('hex')}`,
        }),
    };
}
test('public authority-program vector verifies exact program and cross-organization stage signatures', () => {
    assert.equal(vector.status, 'public-experimental-test-vector');
    assert.equal(authorityProgramDigest(vector.program), vector.program_pin.digest);
    const result = verifyAuthorityProgram(vector.program, vector.stage_receipts, options());
    assert.equal(result.valid, true);
    assert.equal(result.execution_proven, false);
    assert.equal(result.freshness_proven, false);
    assert.equal(result.revocation_checked, false);
    assert.equal(result.root_action_binding_status, 'verified');
    assert.equal(result.parallel_allocation_status, 'verified');
    assert.deepEqual(result.stage_receipt_digests, Object.fromEntries(vector.stage_receipts
        .map((receipt) => [receipt.stage_id, authorityStageReceiptDigest(receipt)])
        .sort(([left], [right]) => left.localeCompare(right))));
});
test('public authority-program vector requires a relying-party root action binding verifier', () => {
    const withoutRootBinding = { ...options(), verifyRootActionBinding: undefined };
    const result = verifyAuthorityProgram(vector.program, vector.stage_receipts, withoutRootBinding);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'root_action_binding_unproven');
});
for (const invalidCase of vector.invalid_cases) {
    test(`public authority-program vector rejects ${invalidCase.name}`, () => {
        const receipts = structuredClone(vector.stage_receipts);
        const index = receipts.findIndex((receipt) => (receipt.stage_id === invalidCase.replace_stage_id));
        assert.notEqual(index, -1);
        receipts[index] = invalidCase.replacement_receipt;
        const result = verifyAuthorityProgram(vector.program, receipts, options());
        assert.equal(result.valid, false);
        assert.equal(result.reason, invalidCase.expected_reason);
    });
}
test('public authority-program vector cannot claim parallel conservation without native proof', () => {
    const withoutAllocation = { ...options(), verifyParallelAllocation: undefined };
    const result = verifyAuthorityProgram(vector.program, vector.stage_receipts, withoutAllocation);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'parallel_allocation_unproven');
    assert.equal(result.execution_proven, false);
});
