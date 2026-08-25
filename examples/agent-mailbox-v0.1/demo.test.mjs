// SPDX-License-Identifier: Apache-2.0
// Generated from demo.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { runDemo } from './demo.mjs';
test('signed agent mailbox round trip persists context and gates the exact GRACE action', async () => {
    const result = await runDemo();
    assert.deepEqual(result, {
        delivery_status: 'ACCEPTED',
        delivery_receipt_verified: true,
        chime_count: 1,
        chime_contains_payload: false,
        persisted_after_restart: true,
        duplicate_status: 'DUPLICATE',
        mailbox_authorizes: false,
        before_admission: {
            ready_for_executor: false,
            reason: 'admission_verifier_required',
        },
        after_admission: {
            ready_for_executor: true,
            authority_source: 'emilia_gate',
            exact_action_bound: true,
        },
    });
});
