// SPDX-License-Identifier: Apache-2.0
// Generated from action-identity.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { buildMobileActionIdentity, mobileActionFingerprint, verifyMobileActionIdentity, } from './action-identity.js';
const ACTION_REFERENCE = 'action:mobile:current:1';
const ACTION = Object.freeze({
    action_type: 'benefit.payment_destination_change',
    case_id: 'case-9482',
    destination_last4: '4401',
});
test('package metadata publishes the canactid-only release on Verify 8', () => {
    const packageJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
    assert.equal(packageJson.version, '0.4.0');
    assert.equal(packageJson.dependencies['@emilia-protocol/verify'], '8.0.0');
});
test('mobile action identity emits and validates only the current canactid scheme', () => {
    const identity = buildMobileActionIdentity({
        actionReference: ACTION_REFERENCE,
        action: ACTION,
    });
    assert.match(identity.action_caid, /^canactid:1:/);
    assert.notEqual(mobileActionFingerprint(identity.action_caid), null);
    assert.equal(verifyMobileActionIdentity({
        actionReference: ACTION_REFERENCE,
        action: ACTION,
        actionCaid: identity.action_caid,
        actionDigest: identity.action_digest,
    }).valid, true);
    const legacy = identity.action_caid.replace(/^canactid:/, 'caid:');
    assert.equal(mobileActionFingerprint(legacy), null);
    assert.equal(verifyMobileActionIdentity({
        actionReference: ACTION_REFERENCE,
        action: ACTION,
        actionCaid: legacy,
        actionDigest: identity.action_digest,
    }).valid, false);
});
