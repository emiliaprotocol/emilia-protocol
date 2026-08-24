// SPDX-License-Identifier: Apache-2.0
// Generated from aadp-authorization-artifact.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { AADP_AUTHORIZATION_ARTIFACT_VERSION, AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE, deriveAadpEpAuthorizationArtifact, matchAadpAuthorizationArtifact, parseAadpAuthorizationArtifact, verifyAadpEpAuthorizationArtifact, } from './dist/aadp-authorization-artifact.js';
import { digestAeb } from './dist/aeb-adapter-contract.js';
const vectors = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/authorization-bundle.v1.json', import.meta.url), 'utf8'));
const fixture = vectors.cases.find((entry) => entry.id === 'valid-non-oauth-native-binding');
const aadpAction = {
    action_type: fixture.expected_action.action_type,
    params: {
        initiator: fixture.expected_action.initiator,
        ...fixture.expected_action.parameters,
    },
};
const mappingProfile = 'https://emiliaprotocol.ai/profiles/aadp-ep-payment-release-v1';
const mapAction = (action) => ({
    action_type: action.action_type,
    initiator: action.params.initiator,
    parameters: {
        amount_minor: action.params.amount_minor,
        currency: action.params.currency,
        payee: action.params.payee,
    },
});
const bundleOptions = {
    now: fixture.now,
    audience: fixture.audience,
    approverKeys: fixture.approver_keys,
    expectedApprovers: fixture.expected_approvers,
    acceptedKeyClasses: fixture.accepted_key_classes,
    currentPolicy: fixture.current_policy,
    expectedAuthorizationInstance: fixture.expected_authorization_instance,
    expectedAuthorizationBinding: fixture.expected_authorization_binding,
    requireAuthorizationBinding: true,
};
test('AADP hook is closed, profile-neutral, and safely normalized', () => {
    const hook = {
        profile: AADP_AUTHORIZATION_ARTIFACT_VERSION,
        artifact_profile: AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE,
        artifact_digest: `sha256:${'a'.repeat(64)}`,
        verification_outcome: 'verified',
        action_mapping_profile: mappingProfile,
        action_digest: `sha256:${'b'.repeat(64)}`,
    };
    assert.deepEqual(parseAadpAuthorizationArtifact(hook), hook);
    assert.equal(parseAadpAuthorizationArtifact({ ...hook, permit_id: 'permit:smuggled' }), null);
    assert.equal(parseAadpAuthorizationArtifact({ ...hook, artifact_profile: '' }), null);
    assert.equal(parseAadpAuthorizationArtifact({ ...hook, artifact_digest: `sha256:${'A'.repeat(64)}` }), null);
});
test('generic hook matching distinguishes mismatch from unavailable native input', () => {
    const hook = {
        profile: AADP_AUTHORIZATION_ARTIFACT_VERSION,
        artifact_profile: 'example-native-authorization-v1',
        artifact_digest: `sha256:${'a'.repeat(64)}`,
        verification_outcome: 'verified',
        action_mapping_profile: 'https://example.com/mapping-v1',
        action_digest: `sha256:${'b'.repeat(64)}`,
    };
    assert.equal(matchAadpAuthorizationArtifact(hook, structuredClone(hook)).verdict, 'MATCH');
    assert.equal(matchAadpAuthorizationArtifact({ ...hook, action_digest: `sha256:${'c'.repeat(64)}` }, hook).verdict, 'MISMATCH');
    assert.equal(matchAadpAuthorizationArtifact(hook, undefined).verdict, 'INDETERMINATE');
});
test('EP profile derives a digest hook only after native bundle and exact-action verification', () => {
    const result = deriveAadpEpAuthorizationArtifact({
        bundle: fixture.bundle,
        aadpAction,
        actionMappingProfile: mappingProfile,
        mapAction,
        bundleOptions,
    });
    assert.equal(result.verdict, 'VERIFIED', JSON.stringify(result, null, 2));
    assert.equal(result.authorization_decision, false);
    assert.equal(result.artifact?.profile, AADP_AUTHORIZATION_ARTIFACT_VERSION);
    assert.equal(result.artifact?.artifact_profile, AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE);
    assert.match(result.artifact?.artifact_digest ?? '', /^sha256:[0-9a-f]{64}$/);
    assert.equal(result.artifact?.verification_outcome, 'verified');
    assert.equal(result.artifact?.action_digest, digestAeb(aadpAction));
});
test('EP profile refuses substitution and tampering instead of blessing a digest', () => {
    const substituted = deriveAadpEpAuthorizationArtifact({
        bundle: fixture.bundle,
        aadpAction: {
            ...aadpAction,
            params: { ...aadpAction.params, amount_minor: 999_999 },
        },
        actionMappingProfile: mappingProfile,
        mapAction,
        bundleOptions,
    });
    assert.equal(substituted.verdict, 'REFUSE');
    assert.ok(substituted.reasons.includes('action_mismatch'));
    assert.equal(substituted.artifact?.verification_outcome, 'not_satisfying');
    const tampered = structuredClone(fixture.bundle);
    tampered.contexts[0].audience = 'https://attacker.example';
    const result = deriveAadpEpAuthorizationArtifact({
        bundle: tampered,
        aadpAction,
        actionMappingProfile: mappingProfile,
        mapAction,
        bundleOptions,
    });
    assert.equal(result.verdict, 'REFUSE');
    assert.equal(result.artifact?.verification_outcome, 'not_satisfying');
});
test('unavailable mapping stays indeterminate and a changed presented hook refuses', () => {
    const unavailable = deriveAadpEpAuthorizationArtifact({
        bundle: fixture.bundle,
        aadpAction,
        actionMappingProfile: mappingProfile,
        mapAction: () => { throw new Error('mapping registry unavailable'); },
        bundleOptions,
    });
    assert.equal(unavailable.verdict, 'INDETERMINATE');
    assert.deepEqual(unavailable.reasons, ['aadp_action_mapping_unavailable']);
    assert.equal(unavailable.artifact?.verification_outcome, 'not_reachable');
    const derived = deriveAadpEpAuthorizationArtifact({
        bundle: fixture.bundle,
        aadpAction,
        actionMappingProfile: mappingProfile,
        mapAction,
        bundleOptions,
    });
    assert.equal(derived.verdict, 'VERIFIED');
    const changed = { ...derived.artifact, action_mapping_profile: 'https://attacker.example/mapping' };
    const verified = verifyAadpEpAuthorizationArtifact(changed, {
        bundle: fixture.bundle,
        aadpAction,
        actionMappingProfile: mappingProfile,
        mapAction,
        bundleOptions,
    });
    assert.equal(verified.verdict, 'REFUSE');
    assert.deepEqual(verified.reasons, ['authorization_artifact_mismatch']);
});
test('hostile accessors and proxies produce verdicts without executing getters', () => {
    const accessor = Object.create(null);
    Object.defineProperty(accessor, 'profile', {
        enumerable: true,
        get() { throw new Error('must not execute'); },
    });
    assert.doesNotThrow(() => parseAadpAuthorizationArtifact(accessor));
    assert.equal(parseAadpAuthorizationArtifact(accessor), null);
    const proxy = new Proxy({}, {
        getPrototypeOf() { throw new Error('must not escape'); },
    });
    assert.doesNotThrow(() => matchAadpAuthorizationArtifact(proxy, proxy));
    assert.equal(matchAadpAuthorizationArtifact(proxy, proxy).verdict, 'MISMATCH');
});
