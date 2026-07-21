// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';

import { createGovernmentMobileController } from './government.js';

test('government controller gets action and display bytes from the system of record', async () => {
  let issued;
  const profile = { profile_id: 'gov.mobile.v1', profile_hash: `sha256:${'a'.repeat(64)}` };
  const controller = createGovernmentMobileController({
    service: {
      async issue(args) { issued = args; return { ok: true, verdict: 'issued', challenge: { profile_hash: profile.profile_hash } }; },
      async verifyAndConsume(args) { return { valid: true, verdict: 'verified', decision: 'approved', profile: args.profile }; },
    },
    profiles: new Map([[profile.profile_id, profile]]),
    async authorize(input) {
      assert.equal(input.caller.subject, 'agency-user-42');
      assert.equal(input.approver_id, 'ep:approver:case-supervisor');
      return true;
    },
    async resolveRequest(reference) {
      assert.equal(reference.action_reference, 'case-9482');
      return {
        action: { action_type: 'benefit.payment_destination_change', case_id: 'case-9482', destination_last4: '4401' },
        presentation: { title: 'Payment destination change', material_fields: { destination_last4: '4401' } },
        policy: { human_approval: true },
        policy_id: 'gov-benefits-v1',
        initiator_id: 'ep:agent:benefits-assistant',
        approver_id: 'ep:approver:case-supervisor',
        issued_at: '2026-07-14T19:00:00.000Z',
        expires_at: '2026-07-14T19:05:00.000Z',
        challenge_id: 'mob_0123456789abcdef',
        nonce: 'sig_0123456789abcdef0123456789abcdef',
      };
    },
  });
  const result = await controller.issue({
    profile_id: profile.profile_id,
    action_reference: 'case-9482',
    decision: 'approved',
    platform: 'ios',
    app_id: 'gov.example.ios.approvals',
    device_key_id: 'ep:key:mobile-ios-1',
    approver_id: 'ep:approver:case-supervisor',
  }, { subject: 'agency-user-42' });
  assert.equal(result.ok, true);
  assert.equal(issued.action.destination_last4, '4401');
  assert.equal(issued.presentation.title, 'Payment destination change');
  assert.equal(Object.hasOwn(issued, 'requester_context'), false);
});

test('government controller never accepts a caller-supplied profile', async () => {
  let verifierCalled = false;
  const controller = createGovernmentMobileController({
    service: {
      async issue() { throw new Error('not used'); },
      async verifyAndConsume() { verifierCalled = true; },
    },
    profiles: new Map([['pinned', { profile_id: 'pinned', profile_hash: `sha256:${'a'.repeat(64)}` }]]),
    async authorize() { return true; },
    async resolveRequest() { throw new Error('not used'); },
  });
  const result = await controller.verify({
    challenge: { profile_hash: `sha256:${'b'.repeat(64)}` },
    response: {},
    profile: { profile_id: 'attacker' },
  });
  assert.equal(result.verdict, 'refuse_profile_mismatch');
  assert.equal(verifierCalled, false);
});

test('government controller refuses untrusted fields and unauthorized callers before protected work', async () => {
  let resolved = false;
  let verified = false;
  const profile = { profile_id: 'gov.mobile.v1', profile_hash: `sha256:${'a'.repeat(64)}` };
  const controller = createGovernmentMobileController({
    service: {
      async issue() { throw new Error('must not issue'); },
      async verifyAndConsume() { verified = true; },
    },
    profiles: new Map([[profile.profile_id, profile]]),
    async authorize(input) { return input.caller?.subject === 'authorized-user'; },
    async resolveRequest() { resolved = true; },
  });
  const request = {
    profile_id: profile.profile_id,
    action_reference: 'case-9482',
    approver_id: 'ep:approver:case-supervisor',
    decision: 'approved',
    platform: 'ios',
    app_id: 'gov.example.ios.approvals',
    device_key_id: 'ep:key:mobile-ios-1',
  };
  const injected = await controller.issue({ ...request, action: { amount: 1 } }, { subject: 'authorized-user' });
  assert.equal(injected.verdict, 'refuse_malformed');
  const unauthorized = await controller.issue(request, { subject: 'other-user' });
  assert.equal(unauthorized.verdict, 'refuse_unauthorized');
  assert.equal(resolved, false);

  const verifyResult = await controller.verify({
    challenge: {
      profile_hash: profile.profile_hash,
      challenge_id: 'mob_0123456789abcdef',
      action_hash: `sha256:${'b'.repeat(64)}`,
      authorization_context: {
        approver: 'ep:approver:case-supervisor',
        decision: 'approved',
        mobile_binding: {
          platform: 'ios',
          app_id: 'gov.example.ios.approvals',
          device_key_id: 'ep:key:mobile-ios-1',
        },
      },
    },
    response: {},
  }, { subject: 'other-user' });
  assert.equal(verifyResult.verdict, 'refuse_unauthorized');
  assert.equal(verified, false);
});

test('government controller refuses a system-of-record approver substitution', async () => {
  let issued = false;
  const profile = { profile_id: 'gov.mobile.v1', profile_hash: `sha256:${'a'.repeat(64)}` };
  const controller = createGovernmentMobileController({
    service: {
      async issue() { issued = true; },
      async verifyAndConsume() { throw new Error('not used'); },
    },
    profiles: new Map([[profile.profile_id, profile]]),
    async authorize(input) { return input.approver_id === 'ep:approver:authorized'; },
    async resolveRequest() {
      return {
        action: { action_type: 'benefit.payment_destination_change', case_id: 'case-9482' },
        presentation: { title: 'Payment destination change', material_fields: { case_id: 'case-9482' } },
        initiator_id: 'ep:agent:benefits-assistant',
        approver_id: 'ep:approver:substituted',
        issued_at: '2026-07-14T19:00:00.000Z',
        expires_at: '2026-07-14T19:05:00.000Z',
      };
    },
  });
  const result = await controller.issue({
    profile_id: profile.profile_id,
    action_reference: 'case-9482',
    decision: 'approved',
    platform: 'ios',
    app_id: 'gov.example.ios.approvals',
    device_key_id: 'ep:key:mobile-ios-1',
    approver_id: 'ep:approver:authorized',
  }, { subject: 'agency-user-42' });
  assert.equal(result.verdict, 'refuse_unauthorized');
  assert.equal(issued, false);
});

test('government controller records the action-to-challenge binding before returning it', async () => {
  const profile = { profile_id: 'gov.mobile.v1', profile_hash: `sha256:${'a'.repeat(64)}` };
  let binding;
  const controller = createGovernmentMobileController({
    service: {
      async issue() {
        return {
          ok: true,
          verdict: 'issued',
          challenge: {
            challenge_id: 'mob_0123456789abcdef',
            action_hash: `sha256:${'b'.repeat(64)}`,
            expires_at: '2026-07-14T19:05:00.000Z',
          },
        };
      },
      async verifyAndConsume() { throw new Error('not used'); },
    },
    profiles: new Map([[profile.profile_id, profile]]),
    async authorize() { return true; },
    async resolveRequest() {
      return {
        action: { action_type: 'benefit.payment_destination_change', case_id: 'case-9482' },
        presentation: { title: 'Payment destination change', material_fields: { case_id: 'case-9482' } },
        initiator_id: 'ep:agent:benefits-assistant',
        approver_id: 'ep:approver:case-supervisor',
        issued_at: '2026-07-14T19:00:00.000Z',
        expires_at: '2026-07-14T19:05:00.000Z',
      };
    },
    async registerChallenge(value) { binding = value; return true; },
  });
  const request = {
    profile_id: profile.profile_id,
    action_reference: 'case-9482',
    decision: 'denied',
    platform: 'ios',
    app_id: 'gov.example.ios.approvals',
    device_key_id: 'ep:key:mobile-ios-1',
    approver_id: 'ep:approver:case-supervisor',
  };
  assert.equal((await controller.issue(request)).ok, true);
  assert.deepEqual(binding, {
    action_reference: 'case-9482',
    approver_id: 'ep:approver:case-supervisor',
    decision: 'denied',
    challenge_id: 'mob_0123456789abcdef',
    action_hash: `sha256:${'b'.repeat(64)}`,
    expires_at: '2026-07-14T19:05:00.000Z',
  });

  const refused = createGovernmentMobileController({
    service: controllerService(),
    profiles: new Map([[profile.profile_id, profile]]),
    async authorize() { return true; },
    async resolveRequest() { return resolvedRequest(); },
    async registerChallenge() { return false; },
  });
  assert.equal((await refused.issue(request)).verdict, 'refuse_replay');

  function controllerService() {
    return {
      async issue() {
        return {
          ok: true,
          verdict: 'issued',
          challenge: {
            challenge_id: 'mob_0123456789abcdef',
            action_hash: `sha256:${'b'.repeat(64)}`,
            expires_at: '2026-07-14T19:05:00.000Z',
          },
        };
      },
      async verifyAndConsume() { throw new Error('not used'); },
    };
  }

  function resolvedRequest() {
    return {
      action: { action_type: 'benefit.payment_destination_change', case_id: 'case-9482' },
      presentation: { title: 'Payment destination change', material_fields: { case_id: 'case-9482' } },
      initiator_id: 'ep:agent:benefits-assistant',
      approver_id: 'ep:approver:case-supervisor',
      issued_at: '2026-07-14T19:00:00.000Z',
      expires_at: '2026-07-14T19:05:00.000Z',
    };
  }
});
