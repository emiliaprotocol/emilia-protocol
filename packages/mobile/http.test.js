// SPDX-License-Identifier: Apache-2.0
// Generated from http.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createMobileHttpHandler } from './http.js';
function request(path, body, { token = 'valid', method = 'POST', raw = null } = {}) {
    return new Request(`https://approve.example.gov${path}`, {
        method,
        headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json',
        },
        body: method === 'POST' ? (raw ?? JSON.stringify(body)) : undefined,
    });
}
function fixture() {
    const calls = [];
    const handler = createMobileHttpHandler({
        controller: {
            async issue(body, caller) { calls.push(['issue', body, caller]); return { ok: true, verdict: 'issued', challenge: {} }; },
            async verify(body, caller) { calls.push(['verify', body, caller]); return { valid: true, verdict: 'verified', decision: 'approved' }; },
        },
        enrollmentService: {
            async issue(body) { calls.push(['enroll-issue', body]); return { ok: true, verdict: 'issued', challenge: {} }; },
            async complete(body) { calls.push(['enroll-complete', body]); return { ok: true, verdict: 'enrolled', enrollment: {} }; },
        },
        async authenticate(input) {
            return input.headers.get('authorization') === 'Bearer valid' ? { subject: 'agency-user-42' } : null;
        },
        async resolveEnrollmentIdentity({ caller }) {
            assert.equal(caller.subject, 'agency-user-42');
            return { userName: 'case-supervisor@example.gov', displayName: 'Case Supervisor' };
        },
        enrollmentConfig: { rpId: 'approve.example.gov', origin: 'https://approve.example.gov' },
    });
    return { handler, calls };
}
test('mobile HTTP adapter authenticates and routes all four strict endpoints', async () => {
    const { handler, calls } = fixture();
    const issue = await handler(request('/v1/mobile/challenges', {
        profile_id: 'agency.mobile.v1',
        action_reference: 'case-9482',
        approver_id: 'ep:approver:case-supervisor',
        decision: 'approved',
        platform: 'ios',
        app_id: 'org.example.government.approvals',
        device_key_id: 'ep:key:mobile-ios-1',
    }));
    assert.equal(issue.status, 200);
    assert.equal(calls[0][2].subject, 'agency-user-42');
    const ceremony = await handler(request('/v1/mobile/ceremonies', { challenge: {}, response: {} }));
    assert.equal(ceremony.status, 200);
    const enrollment = await handler(request('/v1/mobile/enrollments/challenges', {
        approver_id: 'ep:approver:case-supervisor',
        platform: 'ios',
        app_id: 'org.example.government.approvals',
    }));
    assert.equal(enrollment.status, 200);
    assert.equal(calls[2][1].rpId, 'approve.example.gov');
    assert.equal(calls[2][1].userName, 'case-supervisor@example.gov');
    assert.equal(Object.hasOwn(calls[2][1], 'user_name'), false);
    const completion = await handler(request('/v1/mobile/enrollments', { challenge: {}, response: {} }));
    assert.equal(completion.status, 200);
    assert.equal(calls[3][1].caller.subject, 'agency-user-42');
});
test('mobile HTTP adapter rejects insecure, unauthenticated, duplicate, oversized, and unknown input', async () => {
    const { handler, calls } = fixture();
    const insecure = await handler(new Request('http://approve.example.gov/v1/mobile/challenges', {
        method: 'POST',
        headers: { authorization: 'Bearer valid', 'content-type': 'application/json' },
        body: '{}',
    }));
    assert.equal(insecure.status, 400);
    assert.equal((await insecure.json()).verdict, 'refuse_malformed');
    const unauthenticated = await handler(request('/v1/mobile/challenges', {}, { token: 'invalid' }));
    assert.equal(unauthenticated.status, 401);
    const duplicate = await handler(request('/v1/mobile/ceremonies', null, {
        raw: '{"challenge":{},"response":{},"\\u0063hallenge":{}}',
    }));
    assert.equal(duplicate.status, 400);
    const unknown = await handler(request('/v1/mobile/enrollments/challenges', {
        approver_id: 'ep:approver:case-supervisor',
        platform: 'ios',
        app_id: 'org.example.government.approvals',
        user_name: 'attacker-selected',
    }));
    assert.equal(unknown.status, 400);
    const unsafeNumber = await handler(request('/v1/mobile/ceremonies', null, {
        raw: '{"challenge":{"counter":9007199254740992},"response":{}}',
    }));
    assert.equal(unsafeNumber.status, 400);
    const smallHandler = createMobileHttpHandler({
        controller: { issue() { }, verify() { } },
        enrollmentService: { issue() { }, complete() { } },
        authenticate: async () => ({ subject: 'agency-user-42' }),
        resolveEnrollmentIdentity: async () => ({ userName: 'u', displayName: 'd' }),
        enrollmentConfig: { rpId: 'approve.example.gov', origin: 'https://approve.example.gov' },
        maxBodyBytes: 1024,
    });
    const oversized = await smallHandler(request('/v1/mobile/ceremonies', { padding: 'x'.repeat(1100) }));
    assert.equal(oversized.status, 400);
    assert.equal(calls.length, 0);
});
