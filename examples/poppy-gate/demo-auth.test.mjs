// SPDX-License-Identifier: Apache-2.0
// Generated from demo-auth.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createDemoSessionAuth } from './demo-auth.mjs';
const issuer = 'https://auth.example/tenant/shop';
const endpoint = 'https://api.example/poppy/operations';
let now = Date.parse('2026-10-12T18:00:00Z');
const owner = { clientId: 'https://agent.example/client.json', userId: 'user-1',
    sessionId: 'session-1', accountId: 'account-1', scopes: ['poppy:write'],
    extensions: { operations: { version: '1' }, 'emiliaprotocol.ai/approval-evidence': { version: '1' } } };
const fixture = () => createDemoSessionAuth({ companyIssuer: issuer, endpoint, owner, now: () => now });
test('demo auth cryptographically verifies a resource-bound token and DPoP proof', async () => {
    const auth = fixture();
    const result = await auth.authenticateRequest(auth.request({ url: `${endpoint}/op-1`, method: 'GET' }));
    assert.equal(result.clientId, owner.clientId);
    assert.equal(result.accountId, owner.accountId);
    assert.equal(result.dpop.verified, true);
});
test('a replayed DPoP proof is refused', async () => {
    const auth = fixture();
    const request = auth.request({ url: `${endpoint}/op-1`, method: 'GET' });
    await auth.authenticateRequest(request);
    await assert.rejects(() => auth.authenticateRequest(request));
});
test('changing URL or method invalidates the DPoP binding', async () => {
    for (const patch of [{ url: `${endpoint}/other` }, { method: 'POST' }, { url: 'https://attacker.example/poppy/operations/op-1' }]) {
        const auth = fixture();
        const request = auth.request({ url: `${endpoint}/op-1`, method: 'GET' });
        await assert.rejects(() => auth.authenticateRequest({ ...request, ...patch }));
    }
});
test('token and proof tampering is refused; request-carried principal is ignored', async () => {
    for (const field of ['Authorization', 'DPoP']) {
        const auth = fixture();
        const request = auth.request({ url: `${endpoint}/op-1`, method: 'GET' });
        const pieces = request.headers[field].split('.');
        pieces[1] = Buffer.from('{"admin":true}').toString('base64url');
        request.headers[field] = pieces.join('.');
        await assert.rejects(() => auth.authenticateRequest(request));
    }
    const auth = fixture();
    const request = auth.request({ url: `${endpoint}/op-1`, method: 'GET' });
    request.principal = { accountId: 'attacker' };
    assert.equal((await auth.authenticateRequest(request)).accountId, 'account-1');
});
test('MCP bearer tokens are not accepted at the Operations endpoint', async () => {
    const auth = fixture();
    const request = auth.request({ url: `${endpoint}/op-1`, method: 'GET' });
    request.headers.Authorization = request.headers.Authorization.replace(/^DPoP /, 'Bearer ');
    await assert.rejects(() => auth.authenticateRequest(request));
});
test('expired tokens and stale proofs are refused', async () => {
    const auth = fixture();
    const request = auth.request({ url: `${endpoint}/op-1`, method: 'GET' });
    now += 3_601_000;
    try {
        await assert.rejects(() => auth.authenticateRequest(request));
    }
    finally {
        now -= 3_601_000;
    }
});
test('stale DPoP is refused even while its Session Token is still valid', async () => {
    const auth = fixture();
    const request = auth.request({ url: `${endpoint}/op-1`, method: 'GET' });
    now += 61_000;
    try {
        await assert.rejects(() => auth.authenticateRequest(request));
    }
    finally {
        now -= 61_000;
    }
});
test('proof signed for one session key cannot be used with another session token', async () => {
    const first = fixture(), second = fixture();
    const a = first.request({ url: `${endpoint}/op-1`, method: 'GET' });
    const b = second.request({ url: `${endpoint}/op-1`, method: 'GET' });
    a.headers.DPoP = b.headers.DPoP;
    await assert.rejects(() => first.authenticateRequest(a));
});
