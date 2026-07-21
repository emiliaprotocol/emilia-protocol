// SPDX-License-Identifier: Apache-2.0
// Generated from index.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { _resetConsumed, guardAction, requireReceiptForOpenAITool, runToolCalls, withGuard, } from './index.js';
import { mintReceipt as hostedMintReceipt } from './receipt.js';
function canonicalize(value) {
    if (value === null || value === undefined)
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalize).join(',')}]`;
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
    }
    return JSON.stringify(value);
}
const keyPair = crypto.generateKeyPairSync('ed25519');
const trustedKey = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
function receipt(action) {
    const payload = {
        receipt_id: `rcpt_${crypto.randomUUID()}`,
        subject: 'ep:approver:alice',
        created_at: new Date().toISOString(),
        claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'ep:approver:alice' },
    };
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: {
            algorithm: 'Ed25519',
            value: crypto.sign(null, Buffer.from(canonicalize(payload)), keyPair.privateKey).toString('base64url'),
        },
    };
}
function response(body, status = 200) {
    return { ok: status >= 200 && status < 300, status, async json() { return body; } };
}
test('hosted gate allows only an explicit allow backed by a durable commit', async () => {
    const base = { actor: 'ep:entity:agent', action: 'payment.release', apiKey: 'secret' };
    const accepted = await guardAction({
        ...base,
        fetchImpl: async () => response({ decision: 'allow', commit_ref: 'commit_123' }),
    });
    assert.equal(accepted.allow, true);
    for (const fetchImpl of [
        async () => response({ decision: 'allow' }),
        async () => response({}),
        async () => response({ decision: 'unknown' }),
        async () => response({ decision: 'allow', commit_ref: 'commit_123' }, 500),
        async () => { throw new Error('network down'); },
    ]) {
        const result = await guardAction({ ...base, fetchImpl });
        assert.equal(result.allow, false);
        assert.equal(result.deny, true);
    }
});
test('hosted gate never sends a credential without an authenticated endpoint boundary', async () => {
    let calls = 0;
    const fetchImpl = async () => { calls += 1; return response({ decision: 'allow', commit_ref: 'c' }); };
    assert.equal((await guardAction({ actor: 'agent', action: 'x', fetchImpl })).reason, 'api_key_required');
    assert.equal((await guardAction({ actor: 'agent', action: 'x', apiKey: 'k', gateUrl: 'http://remote.example/gate', fetchImpl })).reason, 'insecure_gate_url');
    assert.equal(calls, 0);
});
test('legacy signoff callback requires an explicit approved result', async () => {
    let runs = 0;
    const fn = async () => { runs += 1; return 'ran'; };
    const fetchImpl = async () => response({ decision: 'review' });
    const common = { action: 'payment.release', actor: 'agent', apiKey: 'k', fetchImpl };
    await assert.rejects(withGuard(fn, { ...common, onSignoff: async () => undefined })({}), /explicit signoff/);
    assert.equal(runs, 0);
    assert.equal(await withGuard(fn, { ...common, onSignoff: async () => ({ approved: true }) })({}), 'ran');
    assert.equal(runs, 1);
});
test('offline tool gate binds material arguments and consumes a receipt once', async () => {
    _resetConsumed();
    let runs = 0;
    const guarded = requireReceiptForOpenAITool(async (args) => {
        runs += 1;
        assert.equal(args.__ep, undefined);
        return args.amount;
    }, {
        actionFor: (args) => `payment.release:${args.destination}:${args.amount}`,
        trustedKeys: [trustedKey],
    });
    const authorization = receipt('payment.release:acct_vendor:25');
    assert.equal(await guarded({ destination: 'acct_vendor', amount: 25, __ep: { receipt: authorization } }), 25);
    await assert.rejects(guarded({ destination: 'acct_vendor', amount: 25, __ep: { receipt: authorization } }), /replay_refused/);
    const wrongAmount = receipt('payment.release:acct_vendor:25');
    await assert.rejects(guarded({ destination: 'acct_vendor', amount: 250000, __ep: { receipt: wrongAmount } }), /action_mismatch/);
    assert.equal(runs, 1);
});
test('tool-loop defaults to gated, requires explicit read-only, and refuses duplicate JSON', async () => {
    let mutatingRuns = 0;
    let readRuns = 0;
    const tools = {
        mutate: { fn: async () => { mutatingRuns += 1; } },
        read: { readOnly: true, fn: async () => { readRuns += 1; return 'ok'; } },
    };
    const calls = [
        { id: 'a', function: { name: 'mutate', arguments: '{}' } },
        { id: 'b', function: { name: 'read', arguments: '{"q":1}' } },
        { id: 'c', function: { name: 'read', arguments: '{"q":1,"q":2}' } },
    ];
    const result = await runToolCalls(calls, tools);
    assert.match(result[0].content, /not explicitly read-only/);
    assert.equal(result[1].content, 'ok');
    assert.match(result[2].content, /duplicate-member/);
    assert.equal(mutatingRuns, 0);
    assert.equal(readRuns, 1);
});
test('hosted receipt client validates the origin before sending an API key', async () => {
    let called = false;
    await assert.rejects(hostedMintReceipt({
        apiKey: 'secret',
        base: 'https://user:password@example.com',
        organization_id: 'org',
        action_type: 'large_payment_release',
        target_resource_id: 'invoice',
        fetchImpl: async () => { called = true; },
    }), /absolute origin/);
    assert.equal(called, false);
});
