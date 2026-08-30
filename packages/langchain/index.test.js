// Generated from index.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/langchain — RR-1 unit suite for the offline receipt gate.
 * @license Apache-2.0
 *
 * Proves the four normative behaviors WITHOUT any network, against a fake
 * LangChain tool (an object exposing `.invoke(input, config)`):
 *   missing  -> refused (throws)
 *   valid    -> runs    (returns the tool result)
 *   replay   -> refused (throws)
 *   forged   -> refused (throws)
 * plus per-call action binding (a receipt for target A can't drive target B).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { requireReceiptForLangChainTool, guardAction, withGuard, _resetConsumed, } from './index.js';
import { bindToolAction } from '../require-receipt/index.js';
test('package metadata pins the current receipt gate release line', () => {
    const packageJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
    assert.equal(packageJson.version, '0.4.1');
    assert.equal(packageJson.dependencies['@emilia-protocol/require-receipt'], '^0.8.1');
    assert.ok(packageJson.files.includes('CHANGELOG.md'));
});
function canonicalize(v) {
    if (v === null || v === undefined)
        return JSON.stringify(v);
    if (Array.isArray(v))
        return `[${v.map(canonicalize).join(',')}]`;
    if (typeof v === 'object') {
        return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
    }
    return JSON.stringify(v);
}
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const TRUSTED_KEY = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
function mintReceipt({ action, createdAt } = {}) {
    const payload = {
        receipt_id: 'rcpt_' + crypto.randomUUID(),
        subject: 'alice@futureenterprises.example',
        created_at: createdAt || new Date().toISOString(),
        claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'alice@futureenterprises.example' },
    };
    const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey);
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: sig.toString('base64url') },
        public_key: TRUSTED_KEY,
    };
}
// Minimal fake LangChain tool: records calls, returns a sentinel.
function fakeTool(name = 'release_payment') {
    const calls = [];
    return {
        name,
        description: 'test tool',
        calls,
        async invoke(input, _config) {
            calls.push(input);
            return { ok: true, ran: input };
        },
    };
}
const cfg = (receipt) => ({ configurable: { emiliaReceipt: receipt } });
const exact = (input, base = 'payment.release', toolName = 'release_payment') => bindToolAction(toolName, input, base);
test('missing receipt -> refused (throws, tool never runs)', async () => {
    _resetConsumed();
    const tool = fakeTool();
    const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
    await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(null)), /EMILIA blocked/);
    assert.equal(tool.calls.length, 0);
});
test('valid action-bound receipt -> runs', async () => {
    _resetConsumed();
    const tool = fakeTool();
    const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
    const r = mintReceipt({ action: exact({ to: 'acct_1' }) });
    const out = await guarded.invoke({ to: 'acct_1' }, cfg(r));
    assert.deepEqual(out, { ok: true, ran: { to: 'acct_1' } });
    assert.equal(tool.calls.length, 1);
});
test('replay of the same receipt -> refused (one-time consumption)', async () => {
    _resetConsumed();
    const tool = fakeTool();
    const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
    const r = mintReceipt({ action: exact({ to: 'acct_1' }) });
    await guarded.invoke({ to: 'acct_1' }, cfg(r));
    await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(r)), /EMILIA blocked/);
    assert.equal(tool.calls.length, 1);
});
test('forged receipt (action altered post-sign) -> refused', async () => {
    _resetConsumed();
    const tool = fakeTool();
    const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
    const forged = mintReceipt({ action: exact({ to: 'acct_1' }) });
    forged.payload.claim.action_type = exact({ to: 'acct_attacker' });
    await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(forged)), /EMILIA blocked/);
    assert.equal(tool.calls.length, 0);
});
test('untrusted issuer -> refused', async () => {
    _resetConsumed();
    const other = crypto.generateKeyPairSync('ed25519');
    const otherKey = other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const tool = fakeTool();
    const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [otherKey] });
    const r = mintReceipt({ action: 'payment.release' });
    await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(r)), /EMILIA blocked/);
    assert.equal(tool.calls.length, 0);
});
test('per-call binding: receipt for target A cannot drive target B', async () => {
    _resetConsumed();
    const tool = fakeTool();
    const guarded = requireReceiptForLangChainTool(tool, {
        actionFor: () => 'payment.release',
        trustedKeys: [TRUSTED_KEY],
    });
    const rA = mintReceipt({ action: exact({ to: 'acct_A' }) });
    // Correct target runs:
    const out = await guarded.invoke({ to: 'acct_A' }, cfg(rA));
    assert.deepEqual(out, { ok: true, ran: { to: 'acct_A' } });
    // Same receipt against a different target is refused:
    const rA2 = mintReceipt({ action: exact({ to: 'acct_A' }) });
    await assert.rejects(() => guarded.invoke({ to: 'acct_B' }, cfg(rA2)), /EMILIA blocked/);
    assert.equal(tool.calls.length, 1);
});
test('indeterminate tool failure consumes the receipt and blocks automatic retry', async () => {
    _resetConsumed();
    let attempts = 0;
    const flaky = {
        name: 'release_payment',
        async invoke(input) {
            attempts += 1;
            if (attempts === 1)
                throw new Error('transient downstream error');
            return { ok: true, ran: input };
        },
    };
    const guarded = requireReceiptForLangChainTool(flaky, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
    const r = mintReceipt({ action: exact({ to: 'acct_1' }) });
    await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(r)), /transient downstream error/);
    // The downstream may have applied the effect before losing its response. The
    // approval is burned, so the same receipt cannot duplicate the action.
    await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(r)), /EMILIA blocked/);
    assert.equal(attempts, 1);
});
test('tool identity/name preserved through the proxy', async () => {
    const tool = fakeTool('wire_transfer');
    const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
    assert.equal(guarded.name, 'wire_transfer');
    assert.equal(guarded.description, 'test tool');
});
test('actionFor is evaluated once and derivation failures block before tool execution', async () => {
    _resetConsumed();
    const tool = fakeTool();
    let calls = 0;
    const guarded = requireReceiptForLangChainTool(tool, {
        actionFor: () => {
            calls += 1;
            return calls === 1 ? 'payment.release' : 'payment.release.attacker';
        },
        trustedKeys: [TRUSTED_KEY],
    });
    await guarded.invoke({ to: 'acct_A' }, cfg(mintReceipt({ action: exact({ to: 'acct_A' }) })));
    assert.equal(calls, 1, 'a stateful mapper must not be re-evaluated after verification begins');
    const blockedTool = fakeTool();
    const blocked = requireReceiptForLangChainTool(blockedTool, {
        actionFor: () => { throw new Error('bad input'); },
        trustedKeys: [TRUSTED_KEY],
    });
    await assert.rejects(() => blocked.invoke({}, cfg(mintReceipt({ action: 'payment.release' }))), /action_binding_invalid/);
    assert.equal(blockedTool.calls.length, 0);
});
test('selector and caller mutation cannot change the bound executor snapshot', async () => {
    _resetConsumed();
    const input = { to: 'acct_A', nested: { amount: 10.5 } };
    const tool = fakeTool();
    const store = {
        ownershipFenced: true,
        async reserve() {
            input.to = 'acct_B';
            input.nested.amount = 999;
            return true;
        },
        async commit() { return true; },
        async release() { return true; },
    };
    const guarded = requireReceiptForLangChainTool(tool, {
        actionFor: (candidate) => {
            candidate.to = 'acct_selector_mutation';
            return 'payment.release';
        },
        trustedKeys: [TRUSTED_KEY],
        store,
    });
    const approved = { to: 'acct_A', nested: { amount: 10.5 } };
    const receipt = mintReceipt({ action: exact(approved) });
    const out = await guarded.invoke(input, cfg(receipt));
    assert.deepEqual(out.ran, approved);
    assert.deepEqual(tool.calls, [approved]);
});
function gateResponse(raw, { status = 200, ok = status >= 200 && status < 300 } = {}) {
    return { status, ok, async json() { return raw; } };
}
test('legacy hosted guard allows only an explicit successful allow verdict', async () => {
    const allowed = await guardAction({
        action: 'payment.release',
        fetchImpl: async () => gateResponse({ decision: 'allow' }),
    });
    assert.equal(allowed.allow, true);
    assert.equal(allowed.deny, false);
    for (const fetchImpl of [
        async () => gateResponse({}),
        async () => gateResponse({ decision: 'unexpected' }),
        async () => gateResponse({ decision: 'allow' }, { status: 500, ok: false }),
        async () => { throw new Error('network unavailable'); },
    ]) {
        const result = await guardAction({ action: 'payment.release', fetchImpl });
        assert.equal(result.allow, false);
        assert.equal(result.deny, true);
    }
    const review = await guardAction({
        action: 'payment.release',
        fetchImpl: async () => gateResponse({ decision: 'review' }),
    });
    assert.equal(review.allow, false);
    assert.equal(review.signoffRequired, true);
});
test('legacy withGuard callbacks and hosted allow verdicts cannot authorize execution', async () => {
    const tool = fakeTool();
    const fetchImpl = async () => gateResponse({ decision: 'review' });
    const merelyNotified = withGuard(tool, {
        action: 'payment.release',
        fetchImpl,
        onSignoff: async () => undefined,
    });
    await assert.rejects(() => merelyNotified.invoke({ amount: 10 }), /exact-action receipt/);
    assert.equal(tool.calls.length, 0);
    const approved = withGuard(tool, {
        action: 'payment.release',
        fetchImpl,
        onSignoff: async () => ({ approved: true }),
    });
    await assert.rejects(() => approved.invoke({ amount: 10 }), /exact-action receipt/);
    assert.equal(tool.calls.length, 0);
    const hostedAllow = withGuard(tool, {
        action: 'payment.release',
        fetchImpl: async () => gateResponse({ decision: 'allow' }),
    });
    await assert.rejects(() => hostedAllow.invoke({ amount: 10 }), /legacy hosted gate execution/);
    assert.equal(tool.calls.length, 0);
});
