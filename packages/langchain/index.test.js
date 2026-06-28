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
import { requireReceiptForLangChainTool, _resetConsumed } from './index.js';

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
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
  const r = mintReceipt({ action: 'payment.release' });
  const out = await guarded.invoke({ to: 'acct_1' }, cfg(r));
  assert.deepEqual(out, { ok: true, ran: { to: 'acct_1' } });
  assert.equal(tool.calls.length, 1);
});

test('replay of the same receipt -> refused (one-time consumption)', async () => {
  _resetConsumed();
  const tool = fakeTool();
  const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
  const r = mintReceipt({ action: 'payment.release' });
  await guarded.invoke({ to: 'acct_1' }, cfg(r));
  await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(r)), /EMILIA blocked/);
  assert.equal(tool.calls.length, 1);
});

test('forged receipt (action altered post-sign) -> refused', async () => {
  _resetConsumed();
  const tool = fakeTool();
  const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
  const forged = mintReceipt({ action: 'payment.release' });
  forged.payload.claim.action_type = 'payment.release.tampered';
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
    actionFor: (input) => `payment.release:${input.to}`,
    trustedKeys: [TRUSTED_KEY],
  });
  const rA = mintReceipt({ action: 'payment.release:acct_A' });
  // Correct target runs:
  const out = await guarded.invoke({ to: 'acct_A' }, cfg(rA));
  assert.deepEqual(out, { ok: true, ran: { to: 'acct_A' } });
  // Same receipt against a different target is refused:
  const rA2 = mintReceipt({ action: 'payment.release:acct_A' });
  await assert.rejects(() => guarded.invoke({ to: 'acct_B' }, cfg(rA2)), /EMILIA blocked/);
  assert.equal(tool.calls.length, 1);
});

test('transient tool failure does NOT consume the receipt (retryable)', async () => {
  _resetConsumed();
  let attempts = 0;
  const flaky = {
    name: 'release_payment',
    async invoke(input) {
      attempts += 1;
      if (attempts === 1) throw new Error('transient downstream error');
      return { ok: true, ran: input };
    },
  };
  const guarded = requireReceiptForLangChainTool(flaky, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
  const r = mintReceipt({ action: 'payment.release' });
  await assert.rejects(() => guarded.invoke({ to: 'acct_1' }, cfg(r)), /transient downstream error/);
  // The approval was NOT burned by the failure — the same receipt now succeeds.
  const out = await guarded.invoke({ to: 'acct_1' }, cfg(r));
  assert.deepEqual(out, { ok: true, ran: { to: 'acct_1' } });
});

test('tool identity/name preserved through the proxy', async () => {
  const tool = fakeTool('wire_transfer');
  const guarded = requireReceiptForLangChainTool(tool, { action: 'payment.release', trustedKeys: [TRUSTED_KEY] });
  assert.equal(guarded.name, 'wire_transfer');
  assert.equal(guarded.description, 'test tool');
});
