/**
 * @emilia-protocol/gate — regression tests for the June-2026 code red-team fixes.
 * @license Apache-2.0
 *   CR-1: in-prod, no store -> fail closed (throw) unless allowEphemeralStore.
 *   CR-2: strict evidence + failing sink -> an allow is downgraded to a refusal.
 *   HI-5: a receipt without receipt_id -> refused (no content-hash fallback).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createGate,
  createEvidenceLog,
  MemoryConsumptionStore,
  createDurableConsumptionStore,
  createMemoryBackend,
} from './index.js';

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const TRUSTED = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
function mint({ action, omitId = false } = {}) {
  const payload = {
    ...(omitId ? {} : { receipt_id: 'rcpt_' + crypto.randomUUID() }),
    subject: 'alice@ex',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'alice@ex' },
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey);
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: sig.toString('base64url') }, public_key: TRUSTED };
}

function secureStore(options = {}) {
  const backend = createMemoryBackend();
  backend.durable = true;
  return createDurableConsumptionStore(backend, options);
}

test('CR-1: unset NODE_ENV + no store -> throws unless ephemeral use is explicit', () => {
  const saved = process.env.NODE_ENV;
  delete process.env.NODE_ENV;
  try {
    assert.throws(
      () => createGate({ trustedKeys: [TRUSTED] }),
      /durable.*ownership-fenced.*permanent/i,
    );
    // explicit single-instance opt-in is allowed
    assert.doesNotThrow(() => createGate({ trustedKeys: [TRUSTED], allowEphemeralStore: true }));
  } finally {
    if (saved === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = saved;
  }
});

test('CR-1: an explicit memory store is refused in production without the opt-in', () => {
  const saved = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    assert.throws(
      () => createGate({ trustedKeys: [TRUSTED], store: new MemoryConsumptionStore() }),
      /durable.*ownership-fenced.*permanent/i,
    );
    assert.doesNotThrow(() => createGate({
      trustedKeys: [TRUSTED],
      store: new MemoryConsumptionStore(),
      allowEphemeralStore: true,
    }));
  } finally {
    if (saved === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = saved;
  }
});

test('CR-1: durable, ownership-fenced, and permanent are independently mandatory', () => {
  assert.doesNotThrow(() => createGate({ trustedKeys: [TRUSTED], store: secureStore() }));

  for (const capability of ['durable', 'ownershipFenced', 'permanentConsumption']) {
    const store = { ...secureStore(), [capability]: false };
    assert.throws(
      () => createGate({ trustedKeys: [TRUSTED], store }),
      /durable.*ownership-fenced.*permanent/i,
      capability,
    );
  }

  assert.throws(
    () => createGate({ trustedKeys: [TRUSTED], store: secureStore({ ttlSeconds: 60 }) }),
    /durable.*ownership-fenced.*permanent/i,
  );
});

test('CR-2: strict evidence + failing sink -> allow downgraded to refusal', async () => {
  const failingLog = createEvidenceLog({ strict: true, sink: async () => { throw new Error('sink down'); } });
  const gate = createGate({ trustedKeys: [TRUSTED], log: failingLog, allowEphemeralStore: true });
  const out = await gate.check({ selector: { action_type: 'payment.release' }, receipt: mint({ action: 'payment.release' }) });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'evidence_log_failed');
});

test('CR-2: observe-mode (non-strict) sink failure does NOT block', async () => {
  const bestEffort = createEvidenceLog({ strict: false, sink: async () => { throw new Error('sink down'); } });
  const gate = createGate({ trustedKeys: [TRUSTED], log: bestEffort, allowEphemeralStore: true });
  const out = await gate.check({ selector: { action_type: 'payment.release' }, receipt: mint({ action: 'payment.release' }) });
  assert.equal(out.allow, true);
});

test('HI-5: receipt without receipt_id -> refused (no hash fallback)', async () => {
  const gate = createGate({ trustedKeys: [TRUSTED], allowEphemeralStore: true });
  const out = await gate.check({ selector: { action_type: 'payment.release' }, receipt: mint({ action: 'payment.release', omitId: true }) });
  assert.equal(out.allow, false);
  assert.match(out.reason, /missing_receipt_id/);
});

test('sanity: valid receipt with id still allows', async () => {
  const gate = createGate({ trustedKeys: [TRUSTED], allowEphemeralStore: true });
  const out = await gate.check({ selector: { action_type: 'payment.release' }, receipt: mint({ action: 'payment.release' }) });
  assert.equal(out.allow, true);
});
