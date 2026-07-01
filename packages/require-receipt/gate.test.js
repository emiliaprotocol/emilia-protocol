// SPDX-License-Identifier: Apache-2.0
// Hardened-gate conformance for makeReceiptGate: target binding, consume-after-
// success, replay safety (post-commit AND in-flight), and sanitized rejections.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { makeReceiptGate } from './gate.js';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

// Mint a valid EP-RECEIPT-v1 bound to exactly `actionType`.
function mint(actionType, { outcome = 'allow_with_signoff', extra = {} } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: { action_type: actionType, outcome, approver: 'jane@yourco.example', ...extra },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
}

const gate = () => makeReceiptGate({ action: 'db.records.delete', allowInlineKey: true, maxAgeSec: 900 });

test('missing receipt -> 428 challenge, no rejected detail', async () => {
  let ran = false;
  const r = await gate().run(null, { target: 'customers' }, async () => { ran = true; });
  assert.equal(r.ok, false);
  assert.equal(r.status, 428);
  assert.ok(r.body.required, 'challenge tells the agent what to bring');
  assert.equal(r.body.rejected, undefined, 'a plain missing-receipt challenge carries no rejected detail');
  assert.equal(ran, false, 'the action never ran');
});

test('valid, target-bound receipt -> runs and commits', async () => {
  const g = gate();
  let ran = false;
  const rc = mint('db.records.delete:customers');
  const r = await g.run(rc, { target: 'customers' }, async () => { ran = true; return 'deleted'; });
  assert.equal(r.ok, true);
  assert.equal(r.result, 'deleted');
  assert.equal(ran, true);
});

test('replay after success -> refused, sanitized, action not re-run', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  await g.run(rc, { target: 'customers' }, async () => 'ok');
  let ranAgain = false;
  const r = await g.run(rc, { target: 'customers' }, async () => { ranAgain = true; });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'replay_refused');
  assert.deepEqual(Object.keys(r.body.rejected), ['reason'], 'rejection sanitized to { reason } only');
  assert.equal(ranAgain, false);
});

test('forged receipt -> refused, sanitized (no signer/subject leak)', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  rc.payload.claim.action_type = 'db.records.delete:customers'; // tamper AFTER signing
  rc.payload.subject = 'attacker';
  const r = await g.run(rc, { target: 'customers' }, async () => { throw new Error('should not run'); });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'untrusted_or_invalid_signature');
  assert.deepEqual(Object.keys(r.body.rejected), ['reason']);
});

test('payload outside the I-JSON profile -> refused before canonicalization can diverge', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  rc.payload.claim.amount = Number.NaN;
  const r = await g.run(rc, { target: 'customers' }, async () => 'should-not-run');
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'payload_outside_ijson_profile');
});

test('cross-target -> a receipt for customers cannot delete orders', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  let ran = false;
  const r = await g.run(rc, { target: 'orders' }, async () => { ran = true; });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'action_mismatch');
  assert.deepEqual(Object.keys(r.body.rejected), ['reason']);
  assert.equal(ran, false);
});

test('consume-after-FAILURE -> failed action leaves the receipt retryable', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  await assert.rejects(g.run(rc, { target: 'customers' }, async () => { throw new Error('notion down'); }));
  // The transient failure must NOT have burned the approval — retry succeeds.
  let ran = false;
  const r = await g.run(rc, { target: 'customers' }, async () => { ran = true; return 'ok'; });
  assert.equal(r.ok, true);
  assert.equal(ran, true);
});

test('in-flight replay -> the same receipt cannot drive two concurrent actions', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  let release;
  const gate1 = g.run(rc, { target: 'customers' }, () => new Promise((res) => { release = res; }));
  // While the first action is still in progress, a second attempt is refused.
  const second = await g.run(rc, { target: 'customers' }, async () => 'should-not-run');
  assert.equal(second.ok, false);
  assert.equal(second.body.rejected.reason, 'replay_refused');
  release('done');
  const first = await gate1;
  assert.equal(first.ok, true);
});

test('target binding via action function', async () => {
  const g = makeReceiptGate({ action: (t) => `block.delete:${t}`, allowInlineKey: true });
  const rc = mint('block.delete:abc123');
  const r = await g.run(rc, { target: 'abc123' }, async () => 'gone');
  assert.equal(r.ok, true);
});

test('assuranceClass: software receipt cannot satisfy Class-A requirement', async () => {
  const g = makeReceiptGate({ action: 'payment.release', allowInlineKey: true, assuranceClass: 'class_a' });
  const rc = mint('payment.release', { outcome: 'allow' });
  let ran = false;
  const r = await g.run(rc, {}, async () => { ran = true; });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'assurance_too_low');
  assert.equal(ran, false);
});

test('assuranceClass: Class-A receipt cannot satisfy quorum requirement', async () => {
  const g = makeReceiptGate({ action: 'deploy.production', allowInlineKey: true, assuranceClass: 'quorum' });
  const rc = mint('deploy.production', { outcome: 'allow_with_signoff' });
  const r = await g.run(rc, {}, async () => 'deployed');
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'assurance_too_low');
});

test('assuranceClass: signed quorum claim satisfies quorum requirement', async () => {
  const g = makeReceiptGate({ action: 'deploy.production', allowInlineKey: true, assuranceClass: 'quorum' });
  const rc = mint('deploy.production', {
    outcome: 'allow_with_signoff',
    extra: { quorum: { signers: ['ep:alice', 'ep:bob'], threshold: 2 } },
  });
  const r = await g.run(rc, {}, async () => 'deployed');
  assert.equal(r.ok, true);
  assert.equal(r.result, 'deployed');
});
