// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReliancePacket } from './reliance-packet.js';

const decision = {
  allow: true,
  reason: 'allow',
  action: 'payment.release',
  evidence: {
    hash: 'decision-hash',
    receipt_id: 'receipt-1',
    execution_binding: { ok: true },
  },
};
const execution = {
  kind: 'execution',
  hash: 'execution-hash',
  authorizes_decision: 'decision-hash',
};

test('reliance waits for an asynchronous evidence verifier before emitting rely', async () => {
  let release;
  const verification = new Promise((resolve) => { release = resolve; });
  let settled = false;
  const packetPromise = buildReliancePacket({
    decision,
    execution,
    evidence: { verify: () => verification },
  }).then((packet) => { settled = true; return packet; });
  await Promise.resolve();
  assert.equal(settled, false);
  release({ ok: true, length: 2, head: 'evidence-head' });
  const packet = await packetPromise;
  assert.equal(packet.verdict, 'rely');
  assert.equal(packet.summary.evidence_head, 'evidence-head');
});

for (const [name, evidence, reason] of [
  ['resolved rejection', { verify: async () => ({ ok: false, reason: 'hash_mismatch' }) }, 'hash_mismatch'],
  ['thrown verifier', { verify: async () => { throw new Error('backend unavailable'); } }, 'evidence_verification_failed'],
  ['malformed result', { verify: async () => ({}) }, 'evidence_verification_rejected'],
  ['missing verifier', null, 'evidence_verification_unavailable'],
]) {
  test(`reliance fails closed on ${name}`, async () => {
    const packet = await buildReliancePacket({ decision, execution, evidence });
    assert.equal(packet.verdict, 'do_not_rely');
    const check = packet.checks.find((entry) => entry.id === 'evidence_log_intact');
    assert.equal(check.ok, false);
    assert.equal(check.detail, reason);
  });
}

test('an allow decision without execution evidence is always do_not_rely', async () => {
  const packet = await buildReliancePacket({
    decision,
    evidence: { verify: async () => ({ ok: true, length: 1, head: 'head' }) },
  });
  assert.equal(packet.verdict, 'do_not_rely');
  assert.equal(packet.checks.find((entry) => entry.id === 'execution_attests_decision').ok, false);
});
