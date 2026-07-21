// SPDX-License-Identifier: Apache-2.0
//
// The Eve "Receipt Required" kit must gate its dangerous tools: no receipt -> blocked,
// valid+bound -> runs once, replay -> blocked, wrong-target -> blocked. Runs the SAME
// gate the Eve tool files import (examples/eve-receipt-required/lib/guards.mjs).

import { test, expect } from 'vitest';
import crypto from 'node:crypto';
import { releaseFundsGate } from '../examples/eve-receipt-required/lib/guards.mjs';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

function humanApproves(actionType) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:ops-bot',
    created_at: new Date().toISOString(),
    claim: { action_type: actionType, outcome: 'allow_with_signoff', approver: 'cfo@yourco.example' },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
}

test('release_funds gate: block / run-once / replay-block / wrong-target-block', async () => {
  const DEST = 'acct-9931';
  const bound = releaseFundsGate.boundActionFor(DEST);
  const run = () => ({ released: true });

  const r1 = await releaseFundsGate.run(undefined, { target: DEST }, run);
  expect(r1.ok).toBe(false);
  expect(r1.status).toBe(428);

  const receipt = humanApproves(bound);
  const r2 = await releaseFundsGate.run(receipt, { target: DEST }, run);
  expect(r2.ok).toBe(true);

  const r3 = await releaseFundsGate.run(receipt, { target: DEST }, run);
  expect(r3.ok).toBe(false);
  expect(r3.body.rejected.reason).toBe('replay_refused');

  const wrong = humanApproves(releaseFundsGate.boundActionFor('attacker-acct'));
  const r4 = await releaseFundsGate.run(wrong, { target: DEST }, run);
  expect(r4.ok).toBe(false);
  expect(r4.body.rejected.reason).toBe('action_mismatch');
});
