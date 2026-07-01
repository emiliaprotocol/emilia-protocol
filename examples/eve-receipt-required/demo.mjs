// SPDX-License-Identifier: Apache-2.0
//
// Local proof of the Receipt-Required loop for the Eve `release_funds` tool —
// no Eve runtime or network needed. Runs the SAME gate the tool uses
// (lib/guards.mjs), so this is a faithful demo of the deployed behavior:
//
//   1. no receipt        -> BLOCKED (428 challenge, funds not moved)
//   2. human signs        -> RUNS ONCE (funds released, receipt consumed)
//   3. replay same receipt -> BLOCKED (one-time consumption)
//   4. receipt for another account -> BLOCKED (target binding)
//
//   run:  node demo.mjs

import crypto from 'node:crypto';
import { releaseFundsGate, demoMode } from './lib/guards.mjs';

// Canonical JSON — must match the verifier in lib/emilia-gate.mjs.
const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

// Stand-in for a real human device-signoff: mint an EP-RECEIPT-v1 bound to an
// exact action. In production a named human signs this on their own device via
// your EMILIA issuer; the agent never mints its own.
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

const DEST = 'acct-9931';
const bound = releaseFundsGate.boundActionFor(DEST); // funds.release:acct-9931
const doRelease = async () => ({ released: true, amount: 5000, currency: 'USD', destination: DEST });

console.log(`EMILIA × Eve — release_funds demo${demoMode ? ' (demo mode: inline key; set EMILIA_TRUSTED_KEYS in prod)' : ''}`);
console.log(`action bound to: ${bound}\n`);

const r1 = await releaseFundsGate.run(undefined, { target: DEST }, doRelease);
console.log(`1. no receipt          -> ${r1.ok ? 'RAN (BUG!)' : `BLOCKED (${r1.status}) — funds NOT moved`}`);

const receipt = humanApproves(bound);
const r2 = await releaseFundsGate.run(receipt, { target: DEST }, doRelease);
console.log(`2. human signs         -> ${r2.ok ? `RAN ONCE — released $${r2.result.amount} to ${DEST}` : `BLOCKED (${r2.body?.rejected?.reason})`}`);

const r3 = await releaseFundsGate.run(receipt, { target: DEST }, doRelease);
console.log(`3. replay same receipt -> ${r3.ok ? 'RAN (BUG!)' : `BLOCKED (${r3.body.rejected.reason})`}`);

const wrong = humanApproves(releaseFundsGate.boundActionFor('attacker-acct'));
const r4 = await releaseFundsGate.run(wrong, { target: DEST }, doRelease);
console.log(`4. receipt for another acct -> ${r4.ok ? 'RAN (BUG!)' : `BLOCKED (${r4.body.rejected.reason})`}`);

const pass = !r1.ok && r2.ok && !r3.ok && !r4.ok;
console.log(`\n${pass ? 'PASS' : 'FAIL'} — no receipt, no mutation; if it runs, the proof travels.`);
process.exit(pass ? 0 : 1);
