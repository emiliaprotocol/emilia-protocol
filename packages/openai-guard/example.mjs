// SPDX-License-Identifier: Apache-2.0
//
// EMILIA x OpenAI-compatible tool calls - guard an irreversible tool.
// Runs fully offline (a demo issuer signs the receipts) so you see every
// outcome in one go:
//   node packages/openai-guard/example.mjs
//
// For real use: delete the demo issuer, pin YOUR issuer's public key in
// trustedKeys, and feed your model's real `message.tool_calls` (from OpenAI,
// xAI Grok, ...) in.

import crypto from 'node:crypto';
import { runToolCalls } from './index.js';
import { bindToolAction } from '../require-receipt/index.js';

// ---- A demo issuer. In production this is your approval service, and you
// ---- only ever hold its PUBLIC key.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const ISSUER_KEY = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

function mintReceipt(action) {
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomUUID(),
    subject: 'cfo@example.com',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'cfo@example.com' },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url'),
    },
  };
}

// Your tool implementations. A tool with an `action` is irreversible -> gated.
const tools = {
  lookup_invoice: { readOnly: true, fn: async ({ id }) => ({ id, amount_due: 82000 }) },
  release_payment: {
    action: 'payment.release',
    fn: async ({ amount, destination }) => ({ status: 'released', amount, destination }),
  },
};

// The action a receipt must be minted against: the base action PLUS a digest of
// the tool name and the exact arguments that will execute.
const approved = { amount: 82000, destination: 'acct_new' };
const approvedAction = bindToolAction('release_payment', approved, 'payment.release');

// Simulated model output - exactly the shape Grok/OpenAI return.
const call = (id, args) => ({
  id,
  function: { name: 'release_payment', arguments: JSON.stringify(args) },
});

const authorized = mintReceipt(approvedAction);
const results = await runToolCalls(
  [
    call('a', approved),                                        // no receipt
    call('b', approved),                                        // the approved call
    call('c', { amount: 9999999, destination: 'acct_attacker' }), // substituted args
    call('d', approved),                                        // replay
  ],
  tools,
  {
    trustedKeys: [ISSUER_KEY],
    receipts: {
      b: authorized,
      // A freshly signed receipt for the SAME bound action, spent on other
      // arguments. The digest does not match, so it buys nothing.
      c: mintReceipt(approvedAction),
      d: authorized,
    },
  },
);

console.log('EMILIA x OpenAI-compatible tool calls - one helper guards the whole loop:\n');
console.log('  1) no receipt              ->', results[0].content);
console.log('  2) receipt bound to $82k   ->', results[1].content);
console.log('  3) same action, other args ->', results[2].content);
console.log('  4) replay of receipt 2     ->', results[3].content);
console.log('\nThe action a receipt authorizes is:\n  ' + approvedAction);
console.log('\nReal use: pin your issuer in trustedKeys and pass your model\'s real tool_calls.\n');
