// SPDX-License-Identifier: Apache-2.0
//
// Shared kit for the three canonical MCP examples. Models a tiny MCP tool
// dispatcher whose irreversible tools REFUSE to run without a valid
// EP-RECEIPT-v1, and proves the receipt offline with the REAL verifier from
// @emilia-protocol/require-receipt — no API, no key, no EP server trusted.
//
// The loop every example runs:
//   1. Agent calls the dangerous tool with NO receipt        -> refused (fail-closed)
//   2. A named human signs the exact action                  -> EP-RECEIPT-v1 (Ed25519)
//   3. Agent retries WITH the receipt                         -> tool runs
//   4. A tampered receipt is rejected                         -> refused (fail-closed)

import crypto from 'node:crypto';
import { verifyEmiliaReceipt, receiptChallenge } from '../../packages/require-receipt/index.js';

const FAST = !!process.env.FAST;
const pause = (ms) => (FAST ? Promise.resolve() : new Promise((r) => setTimeout(r, ms)));
export const line = (s = '') => console.log(s);
const rule = () => line('─'.repeat(66));

// EP-RECEIPT-v1 canonical signer (byte-identical to @emilia-protocol/verify).
const canonicalize = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
      : JSON.stringify(v));

// A named human's device signs the EXACT action. Here we mint the receipt
// locally with an inline key so the demo is self-contained; in production this
// is produced by a real Face ID / passkey signoff on the approver's device.
function signAction(action, { approver, tamper = false } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver },
  };
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
  if (tamper) doc.payload = { ...payload, claim: { ...payload.claim, action_type: 'something.harmless' } };
  return doc;
}

// The MCP tool dispatcher. `irreversible` tools require a receipt bound to
// `action`; everything else passes straight through. The verifier is real.
export function makeGuardedServer({ tool, action }) {
  return async function callTool(name, args = {}, receipt = null) {
    if (name !== tool) return { status: 200, body: { ran: true, note: 'reversible/read-only tool — passed through' } };
    if (!receipt) {
      return { status: 402, body: receiptChallenge(action, `MCP tool "${tool}" is irreversible — no EMILIA receipt presented.`) };
    }
    const v = verifyEmiliaReceipt(receipt, { allowInlineKey: true, action, maxAgeSec: 900 });
    if (!v.ok) {
      return { status: 402, body: { ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`), rejected: v } };
    }
    return { status: 200, body: { ran: true, action, ...args, evidence: { receipt_id: v.receipt_id, approver: v.outcome, signer: v.signer } } };
  };
}

const show = (r) => line(`     ← ${r.status} ${r.status === 402 ? (r.body.title || 'REFUSED') : 'OK — tool ran'}${r.body.rejected ? ` (${r.body.rejected.reason})` : ''}`);

// Runs the full 4-step demo for one dangerous tool.
export async function runDemo({ title, tool, action, args, approver, agentLine }) {
  const server = makeGuardedServer({ tool, action });
  line();
  line(`  ${title}`);
  rule();
  await pause(700);

  line(`\n  [agent]  ${agentLine}`);
  line(`           → ${tool}(${Object.entries(args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')})`);
  await pause(900);

  line('\n  1. Agent calls the tool with NO receipt');
  let res = await server(tool, args, null);
  show(res);
  line(`     challenge: bring an ${res.body?.required?.header || 'EP-RECEIPT-v1'} bound to "${res.body?.required?.action || action}"`);
  await pause(1000);

  line(`\n  2. A named human reviews the exact action and signs it (${approver})`);
  const receipt = signAction(action, { approver });
  line(`     receipt_id ${receipt.payload.receipt_id} · outcome ${receipt.payload.claim.outcome}`);
  await pause(900);

  line('\n  3. Agent retries WITH the receipt');
  res = await server(tool, args, receipt);
  show(res);
  if (res.status === 200) line(`     tool performed; evidence ${res.body.evidence.receipt_id} verifies offline, trusting no one`);
  await pause(900);

  line('\n  4. A forged receipt (a signed field altered) is presented');
  res = await server(tool, args, signAction(action, { approver, tamper: true }));
  show(res);

  line('\n  No receipt, no irreversible action. If it ran, anyone can verify who authorized exactly what.');
  line();
}
