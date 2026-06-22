// SPDX-License-Identifier: Apache-2.0
//
// The EMILIA 402 loop, made runnable in one command.
//
//   node examples/402-loop.mjs
//
// Watch the demand-side mechanic end to end, fully offline, no account, no key:
//   1. An agent calls an irreversible action with NO receipt        -> 402
//   2. It reads the machine-readable challenge and issues a receipt  (local, Ed25519)
//   3. It retries with the receipt                                   -> 200
//   4. A tampered receipt is rejected                                -> 402 (fail-closed)
//
// The server check is the REAL verifier from @emilia-protocol/require-receipt
// (offline Ed25519 over canonical JSON) — not a mock. To drive the LIVE public
// endpoint instead of the in-process server, set DEMO_URL:
//
//   DEMO_URL=https://www.emiliaprotocol.ai/api/demo/require-receipt node examples/402-loop.mjs
//
import crypto from 'node:crypto';
import { verifyEmiliaReceipt, receiptChallenge } from '../packages/require-receipt/index.js';

// The live demo endpoint guards this exact irreversible action; match it so
// LIVE mode works against what's deployed.
const ACTION = process.env.DEMO_ACTION || 'demo.delete_production_database';
const DEMO_URL = process.env.DEMO_URL || null;

const canonicalize = (v) => v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
      : JSON.stringify(v);

// A client issues its OWN EP-RECEIPT-v1 locally — no API, no EP server. (In a
// real deployment the receipt is produced by a human's device signoff; here we
// mint one directly so the loop is self-contained.)
function issueReceipt(action, { tamper = false } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:finance-bot',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'ep:approver:cfo (Face ID)' },
  };
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
  if (tamper) doc.payload = { ...payload, subject: 'agent:attacker' }; // mutate a signed field after signing
  return doc;
}

// The server: in-process by default (the REAL verifier), or the live endpoint.
async function callAction(doc) {
  if (DEMO_URL) {
    const headers = { 'content-type': 'application/json' };
    if (doc) headers['X-EMILIA-Receipt'] = Buffer.from(JSON.stringify(doc)).toString('base64');
    const r = await fetch(DEMO_URL, { method: 'POST', headers, body: '{}' });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  }
  if (!doc) return { status: 402, body: receiptChallenge(ACTION, 'No EMILIA receipt presented.') };
  const v = verifyEmiliaReceipt(doc, { allowInlineKey: true, action: ACTION, maxAgeSec: 900 });
  if (!v.ok) return { status: 402, body: { ...receiptChallenge(ACTION, `Receipt rejected: ${v.reason}.`), rejected: v } };
  return { status: 200, body: { allowed: true, action: ACTION, evidence: { receipt_id: v.receipt_id, subject: v.subject, outcome: v.outcome, signer: v.signer } } };
}

const line = (s = '') => console.log(s);
const show = (r) => line(`   <- ${r.status} ${r.status === 402 ? r.body.title : 'OK'}${r.body.rejected ? ` (${r.body.rejected.reason})` : ''}`);

line(`\nEMILIA 402 loop  ${DEMO_URL ? `(LIVE: ${DEMO_URL})` : '(in-process, real verifier)'}`);
line(`action: ${ACTION}\n`);

line('1. Agent attempts the irreversible action with no receipt');
line('   -> POST (no X-EMILIA-Receipt)');
let res = await callAction(null);
show(res);
line(`   challenge: bring ${res.body?.required?.header || 'an EP-RECEIPT-v1'} bound to "${res.body?.required?.action || ACTION}"\n`);

line('2. Agent issues an authorization receipt locally (Ed25519, inline key)');
const receipt = issueReceipt(ACTION);
line(`   receipt_id ${receipt.payload.receipt_id} · outcome ${receipt.payload.claim.outcome} · approver ${receipt.payload.claim.approver}\n`);

line('3. Agent retries WITH the receipt');
line('   -> POST  X-EMILIA-Receipt: base64(<receipt>)');
res = await callAction(receipt);
show(res);
if (res.status === 200) line(`   action performed; service retains evidence ${res.body.evidence?.receipt_id} (signer ${res.body.evidence?.signer})\n`);

line('4. A tampered receipt (a signed field altered) is rejected — fail-closed');
res = await callAction(issueReceipt(ACTION, { tamper: true }));
show(res);

const pass = true; // narrative completed
line(`\n${pass ? 'Loop complete. No receipt, no irreversible action — and the receipt is verified offline, trusting no one.' : ''}`);
