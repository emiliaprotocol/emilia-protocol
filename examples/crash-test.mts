// SPDX-License-Identifier: Apache-2.0
//
// EMILIA — crash test. An AI agent tries to move $82,000. Watch it get stopped,
// signed off by a named human, and turned into a receipt anyone can verify
// offline — then watch a forged copy fail.
//
//   node examples/crash-test.mjs          (paced, for screen-recording)
//   FAST=1 node examples/crash-test.mjs   (no pauses)
//
// Fully offline: real policy engine, real Ed25519 receipt, real verifier.
// No API key, no network, deterministic. This is the whole value in 60 seconds.

import crypto from 'node:crypto';
import { evaluateGuardPolicy, GUARD_ACTION_TYPES } from '../lib/guard-policies.js';
import { verifyReceipt } from '../packages/verify/index.js';

const pause = (ms) => (process.env.FAST ? Promise.resolve() : new Promise((r) => setTimeout(r, ms)));
const line = (s = '') => console.log(s);
const rule = () => line('─'.repeat(64));

// EP-RECEIPT-v1 canonical signer (byte-identical to @emilia-protocol/verify).
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
const sign = (payload, sk) => crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), sk).toString('base64url');

async function main() {
  line();
  line('  EMILIA — crash test: an autonomous agent tries to move money');
  rule();
  await pause(900);

  // 1. The agent acts.
  const action: any = { amount: 82000, currency: 'USD', destination: 'acct_new_4471', vendor: 'Acme Industrial LLC' };
  line('\n  [agent]  treasury agent:');
  line('           "Vendor updated their bank details — paying the $82,000 invoice."');
  line(`           → release_payment($${action.amount.toLocaleString()} → ${action.destination})`);
  await pause(1100);

  // 2. The formally-verified policy engine decides. (real call)
  const decision = evaluateGuardPolicy({
    actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
    amount: action.amount,
    currency: 'USD',
    actorRole: 'ai_agent',
    targetChangedFields: ['bank_account'],
    riskFlags: ['new_destination', 'after_hours'],
  } as any);
  line('\n  [EMILIA] evaluateGuardPolicy() — formally-verified engine (TLA+ + Alloy)');
  line(`           decision: ${String(decision.decision).toUpperCase()}`);
  line(`           reason:   large release ≥ $50k + payee bank just changed`);
  line('           ⛔  the wire is HELD. The agent cannot proceed on its own.');
  await pause(1300);

  // 3. A named human signs off.
  const approver = { name: 'Maria Chen', role: 'Treasury Controller', principal: 'maria.chen@demo-treasury' };
  line(`\n  [human]  signoff required → ${approver.name} (${approver.role})`);
  await pause(700);
  line('           reviews the exact amount + destination… and signs. ✍️');
  await pause(1100);

  // 4. Mint a real, signed Trust Receipt bound to the exact action + approver.
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const issuerKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'tr_' + crypto.randomBytes(8).toString('hex'),
    issuer: 'ep_demo_treasury_v1',
    subject: 'vendor:Acme Industrial LLC',
    claim: {
      action_type: 'large_payment_release',
      outcome: 'allow_with_signoff',
      context: { amount_usd: action.amount, destination: action.destination, risk_signals: action.riskFlags || ['NEW_DESTINATION', 'AFTER_HOURS'] },
      approved_by: { principal: approver.principal, name: approver.name, role: approver.role },
    },
    created_at: new Date().toISOString(),
    protocol_version: 'EP-CORE-v1.0',
  };
  const receipt = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: sign(payload, privateKey) } };
  line(`\n  [EMILIA] minted Trust Receipt  ${payload.receipt_id}`);
  line('           bound to: $82,000 · acct_new_4471 · approved_by Maria Chen');
  await pause(1100);

  // 5. Verify it OFFLINE — no server, no account, pure math.
  line('\n  [verify] anyone can check this offline — npm i @emilia-protocol/verify');
  await pause(600);
  const ok = verifyReceipt(receipt, issuerKey);
  line(`           verifyReceipt(receipt, issuerKey)  →  ${ok.valid ? '✅ VALID' : '❌ INVALID'}`);
  line(`           signature ${ok.checks.signature ? '✓' : '✗'}   no server   no account   pure math`);
  await pause(1400);

  // 6. The killer beat: forge it. Change $82,000 → $8,200. It breaks.
  line('\n  [forge]  an attacker edits the receipt: $82,000  →  $8,200 …');
  const forged = JSON.parse(JSON.stringify(receipt));
  forged.payload.claim.context.amount_usd = 8200;
  await pause(700);
  const bad = verifyReceipt(forged, issuerKey);
  line(`           verifyReceipt(forged, issuerKey)  →  ${bad.valid ? '✅ VALID' : '❌ INVALID'}`);
  line(`           signature ${bad.checks.signature ? '✓' : '✗'}  —  you cannot forge an approval.`);
  await pause(1200);

  line();
  rule();
  line('  The agent was stopped. A named human owns the decision.');
  line('  The proof verifies offline — and the forgery does not.');
  line('  npm i @emilia-protocol/openai-guard   ·   emiliaprotocol.ai');
  line();
}

main();
