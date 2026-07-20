// SPDX-License-Identifier: Apache-2.0
//
// EMILIA — async / high-volume signoff pattern (runnable, offline).
//
//   node examples/async-signoff.mjs
//
// Answers the question: how does pre-execution signoff handle async + high-volume
// flows without blocking the agent loop?
//
//   1. The gate is SELECTIVE — most tool calls resolve to `allow` at the policy
//      check (the real evaluateGuardPolicy engine) and execute immediately.
//   2. Only irreversible actions open a handshake. Instead of blocking, the call
//      returns a `signoff_id` and the agent PARKS that one action as "pending"
//      and keeps processing the rest of the batch.
//   3. A named human approves out-of-band (here: a local stand-in for the live
//      /api/v1/signoffs/* backend). The parked action then consumes + executes.
//
// The SignoffStore below simulates EMILIA's hosted signoff backend so this runs
// with zero setup; in production those are real API calls (mintReceipt →
// requestSignoff → approveSignoff in `@emilia-protocol/openai-guard/receipt`).

import { evaluateGuardPolicy, GUARD_ACTION_TYPES } from '../lib/guard-policies.js';

// --- local stand-in for /api/v1/signoffs/* (out-of-band approval) ---
class SignoffStore {
  constructor() { this.pending = new Map(); }
  request(receiptId, call) {
    const id = `sig_${receiptId}`;
    // each handshake is nonce + action-hash bound; approvals carry a TTL.
    this.pending.set(id, { call, status: 'pending', expiresAt: 'now+4h' });
    return id;
  }
  approve(id) { const s = this.pending.get(id); if (s) s.status = 'approved'; }
  status(id) { return this.pending.get(id)?.status; }
}

// Map a tool call to the real policy engine; null actionType = read-only/allow.
function decide(call) {
  if (call.name === 'release_payment') {
    // This demo classifier doesn't carry tenant/actor/auth-strength context yet;
    // evaluateGuardPolicy tolerates the other fields being absent at runtime
    // (basePolicy defaults them via `|| []`/optional-chaining) — cast only.
    return evaluateGuardPolicy(/** @type {Parameters<typeof evaluateGuardPolicy>[0]} */ (/** @type {unknown} */ ({
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      amount: call.args.amount,
      actorRole: 'ai_agent',
      targetChangedFields: [],
      riskFlags: [],
    })));
  }
  return { decision: 'allow', signoffRequired: false }; // lookups, reads, low-risk
}

const store = new SignoffStore();
const parked = [];
let ranImmediately = 0;

// A high-volume batch — mostly pass-through, one irreversible action.
const batch = [
  { id: 1, name: 'lookup_invoice', args: { invoice: 'INV-1' } },
  { id: 2, name: 'release_payment', args: { amount: 200, destination: 'acct_a' } },   // small → allow
  { id: 3, name: 'release_payment', args: { amount: 90000, destination: 'acct_b' } }, // large → signoff
  { id: 4, name: 'lookup_invoice', args: { invoice: 'INV-2' } },
  { id: 5, name: 'release_payment', args: { amount: 1200, destination: 'acct_c' } },  // small → allow
  { id: 6, name: 'lookup_invoice', args: { invoice: 'INV-3' } },
];

console.log('\n— processing batch (the loop never blocks) —');
for (const call of batch) {
  const d = decide(call);
  const gated = d.signoffRequired || d.decision === 'allow_with_signoff' || d.decision === 'deny';
  if (gated && d.decision !== 'deny') {
    const sigId = store.request(`tr_${call.id}`, call);
    parked.push({ call, sigId });
    console.log(`  #${call.id} ${call.name}($${call.args.amount}) → PARKED, returns ${sigId}; agent keeps going`);
  } else if (d.decision === 'deny') {
    console.log(`  #${call.id} ${call.name} → denied by policy`);
  } else {
    ranImmediately++;
    console.log(`  #${call.id} ${call.name}${call.args.amount ? `($${call.args.amount})` : ''} → executed immediately`);
  }
}
console.log(`\n${ranImmediately}/${batch.length} ran without a human; ${parked.length} parked for signoff. Nothing blocked.\n`);

// ...minutes later, out-of-band, the named human approves (Slack/dashboard)...
console.log('— named human approves out-of-band —');
for (const { sigId } of parked) store.approve(sigId);

console.log('— parked actions resume on approval (atomic consume → execute) —');
for (const { call, sigId } of parked) {
  if (store.status(sigId) === 'approved') {
    console.log(`  ${sigId}: approved → executing ${call.name}($${call.args.amount})`);
  }
}
console.log('\nSelective gating + async signoff_id + out-of-band approval = high volume stays unblocked,');
console.log('irreversible actions still wait for a named human. Production: mintReceipt → requestSignoff →');
console.log('approveSignoff in @emilia-protocol/openai-guard/receipt.\n');
