// SPDX-License-Identifier: Apache-2.0
//
// EMILIA × LangChain — guard an irreversible tool in one wrapper.
// Runs offline (a local stand-in for the gate) so you can see all three
// outcomes immediately:  node packages/langchain/example.mjs
//
// In production you delete `fetchImpl` and calls go to the live EMILIA gate
// (https://www.emiliaprotocol.ai/api/trust/gate) — nothing else changes.

import { withGuard } from './index.js';

// 1) Any LangChain tool works — StructuredTool, DynamicStructuredTool, or just
//    an object with { name, invoke(input) }. Here: a tool that moves money.
const wireTransfer = {
  name: 'wire_transfer',
  description: 'Send a wire to a bank account.',
  invoke: async ({ amount, destination }) => `wired $${amount.toLocaleString()} to ${destination}`,
};

// 2) A local stand-in for the EMILIA gate so this file runs with zero setup.
//    Delete this (and the `fetchImpl` below) to use the real gate.
const fakeGate = (policy) => async (_url, { body }) => ({
  json: async () => policy(JSON.parse(body).context),
});
const demoPolicy = ({ amount = 0, destination = '' }) => {
  if (destination.includes('sanctioned')) return { decision: 'deny', reason: 'destination on blocklist' };
  if (amount >= 50000) return { decision: 'allow_with_signoff', reason: 'large payment release' };
  return { decision: 'allow' };
};

// 3) Wrap it. One call. The irreversible action now routes through EMILIA first.
const guarded = withGuard(wireTransfer, {
  action: 'payment.release',
  context: (input) => ({ amount: input.amount, destination: input.destination }),
  onSignoff: async (decision) => {
    // Production: block here until a NAMED human approves (Slack, the EP
    // dashboard, the signoff API). Demo: simulate the approval.
    console.log(`   signoff required (${decision.reason}) — simulating CFO approval…`);
  },
  fetchImpl: fakeGate(demoPolicy),
});

async function tryIt(label, input) {
  process.stdout.write(`\n${label}\n  agent -> wire_transfer(${JSON.stringify(input)})\n`);
  try {
    console.log(`  ${await guarded.invoke(input)}`);
  } catch (e) {
    console.log(`  BLOCKED: ${e.message}`);
  }
}

console.log('EMILIA x LangChain — one wrapper guards an irreversible tool');
await tryIt('1) small payment -> allowed', { amount: 200, destination: 'acct_known' });
await tryIt('2) large payment -> human signoff -> released', { amount: 50000, destination: 'acct_new' });
await tryIt('3) blocked destination -> denied', { amount: 1000, destination: 'acct_sanctioned' });
console.log('\nDelete `fetchImpl` to use the live gate. Same wrapper, every irreversible tool.\n');
