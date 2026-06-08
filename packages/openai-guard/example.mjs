// SPDX-License-Identifier: Apache-2.0
//
// EMILIA × OpenAI-compatible tool calls — guard an irreversible tool.
// Runs offline (a local stand-in for the gate) so you see all three outcomes:
//   node packages/openai-guard/example.mjs
//
// For real use: pass { apiKey: process.env.EP_API_KEY }, delete fetchImpl, and
// feed your model's real `message.tool_calls` (from OpenAI, xAI Grok, …) in.

import { runToolCalls } from './index.js';

// A local stand-in for the EMILIA gate, so this file runs with zero setup.
const fakeGate = (policy) => async (_url, { body }) => ({ json: async () => policy(JSON.parse(body).context) });
const demoPolicy = ({ amount = 0, destination = '' }) => {
  if (String(destination).includes('sanctioned')) return { decision: 'deny', reason: 'destination on blocklist' };
  if (amount >= 50000) return { decision: 'allow_with_signoff', reason: 'large payment release >= $50k' };
  return { decision: 'allow' };
};

// Your tool implementations. Tools with an `action` are irreversible → gated.
const tools = {
  lookup_invoice: { fn: async ({ id }) => ({ id, amount_due: 82000, vendor: 'acct_new' }) }, // read-only → ungated
  release_payment: {
    action: 'payment.release',
    context: (a) => ({ amount: a.amount, destination: a.destination }),
    fn: async ({ amount, destination }) => ({ status: 'released', amount, destination }),
  },
};

// Simulated model output — exactly the shape Grok/OpenAI return in message.tool_calls.
const toolCalls = [
  { id: 'a', function: { name: 'release_payment', arguments: JSON.stringify({ amount: 200, destination: 'acct_known' }) } },
  { id: 'b', function: { name: 'release_payment', arguments: JSON.stringify({ amount: 82000, destination: 'acct_new' }) } },
  { id: 'c', function: { name: 'release_payment', arguments: JSON.stringify({ amount: 1000, destination: 'acct_sanctioned' }) } },
];

const results = await runToolCalls(toolCalls, tools, {
  actor: 'grok-agent',
  onSignoff: async (d) => {
    console.log(`   signoff required (${d.reason}) — simulating a named human approving…`);
    return true; // return false to reject
  },
  fetchImpl: fakeGate(demoPolicy),
});

console.log('EMILIA x OpenAI-compatible tool calls — one helper guards the whole loop:\n');
console.log('  1) $200 to known acct      ->', results[0].content);
console.log('  2) $82,000 (>= $50k)       ->', results[1].content);
console.log('  3) $1,000 to sanctioned    ->', results[2].content);
console.log('\nReal use: { apiKey: process.env.EP_API_KEY } + your model\'s real tool_calls. Same helper.\n');
