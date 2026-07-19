// SPDX-License-Identifier: Apache-2.0
/**
 * Grok + EMILIA Protocol — provably accountable tool use.
 * ───────────────────────────────────────────────────────────────────────────
 * An xAI Grok agent with a high-risk tool (`release_payment`). Before any tool
 * call runs, it is routed through EMILIA's policy engine — the SAME
 * `evaluateGuardPolicy` covered by EMILIA's 26 TLA+ theorems / 35 Alloy facts,
 * imported directly from ../lib/guard-policies.js (not a reimplementation).
 *
 * The agent cannot take the irreversible action until the engine allows it — or,
 * for a high-risk action, a NAMED HUMAN signs off. Safe actions flow friction-free.
 *
 * Works with ANY OpenAI-compatible chat API: set XAI_BASE_URL / XAI_MODEL to
 * point at OpenAI, Together, Fireworks, etc. The accountability layer is identical.
 *
 * SCOPE — read this, because honesty is the whole product: EMILIA's proofs cover
 * the policy ENGINE (no self-approval, no replay, money-destination changes always
 * gated, $50k+ releases gated, …). They do NOT "formally verify Grok." This file
 * is ordinary glue wiring Grok's tool loop to that verified engine.
 *
 * Run:
 *   export XAI_API_KEY=xai-...                              # https://x.ai/api
 *   node examples/grok-guard.mjs                            # pay an $82k invoice → needs signoff
 *   node examples/grok-guard.mjs "refund $30 to order 8812" # low-risk → flows freely
 *
 * (A harmless MODULE_TYPELESS warning may print — Node auto-detecting the engine
 *  as ESM. Ignore it, or run with `node --no-warnings examples/grok-guard.mjs`.)
 */

import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import {
  evaluateGuardPolicy,
  hashCanonicalAction,
  GUARD_ACTION_TYPES,
} from '../lib/guard-policies.js';

const XAI_BASE_URL = process.env.XAI_BASE_URL || 'https://api.x.ai/v1';
const XAI_MODEL = process.env.XAI_MODEL || 'grok-4';
const XAI_API_KEY = process.env.XAI_API_KEY;

if (!XAI_API_KEY) {
  console.error('Set XAI_API_KEY first (get one at https://x.ai/api).');
  process.exit(1);
}

// ── The agent's tools (xAI / OpenAI tool-calling schema). One is irreversible. ──
const tools = [
  {
    type: 'function',
    function: {
      name: 'lookup_invoice',
      description: 'Read-only. Fetch an invoice (amount due, vendor account) by id.',
      parameters: {
        type: 'object',
        properties: { invoice_id: { type: 'string' } },
        required: ['invoice_id'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'release_payment',
      description: 'Release a wire/ACH payment. IRREVERSIBLE — money leaves the account.',
      parameters: {
        type: 'object',
        properties: {
          amount: { type: 'number', description: 'USD amount' },
          destination: { type: 'string', description: 'Destination account id' },
        },
        required: ['amount', 'destination'],
      },
    },
  },
];

// ── Declare which tool calls are accountable, and describe them to the engine. ──
function toGuardInput(name, args) {
  if (name === 'release_payment') {
    return {
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      amount: args.amount,
      currency: 'USD',
      targetChangedFields: [],
      riskFlags: [],
      actorRole: 'ai_agent',
    };
  }
  return null; // read-only / non-accountable tools run freely
}

// ── EMILIA's four primitives, condensed: Eye (see the action) → Handshake (bind ──
// ── it) → Signoff (a named human) → Commit (execute). Here, on the CLI. ─────────
async function humanSignoff(name, args, reasons) {
  const rl = readline.createInterface({ input, output });
  console.log('\n  ────────────────────────────────────────────────────────────');
  console.log('  🛑 EMILIA: this action requires a NAMED HUMAN to sign off.');
  console.log(`     action:   ${name}(${JSON.stringify(args)})`);
  for (const r of reasons) console.log(`     reason:   ${r}`);
  console.log(`     binding:  ${hashCanonicalAction({ name, args }).slice(0, 16)}…  (the exact action a receipt would pin to)`);
  console.log('  ────────────────────────────────────────────────────────────');
  const signer = (await rl.question('     Type your name to APPROVE, or press Enter to DENY: ')).trim();
  rl.close();
  return signer ? { approved: true, signer } : { approved: false };
}

// ── Replace with your real side effects. ──
function execute(name, args) {
  if (name === 'lookup_invoice') {
    return { invoice_id: args.invoice_id, amount_due: 82000, vendor_account: 'acct_9f12', status: 'unpaid' };
  }
  if (name === 'release_payment') {
    return { status: 'released', amount: args.amount, destination: args.destination, ref: `pay_${process.pid}_${args.amount}` };
  }
  return { status: 'ok' };
}

async function callGrok(messages) {
  const res = await fetch(`${XAI_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${XAI_API_KEY}` },
    body: JSON.stringify({ model: XAI_MODEL, messages, tools, tool_choice: 'auto' }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`xAI ${res.status}: ${JSON.stringify(data).slice(0, 300)}`);
  return data.choices?.[0]?.message;
}

async function main() {
  const task =
    process.argv.slice(2).join(' ') ||
    'Look up invoice INV-4421 and pay it in full to the vendor on file.';
  console.log(`\n🤖 Grok (${XAI_MODEL}) — task: ${task}`);

  const messages = [
    { role: 'system', content: 'You are an autonomous treasury agent. Use the tools to complete the task; pay the full amount due.' },
    { role: 'user', content: task },
  ];

  for (let turn = 0; turn < 8; turn++) {
    const msg = await callGrok(messages);
    if (!msg) break;
    messages.push(msg);

    if (!msg.tool_calls?.length) {
      console.log(`\n💬 Grok: ${msg.content}\n`);
      break;
    }

    for (const tc of msg.tool_calls) {
      const name = tc.function.name;
      let args = {};
      try { args = JSON.parse(tc.function.arguments || '{}'); } catch { /* leave {} */ }
      const guardInput = toGuardInput(name, args);
      let result;

      if (!guardInput) {
        result = execute(name, args);
        console.log(`\n  ▶ ${name}(${JSON.stringify(args)}) — read-only, ran freely`);
      } else {
        // guardInput intentionally omits organizationId/actorId/authStrength — evaluateGuardPolicy
        // (lib/guard-policies.js) documents them as required but never reads them.
        const d = evaluateGuardPolicy(/** @type {any} */ (guardInput));
        console.log(`\n  🔎 Grok wants: ${name}(${JSON.stringify(args)})  →  EMILIA decision: ${d.decision}`);

        if (d.decision === 'deny') {
          console.log(`  ⛔ DENIED: ${d.reasons.join(' ')}`);
          result = { error: `BLOCKED by EMILIA: ${d.reasons.join(' ')}` };
        } else if (d.signoffRequired) {
          const s = await humanSignoff(name, args, d.reasons);
          if (!s.approved) {
            console.log('  ⛔ Signoff declined — action blocked.');
            result = { error: 'BLOCKED: human signoff not granted' };
          } else {
            console.log(`  ✅ Signed off by "${s.signer}". Committing.`);
            result = { ...execute(name, args), signed_off_by: s.signer };
          }
        } else {
          console.log('  ✅ Allowed (low-risk) — committed with no friction.');
          result = execute(name, args);
        }
      }

      messages.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify(result) });
    }
  }
}

main().catch((e) => { console.error('\n💥', e.message); process.exit(1); });
