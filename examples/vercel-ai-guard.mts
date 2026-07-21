// SPDX-License-Identifier: Apache-2.0
//
// EMILIA × Vercel AI SDK — guard a tool's execute() with a verified-human gate.
//
// `withEmiliaGuard(tool, { action, context })` wraps any AI SDK tool so the
// irreversible ones route through EMILIA before they run: allowed → execute,
// otherwise the tool returns a { blocked, reason } result the model can relay
// ("that needs human sign-off") instead of doing the action. Opt-in, and a
// no-op for any tool you don't wrap.
//
// In your project: import { guard } from '@emilia-protocol/openai-guard';
// (here we import the local path so this file is runnable from the repo.)

import { guard } from '../packages/openai-guard/index.js';

/**
 * Wrap a Vercel AI SDK tool so its execute() is gated by EMILIA.
 * @param {object} tool  an AI SDK tool ({ description, parameters, execute })
 * @param {object} o     { action, context, apiKey?, gateUrl?, fetchImpl? }
 *   action/context may be values or (args) => value.
 */
export function withEmiliaGuard(tool: any, { action, context, ...opts }: { action?: any; context?: any; [k: string]: any } = {}) {
  if (!tool || typeof tool.execute !== 'function') return tool;
  if (!action) throw new Error('withEmiliaGuard: { action } is required');
  const original = tool.execute;
  return {
    ...tool,
    execute: async (args: any, ctx: any) => {
      const decision = await guard({
        action: typeof action === 'function' ? action(args) : action,
        context: typeof context === 'function' ? context(args) : context,
        ...opts,
      });
      if (!decision.allowed) {
        return { blocked: true, reason: decision.reason, decision: decision.decision };
      }
      return original(args, ctx);
    },
  };
}

/* ---------------------------------------------------------------------------
 * Real usage (uncomment in a project that has `ai`, `@ai-sdk/openai`, `zod`):
 *
 *   import { openai } from '@ai-sdk/openai';
 *   import { generateText, tool } from 'ai';
 *   import { z } from 'zod';
 *
 *   const releasePayment = withEmiliaGuard(
 *     tool({
 *       description: 'Release a payment',
 *       parameters: z.object({ amount: z.number(), destination: z.string() }),
 *       execute: async ({ amount, destination }) => bank.wire(amount, destination),
 *     }),
 *     { action: 'payment.release', context: (a) => ({ amount: a.amount, destination: a.destination }), apiKey: process.env.EP_API_KEY },
 *   );
 *
 *   await generateText({ model: openai('gpt-4o'), tools: { releasePayment }, prompt });
 *   // high-stakes calls now require a human; everything else is untouched.
 * ------------------------------------------------------------------------- */

// --- offline self-test (run: node examples/vercel-ai-guard.mjs) ---
if (import.meta.url === `file://${process.argv[1]}`) {
  const fakeGate = (policy) => async (_url, { body }) => ({ ok: true, json: async () => policy(JSON.parse(body).context) });
  const policy = ({ amount = 0 }) => (amount >= 50000 ? { decision: 'allow_with_signoff', reason: 'large payment release' } : { decision: 'allow' });

  const tool = {
    description: 'Release a payment',
    parameters: {},
    execute: async ({ amount, destination }) => ({ status: 'released', amount, destination }),
  };
  const guarded = withEmiliaGuard(tool, {
    action: 'payment.release',
    context: (a) => ({ amount: a.amount }),
    fetchImpl: fakeGate(policy),
  });

  console.log('small ($200):', JSON.stringify(await guarded.execute({ amount: 200, destination: 'acct_known' })));
  console.log('large ($84k):', JSON.stringify(await guarded.execute({ amount: 84000, destination: 'acct_new' })));
}
