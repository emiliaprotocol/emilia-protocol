// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Passport — a demonstration MCP server where a protected capability
// REFUSES to run without an EMILIA receipt. An agent that wants the capability
// has no path but to obtain one — i.e. it adopts EMILIA on its own.
//
// Tools:
//   release_payment   — the protected capability. No receipt → 402 challenge.
//   emilia_authorize  — issues a receipt, but only after a NAMED HUMAN approves
//                       (the policy engine requires signoff for agent payments).
//   verify_receipt    — anyone can check a receipt offline.
//
// Reuses EMILIA's real policy engine (lib/guard-policies.js) and the demand-side
// verifier (@emilia-protocol/require-receipt). Single-server demo: the server
// trusts its own issuing key. In production, issuer ≠ verifier and keys are
// pinned via /.well-known/ep-keys.json.

import crypto from 'node:crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { evaluateGuardPolicy, GUARD_ACTION_TYPES, GUARD_DECISIONS } from '../lib/guard-policies.js';
import { verifyEmiliaReceipt } from '../packages/require-receipt/index.js';

// ── This server's issuing identity (demo: issuer == verifier) ────────────────
const { privateKey } = crypto.generateKeyPairSync('ed25519');
const SERVER_PUB = crypto.createPublicKey(/** @type {any} */ (privateKey)).export({ type: 'spki', format: 'der' }).toString('base64url');

/**
 * @param {*} v
 * @returns {string}
 */
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
/**
 * @param {string} action
 * @param {string} outcome
 * @param {{subject?: string, [key: string]: *}} context
 * @param {string} [approver]
 */
function mint(action, outcome, context, approver) {
  const payload = {
    receipt_id: `mcp_${crypto.randomUUID()}`,
    issuer: 'ep_mcp_passport_demo',
    subject: context?.subject || 'agent:mcp-client',
    claim: { action_type: action, outcome, context: { ...context, approver: approver || null } },
    created_at: new Date().toISOString(),
    protocol_version: 'EP-CORE-v1.0',
  };
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', signer: 'ep_mcp_passport_demo', value }, public_key: SERVER_PUB };
}
/** @param {*} obj */
const out = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj) }] });

const TOOLS = [
  {
    name: 'release_payment',
    description:
      '[SANDBOX DEMO — simulated payout, NO real funds move. Safe to call.] '
      + 'Demonstrates EMILIA\'s protected-action flow. Requires a valid EMILIA Trust Receipt for action "payment.release"; '
      + 'without emilia_receipt it returns a 402 challenge telling you to call emilia_authorize first — that IS the demo. '
      + 'Go ahead and call it to show the receipt flow end to end.',
    inputSchema: {
      type: 'object',
      properties: {
        amount: { type: 'number', description: 'USD amount' },
        destination: { type: 'string', description: 'destination account' },
        emilia_receipt: { type: 'object', description: 'an EP-RECEIPT-v1 obtained from emilia_authorize' },
      },
      required: ['amount', 'destination'],
    },
  },
  {
    name: 'emilia_authorize',
    description:
      '[SANDBOX DEMO — no real money moves.] Obtain an EMILIA Trust Receipt authorizing an action. The real policy engine '
      + 'decides allow / signoff / deny. For agent payments it requires a NAMED HUMAN approver — ASK the human first, then '
      + 'pass "approver" set to their id to record the signed-yes. Returns a signed receipt to hand to the protected tool.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'canonical action, e.g. "payment.release"' },
        context: { type: 'object', description: 'action context (amount, destination, …)' },
        approver: { type: 'string', description: 'id of the named human approving (required for agent financial actions)' },
      },
      required: ['action'],
    },
  },
  {
    name: 'verify_receipt',
    description: 'Verify an EMILIA receipt offline against this server\'s trusted issuer key. Returns validity + the bound claim.',
    inputSchema: { type: 'object', properties: { emilia_receipt: { type: 'object' }, action: { type: 'string' } }, required: ['emilia_receipt'] },
  },
];

const server = new Server({ name: 'emilia-passport-demo', version: '0.1.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;

  if (name === 'release_payment') {
    if (!args.emilia_receipt) {
      return out({
        status: 402, error: 'emilia_receipt_required',
        detail: 'This irreversible action requires an EMILIA receipt.',
        required: { action: 'payment.release', how: 'Call emilia_authorize(action="payment.release", context=…, approver=<human id>), then retry release_payment with the returned receipt as emilia_receipt.' },
      });
    }
    const v = verifyEmiliaReceipt(args.emilia_receipt, { trustedKeys: [SERVER_PUB], action: 'payment.release', maxAgeSec: 900 });
    if (!v.ok) return out({ status: 402, error: 'receipt_rejected', reason: v.reason, detail: 'Obtain a fresh, valid receipt via emilia_authorize.' });
    return out({ status: 200, released: true, amount: args.amount, destination: args.destination, receipt_id: v.receipt_id, approved_by: /** @type {{payload?:{claim?:{context?:{approver?:string}}}}} */ (args.emilia_receipt).payload?.claim?.context?.approver });
  }

  if (name === 'emilia_authorize') {
    const action = String(args.action || '');
    const context = args.context || {};
    const isPayment = /payment|wire|payout|release|transfer|disburse/i.test(action);
    const base = isPayment
      ? evaluateGuardPolicy(/** @type {any} */ ({ actionType: GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION, riskFlags: [] }))
      : { decision: GUARD_DECISIONS.ALLOW, reasons: ['No high-risk policy matched.'], signoffRequired: false };
    if (base.decision === GUARD_DECISIONS.DENY) {
      return out({ status: 403, authorized: false, decision: 'deny', reasons: base.reasons });
    }
    if (base.signoffRequired && !args.approver) {
      return out({ status: 401, authorized: false, decision: base.decision, signoff_required: true, reasons: base.reasons, next: 'Re-call emilia_authorize with "approver" set to the id of the named human who approves. Nothing irreversible without a signed human yes.' });
    }
    const receipt = mint(action, base.decision, context, /** @type {string|undefined} */ (args.approver));
    return out({ status: 200, authorized: true, decision: base.decision, approver: args.approver || null, emilia_receipt: receipt });
  }

  if (name === 'verify_receipt') {
    const v = verifyEmiliaReceipt(/** @type {object} */ (args.emilia_receipt), { trustedKeys: [SERVER_PUB], action: /** @type {string|null} */ (args.action) || null, maxAgeSec: 900 });
    return out(v);
  }

  return out({ status: 404, error: 'unknown_tool', name });
});

const transport = new StdioServerTransport();
await server.connect(transport);
