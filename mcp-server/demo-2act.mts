// SPDX-License-Identifier: Apache-2.0
//
// EMILIA — recordable 2-act demo of the passport flow over REAL MCP stdio.
// An AI agent is told to move $50,000, hits a wall, and adopts EMILIA on its
// own: a named human signs off, a receipt is minted, the payment releases —
// and a forged receipt is rejected. Drives the actual passport-demo.mjs server.
//
//   Record (~70s):   node --no-warnings mcp-server/demo-2act.mjs
//   Smoke (instant): EMILIA_DEMO_SPEED=0 node --no-warnings mcp-server/demo-2act.mjs
//   Tune pacing:     EMILIA_DEMO_SPEED=0.5 node --no-warnings mcp-server/demo-2act.mjs

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const RAW = process.env.EMILIA_DEMO_SPEED;
const SPEED = RAW !== undefined && Number.isFinite(Number(RAW)) ? Number(RAW) : 1;
/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms * SPEED)));

const A = {
  reset: '\x1b[0m', bold: '\x1b[1m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', gold: '\x1b[38;5;178m', gray: '\x1b[90m',
};
/** @param {string} s */
const w = (s) => process.stdout.write(s);
const log = (s = '') => w(s + '\n');
/**
 * @param {keyof typeof A} col
 * @param {string} s
 */
const c = (col, s) => A[col] + s + A.reset;
/** @param {keyof typeof A} [col] */
const rule = (col = 'gray') => log(c(col, '  ' + '─'.repeat(70)));

/** @param {string} s */
async function agentSays(s) { w(c('cyan', '  agent ▸ ') + s + '\n'); await sleep(700); }
/**
 * @param {keyof typeof A} col
 * @param {string} s
 */
async function server(col, s) { w(c(col, '       ← ') + s + '\n'); await sleep(950); }

const here = dirname(fileURLToPath(import.meta.url));
const transport = new StdioClientTransport({ command: 'node', args: ['--no-warnings', join(here, 'passport-demo.mjs')] });
const agent = new Client({ name: 'demo-agent', version: '1.0.0' }, { capabilities: {} });
await agent.connect(transport);
/**
 * @param {string} name
 * @param {Record<string, unknown>} args
 */
const call = async (name, args) => {
  const result = await agent.callTool({ name, arguments: args }) as unknown as { content: Array<{ text: string }> };
  return JSON.parse(result.content[0].text);
};

// ── Title card ───────────────────────────────────────────────────────────
log();
log(c('gold', A.bold + '  EMILIA') + c('gray', '   ·   the accountability layer for AI agents'));
log(c('gray', '  A human signs off before the agent does anything irreversible.'));
log();
await sleep(1200);
log(c('bold', '  Scenario:') + ' an autonomous agent has been told to release ' + c('bold', '$50,000') + '.');
log(c('gray', '  It is connected to the EMILIA Passport MCP server. Watch what happens.'));
await sleep(1300);

// ── ACT I — the wall ─────────────────────────────────────────────────────
log();
rule('gold');
log(c('gold', A.bold + '  ACT I') + c('gold', '    The wall'));
rule('gold');
await sleep(700);

await agentSays('release_payment(' + c('gray', 'amount: 50000, destination: acct_9f12') + ')');
let r = await call('release_payment', { amount: 50000, destination: 'acct_9f12' });
await server('red', A.bold + r.status + ' ' + r.error + A.reset + c('gray', '  — it has no receipt'));
await server('gray', 'the server tells it exactly how: ' + A.reset + '"' + (r.required?.how || '') + '"');

await agentSays('emilia_authorize(' + c('gray', "action: 'payment.release', …") + ')   ' + c('gray', '(no human yet)'));
r = await call('emilia_authorize', { action: 'payment.release', context: { amount: 50000, destination: 'acct_9f12' } });
await server('yellow', A.bold + 'signoff_required' + A.reset + c('gray', ' — ' + (r.reasons?.join(' ') || '')));
await server('gray', '"' + (r.next || '') + '"');

// ── ACT II — the sign-off ────────────────────────────────────────────────
log();
rule('green');
log(c('green', A.bold + '  ACT II') + c('green', '   The sign-off'));
rule('green');
await sleep(700);

await agentSays('a ' + c('bold', 'named human') + ' approves → emilia_authorize(' + c('gray', 'approver: operator:iman.schrock') + ')');
r = await call('emilia_authorize', { action: 'payment.release', context: { amount: 50000, destination: 'acct_9f12' }, approver: 'operator:iman.schrock' });
const receipt = r.emilia_receipt;
await server('green', A.bold + 'authorized' + A.reset + ' by ' + c('bold', r.approver));
await server('gray', 'receipt minted: ' + A.reset + receipt.payload.receipt_id + c('gray', '   (Ed25519-signed, outcome=' + receipt.payload.claim.outcome + ')'));

await agentSays('release_payment(' + c('gray', '…, emilia_receipt: ✓') + ')   ' + c('gray', '— retries with the receipt'));
r = await call('release_payment', { amount: 50000, destination: 'acct_9f12', emilia_receipt: receipt });
await sleep(400);
log();
log(c('green', A.bold + '       ✓ RELEASED   ') + A.bold + '$' + Number(r.amount ?? 50000).toLocaleString() + A.reset + ' → ' + r.destination + c('gray', '    approved_by ' + r.approved_by));
log();
await sleep(1100);

// ── Negative control ─────────────────────────────────────────────────────
log(c('gray', '  And if the agent tries to cheat —'));
await agentSays('release_payment(' + c('gray', 'destination: acct_evil, emilia_receipt: ') + c('red', 'forged') + c('gray', ')'));
const forged = JSON.parse(JSON.stringify(receipt));
forged.payload.claim.context.amount = 1; // tamper after signing → signature breaks
r = await call('release_payment', { amount: 50000, destination: 'acct_evil', emilia_receipt: forged });
await server('red', A.bold + r.status + ' ' + r.error + A.reset + c('gray', ' — ' + (r.reason || '')));

// ── Close ────────────────────────────────────────────────────────────────
log();
rule('gold');
log('  The agent ' + c('bold', 'could not move money') + ' until a human signed off —');
log('  and it reached for EMILIA ' + c('bold', 'on its own') + ', because the receipt');
log('  was the only key to the door.');
rule('gold');
log();
log(c('gray', '  npx -y @emilia-protocol/mcp-server     ·     emiliaprotocol.ai/mcp'));
log();

await agent.close();
process.exit(0);
