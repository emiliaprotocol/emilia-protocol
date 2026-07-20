// SPDX-License-Identifier: Apache-2.0
//
// Plays an AI agent talking to the EMILIA Passport MCP server over real stdio
// JSON-RPC. Shows the agent hit a wall and adopt EMILIA on its own:
//   release_payment (no receipt) → 402 → emilia_authorize → human approves →
//   receipt → release_payment (with receipt) → released.  Then a forged receipt
//   is rejected.  Run:  node --no-warnings mcp-server/passport-client.mjs

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const here = dirname(fileURLToPath(import.meta.url));
const transport = new StdioClientTransport({ command: 'node', args: ['--no-warnings', join(here, 'passport-demo.mjs')] });
const agent = new Client({ name: 'demo-agent', version: '1.0.0' }, { capabilities: {} });
await agent.connect(transport);

/** @param {string} name @param {Record<string, unknown>} args */
const call = async (name, args) => JSON.parse((/** @type {{ content: { text: string }[] }} */ (/** @type {unknown} */ (await agent.callTool({ name, arguments: args })))).content[0].text);
/** @param {string} s */
const log = (s) => process.stdout.write(s + '\n');
/** @param {string} n @param {string} s */
const step = (n, s) => log(`\n${n}  ${s}`);

log('\n  AI agent connected to the EMILIA Passport MCP server. It wants to release $50,000.\n  ' + '='.repeat(74));

step('①', 'Agent calls release_payment (no receipt — it doesn\'t know it needs one yet)');
let r = await call('release_payment', { amount: 50000, destination: 'acct_9f12' });
log(`     ← ${r.status} ${r.error}: ${r.required?.action}`);
log(`       server tells it exactly what to do: "${r.required?.how}"`);

step('②', 'Agent does as told — calls emilia_authorize for that action (no human yet)');
r = await call('emilia_authorize', { action: 'payment.release', context: { amount: 50000, destination: 'acct_9f12' } });
log(`     ← ${r.status} signoff_required=${r.signoff_required}: ${r.reasons?.join(' ')}`);
log(`       "${r.next}"`);

step('③', 'A NAMED HUMAN approves. Agent re-calls emilia_authorize with the approver');
r = await call('emilia_authorize', { action: 'payment.release', context: { amount: 50000, destination: 'acct_9f12' }, approver: 'operator:iman.schrock' });
const receipt = r.emilia_receipt;
log(`     ← ${r.status} authorized=${r.authorized}, approver=${r.approver}`);
log(`       receipt minted: ${receipt.payload.receipt_id} (Ed25519-signed, outcome=${receipt.payload.claim.outcome})`);

step('④', 'Agent retries release_payment WITH the receipt');
r = await call('release_payment', { amount: 50000, destination: 'acct_9f12', emilia_receipt: receipt });
log(`     ← ${r.status} released=${r.released}  $${r.amount} → ${r.destination}  (approved_by ${r.approved_by})`);

step('⑤', 'Negative control — agent forges a receipt (tampers the amount after signing)');
const forged = JSON.parse(JSON.stringify(receipt));
forged.payload.claim.context.amount = 1; // change after signing → signature breaks
r = await call('release_payment', { amount: 50000, destination: 'acct_evil', emilia_receipt: forged });
log(`     ← ${r.status} ${r.error}: ${r.reason}`);

log('\n  ' + '='.repeat(74));
log('  The agent could not move money until a human signed off — and it reached for');
log('  EMILIA on its own, because the receipt was the only key to the door.\n');

await agent.close();
process.exit(0);
