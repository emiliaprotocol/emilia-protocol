// SPDX-License-Identifier: Apache-2.0
//
// Canonical MCP example #1 — a payments MCP server whose `release_payment`
// tool cannot run without an EMILIA authorization receipt.
//
//   node examples/mcp/payment-server.mjs          (paced, for screen-recording)
//   FAST=1 node examples/mcp/payment-server.mjs   (no pauses)
//
// Fully offline: real verifier from @emilia-protocol/require-receipt. No key,
// no account, no EP server. This is the wedge in 60 seconds.

import { runDemo } from './_kit.mts';

await runDemo({
  title: 'mcp-payment-server — release_payment requires a receipt',
  tool: 'release_payment',
  action: 'payment.release',
  args: { amount_usd: 82000, destination: 'acct_new_4471', vendor: 'Acme Industrial LLC' },
  approver: 'ep:approver:treasury-controller (Face ID)',
  agentLine: '"Vendor updated their bank details — paying the $82,000 invoice."',
} as any);
