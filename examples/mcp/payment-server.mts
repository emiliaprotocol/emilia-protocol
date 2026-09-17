// SPDX-License-Identifier: Apache-2.0
//
// Canonical MCP example #1 — a payments MCP server whose `release_payment`
// tool cannot run without an EMILIA authorization receipt.
//
//   node examples/mcp/payment-server.mjs          (paced, for screen-recording)
//   FAST=1 node examples/mcp/payment-server.mjs   (no pauses)
//
// Fully offline: real verifier, process-local generated demo keys and an
// in-memory receipt store. Mock execution only: no bank or human ceremony.

import { runDemo } from './_kit.mjs';

await runDemo({
  title: 'mcp-payment-server — release_payment requires a receipt',
  tool: 'release_payment',
  args: { amount_minor: 8200000, currency: 'USD', destination: 'acct_new_4471', vendor: 'Acme Industrial LLC' },
  approver: 'demo treasury-controller fixture',
  agentLine: '"Vendor updated their bank details — paying the $82,000 invoice."',
});
