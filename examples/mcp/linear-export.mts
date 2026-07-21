// SPDX-License-Identifier: Apache-2.0
//
// Canonical MCP example #5 — a Linear MCP server whose `export_customer_data`
// tool cannot run without an EMILIA authorization receipt.
//
//   node examples/mcp/linear-export.mjs          (paced, for screen-recording)
//   FAST=1 node examples/mcp/linear-export.mjs   (no pauses)
//
// Fully offline: real verifier from @emilia-protocol/require-receipt, no Linear
// OAuth, no workspace. Manifest-driven; earns RR-1.

import { runDemo } from './_kit.mts';

await runDemo({
  title: 'mcp-linear-export — export_customer_data requires a receipt',
  tool: 'export_customer_data',
  args: { workspace: 'acme', scope: 'all_issues', format: 'csv' },
  approver: 'ep:approver:data-protection-officer (passkey)',
  agentLine: '"Pulling a full customer/issue export for the analytics request."',
});
