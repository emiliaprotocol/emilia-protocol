// SPDX-License-Identifier: Apache-2.0
//
// Canonical MCP example #2 — a GitHub-admin MCP server whose `delete_repo`
// tool cannot run without an EMILIA authorization receipt.
//
//   node examples/mcp/github-admin.mjs
//   FAST=1 node examples/mcp/github-admin.mjs
//
// Fully offline: real verifier from @emilia-protocol/require-receipt.

import { runDemo } from './_kit.mts';

await runDemo({
  title: 'mcp-github-admin — delete_repo / change_permissions requires a receipt',
  tool: 'delete_repo',
  action: 'github.repo.delete',
  args: { owner: 'acme', repo: 'billing-core', confirm: true },
  approver: 'ep:approver:eng-director (passkey)',
  agentLine: '"Cleaning up stale repos — removing acme/billing-core."',
} as any);
