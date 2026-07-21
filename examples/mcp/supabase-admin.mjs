// SPDX-License-Identifier: Apache-2.0
// Generated from supabase-admin.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Canonical MCP example #4 — a Supabase-admin MCP server whose
// `run_destructive_sql` tool cannot run without an EMILIA authorization receipt.
//
//   node examples/mcp/supabase-admin.mjs          (paced, for screen-recording)
//   FAST=1 node examples/mcp/supabase-admin.mjs   (no pauses)
//
// Fully offline: real verifier from @emilia-protocol/require-receipt, no Supabase
// project, no credentials. Manifest-driven; earns RR-1.
import { runDemo } from './_kit.mts';
await runDemo({
    title: 'mcp-supabase-admin — run_destructive_sql requires a receipt',
    tool: 'run_destructive_sql',
    args: { sql: 'DROP TABLE invoices;', database: 'prod' },
    approver: 'ep:approver:db-owner (Face ID)',
    agentLine: '"Cleaning up — running DROP TABLE invoices on prod."',
});
