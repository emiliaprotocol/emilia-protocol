// SPDX-License-Identifier: Apache-2.0
// Generated from prod-deploy.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Canonical MCP example #3 — a deploy MCP server whose `deploy_production`
// tool cannot run without an EMILIA authorization receipt.
//
//   node examples/mcp/prod-deploy.mjs
//   FAST=1 node examples/mcp/prod-deploy.mjs
//
// Fully offline: real verifier from @emilia-protocol/require-receipt.
import { runDemo } from './_kit.mts';
await runDemo({
    title: 'mcp-prod-deploy — deploy_production requires a receipt',
    tool: 'deploy_production',
    action: 'deploy.production',
    args: { service: 'payments-api', ref: 'a91f3c2', environment: 'production' },
    approver: 'ep:approver:on-call-sre (passkey)',
    agentLine: '"Tests are green — shipping payments-api@a91f3c2 to production."',
});
