#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * npx @emilia-protocol/fire-drill <manifest.json | openapi.json | tools.json>
 *
 * The Agent Action Firewall Test. Reads an MCP manifest, OpenAPI spec, or tool
 * list (JSON, or stdin) and reports whether a dangerous action can run without
 * an accountable human receipt. Exits non-zero if any does (CI-friendly).
 *
 *   --json   machine-readable report
 *   --fix    print the EMILIA Gate patch snippets for the failures
 * @license Apache-2.0
 */
import fs from 'node:fs';
import { scan, TAGLINE, generatePullRequest } from './index.js';

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));
const file = argv.find((a) => !a.startsWith('--'));

function readInput() {
  if (file) return fs.readFileSync(file, 'utf8');
  if (!process.stdin.isTTY) return fs.readFileSync(0, 'utf8');
  return null;
}

const raw = readInput();
if (!raw) {
  console.error('usage: fire-drill <manifest.json|openapi.json|tools.json> [--json] [--fix]\n       (or pipe JSON via stdin)');
  process.exit(2);
}

let report;
try {
  report = scan(JSON.parse(raw));
} catch (e) {
  console.error(`fire-drill: ${e.message}`);
  process.exit(2);
}

if (flags.has('--json')) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.eg1 === 'pass' ? 0 : 1);
}

if (flags.has('--pr')) {
  const pr = generatePullRequest(report);
  console.log(`# ${pr.title}\n\n${pr.body}`);
  process.exit(report.eg1 === 'pass' ? 0 : 1);
}

const G = (s) => `\x1b[32m${s}\x1b[0m`;
const R = (s) => `\x1b[31m${s}\x1b[0m`;
const Y = (s) => `\x1b[33m${s}\x1b[0m`;
const B = (s) => `\x1b[1m${s}\x1b[0m`;
const line = (s = '') => console.log(s);

line('='.repeat(68));
line(B('  Agent Action Firewall Test — @emilia-protocol/fire-drill'));
line('='.repeat(68));
line(`  Target: ${report.target_type}   Operations: ${report.summary.operations}   `
  + `Dangerous: ${report.summary.dangerous}   Gated: ${report.summary.gated}`);
const scoreStr = `  Agent Action Firewall score: ${report.score}/100`;
line(report.score === 100 ? G(scoreStr) : report.score >= 50 ? Y(scoreStr) : R(scoreStr));
line('');

if (report.findings.length === 0) {
  line(G('  ✓ No dangerous action can run without a receipt.'));
  line(G(`  ✓ EG-1: ${report.eg1.toUpperCase()} — eligible for the "EG-1 Enforced" badge.`));
} else {
  for (const f of report.findings) {
    line(`  ${R('✗')} ${f.message}`);
    line(`      ${Y('Fix:')} ${f.fix}`);
    line(`      ${Y('Earn:')} ${f.earn}`);
    if (flags.has('--fix')) line(fixSnippet(f));
  }
  line('');
  line(R(`  EG-1: FAIL — ${report.summary.ungated} dangerous operation(s) can run without a receipt.`));
}
line('  ' + '-'.repeat(64));
line('  ' + B(TAGLINE));
line('='.repeat(68));
process.exit(report.eg1 === 'pass' ? 0 : 1);

function fixSnippet(f) {
  if (f.family && f.fix.includes('adapters/')) {
    return `\n      ──────────────────────────────────────────────\n`
      + `      import { createGate } from '@emilia-protocol/gate';\n`
      + `      import { gateMcpTool } from '@emilia-protocol/gate/mcp';\n`
      + `      const gate = createGate({ manifest, trustedKeys: [ISSUER] });\n`
      + `      server.tool('${f.operation}', gateMcpTool(gate, { tool: '${f.operation}' }, handler));\n`
      + `      ──────────────────────────────────────────────`;
  }
  return '';
}
