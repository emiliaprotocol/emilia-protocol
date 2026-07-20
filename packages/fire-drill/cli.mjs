#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * npx @emilia-protocol/fire-drill <manifest.json | openapi.json | tools.json>
 *
 * The Agent Action Firewall Test. Reads an MCP manifest, OpenAPI spec, or tool
 * list (JSON, or stdin) and reports missing required receipt declarations.
 * Runtime enforcement is not assessed. Exits non-zero when declarations are missing.
 *
 *   --json   machine-readable report
 *   --fix    print the EMILIA Gate patch snippets for the failures
 * @license Apache-2.0
 */
import fs from 'node:fs';
import { scan, TAGLINE, generatePullRequest } from './index.js';
let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../verify/strict-json.js')); }

const MAX_INPUT_BYTES = 8 * 1024 * 1024;

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));
const file = argv.find((a) => !a.startsWith('--'));

function readInput() {
  if (file) return fs.readFileSync(file);
  if (!process.stdin.isTTY) return fs.readFileSync(0);
  return null;
}

const input = readInput();
const raw = input?.toString('utf8');
if (!raw) {
  console.error('usage: fire-drill <manifest.json|openapi.json|tools.json> [--json] [--fix]\n       (or pipe JSON via stdin)');
  process.exit(2);
}

let report;
try {
  // input is provably non-null here: raw = input?.toString() was checked truthy above,
  // and toString() on a null input would yield undefined, not a truthy string.
  if (/** @type {Buffer} */ (input).length > MAX_INPUT_BYTES) throw new Error(`input exceeds ${MAX_INPUT_BYTES} bytes`);
  const gate = strictJsonGate(raw);
  if (!gate.ok) throw new Error(gate.reason);
  report = scan(JSON.parse(raw));
} catch (e) {
  console.error(`fire-drill: ${e.message}`);
  process.exit(2);
}

if (flags.has('--json')) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.static_result === 'complete' ? 0 : 1);
}

if (flags.has('--pr')) {
  const pr = generatePullRequest(report);
  console.log(`# ${pr.title}\n\n${pr.body}`);
  process.exit(report.static_result === 'complete' ? 0 : 1);
}

const R = (s) => `\x1b[31m${s}\x1b[0m`;
const Y = (s) => `\x1b[33m${s}\x1b[0m`;
const B = (s) => `\x1b[1m${s}\x1b[0m`;
const line = (s = '') => console.log(s);

line('='.repeat(68));
line(B('  Agent Action Firewall Test — @emilia-protocol/fire-drill'));
line('='.repeat(68));
line(`  Target: ${report.target_type}   Operations: ${report.summary.operations}   `
  + `Dangerous: ${report.summary.dangerous}   Receipt declared: ${report.summary.declared}`);
const scoreStr = `  Static receipt declaration score: ${report.score}/100`;
line(report.score >= 50 ? Y(scoreStr) : R(scoreStr));
line('');

if (report.findings.length === 0) {
  line(Y('  ! Every detected dangerous action declares a required receipt input.'));
  line(Y('  ! Runtime verification and consumption are NOT ASSESSED. Run EG-1 separately.'));
} else {
  for (const f of report.findings) {
    line(`  ${R('✗')} ${f.message}`);
    line(`      ${Y('Fix:')} ${f.fix}`);
    line(`      ${Y('Earn:')} ${f.earn}`);
    if (flags.has('--fix')) line(fixSnippet(f));
  }
  line('');
  line(R(`  STATIC SCAN: INCOMPLETE — ${report.summary.missing_declaration} dangerous operation(s) lack a required receipt declaration.`));
}
line('  ' + '-'.repeat(64));
line('  ' + B(TAGLINE));
line('='.repeat(68));
process.exit(report.static_result === 'complete' ? 0 : 1);

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
