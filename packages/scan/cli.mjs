// SPDX-License-Identifier: Apache-2.0
//
//   node packages/scan/cli.mjs <actions.json | openapi.json>  [--emit manifest.json]
//   node packages/scan/cli.mjs --sample
//
// Ingests MCP tool lists ([{name, description, annotations}] or {tools:[...]}) or
// an OpenAPI spec, classifies, and prints an HONEST report. Enforces nothing on
// its own — it proposes; you confirm and add the wrap.
import fs from 'node:fs';
import { scanActions, KNOWN_CATEGORIES } from './index.js';

let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../verify/strict-json.js')); }
const MAX_INPUT_BYTES = 8 * 1024 * 1024;

const SAMPLE = [
  { name: 'getAccountBalance', description: 'Return the current balance for an account' },
  { name: 'searchTransactions', description: 'Search transaction history' },
  { name: 'sendWire', description: 'Send an outgoing wire transfer to a beneficiary' },
  { name: 'updateBeneficiaryBankDetails', description: 'Change the destination bank account for a payee' },
  { name: 'deployToProduction', description: 'Ship the current build to the production environment' },
  { name: 'grantAdminRole', description: 'Give a user administrator privileges' },
  { name: 'exportCustomerPII', description: 'Bulk export of customer records to CSV' },
  { name: 'deleteCustomer', description: 'Permanently remove a customer record' },
  { name: 'rotateApiKey', description: 'Rotate the service API key', annotations: { destructiveHint: true } },
  { name: 'summarizeTicket', description: 'Summarize a support ticket', annotations: { readOnlyHint: true } },
  { name: 'reconcileLedger', description: 'Reconcile the internal ledger and post adjustments' },
];

function ingest(raw) {
  if (Buffer.byteLength(raw, 'utf8') > MAX_INPUT_BYTES) throw new Error(`Input exceeds ${MAX_INPUT_BYTES} bytes.`);
  const gate = strictJsonGate(raw);
  if (!gate.ok) throw new Error(`Input refused: ${gate.reason}.`);
  const j = JSON.parse(raw);
  if (j && j.openapi && j.paths) {
    const actions = [];
    for (const [p, ops] of Object.entries(j.paths)) {
      for (const [method, op] of Object.entries(ops)) {
        if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) continue;
        actions.push({ name: op?.operationId || `${method} ${p}`, description: op?.summary || op?.description || '', http_method: method });
      }
    }
    return { actions, source: 'openapi', blindSpots: ['Only operations declared in the spec are visible; undocumented endpoints and query-param-dependent risk are not.'] };
  }
  const list = Array.isArray(j) ? j : Array.isArray(j.tools) ? j.tools : null;
  if (!list) throw new Error('Unrecognized input: expected an OpenAPI spec, a JSON array of {name,...}, or {"tools":[...]}.');
  return { actions: list.map((t) => ({ name: t.name, description: t.description, annotations: t.annotations, http_method: t.http_method })), source: 'mcp', blindSpots: ['Only statically-listed tools are visible; tools registered at runtime, and risk that depends on argument VALUES rather than the tool name, are not.'] };
}

const args = process.argv.slice(2);
const emitIdx = args.indexOf('--emit');
const emitPath = emitIdx >= 0 ? args[emitIdx + 1] : null;
let input;
if (args.includes('--sample')) {
  input = { actions: SAMPLE, source: 'mcp', blindSpots: ['This is the built-in sample. Real scans see only statically-listed tools; runtime-registered tools and value-dependent risk are invisible.'] };
} else {
  const file = args.find((a) => !a.startsWith('--') && a !== emitPath);
  if (!file) { console.error('usage: cli.mjs <actions.json|openapi.json> [--emit manifest.json] | --sample'); process.exit(2); }
  const raw = fs.readFileSync(file);
  if (raw.length > MAX_INPUT_BYTES) { console.error(`input exceeds ${MAX_INPUT_BYTES} bytes`); process.exit(2); }
  input = ingest(raw.toString('utf8'));
}

// scanActions' destructured `blindSpots = []` default (packages/scan/index.js) has no JSDoc,
// so TS infers its type as `never[]` from the empty-array default alone; the real, already-true
// type of this options object is `{ source: string, blindSpots: string[] }`. Cast at this call
// boundary only — no runtime effect, no change to what gets passed or what scanActions does.
const rep = scanActions(
  input.actions,
  /** @type {any} */ ({ source: input.source, blindSpots: input.blindSpots }),
);
const C = { gate: '\x1b[31m', fail: '\x1b[33m', pass: '\x1b[32m', dim: '\x1b[2m', b: '\x1b[1m', r: '\x1b[0m' };
const badge = (d) => ({ gate: `${C.gate}REQUIRE RECEIPT${C.r}`, review_fail_closed: `${C.fail}REVIEW (fail-closed)${C.r}`, pass_through: `${C.pass}pass-through${C.r}`, review: `${C.dim}review${C.r}` }[d] || d);

console.log(`\n${C.b}EMILIA scan — ${input.source} surface, ${rep.counts.total} actions${C.r}`);
console.log(`${C.dim}Proposes which actions need a human-authorization receipt. Confirms nothing and enforces nothing on its own.${C.r}\n`);
for (const { action, classification: c } of rep.results) {
  console.log(`  ${badge(c.decision).padEnd(30)} ${action.name}`);
  console.log(`      ${C.dim}${c.assurance_class ? `tier=${c.assurance_class}  ` : ''}${c.reason} (confidence ${c.confidence})${C.r}`);
}
console.log(`\n${C.b}Summary${C.r}`);
console.log(`  require receipt (recognized high-risk): ${rep.counts.gate}`);
console.log(`  ${C.fail}review, defaulted FAIL-CLOSED (mutating, unrecognized): ${rep.counts.review_fail_closed}${C.r}`);
console.log(`  pass-through (read-only): ${rep.counts.pass_through}`);
console.log(`  needs a human eye (ambiguous): ${rep.counts.review}`);

console.log(`\n${C.b}What this scan could NOT see (read this)${C.r}`);
for (const b of rep.blindSpots) console.log(`  - ${b}`);
console.log('  - Whether your organization will actually fail-closed on a denial. That is your decision, not a setting.');
console.log(`  ${C.dim}Recognized categories: ${KNOWN_CATEGORIES.join(', ')}. Anything outside them that mutates state was defaulted to require a receipt, not waved through.${C.r}`);

console.log(`\n${C.b}Next (nothing is enforced until you do this)${C.r}`);
console.log('  1. Review the classifications above; downgrade any false positive, and confirm each REVIEW item.');
console.log('  2. Wire the guard at your tool-call choke point (one wrap):');
console.log(`     ${C.dim}import { withMcpGuard } from '@emilia-protocol/mcp-guard';${C.r}`);
console.log(`     ${C.dim}const dispatch = withMcpGuard(yourDispatch, { manifest, verifyOpts: { trustedKeys } });${C.r}`);
console.log('  3. Pin your issuer/approver keys. Until keys are pinned and the wrap is in place, NOTHING is enforced.');

if (emitPath) {
  try {
    fs.writeFileSync(emitPath, `${JSON.stringify(rep.manifest, null, 2)}\n`, { flag: 'wx' });
  } catch (error) {
    if (error.code === 'EEXIST') {
      console.error(`refusing to overwrite existing manifest: ${emitPath}`);
      process.exit(2);
    }
    throw error;
  }
  console.log(`\n${C.b}Proposed manifest written:${C.r} ${emitPath} ${C.dim}(a proposal to review, not a live control)${C.r}`);
}
console.log('');
