#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
//   node packages/scan/cli.mjs <actions.json | openapi.json>  [--emit manifest.json]
//   node packages/scan/cli.mjs --sample
//   node packages/scan/cli.mjs brain <actions.json | openapi.json>
//   node packages/scan/cli.mjs brain --sample
//   node packages/scan/cli.mjs protect <actions.json | openapi.json> [--apply]
//
// Ingests MCP tool lists ([{name, description, annotations}] or {tools:[...]}) or
// an OpenAPI spec, classifies, and prints an HONEST report. Enforces nothing on
// its own — it proposes; you confirm and add the wrap.
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scanActions, KNOWN_CATEGORIES } from './index.js';
import { readBoundedRegularFile } from './safe-file.mjs';
import { renderAuthorityBrain, writeAuthorityBrain } from './brain.mjs';

let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../verify/strict-json.js')); }
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const OPENAPI_METHODS = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']);
const TERMINAL_CONTROLS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;

function terminalSafe(value) {
  return String(value).replace(TERMINAL_CONTROLS, (character) => (
    `\\u{${character.codePointAt(0).toString(16).padStart(4, '0')}}`
  ));
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

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
  if (j && typeof j.openapi === 'string' && Object.hasOwn(j, 'paths')) {
    if (!isRecord(j.paths)) throw new Error('OpenAPI paths must be an object.');
    const actions = [];
    for (const [p, ops] of Object.entries(j.paths)) {
      if (!isRecord(ops)) throw new Error(`OpenAPI path item must be an object: ${p}.`);
      for (const [method, op] of Object.entries(ops)) {
        const normalizedMethod = method.toLowerCase();
        if (!OPENAPI_METHODS.has(normalizedMethod)) continue;
        if (!isRecord(op)) throw new Error(`OpenAPI operation must be an object: ${method} ${p}.`);
        actions.push({
          name: op.operationId || `${normalizedMethod} ${p}`,
          description: op.summary || op.description || '',
          http_method: normalizedMethod,
          route_path: p,
        });
      }
    }
    if (actions.length === 0) {
      throw new Error('OpenAPI spec declares no operations; refusing a false-empty surface.');
    }
    return { actions, source: 'openapi', blindSpots: ['Only operations declared in the spec are visible; undocumented endpoints and query-param-dependent risk are not.'] };
  }
  const list = Array.isArray(j) ? j : Array.isArray(j.tools) ? j.tools : null;
  if (!list) throw new Error('Unrecognized input: expected an OpenAPI spec, a JSON array of {name,...}, or {"tools":[...]}.');
  return { actions: list.map((t) => ({ name: t.name, description: t.description, annotations: t.annotations, http_method: t.http_method })), source: 'mcp', blindSpots: ['Only statically-listed tools are visible; tools registered at runtime, and risk that depends on argument VALUES rather than the tool name, are not.'] };
}

const args = process.argv.slice(2);
if (args[0] === 'authority') {
  const { authorityMain } = await import('./dist/authority/cli.js');
  process.exitCode = authorityMain(args.slice(1));
} else if (args[0] === 'protect') {
  // Reuse the hardener in-process. This launches no configured server and makes
  // no network request; it only reads the supplied declaration and, with
  // --apply, creates a reviewed scaffold under the selected output directory.
  process.argv = [process.argv[0], fileURLToPath(new URL('./codemod.mjs', import.meta.url)), ...args.slice(1)];
  await import('./codemod.mjs');
} else if (args[0] === 'brain') {
  let outPath = 'emilia-authority-brain.html';
  let outSeen = false;
  let force = false;
  let sample = false;
  const positionals = [];
  const brainArgs = args.slice(1);
  for (let index = 0; index < brainArgs.length; index += 1) {
    const arg = brainArgs[index];
    if (arg === '--out') {
      const value = brainArgs[index + 1];
      if (!value || value.startsWith('-')) {
        console.error('--out requires a value');
        process.exit(2);
      }
      if (outSeen) { console.error('duplicate option: --out'); process.exit(64); }
      outSeen = true;
      outPath = value;
      index += 1;
      continue;
    }
    if (arg === '--sample' || arg === '--force') {
      if ((arg === '--sample' && sample) || (arg === '--force' && force)) {
        console.error(`duplicate option: ${arg}`);
        process.exit(64);
      }
      if (arg === '--sample') sample = true;
      if (arg === '--force') force = true;
      continue;
    }
    if (arg.startsWith('-')) {
      console.error(`unknown option: ${arg}`);
      process.exit(64);
    }
    positionals.push(arg);
  }
  if (positionals.length > 1 || (sample && positionals.length > 0)) {
    console.error('provide exactly one input file or --sample, not both');
    process.exit(64);
  }

  try {
    let input;
    let inputReference;
    if (sample) {
      input = {
        actions: SAMPLE,
        source: 'mcp',
        blindSpots: ['This is the built-in sample. Real scans see only statically-listed tools; runtime-registered tools and value-dependent risk are invisible.'],
      };
      inputReference = '--sample';
    } else {
      const file = positionals[0];
      if (!file) {
        console.error('usage: cli.mjs brain <actions.json|openapi.json> [--out dashboard.html] [--force] | brain --sample [--out dashboard.html] [--force]');
        process.exit(2);
      }
      const raw = readBoundedRegularFile(file, MAX_INPUT_BYTES);
      input = ingest(raw.toString('utf8'));
      inputReference = file;
    }
    const report = scanActions(
      input.actions,
      /** @type {any} */ ({ source: input.source, blindSpots: input.blindSpots }),
    );
    const html = renderAuthorityBrain(report, { inputReference });
    const written = writeAuthorityBrain(html, { outPath, force });
    console.log(`\nEMILIA Authority Brain written: ${terminalSafe(written)}`);
    console.log('Local artifact only. The scanner proposes; the owner reviews; Gate enforces after integration.\n');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Authority Brain refused: ${terminalSafe(message)}`);
    process.exitCode = 1;
  }
} else {
  let emitPath = null;
  let sample = false;
  const positionals = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--sample') {
      if (sample) { console.error('duplicate option: --sample'); process.exit(64); }
      sample = true;
      continue;
    }
    if (arg === '--emit') {
      const value = args[index + 1];
      if (!value || value.startsWith('-')) {
        console.error('--emit requires a value');
        process.exit(2);
      }
      if (emitPath !== null) { console.error('duplicate option: --emit'); process.exit(64); }
      emitPath = value;
      index += 1;
      continue;
    }
    if (arg.startsWith('-')) {
      console.error(`unknown option: ${arg}`);
      process.exit(64);
    }
    positionals.push(arg);
  }
  if (positionals.length > 1 || (sample && positionals.length > 0)) {
    console.error('provide exactly one input file or --sample, not both');
    process.exit(64);
  }
  let input;
  if (sample) {
    input = { actions: SAMPLE, source: 'mcp', blindSpots: ['This is the built-in sample. Real scans see only statically-listed tools; runtime-registered tools and value-dependent risk are invisible.'] };
  } else {
    const file = positionals[0];
    if (!file) { console.error('usage: cli.mjs <actions.json|openapi.json> [--emit manifest.json] | --sample | brain <input|--sample> | protect <input> [--apply]'); process.exit(2); }
    const raw = readBoundedRegularFile(file, MAX_INPUT_BYTES);
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
  console.log('  2. Generate the reviewed protection scaffold (still a dry-run):');
  console.log(`     ${C.dim}npx @emilia-protocol/scan protect <this-input>${C.r}`);
  console.log('  3. Apply and integrate it at the credential-owning dispatch boundary. Until that boundary, durable state, and pinned keys exist, NOTHING is enforced.');

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
}
