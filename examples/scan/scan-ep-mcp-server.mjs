// SPDX-License-Identifier: Apache-2.0
//
//   node examples/scan/scan-ep-mcp-server.mjs
//
// Dogfood: run @emilia-protocol/scan against EMILIA's OWN MCP server (mcp-server/
// index.js, 36 tools) and print the honest report. Reproducible on every run — it
// re-derives the tool list from source, so it can never go stale. This is the
// "don't trust the claim, run the check" ethos applied to our own adoption tool.
//
// It is deliberately honest about the classifier's limits: a keyword scan cannot
// tell "this tool DOES payments" from "this tool is ABOUT payments," so it
// over-proposes at medium confidence and a human confirms. See KNOWN_FALSE_POSITIVES.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanActions } from '../../packages/scan/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// Extract the `const TOOLS = [ ... ]` literal from the MCP server, string-aware so
// brackets inside tool descriptions don't fool the bracket walk. Data-only literal.
function extractTools() {
  const src = fs.readFileSync(path.join(ROOT, 'mcp-server', 'index.js'), 'utf8');
  const open = src.indexOf('[', src.indexOf('const TOOLS = ['));
  let depth = 0; let i = open; let q = null; let esc = false;
  for (; i < src.length; i++) {
    const c = src[i];
    if (esc) { esc = false; continue; }
    if (q) { if (c === '\\') esc = true; else if (c === q) q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '[') depth++;
    else if (c === ']') { depth--; if (depth === 0) { i++; break; } }
  }
  // eslint-disable-next-line no-eval
  const TOOLS = eval(`(${src.slice(open, i)})`);
  return TOOLS.map((t) => ({ name: t.name, description: t.description }));
}

// Documented, on purpose: the classifier flags these on a word in their
// description, but they are the AUTHORIZATION mechanism, not consequential actions.
// A reviewer downgrades them. Showing them is the point — the tool proposes, a
// human decides.
const KNOWN_FALSE_POSITIVES = {
  ep_guard_action: 'IS the guard (its description names payments); it authorizes, it does not move money.',
  ep_trust_gate: 'IS the gate; same reason.',
  ep_generate_zk_proof: 'matched the word "privilege"; it produces a proof, it grants nothing.',
  ep_trust_evaluate: 'matched "routing"; it evaluates trust for an action, it does not change bank details.',
};

const tools = extractTools();
const rep = scanActions(tools, { source: 'mcp' });
const truePositives = rep.results.filter((r) => (r.classification.decision === 'gate') && !KNOWN_FALSE_POSITIVES[r.action.name]);

console.log(`EMILIA scan — our own MCP server, ${tools.length} tools\n`);
console.log('GENUINELY consequential (confirmed true positives):');
for (const r of truePositives) console.log(`  ${r.action.name}  ->  ${r.classification.assurance_class}  (${r.classification.category})`);
console.log('\nMutating, unrecognized -> defaulted FAIL-CLOSED for human review:');
for (const r of rep.results.filter((r) => r.classification.decision === 'review_fail_closed')) console.log(`  ${r.action.name}`);
console.log('\nHONEST false positives (flagged by keyword, a reviewer downgrades — the tool proposes, you decide):');
for (const [name, why] of Object.entries(KNOWN_FALSE_POSITIVES)) console.log(`  ${name}: ${why}`);
console.log(`\nSummary: ${rep.counts.gate} gated / ${rep.counts.review_fail_closed} fail-closed for review / ${rep.counts.pass_through} pass-through / ${rep.counts.review} ambiguous, of ${tools.length}.`);
console.log('Nothing here is enforced. This is a proposal to review, run on our own code in the open.');
