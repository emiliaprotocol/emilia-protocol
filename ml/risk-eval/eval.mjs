// SPDX-License-Identifier: Apache-2.0
// Risk-classifier eval harness. Benchmarks any classify(input) against
// cases.jsonl. Covered cases are a regression gate (a dangerous miss exits 1);
// perimeter cases are a coverage benchmark (the model's scoreboard).
//
//   node ml/risk-eval/eval.mjs            # baseline = the real rule engine
//   node ml/risk-eval/eval.mjs tinker     # future self-hosted model
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const which = process.argv[2] && !process.argv[2].startsWith('-') ? process.argv[2] : 'rules';
const { classify } = await import(`./classifiers/${which}.mjs`);

const cases = fs.readFileSync(path.join(HERE, 'cases.jsonl'), 'utf8')
  .split('\n').map((l) => l.trim()).filter(Boolean).map((l) => JSON.parse(l));

const GATE = new Set(['deny', 'allow_with_signoff']);
const out = {
  covered: 0, coveredOk: 0, dangerous: [], safeMismatch: [],
  perimeter: 0, perimeterCaught: 0, perimeterMissed: [],
};

for (const c of cases) {
  const got = await classify(c.input);
  const exp = c.expected.decision;
  const gotIsGate = GATE.has(got.decision);

  if (c.tier === 'perimeter') {
    out.perimeter++;
    if (gotIsGate) out.perimeterCaught++;
    else out.perimeterMissed.push({ id: c.id, exp, got: got.decision, note: c.note });
    continue;
  }

  out.covered++;
  if (got.decision === exp) { out.coveredOk++; continue; }
  if (GATE.has(exp) && !gotIsGate) out.dangerous.push({ id: c.id, exp, got: got.decision }); // high-risk seen as safe
  else out.safeMismatch.push({ id: c.id, exp, got: got.decision }); // over-escalation — safe but noted
}

const log = (s = '') => console.log(s);
log(`\nclassifier: ${which}    cases: ${cases.length}`);
log('────────────────────────────────────────────');
log(`COVERED  (regression gate)    ${out.coveredOk}/${out.covered} exact`);
for (const m of out.safeMismatch) log(`   · over-escalation (safe): ${m.id} expected ${m.exp}, got ${m.got}`);
for (const d of out.dangerous) log(`   ⛔ DANGEROUS MISS: ${d.id} expected ${d.exp}, got ${d.got}`);
log(`PERIMETER (model scoreboard)  ${out.perimeterCaught}/${out.perimeter} escalated`);
for (const m of out.perimeterMissed) log(`   · gap: ${m.id} — got ${m.got}, should be ${m.exp}  (${m.note})`);
log('────────────────────────────────────────────');

if (out.dangerous.length) {
  log(`FAIL — ${out.dangerous.length} dangerous miss(es) on covered cases.\n`);
  process.exit(1);
}
const pct = Math.round((100 * out.perimeterCaught) / (out.perimeter || 1));
log(`PASS — no dangerous misses on covered cases.`);
log(`Perimeter coverage ${pct}% — the rules are expected to miss these; closing the gap is the model's job.\n`);
