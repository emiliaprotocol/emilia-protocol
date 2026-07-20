// SPDX-License-Identifier: Apache-2.0
// Risk-classifier eval harness. Benchmarks any classify(input) against
// cases.jsonl. Covered cases are a regression gate (a dangerous miss exits 1);
// perimeter cases are a coverage benchmark (the model's scoreboard).
//
//   node ml/risk-eval/eval.mjs
//   node ml/risk-eval/eval.mjs heuristic --min-perimeter=100
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
let which = 'rules';
let classifierSet = false;
let minPerimeter = null;

for (const arg of args) {
  if (arg.startsWith('--min-perimeter=')) {
    const value = Number(arg.slice('--min-perimeter='.length));
    if (!Number.isFinite(value) || value < 0 || value > 100) {
      throw new Error('--min-perimeter must be a number from 0 through 100');
    }
    minPerimeter = value;
  } else if (!arg.startsWith('-') && !classifierSet) {
    which = arg;
    classifierSet = true;
  } else {
    throw new Error(`unknown eval argument: ${arg}`);
  }
}

if (!/^[a-z0-9_-]+$/i.test(which)) {
  throw new Error(`invalid classifier name: ${which}`);
}
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

const pct = Math.round((100 * out.perimeterCaught) / (out.perimeter || 1));
const missesCoverageGate = minPerimeter !== null && pct < minPerimeter;

if (out.dangerous.length || missesCoverageGate) {
  if (out.dangerous.length) {
    log(`FAIL — ${out.dangerous.length} dangerous miss(es) on covered cases.`);
  }
  if (missesCoverageGate) {
    log(`FAIL — perimeter coverage ${pct}% is below the required ${minPerimeter}%.`);
  }
  log();
  process.exitCode = 1;
} else {
  log('PASS — no dangerous misses on covered cases.');
  if (minPerimeter !== null) {
    log(`PASS — perimeter coverage ${pct}% meets the required ${minPerimeter}%.`);
  } else {
    log(`Perimeter coverage ${pct}% — informational (no minimum requested).`);
  }
  log();
}
