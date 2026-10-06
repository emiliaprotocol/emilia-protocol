#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// CAID conformance: every check the CAID CI step runs, in one command
// (npm run caid:conformance). Every step runs even after a failure, and the
// command exits 1 if any step failed.
//
//   1. Spec: the generated constants in every port and the vendored Verify
//      copy match a regeneration (caid/spec/gen.mjs --check).
//   2. Registry: identity against the corpora, and caid/registry/check.mjs
//      (v5 invariants, strict decoding, history v4 bytes, digests.json,
//      definition checks).
//   3. Corpora: vectors.json (v6), grammar-vectors.json and
//      mapping-vectors.json (v3) equal their builders' output; version 4 and
//      mapping version 1 carry forward (check-v4.mjs); the JavaScript runner
//      passes every vector against the spec oracle itself.
//   4. Ports: the core and grammar corpora in JavaScript, Python and Go
//      through public entry points (caid/conformance/runners), the unit
//      tests of all three ports, and the mapping corpus v3 and
//      consequential-interoperability corpus in all three with
//      cross-language parity.
//
// The steps are independent and run concurrently (CAID_JOBS of them at a
// time, default the number of available CPUs); results print in the order
// above. CAID_PYTHON names the Python interpreter (default python3).
// CAID_GRAMMAR_CASES names a case list caid/spec/abnf-check.mjs --out
// already wrote, which the grammar corpus check reuses instead of running
// abnf-check again.

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const REPO = path.resolve(ROOT, '..');
const GO_ROOT = path.join(ROOT, 'impl/go');
const PYTHON = process.env.CAID_PYTHON || 'python3';
const JOBS = Math.max(1, Number(process.env.CAID_JOBS) || (os.availableParallelism?.() ?? os.cpus().length));
const failed = [];

// Each step starts when a slot is free; its result is reported in order.
let active = 0;
const waiting = [];
const slot = () => (active < JOBS ? (active += 1, Promise.resolve()) : new Promise((resolve) => waiting.push(resolve)));
const release = () => { const next = waiting.shift(); if (next) next(); else active -= 1; };
const steps = [];

function spawnStep(command, args, cwd) {
  return slot().then(() => new Promise((resolve) => {
    const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (b) => out.push(b));
    child.stderr.on('data', (b) => err.push(b));
    child.on('error', (error) => { release(); resolve({ status: null, stdout: '', stderr: '', error }); });
    child.on('close', (status) => {
      release();
      resolve({ status, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  }));
}

/** Queues a step; the returned promise resolves to its stdout, or null on failure. */
function run(label, command, args, cwd = ROOT) {
  const result = spawnStep(command, args, cwd);
  const report = result.then((r) => {
    if (r.status !== 0) {
      return { ok: false, label, text: `FAIL ${label}\n${(r.stdout || '').slice(-6000)}${(r.stderr || '').slice(-6000)}${r.error ? String(r.error) : ''}\n`, output: null };
    }
    return { ok: true, text: `PASS ${label}\n`, output: r.stdout.trim() };
  });
  steps.push(report);
  return report.then((r) => r.output);
}

/** Queues a result computed in this process. */
function note(label, problems) {
  steps.push(Promise.resolve(problems.length
    ? { ok: false, label, text: `FAIL ${label}\n  ${problems.join('\n  ')}\n` }
    : { ok: true, text: `PASS ${label}\n` }));
}

// ---------------------------------------------------------------- 1. spec
run('generated spec constants and vendored Verify copy (caid/spec/gen.mjs --check)', 'node', ['caid/spec/gen.mjs', '--check'], REPO);

// ---------------------------------------------------------------- 2. registry
const registry = JSON.parse(readFileSync(path.join(ROOT, 'registry/action-types.json'), 'utf8'));
const mappingCorpus = JSON.parse(readFileSync(path.join(ROOT, 'conformance/mapping-vectors.json'), 'utf8'));
const interopCorpusPath = path.join(ROOT, 'interop/consequential-action-v1/mapping-vectors.json');
const interopCorpus = JSON.parse(readFileSync(interopCorpusPath, 'utf8'));
const stable = (value) => {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  return value;
};
{
  const problems = [];
  const names = registry.types.map((entry) => entry.action_type);
  if (new Set(names).size !== names.length) problems.push('duplicate action type in the public registry');
  for (const definition of mappingCorpus.definitions) {
    const registered = registry.types.find((entry) => entry.action_type === definition.action_type);
    if (!registered || JSON.stringify(stable(registered)) !== JSON.stringify(stable(definition))) problems.push(`mapping definition aliases public type ${definition.action_type} with different semantics`);
  }
  for (const definition of interopCorpus.definitions) {
    if (registry.types.some((entry) => entry.action_type === definition.action_type)) problems.push(`interoperability-local action type ${definition.action_type} aliases the public registry`);
  }
  note(problems.length ? 'registry identity'
    : `registry identity: ${registry.types.length} unique types; mapping definitions match exact public entries; ${interopCorpus.definitions.length} interoperability-local definition(s) do not alias it`, problems);
}
run('registry check (caid/registry/check.mjs)', 'node', ['caid/registry/check.mjs'], REPO);

// ---------------------------------------------------------------- 3. corpora
run('core corpus v6 is its builder\'s output', 'node', ['caid/conformance/tools/build-core.mjs', '--check'], REPO);
run('grammar corpus is its builder\'s output', 'node', ['caid/conformance/tools/build-grammar.mjs', '--check',
  ...(process.env.CAID_GRAMMAR_CASES ? ['--cases', path.resolve(process.env.CAID_GRAMMAR_CASES)] : [])], REPO);
run('mapping corpus v3 is its builder\'s output', 'node', ['caid/conformance/tools/build-mapping.mjs', '--check'], REPO);
run('version 4 and mapping version 1 carried forward (check-v4.mjs)', 'node', ['caid/conformance/check-v4.mjs'], REPO);
run('core and grammar corpora against the spec oracle', 'node', ['caid/conformance/runners/run.mjs', '--impl', 'caid/conformance/tools/reference-port.mjs'], REPO);

// ---------------------------------------------------------------- 4. ports
const core = JSON.parse(readFileSync(path.join(ROOT, 'conformance/vectors.json'), 'utf8'));
const grammar = JSON.parse(readFileSync(path.join(ROOT, 'conformance/grammar-vectors.json'), 'utf8'));
// Each language line reports what its runner ran, from the runner's own
// summary: a vector whose applies_when condition does not hold for that
// implementation is skipped, never counted as passed.
function runLanguage(language, command, args, cwd) {
  const label = `${language}: core and grammar corpora`;
  steps.push(spawnStep(command, [...args, '--json'], cwd).then((r) => {
    let summary = null;
    try { summary = JSON.parse(r.stdout); } catch { /* reported below */ }
    if (r.status !== 0 || !summary || summary.fail !== 0) {
      const failures = summary?.failures ? JSON.stringify(summary.failures.slice(0, 20), null, 1) : (r.stdout || '').slice(-6000);
      return { ok: false, label, text: `FAIL ${label}\n${failures}${(r.stderr || '').slice(-6000)}${r.error ? String(r.error) : ''}\n` };
    }
    const part = (total, skipped, noun) => (skipped ? `${total - skipped} of ${total} ${noun} (${skipped} skipped)` : `${total} ${noun}`);
    const skippedCore = summary.per_corpus?.core?.skipped ?? 0;
    const skippedGrammar = summary.per_corpus?.grammar?.skipped ?? 0;
    return { ok: true, text: `PASS ${language}: ${part(core.vectors.length, skippedCore, 'core')} + ${part(grammar.cases.length, skippedGrammar, 'grammar')}\n` };
  }));
}
runLanguage('JavaScript', 'node', ['caid/conformance/runners/run.mjs'], REPO);
runLanguage('Python', PYTHON, ['caid/conformance/runners/run.py'], REPO);
runLanguage('Go', 'go', ['run', '.'], path.join(HERE, 'runners/go'));
run('JavaScript unit tests', 'node', ['--test', 'caid/impl/js/unit-tests.mjs'], REPO);
run('Python unit tests', PYTHON, ['caid/impl/python/test_caid.py'], REPO);
run('Go unit tests', 'go', ['test', '-count=1', './...'], GO_ROOT);

function parity(label, outputs) {
  const report = Promise.all(outputs.map(([language, output]) => output.then((text) => [language, text]))).then((present) => {
    if (present.some(([, output]) => output === null)) return null;
    const baseline = JSON.stringify(JSON.parse(present[0][1]));
    const diverging = present.slice(1).filter(([, output]) => JSON.stringify(JSON.parse(output)) !== baseline).map(([language]) => language);
    if (diverging.length) {
      return { ok: false, label, text: `FAIL ${label}: JavaScript != ${diverging.join(', ')}\n` };
    }
    return { ok: true, text: `PASS ${label}\n` };
  });
  steps.push(report);
}
parity('cross-language mapping verdict and reason parity', [
  ['JavaScript', run(`JavaScript mapping v3: ${mappingCorpus.vectors.length} vectors`, 'node', ['impl/js/run-mapping-vectors.mjs', '--json'])],
  ['Python', run(`Python mapping v3: ${mappingCorpus.vectors.length} vectors`, PYTHON, ['impl/python/run_mapping_vectors.py', '--json'])],
  ['Go', run(`Go mapping v3: ${mappingCorpus.vectors.length} vectors`, 'go', ['run', './cmd/mapping-vectors', '--json'], GO_ROOT)],
]);
parity('cross-language consequential-interoperability parity', [
  ['JavaScript', run(`JavaScript consequential interop: ${interopCorpus.vectors.length} vectors`, 'node', ['impl/js/run-mapping-vectors.mjs', '--corpus', interopCorpusPath, '--json'])],
  ['Python', run(`Python consequential interop: ${interopCorpus.vectors.length} vectors`, PYTHON, ['impl/python/run_mapping_vectors.py', '--corpus', interopCorpusPath, '--json'])],
  ['Go', run(`Go consequential interop: ${interopCorpus.vectors.length} vectors`, 'go', ['run', './cmd/mapping-vectors', '--corpus', interopCorpusPath, '--json'], GO_ROOT)],
]);

for (const step of steps) {
  const r = await step;
  if (r === null) continue; // a parity check whose inputs already failed
  if (r.ok) process.stdout.write(r.text);
  else {
    failed.push(r.label);
    process.stderr.write(r.text);
  }
}
if (failed.length) {
  process.stderr.write(`\nCAID conformance: ${failed.length} step(s) failed:\n  ${failed.join('\n  ')}\n`);
  process.exit(1);
}
// A vector with applies_when runs only where its suite condition holds
// (cbor-sha256 support is OPTIONAL); the runners count the others as skipped.
const conditional = core.vectors.filter((v) => v.applies_when).length + grammar.cases.filter((c) => c.applies_when).length;
console.log(`CAID conformance: green for ${core.vectors.length} core + ${grammar.cases.length} grammar + ${mappingCorpus.vectors.length} mapping + ${interopCorpus.vectors.length} consequential-interoperability vectors in JavaScript, Python and Go and against the spec oracle, except that ${conditional} of them apply only where an OPTIONAL suite is, or is not, implemented, and each runner skipped those whose condition does not hold for its implementation (the per-language lines above give what each ran).`);
