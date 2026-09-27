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
//      (v5 invariants, history v4 bytes, digests.json, definition checks).
//   3. Corpora: vectors.json (v5), grammar-vectors.json and
//      mapping-vectors.json (v2) equal their builders' output; version 4 and
//      mapping version 1 carry forward (check-v4.mjs); the JavaScript runner
//      passes every vector against the spec oracle itself.
//   4. Ports: the core and grammar corpora in JavaScript, Python and Go
//      through public entry points (caid/conformance/runners), the Go unit
//      tests, and the mapping corpus v2 and consequential-interoperability
//      corpus in all three with cross-language parity.
//
// CAID_PYTHON names the Python interpreter (default python3).

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const REPO = path.resolve(ROOT, '..');
const GO_ROOT = path.join(ROOT, 'impl/go');
const PYTHON = process.env.CAID_PYTHON || 'python3';
const failed = [];

function run(label, command, args, cwd = ROOT) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    failed.push(label);
    process.stderr.write(`FAIL ${label}\n${(result.stdout || '').slice(-6000)}${(result.stderr || '').slice(-6000)}${result.error ? String(result.error) : ''}\n`);
    return null;
  }
  console.log(`PASS ${label}`);
  return result.stdout.trim();
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
  if (problems.length) {
    failed.push('registry identity');
    process.stderr.write(`FAIL registry identity\n  ${problems.join('\n  ')}\n`);
  } else {
    console.log(`PASS registry identity: ${registry.types.length} unique types; mapping definitions match exact public entries; ${interopCorpus.definitions.length} interoperability-local definition(s) do not alias it`);
  }
}
run('registry check (caid/registry/check.mjs)', 'node', ['caid/registry/check.mjs'], REPO);

// ---------------------------------------------------------------- 3. corpora
run('core corpus v5 is its builder\'s output', 'node', ['caid/conformance/tools/build-core.mjs', '--check'], REPO);
run('grammar corpus is its builder\'s output', 'node', ['caid/conformance/tools/build-grammar.mjs', '--check'], REPO);
run('mapping corpus v2 is its builder\'s output', 'node', ['caid/conformance/tools/build-mapping.mjs', '--check'], REPO);
run('version 4 and mapping version 1 carried forward (check-v4.mjs)', 'node', ['caid/conformance/check-v4.mjs'], REPO);
run('core and grammar corpora against the spec oracle', 'node', ['caid/conformance/runners/run.mjs', '--impl', 'caid/conformance/tools/reference-port.mjs'], REPO);

// ---------------------------------------------------------------- 4. ports
const core = JSON.parse(readFileSync(path.join(ROOT, 'conformance/vectors.json'), 'utf8'));
const grammar = JSON.parse(readFileSync(path.join(ROOT, 'conformance/grammar-vectors.json'), 'utf8'));
const corpora = `${core.vectors.length} core + ${grammar.cases.length} grammar`;
run(`JavaScript: ${corpora}`, 'node', ['caid/conformance/runners/run.mjs'], REPO);
run(`Python: ${corpora}`, PYTHON, ['caid/conformance/runners/run.py'], REPO);
run(`Go: ${corpora}`, 'go', ['run', '.'], path.join(HERE, 'runners/go'));
run('Go unit tests', 'go', ['test', '-count=1', './...'], GO_ROOT);

function parity(label, outputs) {
  const present = outputs.filter(([, output]) => output !== null);
  if (present.length !== outputs.length) return;
  const baseline = JSON.stringify(JSON.parse(present[0][1]));
  const diverging = present.slice(1).filter(([, output]) => JSON.stringify(JSON.parse(output)) !== baseline).map(([language]) => language);
  if (diverging.length) {
    failed.push(label);
    process.stderr.write(`FAIL ${label}: JavaScript != ${diverging.join(', ')}\n`);
  } else {
    console.log(`PASS ${label}`);
  }
}
parity('cross-language mapping verdict and reason parity', [
  ['JavaScript', run(`JavaScript mapping v2: ${mappingCorpus.vectors.length} vectors`, 'node', ['impl/js/run-mapping-vectors.mjs', '--json'])],
  ['Python', run(`Python mapping v2: ${mappingCorpus.vectors.length} vectors`, PYTHON, ['impl/python/run_mapping_vectors.py', '--json'])],
  ['Go', run(`Go mapping v2: ${mappingCorpus.vectors.length} vectors`, 'go', ['run', './cmd/mapping-vectors', '--json'], GO_ROOT)],
]);
parity('cross-language consequential-interoperability parity', [
  ['JavaScript', run(`JavaScript consequential interop: ${interopCorpus.vectors.length} vectors`, 'node', ['impl/js/run-mapping-vectors.mjs', '--corpus', interopCorpusPath, '--json'])],
  ['Python', run(`Python consequential interop: ${interopCorpus.vectors.length} vectors`, PYTHON, ['impl/python/run_mapping_vectors.py', '--corpus', interopCorpusPath, '--json'])],
  ['Go', run(`Go consequential interop: ${interopCorpus.vectors.length} vectors`, 'go', ['run', './cmd/mapping-vectors', '--corpus', interopCorpusPath, '--json'], GO_ROOT)],
]);

if (failed.length) {
  process.stderr.write(`\nCAID conformance: ${failed.length} step(s) failed:\n  ${failed.join('\n  ')}\n`);
  process.exit(1);
}
console.log(`CAID conformance: ${core.vectors.length} core + ${grammar.cases.length} grammar + ${mappingCorpus.vectors.length} mapping + ${interopCorpus.vectors.length} consequential-interoperability vectors green in JavaScript, Python and Go, against the spec oracle.`);
