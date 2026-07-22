#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GO_ROOT = path.join(ROOT, 'impl/go');

const registry = JSON.parse(readFileSync(path.join(ROOT, 'registry/action-types.json'), 'utf8'));
const mappingCorpus = JSON.parse(readFileSync(path.join(ROOT, 'conformance/mapping-vectors.json'), 'utf8'));
const stable = (value) => {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
};

const names = registry.types.map((entry) => entry.action_type);
if (new Set(names).size !== names.length) {
  throw new Error('duplicate action type in public registry');
}
for (const definition of mappingCorpus.definitions) {
  const registered = registry.types.find((entry) => entry.action_type === definition.action_type);
  if (!registered || JSON.stringify(stable(registered)) !== JSON.stringify(stable(definition))) {
    throw new Error(`mapping definition aliases public type ${definition.action_type} with different semantics`);
  }
}
console.log(`PASS registry identity: ${registry.types.length} unique types; mapping definitions match exact public entries`);

function run(label, command, args, cwd = ROOT) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    process.stderr.write(`FAIL ${label}\n${result.stdout || ''}${result.stderr || ''}`);
    process.exit(1);
  }
  console.log(`PASS ${label}`);
  return result.stdout.trim();
}

run('JavaScript core: 48 vectors', 'node', ['impl/js/run-vectors.mjs']);
run('Python core: 48 vectors', 'python3', ['impl/python/run_vectors.py']);
run('Go core: 48 vectors', 'go', ['run', './cmd/core-vectors'], GO_ROOT);

const mappingOutputs = [
  ['JavaScript', run(`JavaScript mapping: ${mappingCorpus.vectors.length} vectors`, 'node', ['impl/js/run-mapping-vectors.mjs', '--json'])],
  ['Python', run(`Python mapping: ${mappingCorpus.vectors.length} vectors`, 'python3', ['impl/python/run_mapping_vectors.py', '--json'])],
  ['Go', run(`Go mapping: ${mappingCorpus.vectors.length} vectors`, 'go', ['run', './cmd/mapping-vectors', '--json'], GO_ROOT)],
];

const baseline = JSON.stringify(JSON.parse(mappingOutputs[0][1]));
for (const [language, output] of mappingOutputs.slice(1)) {
  if (JSON.stringify(JSON.parse(output)) !== baseline) {
    process.stderr.write(`FAIL mapping output divergence: JavaScript != ${language}\n`);
    process.exit(1);
  }
}

console.log('PASS cross-language mapping verdict and reason parity');
console.log(`CAID conformance: 48 core + ${mappingCorpus.vectors.length} mapping vectors green in JS, Python, and Go.`);
