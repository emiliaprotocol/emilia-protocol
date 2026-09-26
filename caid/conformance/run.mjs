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
const interopCorpusPath = path.join(ROOT, 'interop/consequential-action-v1/mapping-vectors.json');
const interopCorpus = JSON.parse(readFileSync(interopCorpusPath, 'utf8'));
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
for (const definition of interopCorpus.definitions) {
  if (registry.types.some((entry) => entry.action_type === definition.action_type)) {
    throw new Error(`interoperability-local action type ${definition.action_type} aliases the public registry`);
  }
}
console.log(`PASS registry identity: ${registry.types.length} unique types; mapping definitions match exact public entries`);

// Every active enum field must either resolve under this registry version or
// be listed in unresolved_external_enums, so a type that cannot produce a
// CAID is never silently counted as usable.
const pinnedSets = new Set((registry.enum_snapshot_files ?? []).map((entry) =>
  JSON.stringify([entry.values_ref, entry.values_snapshot, entry.values_sha256])));
const unresolved = new Set();
for (const type of registry.types.filter((entry) => entry.status === 'active')) {
  for (const field of [...(type.required_fields ?? []), ...(type.optional_fields ?? [])]) {
    if (field.type !== 'enum') continue;
    const inline = Array.isArray(field.values) && !('values_ref' in field);
    const compact = typeof field.values_ref === 'string' && field.values_ref.startsWith('inline:');
    const pinned = pinnedSets.has(JSON.stringify([field.values_ref, field.values_snapshot, field.values_sha256]));
    if (!inline && !compact && !pinned) unresolved.add(`${type.action_type}.${field.name}`);
  }
}
const listedUnresolved = new Set((registry.unresolved_external_enums ?? []).map((item) => `${item.action_type}.${item.field}`));
if (JSON.stringify([...unresolved].sort()) !== JSON.stringify([...listedUnresolved].sort())) {
  throw new Error(`unresolved_external_enums differs from the active enum fields without a pinned snapshot: ${[...unresolved].sort().join(', ')}`);
}
const blockedTypes = new Set((registry.unresolved_external_enums ?? []).filter((item) => item.required).map((item) => item.action_type));
const activeTypes = registry.types.filter((entry) => entry.status === 'active').length;
console.log(`PASS registry enum coverage: ${activeTypes - blockedTypes.size} of ${activeTypes} active types resolve every enum; ${blockedTypes.size} listed as blocked by ${listedUnresolved.size} unpinned external enums`);
console.log(`PASS local interop identity: ${interopCorpus.definitions.length} definition does not modify the public registry`);

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

const coreCorpus = JSON.parse(readFileSync(path.join(ROOT, 'conformance/vectors.json'), 'utf8'));
run(`JavaScript core: ${coreCorpus.vectors.length} vectors`, 'node', ['impl/js/run-vectors.mjs']);
run(`Python core: ${coreCorpus.vectors.length} vectors`, 'python3', ['impl/python/run_vectors.py']);
run(`Go core: ${coreCorpus.vectors.length} vectors`, 'go', ['run', './cmd/core-vectors'], GO_ROOT);
run('Go unit tests (strict JSON decoding, UTF-8 refusal)', 'go', ['test', '-count=1', './...'], GO_ROOT);

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

const interopOutputs = [
  ['JavaScript', run(`JavaScript consequential interop: ${interopCorpus.vectors.length} vectors`, 'node', ['impl/js/run-mapping-vectors.mjs', '--corpus', interopCorpusPath, '--json'])],
  ['Python', run(`Python consequential interop: ${interopCorpus.vectors.length} vectors`, 'python3', ['impl/python/run_mapping_vectors.py', '--corpus', interopCorpusPath, '--json'])],
  ['Go', run(`Go consequential interop: ${interopCorpus.vectors.length} vectors`, 'go', ['run', './cmd/mapping-vectors', '--corpus', interopCorpusPath, '--json'], GO_ROOT)],
];
const interopBaseline = JSON.stringify(JSON.parse(interopOutputs[0][1]));
for (const [language, output] of interopOutputs.slice(1)) {
  if (JSON.stringify(JSON.parse(output)) !== interopBaseline) {
    process.stderr.write(`FAIL consequential interop output divergence: JavaScript != ${language}\n`);
    process.exit(1);
  }
}

console.log('PASS cross-language consequential-interoperability verdict and reason parity');
console.log(`CAID conformance: ${coreCorpus.vectors.length} core + ${mappingCorpus.vectors.length} base mapping + ${interopCorpus.vectors.length} consequential-interoperability vectors green in JS, Python, and Go.`);
