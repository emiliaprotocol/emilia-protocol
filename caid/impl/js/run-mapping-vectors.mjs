#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// Runs a CAID mapping corpus (conformance/mapping-vectors.json, or the
// consequential-interoperability corpus with --corpus) against mapping.mjs.
// The corpus is read with this port's strict decoder. A vector's expected
// reasons are an exact list ("reasons"); "reason_contains" is accepted for
// corpora that pin a single reason.
//
// Usage: node run-mapping-vectors.mjs [--corpus FILE] [--json]

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeCaidDocument } from './caid.mjs';
import { compareMappedActions, mappingProfileHash } from './mapping.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = path.resolve(HERE, '../../conformance/mapping-vectors.json');
const clone = (value) => structuredClone(value);

function readCorpus(file) {
  const decoded = decodeCaidDocument(fs.readFileSync(file));
  if (!decoded.ok) throw new Error(`${file} is not a strict JSON text`);
  return decoded.value;
}

function corpusPath(argv = process.argv.slice(2)) {
  const index = argv.indexOf('--corpus');
  if (index === -1) return VECTORS;
  if (!argv[index + 1]) throw new Error('--corpus requires a path');
  return path.resolve(argv[index + 1]);
}

function segments(pointer) {
  return pointer.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'));
}

function mutate(root, operation) {
  const parts = segments(operation.path);
  let parent = root;
  for (const part of parts.slice(0, -1)) parent = parent[Array.isArray(parent) ? Number(part) : part];
  const key = Array.isArray(parent) ? Number(parts.at(-1)) : parts.at(-1);
  if (operation.op === 'delete') {
    if (Array.isArray(parent)) parent.splice(key, 1);
    else delete parent[key];
  } else if (operation.op === 'set') {
    Object.defineProperty(parent, key, { value: clone(operation.value), writable: true, enumerable: true, configurable: true });
  } else {
    throw new Error('unsupported vector mutation: ' + operation.op);
  }
}

function buildSide(corpus, descriptor) {
  const profile = clone(corpus.profiles[descriptor.profile]);
  const side = {
    source: clone(corpus.sources[descriptor.source]),
    profile,
    source_descriptor: clone(profile.source_format),
    expected_profile_hash: descriptor.pin === 'profile' ? mappingProfileHash(profile) : descriptor.pin,
    native_verified: descriptor.native_verified !== false,
  };
  return side;
}

export function runMappingVectors(corpus = readCorpus(VECTORS)) {
  const results = [];
  for (const vector of corpus.vectors) {
    const left = buildSide(corpus, vector.left);
    const right = buildSide(corpus, vector.right);
    for (const operation of vector.mutations || []) mutate(operation.side === 'left' ? left[operation.target] : right[operation.target], operation);
    for (const sideName of vector.repin_after_mutation || []) {
      const side = sideName === 'left' ? left : right;
      side.expected_profile_hash = mappingProfileHash(side.profile);
    }
    const result = compareMappedActions(left, right, {
      definitions: corpus.definitions,
      enumSnapshots: corpus.enum_snapshots,
      suite: Object.prototype.hasOwnProperty.call(vector, 'suite') ? vector.suite : corpus.suite,
    });
    const verdictOK = result.verdict === vector.expect.verdict;
    const reasonsOK = vector.expect.reason_contains
      ? result.reasons.includes(vector.expect.reason_contains)
      : JSON.stringify(result.reasons) === JSON.stringify(vector.expect.reasons || []);
    results.push({ id: vector.id, pass: verdictOK && reasonsOK, verdict: result.verdict, reasons: result.reasons });
  }
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const results = runMappingVectors(readCorpus(corpusPath()));
  if (process.argv.includes('--json')) {
    process.stdout.write(JSON.stringify(results) + '\n');
  } else {
    for (const result of results) console.log((result.pass ? 'PASS' : 'FAIL') + ' ' + result.id + ' ' + result.verdict);
  }
  if (results.some((result) => !result.pass)) process.exitCode = 1;
}
