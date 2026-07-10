#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Deterministic hostile-input differential runner for the one-team JS/Python/Go
// ports. Agreement is a consistency result, never an independence claim.
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE = JSON.parse(fs.readFileSync(path.join(ROOT, 'conformance/clean-room/bundle.v1.json'), 'utf8'));
const PRIMARY_FIELDS = [
  'document', 'signoff', 'quorum', 'revocation', 'time_attestation',
  'trust_receipt', 'provenance_chain', 'evidence_record', 'canonicalization',
  'currency', 'initiator_attestation', 'consumption_proof', 'witness_quorum',
  'timestamp_proof',
];
const destructiveValues = [null, {}, [], '', true, 9007199254740992];

function clone(value) {
  return structuredClone(value);
}

function mutateFirstLeaf(value) {
  if (!value || typeof value !== 'object') return false;
  for (const key of Object.keys(value).sort()) {
    const child = value[key];
    if (typeof child === 'string') {
      value[key] = `${child}#hostile`;
      return true;
    }
    if (typeof child === 'number') {
      value[key] = child + 1;
      return true;
    }
    if (mutateFirstLeaf(child)) return true;
  }
  return false;
}

const cases = [];
const expectations = new Map();
for (const suiteRef of BUNDLE.suites) {
  const suite = JSON.parse(fs.readFileSync(path.join(ROOT, suiteRef.path), 'utf8'));
  const selected = [];
  const positive = suite.vectors.find((vector) => vector.expect?.valid === true);
  const negative = suite.vectors.find((vector) => vector.expect?.valid === false);
  if (positive) selected.push(positive);
  if (negative && negative !== positive) selected.push(negative);

  for (const source of selected) {
    const prefix = `${path.basename(suiteRef.path, '.json')}_${source.id}`.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const primary = PRIMARY_FIELDS.find((field) => Object.hasOwn(source, field));
    if (!primary) throw new Error(`no polymorphic primary field for ${suiteRef.path}#${source.id}`);

    const inert = clone(source);
    inert.id = `${prefix}__unknown_wrapper`;
    inert._ep_hostility = { ignored: true, unicode: 'replacement-�-astral-🙂' };
    cases.push(inert);
    expectations.set(inert.id, { kind: 'metamorphic', expected: source.expect.valid });

    for (let i = 0; i < destructiveValues.length; i += 1) {
      const hostile = clone(source);
      hostile.id = `${prefix}__type_${i}`;
      hostile[primary] = clone(destructiveValues[i]);
      cases.push(hostile);
      expectations.set(hostile.id, { kind: 'consensus' });
    }

    if (source[primary] && typeof source[primary] === 'object') {
      const nested = clone(source);
      nested.id = `${prefix}__nested_leaf`;
      if (mutateFirstLeaf(nested[primary])) {
        cases.push(nested);
        expectations.set(nested.id, { kind: 'consensus' });
      }
    }
  }
}

const corpus = {
  suite: 'EP-DIFFERENTIAL-HOSTILITY-v1',
  seed: 'ep-hostility-v1-fixed',
  vectors: cases,
};
const corpusBytes = Buffer.from(`${JSON.stringify(corpus)}\n`);
const corpusHash = crypto.createHash('sha256').update(corpusBytes).digest('hex');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-hostility-'));
const corpusPath = path.join(dir, 'vectors.json');
fs.writeFileSync(corpusPath, corpusBytes);

const implementations = [
  { name: 'javascript', command: 'node', args: ['conformance/runners/run-js.mjs'], cwd: ROOT },
  { name: 'python', command: 'python3', args: ['conformance/runners/run_py.py'], cwd: ROOT },
  { name: 'go', command: 'go', args: ['run', './cmd/conformance'], cwd: path.join(ROOT, 'packages/go-verify') },
];

try {
  const outputs = new Map();
  for (const implementation of implementations) {
    let stdout;
    try {
      stdout = execFileSync(implementation.command, [...implementation.args, corpusPath], {
        cwd: implementation.cwd,
        encoding: 'utf8',
        timeout: 180_000,
        maxBuffer: 64 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      throw new Error(`${implementation.name} crashed on hostile corpus: ${error.stderr || error.message}`);
    }
    let parsed;
    try { parsed = JSON.parse(stdout); } catch (error) { throw new Error(`${implementation.name} emitted invalid JSON: ${error.message}`); }
    if (!Array.isArray(parsed) || parsed.length !== cases.length) throw new Error(`${implementation.name} returned ${parsed?.length} results for ${cases.length} cases`);
    const map = new Map();
    for (const result of parsed) {
      if (map.has(result.id) || typeof result.valid !== 'boolean') throw new Error(`${implementation.name} emitted malformed or duplicate result ${result.id}`);
      map.set(result.id, result.valid);
    }
    outputs.set(implementation.name, map);
  }

  const divergences = [];
  for (const hostile of cases) {
    const values = implementations.map((implementation) => outputs.get(implementation.name).get(hostile.id));
    if (values.some((value) => typeof value !== 'boolean')) {
      divergences.push({ id: hostile.id, reason: 'missing_result', values });
      continue;
    }
    if (!values.every((value) => value === values[0])) {
      divergences.push({ id: hostile.id, reason: 'cross_language_divergence', values });
      continue;
    }
    const expected = expectations.get(hostile.id);
    if (expected.kind === 'metamorphic' && values[0] !== expected.expected) {
      divergences.push({ id: hostile.id, reason: 'unknown_wrapper_changed_verdict', expected: expected.expected, values });
    }
  }
  if (divergences.length) {
    console.error(`DIFFERENTIAL HOSTILITY: FAIL (${divergences.length} divergence(s))`);
    for (const divergence of divergences.slice(0, 50)) console.error(JSON.stringify(divergence));
    process.exitCode = 1;
  } else {
    console.log(`DIFFERENTIAL HOSTILITY: PASS (${cases.length} hostile/metamorphic cases, 3 one-team ports, corpus sha256:${corpusHash})`);
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
