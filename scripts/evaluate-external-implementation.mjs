#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE_PATH = path.join(ROOT, 'conformance/clean-room/bundle.v1.json');
const argv = process.argv.slice(2);
const option = (name) => {
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
};
const pinPath = option('--pin');
const sourcePath = option('--source');
const runnerPath = option('--runner');
const emitPath = option('--emit');
if (!pinPath || !sourcePath || !runnerPath || !emitPath) {
  console.error('usage: evaluate-external-implementation --pin FILE --source CHECKOUT --runner EXECUTABLE --emit FILE');
  process.exit(2);
}

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
function readStrictJson(target, label) {
  const bytes = fs.readFileSync(target);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const gate = strictParseGate(text);
  if (!gate.ok) throw new Error(`${label}: ${gate.reason}`);
  return { bytes, value: JSON.parse(text) };
}

const pinAbsolute = path.resolve(pinPath);
const sourceAbsolute = path.resolve(sourcePath);
const runnerAbsolute = path.resolve(runnerPath);
const { bytes: pinBytes, value: pin } = readStrictJson(pinAbsolute, 'external implementation pin');
if (pin['@version'] !== 'EP-EXTERNAL-IMPLEMENTATION-PIN-v1') throw new Error('unsupported external implementation pin');
if (!/^[0-9a-f]{40}$/.test(pin.source?.commit || '') || !/^[0-9a-f]{40}$/.test(pin.source?.tree_oid || '')) {
  throw new Error('external source commit and tree must be immutable Git object IDs');
}
if (!fs.statSync(runnerAbsolute).isFile()) throw new Error('external runner is not a file');
const implementationRoot = path.resolve(sourceAbsolute, pin.source.tree_path);
if (runnerAbsolute !== implementationRoot && !runnerAbsolute.startsWith(`${implementationRoot}${path.sep}`)) {
  throw new Error('external runner is outside the pinned implementation tree');
}

const git = (...args) => execFileSync('git', ['-C', sourceAbsolute, ...args], { encoding: 'utf8' }).trim();
const sourceCommit = git('rev-parse', 'HEAD');
if (sourceCommit !== pin.source.commit) throw new Error(`external source commit drift: ${sourceCommit}`);
const sourceTree = git('rev-parse', `${sourceCommit}:${pin.source.tree_path}`);
if (sourceTree !== pin.source.tree_oid) throw new Error(`external source tree drift: ${sourceTree}`);

const { bytes: bundleBytes, value: bundle } = readStrictJson(BUNDLE_PATH, 'vector bundle');
if (bundle['@version'] !== 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v1' || !Array.isArray(bundle.suites)) {
  throw new Error('unsupported vector bundle');
}
const suites = [];
let vectorCount = 0;
for (const suiteRef of bundle.suites) {
  const suitePath = path.resolve(ROOT, suiteRef.path);
  const { bytes, value: suite } = readStrictJson(suitePath, `suite ${suiteRef.path}`);
  if (sha256(bytes) !== suiteRef.sha256) throw new Error(`vector bundle drift: ${suiteRef.path}`);
  let stdout;
  try {
    stdout = execFileSync(runnerAbsolute, [suitePath], {
      cwd: implementationRoot,
      encoding: 'utf8',
      timeout: 180_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    throw new Error(`external runner failed ${suiteRef.path}: ${error.stderr || error.message}`);
  }
  const outputGate = strictParseGate(stdout);
  if (!outputGate.ok) throw new Error(`external runner output ${suiteRef.path}: ${outputGate.reason}`);
  const results = JSON.parse(stdout);
  const expected = new Map(suite.vectors.map((vector) => [vector.id, vector.expect.valid]));
  if (!Array.isArray(results) || results.length !== expected.size) {
    throw new Error(`external runner returned the wrong result count for ${suiteRef.path}`);
  }
  const seen = new Set();
  for (const result of results) {
    if (!result || typeof result !== 'object' || Array.isArray(result)
      || Object.keys(result).length !== 2 || typeof result.id !== 'string'
      || typeof result.valid !== 'boolean' || seen.has(result.id) || !expected.has(result.id)) {
      throw new Error(`external runner emitted a malformed result for ${suiteRef.path}`);
    }
    if (result.valid !== expected.get(result.id)) throw new Error(`external divergence ${suiteRef.path}#${result.id}`);
    seen.add(result.id);
  }
  vectorCount += expected.size;
  suites.push({ path: suiteRef.path, sha256: suiteRef.sha256, vectors: expected.size, status: 'pass' });
}

const evaluatorCommit = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const report = {
  '@version': 'EP-EXTERNAL-CONFORMANCE-EVALUATION-v1',
  status: 'pass',
  implementation: pin.implementation,
  source: { ...pin.source, verified: true },
  build: {
    ...pin.build,
    runner_sha256: sha256(fs.readFileSync(runnerAbsolute)),
  },
  construction_evidence: pin.construction_evidence,
  evaluator: {
    repository: 'https://github.com/emiliaprotocol/emilia-protocol',
    commit: evaluatorCommit,
    pin_sha256: sha256(pinBytes),
  },
  conformance: {
    bundle: bundle['@version'],
    bundle_sha256: sha256(bundleBytes),
    suites: suites.length,
    vectors: vectorCount,
    status: 'pass',
  },
  suites,
};
report.report_sha256 = sha256(Buffer.from(canonicalize(report), 'utf8'));
const target = path.resolve(emitPath);
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
console.log(`EXTERNAL CONFORMANCE: PASS (${suites.length} suites, ${vectorCount} vectors; source ${sourceCommit}; sha256:${report.report_sha256})`);
