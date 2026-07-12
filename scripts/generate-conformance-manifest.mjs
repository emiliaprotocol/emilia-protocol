#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';
import { LIVE_SUITE_FILES } from '../conformance/suites.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE_PATH = path.join(ROOT, 'conformance/clean-room/bundle.v1.json');
const CATALOG_PATH = path.join(ROOT, 'conformance/suites.mjs');
const argv = process.argv.slice(2);
const cleanRoom = argv.includes('--clean-room');
const DEFAULT_OUTPUT = path.join(ROOT, cleanRoom
  ? 'conformance/clean-room/conformance-manifest.v1.json'
  : 'conformance/conformance-manifest.json');
const emitIndex = argv.indexOf('--emit');
const emitPath = emitIndex >= 0 ? path.resolve(argv[emitIndex + 1] || '') : null;
const check = argv.includes('--check');
if (emitIndex >= 0 && !argv[emitIndex + 1]) throw new Error('--emit requires a path');

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const relative = (absolute) => path.relative(ROOT, absolute).split(path.sep).join('/');

function parseStrictJson(text, label) {
  const gate = strictParseGate(text);
  if (!gate.ok) throw new Error(`${label}: ${gate.reason}`);
  try { return JSON.parse(text); }
  catch (error) { throw new Error(`${label}: ${error.message}`); }
}

function filesUnder(root, predicate = () => true) {
  const out = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.name === '__pycache__' || entry.name === 'dist' || entry.name.startsWith('.')) continue;
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile() && predicate(absolute)) out.push(absolute);
    }
  };
  walk(root);
  return out;
}

function sourceTree(paths) {
  const members = paths
    .flatMap((source) => (fs.statSync(source).isDirectory() ? filesUnder(source) : [source]))
    .filter((file, index, all) => all.indexOf(file) === index)
    .map((file) => {
      const bytes = fs.readFileSync(file);
      return { path: relative(file), sha256: sha256(bytes), bytes: bytes.length };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
  return {
    files: members.length,
    bytes: members.reduce((sum, member) => sum + member.bytes, 0),
    tree_sha256: sha256(Buffer.from(canonicalize(members), 'utf8')),
  };
}

const implementations = [
  {
    id: 'emilia-javascript-reference', language: 'javascript', relationship: 'one_team_port',
    command: process.execPath, args: (suite) => ['conformance/runners/run-js.mjs', suite], cwd: ROOT,
    runner: path.join(ROOT, 'conformance/runners/run-js.mjs'),
    sources: [path.join(ROOT, 'packages/verify')],
  },
  {
    id: 'emilia-python-reference', language: 'python', relationship: 'one_team_port',
    command: 'python3', args: (suite) => ['conformance/runners/run_py.py', suite], cwd: ROOT,
    runner: path.join(ROOT, 'conformance/runners/run_py.py'),
    sources: [path.join(ROOT, 'packages/python-verify/emilia_verify')],
  },
  {
    id: 'emilia-go-reference', language: 'go', relationship: 'one_team_port',
    command: 'go', args: (suite) => ['run', './cmd/conformance', suite], cwd: path.join(ROOT, 'packages/go-verify'),
    runner: path.join(ROOT, 'packages/go-verify/cmd/conformance/main.go'),
    sources: [path.join(ROOT, 'packages/go-verify')],
  },
];

let bundleBytes;
let bundleVersion;
let bundlePath;
let suiteRefs;
if (cleanRoom) {
  bundlePath = BUNDLE_PATH;
  bundleBytes = fs.readFileSync(bundlePath);
  const bundle = parseStrictJson(bundleBytes.toString('utf8'), 'conformance bundle');
  if (bundle['@version'] !== 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v1') throw new Error('unsupported conformance bundle');
  bundleVersion = bundle['@version'];
  suiteRefs = bundle.suites;
} else {
  bundlePath = CATALOG_PATH;
  bundleBytes = fs.readFileSync(bundlePath);
  bundleVersion = 'EP-LIVE-CONFORMANCE-CATALOG-v1';
  suiteRefs = LIVE_SUITE_FILES.map((file) => ({ path: `conformance/vectors/${file}` }));
}
const suites = [];
let vectorCount = 0;
for (const suiteRef of suiteRefs) {
  const suitePath = path.resolve(ROOT, suiteRef.path);
  const bytes = fs.readFileSync(suitePath);
  const suiteSha256 = sha256(bytes);
  if (suiteRef.sha256 && suiteSha256 !== suiteRef.sha256) throw new Error(`conformance vector drift: ${suiteRef.path}`);
  const suite = parseStrictJson(bytes.toString('utf8'), `suite ${suiteRef.path}`);
  if (!Array.isArray(suite.vectors)) throw new Error(`suite has no vectors: ${suiteRef.path}`);
  vectorCount += suite.vectors.length;
  suites.push({ path: suiteRef.path, sha256: suiteSha256, vectors: suite.vectors.length });
}

const implementationResults = [];
for (const implementation of implementations) {
  const normalized = [];
  for (const suite of suites) {
    const suitePath = path.resolve(ROOT, suite.path);
    let stdout;
    try {
      stdout = execFileSync(implementation.command, implementation.args(suitePath), {
        cwd: implementation.cwd,
        encoding: 'utf8',
        timeout: 180_000,
        maxBuffer: 64 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      throw new Error(`${implementation.id} failed ${suite.path}: ${error.stderr || error.message}`);
    }
    const results = parseStrictJson(stdout, `${implementation.id} output for ${suite.path}`);
    const sourceSuite = parseStrictJson(fs.readFileSync(suitePath, 'utf8'), `suite ${suite.path}`);
    const expected = new Map(sourceSuite.vectors.map((vector) => [vector.id, vector.expect.valid]));
    if (!Array.isArray(results) || results.length !== expected.size) throw new Error(`${implementation.id} returned wrong result count for ${suite.path}`);
    const seen = new Set();
    for (const result of results) {
      if (!result || typeof result !== 'object' || Array.isArray(result)
        || Object.keys(result).length !== 2 || !Object.hasOwn(result, 'id') || !Object.hasOwn(result, 'valid')
        || typeof result.id !== 'string' || typeof result.valid !== 'boolean' || seen.has(result.id)) {
        throw new Error(`${implementation.id} emitted a malformed result for ${suite.path}`);
      }
      seen.add(result.id);
      if (!expected.has(result.id) || expected.get(result.id) !== result.valid) {
        throw new Error(`${implementation.id} disagreed on ${suite.path}#${result.id}`);
      }
      normalized.push({ suite: suite.path, id: result.id, valid: result.valid });
    }
  }
  normalized.sort((a, b) => a.suite.localeCompare(b.suite) || a.id.localeCompare(b.id));
  const runnerBytes = fs.readFileSync(implementation.runner);
  implementationResults.push({
    implementation_id: implementation.id,
    language: implementation.language,
    relationship: implementation.relationship,
    runner: { path: relative(implementation.runner), sha256: sha256(runnerBytes) },
    source: sourceTree(implementation.sources),
    suites: suites.length,
    vectors: normalized.length,
    normalized_results_sha256: sha256(Buffer.from(canonicalize(normalized), 'utf8')),
    status: 'pass',
  });
}

const manifest = {
  '@version': 'EP-CONFORMANCE-MANIFEST-v1',
  claim_scope: cleanRoom
    ? 'same-team consistency over the frozen external clean-room bundle; not independent implementation evidence'
    : 'current same-team cross-language consistency; not independent implementation evidence',
  vector_bundle: {
    version: bundleVersion,
    path: relative(bundlePath),
    sha256: sha256(bundleBytes),
  },
  suites,
  totals: { suites: suites.length, vectors: vectorCount, implementations: implementationResults.length },
  implementations: implementationResults,
};
manifest.manifest_sha256 = sha256(Buffer.from(canonicalize(manifest), 'utf8'));
const output = `${JSON.stringify(manifest, null, 2)}\n`;

if (check) {
  const expected = fs.readFileSync(DEFAULT_OUTPUT, 'utf8');
  if (expected !== output) throw new Error(`${relative(DEFAULT_OUTPUT)} is stale; regenerate its conformance manifest`);
}
if (emitPath) {
  fs.mkdirSync(path.dirname(emitPath), { recursive: true });
  fs.writeFileSync(emitPath, output);
}
if (!check && !emitPath) process.stdout.write(output);
console.error(`CONFORMANCE MANIFEST: PASS (${cleanRoom ? 'clean-room frozen' : 'live'}; ${suites.length} suites, ${vectorCount} vectors, ${implementationResults.length} one-team ports; sha256:${manifest.manifest_sha256})`);
