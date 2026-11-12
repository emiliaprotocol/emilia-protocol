// SPDX-License-Identifier: Apache-2.0
// Reverse direction: EMILIA's published vectors under Gargoyle's own verifier.
//
// Runs the two live suites Gargoyle implements (EP-RECEIPT-v1 and
// EP-CANONICALIZATION-v1) through `python -m gargoyle.emilia_runner` in a
// Gargoyle checkout pinned by commit and file digest, and compares every row
// with this repository's result contract. Also checks that a suite Gargoyle
// does not implement is refused outright rather than answered.
//
//   GARGOYLE_CHECKOUT=/path/to/Gargoyle node interop/gargoyle-emilia/reverse.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSuiteContract, compareResultRow, validateResultRows } from '../../conformance/result-contract.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const source = JSON.parse(readFileSync(join(here, 'reverse-source.json'), 'utf8'));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const checkout = process.env.GARGOYLE_CHECKOUT;
assert.ok(checkout, `set GARGOYLE_CHECKOUT to a Gargoyle checkout at ${source.upstream_commit}`);
const python = process.env.PYTHON || 'python3';
const upstream = {
  cwd: checkout, encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024,
  env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
};
const local = { ...upstream, cwd: root };

// Pin the upstream verifier: the commit, a clean package tree, and the exact
// bytes of the three modules that produce the verdicts.
const head = execFileSync('git', ['rev-parse', 'HEAD'], upstream).trim();
assert.equal(head, source.upstream_commit, 'Gargoyle checkout is not at the pinned commit');
const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=all', '--',
  'gargoyle', 'pyproject.toml'], upstream).trim();
assert.equal(dirty, '', 'Gargoyle package tree must be clean');
for (const [path, digest] of Object.entries(source.upstream_files)) {
  assert.equal(sha256(readFileSync(join(checkout, path))), digest, `${path} differs from the pinned bytes`);
}

// Pin the suites to the bytes the recorded run used. A later vector revision
// is a new run, not an upgrade of this one.
const suites = {};
for (const [suiteFile, digest] of Object.entries(source.suites)) {
  const vectorsPath = resolve(root, 'conformance/vectors', suiteFile);
  const bytes = readFileSync(vectorsPath);
  assert.equal(sha256(bytes), digest, `${suiteFile} changed since the recorded run`);
  const suite = JSON.parse(bytes.toString('utf8'));
  const contract = buildSuiteContract(suiteFile, suite);
  const rows = JSON.parse(execFileSync(python, ['-m', 'gargoyle.emilia_runner', vectorsPath], upstream));
  const byId = validateResultRows(contract, rows);
  const divergences = [];
  for (const vector of suite.vectors) {
    const comparison = compareResultRow(contract, byId.get(vector.id));
    if (!comparison.ok) divergences.push({ id: vector.id, detail: comparison.detail });
  }
  assert.deepEqual(divergences, [], `${suiteFile}: Gargoyle verdicts diverge from the published expectations`);
  suites[suiteFile] = { suite: suite.suite, vectors: suite.vectors.length, rows };
}

// A suite outside Gargoyle's coverage must be a refusal (exit status 2 and no
// rows), never a batch of false verdicts that would read as rejections.
let refusal = null;
try {
  execFileSync(python, ['-m', 'gargoyle.emilia_runner',
    resolve(root, 'conformance/vectors', source.uncovered_suite)], { ...upstream, stdio: ['ignore', 'pipe', 'pipe'] });
} catch (error) {
  refusal = { status: error.status, stdout: String(error.stdout || '') };
}
assert.ok(refusal && refusal.status === 2 && refusal.stdout === '',
  `${source.uncovered_suite} must be refused with exit status 2 and no rows`);

const emiliaCommit = execFileSync('git', ['rev-parse', 'HEAD'], local).trim();
const emiliaDirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=all', '--',
  'conformance/vectors', 'conformance/result-contract.mjs', 'conformance/suites.mjs'], local).trim();
assert.equal(emiliaDirty, '', 'EMILIA vectors and result contract must be clean');
const gargoyleVersion = execFileSync(python, ['-c',
  'import importlib.metadata as m; print(m.version("gargoyle-receipts"))'], upstream).trim();

console.log(JSON.stringify({
  format: 'emilia-gargoyle-reverse-result-v1',
  upstream_repository: source.upstream_repository,
  upstream_commit: source.upstream_commit,
  upstream_runner: 'python -m gargoyle.emilia_runner',
  upstream_files: source.upstream_files,
  gargoyle_version: gargoyleVersion,
  emilia_checkout_commit: emiliaCommit,
  emilia_vectors_clean: true,
  python: execFileSync(python, ['--version'], upstream).trim(),
  node: process.version,
  suites,
  uncovered_suite_refused: source.uncovered_suite,
  scope: source.scope,
}, null, 2));
