// SPDX-License-Identifier: Apache-2.0
//
// Sign an EP-EXTERNAL-VERIFICATION-STATEMENT-v1 over an EP conformance run.
//
// TWO DISTINCT PROCEDURES, honestly labeled, never interchangeable:
//
// MODE A (default, the meaningful one): --results <dir-or-files>
//   You ran YOUR OWN verifier over suites in conformance/vectors/ and saved
//   its per-vector output as <suite-file-name>.results.json files following
//   the plugfest contract: a JSON array of { "id": ..., "valid": ... }, one
//   entry per vector. This script compares your reported results against each
//   vector's expect.valid and signs a statement in your name.
//     procedure.id      = ep-conformance-own-implementation
//     procedure.version = EP-CONFORMANCE-RUN-OWN-IMPLEMENTATION-v1
//
// MODE B (--run-reference): executes this repository's own reference runner
//   (node conformance/run.mjs) and signs over its outcome. That is a
//   consistency check of one repository's own verifiers re-executed on your
//   machine. It is NOT an independent implementation, and the statement says
//   so in its limitations.
//     procedure.id      = ep-conformance-reference-runner
//     procedure.version = EP-CONFORMANCE-RUN-REFERENCE-RUNNER-v1
//
// A statement is signed even when results diverge from expectations
// (result.status = 'divergent'): a signed divergence is a valid finding.
// Structural problems (unknown suite, missing/duplicate/extra vector ids,
// malformed files) are refusals with distinct reasons and exit code 1.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { signExternalVerificationStatement } from '../../packages/gate/reports/external-verification.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const VECTORS_DIR = path.join(REPO_ROOT, 'conformance', 'vectors');

export const MODE_A_PROCEDURE = Object.freeze({
  id: 'ep-conformance-own-implementation',
  version: 'EP-CONFORMANCE-RUN-OWN-IMPLEMENTATION-v1',
});
export const MODE_B_PROCEDURE = Object.freeze({
  id: 'ep-conformance-reference-runner',
  version: 'EP-CONFORMANCE-RUN-REFERENCE-RUNNER-v1',
});

export const REFERENCE_RUNNER_LIMITATION =
  'This procedure re-executed the repository\'s own reference runner '
  + '(node conformance/run.mjs) on the signer\'s machine. That is a consistency '
  + 'check of one repository\'s own verifiers and is NOT an independent '
  + 'implementation of the protocol.';

const BASE_LIMITATIONS = [
  'This statement records the external verifier procedure and result; it does not authorize any action.',
  'It does not certify business correctness, legal compliance, or human wisdom.',
  'Acceptance depends on the relying party pinning the verifier key out of band.',
];

const MODE_A_LIMITATION =
  'Per-vector results were produced by the named implementation outside this '
  + 'harness and are self-reported; this harness only compared them against each '
  + 'suite vector\'s expect.valid.';

/** Fail-closed refusal with a distinct machine-readable reason. */
export class Refusal extends Error {
  constructor(reason, detail) {
    super(`REFUSED (${reason})${detail ? `: ${detail}` : ''}`);
    this.reason = reason;
  }
}

function sha256hexOf(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function gitCommit(root = REPO_ROOT) {
  try {
    const r = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' });
    if (r.status === 0) {
      const c = r.stdout.trim();
      if (/^[0-9a-f]{40}$/.test(c)) return c;
    }
  } catch { /* fall through to 'unknown' */ }
  return 'unknown';
}

/**
 * Load and structurally validate one suite file from conformance/vectors/.
 * Returns { file, digest, vectors: Map<id, expectValid>, json }.
 */
export function loadSuite(suiteFile, vectorsDir = VECTORS_DIR) {
  const p = path.join(vectorsDir, suiteFile);
  if (!fs.existsSync(p)) {
    throw new Refusal('unknown_suite', `no suite named ${suiteFile} in conformance/vectors/`);
  }
  let raw;
  let json;
  try {
    raw = fs.readFileSync(p);
    json = JSON.parse(raw.toString('utf8'));
  } catch (e) {
    throw new Refusal('suite_unreadable', `${suiteFile}: ${e.message}`);
  }
  if (!json || typeof json !== 'object' || !Array.isArray(json.vectors)) {
    throw new Refusal('malformed_suite', `${suiteFile}: missing vectors array`);
  }
  const vectors = new Map();
  for (const v of json.vectors) {
    if (!v || typeof v.id !== 'string' || !v.id || typeof v?.expect?.valid !== 'boolean') {
      throw new Refusal('malformed_suite', `${suiteFile}: every vector needs a string id and boolean expect.valid`);
    }
    if (vectors.has(v.id)) {
      throw new Refusal('malformed_suite', `${suiteFile}: duplicate vector id ${v.id}`);
    }
    vectors.set(v.id, v.expect.valid);
  }
  if (vectors.size === 0) {
    throw new Refusal('malformed_suite', `${suiteFile}: zero vectors`);
  }
  return { file: suiteFile, digest: sha256hexOf(raw), vectors, json };
}

/** Map a results file name to its suite file name in conformance/vectors/. */
export function suiteNameForResultsFile(resultsFileName) {
  const base = path.basename(resultsFileName);
  if (!base.endsWith('.results.json') || base === '.results.json') {
    throw new Refusal('results_filename_invalid',
      `${base}: results files must be named <suite-file-name>.results.json (e.g. receipts.v1.json.results.json)`);
  }
  const stem = base.slice(0, -'.results.json'.length);
  return stem.endsWith('.json') ? stem : `${stem}.json`;
}

/**
 * Load one plugfest-contract results file: a JSON array of {id, valid}.
 * Returns { digest, results: Map<id, valid> }.
 */
export function loadResults(resultsPath) {
  let raw;
  let json;
  try {
    raw = fs.readFileSync(resultsPath);
    json = JSON.parse(raw.toString('utf8'));
  } catch (e) {
    throw new Refusal('results_unreadable', `${resultsPath}: ${e.message}`);
  }
  if (!Array.isArray(json)) {
    throw new Refusal('results_not_array',
      `${resultsPath}: a results file is a JSON array of {"id": ..., "valid": ...}`);
  }
  const results = new Map();
  for (let i = 0; i < json.length; i++) {
    const entry = json[i];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
      || typeof entry.id !== 'string' || !entry.id || typeof entry.valid !== 'boolean') {
      throw new Refusal('malformed_results_entry',
        `${resultsPath}: entry ${i} must be {"id": <string>, "valid": <boolean>}`);
    }
    if (results.has(entry.id)) {
      throw new Refusal('duplicate_result_ids', `${resultsPath}: duplicate id ${entry.id}`);
    }
    results.set(entry.id, entry.valid);
  }
  return { digest: sha256hexOf(raw), results };
}

/**
 * Compare reported results against a suite's expectations.
 * Structural mismatches refuse; value mismatches count as divergence.
 * Returns { passed, total, ok }.
 */
export function compareSuiteResults(suite, results) {
  const missing = [...suite.vectors.keys()].filter((id) => !results.has(id));
  if (missing.length > 0) {
    throw new Refusal('missing_vector_ids', `${suite.file}: no result for ${missing.join(', ')}`);
  }
  const extra = [...results.keys()].filter((id) => !suite.vectors.has(id));
  if (extra.length > 0) {
    throw new Refusal('unknown_vector_ids', `${suite.file}: results name ids not in the suite: ${extra.join(', ')}`);
  }
  let passed = 0;
  for (const [id, expected] of suite.vectors) {
    if (results.get(id) === expected) passed++;
  }
  const total = suite.vectors.size;
  return { passed, total, ok: passed === total };
}

/** Expand --results arguments (dirs and/or files) into a flat file list. */
export function resolveResultsFiles(specs) {
  const files = [];
  for (const spec of specs) {
    const p = path.resolve(spec);
    if (!fs.existsSync(p)) {
      throw new Refusal('results_path_missing', p);
    }
    if (fs.statSync(p).isDirectory()) {
      const found = fs.readdirSync(p).filter((f) => f.endsWith('.results.json')).sort()
        .map((f) => path.join(p, f));
      files.push(...found);
    } else {
      files.push(p);
    }
  }
  const unique = [...new Set(files)];
  if (unique.length === 0) {
    throw new Refusal('no_results_files',
      'no *.results.json files found; each file must be named <suite-file-name>.results.json');
  }
  return unique;
}

function subjectFor(suiteEntries, commit) {
  return {
    kind: 'conformance_vector_pack',
    suites: suiteEntries.length,
    vectors: suiteEntries.reduce((n, s) => n + s.suite.vectors.size, 0),
    commit,
  };
}

function suiteDigests(suiteEntries) {
  const digests = {};
  for (const s of suiteEntries) digests[s.suite.file] = s.suite.digest;
  return digests;
}

/**
 * MODE A: build the unsigned statement arguments from the implementer's own
 * verifier results. suiteEntries: [{ suite, resultsDigest, comparison }].
 */
export function buildModeAStatementArgs({ suiteEntries, verifier, implementation, commit }) {
  const checks = suiteEntries.map((s) => ({
    id: s.suite.file,
    ok: s.comparison.ok,
    detail: `${s.comparison.passed}/${s.comparison.total}`,
  }));
  const allOk = checks.every((c) => c.ok);
  const resultsDigests = {};
  for (const s of suiteEntries) resultsDigests[s.suite.file] = s.resultsDigest;
  return {
    verifier,
    subject: subjectFor(suiteEntries, commit),
    procedure: { ...MODE_A_PROCEDURE },
    inputs: {
      commit,
      implementation,
      suite_digests: suiteDigests(suiteEntries),
      results_digests: resultsDigests,
    },
    result: { status: allOk ? 'verified' : 'divergent', checks },
    limitations: [MODE_A_LIMITATION, ...BASE_LIMITATIONS],
  };
}

/** Read the authoritative SUITES list out of conformance/run.mjs. */
export function referenceRunnerSuites(repoRoot = REPO_ROOT) {
  let src;
  try {
    src = fs.readFileSync(path.join(repoRoot, 'conformance', 'run.mjs'), 'utf8');
  } catch (e) {
    throw new Refusal('reference_runner_suites_unreadable', e.message);
  }
  const m = src.match(/const SUITES = \[([^\]]*)\]/);
  const names = m ? [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]) : [];
  if (names.length === 0) {
    throw new Refusal('reference_runner_suites_unreadable', 'could not locate the SUITES list in conformance/run.mjs');
  }
  return names;
}

/**
 * Parse per-suite pass counts out of the reference runner's stdout.
 * Fail-closed: any suite block we cannot find refuses.
 */
function parseRunnerOutput(output, suites) {
  const perSuite = [];
  let cursor = 0;
  for (const s of suites) {
    const header = `${s.json.suite || s.file} — `;
    const idx = output.indexOf(header, cursor);
    if (idx === -1) {
      throw new Refusal('reference_runner_output_unparseable', `no output block found for ${s.file}`);
    }
    let end = output.indexOf('\n\n', idx);
    if (end === -1) end = output.length;
    const block = output.slice(idx, end);
    const failures = block.split('\n').filter((line) => line.includes('✗')).length;
    perSuite.push({ suite: s, failures });
    cursor = end;
  }
  return perSuite;
}

/**
 * MODE B: build the unsigned statement arguments over a reference-runner
 * outcome. Factored out of the CLI so it is testable without the subprocess.
 * runner: { command, exit_code, output }.
 */
export function buildModeBStatementArgs({ suiteEntries, runner, verifier, commit }) {
  const suites = suiteEntries.map((s) => s.suite);
  const output = String(runner.output ?? '');
  if (/No implementations ran/.test(output) || /incomplete: only \d+\/\d+ implementations ran/.test(output)) {
    throw new Refusal('reference_runner_incomplete',
      'the reference runner did not complete across all its language lanes '
      + '(missing toolchain?); refusing to sign an incomplete run as a conformance outcome');
  }
  let checks;
  if (runner.exit_code === 0) {
    checks = suites.map((s) => ({ id: s.file, ok: true, detail: `${s.vectors.size}/${s.vectors.size}` }));
  } else {
    const perSuite = parseRunnerOutput(output, suites);
    if (!perSuite.some((p) => p.failures > 0)) {
      throw new Refusal('reference_runner_output_unparseable',
        'runner exited nonzero but no per-vector divergence could be attributed');
    }
    checks = perSuite.map(({ suite, failures }) => {
      const total = suite.vectors.size;
      const passed = Math.max(0, total - failures);
      return { id: suite.file, ok: failures === 0, detail: `${passed}/${total}` };
    });
  }
  const allOk = runner.exit_code === 0 && checks.every((c) => c.ok);
  return {
    verifier,
    subject: subjectFor(suiteEntries, commit),
    procedure: { ...MODE_B_PROCEDURE },
    inputs: {
      commit,
      suite_digests: suiteDigests(suiteEntries),
      reference_runner: {
        command: runner.command,
        exit_code: runner.exit_code,
        output_digest: sha256hexOf(Buffer.from(output, 'utf8')),
      },
    },
    result: { status: allOk ? 'verified' : 'divergent', checks },
    limitations: [REFERENCE_RUNNER_LIMITATION, ...BASE_LIMITATIONS],
  };
}

function loadPrivateKey(keyPath) {
  let pem;
  try {
    pem = fs.readFileSync(keyPath, 'utf8');
  } catch (e) {
    throw new Refusal('key_unreadable', `${keyPath}: ${e.message} (run generate-key.mjs first)`);
  }
  let key;
  try {
    key = crypto.createPrivateKey(pem);
  } catch (e) {
    throw new Refusal('key_unreadable', `${keyPath}: not a parseable private key (${e.message})`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Refusal('key_not_ed25519', `${keyPath}: got ${key.asymmetricKeyType}`);
  }
  return key;
}

function main() {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        results: { type: 'string', multiple: true },
        'run-reference': { type: 'boolean', default: false },
        'verifier-id': { type: 'string' },
        'verifier-name': { type: 'string' },
        org: { type: 'string' },
        implementation: { type: 'string' },
        key: { type: 'string' },
        out: { type: 'string' },
      },
    }));
  } catch (e) {
    throw new Refusal('bad_arguments', e.message);
  }

  const modeA = Array.isArray(values.results) && values.results.length > 0;
  const modeB = values['run-reference'] === true;
  if (modeA && modeB) {
    throw new Refusal('mode_conflict', 'pass either --results (your own verifier, MODE A) or --run-reference (MODE B), not both');
  }
  if (!modeA && !modeB) {
    throw new Refusal('mode_missing', 'pass --results <dir-or-files> (your own verifier, MODE A) or --run-reference (MODE B)');
  }
  if (modeB && values.implementation) {
    throw new Refusal('mode_conflict', '--implementation names YOUR verifier; it does not apply to --run-reference');
  }
  if (!values['verifier-id']) {
    throw new Refusal('verifier_id_missing', 'pass --verifier-id (e.g. ext:verifier:cosa); the statement is signed in this name');
  }
  if (modeA && !values.implementation) {
    throw new Refusal('implementation_missing', 'pass --implementation to name what produced the results (e.g. "cosa-verify 0.3.0, Rust")');
  }

  const verifier = {
    id: values['verifier-id'],
    ...(values['verifier-name'] ? { name: values['verifier-name'] } : {}),
    ...(values.org ? { organization: values.org } : {}),
  };
  const privateKey = loadPrivateKey(path.resolve(values.key ?? path.join(HERE, 'out', 'private-key.pem')));
  const outDir = path.resolve(values.out ?? path.join(HERE, 'out'));
  const commit = gitCommit();

  let args;
  if (modeA) {
    const files = resolveResultsFiles(values.results);
    const suiteEntries = [];
    const seen = new Set();
    for (const f of files) {
      const suiteFile = suiteNameForResultsFile(f);
      if (seen.has(suiteFile)) {
        throw new Refusal('duplicate_suite_results', `more than one results file maps to ${suiteFile}`);
      }
      seen.add(suiteFile);
      const suite = loadSuite(suiteFile);
      const { digest, results } = loadResults(f);
      suiteEntries.push({ suite, resultsDigest: digest, comparison: compareSuiteResults(suite, results) });
    }
    suiteEntries.sort((a, b) => a.suite.file.localeCompare(b.suite.file));
    args = buildModeAStatementArgs({ suiteEntries, verifier, implementation: values.implementation, commit });
    process.stdout.write(`MODE A: own-implementation results (${MODE_A_PROCEDURE.version})\n`);
  } else {
    process.stdout.write(`MODE B: re-executing the repository's own reference runner (${MODE_B_PROCEDURE.version})\n`);
    process.stdout.write('NOTE: this is a consistency check of the repository\'s own verifiers, not an independent implementation.\n');
    const suiteEntries = referenceRunnerSuites().map((name) => ({ suite: loadSuite(name) }));
    const run = spawnSync('node', ['conformance/run.mjs'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (run.error) {
      throw new Refusal('reference_runner_failed_to_start', run.error.message);
    }
    args = buildModeBStatementArgs({
      suiteEntries,
      runner: {
        command: 'node conformance/run.mjs',
        exit_code: run.status ?? -1,
        output: `${run.stdout ?? ''}${run.stderr ?? ''}`,
      },
      verifier,
      commit,
    });
  }

  const statement = signExternalVerificationStatement(args, privateKey);
  fs.mkdirSync(outDir, { recursive: true });
  const statementPath = path.join(outDir, 'statement.json');
  fs.writeFileSync(statementPath, `${JSON.stringify(statement, null, 2)}\n`);

  for (const c of statement.result.checks) {
    process.stdout.write(`  ${c.id}: ${c.detail} ${c.ok ? 'ok' : 'DIVERGENT'}\n`);
  }
  process.stdout.write(`result.status: ${statement.result.status}\n`);
  process.stdout.write(`statement: ${statementPath}\n`);
  process.stdout.write(`statement_digest: ${statement.signature.statement_digest}\n`);
}

const isMain = process.argv[1]
  && pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    main();
  } catch (e) {
    if (e instanceof Refusal) {
      process.stderr.write(`${e.message}\n`);
      process.exit(1);
    }
    throw e;
  }
}
