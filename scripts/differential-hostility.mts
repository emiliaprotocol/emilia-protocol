#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Deterministic hostile-input differential runner. The built-in JS/Python/Go
// ports are one-team consistency evidence; accepted external runners can be
// added without changing the corpus or upgrading that claim implicitly.
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv: string[] = process.argv.slice(2);
const option = (name: string): string | null => {
  const index: number = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
};
const emitPath: string | null = option('--emit');
if (argv.includes('--emit') && !emitPath) throw new Error('--emit requires a path');
const manifestOption: string | null = option('--manifest');
if (argv.includes('--manifest') && !manifestOption) throw new Error('--manifest requires a path');
const liveManifestPath: string | null = manifestOption ? path.resolve(manifestOption) : null;
const sourceBytes: Buffer = fs.readFileSync(liveManifestPath
  ?? path.join(ROOT, 'conformance/clean-room/bundle.v1.json'));
const BUNDLE: any = JSON.parse(sourceBytes.toString('utf8'));
const liveManifestMode: boolean = liveManifestPath !== null;
const PRIMARY_FIELDS: string[] = [
  'document', 'signoff', 'quorum', 'revocation', 'time_attestation',
  'trust_receipt', 'provenance_chain', 'evidence_record', 'canonicalization',
  'currency', 'initiator_attestation', 'consumption_proof', 'witness_quorum',
  'timestamp_proof',
  'resolution_receipt', 'resolution_authorization', 'predicted_effects',
  'attestation', 'aec_chain', 'proof',
];
const destructiveValues: any[] = [null, {}, [], '', true, 9007199254740992];
const timestampNames: RegExp = /^(?:issued_at|expires_at|signed_at|revoked_at|checked_at|valid_from|valid_to|gen_time|now|not_before|not_after)$/i;
const publicKeyNames: RegExp = /(?:^|_)(?:public_key|approver_public_key|log_public_key|tsa_keys|revoker_keys)$/i;
const graphArrayNames: RegExp = /^(?:links|nodes|edges|members|contexts|signoffs|chain|delegations)$/i;

function clone(value: any): any {
  return structuredClone(value);
}

function mutateFirstLeaf(value: any): boolean {
  if (!value || typeof value !== 'object') return false;
  for (const key of Object.keys(value).sort()) {
    const child: any = value[key];
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

function mutateNamed(value: any, pattern: RegExp, replacement: any): boolean {
  if (!value || typeof value !== 'object') return false;
  for (const key of Object.keys(value).sort()) {
    if (pattern.test(key)) {
      value[key] = clone(replacement);
      return true;
    }
    if (mutateNamed(value[key], pattern, replacement)) return true;
  }
  return false;
}

function mutateAllNamed(value: any, pattern: RegExp, replacement: any): number {
  if (!value || typeof value !== 'object') return 0;
  let count: number = 0;
  for (const key of Object.keys(value).sort()) {
    if (pattern.test(key)) {
      value[key] = clone(replacement);
      count += 1;
    } else {
      count += mutateAllNamed(value[key], pattern, replacement);
    }
  }
  return count;
}

function duplicateNamedGraphNode(value: any): boolean {
  if (!value || typeof value !== 'object') return false;
  for (const key of Object.keys(value).sort()) {
    if (graphArrayNames.test(key) && Array.isArray(value[key]) && value[key].length > 0) {
      value[key] = [clone(value[key][0]), ...value[key]];
      return true;
    }
    if (duplicateNamedGraphNode(value[key])) return true;
  }
  return false;
}

function reverseObjectOrder(value: any): any {
  if (Array.isArray(value)) return value.map(reverseObjectOrder);
  if (!value || typeof value !== 'object') return value;
  const out: any = {};
  for (const key of Object.keys(value).reverse()) out[key] = reverseObjectOrder(value[key]);
  return out;
}

function stableJson(value: any): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key: string) =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const cases: any[] = [];
const expectations: Map<string, any> = new Map();
const caseSuites: Map<string, string> = new Map();
const categoryCounts: Map<string, number> = new Map();
const coveredSuites: any[] = [];
function addCase(value: any, category: string, expectation: any, suite: string): void {
  cases.push(value);
  expectations.set(value.id, expectation);
  caseSuites.set(value.id, suite);
  categoryCounts.set(category, (categoryCounts.get(category) || 0) + 1);
}

for (const suiteRef of BUNDLE.suites) {
  const cataloguePath: string = path.join(ROOT, suiteRef.path);
  const catalogueBytes: Buffer = fs.readFileSync(cataloguePath);
  if (liveManifestMode) {
    const actualHash: string = crypto.createHash('sha256').update(catalogueBytes).digest('hex');
    if (actualHash !== suiteRef.sha256) throw new Error(`live manifest suite hash mismatch: ${suiteRef.path}`);
  }
  const executionRelativePath: string = liveManifestMode
    ? (suiteRef.execution_path || suiteRef.path)
    : suiteRef.path;
  const executionBytes: Buffer = fs.readFileSync(path.join(ROOT, executionRelativePath));
  if (liveManifestMode && suiteRef.execution_path) {
    const actualExecutionHash: string = crypto.createHash('sha256').update(executionBytes).digest('hex');
    if (actualExecutionHash !== suiteRef.execution_sha256) {
      throw new Error(`live manifest execution suite hash mismatch: ${executionRelativePath}`);
    }
  }
  const suite: any = JSON.parse(executionBytes.toString('utf8'));
  if (liveManifestMode && suite.vectors.length !== suiteRef.vectors) {
    throw new Error(`live manifest vector count mismatch: ${suiteRef.path}`);
  }
  coveredSuites.push({
    path: suiteRef.path,
    sha256: suiteRef.sha256,
    vectors: suiteRef.vectors,
    execution_path: executionRelativePath,
    ...(suiteRef.execution_sha256 ? { execution_sha256: suiteRef.execution_sha256 } : {}),
  });
  const selected: any[] = [];
  const positive: any = suite.vectors.find((vector: any) => vector.expect?.valid === true);
  const negative: any = suite.vectors.find((vector: any) => vector.expect?.valid === false);
  if (positive) selected.push(positive);
  if (negative && negative !== positive) selected.push(negative);
  if (liveManifestMode && selected.length === 0) {
    selected.push(...suite.vectors.slice(0, Math.min(2, suite.vectors.length)));
  }

  for (const source of selected) {
    const prefix: string = `${path.basename(suiteRef.path, '.json')}_${source.id}`.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const primary: string | undefined = PRIMARY_FIELDS.find((field: string) => Object.hasOwn(source, field));
    if (!primary) throw new Error(`no polymorphic primary field for ${suiteRef.path}#${source.id}`);

    const inert = clone(source);
    inert.id = `${prefix}__unknown_wrapper`;
    inert._ep_hostility = { ignored: true, unicode: 'replacement-�-astral-🙂' };
    const hasSimpleValidExpectation: boolean = source.expect
      && Object.hasOwn(source.expect, 'valid')
      && !Object.hasOwn(source.expect, 'result_digest');
    addCase(inert, 'unknown-wrapper', hasSimpleValidExpectation
      ? { kind: 'metamorphic', expected: source.expect.valid }
      : { kind: 'consensus' }, suite.suite);

    const unicode = clone(source);
    unicode.id = `${prefix}__unicode_aliases`;
    unicode._ep_hostility = { 'caf\u00e9': 'caf\u00e9', 'cafe\u0301': 'cafe\u0301', bidi: '\u202ereliance' };
    addCase(unicode, 'unicode', hasSimpleValidExpectation
      ? { kind: 'metamorphic', expected: source.expect.valid }
      : { kind: 'consensus' }, suite.suite);

    const permuted = reverseObjectOrder(source);
    permuted.id = `${prefix}__object_permutation`;
    addCase(permuted, 'action-permutation', hasSimpleValidExpectation
      ? { kind: 'metamorphic', expected: source.expect.valid }
      : { kind: 'consensus' }, suite.suite);

    if (liveManifestMode && (
      !Object.hasOwn(source.expect || {}, 'valid')
      || Object.hasOwn(source.expect || {}, 'result_digest')
    )) continue;

    // Exact-result suites often hash a typed substructure before they can
    // return a verdict. Keep their live-manifest coverage metamorphic and add
    // targeted, semantically specified mutations below instead of treating a
    // thrown canonical-domain error as a valid refusal.
    for (let i = 0; i < destructiveValues.length; i += 1) {
      const hostile = clone(source);
      hostile.id = `${prefix}__type_${i}`;
      hostile[primary] = clone(destructiveValues[i]);
      addCase(hostile, 'hostile-type', { kind: 'reject' }, suite.suite);
    }

    if (source[primary] && typeof source[primary] === 'object') {
      const nested = clone(source);
      nested.id = `${prefix}__nested_leaf`;
      if (mutateFirstLeaf(nested[primary])) addCase(nested, 'nested-leaf', { kind: 'consensus' }, suite.suite);
    }

    const timestamp = clone(source);
    timestamp.id = `${prefix}__impossible_timestamp`;
    if (mutateNamed(timestamp[primary], timestampNames, '2026-02-30T25:61:61Z')) {
      addCase(timestamp, 'timestamp', { kind: primary === 'currency' ? 'consensus' : 'reject' }, suite.suite);
    }

    const spki = clone(source);
    spki.id = `${prefix}__invalid_spki`;
    if (mutateAllNamed(spki, publicKeyNames, '***not-base64url-spki***') > 0) {
      addCase(spki, 'spki', { kind: 'reject' }, suite.suite);
    }

    const graph = clone(source);
    graph.id = `${prefix}__duplicate_graph_node`;
    if (duplicateNamedGraphNode(graph[primary])) addCase(graph, 'evidence-graph', { kind: 'consensus' }, suite.suite);
  }
}

if (liveManifestMode) {
  const uniquePaths: Set<string> = new Set(coveredSuites.map((entry: any) => entry.path));
  const coveredVectors: number = coveredSuites.reduce(
    (sum: number, entry: any) => sum + entry.vectors,
    0,
  );
  if (uniquePaths.size !== coveredSuites.length) {
    throw new Error('live manifest contains duplicate suite paths');
  }
  if (coveredSuites.length !== BUNDLE.totals?.suites
      || coveredVectors !== BUNDLE.totals?.vectors) {
    throw new Error('live manifest totals do not match its exact suite revisions');
  }
}

if (liveManifestMode) {
  const outcomeSuiteRef: any = BUNDLE.suites.find((entry: any) =>
    entry.path === 'conformance/vectors/outcome-binding.v1.json');
  if (!outcomeSuiteRef) throw new Error('live manifest omits outcome-binding.v1');
  const outcomeSuite: any = JSON.parse(fs.readFileSync(path.join(ROOT, outcomeSuiteRef.path), 'utf8'));
  const source: any = outcomeSuite.vectors.find((vector: any) =>
    vector.kind === 'predicate' && Array.isArray(vector.predicted_effects));
  if (!source) throw new Error('outcome-binding.v1 has no predicted_effects regression seed');
  const malformed: any = clone(source);
  malformed.id = 'current_outcome_binding__malformed_predicted_effects_object';
  malformed.predicted_effects = {};
  addCase(malformed, 'malformed-predicted-effects', {
    kind: 'typed-result',
    expected: { outcome: 'incomparable' },
  }, outcomeSuite.suite);
}

const corpus = {
  suite: liveManifestMode ? 'EP-DIFFERENTIAL-HOSTILITY-v3' : 'EP-DIFFERENTIAL-HOSTILITY-v2',
  seed: liveManifestMode ? 'ep-hostility-v3-current-manifest' : 'ep-hostility-v2-fixed',
  vectors: cases,
};
const corpusBytes = Buffer.from(`${JSON.stringify(corpus)}\n`);
const corpusHash = crypto.createHash('sha256').update(corpusBytes).digest('hex');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-hostility-'));
const corpusPath = path.join(dir, 'vectors.json');
fs.writeFileSync(corpusPath, corpusBytes);

const implementations: any[] = [
  { name: 'javascript', kind: 'one-team-port', command: 'node', args: ['conformance/runners/run-js.mjs'], cwd: ROOT },
  { name: 'python', kind: 'one-team-port', command: 'python3', args: ['conformance/runners/run_py.py'], cwd: ROOT },
  { name: 'go', kind: 'one-team-port', command: 'go', args: ['run', './cmd/conformance'], cwd: path.join(ROOT, 'packages/go-verify') },
];

const externalPath: string | null = option('--external-runners');
if (externalPath) {
  const config: any = JSON.parse(fs.readFileSync(path.resolve(externalPath), 'utf8'));
  if (!Array.isArray(config.runners)) throw new Error('external runner config must contain a runners array');
  for (const runner of config.runners) {
    if (typeof runner?.name !== 'string' || typeof runner.command !== 'string' || !Array.isArray(runner.args || [])) {
      throw new Error('external runner config contains a malformed runner');
    }
    if (!path.isAbsolute(runner.command)) throw new Error(`external runner ${runner.name} command must be absolute`);
    const commandReal: string = fs.realpathSync(runner.command);
    if (!fs.statSync(commandReal).isFile()) throw new Error(`external runner ${runner.name} command is not a file`);
    implementations.push({
      name: runner.name,
      kind: 'external-submission',
      dispatch: runner.dispatch || 'mixed',
      command: commandReal,
      args: runner.args || [],
      cwd: path.resolve(ROOT, runner.cwd || '.'),
      artifactSha256: crypto.createHash('sha256').update(fs.readFileSync(commandReal)).digest('hex'),
    });
    const lastImplementation: any = implementations.at(-1);
    if (!['mixed', 'suite'].includes(lastImplementation?.dispatch)) {
      throw new Error(`external runner ${runner.name} has unsupported dispatch mode`);
    }
  }
}
if (new Set(implementations.map((implementation) => implementation.name)).size !== implementations.length) {
  throw new Error('implementation names must be unique');
}

interface RawParserCase {
  id: string;
  bytes: Buffer;
}

interface Implementation {
  name: string;
  kind: string;
  command: string;
  args: string[];
  cwd: string;
  dispatch?: string;
  artifactSha256?: string;
}

interface ReportData {
  '@version': string;
  status: string;
  corpus: any;
  implementations: any[];
  divergences: any[];
  report_sha256?: string;
}

type DeepNested = { leaf: boolean } | { nested: DeepNested };

let deep: DeepNested = { leaf: true };
for (let i = 0; i < 66; i += 1) deep = { nested: deep };
const rawParserCases: RawParserCase[] = [
  { id: 'truncated-json', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[') },
  { id: 'duplicate-root-member', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[],"vectors":[]}') },
  { id: 'duplicate-vector-member', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[{"id":"a","id":"b"}]}') },
  { id: 'unpaired-surrogate', bytes: Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[{"id":"\\ud800"}]}') },
  { id: 'over-depth', bytes: Buffer.from(JSON.stringify({ suite: 'EP-RECEIPT-v1', vectors: [{ id: 'deep', document: deep }] })) },
  { id: 'invalid-utf8', bytes: Buffer.concat([Buffer.from('{"suite":"EP-RECEIPT-v1","vectors":[],"x":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}')]) },
];

function executeCorpus(implementation: Implementation, inputPath: string, expectedCount: number, label: string): any[] {
  let stdout: string;
  try {
    stdout = execFileSync(implementation.command, [...implementation.args, inputPath], {
      cwd: implementation.cwd,
      encoding: 'utf8',
      timeout: 180_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error: any) {
    throw new Error(`${implementation.name} crashed on ${label}: ${error.stderr || error.message}`);
  }
  let parsed: any;
  try { parsed = JSON.parse(stdout); } catch (error: any) { throw new Error(`${implementation.name} emitted invalid JSON for ${label}: ${error.message}`); }
  if (!Array.isArray(parsed) || parsed.length !== expectedCount) {
    throw new Error(`${implementation.name} returned ${parsed?.length} results for ${expectedCount} ${label} cases`);
  }
  return parsed;
}

function writeReport(status: string, divergences: any[]): void {
  if (!emitPath) return;
  const report: any = {
    '@version': 'EP-DIFFERENTIAL-HOSTILITY-REPORT-v1',
    status,
    corpus: {
      suite: corpus.suite,
      seed: corpus.seed,
      sha256: corpusHash,
      structured_cases: cases.length,
      raw_parser_cases: rawParserCases.length,
      categories: Object.fromEntries([...categoryCounts.entries()].sort()),
      ...(liveManifestMode ? {
        source_manifest: {
          path: path.relative(ROOT, liveManifestPath as string),
          sha256: crypto.createHash('sha256').update(sourceBytes).digest('hex'),
          suites: BUNDLE.totals?.suites,
          vectors: BUNDLE.totals?.vectors,
        },
        covered_suites: coveredSuites,
        required_regressions: [{
          id: 'current_outcome_binding__malformed_predicted_effects_object',
          expected: { outcome: 'incomparable' },
        }],
      } : {}),
    },
    implementations: implementations.map((implementation: Implementation) => ({
      name: implementation.name,
      relationship: implementation.kind,
      dispatch: implementation.dispatch || 'mixed',
      ...(implementation.artifactSha256 ? { artifact_sha256: implementation.artifactSha256 } : {}),
    })),
    divergences,
  };
  report.report_sha256 = crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex');
  const target = path.resolve(emitPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
}

try {
  const divergences: any[] = [];
  const executionFailures: Map<string, Set<string>> = new Map(implementations.map((implementation: Implementation) => [implementation.name, new Set()]));
  for (const rawCase of rawParserCases) {
    const rawPath: string = path.join(dir, `${rawCase.id}.json`);
    fs.writeFileSync(rawPath, rawCase.bytes);
    for (const implementation of implementations) {
      const result: any = spawnSync(implementation.command, [...implementation.args, rawPath], {
        cwd: implementation.cwd,
        encoding: 'utf8',
        timeout: 180_000,
        maxBuffer: 64 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      if (result.status === 0) {
        divergences.push({ id: rawCase.id, implementation: implementation.name, reason: 'malformed_raw_json_accepted' });
      } else if (result.signal || /panicked at/.test(result.stderr || '')) {
        divergences.push({ id: rawCase.id, implementation: implementation.name, reason: 'runner_crash' });
      }
    }
  }

  const outputs: Map<string, Map<string, any>> = new Map();
  for (const implementation of implementations) {
    let parsed: any[];
    if (implementation.dispatch === 'suite') {
      parsed = [];
      const bySuite: Map<string, any[]> = new Map();
      for (const hostile of cases) {
        const suite: string = caseSuites.get(hostile.id) || '';
        if (!bySuite.has(suite)) bySuite.set(suite, []);
        bySuite.get(suite)!.push(hostile);
      }
      let suiteIndex: number = 0;
      for (const [suite, suiteCases] of bySuite) {
        const suitePath: string = path.join(dir, `suite-${suiteIndex}.json`);
        fs.writeFileSync(suitePath, `${JSON.stringify({ suite, seed: corpus.seed, vectors: suiteCases })}\n`);
        try {
          parsed.push(...executeCorpus(implementation, suitePath, suiteCases.length, `hostile ${suite} corpus`));
        } catch {
          for (let caseIndex: number = 0; caseIndex < suiteCases.length; caseIndex += 1) {
            const hostile: any = suiteCases[caseIndex];
            const singlePath: string = path.join(dir, `suite-${suiteIndex}-case-${caseIndex}.json`);
            fs.writeFileSync(singlePath, `${JSON.stringify({ suite, seed: corpus.seed, vectors: [hostile] })}\n`);
            try {
              parsed.push(...executeCorpus(implementation, singlePath, 1, `hostile ${suite} case ${hostile.id}`));
            } catch (error: any) {
              (executionFailures.get(implementation.name) as Set<string>).add(hostile.id);
              const detail: string = String(error.message)
                .replace(/\(\d+\) panicked at/g, '(process) panicked at')
                .split('\n').map((line: string) => line.trim()).filter(Boolean).slice(0, 2).join(' | ');
              divergences.push({
                id: hostile.id,
                implementation: implementation.name,
                reason: 'runner_crash',
                detail,
              });
            }
          }
        }
        suiteIndex += 1;
      }
    } else {
      parsed = executeCorpus(implementation, corpusPath, cases.length, 'hostile mixed-suite corpus');
    }
    const map: Map<string, any> = new Map();
    for (const result of parsed) {
      if (map.has(result.id) || typeof result?.id !== 'string') throw new Error(`${implementation.name} emitted malformed or duplicate result ${result?.id}`);
      const normalized: any = { ...result };
      delete normalized.id;
      if (!liveManifestMode && typeof normalized.valid !== 'boolean') throw new Error(`${implementation.name} emitted malformed or duplicate result ${result.id}`);
      map.set(result.id, normalized);
    }
    outputs.set(implementation.name, map);
  }

  for (const hostile of cases) {
    if (implementations.some((implementation: Implementation) => (executionFailures.get(implementation.name) as Set<string>).has(hostile.id))) continue;
    const values: any[] = implementations.map((implementation: Implementation) => outputs.get(implementation.name)!.get(hostile.id));
    if (values.some((value: any) => value === undefined)) {
      divergences.push({ id: hostile.id, reason: 'missing_result', values });
      continue;
    }
    const encodedValues: string[] = values.map((value: any) => stableJson(value));
    if (!encodedValues.every((value: string) => value === encodedValues[0])) {
      divergences.push({ id: hostile.id, reason: 'cross_language_divergence', values });
      continue;
    }
    const expected: any = expectations.get(hostile.id);
    const valid: any = values[0]?.valid;
    if (expected.kind === 'metamorphic' && valid !== expected.expected) {
      divergences.push({ id: hostile.id, reason: 'metamorphic_verdict_changed', expected: expected.expected, values });
    } else if (expected.kind === 'reject' && valid !== false && values[0]?.outcome !== 'incomparable') {
      divergences.push({ id: hostile.id, reason: 'hostile_input_accepted', values });
    } else if (expected.kind === 'typed-result') {
      for (const [field, value] of Object.entries(expected.expected)) {
        if (values[0]?.[field] !== value) {
          divergences.push({ id: hostile.id, reason: 'required_regression_not_refused', expected: expected.expected, values });
          break;
        }
      }
    }
  }
  if (divergences.length) {
    writeReport('fail', divergences);
    console.error(`DIFFERENTIAL HOSTILITY: FAIL (${divergences.length} divergence(s))`);
    for (const divergence of divergences.slice(0, 50)) console.error(JSON.stringify(divergence));
    process.exitCode = 1;
  } else {
    const externalCount: number = implementations.filter((implementation: Implementation) => implementation.kind === 'external-submission').length;
    const categories: Record<string, number> = Object.fromEntries([...categoryCounts.entries()].sort());
    writeReport('pass', []);
    console.log(`DIFFERENTIAL HOSTILITY: PASS (${cases.length} structured cases + ${rawParserCases.length} raw parser refusals; ${implementations.length} implementations; ${externalCount} external; corpus sha256:${corpusHash})`);
    console.log(`  categories ${JSON.stringify(categories)}`);
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
