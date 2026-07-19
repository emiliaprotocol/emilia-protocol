#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Resolve and execute every exact security claim, then bind the result to the
// reproducible release artifacts reviewers receive. This gate deliberately
// rejects keyword/substr coverage as evidence of an invariant.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyReproduciblePackage } from './verify-reproducible-package.mjs';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';
import {
  buildSuiteContract,
  compareResultRow,
  executionSuiteFile,
  validateResultRows,
} from '../conformance/result-contract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = path.join(ROOT, 'security', 'claims.v1.json');
const DEFAULT_RESOLVED = path.join(ROOT, 'security', 'security-case.json');
const SELF = fileURLToPath(import.meta.url);
const args = process.argv.slice(2);
const execute = args.includes('--execute');
const emitIndex = args.indexOf('--emit');
const emitPath = emitIndex >= 0 ? args[emitIndex + 1] : null;
if (emitIndex >= 0 && !emitPath) throw new Error('--emit requires a path');

const errors = [];
const evidenceFiles = new Set([
  path.relative(ROOT, SOURCE),
  path.relative(ROOT, SELF),
  'conformance/result-contract.mjs',
  'conformance/runners/strict-json.mjs',
  'conformance/suites.mjs',
]);
const executionPlan = new Map();
const crossLanguageCases = new Map();
const boundedFormalPlan = new Map();
const executionEvidence = [];
const fail = (id, message) => errors.push(`[${id}] ${message}`);
const nonEmpty = (value) => typeof value === 'string' && value.trim().length > 0;
const escaped = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function resolveFile(id, relative) {
  if (!nonEmpty(relative)) {
    fail(id, 'missing evidence file path');
    return null;
  }
  const absolute = path.resolve(ROOT, relative);
  if (absolute !== ROOT && !absolute.startsWith(`${ROOT}${path.sep}`)) {
    fail(id, `path escapes repository: ${relative}`);
    return null;
  }
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
    fail(id, `evidence file not found: ${relative}`);
    return null;
  }
  evidenceFiles.add(path.relative(ROOT, absolute));
  return absolute;
}

function deepSubset(actual, expected) {
  if (expected === null || typeof expected !== 'object') return Object.is(actual, expected);
  if (Array.isArray(expected)) {
    return Array.isArray(actual) && expected.length === actual.length
      && expected.every((value, index) => deepSubset(actual[index], value));
  }
  return actual !== null && typeof actual === 'object'
    && Object.entries(expected).every(([key, value]) => deepSubset(actual[key], value));
}

function parseStrictJson(text, label) {
  const gate = strictParseGate(text);
  if (!gate.ok) throw new Error(`${label}: ${gate.reason}`);
  try { return JSON.parse(text); }
  catch (error) { throw new Error(`${label}: ${error.message}`); }
}

function hasNamedDeclaration(source, language, symbol) {
  const name = escaped(symbol);
  if (language === 'python') return new RegExp(`^def\\s+${name}\\s*\\(`, 'm').test(source);
  if (language === 'go') return new RegExp(`^func\\s+(?:\\([^)]*\\)\\s*)?${name}\\s*\\(`, 'm').test(source);
  return new RegExp(`(?:^|\\n)\\s*(?:export\\s+)?(?:async\\s+)?(?:function|class)\\s+${name}\\b|(?:^|\\n)\\s*(?:export\\s+)?(?:const|let|var)\\s+${name}\\s*=`, 'm').test(source);
}

function hasExactTestTitle(source, title) {
  const name = escaped(title);
  return new RegExp(`(?:test|it)\\s*\\(\\s*(['\"\`])${name}\\1`).test(source);
}

function hasFormalLemma(source, lemma) {
  return new RegExp(`^lemma\\s+${escaped(lemma)}\\s*:`, 'm').test(source);
}

function hasVerifiedResult(source, lemma) {
  return new RegExp(`^\\s*${escaped(lemma)}\\s+\\([^\\n]*\\):\\s+verified\\b`, 'm').test(source);
}

function hasBoundedFormalResult(source, obligation) {
  return new RegExp(
    `^\\s*${escaped(obligation)}\\s+\\([^\\n]*\\):\\s+verified\\b`,
    'm',
  ).test(source);
}

function planTest(id, executionSpec, suitePath = null) {
  if (!executionSpec || !['vitest', 'node-test'].includes(executionSpec.runner)) {
    fail(id, 'execution must name runner vitest or node-test');
    return;
  }
  const testFile = resolveFile(id, executionSpec.file);
  if (!testFile) return;
  const source = fs.readFileSync(testFile, 'utf8');
  if (!nonEmpty(executionSpec.title)) {
    fail(id, `${executionSpec.file} execution needs an exact title`);
    return;
  }
  if (!hasExactTestTitle(source, executionSpec.title)) {
    const suiteName = suitePath ? path.basename(suitePath) : '';
    const suiteDriven = suiteName && source.includes(suiteName) && source.includes('v.id');
    if (!suiteDriven) fail(id, `${executionSpec.file} has no exact or suite-driven test title: ${executionSpec.title}`);
  }
  const key = `${executionSpec.runner}\0${executionSpec.file}`;
  const planned = executionPlan.get(key) ?? { runner: executionSpec.runner, file: executionSpec.file, titles: new Set() };
  planned.titles.add(executionSpec.title);
  executionPlan.set(key, planned);
}

function planCrossLanguage(id, suite, caseId, expect) {
  const key = suite;
  const planned = crossLanguageCases.get(key) ?? new Map();
  planned.set(caseId, { id, expect });
  crossLanguageCases.set(key, planned);
}

function runChecked(command, commandArgs, options, label) {
  const run = spawnSync(command, commandArgs, {
    cwd: options.cwd ?? ROOT,
    encoding: 'utf8',
    env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' },
    maxBuffer: 32 * 1024 * 1024,
    timeout: 180_000,
  });
  if (run.status !== 0) {
    throw new Error(`${label} failed (${run.status}):\n${run.stdout || ''}${run.stderr || ''}`);
  }
  return run.stdout;
}

function executePlannedTests() {
  for (const planned of [...executionPlan.values()].sort((a, b) => a.file.localeCompare(b.file))) {
    if (planned.runner === 'vitest') {
      runChecked('npm', ['exec', 'vitest', '--', 'run', planned.file, '--reporter=dot'], {}, `vitest ${planned.file}`);
    } else {
      runChecked(process.execPath, ['--test', planned.file], {}, `node:test ${planned.file}`);
    }
    executionEvidence.push({ runner: planned.runner, file: planned.file, titles: [...planned.titles].sort(), result: 'passed' });
  }
}

function executeCrossLanguage() {
  const implementations = [
    { language: 'javascript', command: process.execPath, args: (suite) => ['conformance/runners/run-js.mjs', suite], cwd: ROOT },
    { language: 'python', command: 'python3', args: (suite) => ['conformance/runners/run_py.py', suite], cwd: ROOT },
    { language: 'go', command: 'go', args: (suite) => ['run', './cmd/conformance', suite], cwd: path.join(ROOT, 'packages', 'go-verify') },
  ];
  for (const [suite, cases] of [...crossLanguageCases.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const suiteAbsolute = path.resolve(ROOT, suite);
    const suiteFile = path.basename(suiteAbsolute);
    const suiteDocument = parseStrictJson(
      fs.readFileSync(suiteAbsolute, 'utf8'),
      `invalid conformance suite ${suite}`,
    );
    const executionFile = executionSuiteFile(suiteFile);
    const executionAbsolute = executionFile === suiteFile
      ? suiteAbsolute
      : path.join(path.dirname(suiteAbsolute), executionFile);
    evidenceFiles.add(path.relative(ROOT, executionAbsolute));
    const executionDocument = executionFile === suiteFile
      ? suiteDocument
      : parseStrictJson(
        fs.readFileSync(executionAbsolute, 'utf8'),
        `invalid conformance execution suite ${executionFile}`,
      );
    const contract = buildSuiteContract(suiteFile, suiteDocument, executionDocument);
    const languages = [];
    for (const implementation of implementations) {
      const stdout = runChecked(
        implementation.command,
        implementation.args(executionAbsolute),
        { cwd: implementation.cwd },
        `${implementation.language} conformance ${suite}`,
      );
      const results = parseStrictJson(stdout, `${implementation.language} emitted invalid JSON for ${suite}`);
      if (!Array.isArray(results)) throw new Error(`${implementation.language} emitted a non-array result for ${suite}`);
      const byId = validateResultRows(contract, results);
      for (const result of results) {
        const comparison = compareResultRow(contract, result);
        if (!comparison.ok) {
          throw new Error(
            `${implementation.language} emitted ${comparison.detail} for ${suite}#${result.id}`,
          );
        }
      }
      for (const [caseId, ref] of cases) {
        if (!byId.has(caseId)) throw new Error(`${implementation.language} omitted ${suite}#${caseId}`);
        const result = byId.get(caseId);
        if (typeof ref.expect.valid === 'boolean' && result.valid !== ref.expect.valid) {
          throw new Error(`${implementation.language} returned ${result.valid} for ${suite}#${caseId}; expected ${ref.expect.valid}`);
        }
      }
      languages.push(implementation.language);
    }
    executionEvidence.push({ runner: 'cross-language', suite, cases: [...cases.keys()].sort(), languages, result: 'passed' });
  }
}

function executeBoundedFormal() {
  for (const planned of [...boundedFormalPlan.values()].sort(
    (a, b) => a.runner.localeCompare(b.runner),
  )) {
    const stdout = runChecked(
      process.execPath,
      [planned.runner, '--json'],
      {},
      `bounded formal checker ${planned.runner}`,
    );
    const result = parseStrictJson(stdout, `${planned.runner} emitted invalid JSON`);
    if (result?.verified !== true
        || result?.method !== 'bounded_exhaustive_state_exploration') {
      throw new Error(`${planned.runner} did not report a verified bounded exploration`);
    }
    for (const obligation of planned.obligations) {
      const row = result.obligations?.[obligation];
      if (row?.verified !== true || row?.counterexample !== null
          || row?.mutation_counterexample === null
          || row?.mutation_counterexample === undefined) {
        throw new Error(
          `${planned.runner} did not verify ${obligation} with a mutation counterexample`,
        );
      }
    }
    executionEvidence.push({
      runner: 'bounded-formal',
      file: planned.runner,
      obligations: [...planned.obligations].sort(),
      result: 'passed',
    });
  }
}

let sourceCase;
try {
  sourceCase = parseStrictJson(fs.readFileSync(SOURCE, 'utf8'), 'security case source');
} catch (error) {
  console.error(`SECURITY CASE: cannot parse ${SOURCE}: ${error.message}`);
  process.exit(2);
}

if (sourceCase['@version'] !== 'EP-SECURITY-CASE-SOURCE-v2') fail('source', 'unexpected @version');
if (!Array.isArray(sourceCase.claims) || sourceCase.claims.length === 0) fail('source', 'claims must be non-empty');
if (!sourceCase.release_artifacts || typeof sourceCase.release_artifacts !== 'object') fail('source', 'release_artifacts must be an object');

const seenClaims = new Set();
for (const claim of sourceCase.claims ?? []) {
  const id = claim?.claim_id ?? '(missing claim_id)';
  if (!nonEmpty(claim?.claim_id)) fail(id, 'claim_id is required');
  if (seenClaims.has(id)) fail(id, 'duplicate claim_id');
  seenClaims.add(id);
  if (!nonEmpty(claim?.statement)) fail(id, 'statement is required');
  if (!Array.isArray(claim?.acceptance_roots) || claim.acceptance_roots.length === 0 || claim.acceptance_roots.some((v) => !nonEmpty(v))) fail(id, 'acceptance_roots must contain non-empty strings');
  if (!Array.isArray(claim?.assumptions) || claim.assumptions.length === 0 || claim.assumptions.some((v) => !nonEmpty(v))) fail(id, 'assumptions must be explicit non-empty strings');
  if (!Array.isArray(claim?.exclusions) || claim.exclusions.length === 0 || claim.exclusions.some((v) => !nonEmpty(v))) fail(id, 'exclusions must be explicit non-empty strings');

  if (!Array.isArray(claim?.enforcement_path) || claim.enforcement_path.length === 0) fail(id, 'enforcement_path must name at least one exact code symbol');
  for (const step of claim.enforcement_path ?? []) {
    const stepFile = resolveFile(id, step.file);
    if (!stepFile || !nonEmpty(step.symbol) || !['javascript', 'python', 'go'].includes(step.language)) {
      fail(id, 'every enforcement_path step needs language, file, and symbol');
      continue;
    }
    if (!hasNamedDeclaration(fs.readFileSync(stepFile, 'utf8'), step.language, step.symbol)) {
      fail(id, `${step.file} has no exact ${step.language} declaration ${step.symbol}`);
    }
  }

  if (!Array.isArray(claim?.implementations) || claim.implementations.length === 0) fail(id, 'at least one implementation is required');
  for (const implementation of claim.implementations ?? []) {
    const implementationFile = resolveFile(id, implementation.file);
    if (!implementationFile) continue;
    if (implementation.language === 'javascript') {
      if (!nonEmpty(implementation.export)) {
        fail(id, `javascript implementation ${implementation.file} needs export`);
        continue;
      }
      try {
        const module = await import(`${pathToFileURL(implementationFile).href}?security-case=${encodeURIComponent(id)}`);
        if (typeof module[implementation.export] !== 'function') fail(id, `${implementation.file} has no callable named export ${implementation.export}`);
      } catch (error) {
        fail(id, `cannot import ${implementation.file}: ${error.message}`);
      }
    } else if (implementation.language === 'python' || implementation.language === 'go') {
      if (!nonEmpty(implementation.symbol) || !hasNamedDeclaration(fs.readFileSync(implementationFile, 'utf8'), implementation.language, implementation.symbol)) {
        fail(id, `${implementation.file} has no exact ${implementation.language} declaration ${implementation.symbol}`);
      }
    } else {
      fail(id, `unknown implementation language: ${implementation.language}`);
    }
  }

  const coverage = claim.language_coverage;
  for (const language of ['javascript', 'python', 'go']) {
    const entry = coverage?.[language];
    if (!entry || !['covered', 'gap', 'not_applicable'].includes(entry.status)) {
      fail(id, `language_coverage.${language} must explicitly be covered, gap, or not_applicable`);
    } else if (entry.status === 'covered') {
      resolveFile(id, entry.evidence);
    } else if (!nonEmpty(entry.reason)) {
      fail(id, `language_coverage.${language}.${entry.status} requires a reason`);
    }
  }

  if (!Array.isArray(claim?.vectors) || claim.vectors.length < 2) fail(id, 'at least one positive and one negative vector are required');
  const polarities = new Set();
  for (const vectorRef of claim.vectors ?? []) {
    polarities.add(vectorRef.polarity);
    if (!['positive', 'negative'].includes(vectorRef.polarity)) fail(id, 'vector polarity must be positive or negative');
    if (vectorRef.polarity === 'positive' && vectorRef.expect?.valid !== true) fail(id, `${vectorRef.case_id} positive vector must expect valid:true`);
    if (vectorRef.polarity === 'negative' && vectorRef.expect?.valid !== false) fail(id, `${vectorRef.case_id} negative vector must expect valid:false`);
    const suiteFile = resolveFile(id, vectorRef.suite);
    if (!suiteFile) continue;
    let suite;
    try { suite = parseStrictJson(fs.readFileSync(suiteFile, 'utf8'), `vector suite ${vectorRef.suite}`); } catch (error) {
      fail(id, `cannot parse vector suite ${vectorRef.suite}: ${error.message}`);
      continue;
    }
    const matching = (suite.vectors ?? []).filter((vector) => vector?.id === vectorRef.case_id);
    if (matching.length !== 1) {
      fail(id, `${vectorRef.suite} must contain exactly one vector id ${vectorRef.case_id}; found ${matching.length}`);
      continue;
    }
    if (!deepSubset(matching[0].expect, vectorRef.expect)) {
      fail(id, `${vectorRef.suite}#${vectorRef.case_id} expectation does not match ${JSON.stringify(vectorRef.expect)}`);
    }
    const executionSpec = vectorRef.execution ?? matching[0].execution;
    if (executionSpec?.runner === 'cross-language') {
      planCrossLanguage(id, vectorRef.suite, vectorRef.case_id, vectorRef.expect);
    } else {
      planTest(id, executionSpec, vectorRef.suite);
    }
  }
  if (!polarities.has('positive') || !polarities.has('negative')) fail(id, 'vectors must contain both positive and negative polarity');

  if (!Array.isArray(claim?.tests) || claim.tests.length === 0) fail(id, 'at least one exact test is required');
  for (const testRef of claim.tests ?? []) {
    const testFile = resolveFile(id, testRef.file);
    if (!testFile) continue;
    if (!nonEmpty(testRef.title) || !hasExactTestTitle(fs.readFileSync(testFile, 'utf8'), testRef.title)) {
      fail(id, `${testRef.file} has no exact test title: ${testRef.title}`);
    }
    planTest(id, { runner: testRef.runner, file: testRef.file, title: testRef.title });
  }

  if (claim.operational_evidence !== undefined && !Array.isArray(claim.operational_evidence)) fail(id, 'operational_evidence must be an array when present');
  for (const artifact of claim.operational_evidence ?? []) {
    const artifactFile = resolveFile(id, artifact.file);
    if (!artifactFile) continue;
    const source = fs.readFileSync(artifactFile, 'utf8');
    if (!Array.isArray(artifact.contains) || artifact.contains.length === 0 || artifact.contains.some((value) => !nonEmpty(value))) {
      fail(id, `${artifact.file} operational evidence needs exact non-empty contains strings`);
      continue;
    }
    for (const exact of artifact.contains) if (!source.includes(exact)) fail(id, `${artifact.file} does not contain exact operational evidence: ${exact}`);
  }

  if (!Array.isArray(claim?.formal) || claim.formal.length === 0) fail(id, 'formal status must be explicit');
  for (const formal of claim.formal ?? []) {
    if (formal.status === 'not_modeled') {
      if (!nonEmpty(formal.gap)) fail(id, 'not_modeled formal evidence requires a gap statement');
      continue;
    }
    if (!['verified', 'partial'].includes(formal.status)) {
      fail(id, `unknown formal status: ${formal.status}`);
      continue;
    }
    const modelFile = resolveFile(id, formal.model);
    const runnerFile = resolveFile(id, formal.runner);
    const resultFile = resolveFile(id, formal.result_evidence);
    if (!modelFile || !runnerFile || !resultFile) continue;
    const modelSource = fs.readFileSync(modelFile, 'utf8');
    const runnerSource = fs.readFileSync(runnerFile, 'utf8');
    const resultSource = fs.readFileSync(resultFile, 'utf8');
    const modelSha256 = crypto.createHash('sha256').update(fs.readFileSync(modelFile)).digest('hex');
    const runnerSha256 = crypto.createHash('sha256').update(fs.readFileSync(runnerFile)).digest('hex');
    if (!resultSource.includes(`Model SHA-256: ${modelSha256}`)) fail(id, `${formal.result_evidence} is not bound to the current ${formal.model} bytes`);
    if (!resultSource.includes(`Runner SHA-256: ${runnerSha256}`)) fail(id, `${formal.result_evidence} is not bound to the current ${formal.runner} bytes`);
    if (formal.method === 'bounded_exhaustive_state_exploration') {
      if (formal.status !== 'partial') {
        fail(id, 'bounded exhaustive formal evidence must remain status partial');
      }
      if (!Array.isArray(formal.obligations) || formal.obligations.length === 0
          || formal.obligations.some((obligation) => !nonEmpty(obligation))
          || new Set(formal.obligations).size !== formal.obligations.length) {
        fail(id, 'bounded exhaustive formal evidence requires unique named obligations');
      }
      for (const obligation of formal.obligations ?? []) {
        if (!modelSource.includes(`'${obligation}'`)
            && !modelSource.includes(`"${obligation}"`)) {
          fail(id, `${formal.model} does not declare exact obligation ${obligation}`);
        }
        if (!runnerSource.includes(`${obligation}:`)) {
          fail(id, `${formal.runner} does not execute exact obligation ${obligation}`);
        }
        if (!hasBoundedFormalResult(resultSource, obligation)) {
          fail(id, `${formal.result_evidence} has no verified bounded result for ${obligation}`);
        }
      }
      if (!nonEmpty(formal.scope)
          || !formal.scope.toLowerCase().includes('bounded')
          || !formal.scope.toLowerCase().includes('same-team')) {
        fail(id, 'bounded exhaustive formal evidence requires explicit bounded and same-team scope');
      }
      const key = path.relative(ROOT, runnerFile);
      const planned = boundedFormalPlan.get(key) ?? {
        runner: key,
        obligations: new Set(),
      };
      for (const obligation of formal.obligations ?? []) {
        planned.obligations.add(obligation);
      }
      boundedFormalPlan.set(key, planned);
      continue;
    }
    if (!nonEmpty(formal.lemma) || !hasFormalLemma(modelSource, formal.lemma)) fail(id, `${formal.model} has no exact lemma ${formal.lemma}`);
    if (!runnerSource.includes(formal.lemma)) fail(id, `${formal.runner} does not execute exact lemma ${formal.lemma}`);
    if (!hasVerifiedResult(resultSource, formal.lemma)) fail(id, `${formal.result_evidence} has no verified result for ${formal.lemma}`);
    if (!nonEmpty(formal.scope)) fail(id, `${formal.lemma} requires an explicit scope boundary`);
  }

  if (!Array.isArray(claim.release_artifacts) || claim.release_artifacts.length === 0) fail(id, 'claim must bind at least one release artifact');
  for (const artifactId of claim.release_artifacts ?? []) {
    if (!sourceCase.release_artifacts?.[artifactId]) fail(id, `unknown release artifact ${artifactId}`);
  }
}

if (errors.length) {
  console.error(`SECURITY CASE: FAIL (${errors.length} problem${errors.length === 1 ? '' : 's'})`);
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

if (execute) {
  try {
    executeBoundedFormal();
    executeCrossLanguage();
    executePlannedTests();
  } catch (error) {
    console.error(`SECURITY CASE: EXECUTION FAIL\n${error.message}`);
    process.exit(1);
  }
}

const fileHashes = [...evidenceFiles].sort().map((relative) => {
  const bytes = fs.readFileSync(path.join(ROOT, relative));
  return { path: relative, sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
});
const evidenceBundleSha256 = crypto.createHash('sha256')
  .update(fileHashes.map(({ path: relative, sha256 }) => `${relative}\0${sha256}\n`).join(''))
  .digest('hex');

const releaseArtifacts = {};
for (const [artifactId, definition] of Object.entries(sourceCase.release_artifacts ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
  if (definition.kind === 'npm') {
    const artifact = verifyReproduciblePackage(definition.path);
    releaseArtifacts[artifactId] = { kind: 'npm-tarball', package: artifact.name, version: artifact.version, filename: artifact.filename, sha256: artifact.sha256, file_count: artifact.fileCount };
  } else if (definition.kind === 'content-addressed-evidence-bundle') {
    releaseArtifacts[artifactId] = { kind: definition.kind, filename: 'security-case-evidence.v1', sha256: evidenceBundleSha256, file_count: fileHashes.length };
  } else {
    throw new Error(`unsupported release artifact kind: ${definition.kind}`);
  }
}

const resolvedClaims = sourceCase.claims.map((claim) => ({
  ...claim,
  release_artifact_hashes: claim.release_artifacts.map((artifactId) => ({ artifact_id: artifactId, sha256: releaseArtifacts[artifactId].sha256 })),
}));
const resolved = {
  '@version': 'EP-SECURITY-CASE-RESOLVED-v2',
  source: 'security/claims.v1.json',
  evidence_bundle_sha256: evidenceBundleSha256,
  claim_count: resolvedClaims.length,
  evidence_file_count: fileHashes.length,
  execution: {
    required: true,
    status: execute ? 'passed' : 'not_executed',
    evidence: execute ? executionEvidence.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))) : [],
  },
  attestation_policy: 'GitHub artifact attestation over this exact JSON is required on protected-branch and release runs.',
  release_artifacts: releaseArtifacts,
  claims: resolvedClaims,
  evidence_files: fileHashes,
};
const serialized = `${JSON.stringify(resolved, null, 2)}\n`;

if (emitPath) {
  const target = path.resolve(ROOT, emitPath);
  if (target !== ROOT && !target.startsWith(`${ROOT}${path.sep}`)) throw new Error(`emit path escapes repository: ${emitPath}`);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, serialized);
} else if (fs.existsSync(DEFAULT_RESOLVED)) {
  const checkedIn = fs.readFileSync(DEFAULT_RESOLVED, 'utf8');
  if (checkedIn !== serialized) {
    console.error('SECURITY CASE: FAIL (security/security-case.json is stale; run npm run security-case:emit)');
    process.exit(1);
  }
}

const artifactSummary = Object.entries(releaseArtifacts).map(([id, artifact]) => `${id}=sha256:${artifact.sha256}`).join(', ');
console.log(`SECURITY CASE: OK (${resolved.claim_count} executable claims, ${resolved.evidence_file_count} hashed evidence files, execution=${resolved.execution.status})`);
console.log(`RELEASE BINDINGS: ${artifactSummary}`);
