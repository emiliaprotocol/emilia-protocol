// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  digestExecutable,
  loadRefereePack,
  parseStrictJson,
  runExternalCase,
  runReferee,
  sanitizedChildEnvironment,
} from './run-referee-conformance.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(repositoryRoot, 'conformance/referee/fixtures/manifest.json');
const referenceRunner = path.join(repositoryRoot, 'conformance/referee/fixtures/reference-runner.mjs');
const protocolFixture = path.join(repositoryRoot, 'conformance/referee/fixtures/protocol-fixture.mjs');
const runnerScript = path.join(repositoryRoot, 'scripts/run-referee-conformance.mjs');

test('closed schemas accept the complete curated fixture pack and reject unknown keys', async () => {
  const pack = await loadRefereePack(manifestPath);
  assert.equal(pack.manifest.fixtures.length, 13);

  const malformedCase = structuredClone(pack.manifest.fixtures[0].case);
  malformedCase.native_evidence[0].mapping.surprise = true;
  assert.throws(
    () => pack.validateCase(malformedCase),
    /additional property|unknown property/i,
  );

  const malformedResult = { ...pack.manifest.fixtures[0].expected, surprise: true };
  assert.throws(
    () => pack.validateResult(malformedResult),
    /additional property|unknown property/i,
  );

  const malformedManifest = { ...pack.manifest, surprise: true };
  assert.throws(
    () => pack.validateManifest(malformedManifest),
    /additional property|unknown property/i,
  );
});

test('fixture matrix pins every required referee behavior and keeps provider/effect truth separate', async () => {
  const { manifest } = await loadRefereePack(manifestPath);
  const byId = new Map(manifest.fixtures.map((fixture) => [fixture.case.case_id, fixture.expected]));
  assert.deepEqual([...byId.keys()], [
    'exact-match',
    'exact-action-mismatch',
    'rp-acceptance-rejected',
    'material-loss-indeterminate',
    'wrong-root-native-failure',
    'stale-status',
    'unavailable-status',
    'stable-replay-identity',
    'provider-timeout',
    'crash-to-indeterminate',
    'authenticated-reconcile',
    'committed-diverged',
    'proven-not-committed',
  ]);
  assert.equal(byId.get('material-loss-indeterminate').admission, 'INDETERMINATE');
  assert.equal(byId.get('exact-match').rp_acceptance, 'ACCEPTED');
  assert.deepEqual(
    [byId.get('rp-acceptance-rejected').native_verification, byId.get('rp-acceptance-rejected').rp_acceptance],
    ['VERIFIED', 'REJECTED'],
  );
  assert.equal(byId.get('stale-status').rp_acceptance, 'INDETERMINATE');
  assert.equal(byId.get('provider-timeout').retry, 'REFUSE');
  assert.equal(byId.get('crash-to-indeterminate').custody, 'INDETERMINATE');
  assert.equal(byId.get('authenticated-reconcile').reconciliation, 'APPLIED');
  assert.deepEqual(
    [byId.get('committed-diverged').provider_commitment, byId.get('committed-diverged').observed_effect],
    ['COMMITTED', 'DIVERGED'],
  );
  assert.equal(byId.get('proven-not-committed').retry, 'REQUIRES_NEW_ADMISSION');
});

test('strict JSON rejects duplicate names, trailing documents, excessive depth, and bytes', () => {
  assert.throws(
    () => parseStrictJson('{"case_id":"a","case_id":"b"}', {
      label: 'duplicate', maxBytes: 1024, maxDepth: 8,
    }),
    /duplicate object member/i,
  );
  assert.throws(
    () => parseStrictJson('{"a":1,"\\u0061":2}', {
      label: 'escaped duplicate', maxBytes: 1024, maxDepth: 8,
    }),
    /duplicate object member/i,
  );
  assert.throws(
    () => parseStrictJson('"\\ud800"', {
      label: 'surrogate', maxBytes: 1024, maxDepth: 8,
    }),
    /Unicode/i,
  );
  assert.throws(
    () => parseStrictJson('{"ok":true}\n{"second":true}', {
      label: 'trailing', maxBytes: 1024, maxDepth: 8,
    }),
    /invalid JSON/i,
  );
  assert.throws(
    () => parseStrictJson('[[[[[null]]]]]', {
      label: 'deep', maxBytes: 1024, maxDepth: 4,
    }),
    /depth/i,
  );
  assert.throws(
    () => parseStrictJson(`"${'x'.repeat(128)}"`, {
      label: 'large', maxBytes: 64, maxDepth: 8,
    }),
    /byte limit/i,
  );
});

test('one case uses bounded direct argv execution and detects nondeterminism', async () => {
  const pack = await loadRefereePack(manifestPath);
  const fixture = pack.manifest.fixtures[0];
  const counterDirectory = await mkdtemp(path.join(tmpdir(), 'aeb-referee-counter-'));
  const counterPath = path.join(counterDirectory, 'counter');
  const executableSha256 = await digestExecutable(process.execPath);
  try {
    const row = await runExternalCase({
      fixture,
      commandArgv: [process.execPath, protocolFixture, 'nondeterministic', counterPath],
      resultSchema: pack.schemas.runnerResult,
      schemaStore: pack.schemas.store,
      limits: pack.manifest.limits,
      workspace: repositoryRoot,
      runnerPin: { executable_sha256: executableSha256 },
    });
    assert.equal(row.matched, false);
    assert.equal(row.error, 'NONDETERMINISTIC');
  } finally {
    await rm(counterDirectory, { recursive: true, force: true });
  }
});

test('external timeout, stdout overflow, malformed JSON, and crash fail closed', async () => {
  const pack = await loadRefereePack(manifestPath);
  const fixture = pack.manifest.fixtures[0];
  const executableSha256 = await digestExecutable(process.execPath);
  const modes = new Map([
    ['timeout', 'TIMEOUT'],
    ['oversize', 'STDOUT_LIMIT'],
    ['stderr-oversize', 'STDERR_LIMIT'],
    ['duplicate', 'INVALID_JSON'],
    ['trailing', 'INVALID_JSON'],
    ['crash', 'COMMAND_FAILED'],
  ]);
  for (const [mode, expectedError] of modes) {
    const row = await runExternalCase({
      fixture,
      commandArgv: [process.execPath, protocolFixture, mode],
      resultSchema: pack.schemas.runnerResult,
      schemaStore: pack.schemas.store,
      limits: { ...pack.manifest.limits, timeout_ms: 100 },
      workspace: repositoryRoot,
      runnerPin: { executable_sha256: executableSha256 },
    });
    assert.equal(row.matched, false, mode);
    assert.equal(row.error, expectedError, mode);
  }
});

test('executable bytes are verified against the runtime pin before spawn', async () => {
  const pack = await loadRefereePack(manifestPath);
  const row = await runExternalCase({
    fixture: pack.manifest.fixtures[0],
    commandArgv: [process.execPath, referenceRunner],
    resultSchema: pack.schemas.runnerResult,
    schemaStore: pack.schemas.store,
    limits: pack.manifest.limits,
    workspace: repositoryRoot,
    runnerPin: { executable_sha256: `sha256:${'0'.repeat(64)}` },
  });
  assert.equal(row.matched, false);
  assert.equal(row.error, 'EXECUTABLE_PIN_MISMATCH');
});

test('child commands receive a deterministic allowlisted environment with no credential variables', () => {
  const env = sanitizedChildEnvironment({
    PATH: '/usr/bin',
    HOME: '/secret/home',
    GITHUB_TOKEN: 'secret',
    AWS_SECRET_ACCESS_KEY: 'secret',
    NODE_OPTIONS: '--require malicious',
  });
  assert.deepEqual(env, {
    CI: '1',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
    PATH: '/usr/bin',
    TZ: 'UTC',
  });
});

test('reference runner produces a closed deterministic SELF_TEST report', async () => {
  const reportDirectory = await mkdtemp(path.join(tmpdir(), 'aeb-referee-report-'));
  const reportPath = path.join(reportDirectory, 'report.json');
  const executableSha256 = await digestExecutable(process.execPath);
  try {
    const report = await runReferee({
      manifestPath,
      reportPath,
      commandArgv: [process.execPath, referenceRunner],
      workspace: repositoryRoot,
      runnerPin: { executable_sha256: executableSha256 },
    });
    assert.deepEqual(report.summary, { total: 13, passed: 13, failed: 0, outcome: 'PASS' });
    assert.deepEqual(report.claim_boundary, {
      certification: false,
      authorization: false,
      production_deployment: false,
      production_sandbox: false,
    });
    assert.equal(report.implementation.runner_pin.executable_sha256, executableSha256);
    assert.equal(report.assessment, 'SELF_TEST');
    assert.equal(await readFile(reportPath, 'utf8'), canonicalJson(report));
  } finally {
    await rm(reportDirectory, { recursive: true, force: true });
  }
});

test('CLI stdout is exactly SELF_TEST and MJS is a governed generated companion', async () => {
  const reportDirectory = await mkdtemp(path.join(tmpdir(), 'aeb-referee-cli-'));
  const reportPath = path.join(reportDirectory, 'report.json');
  const executableSha256 = await digestExecutable(process.execPath);
  try {
    const run = spawnSync(process.execPath, [
      runnerScript,
      '--manifest', manifestPath,
      '--report', reportPath,
      '--workspace', repositoryRoot,
      '--command-json', JSON.stringify([process.execPath, referenceRunner]),
      '--executable-sha256', executableSha256,
    ], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout, 'SELF_TEST\n');
    assert.equal(run.stderr, '');
    const generated = await readFile(path.join(repositoryRoot, 'scripts/run-referee-conformance.mjs'), 'utf8');
    assert.match(generated, /Generated from run-referee-conformance\.mts by scripts\/build-standalone-runtimes\.mjs/);
  } finally {
    await rm(reportDirectory, { recursive: true, force: true });
  }
});
