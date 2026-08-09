import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  STATIC_BOUNDARY,
  main,
  renderMarkdown,
  scanWorkspace,
} from '../scan.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureWorkspace = path.join(here, 'fixtures', 'hostile-workspace');
const scannerPath = path.resolve(here, '..', 'scan.mjs');

function workflow(report, fileName) {
  return report.workflows.find((item) => item.file.endsWith(fileName));
}

test('inventories only top-level YAML workflow files and their triggers', async () => {
  const report = await scanWorkspace(fixtureWorkspace, {
    generatedAt: '2026-08-08T00:00:00.000Z',
  });

  assert.equal(report.schemaVersion, '1.0');
  assert.equal(report.tool.name, 'EMILIA Authority Map');
  assert.equal(report.summary.workflowCount, 6);
  assert.deepEqual(
    report.workflows.map((item) => item.file),
    [
      '.github/workflows/dangerous-compositions.yml',
      '.github/workflows/hostile.yml',
      '.github/workflows/review-only.yml',
      '.github/workflows/scheduled-self-hosted.yaml',
      '.github/workflows/unsupported.yml',
      '.github/workflows/valid-forms.yaml',
    ],
  );
  assert.deepEqual(workflow(report, 'hostile.yml').triggers, [
    'pull_request_target',
    'push',
  ]);
  assert.deepEqual(workflow(report, 'valid-forms.yaml').triggers, [
    'push',
    'workflow_dispatch',
  ]);
});

test('finds write permissions, pull_request_target, self-hosted, and unpinned third-party refs', async () => {
  const report = await scanWorkspace(fixtureWorkspace);
  const hostile = workflow(report, 'hostile.yml');

  assert.equal(hostile.permissions.topLevel.form, 'write-all');
  assert.equal(hostile.permissions.topLevel.writeAll, true);
  assert.deepEqual(hostile.permissions.jobs.publish.writeScopes, [
    'contents',
    'packages',
  ]);
  assert.equal(hostile.permissions.jobs.administration.writeAll, true);
  assert.equal(hostile.hazards.pullRequestTarget.present, true);
  assert.equal(hostile.hazards.selfHostedRunners.length, 1);
  assert.equal(hostile.hazards.selfHostedRunners[0].job, 'publish');
  assert.match(hostile.hazards.selfHostedRunners[0].value, /self-hosted/);
  assert.deepEqual(
    hostile.hazards.unpinnedThirdPartyActions.map((item) => item.uses),
    ['octo-org/deploy-action@main'],
  );
  assert.equal(hostile.mutation.hasDeclaredWriteCapability, true);
  assert.equal(hostile.mutation.withoutEnvironment, true);
  assert.ok(hostile.mutation.signals.length >= 2);
  assert.ok(report.findings.some((item) => item.code === 'MUTATION_WITHOUT_ENVIRONMENT'));
});

test('recognizes mapped environments, production references, and pinned full SHAs', async () => {
  const report = await scanWorkspace(fixtureWorkspace);
  const valid = workflow(report, 'valid-forms.yaml');

  assert.deepEqual(valid.permissions.topLevel.writeScopes, []);
  assert.deepEqual(valid.permissions.jobs.release.writeScopes, [
    'contents',
    'id-token',
  ]);
  assert.equal(valid.environmentReferences.length, 1);
  assert.deepEqual(valid.environmentReferences[0], {
    job: 'release',
    value: 'production',
    line: 12,
    production: true,
    ambiguous: false,
  });
  assert.ok(valid.productionReferences.some((item) => item.value === 'production'));
  assert.equal(valid.hazards.unpinnedThirdPartyActions.length, 0);
  assert.equal(valid.mutation.withoutEnvironment, false);
});

test('marks anchors, merges, expressions, and dynamic action refs as ambiguous', async () => {
  const report = await scanWorkspace(fixtureWorkspace);
  const unsupported = workflow(report, 'unsupported.yml');
  const kinds = new Set(unsupported.ambiguities.map((item) => item.kind));

  assert.ok(kinds.has('yaml-anchor'));
  assert.ok(kinds.has('yaml-merge-key'));
  assert.ok(kinds.has('dynamic-runner'));
  assert.ok(kinds.has('dynamic-environment'));
  assert.ok(kinds.has('dynamic-permission'));
  assert.ok(kinds.has('dynamic-action-reference'));
  assert.equal(unsupported.environmentReferences[0].ambiguous, true);
  assert.equal(unsupported.mutation.withoutEnvironment, false);
  assert.equal(unsupported.mutation.environmentAssessment, 'ambiguous');
  assert.ok(report.summary.ambiguityCount >= kinds.size);
});

test('JSON and Markdown carry the non-enforcement and external-settings boundary', async () => {
  const report = await scanWorkspace(fixtureWorkspace);
  const markdown = renderMarkdown(report);

  assert.deepEqual(report.boundary, STATIC_BOUNDARY);
  assert.equal(report.boundary.blocksMutations, false);
  assert.equal(report.boundary.completeMediation, false);
  assert.equal(report.boundary.repositoryConfigurationIsAuthority, false);
  assert.deepEqual(report.boundary.requiresApiPermissionsFor, [
    'GitHub environment protection settings',
    'GitHub rulesets',
    'GitHub bypass actors and settings',
  ]);
  assert.match(markdown, /does not block mutations/i);
  assert.match(markdown, /not complete mediation/i);
  assert.match(markdown, /does not use repository configuration as authority/i);
  assert.match(markdown, /API permissions/i);
  assert.match(markdown, /pull_request_target/);
  assert.match(markdown, /review paths without an environment/i);
});

test('bare pull_request_target and scoped write paths without an environment are warnings', async () => {
  const report = await scanWorkspace(fixtureWorkspace);
  const review = workflow(report, 'review-only.yml');
  const reviewFindings = report.findings.filter((item) => item.file === review.file);

  assert.ok(reviewFindings.length > 0);
  assert.ok(reviewFindings.every((item) => item.file === item.workflow));
  assert.equal(reviewFindings.some((item) => item.severity === 'critical'), false);
  assert.equal(
    reviewFindings.find((item) => item.code === 'PULL_REQUEST_TARGET').severity,
    'warning',
  );
  assert.equal(
    reviewFindings.find((item) => item.code === 'MUTATION_WITHOUT_ENVIRONMENT').severity,
    'warning',
  );
  assert.ok(
    reviewFindings
      .filter((item) => item.code === 'JOB_WRITE_PERMISSION')
      .every((item) => item.severity === 'warning'),
  );
});

test('critical severity requires dangerous PR composition or an obvious unprotected sink', async () => {
  const report = await scanWorkspace(fixtureWorkspace);
  const dangerous = workflow(report, 'dangerous-compositions.yml');
  const critical = report.findings.filter(
    (item) => item.file === dangerous.file && item.severity === 'critical',
  );

  assert.deepEqual(
    dangerous.hazards.dangerousPullRequestTargetCompositions.map((item) => item.job),
    ['candidate-code', 'untrusted-shell'],
  );
  assert.deepEqual(
    dangerous.mutation.obviousPrivilegedSinks.map((item) => item.job),
    ['publish-without-environment', 'protected-publish'],
  );
  assert.ok(
    critical.some(
      (item) =>
        item.code === 'DANGEROUS_PULL_REQUEST_TARGET_COMPOSITION' &&
        item.job === 'candidate-code',
    ),
  );
  assert.ok(
    critical.some(
      (item) =>
        item.code === 'DANGEROUS_PULL_REQUEST_TARGET_COMPOSITION' &&
        item.job === 'untrusted-shell',
    ),
  );
  assert.ok(
    critical.some(
      (item) =>
        item.code === 'PRIVILEGED_SINK_WITHOUT_ENVIRONMENT' &&
        item.job === 'publish-without-environment',
    ),
  );
  assert.equal(critical.some((item) => item.job === 'protected-publish'), false);
});

test('self-hosted runners are critical only on contributor-controlled triggers', async () => {
  const report = await scanWorkspace(fixtureWorkspace);
  const hostile = workflow(report, 'hostile.yml');
  const scheduled = workflow(report, 'scheduled-self-hosted.yaml');
  const hostileFinding = report.findings.find(
    (item) => item.file === hostile.file && item.code === 'SELF_HOSTED_RUNNER',
  );
  const scheduledFinding = report.findings.find(
    (item) => item.file === scheduled.file && item.code === 'SELF_HOSTED_RUNNER',
  );

  assert.equal(hostileFinding.severity, 'critical');
  assert.equal(hostileFinding.composition, 'contributor-trigger');
  assert.equal(scheduledFinding.severity, 'warning');
  assert.equal(scheduledFinding.composition, null);
});

test('every normalized finding contains a source file', async () => {
  const report = await scanWorkspace(fixtureWorkspace);

  assert.ok(report.findings.length > 0);
  assert.ok(report.findings.every((item) => item.file === item.workflow));
});

test('CLI emits JSON and Markdown before fail-on=critical exits nonzero', async () => {
  const outputDirectory = await mkdtemp(path.join(tmpdir(), 'emilia-authority-map-'));
  const jsonPath = path.join(outputDirectory, 'map.json');
  const markdownPath = path.join(outputDirectory, 'map.md');
  const result = spawnSync(
    process.execPath,
    [
      scannerPath,
      '--workspace',
      fixtureWorkspace,
      '--json',
      jsonPath,
      '--markdown',
      markdownPath,
      '--fail-on',
      'critical',
    ],
    { encoding: 'utf8' },
  );

  assert.equal(result.status, 1, result.stderr);
  const parsed = JSON.parse(await readFile(jsonPath, 'utf8'));
  assert.ok(parsed.summary.criticalFindingCount > 0);
  assert.match(await readFile(markdownPath, 'utf8'), /EMILIA Authority Map/);
  assert.match(result.stdout, /critical finding/i);
});

test('CLI supports fail-on=never and rejects unsupported fail policies', async () => {
  const outputDirectory = await mkdtemp(path.join(tmpdir(), 'emilia-authority-map-'));
  const never = spawnSync(
    process.execPath,
    [
      scannerPath,
      '--workspace',
      fixtureWorkspace,
      '--json',
      path.join(outputDirectory, 'never.json'),
      '--markdown',
      path.join(outputDirectory, 'never.md'),
      '--fail-on',
      'never',
    ],
    { encoding: 'utf8' },
  );
  const invalid = spawnSync(
    process.execPath,
    [scannerPath, '--workspace', fixtureWorkspace, '--fail-on', 'warning'],
    { encoding: 'utf8' },
  );

  assert.equal(never.status, 0, never.stderr);
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /never\|critical/);
});

test('action metadata selects Node 24 and declares the scanner inputs and outputs', async () => {
  const actionYaml = await readFile(path.resolve(here, '..', 'action.yml'), 'utf8');

  assert.match(actionYaml, /^name: EMILIA Authority Map$/m);
  assert.match(actionYaml, /^  using: node24$/m);
  assert.match(actionYaml, /^  main: scan\.mjs$/m);
  assert.match(actionYaml, /^  fail-on:$/m);
  assert.match(actionYaml, /^  json-output:$/m);
  assert.match(actionYaml, /^  markdown-output:$/m);
  assert.match(actionYaml, /^  json-path:$/m);
  assert.match(actionYaml, /^  markdown-path:$/m);
  assert.match(actionYaml, /^  critical-findings:$/m);
  assert.match(actionYaml, /^  ambiguity-count:$/m);
});

test('GitHub runner protocol writes temp artifacts, step summary, and action outputs', async () => {
  const runnerTemp = await mkdtemp(path.join(tmpdir(), 'emilia-authority-map-runner-'));
  const githubOutput = path.join(runnerTemp, 'github-output.txt');
  const stepSummary = path.join(runnerTemp, 'step-summary.md');
  const status = await main([], {
    GITHUB_WORKSPACE: fixtureWorkspace,
    RUNNER_TEMP: runnerTemp,
    GITHUB_OUTPUT: githubOutput,
    GITHUB_STEP_SUMMARY: stepSummary,
    'INPUT_FAIL-ON': 'never',
  });

  assert.equal(status, 0);
  const json = await readFile(path.join(runnerTemp, 'emilia-authority-map.json'), 'utf8');
  assert.doesNotThrow(() => JSON.parse(json));
  assert.match(
    await readFile(path.join(runnerTemp, 'emilia-authority-map.md'), 'utf8'),
    /does not block mutations/i,
  );
  assert.match(await readFile(stepSummary, 'utf8'), /EMILIA Authority Map/);
  const outputs = await readFile(githubOutput, 'utf8');
  assert.match(outputs, /^json-path=/m);
  assert.match(outputs, /^markdown-path=/m);
  assert.match(outputs, /^critical-findings=\d+$/m);
  assert.match(outputs, /^ambiguity-count=\d+$/m);
});
