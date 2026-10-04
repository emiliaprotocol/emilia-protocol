// SPDX-License-Identifier: Apache-2.0
//
// Contract and behavior tests for the CI lanes in .github/workflows/ci.yml
// (the lane conditions and laneContract live in change-lane.mjs). This file
// runs in the `test` job, not in the `changes` job's base-classifier
// self-test, because it reads the real workflow and needs the `yaml` package.
//
// It executes the real shell of the `changes` job's lane step against a fake
// `gh` that answers from fixtures, and the real shell of the three required
// aggregators (conformance, gate-product, language-governance) for every lane
// and dependency result, so a lane skip is proven to pass and a failure or
// cancellation is proven to fail. aggregate-conformance-case is not required
// itself; the conformance aggregator carries it.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import YAML from 'yaml';

import {
  DEFER_CONDITION,
  QUEUE_TESTED_CONDITION,
  SKIP_CONDITION,
  laneContract,
} from './change-lane.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const WORKFLOW_TEXT = readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8');
const WORKFLOW = YAML.parse(WORKFLOW_TEXT);
const JOBS = WORKFLOW.jobs;
const carrying = (condition) => Object.keys(JOBS).filter((name) => String(JOBS[name].if ?? '').includes(condition)).sort();

/** The jobs a quick pull request defers to the merge queue. */
const DEFERRED = ['conformance-caid', 'conformance-caid-packets', 'conformance-core', 'docker-build', 'e2e', 'gate-product-suite', 'security-case'];
/** The jobs a push the merge queue already tested skips: DEFERRED minus security-case. */
const QUEUE_TESTED = DEFERRED.filter((name) => name !== 'security-case');
/** Required status checks this workflow reports (branch protection names them). */
const REQUIRED = ['build', 'conformance', 'docker-build', 'e2e', 'gate-product', 'language-governance', 'secret-scan', 'security-case', 'test', 'typecheck-core', 'write-discipline'];
/** Fast checks that must keep running on every pull request. */
const FAST = ['build', 'language-governance-checks', 'lint', 'preprint-sync', 'protocol-discipline', 'secret-scan', 'test',
  'typecheck-app', 'typecheck-core', 'typecheck-lib', 'typecheck-production-surfaces', 'typecheck-rest', 'write-discipline'];

test('ci.yml keeps the lane contract', () => {
  assert.deepEqual(laneContract(WORKFLOW_TEXT), []);
});

test('ci.yml defers exactly the heavy suites and keeps the fast checks on every pull request', () => {
  assert.deepEqual(carrying(DEFER_CONDITION), DEFERRED);
  assert.deepEqual(carrying(QUEUE_TESTED_CONDITION), QUEUE_TESTED);
  const queueTested = JOBS.changes.steps.find((step) => step.id === 'classify').env.QUEUE_TESTED_JOBS.split(/\s+/).sort();
  assert.deepEqual(queueTested, QUEUE_TESTED);
  for (const name of FAST) {
    assert.ok(JOBS[name], name);
    assert.doesNotMatch(String(JOBS[name].if ?? ''), /outputs\.lane/, `${name} runs in every lane`);
  }
  for (const name of REQUIRED) assert.ok(JOBS[name], `required check ${name} keeps its job name`);
  // No job carries both the docs skip and the merge-queue deferral: the
  // deferral already covers the docs lane, and the docs audit must see
  // exactly the docs-only skips.
  for (const name of carrying(DEFER_CONDITION)) assert.ok(!String(JOBS[name].if).includes(SKIP_CONDITION), name);
  assert.ok(carrying(SKIP_CONDITION).length > 0);
});

test('a push the merge queue tested still runs every job that attests on main', () => {
  // Only push runs attest (and apply the strict security-case policy), so a
  // job with an attest step, and every job it needs, never takes the dedupe.
  const attesting = Object.keys(JOBS).filter((name) => (JOBS[name].steps ?? []).some((step) => String(step.uses ?? '').startsWith('actions/attest@')));
  assert.deepEqual(attesting.sort(), ['aggregate-conformance-case', 'security-case']);
  const closure = new Set();
  const visit = (name) => {
    if (closure.has(name)) return;
    closure.add(name);
    for (const need of [JOBS[name].needs ?? []].flat()) visit(need);
  };
  attesting.forEach(visit);
  for (const name of closure) assert.doesNotMatch(String(JOBS[name].if ?? ''), /lane != 'tested'/, name);
});

test('the push trigger, the merge queue and the manual run are unchanged', () => {
  const on = WORKFLOW.on ?? WORKFLOW[true];
  assert.deepEqual(on.push, { branches: ['main'] });
  assert.deepEqual(on.pull_request, { branches: ['main'] });
  assert.deepEqual(on.merge_group, { types: ['checks_requested'] });
  assert.ok('workflow_dispatch' in on);
  assert.deepEqual(JOBS.changes.permissions, { contents: 'read', actions: 'read', 'pull-requests': 'read' });
});

// ── Aggregators ──────────────────────────────────────────────────────

/**
 * Runs one job's single `run:` step with the given env and returns its exit
 * status.
 */
function runStep(job, env) {
  const step = JOBS[job].steps.find((entry) => entry.run);
  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', step.run], {
    env: { PATH: process.env.PATH, ...env },
    encoding: 'utf8',
  });
  return result.status;
}

const PR_SKIP_LANES = ['quick', 'docs'];
const RESULTS = ['success', 'skipped', 'failure', 'cancelled'];

test('conformance passes a lane skip and fails every real failure or cancellation', () => {
  // The aggregate case succeeds here; the next test varies it.
  const run = (event, lane, results, aggregateCase = 'success') => runStep('conformance', {
    EVENT_NAME: event, LANE: lane, CORE: results[0], CAID: results[1], CAID_PACKETS: results[2], CASE: aggregateCase,
  });
  for (const [event, lanes] of [['pull_request', PR_SKIP_LANES], ['push', ['tested']]]) {
    for (const lane of lanes) {
      assert.equal(run(event, lane, ['skipped', 'skipped', 'skipped']), 0, `${event}/${lane} skipped`);
      assert.equal(run(event, lane, ['success', 'success', 'success']), 0, `${event}/${lane} success`);
      for (const bad of ['failure', 'cancelled']) {
        assert.equal(run(event, lane, ['skipped', bad, 'skipped']), 1, `${event}/${lane} ${bad}`);
      }
    }
  }
  for (const [event, lane] of [['merge_group', 'full'], ['pull_request', 'full'], ['push', 'full'], ['push', ''], ['pull_request', ''],
    ['merge_group', 'quick'], ['push', 'quick'], ['pull_request', 'tested'], ['workflow_dispatch', 'full']]) {
    assert.equal(run(event, lane, ['success', 'success', 'success']), 0, `${event}/${lane}`);
    for (const bad of ['skipped', 'failure', 'cancelled']) {
      assert.equal(run(event, lane, ['success', 'success', bad]), 1, `${event}/${lane} ${bad}`);
    }
  }
});

test('conformance requires the aggregate conformance case except on a quick or docs pull request', () => {
  // aggregate-conformance-case is not a required check; it skips with
  // security-case, so this aggregator is what blocks a merge on it.
  assert.ok([JOBS.conformance.needs].flat().includes('aggregate-conformance-case'));
  assert.ok(!REQUIRED.includes('aggregate-conformance-case'));
  const run = (event, lane, aggregateCase, parts = 'skipped') => runStep('conformance', {
    EVENT_NAME: event, LANE: lane, CORE: parts, CAID: parts, CAID_PACKETS: parts, CASE: aggregateCase,
  });
  for (const lane of PR_SKIP_LANES) {
    assert.equal(run('pull_request', lane, 'skipped'), 0, `${lane} skipped`);
    assert.equal(run('pull_request', lane, 'success'), 0, `${lane} success`);
    for (const bad of ['failure', 'cancelled']) assert.equal(run('pull_request', lane, bad), 1, `${lane} ${bad}`);
  }
  // A tested push skips the parts but runs security-case and the aggregate
  // case (it attests there), so the case must succeed.
  assert.equal(run('push', 'tested', 'success'), 0);
  for (const bad of ['skipped', 'failure', 'cancelled']) assert.equal(run('push', 'tested', bad), 1, `push/tested ${bad}`);
  for (const [event, lane] of [['merge_group', 'full'], ['pull_request', 'full'], ['push', 'full'], ['push', ''], ['pull_request', ''],
    ['merge_group', 'quick'], ['merge_group', 'docs'], ['merge_group', 'tested'], ['push', 'quick'], ['pull_request', 'tested'], ['workflow_dispatch', 'full']]) {
    assert.equal(run(event, lane, 'success', 'success'), 0, `${event}/${lane}`);
    for (const bad of ['skipped', 'failure', 'cancelled']) {
      assert.equal(run(event, lane, bad, 'success'), 1, `${event}/${lane} ${bad}`);
    }
  }
});

test('gate-product passes a lane skip only where the lane defers it, and never a failure', () => {
  const run = (event, lane, securityCase, suite, languageGovernance = 'success') => runStep('gate-product', {
    EVENT_NAME: event, LANE: lane, SECURITY_CASE: securityCase, SUITE: suite, LANGUAGE_GOVERNANCE: languageGovernance,
  });
  for (const lane of PR_SKIP_LANES) {
    for (const securityCase of RESULTS) {
      for (const suite of RESULTS) {
        const pass = ['success', 'skipped'].includes(securityCase) && ['success', 'skipped'].includes(suite);
        assert.equal(run('pull_request', lane, securityCase, suite), pass ? 0 : 1, `${lane} ${securityCase} ${suite}`);
      }
    }
    assert.equal(run('pull_request', lane, 'skipped', 'skipped', 'failure'), 1);
    assert.equal(run('pull_request', lane, 'skipped', 'skipped', 'skipped'), 1);
  }
  // A tested push: the suite passed in the merge queue; the security case runs.
  assert.equal(run('push', 'tested', 'success', 'skipped'), 0);
  assert.equal(run('push', 'tested', 'success', 'success'), 0);
  assert.equal(run('push', 'tested', 'skipped', 'skipped'), 1);
  assert.equal(run('push', 'tested', 'failure', 'skipped'), 1);
  assert.equal(run('push', 'tested', 'success', 'failure'), 1);
  assert.equal(run('push', 'tested', 'success', 'cancelled'), 1);
  for (const [event, lane] of [['merge_group', 'full'], ['pull_request', 'full'], ['push', 'full'], ['push', ''], ['merge_group', 'quick'], ['merge_group', 'tested'], ['pull_request', 'tested'], ['push', 'quick']]) {
    assert.equal(run(event, lane, 'success', 'success'), 0, `${event}/${lane}`);
    for (const bad of ['skipped', 'failure', 'cancelled']) {
      assert.equal(run(event, lane, bad, 'success'), 1, `${event}/${lane} security-case ${bad}`);
      assert.equal(run(event, lane, 'success', bad), 1, `${event}/${lane} suite ${bad}`);
    }
  }
});

test('language-governance passes a deferred security case only on a quick or docs pull request', () => {
  const run = (event, lane, securityCase, checks = 'success') => runStep('language-governance', {
    EVENT_NAME: event, LANE: lane, SECURITY_CASE: securityCase, CHECKS: checks,
  });
  for (const lane of PR_SKIP_LANES) {
    assert.equal(run('pull_request', lane, 'skipped'), 0);
    assert.equal(run('pull_request', lane, 'success'), 0);
    assert.equal(run('pull_request', lane, 'failure'), 1);
    assert.equal(run('pull_request', lane, 'cancelled'), 1);
    assert.equal(run('pull_request', lane, 'skipped', 'failure'), 1);
    assert.equal(run('pull_request', lane, 'skipped', 'skipped'), 1);
  }
  for (const [event, lane] of [['push', 'tested'], ['merge_group', 'full'], ['pull_request', 'full'], ['push', ''], ['merge_group', 'quick']]) {
    assert.equal(run(event, lane, 'success'), 0, `${event}/${lane}`);
    for (const bad of ['skipped', 'failure', 'cancelled']) assert.equal(run(event, lane, bad), 1, `${event}/${lane} ${bad}`);
  }
});

// ── The `changes` job's lane step ────────────────────────────────────

const REPOSITORY = 'emiliaprotocol/emilia-protocol';
const SHA = 'f2a028c66de6f6b62c6105bd75be611fb5d978b9';
const LANE_STEP = JOBS.changes.steps.find((step) => step.id === 'classify');

/** A `gh api` stand-in: answers each URL from a JSON fixture through jq, or fails. */
const FAKE_GH = `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == api ]] || exit 2
shift
filter=.
url=
while (($#)); do
  case "$1" in
    --paginate) shift ;;
    --jq) filter="$2"; shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\\n' "$url" >> "$FAKE_GH_DIR/calls"
file="$FAKE_GH_DIR/$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_').json"
[[ -f "$file" ]] || { echo "fake gh: no answer for $url" >&2; exit 1; }
exec jq -r "$filter" "$file"
`;

function fixtureKey(url) {
  return url.replace(/[^A-Za-z0-9]/g, '_');
}

/**
 * Runs the lane step with `answers` ({ url: json }) behind the fake gh and
 * returns { lane, summary, calls }.
 */
function decide({ env, answers = {}, cwd }) {
  const dir = mkdtempSync(join(tmpdir(), 'ci-lane-step-'));
  try {
    const bin = join(dir, 'bin');
    const ghDir = join(dir, 'gh');
    const runnerTemp = join(dir, 'runner');
    mkdirSync(bin);
    mkdirSync(ghDir);
    mkdirSync(runnerTemp);
    writeFileSync(join(bin, 'gh'), FAKE_GH);
    chmodSync(join(bin, 'gh'), 0o755);
    for (const [url, body] of Object.entries(answers)) writeFileSync(join(ghDir, `${fixtureKey(url)}.json`), JSON.stringify(body));
    const output = join(dir, 'output');
    const summary = join(dir, 'summary');
    writeFileSync(output, '');
    writeFileSync(summary, '');
    const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', LANE_STEP.run], {
      cwd: cwd ?? dir,
      encoding: 'utf8',
      env: {
        PATH: `${bin}:${process.env.PATH}`,
        HOME: process.env.HOME ?? dir,
        FAKE_GH_DIR: ghDir,
        RUNNER_TEMP: runnerTemp,
        GITHUB_OUTPUT: output,
        GITHUB_STEP_SUMMARY: summary,
        GH_TOKEN: 'unused',
        REPOSITORY,
        QUEUE_TESTED_JOBS: LANE_STEP.env.QUEUE_TESTED_JOBS,
        REF: '',
        SHA,
        HEAD_REF: '',
        PR_NUMBER: '',
        EVENT_LABELS: 'null',
        ...env,
      },
    });
    assert.equal(result.status, 0, `lane step failed:\n${result.stdout}\n${result.stderr}`);
    const lanes = readFileSync(output, 'utf8').split('\n').filter((line) => line.startsWith('lane='));
    assert.equal(lanes.length, 1, readFileSync(output, 'utf8'));
    let calls = [];
    try {
      calls = readFileSync(join(ghDir, 'calls'), 'utf8').trim().split('\n').filter(Boolean);
    } catch {
      calls = [];
    }
    return { lane: lanes[0].slice('lane='.length), summary: readFileSync(summary, 'utf8'), calls };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const runsUrl = `repos/${REPOSITORY}/actions/workflows/ci.yml/runs?event=merge_group&head_sha=${SHA}&per_page=100`;
const jobsUrl = (id) => `repos/${REPOSITORY}/actions/runs/${id}/jobs?per_page=100`;
const mergeGroupRun = (id, overrides = {}) => ({ id, head_sha: SHA, event: 'merge_group', path: '.github/workflows/ci.yml', ...overrides });
const jobsAll = (conclusion = 'success', overrides = {}) => ({
  jobs: [...QUEUE_TESTED, 'security-case', 'test', 'mcp-server-pack'].map((name) => {
    const result = name in overrides ? overrides[name] : conclusion;
    return { name, conclusion: result, status: result === null ? 'in_progress' : 'completed' };
  }),
});
const push = { EVENT_NAME: 'push', REF: 'refs/heads/main' };

test('lane step: a push whose exact commit passed the deduplicated jobs in the merge queue is `tested`', () => {
  const decision = decide({
    env: push,
    answers: { [runsUrl]: { workflow_runs: [mergeGroupRun(41)] }, [jobsUrl(41)]: jobsAll() },
  });
  assert.equal(decision.lane, 'tested');
  assert.match(decision.summary, /Merge-queue run 41 passed/);
  // A non-required light job that failed in the queue does not block the
  // dedupe: it is not skipped, so this push runs it again.
  const lightFailed = decide({
    env: push,
    answers: { [runsUrl]: { workflow_runs: [mergeGroupRun(42)] }, [jobsUrl(42)]: jobsAll('success', { 'mcp-server-pack': 'failure' }) },
  });
  assert.equal(lightFailed.lane, 'tested');
  // A later attempt or another run of the same commit that passed is enough.
  const secondRun = decide({
    env: push,
    answers: {
      [runsUrl]: { workflow_runs: [mergeGroupRun(43), mergeGroupRun(44)] },
      [jobsUrl(43)]: jobsAll('success', { e2e: 'failure' }),
      [jobsUrl(44)]: jobsAll(),
    },
  });
  assert.equal(secondRun.lane, 'tested');
  assert.match(secondRun.summary, /run 44/);
});

test('lane step: every push the merge queue did not fully test runs everything', () => {
  const cases = [
    ['direct push (no merge_group run)', { [runsUrl]: { workflow_runs: [] } }, /direct push/],
    ['Actions API failure', {}, /did not answer/],
    ['a deduplicated job failed', { [runsUrl]: { workflow_runs: [mergeGroupRun(51)] }, [jobsUrl(51)]: jobsAll('success', { 'conformance-caid': 'failure' }) }, /passed all of/],
    ['a deduplicated job was cancelled', { [runsUrl]: { workflow_runs: [mergeGroupRun(52)] }, [jobsUrl(52)]: jobsAll('success', { 'gate-product-suite': 'cancelled' }) }, /passed all of/],
    ['a deduplicated job was skipped', { [runsUrl]: { workflow_runs: [mergeGroupRun(53)] }, [jobsUrl(53)]: jobsAll('success', { 'docker-build': 'skipped' }) }, /passed all of/],
    ['a deduplicated job is missing', { [runsUrl]: { workflow_runs: [mergeGroupRun(54)] }, [jobsUrl(54)]: { jobs: [{ name: 'e2e', conclusion: 'success' }] } }, /passed all of/],
    ['a deduplicated job still running', { [runsUrl]: { workflow_runs: [mergeGroupRun(55)] }, [jobsUrl(55)]: jobsAll('success', { 'conformance-core': null }) }, /passed all of/],
    ['the jobs API failed', { [runsUrl]: { workflow_runs: [mergeGroupRun(56)] } }, /passed all of/],
    ['a run of another commit', { [runsUrl]: { workflow_runs: [mergeGroupRun(57, { head_sha: 'a'.repeat(40) })] }, [jobsUrl(57)]: jobsAll() }, /direct push/],
    ['a run of another workflow file', { [runsUrl]: { workflow_runs: [mergeGroupRun(58, { path: '.github/workflows/other.yml' })] }, [jobsUrl(58)]: jobsAll() }, /direct push/],
    ['a run of another event', { [runsUrl]: { workflow_runs: [mergeGroupRun(59, { event: 'pull_request' })] }, [jobsUrl(59)]: jobsAll() }, /direct push/],
  ];
  for (const [label, answers, reason] of cases) {
    const decision = decide({ env: push, answers });
    assert.equal(decision.lane, 'full', label);
    assert.match(decision.summary, reason, label);
  }
  // A push to another ref never asks the API.
  const otherRef = decide({ env: { EVENT_NAME: 'push', REF: 'refs/heads/release' }, answers: { [runsUrl]: { workflow_runs: [mergeGroupRun(60)] }, [jobsUrl(60)]: jobsAll() } });
  assert.equal(otherRef.lane, 'full');
  assert.deepEqual(otherRef.calls, []);
  for (const event of ['merge_group', 'workflow_dispatch']) {
    const decision = decide({ env: { EVENT_NAME: event, REF: 'refs/heads/main' } });
    assert.equal(decision.lane, 'full', event);
    assert.deepEqual(decision.calls, [], event);
  }
});

/** A repository whose HEAD is a pull request's two-parent merge commit. */
function pullRequestRepo({ baseClassifier = true, change }) {
  const repo = mkdtempSync(join(tmpdir(), 'ci-lane-pr-'));
  const git = (...args) => execFileSync('git', args, {
    cwd: repo,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Lane Test',
      GIT_AUTHOR_EMAIL: 'lane@example.com',
      GIT_COMMITTER_NAME: 'Lane Test',
      GIT_COMMITTER_EMAIL: 'lane@example.com',
    },
  });
  const write = (path, text) => {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), text);
  };
  git('init', '-q', '-b', 'main');
  write('.github/workflows/ci.yml', [
    'jobs:',
    '  changes:',
    '    runs-on: ubuntu-latest',
    '  fuzz:',
    '    needs: [changes]',
    `    if: \${{ !cancelled() && ${SKIP_CONDITION} }}`,
    '    steps:',
    '      - run: node fuzz/run.mjs',
    '',
  ].join('\n'));
  write('docs/free.md', 'free\n');
  write('security/security-case.json', '{}\n');
  write('lib/code.ts', 'export {};\n');
  if (baseClassifier) {
    for (const file of ['change-lane.mjs', 'change-lane.node-test.mjs']) {
      mkdirSync(join(repo, 'scripts/ci'), { recursive: true });
      copyFileSync(join(HERE, file), join(repo, 'scripts/ci', file));
    }
  }
  git('add', '-A');
  git('commit', '-q', '-m', 'base');
  git('checkout', '-q', '-b', 'topic');
  change(write);
  git('add', '-A');
  git('commit', '-q', '-m', 'topic');
  git('checkout', '-q', '--detach', 'main');
  git('merge', '-q', '--no-ff', '-m', 'merge topic', 'topic');
  return repo;
}

const pullRequest = (overrides = {}) => ({ EVENT_NAME: 'pull_request', REF: 'refs/pull/7/merge', PR_NUMBER: '7', HEAD_REF: 'topic', EVENT_LABELS: '[]', ...overrides });
const pullUrl = `repos/${REPOSITORY}/pulls/7`;

test('lane step: a pull request is quick unless it is prose-only, labeled full-ci, or carries pull-request-only rules', () => {
  const code = pullRequestRepo({ change: (write) => write('lib/code.ts', 'export const x = 1;\n') });
  const prose = pullRequestRepo({ change: (write) => write('docs/free.md', 'free, edited\n') });
  const workflowChange = pullRequestRepo({ change: (write) => write('.github/workflows/other.yml', 'on: push\n') });
  const securityCase = pullRequestRepo({ change: (write) => write('security/security-case.json', '{"x":1}\n') });
  const noBaseClassifier = pullRequestRepo({ baseClassifier: false, change: (write) => write('docs/free.md', 'edited\n') });
  try {
    const unlabeled = { [pullUrl]: { labels: [{ name: 'dependencies' }] } };
    assert.equal(decide({ env: pullRequest(), answers: unlabeled, cwd: code }).lane, 'quick');
    assert.equal(decide({ env: pullRequest(), answers: unlabeled, cwd: prose }).lane, 'docs');
    assert.equal(decide({ env: pullRequest(), answers: unlabeled, cwd: workflowChange }).lane, 'quick');
    assert.equal(decide({ env: pullRequest(), answers: unlabeled, cwd: noBaseClassifier }).lane, 'quick');

    // `full-ci` from the API (a label added after the push, then a re-run).
    const labeled = { [pullUrl]: { labels: [{ name: 'dependencies' }, { name: 'full-ci' }] } };
    for (const repo of [code, prose]) assert.equal(decide({ env: pullRequest(), answers: labeled, cwd: repo }).lane, 'full');
    // ... or, when the API does not answer, from the event payload.
    assert.equal(decide({ env: pullRequest({ EVENT_LABELS: '["full-ci"]' }), cwd: code }).lane, 'full');
    assert.equal(decide({ env: pullRequest({ EVENT_LABELS: '["full-ci-later"]' }), cwd: code }).lane, 'quick');
    // The API's answer wins over a stale payload (the label was removed).
    assert.equal(decide({ env: pullRequest({ EVENT_LABELS: '["full-ci"]' }), answers: unlabeled, cwd: code }).lane, 'quick');

    // Main's refresh pull request is strict only on its pull_request run.
    assert.equal(decide({ env: pullRequest({ HEAD_REF: 'automation/volatile-evidence-0123456789ab' }), answers: unlabeled, cwd: prose }).lane, 'full');
    // The security-case policy checks a changed case only on pull_request runs.
    assert.equal(decide({ env: pullRequest(), answers: unlabeled, cwd: securityCase }).lane, 'full');
  } finally {
    for (const repo of [code, prose, workflowChange, securityCase, noBaseClassifier]) rmSync(repo, { recursive: true, force: true });
  }
});
