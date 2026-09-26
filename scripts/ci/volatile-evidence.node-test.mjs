// SPDX-License-Identifier: Apache-2.0
//
// Self-test for scripts/ci/volatile-evidence.mjs: drift in the five volatile
// files is advisory on pull requests and merge groups, strict on main's own
// refresh pull request, and on main it fails once it outlives the grace
// window; the refresh bundle and commit carry only those five files.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { COMMIT_TRAILER, DERIVED_EVIDENCE, collect as collectDerived } from './evidence-autopilot.mjs';
import {
  DRIFT_REPORT_VERSION,
  GRACE_HOURS,
  REFRESH_BRANCH_PREFIX,
  REFRESH_TITLE,
  VOLATILE_EVIDENCE,
  decideGrace,
  evaluatePolicy,
  main,
  mergeDriftReports,
  observationFromJobs,
  policyMode,
  refreshBranch,
  summaryMarkdown,
} from './volatile-evidence.mjs';

const REPOSITORY = 'emiliaprotocol/emilia-protocol';
const RUN_URL = `https://github.com/${REPOSITORY}/actions/runs/987654321`;
const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);
const SHA_C = 'c'.repeat(40);
const NOW = new Date('2026-09-26T12:00:00Z');
const hoursAgo = (hours) => new Date(NOW.getTime() - hours * 3_600_000).toISOString();

const report = (writer, stale, extra = {}) => ({
  '@version': DRIFT_REPORT_VERSION,
  writer,
  current: stale.length === 0,
  stale,
  ...extra,
});

function run(id, sha, createdHoursAgo, observation, overrides = {}) {
  return {
    id,
    head_sha: sha,
    created_at: hoursAgo(createdHoursAgo),
    status: 'completed',
    conclusion: observation === 'failed' ? 'failure' : 'success',
    event: 'push',
    observation,
    ...overrides,
  };
}
const observe = async (r) => (r.observation === 'failed' ? 'unknown' : r.observation);

test('the volatile set is exactly the five main-owned files, inside the DCO allowlist', () => {
  assert.deepEqual([...VOLATILE_EVIDENCE].sort(), [
    'AI_CONTEXT.md',
    'lib/proof-stats.json',
    'public/.well-known/emilia-context.json',
    'public/llms-full.txt',
    'public/llms.txt',
  ]);
  for (const path of VOLATILE_EVIDENCE) assert.ok(DERIVED_EVIDENCE.includes(path), path);
  for (const strict of [
    'security/security-case.json',
    'formal/results/formal-runtime-scenario-conformance.v2.json',
    'conformance/conformance-manifest.json',
  ]) assert.ok(!VOLATILE_EVIDENCE.includes(strict), `${strict} stays strict`);
  assert.equal(refreshBranch(SHA_A), `${REFRESH_BRANCH_PREFIX}aaaaaaaaaaaa`);
  assert.throws(() => refreshBranch('main'), /40-character/);
});

test('drift reports must come from both writers, name only volatile files and agree with themselves', () => {
  assert.deepEqual(
    mergeDriftReports([
      report('sync:proof-stats', ['lib/proof-stats.json'], { fields: ['tests'] }),
      report('sync:llm-context', ['AI_CONTEXT.md', 'public/llms-full.txt']),
    ]),
    { stale: ['AI_CONTEXT.md', 'lib/proof-stats.json', 'public/llms-full.txt'], fields: ['tests'] },
  );
  assert.throws(() => mergeDriftReports([report('sync:llm-context', [])]), /one drift report from each/);
  assert.throws(
    () => mergeDriftReports([report('sync:proof-stats', []), report('sync:proof-stats', [])]),
    /one drift report from each/,
  );
  assert.throws(
    () => mergeDriftReports([report('sync:proof-stats', ['security/security-case.json']), report('sync:llm-context', [])]),
    /not volatile evidence/,
  );
  assert.throws(
    () => mergeDriftReports([{ ...report('sync:proof-stats', []), current: false }, report('sync:llm-context', [])]),
    /contradicts/,
  );
  assert.throws(
    () => mergeDriftReports([{ ...report('sync:proof-stats', []), '@version': 'v0' }, report('sync:llm-context', [])]),
    /version/,
  );
});

test('pull requests and merge groups are advisory, the refresh pull request strict, main on a grace clock', () => {
  assert.equal(policyMode({ event: 'pull_request', ref: 'refs/pull/1/merge', headRef: 'feat/x' }), 'advisory');
  assert.equal(policyMode({ event: 'merge_group', ref: 'refs/heads/gh-readonly-queue/main/pr-1-abc' }), 'advisory');
  assert.equal(
    policyMode({ event: 'pull_request', ref: 'refs/pull/2/merge', headRef: `${REFRESH_BRANCH_PREFIX}aaaaaaaaaaaa` }),
    'strict',
  );
  for (const event of ['push', 'schedule', 'workflow_dispatch']) {
    assert.equal(policyMode({ event, ref: 'refs/heads/main' }), 'grace', event);
    assert.equal(policyMode({ event, ref: 'refs/heads/feature' }), 'advisory', event);
  }
});

test('a completed refresh run observed main current only when regenerate passed and publish was skipped', () => {
  assert.equal(observationFromJobs([{ name: 'regenerate', conclusion: 'success' }, { name: 'publish', conclusion: 'skipped' }]), 'current');
  assert.equal(observationFromJobs([{ name: 'regenerate', conclusion: 'success' }, { name: 'publish', conclusion: 'success' }]), 'stale');
  assert.equal(observationFromJobs([{ name: 'regenerate', conclusion: 'success' }, { name: 'publish', conclusion: 'failure' }]), 'stale');
  assert.equal(observationFromJobs([{ name: 'regenerate', conclusion: 'failure' }, { name: 'publish', conclusion: 'skipped' }]), 'unknown');
  assert.equal(observationFromJobs([]), 'unknown');
});

test('grace: a fresh staleness with a refresh in flight passes', async () => {
  const decision = await decideGrace({
    sha: SHA_C,
    runs: [
      run(3, SHA_C, 0.3, 'unknown', { status: 'in_progress', conclusion: null }),
      run(2, SHA_B, 5, 'current'),
      run(1, SHA_A, 9, 'stale'),
    ],
    observe,
    now: NOW,
  });
  assert.equal(decision.verdict, 'pass');
  assert.equal(decision.staleSince, hoursAgo(0.3));
});

test('grace: the clock starts at the first run after the last current observation, skipping failures', async () => {
  const runs = [
    run(5, SHA_C, 1, 'unknown', { status: 'in_progress', conclusion: null }),
    run(4, SHA_B, 20, 'failed'),
    run(3, SHA_B, 26, 'stale'),
    run(2, SHA_A, 30, 'current'),
  ];
  const decision = await decideGrace({ sha: SHA_C, runs, observe, now: NOW });
  assert.equal(decision.verdict, 'fail');
  assert.equal(decision.staleSince, hoursAgo(26));
  assert.match(decision.reason, /no refresh landed within one scheduled refresh cycle/);
  // The same history inside the window passes.
  const within = await decideGrace({ sha: SHA_C, runs, observe, now: new Date(Date.parse(hoursAgo(26 - GRACE_HOURS + 1))) });
  assert.equal(within.verdict, 'pass');
});

test('grace: without any current observation the oldest run is a lower bound on the age', async () => {
  const young = [run(2, SHA_B, 1, 'stale'), run(1, SHA_A, 10, 'failed')];
  assert.equal((await decideGrace({ sha: SHA_C, runs: young, observe, now: NOW })).verdict, 'pass');
  const old = [run(2, SHA_B, 1, 'stale'), run(1, SHA_A, 30, 'failed')];
  const decision = await decideGrace({ sha: SHA_C, runs: old, observe, now: NOW });
  assert.equal(decision.verdict, 'fail');
  assert.equal(decision.staleSince, hoursAgo(30));
});

test('grace fails closed on a disabled workflow, a missing run and irreproducible writers', async () => {
  assert.match((await decideGrace({ sha: SHA_C, runs: [], observe, now: NOW })).reason, /has no runs on main/);
  const missing = await decideGrace({ sha: SHA_C, runs: [run(2, SHA_B, 2, 'current')], observe, now: NOW });
  assert.equal(missing.verdict, 'fail');
  assert.match(missing.reason, /did not start for later pushes/);
  const contradiction = await decideGrace({
    sha: SHA_C,
    runs: [run(3, SHA_C, 0.5, 'current'), run(2, SHA_B, 2, 'stale')],
    observe,
    now: NOW,
  });
  assert.equal(contradiction.verdict, 'fail');
  assert.match(contradiction.reason, /not reproducible/);
});

test('policy outcomes: advisory never fails, strict fails, grace dates the drift, current needs no API', async () => {
  const stale = ['lib/proof-stats.json'];
  assert.equal((await evaluatePolicy({ mode: 'advisory', stale })).exitCode, 0);
  assert.match((await evaluatePolicy({ mode: 'advisory', stale })).annotation, /^::notice /);
  assert.equal((await evaluatePolicy({ mode: 'strict', stale })).exitCode, 1);
  assert.equal((await evaluatePolicy({ mode: 'grace', stale: [] })).exitCode, 0);
  const client = (runs) => ({ refreshRuns: async () => runs, observe });
  const inFlight = await evaluatePolicy({
    mode: 'grace',
    stale,
    sha: SHA_C,
    client: client([run(2, SHA_C, 0.2, 'unknown', { status: 'in_progress', conclusion: null }), run(1, SHA_B, 3, 'current')]),
    now: NOW,
  });
  assert.equal(inFlight.exitCode, 0);
  assert.match(inFlight.annotation, /^::warning /);
  const overdue = await evaluatePolicy({ mode: 'grace', stale, sha: SHA_C, client: client([run(1, SHA_B, 40, 'stale')]), now: NOW });
  assert.equal(overdue.exitCode, 1);
  assert.match(overdue.annotation, /^::error /);
  await assert.rejects(evaluatePolicy({ mode: 'grace', stale, client: client([]), now: NOW }), /--sha/);
});

test('the policy CLI writes the job summary and dates main drift through the Actions API', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'volatile-policy-'));
  try {
    const proof = join(dir, 'proof.json');
    const llm = join(dir, 'llm.json');
    const summary = join(dir, 'summary.md');
    writeFileSync(proof, JSON.stringify(report('sync:proof-stats', ['lib/proof-stats.json'], { fields: ['tests'] })));
    writeFileSync(llm, JSON.stringify(report('sync:llm-context', ['AI_CONTEXT.md'])));
    const env = { GITHUB_STEP_SUMMARY: summary, GH_TOKEN: 'test-token' };

    const noFetch = async () => { throw new Error('the advisory path must not call the API'); };
    const advisory = await main(
      ['policy', '--report', proof, '--report', llm, '--event', 'pull_request', '--ref', 'refs/pull/9/merge', '--head-ref', 'feat/x'],
      { env, fetchImpl: noFetch, now: NOW },
    );
    assert.equal(advisory, 0);
    const text = readFileSync(summary, 'utf8');
    assert.match(text, /\| `lib\/proof-stats\.json` \| stale \|/);
    assert.match(text, /\| `public\/llms\.txt` \| current \|/);
    assert.match(text, /Advisory only; this never fails the check/);
    assert.match(text, /`tests`/);

    const strict = await main(
      ['policy', '--report', proof, '--report', llm, '--event', 'pull_request', '--ref', 'refs/pull/9/merge',
        '--head-ref', `${REFRESH_BRANCH_PREFIX}bbbbbbbbbbbb`],
      { env, fetchImpl: noFetch, now: NOW },
    );
    assert.equal(strict, 1);

    const requests = [];
    const fetchImpl = async (url, init) => {
      requests.push({ url, auth: init.headers.authorization });
      if (url.endsWith(`/actions/workflows/volatile-evidence-refresh.yml/runs?branch=main&per_page=50`)) {
        return Response.json({ workflow_runs: [
          { id: 2, head_sha: SHA_C, created_at: hoursAgo(0.5), status: 'in_progress', conclusion: null, event: 'push' },
          { id: 1, head_sha: SHA_B, created_at: hoursAgo(4), status: 'completed', conclusion: 'success', event: 'push' },
        ] });
      }
      if (url.endsWith('/actions/runs/1/jobs?filter=latest&per_page=100')) {
        return Response.json({ jobs: [{ name: 'regenerate', conclusion: 'success' }, { name: 'publish', conclusion: 'skipped' }] });
      }
      return new Response('not found', { status: 404 });
    };
    const grace = await main(
      ['policy', '--report', proof, '--report', llm, '--event', 'push', '--ref', 'refs/heads/main', '--sha', SHA_C,
        '--repository', REPOSITORY],
      { env, fetchImpl, now: NOW },
    );
    assert.equal(grace, 0);
    assert.ok(requests.every((request) => request.auth === 'Bearer test-token'));
    assert.match(readFileSync(summary, 'utf8'), /Within grace: stale since/);

    const failingApi = async () => new Response('boom', { status: 502 });
    await assert.rejects(
      main(['policy', '--report', proof, '--report', llm, '--event', 'push', '--ref', 'refs/heads/main', '--sha', SHA_C,
        '--repository', REPOSITORY], { env, fetchImpl: failingApi, now: NOW }),
      /answered 502/,
    );
    await assert.rejects(
      main(['policy', '--report', proof, '--event', 'push', '--ref', 'refs/heads/main', '--stale', '[]'], { env, now: NOW }),
      /not both/,
    );
    const fromStale = await main(
      ['policy', '--stale', '["public/llms.txt"]', '--event', 'merge_group', '--ref', 'refs/heads/gh-readonly-queue/main/pr-9'],
      { env, fetchImpl: noFetch, now: NOW },
    );
    assert.equal(fromStale, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the summary names the refresh workflow and the one exception contributors must know', () => {
  const text = summaryMarkdown({ mode: 'advisory', stale: ['public/llms.txt'], fields: [] });
  assert.match(text, /volatile-evidence-refresh\.yml/);
  assert.match(text, /adds\nor removes a security claim/);
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'volatile-evidence-'));
  const repo = join(root, 'repo');
  mkdirSync(repo);
  const git = (...args) => execFileSync('git', args, {
    cwd: repo,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Volatile Test',
      GIT_AUTHOR_EMAIL: 'volatile@example.com',
      GIT_COMMITTER_NAME: 'Volatile Test',
      GIT_COMMITTER_EMAIL: 'volatile@example.com',
    },
  }).trim();
  const write = (path, text) => {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), text);
  };
  git('init', '-q', '-b', 'main');
  for (const path of DERIVED_EVIDENCE) write(path, path.endsWith('.json') ? '{"v":1}\n' : 'v1\n');
  git('add', '-A');
  git('commit', '-q', '-m', 'source');
  const source = git('rev-parse', 'HEAD');
  return { root, repo, git, write, source, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test('collect and request publish only the volatile files as one trailer-carrying compare-and-swap commit', async () => {
  const f = fixture();
  try {
    f.write('lib/proof-stats.json', '{"v":2}\n');
    f.write('public/llms.txt', 'v2\n');
    f.git('commit', '-q', '-am', 'writers');
    const bundle = join(f.root, 'bundle');
    const outputs = join(f.root, 'outputs');
    assert.equal(await main(['collect', '--repo', f.repo, '--source-sha', f.source, '--out', bundle, '--github-output', outputs]), 0);
    assert.match(readFileSync(outputs, 'utf8'), /changed=true\nstale=\["lib\/proof-stats\.json","public\/llms\.txt"\]\n/);

    const out = join(f.root, 'request.json');
    const requestOutputs = join(f.root, 'request-outputs');
    const body = join(f.root, 'body.md');
    assert.equal(await main([
      'request', '--bundle', bundle, '--source-sha', f.source, '--repository', REPOSITORY,
      '--run-url', RUN_URL, '--out', out, '--pr-body-out', body, '--github-output', requestOutputs,
    ]), 0);
    const description = readFileSync(body, 'utf8');
    assert.match(description, new RegExp(`main at ${f.source}`));
    assert.match(description, /- `lib\/proof-stats\.json`\n- `public\/llms\.txt`\n/);
    assert.ok(description.includes(RUN_URL));
    const { variables: { input } } = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(input.branch.branchName, refreshBranch(f.source));
    assert.equal(input.expectedHeadOid, f.source);
    assert.equal(input.message.headline, REFRESH_TITLE);
    assert.ok(input.message.body.split('\n').includes(COMMIT_TRAILER));
    assert.deepEqual(input.fileChanges.additions.map((file) => file.path), ['lib/proof-stats.json', 'public/llms.txt']);
    assert.equal(readFileSync(requestOutputs, 'utf8'), `branch=${refreshBranch(f.source)}\ntitle=${REFRESH_TITLE}\n`);
  } finally {
    f.cleanup();
  }
});

test('the refresh refuses strict evidence, even when the full derived allowlist would accept it', async () => {
  const f = fixture();
  try {
    f.write('lib/proof-stats.json', '{"v":2}\n');
    f.write('security/security-case.json', '{"v":2}\n');
    f.git('commit', '-q', '-am', 'writers touched the security case');
    await assert.rejects(
      main(['collect', '--repo', f.repo, '--source-sha', f.source, '--out', join(f.root, 'bundle')]),
      /outside the derived-evidence allowlist:\nsecurity\/security-case\.json/,
    );
    // The same change is a valid Dependabot autopilot bundle, and that bundle
    // is refused by the volatile request.
    const derived = join(f.root, 'derived');
    collectDerived({ repo: f.repo, sourceSha: f.source, out: derived });
    await assert.rejects(
      main(['request', '--bundle', derived, '--source-sha', f.source, '--repository', REPOSITORY,
        '--run-url', RUN_URL, '--out', join(f.root, 'r.json')]),
      /security\/security-case\.json: not a derived-evidence path/,
    );
    assert.throws(
      () => collectDerived({ repo: f.repo, sourceSha: f.source, out: derived, allowlist: ['lib/code.ts'] }),
      /not derived-evidence paths: lib\/code\.ts/,
    );
  } finally {
    f.cleanup();
  }
});
