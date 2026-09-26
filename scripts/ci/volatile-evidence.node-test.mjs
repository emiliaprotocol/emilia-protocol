// SPDX-License-Identifier: Apache-2.0
//
// Self-test for scripts/ci/volatile-evidence.mjs: only drift in the measured
// test counts may lag (advisory on pull requests and merge groups, graced on
// main), everything else fails in every mode; main's refresh pull request is
// strict and may change nothing but the five files; the writers are
// idempotent, so a refresh on a current main publishes nothing and records the
// "current" observation the grace clock needs; the publisher reuses and
// closes only refresh pull requests it can prove are its own and older.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import YAML from 'yaml';

import {
  ADVISORY_PROOF_STATS_FIELDS,
  proofStatsDriftFields,
  proofStatsFileText,
  stableGeneratedAt,
} from '../generate-proof-stats.mjs';
import { COMMIT_TRAILER, DERIVED_EVIDENCE, collect as collectDerived } from './evidence-autopilot.mjs';
import {
  ADVISORY_DRIFT,
  DRIFT_REPORT_VERSION,
  GRACE_HOURS,
  PUBLISH_JOB,
  REFRESH_BRANCH,
  REFRESH_BRANCH_PREFIX,
  REFRESH_TITLE,
  REFRESH_WORKFLOW,
  REGENERATE_JOB,
  VOLATILE_EVIDENCE,
  changedPaths,
  classifyDrift,
  decideGrace,
  evaluatePolicy,
  githubClient,
  main,
  mergeDriftReports,
  observationFromJobs,
  planRefresh,
  policyMode,
  proofStatsChangeProblems,
  refreshBranch,
  summaryMarkdown,
  touchedVolatile,
  trustedRefreshRun,
} from './volatile-evidence.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const workflow = (name) => YAML.parse(readFileSync(join(ROOT, '.github/workflows', name), 'utf8'));

const REPOSITORY = 'emiliaprotocol/emilia-protocol';
const BOT = 'emilia-evidence-autopilot[bot]';
const RUN_URL = `https://github.com/${REPOSITORY}/actions/runs/987654321`;
const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);
const SHA_C = 'c'.repeat(40);
const SHA_D = 'd'.repeat(40);
const NOW = new Date('2026-09-26T12:00:00Z');
const hoursAgo = (hours) => new Date(NOW.getTime() - hours * 3_600_000).toISOString();
const TESTS_ONLY = ['tests.files', 'tests.total'];

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
    head_branch: 'main',
    head_repository: { full_name: REPOSITORY },
    observation,
    ...overrides,
  };
}
const observe = async (r) => (r.observation === 'failed' ? 'unknown' : r.observation);
const client = (runs, truncated = false) => ({ refreshRuns: async () => ({ runs, truncated }), observe });

test('a refresh merged to main does not create a new proof-stats timestamp on its own', () => {
  const first = {
    generatedAt: '2026-09-26T04:00:00.000Z',
    tests: { total: 120, files: 12 },
    securityCase: { claims: 35, evidenceBundleSha256: 'a'.repeat(64) },
  };
  const refreshed = {
    ...first,
    generatedAt: '2026-09-27T04:00:00.000Z',
  };
  // The next push caused only by merging the refresh has identical evidence.
  // The writer must reproduce byte-identical JSON, so collect opens no PR.
  const repeated = { ...refreshed, generatedAt: stableGeneratedAt(refreshed, first) };
  assert.equal(JSON.stringify(repeated), JSON.stringify(first));
  assert.equal(stableGeneratedAt(refreshed, { ...first, tests: { total: 119, files: 12 } }), refreshed.generatedAt);
  assert.equal(stableGeneratedAt(refreshed, { ...first, generatedAt: 'invalid' }), refreshed.generatedAt);
  assert.equal(stableGeneratedAt(refreshed, { ...first, generatedAt: '2026-09-28T00:00:00.000Z' }), refreshed.generatedAt);
  assert.equal(stableGeneratedAt(refreshed, { ...first, tests: { total: 120, files: 12, policy: 'other' } }), refreshed.generatedAt);
  // generatedAt dates the test measurement: a derived field that changed
  // while the counts did not keeps it. Check mode compares that field (and
  // any forged extra one) with the sources, so the timestamp carries nothing.
  assert.equal(stableGeneratedAt(refreshed, { ...first, securityCase: { claims: 36, evidenceBundleSha256: 'b'.repeat(64) } }), first.generatedAt);
  assert.equal(stableGeneratedAt(refreshed, null), refreshed.generatedAt);
});

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
  assert.ok(REFRESH_BRANCH.test(refreshBranch(SHA_A)));
  for (const bad of [`${REFRESH_BRANCH_PREFIX}foo`, `${REFRESH_BRANCH_PREFIX}aaaaaaaaaaa#`, `${REFRESH_BRANCH_PREFIX}aaaaaaaaaaaa/x`,
    `${REFRESH_BRANCH_PREFIX}AAAAAAAAAAAA`, `x/${REFRESH_BRANCH_PREFIX}aaaaaaaaaaaa`]) {
    assert.ok(!REFRESH_BRANCH.test(bad), bad);
  }
  assert.throws(() => refreshBranch('main'), /40-character/);
});

test('the advisory allowlist is the measured test counts only, and the writer uses the same list', () => {
  assert.deepEqual(Object.keys(ADVISORY_DRIFT), ['lib/proof-stats.json']);
  assert.deepEqual([...ADVISORY_DRIFT['lib/proof-stats.json']], TESTS_ONLY);
  assert.deepEqual([...ADVISORY_PROOF_STATS_FIELDS], TESTS_ONLY);
});

test('deny by default: test-count drift is advisory, every other proof field and any LLM file is denied', () => {
  assert.deepEqual(classifyDrift({ stale: ['lib/proof-stats.json'], fields: ['tests.total'] }), { advisory: ['lib/proof-stats.json'], denied: [] });
  assert.deepEqual(classifyDrift({ stale: ['lib/proof-stats.json'], fields: TESTS_ONLY }).denied, []);
  for (const field of [
    'formalEvidenceCoverage.verifiedFormalObligations.count',
    'formalEvidenceCoverage.boundedRuntimeTraced.claimIds',
    'tamarin.verifiedObligations',
    'tla.invariants',
    'alloy.assertions',
    'formalScenarioConformance.scenarios',
    'conformance.vectors',
    'externalImplementation.hostilityCases',
    'securityCase.evidenceBundleSha256',
    'redTeamCases',
    'tests.policy',
    'tests',
    'aFieldAddedLater',
  ]) {
    const { advisory, denied } = classifyDrift({ stale: ['lib/proof-stats.json'], fields: ['tests.total', field] });
    assert.deepEqual(advisory, [], field);
    assert.deepEqual(denied, [{ path: 'lib/proof-stats.json', fields: [field] }], field);
  }
  // A stale proof-stats report that does not name its fields is denied.
  assert.equal(classifyDrift({ stale: ['lib/proof-stats.json'], fields: null }).denied.length, 1);
  assert.equal(classifyDrift({ stale: ['lib/proof-stats.json'], fields: [] }).denied.length, 1);
  for (const path of VOLATILE_EVIDENCE.filter((file) => file !== 'lib/proof-stats.json')) {
    assert.deepEqual(classifyDrift({ stale: [path], fields: TESTS_ONLY }), { advisory: [], denied: [{ path, fields: [] }] }, path);
  }
});

test('proof-stats drift fields are dotted leaves, and generatedAt is never one', () => {
  const recorded = { generatedAt: 'x', tests: { total: 1, files: 1, policy: 'p' }, tamarin: { verifiedObligations: 20 }, list: [1, 2] };
  assert.deepEqual(proofStatsDriftFields({ ...recorded, generatedAt: 'y' }, recorded), []);
  assert.deepEqual(
    proofStatsDriftFields({ ...recorded, tests: { total: 2, files: 1, policy: 'p' }, list: [1, 3], extra: 1 }, recorded),
    ['extra', 'list', 'tests.total'],
  );
  assert.deepEqual(proofStatsDriftFields({ ...recorded, tamarin: 5 }, recorded), ['tamarin']);
  assert.deepEqual(proofStatsDriftFields([], recorded), ['(root)']);
});

test('drift reports must come from both writers, name only volatile files and agree with themselves', () => {
  assert.deepEqual(
    mergeDriftReports([
      report('sync:proof-stats', ['lib/proof-stats.json'], { fields: ['tests.total'] }),
      report('sync:llm-context', ['AI_CONTEXT.md', 'public/llms-full.txt']),
    ]),
    { stale: ['AI_CONTEXT.md', 'lib/proof-stats.json', 'public/llms-full.txt'], fields: ['tests.total'] },
  );
  assert.equal(
    mergeDriftReports([report('sync:proof-stats', ['lib/proof-stats.json']), report('sync:llm-context', [])]).fields,
    null,
    'a stale proof-stats report without fields is unknown',
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
  assert.throws(
    () => mergeDriftReports([report('sync:proof-stats', []), report('sync:llm-context', [], { fields: ['tests.total'] })]),
    /only the proof-stats report/,
  );
});

test('pull requests and merge groups are advisory, the refresh pull request strict, main on a grace clock', () => {
  assert.equal(policyMode({ event: 'pull_request', ref: 'refs/pull/1/merge', headRef: 'feat/x' }), 'advisory');
  assert.equal(policyMode({ event: 'merge_group', ref: 'refs/heads/gh-readonly-queue/main/pr-1-abc' }), 'advisory');
  assert.equal(
    policyMode({ event: 'pull_request', ref: 'refs/pull/2/merge', headRef: `${REFRESH_BRANCH_PREFIX}aaaaaaaaaaaa` }),
    'strict',
  );
  // Any head branch in the refresh namespace is strict, well-formed or not.
  assert.equal(policyMode({ event: 'pull_request', ref: 'refs/pull/2/merge', headRef: `${REFRESH_BRANCH_PREFIX}foo` }), 'strict');
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
  assert.match(decision.reason, /no refresh landed within one refresh cycle/);
  // The same history inside the window passes.
  const within = await decideGrace({ sha: SHA_C, runs, observe, now: new Date(Date.parse(hoursAgo(26 - GRACE_HOURS + 1))) });
  assert.equal(within.verdict, 'pass');
});

test('grace: a run older than the window that did not find main current fails without reading further', async () => {
  const observed = [];
  const counting = async (r) => { observed.push(r.id); return observe(r); };
  const runs = [run(3, SHA_C, 1, 'stale'), run(2, SHA_B, 30, 'stale'), run(1, SHA_A, 40, 'current')];
  const decision = await decideGrace({ sha: SHA_C, runs, observe: counting, now: NOW });
  assert.equal(decision.verdict, 'fail');
  assert.equal(decision.staleSince, hoursAgo(30));
  assert.match(decision.reason, /stale since at least/);
  assert.deepEqual(observed, [3, 2], 'the run past the window is never observed');
  // A current observation older than the window still resets the clock.
  const reset = await decideGrace({ sha: SHA_C, runs: [run(2, SHA_C, 1, 'stale'), run(1, SHA_B, 40, 'current')], observe, now: NOW });
  assert.equal(reset.verdict, 'pass');
});

test('grace: without any current observation the first run is the clock, and a truncated history fails closed', async () => {
  const young = [run(2, SHA_B, 1, 'stale'), run(1, SHA_A, 10, 'failed')];
  assert.equal((await decideGrace({ sha: SHA_C, runs: young, observe, now: NOW })).verdict, 'pass');
  const truncated = await decideGrace({ sha: SHA_C, runs: young, observe, now: NOW, truncated: true });
  assert.equal(truncated.verdict, 'fail');
  assert.match(truncated.reason, /cannot be dated/);
  const old = [run(2, SHA_B, 1, 'stale'), run(1, SHA_A, 30, 'failed')];
  const decision = await decideGrace({ sha: SHA_C, runs: old, observe, now: NOW });
  assert.equal(decision.verdict, 'fail');
  assert.equal(decision.staleSince, hoursAgo(30));
});

test('grace fails closed on a disabled workflow, a missing run and irreproducible writers', async () => {
  assert.match((await decideGrace({ sha: SHA_C, runs: [], observe, now: NOW })).reason, /has no trusted runs on main/);
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

test('grace: the refresh loop is broken, because a run on a refreshed main observes it current', async () => {
  // Before the idempotent writers every run found main stale (a new
  // generatedAt each time), so a day of merges read as one old staleness.
  const looping = [
    run(6, SHA_D, 0.5, 'stale'),
    run(5, SHA_C, 10, 'stale'),
    run(4, SHA_B, 20, 'stale'),
    run(3, SHA_A, 30, 'stale'),
  ];
  assert.equal((await decideGrace({ sha: SHA_D, runs: looping, observe, now: NOW })).verdict, 'fail');
  // With them, the run for the merged refresh pull request finds main
  // current, and the next staleness is dated from the push after it.
  const refreshed = [
    run(6, SHA_D, 0.5, 'stale'),
    run(5, SHA_C, 10, 'current'),
    run(4, SHA_B, 20, 'stale'),
    run(3, SHA_A, 30, 'stale'),
  ];
  const decision = await decideGrace({ sha: SHA_D, runs: refreshed, observe, now: NOW });
  assert.equal(decision.verdict, 'pass');
  assert.equal(decision.staleSince, hoursAgo(0.5));
});

test('only this repository\'s own main runs of push, schedule or dispatch can date staleness', () => {
  assert.ok(trustedRefreshRun(run(1, SHA_A, 1, 'current'), REPOSITORY));
  for (const [label, overrides] of [
    ['a fork pull request from a branch named main', { event: 'pull_request', head_repository: { full_name: 'attacker/emilia-protocol' } }],
    ['a pull_request event', { event: 'pull_request' }],
    ['a workflow_run event', { event: 'workflow_run' }],
    ['another repository', { head_repository: { full_name: 'attacker/emilia-protocol' } }],
    ['no head repository', { head_repository: null }],
    ['another branch', { head_branch: 'feature' }],
    ['a malformed id', { id: 'x' }],
  ]) {
    assert.ok(!trustedRefreshRun({ ...run(1, SHA_A, 1, 'current'), ...overrides }, REPOSITORY), label);
  }
});

test('the runs listing pages until a trusted run predates the window, filters untrusted runs, and reports truncation', async () => {
  const windowStart = NOW.getTime() - GRACE_HOURS * 3_600_000;
  const page = (n, hoursFrom, extra = {}) => Array.from({ length: n }, (_, i) => run(1000 - hoursFrom * 10 - i, SHA_A, hoursFrom + i * 0.01, 'stale', extra));
  const requested = [];
  const pages = {
    1: [...page(99, 1), run(5, SHA_B, 2, 'current', { event: 'pull_request', head_repository: { full_name: 'fork/x' } })],
    2: [...page(99, 10), run(4, SHA_B, 30, 'stale')],
  };
  const fetchImpl = async (url) => {
    requested.push(url);
    const n = Number(new URL(url).searchParams.get('page'));
    return Response.json({ workflow_runs: pages[n] ?? [] });
  };
  const listing = await githubClient({ token: 't', repository: REPOSITORY, fetchImpl }).refreshRuns({ windowStart });
  assert.equal(requested.length, 2);
  assert.ok(requested.every((url) => url.includes('/actions/workflows/volatile-evidence-refresh.yml/runs?branch=main&per_page=100&page=')));
  assert.equal(listing.truncated, false);
  assert.equal(listing.runs.length, 199);
  assert.ok(!listing.runs.some((r) => r.event === 'pull_request'), 'the fork run is dropped');

  const endless = async () => Response.json({ workflow_runs: page(100, 1) });
  const capped = await githubClient({ token: 't', repository: REPOSITORY, fetchImpl: endless }).refreshRuns({ windowStart });
  assert.equal(capped.truncated, true);
});

test('policy outcomes: advisory tolerates only test counts, strict fails, grace dates the drift, denial needs no API', async () => {
  const stale = ['lib/proof-stats.json'];
  const lag = await evaluatePolicy({ mode: 'advisory', stale, fields: ['tests.total'] });
  assert.equal(lag.exitCode, 0);
  assert.match(lag.annotation, /^::notice /);
  for (const mode of ['advisory', 'strict', 'grace']) {
    const noApi = { refreshRuns: async () => { throw new Error('denied drift must not need the API'); }, observe };
    const formal = await evaluatePolicy({ mode, stale, fields: ['formalEvidenceCoverage.verifiedFormalObligations.claimIds'], sha: SHA_C, client: noApi, now: NOW });
    assert.equal(formal.exitCode, 1, mode);
    assert.match(formal.annotation, /Evidence drift outside the test counts/, mode);
    const llm = await evaluatePolicy({ mode, stale: ['public/llms.txt'], fields: [], sha: SHA_C, client: noApi, now: NOW });
    assert.equal(llm.exitCode, 1, mode);
  }
  assert.equal((await evaluatePolicy({ mode: 'strict', stale, fields: ['tests.total'] })).exitCode, 1);
  assert.equal((await evaluatePolicy({ mode: 'grace', stale: [] })).exitCode, 0);
  const inFlight = await evaluatePolicy({
    mode: 'grace',
    stale,
    fields: ['tests.total'],
    sha: SHA_C,
    client: client([run(2, SHA_C, 0.2, 'unknown', { status: 'in_progress', conclusion: null }), run(1, SHA_B, 3, 'current')]),
    now: NOW,
  });
  assert.equal(inFlight.exitCode, 0);
  assert.match(inFlight.annotation, /^::warning /);
  const overdue = await evaluatePolicy({ mode: 'grace', stale, fields: ['tests.total'], sha: SHA_C, client: client([run(1, SHA_B, 40, 'stale')]), now: NOW });
  assert.equal(overdue.exitCode, 1);
  assert.match(overdue.annotation, /^::error /);
  // The refresh workflow's own regenerated list has no fields and only dates.
  const regenerated = await evaluatePolicy({
    mode: 'grace', stale: ['AI_CONTEXT.md', 'lib/proof-stats.json'], fields: null, regenerated: true, sha: SHA_C,
    client: client([run(2, SHA_C, 0.2, 'unknown', { status: 'in_progress', conclusion: null }), run(1, SHA_B, 3, 'current')]), now: NOW,
  });
  assert.equal(regenerated.exitCode, 0);
  await assert.rejects(evaluatePolicy({ mode: 'grace', stale, fields: ['tests.total'], client: client([]), now: NOW }), /--sha/);
  const refused = await evaluatePolicy({ mode: 'advisory', stale: [], problems: ['nope'] });
  assert.equal(refused.exitCode, 1);
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

const proofStatsText = (tests, generatedAt, extra = {}) => `${JSON.stringify({ generatedAt, tests, tamarin: { verifiedObligations: 20 }, ...extra }, null, 2)}\n`;
const TESTS = { total: 100, files: 10, policy: 'p' };

test('the policy CLI writes the job summary and dates main drift through the Actions API', async () => {
  const f = fixture();
  const dir = mkdtempSync(join(tmpdir(), 'volatile-policy-'));
  try {
    f.write('lib/code.ts', 'export const x = 1;\n');
    f.git('add', '-A');
    f.git('commit', '-q', '-m', 'pull request');
    const proof = join(dir, 'proof.json');
    const llm = join(dir, 'llm.json');
    const summary = join(dir, 'summary.md');
    writeFileSync(proof, JSON.stringify(report('sync:proof-stats', ['lib/proof-stats.json'], { fields: ['tests.total'] })));
    writeFileSync(llm, JSON.stringify(report('sync:llm-context', [])));
    const env = { GITHUB_STEP_SUMMARY: summary, GH_TOKEN: 'test-token' };
    const pr = ['--ref', 'refs/pull/9/merge', '--touched-base', 'HEAD^1', '--repo', f.repo];

    const noFetch = async () => { throw new Error('the pull request path must not call the API'); };
    const advisory = await main(
      ['policy', '--report', proof, '--report', llm, '--event', 'pull_request', '--head-ref', 'feat/x', ...pr],
      { env, fetchImpl: noFetch, now: NOW },
    );
    assert.equal(advisory, 0);
    const text = readFileSync(summary, 'utf8');
    assert.match(text, /\| `lib\/proof-stats\.json` \| stale \|/);
    assert.match(text, /\| `public\/llms\.txt` \| current \|/);
    assert.match(text, /Advisory: only the measured test counts lag/);
    assert.match(text, /`tests\.total`/);
    await assert.rejects(
      main(['policy', '--report', proof, '--report', llm, '--event', 'pull_request', '--head-ref', 'feat/x', '--ref', 'refs/pull/9/merge'],
        { env, fetchImpl: noFetch, now: NOW }),
      /--touched-base/,
    );

    // A formal field drifting fails the pull request, the merge group and main alike.
    writeFileSync(proof, JSON.stringify(report('sync:proof-stats', ['lib/proof-stats.json'], { fields: ['tamarin.verifiedObligations'] })));
    assert.equal(await main(['policy', '--report', proof, '--report', llm, '--event', 'pull_request', '--head-ref', 'feat/x', ...pr],
      { env, fetchImpl: noFetch, now: NOW }), 1);
    assert.equal(await main(['policy', '--report', proof, '--report', llm, '--event', 'merge_group', '--ref', 'refs/heads/gh-readonly-queue/main/pr-9'],
      { env, fetchImpl: noFetch, now: NOW }), 1);
    assert.equal(await main(['policy', '--report', proof, '--report', llm, '--event', 'push', '--ref', 'refs/heads/main', '--sha', SHA_C,
      '--repository', REPOSITORY], { env, fetchImpl: noFetch, now: NOW }), 1);
    assert.match(readFileSync(summary, 'utf8'), /never advisory/);
    writeFileSync(proof, JSON.stringify(report('sync:proof-stats', ['lib/proof-stats.json'], { fields: ['tests.total'] })));

    const requests = [];
    const fetchImpl = async (url, init) => {
      requests.push({ url, auth: init.headers.authorization });
      if (url.includes(`/actions/workflows/volatile-evidence-refresh.yml/runs?branch=main&per_page=100&page=1`)) {
        return Response.json({ workflow_runs: [
          { ...run(2, SHA_C, 0.5, 'unknown'), status: 'in_progress', conclusion: null },
          run(1, SHA_B, 4, 'current'),
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
    // --stale is the refresh workflow's own output and only valid on main.
    await assert.rejects(
      main(['policy', '--stale', '["public/llms.txt"]', '--event', 'merge_group', '--ref', 'refs/heads/gh-readonly-queue/main/pr-9'],
        { env, fetchImpl: noFetch, now: NOW }),
      /grace mode/,
    );
    const fromStale = await main(
      ['policy', '--stale', '["public/llms.txt","lib/proof-stats.json"]', '--event', 'schedule', '--ref', 'refs/heads/main',
        '--sha', SHA_C, '--repository', REPOSITORY],
      { env, fetchImpl, now: NOW },
    );
    assert.equal(fromStale, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    f.cleanup();
  }
});

test('the summary names the refresh workflow and says what stays strict', () => {
  const text = summaryMarkdown({ mode: 'advisory', stale: ['lib/proof-stats.json'], fields: ['tests.total'] });
  assert.match(text, /volatile-evidence-refresh\.yml/);
  assert.match(text, /every other proof field and the LLM context stay strict/);
  const denied = summaryMarkdown({ mode: 'advisory', stale: ['public/llms.txt'], fields: [], denied: [{ path: 'public/llms.txt', fields: [] }] });
  assert.match(denied, /never advisory/);
  assert.match(denied, /npm run sync:llm-context/);
});

test('the proof-stats writer is idempotent: an unchanged test count keeps its generatedAt and bytes', () => {
  const stats = (generatedAt, tests = TESTS) => ({ generatedAt, tests, tamarin: { verifiedObligations: 20 } });
  const first = proofStatsFileText(stats('2026-09-20T00:00:00.000Z'));
  assert.equal(first, proofStatsText(TESTS, '2026-09-20T00:00:00.000Z'));
  // Same counts (even with another derived field changed): timestamp kept.
  assert.equal(proofStatsFileText(stats('2026-09-26T00:00:00.000Z'), first), first);
  assert.match(
    proofStatsFileText({ ...stats('2026-09-26T00:00:00.000Z'), tamarin: { verifiedObligations: 21 } }, first),
    /"generatedAt": "2026-09-20T00:00:00\.000Z"[\s\S]*"verifiedObligations": 21/,
  );
  // New counts: a new timestamp.
  assert.match(proofStatsFileText(stats('2026-09-26T00:00:00.000Z', { ...TESTS, total: 101 }), first), /"generatedAt": "2026-09-26T00:00:00\.000Z"/);
  // A recorded timestamp that is malformed or later than this run is replaced.
  for (const bad of ['yesterday', '2026-09-20T00:00:00Z', '2026-09-27T00:00:00.000Z']) {
    assert.match(proofStatsFileText(stats('2026-09-26T00:00:00.000Z'), proofStatsText(TESTS, bad)), /"generatedAt": "2026-09-26T00:00:00\.000Z"/, bad);
  }
  assert.match(proofStatsFileText(stats('2026-09-26T00:00:00.000Z'), '{broken'), /"generatedAt": "2026-09-26T00:00:00\.000Z"/);
});

test('a no-op refresh on main collects nothing, so publish is skipped and the run observes main current', async () => {
  const committedStats = readFileSync(join(ROOT, 'lib/proof-stats.json'), 'utf8');
  const recorded = JSON.parse(committedStats);
  // The checked-in file is the writer's own output, so re-running the writer
  // with the same measurement reproduces it byte for byte.
  assert.equal(proofStatsFileText(recorded, committedStats), committedStats, 'lib/proof-stats.json is in the writer\'s format');
  const render = () => {
    const out = mkdtempSync(join(tmpdir(), 'volatile-llm-'));
    execFileSync(process.execPath, [join(ROOT, 'scripts/generate-llm-context.mjs'), '--write', '--out-dir', out], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const files = Object.fromEntries(VOLATILE_EVIDENCE.filter((path) => path !== 'lib/proof-stats.json')
      .map((path) => [path, readFileSync(join(out, path), 'utf8')]));
    rmSync(out, { recursive: true, force: true });
    return files;
  };
  const f = fixture();
  try {
    // Main after the last refresh landed: proof stats and the context rendered from them.
    const landed = render();
    f.write('lib/proof-stats.json', committedStats);
    for (const [path, text] of Object.entries(landed)) f.write(path, text);
    f.git('add', '-A');
    f.git('commit', '-q', '-m', 'refresh landed');
    const source = f.git('rev-parse', 'HEAD');

    // The next run: sync:proof-stats measures the same suite a minute later,
    // then sync:llm-context renders; the workflow checkpoints both.
    const later = new Date(Date.parse(recorded.generatedAt) + 60_000).toISOString();
    f.write('lib/proof-stats.json', proofStatsFileText({ ...recorded, generatedAt: later }, committedStats));
    for (const [path, text] of Object.entries(render())) f.write(path, text);
    f.git('commit', '-q', '--allow-empty', '-am', 'local checkpoint');
    const outputs = join(f.root, 'outputs');
    assert.equal(await main(['collect', '--repo', f.repo, '--source-sha', source, '--out', join(f.root, 'bundle'), '--github-output', outputs]), 0);
    assert.equal(readFileSync(outputs, 'utf8'), 'changed=false\nstale=[]\n');

    // The workflow skips publish and grace on changed=false, which is the
    // job pattern observationFromJobs reads as current.
    const { publish, grace } = workflow(REFRESH_WORKFLOW).jobs;
    assert.equal(publish.if, "needs.regenerate.outputs.changed == 'true'");
    assert.match(grace.if, /needs\.regenerate\.outputs\.changed == 'true'/);
    assert.equal(observationFromJobs([{ name: REGENERATE_JOB, conclusion: 'success' }, { name: PUBLISH_JOB, conclusion: 'skipped' }]), 'current');

    // Control: the old writer (a fresh generatedAt on every run) changes the
    // bytes and would publish a timestamp-only refresh after every run.
    f.write('lib/proof-stats.json', proofStatsFileText({ ...recorded, generatedAt: later }));
    f.git('commit', '-q', '-am', 'old writer');
    const loopOutputs = join(f.root, 'loop-outputs');
    await main(['collect', '--repo', f.repo, '--source-sha', source, '--out', join(f.root, 'loop-bundle'), '--github-output', loopOutputs]);
    assert.equal(readFileSync(loopOutputs, 'utf8'), 'changed=true\nstale=["lib/proof-stats.json"]\n');
  } finally {
    f.cleanup();
  }
});

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

test('main\'s refresh pull request fails on any changed path outside the five files, stale or not', async () => {
  const f = fixture();
  const dir = mkdtempSync(join(tmpdir(), 'volatile-strict-'));
  try {
    const proof = join(dir, 'proof.json');
    const llm = join(dir, 'llm.json');
    writeFileSync(proof, JSON.stringify(report('sync:proof-stats', [])));
    writeFileSync(llm, JSON.stringify(report('sync:llm-context', [])));
    const args = ['policy', '--report', proof, '--report', llm, '--event', 'pull_request', '--ref', 'refs/pull/7/merge',
      '--head-ref', refreshBranch(SHA_A), '--touched-base', 'HEAD^1', '--repo', f.repo];
    const env = {};

    f.write('public/llms.txt', 'v2\n');
    f.git('commit', '-q', '-am', 'refresh');
    assert.equal(await main(args, { env, now: NOW }), 0);
    assert.deepEqual(changedPaths('HEAD^1', f.repo), ['public/llms.txt']);

    // A later push that rides the refresh branch with another change.
    f.write('public/llms.txt', 'v3\n');
    f.write('lib/code.ts', 'export const x = 1;\n');
    f.write('security/security-case.json', '{"v":2}\n');
    f.git('add', '-A');
    f.git('commit', '-q', '-m', 'rider');
    assert.deepEqual(touchedVolatile('HEAD^1', f.repo), ['public/llms.txt']);
    assert.equal(await main(args, { env, now: NOW }), 1);
    const result = await evaluatePolicy({ mode: 'strict', stale: [], problems: ['x'] });
    assert.equal(result.exitCode, 1);
    assert.throws(() => changedPaths('--output=/tmp/x', f.repo), /refusing base revision/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    f.cleanup();
  }
});

test('a pull request may carry the base\'s test counts and generatedAt, or exact ones, and nothing else', async () => {
  const base = JSON.parse(proofStatsText(TESTS, hoursAgo(48)));
  const problems = (head, stale) => proofStatsChangeProblems({ head, base, stale, now: NOW });
  // Derived fields refreshed, counts and timestamp kept (bootstrap mode): fine, even while the counts lag.
  assert.deepEqual(problems({ ...base, tamarin: { verifiedObligations: 21 } }, true), []);
  // Exact new counts with a new timestamp: fine.
  assert.deepEqual(problems({ ...base, tests: { ...TESTS, total: 120 }, generatedAt: hoursAgo(1) }, false), []);
  // Counts the suite does not produce (a hand edit), whatever the timestamp.
  assert.match(problems({ ...base, tests: { ...TESTS, total: 99999 }, generatedAt: hoursAgo(1) }, true).join(' '), /neither what the suite measures/);
  // Unchanged counts with a moved timestamp.
  assert.match(problems({ ...base, generatedAt: hoursAgo(1) }, false).join(' '), /must stay/);
  // A timestamp in the future, earlier than the base's, or malformed.
  assert.match(problems({ ...base, tests: { ...TESTS, total: 120 }, generatedAt: new Date(NOW.getTime() + 3_600_000).toISOString() }, false).join(' '), /in the future/);
  assert.match(problems({ ...base, tests: { ...TESTS, total: 120 }, generatedAt: hoursAgo(72) }, false).join(' '), /earlier than the base/);
  assert.match(problems({ ...base, generatedAt: 'soon' }, false).join(' '), /not a canonical/);
  assert.match(problems(undefined, false).join(' '), /missing/);
  // Within the allowed clock skew.
  assert.deepEqual(problems({ ...base, tests: { ...TESTS, total: 120 }, generatedAt: new Date(NOW.getTime() + 5 * 60_000).toISOString() }, false), []);

  const f = fixture();
  const dir = mkdtempSync(join(tmpdir(), 'volatile-touched-'));
  try {
    f.write('lib/proof-stats.json', proofStatsText(TESTS, hoursAgo(48)));
    f.git('commit', '-q', '-am', 'main');
    const proof = join(dir, 'proof.json');
    const llm = join(dir, 'llm.json');
    writeFileSync(proof, JSON.stringify(report('sync:proof-stats', ['lib/proof-stats.json'], { fields: ['tests.total'] })));
    writeFileSync(llm, JSON.stringify(report('sync:llm-context', [])));
    const args = ['policy', '--report', proof, '--report', llm, '--ref', 'refs/pull/7/merge', '--head-ref', 'feat/x',
      '--touched-base', 'HEAD^1', '--repo', f.repo];
    const env = {};

    f.write('lib/proof-stats.json', proofStatsText(TESTS, hoursAgo(48), { redTeamCases: 87 }));
    f.write('lib/code.ts', 'export const x = 1;\n');
    f.git('add', '-A');
    f.git('commit', '-q', '-m', 'derived fields refreshed, counts kept');
    assert.deepEqual(touchedVolatile('HEAD^1', f.repo), ['lib/proof-stats.json']);
    assert.equal(await main([...args, '--event', 'pull_request'], { env, now: NOW }), 0);

    f.write('lib/proof-stats.json', proofStatsText({ ...TESTS, total: 99999 }, hoursAgo(1), { redTeamCases: 87 }));
    f.git('commit', '-q', '-am', 'hand-edited count');
    assert.equal(await main([...args, '--event', 'pull_request'], { env, now: NOW }), 1);
    // A merge-queue candidate may lag only because of pull requests queued
    // ahead of it; the pull_request run already held this one.
    assert.equal(await main([...args, '--event', 'merge_group'], { env, now: NOW }), 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    f.cleanup();
  }
});

function pullsApi({ pulls, commits, compare, extra = {} }) {
  const calls = [];
  return {
    calls,
    client: {
      openPullRequests: async () => pulls.map(({ detail }) => detail),
      pullRequest: async (number) => { calls.push(`pull ${number}`); return pulls.find(({ detail }) => detail.number === number).detail; },
      commit: async (sha) => { calls.push(`commit ${sha}`); return commits[sha]; },
      compare: async (base, head) => { calls.push(`compare ${base}...${head}`); return { status: compare[base] }; },
      ...extra,
    },
  };
}

const pullOn = (number, ref, headSha, overrides = {}) => ({
  detail: {
    number,
    state: 'open',
    node_id: `PR_${number}`,
    user: { login: BOT },
    commits: 1,
    head: { ref, sha: headSha, repo: { full_name: REPOSITORY } },
    ...overrides,
  },
});
const botCommit = (parent, overrides = {}) => ({ parents: [{ sha: parent }], author: { login: BOT }, ...overrides });

test('plan reuses the pull request on its own branch only when the App bot made it as one commit on the source', async () => {
  const branch = refreshBranch(SHA_C);
  const head = '1'.repeat(40);
  const ok = pullsApi({ pulls: [pullOn(10, branch, head)], commits: { [head]: botCommit(SHA_C) }, compare: {} });
  const plan = await planRefresh({ client: ok.client, repository: REPOSITORY, sourceSha: SHA_C, botLogin: BOT });
  assert.equal(plan.action, 'publish');
  assert.deepEqual(plan.reuse, { number: 10, nodeId: 'PR_10', headSha: head });
  assert.equal(plan.replace, null);

  for (const [label, pull, commit] of [
    ['opened by someone else', pullOn(10, branch, head, { user: { login: 'someone' } }), botCommit(SHA_C)],
    ['more than one commit', pullOn(10, branch, head, { commits: 2 }), botCommit(SHA_C)],
    ['a commit on another parent', pullOn(10, branch, head), botCommit(SHA_B)],
    ['a commit authored by someone else', pullOn(10, branch, head), botCommit(SHA_C, { author: { login: 'someone' } })],
    ['a merge commit', pullOn(10, branch, head), botCommit(SHA_C, { parents: [{ sha: SHA_C }, { sha: SHA_B }] })],
  ]) {
    const api = pullsApi({ pulls: [pull], commits: { [head]: commit }, compare: {} });
    const replaced = await planRefresh({ client: api.client, repository: REPOSITORY, sourceSha: SHA_C, botLogin: BOT });
    assert.equal(replaced.reuse, null, label);
    assert.deepEqual({ number: replaced.replace.number, ref: replaced.replace.ref }, { number: 10, ref: branch }, label);
    assert.equal(replaced.action, 'publish', label);
  }
  await assert.rejects(planRefresh({ client: ok.client, repository: REPOSITORY, sourceSha: SHA_C, botLogin: '' }), /bot login/);
  await assert.rejects(planRefresh({ client: ok.client, repository: REPOSITORY, sourceSha: SHA_C, botLogin: 'a b' }), /bot login/);
});

test('plan touches only well-formed same-repository refresh branches', async () => {
  const head = '2'.repeat(40);
  const api = pullsApi({
    pulls: [
      pullOn(20, `${REFRESH_BRANCH_PREFIX}foo`, head),
      pullOn(21, `${REFRESH_BRANCH_PREFIX}aaaaaaaaaaa%23`, head),
      pullOn(22, `${REFRESH_BRANCH_PREFIX}aaaaaaaaaaaa#x`, head),
      pullOn(23, refreshBranch(SHA_A), head, { head: { ref: refreshBranch(SHA_A), sha: head, repo: { full_name: 'fork/emilia-protocol' } } }),
      pullOn(24, 'feature/x', head),
    ],
    commits: { [head]: botCommit(SHA_A) },
    compare: { [SHA_A]: 'ahead' },
  });
  const plan = await planRefresh({ client: api.client, repository: REPOSITORY, sourceSha: SHA_C, botLogin: BOT });
  assert.deepEqual(plan.supersede, []);
  assert.deepEqual(plan.ignored, []);
  assert.deepEqual(api.calls, [], 'no detail, commit or compare request for a branch outside the pattern');
});

test('plan closes only refresh pull requests whose source is an ancestor, and stands down for a newer one', async () => {
  const heads = { older: '3'.repeat(40), same: '4'.repeat(40), newer: '5'.repeat(40), diverged: '6'.repeat(40), forged: '7'.repeat(40) };
  const base = {
    commits: {
      [heads.older]: botCommit(SHA_A),
      [heads.same]: botCommit(SHA_C),
      [heads.newer]: botCommit(SHA_D),
      [heads.diverged]: botCommit(SHA_B),
      [heads.forged]: botCommit(SHA_D, { author: { login: 'someone' } }),
    },
    compare: { [SHA_A]: 'ahead', [SHA_C]: 'identical', [SHA_D]: 'behind', [SHA_B]: 'diverged' },
  };
  const plan = await planRefresh({
    client: pullsApi({
      ...base,
      pulls: [
        pullOn(30, refreshBranch(SHA_A), heads.older),
        pullOn(31, `${REFRESH_BRANCH_PREFIX}cccccccccccd`, heads.same),
        pullOn(32, refreshBranch(SHA_B), heads.diverged),
        pullOn(33, `${REFRESH_BRANCH_PREFIX}eeeeeeeeeeee`, heads.forged, { user: { login: 'someone' } }),
      ],
    }).client,
    repository: REPOSITORY,
    sourceSha: SHA_C,
    botLogin: BOT,
  });
  assert.equal(plan.action, 'publish');
  assert.deepEqual(plan.supersede, [{ number: 30, ref: refreshBranch(SHA_A) }, { number: 31, ref: `${REFRESH_BRANCH_PREFIX}cccccccccccd` }]);
  assert.deepEqual(plan.ignored.map(({ number }) => number), [32, 33], 'diverged and a newer source the bot did not make are left alone');

  // A re-run of an old refresh run (source SHA_C) while the bot's refresh for
  // SHA_D is open publishes nothing and closes nothing.
  const rerun = await planRefresh({
    client: pullsApi({ ...base, pulls: [pullOn(34, refreshBranch(SHA_D), heads.newer), pullOn(30, refreshBranch(SHA_A), heads.older)] }).client,
    repository: REPOSITORY,
    sourceSha: SHA_C,
    botLogin: BOT,
  });
  assert.equal(rerun.action, 'skip');
  assert.deepEqual(rerun.newer, { number: 34, ref: refreshBranch(SHA_D), source: SHA_D });
});

test('the plan CLI and client validate every REST path segment and write the step outputs', async () => {
  const bad = githubClient({ token: 't', repository: REPOSITORY, fetchImpl: async () => { throw new Error('no request expected'); } });
  await assert.rejects(bad.pullRequest('1/../../x'), /refusing pull request/);
  await assert.rejects(bad.commit('main'), /refusing commit/);
  await assert.rejects(bad.compare(SHA_A, 'HEAD'), /refusing commit/);
  await assert.rejects(bad.observe({ id: '1?x' }), /refusing run id/);
  assert.throws(() => githubClient({ token: 't', repository: 'a/b/c' }), /refusing repository/);

  const head = '8'.repeat(40);
  const older = '9'.repeat(40);
  const responses = {
    '/pulls?state=open&base=main&per_page=100&page=1': [
      pullOn(40, refreshBranch(SHA_C), head).detail,
      pullOn(41, refreshBranch(SHA_A), older).detail,
    ],
    '/pulls/40': pullOn(40, refreshBranch(SHA_C), head).detail,
    '/pulls/41': pullOn(41, refreshBranch(SHA_A), older).detail,
    [`/commits/${head}`]: botCommit(SHA_C),
    [`/commits/${older}`]: botCommit(SHA_A),
    [`/compare/${SHA_A}...${SHA_C}`]: { status: 'ahead' },
  };
  const fetchImpl = async (url) => {
    const path = url.slice(`https://api.github.com/repos/${REPOSITORY}`.length);
    return path in responses ? Response.json(responses[path]) : new Response('not found', { status: 404 });
  };
  const dir = mkdtempSync(join(tmpdir(), 'volatile-plan-'));
  try {
    const outputs = join(dir, 'outputs');
    assert.equal(await main(['plan', '--source-sha', SHA_C, '--repository', REPOSITORY, '--bot-login', BOT, '--github-output', outputs],
      { env: { GH_TOKEN: 'app-token' }, fetchImpl }), 0);
    assert.equal(readFileSync(outputs, 'utf8'), [
      'action=publish',
      `branch=${refreshBranch(SHA_C)}`,
      'reuse=40',
      'reuse_node_id=PR_40',
      `reuse_head=${head}`,
      'replace=',
      `supersede=41:${refreshBranch(SHA_A)}`,
      '',
    ].join('\n'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the refresh workflow keeps the App key away from the writers and plans before it writes', () => {
  const refresh = workflow(REFRESH_WORKFLOW);
  assert.deepEqual(Object.keys(refresh.on).sort(), ['push', 'schedule', 'workflow_dispatch']);
  assert.deepEqual(refresh.on.push.branches, ['main']);
  assert.deepEqual(refresh.on.schedule, [{ cron: '41 4,16 * * *' }]);
  assert.deepEqual(refresh.permissions, { contents: 'read' });
  assert.equal(refresh.concurrency['cancel-in-progress'], false);

  const { regenerate, publish, grace } = refresh.jobs;
  // volatile-evidence.mjs dates staleness from these job names.
  assert.equal(regenerate.name, REGENERATE_JOB);
  assert.equal(publish.name, PUBLISH_JOB);
  assert.match(regenerate.if, /github\.ref == 'refs\/heads\/main'/);

  // The job that runs the writers, npm and the suite holds no secret and no
  // write permission.
  assert.deepEqual(regenerate.permissions, { contents: 'read' });
  assert.equal(regenerate.environment, undefined);
  assert.ok(!JSON.stringify(regenerate).includes('secrets.'));
  assert.ok(JSON.stringify(regenerate).includes('volatile-evidence.mjs collect'));

  // Only the publisher enters the main-only environment, and it installs and
  // runs nothing but main's own tooling.
  assert.equal(publish.environment, 'evidence-autopilot');
  assert.deepEqual(publish.needs, 'regenerate');
  assert.equal(publish.if, "needs.regenerate.outputs.changed == 'true'");
  assert.deepEqual(publish.permissions, { contents: 'read' });
  const publishText = JSON.stringify(publish);
  assert.ok(!/npm (ci|install|run)/.test(publishText));
  const checkout = publish.steps.find((step) => String(step.uses).startsWith('actions/checkout@'));
  assert.equal(checkout.with.ref, '${{ github.sha }}');
  assert.equal(checkout.with.path, 'trusted');
  const appToken = publish.steps.find((step) => String(step.uses).startsWith('actions/create-github-app-token@'));
  assert.equal(appToken.with['permission-contents'], 'write');
  assert.equal(appToken.with['permission-pull-requests'], 'write', 'the publisher cannot create a PR with the App\'s current Contents-only grant');
  assert.ok(publishText.includes('node trusted/scripts/ci/volatile-evidence.mjs request'));

  // The plan runs with trusted code before any write, pinned to the bot login.
  const names = publish.steps.map((step) => step.name);
  const planIndex = names.indexOf('Plan against the open refresh pull requests with trusted code');
  const writeIndex = names.indexOf('Open the refresh pull request, enable auto-merge, close superseded ones');
  assert.ok(planIndex > 0 && writeIndex > planIndex);
  const plan = publish.steps[planIndex];
  assert.match(plan.run, /node trusted\/scripts\/ci\/volatile-evidence\.mjs plan/);
  assert.equal(plan.env.BOT_LOGIN, '${{ vars.EVIDENCE_AUTOPILOT_BOT_LOGIN }}');
  const writer = publish.steps[writeIndex];
  for (const name of ['ACTION', 'REUSE', 'REUSE_NODE_ID', 'REUSE_HEAD', 'REPLACE', 'SUPERSEDE']) {
    assert.equal(writer.env[name], `\${{ steps.plan.outputs.${name.toLowerCase()} }}`, name);
  }
  assert.ok(writer.run.includes('createCommitOnBranch') || writer.run.includes('create-commit.json'));
  assert.match(writer.run, /enablePullRequestAutoMerge\(input: \{ pullRequestId: \$id, expectedHeadOid: \$head \}\)/);
  assert.ok(writer.run.includes("refresh_ref='^automation/volatile-evidence-[0-9a-f]{12}$'"));
  assert.match(writer.run, /\[\[ "\$ACTION" == skip \]\][\s\S]*exit 0/);
  // Every close and delete goes through the validating helper.
  const closes = writer.run.split('\n').filter((line) => /-X (PATCH|DELETE)/.test(line));
  assert.ok(closes.every((line) => /\$number|\$ref|\$BRANCH/.test(line)), closes.join('\n'));
  assert.ok(!/startswith\(/.test(writer.run), 'no prefix-only branch selection remains');

  assert.equal(grace.environment, undefined);
  assert.ok(!JSON.stringify(grace).includes('secrets.'));
  assert.deepEqual(grace.permissions, { contents: 'read', actions: 'read' });
  assert.ok(JSON.stringify(grace).includes('volatile-evidence.mjs policy'));
});

test('ci.yml reports volatile drift and applies the policy with the merge base', () => {
  const job = workflow('ci.yml').jobs['language-governance-checks'];
  const runs = job.steps.map((step) => step.run ?? '').join('\n');
  assert.match(runs, /npm run check:proof-stats --\s+--security-case-preverified\s+--drift-report "\$RUNNER_TEMP\/proof-stats-drift\.json"/);
  assert.match(runs, /npm run check:llm-context -- --drift-report "\$RUNNER_TEMP\/llm-context-drift\.json"/);
  assert.match(runs, /node scripts\/ci\/volatile-evidence\.mjs policy[\s\S]*--touched-base HEAD\^1[\s\S]*--sha "\$GITHUB_SHA"/);
  assert.ok(!/npm run check:(proof-stats|llm-context)\s*$/m.test(runs), 'no strict volatile check remains');
  assert.deepEqual(job.permissions, { contents: 'read', actions: 'read' });
  assert.equal(job.steps[0].with['fetch-depth'], 2);

  // The strict derived evidence keeps its strict checks.
  const security = workflow('ci.yml').jobs['security-case'].steps.map((step) => step.run ?? '').join('\n');
  for (const command of ['check:security-case', 'check:formal-traces', 'conformance:manifest:check', 'conformance:manifest:clean-room', 'check:standalone-runtimes']) {
    assert.match(security, new RegExp(`npm run ${command}$`, 'm'), command);
  }
});

test('the writers fail drift outside the test counts even with --drift-report', () => {
  const proofStats = readFileSync(join(ROOT, 'scripts/generate-proof-stats.mts'), 'utf8');
  assert.match(proofStats, /const denied: string\[\] = fields\.filter\(\s*\(field\) => !ADVISORY_PROOF_STATS_FIELDS\.includes\(field\),?\s*\);/);
  assert.match(proofStats, /const lagOnly: boolean = Boolean\(driftReport\) && denied\.length === 0;/);
  const llm = readFileSync(join(ROOT, 'scripts/generate-llm-context.mts'), 'utf8');
  assert.match(llm, /console\.error\(`LLM CONTEXT: FAIL - stale generated artifact\(s\): \$\{stale\.join\(', '\)\}`\);\n\s*console\.error\('Fix: npm run sync:llm-context, then commit the four artifacts\.'\);\n\s*process\.exit\(1\);/);
});

test('dco.yml exempts every volatile file for the autopilot commit, and the PR autopilot never measures the suite', () => {
  const dco = readFileSync(join(ROOT, '.github/workflows/dco.yml'), 'utf8');
  for (const path of VOLATILE_EVIDENCE) assert.ok(dco.includes(`-e '${path}'`), path);
  const autopilot = readFileSync(join(ROOT, '.github/workflows/evidence-autopilot.yml'), 'utf8');
  // It refreshes the derived proof fields and the LLM context, keeping the
  // base's test counts, and never runs the measured writer.
  assert.ok(autopilot.includes('npm run sync:proof-stats -- --bootstrap-derived-evidence'));
  assert.ok(!/npm run sync:proof-stats\s*$/m.test(autopilot), 'no measured proof-stats run');
  assert.ok(autopilot.includes('npm run sync:llm-context'));
  assert.ok(autopilot.includes('npm run check:llm-context'));
});
