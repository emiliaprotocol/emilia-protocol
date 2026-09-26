#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Volatile evidence: policy and main-branch refresh tooling.
 *
 * Five derived files change on almost every merge: lib/proof-stats.json
 * (exact test counts) and the four LLM context artifacts rendered from it.
 * Requiring every pull request to carry them made each merge conflict every
 * other open pull request and forced a ~25 minute regeneration plus a full CI
 * re-run. Main now owns them:
 *
 *   - On pull_request and merge_group, `policy` reports their drift in the job
 *     summary and does not fail on it. The checks that produce the drift
 *     reports (check:proof-stats and check:llm-context with --drift-report)
 *     still fail on everything else they verify: a failing measured suite, the
 *     security case, formal and conformance evidence, and every generator
 *     assertion. Two cases stay strict, because a pull request that writes
 *     these files must write what the writers produce (hand-edited public
 *     evidence must not merge): a pull request that changes one of the files
 *     fails if that file is stale (--touched-base), and main's own refresh
 *     pull request (head branch REFRESH_BRANCH_PREFIX...) fails on any stale
 *     file, so auto-merge lands only content CI re-derived itself.
 *   - .github/workflows/volatile-evidence-refresh.yml runs on every push to
 *     main and daily. It regenerates the five files with the official writers
 *     in an unprivileged job, and a privileged job publishes them as ONE open
 *     pull request (REFRESH_TITLE) through the evidence autopilot App, with a
 *     compare-and-swap createCommitOnBranch commit that dco.yml exempts from
 *     sign-off only on GitHub's own evidence, and enables auto-merge.
 *   - On main (push, schedule, manual), `policy` fails once the files have
 *     been stale for more than GRACE_HOURS, one scheduled refresh cycle. The
 *     clock starts at the first refresh run created after the latest run that
 *     found main current, so staleness cannot persist silently when the App is
 *     unprovisioned, the refresh pull request is stuck, or the workflow is off.
 *
 * Usage:
 *   node scripts/ci/volatile-evidence.mjs policy --event <name> --ref <ref>
 *     (--report <drift.json> --report <drift.json> | --stale <json array>)
 *     [--head-ref <branch>] [--touched-base <rev>] [--sha <commit>] [--repository <owner/name>]
 *   node scripts/ci/volatile-evidence.mjs collect --source-sha <sha> --out <dir> [--github-output <file>]
 *   node scripts/ci/volatile-evidence.mjs request --bundle <dir> --source-sha <sha> \
 *     --repository <owner/name> --run-url <url> --out <file> [--pr-body-out <file>] [--github-output <file>]
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { COMMIT_TRAILER, DERIVED_EVIDENCE, collect, commitRequest } from './evidence-autopilot.mjs';

/** Written by sync:proof-stats and sync:llm-context; a subset of DERIVED_EVIDENCE. */
export const VOLATILE_EVIDENCE = Object.freeze([
  'lib/proof-stats.json',
  'AI_CONTEXT.md',
  'public/llms.txt',
  'public/llms-full.txt',
  'public/.well-known/emilia-context.json',
]);
if (!VOLATILE_EVIDENCE.every((path) => DERIVED_EVIDENCE.includes(path))) {
  throw new Error('volatile evidence must stay inside the derived-evidence allowlist dco.yml exempts');
}

export const DRIFT_REPORT_VERSION = 'EP-VOLATILE-EVIDENCE-DRIFT-v1';
export const DRIFT_WRITERS = Object.freeze(['sync:proof-stats', 'sync:llm-context']);
export const REFRESH_WORKFLOW = 'volatile-evidence-refresh.yml';
export const REFRESH_BRANCH_PREFIX = 'automation/volatile-evidence-';
export const REFRESH_TITLE = 'chore(evidence): refresh volatile evidence';
export const REGENERATE_JOB = 'regenerate';
export const PUBLISH_JOB = 'publish';
/** One scheduled refresh cycle: the workflow runs daily even without pushes. */
export const GRACE_HOURS = 24;

const SHA = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const HOUR_MS = 60 * 60 * 1000;

/**
 * @typedef {{ '@version': string, writer: string, current: boolean, stale: string[], fields?: string[] }} DriftReport
 * @typedef {{ id: number, created_at: string, status: string, conclusion: string | null, head_sha: string, event: string, html_url?: string }} RefreshRun
 * @typedef {'current' | 'stale' | 'unknown'} Observation
 * @typedef {{ verdict: 'pass' | 'fail', staleSince: string | null, ageHours: number | null, reason: string }} GraceDecision
 */

/**
 * @param {unknown} paths
 * @returns {string[]}
 */
function staleList(paths) {
  if (!Array.isArray(paths)) throw new Error('stale must be an array of paths');
  const unknown = paths.filter((path) => !VOLATILE_EVIDENCE.includes(path));
  if (unknown.length > 0) throw new Error(`not volatile evidence: ${unknown.join(', ')}`);
  return [...new Set(paths)].sort();
}

/**
 * Validates the drift reports the two checks wrote and merges their stale
 * paths. Exactly one report per writer is required, so a check that never
 * reached its comparison cannot read as current.
 *
 * @param {DriftReport[]} reports
 * @returns {{ stale: string[], fields: string[] }}
 */
export function mergeDriftReports(reports) {
  const writers = reports.map((report) => report?.writer).sort();
  if (JSON.stringify(writers) !== JSON.stringify([...DRIFT_WRITERS].sort())) {
    throw new Error(`expected one drift report from each of ${DRIFT_WRITERS.join(' and ')}, got ${JSON.stringify(writers)}`);
  }
  const stale = [];
  const fields = [];
  for (const report of reports) {
    if (report['@version'] !== DRIFT_REPORT_VERSION) throw new Error(`${report.writer}: unsupported drift report version`);
    if (typeof report.current !== 'boolean') throw new Error(`${report.writer}: current must be a boolean`);
    const paths = staleList(report.stale);
    if (report.current !== (paths.length === 0)) throw new Error(`${report.writer}: current contradicts stale`);
    stale.push(...paths);
    if (Array.isArray(report.fields)) fields.push(...report.fields.filter((field) => typeof field === 'string'));
  }
  return { stale: [...new Set(stale)].sort(), fields: [...new Set(fields)].sort() };
}

/**
 * The volatile files a pull request changes: `git diff base..HEAD` limited to
 * VOLATILE_EVIDENCE. On a pull_request run HEAD is GitHub's merge commit and
 * its first parent (HEAD^1) is the base.
 *
 * @param {string} base
 * @param {string} [repo]
 * @returns {string[]}
 */
export function touchedVolatile(base, repo = process.cwd()) {
  if (!/^[A-Za-z0-9][A-Za-z0-9^~._/-]*$/.test(base)) throw new Error(`refusing base revision ${JSON.stringify(base)}`);
  const output = execFileSync(
    'git',
    ['diff', '--name-only', '-z', '--no-renames', base, 'HEAD', '--', ...VOLATILE_EVIDENCE],
    { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return staleList(output.split('\0').filter(Boolean));
}

/**
 * How a run treats drift in the five files.
 *   strict   main's refresh pull request: stale fails.
 *   advisory any other pull request (except a stale file it changes itself),
 *            merge-queue candidates, other refs.
 *   grace    main: stale fails after GRACE_HOURS.
 *
 * @param {{ event: string, ref: string, headRef?: string }} run
 * @returns {'strict' | 'advisory' | 'grace'}
 */
export function policyMode({ event, ref, headRef = '' }) {
  if (event === 'pull_request' && headRef.startsWith(REFRESH_BRANCH_PREFIX)) return 'strict';
  if (event === 'pull_request' || event === 'merge_group') return 'advisory';
  if (ref !== 'refs/heads/main') return 'advisory';
  if (!['push', 'schedule', 'workflow_dispatch'].includes(event)) return 'advisory';
  return 'grace';
}

/**
 * What a completed refresh run established about its head commit, from its
 * job conclusions: regenerate succeeded and publish was skipped means the
 * writers reproduced the checked-in files byte for byte.
 *
 * @param {Array<{ name: string, conclusion: string | null }>} jobs
 * @returns {Observation}
 */
export function observationFromJobs(jobs) {
  const conclusion = (name) => jobs.find((job) => job.name === name)?.conclusion ?? null;
  if (conclusion(REGENERATE_JOB) !== 'success') return 'unknown';
  if (conclusion(PUBLISH_JOB) === 'skipped') return 'current';
  if (conclusion(PUBLISH_JOB)) return 'stale';
  return 'unknown';
}

/**
 * Decides whether stale volatile evidence at `sha` is still inside the grace
 * window. `runs` are the refresh workflow's runs on main; `observe` returns
 * the Observation for a completed, successful run.
 *
 * @param {{ sha: string, runs: RefreshRun[], observe: (run: RefreshRun) => Promise<Observation>,
 *   now: Date, graceHours?: number }} input
 * @returns {Promise<GraceDecision>}
 */
export async function decideGrace({ sha, runs, observe, now, graceHours = GRACE_HOURS }) {
  const ordered = [...runs].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id);
  if (ordered.length === 0) {
    return {
      verdict: 'fail',
      staleSince: null,
      ageHours: null,
      reason: `${REFRESH_WORKFLOW} has no runs on main, so nothing will refresh this evidence; enable the workflow`,
    };
  }
  let lastCurrent = -1;
  for (const [index, run] of ordered.entries()) {
    if (run.status !== 'completed' || run.conclusion !== 'success') continue;
    const observation = await observe(run);
    if (observation !== 'current') continue;
    if (run.head_sha === sha) {
      return {
        verdict: 'fail',
        staleSince: null,
        ageHours: null,
        reason: `refresh run ${run.id} regenerated ${sha} and found it current, but this check finds it stale: the writers are not reproducible`,
      };
    }
    lastCurrent = index;
    break;
  }
  if (lastCurrent === 0) {
    return {
      verdict: 'fail',
      staleSince: null,
      ageHours: null,
      reason: `no ${REFRESH_WORKFLOW} run exists for any commit after run ${ordered[0].id} found main current; the workflow did not start for later pushes`,
    };
  }
  // The earliest run created after the last current observation marks the
  // first push that could have made the evidence stale. Without any current
  // observation in the window, the oldest run is a lower bound.
  const clock = lastCurrent === -1 ? ordered[ordered.length - 1] : ordered[lastCurrent - 1];
  const ageHours = (now.getTime() - Date.parse(clock.created_at)) / HOUR_MS;
  const since = `stale since ${clock.created_at} (${ageHours.toFixed(1)} h; grace ${graceHours} h)`;
  if (ageHours > graceHours) {
    return {
      verdict: 'fail',
      staleSince: clock.created_at,
      ageHours,
      reason: `${since}: no refresh landed within one scheduled refresh cycle`,
    };
  }
  return { verdict: 'pass', staleSince: clock.created_at, ageHours, reason: `${since}: a refresh is in flight` };
}

/**
 * Minimal GitHub REST client over fetch. Any API failure throws: on main the
 * policy fails closed rather than passing stale evidence it cannot date.
 *
 * @param {{ token: string, repository: string, apiUrl?: string, fetchImpl?: typeof fetch }} options
 */
export function githubClient({ token, repository, apiUrl = 'https://api.github.com', fetchImpl = fetch }) {
  if (!token) throw new Error('GH_TOKEN (or GITHUB_TOKEN) is required to date stale evidence on main');
  if (!REPOSITORY.test(repository)) throw new Error(`refusing repository ${JSON.stringify(repository)}`);
  const get = async (path) => {
    const response = await fetchImpl(`${apiUrl}/repos/${repository}${path}`, {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28',
      },
    });
    if (!response.ok) throw new Error(`GitHub API ${path} answered ${response.status}`);
    return response.json();
  };
  return {
    /** @returns {Promise<RefreshRun[]>} */
    async refreshRuns() {
      const body = await get(`/actions/workflows/${REFRESH_WORKFLOW}/runs?branch=main&per_page=50`);
      return body.workflow_runs ?? [];
    },
    /** @param {RefreshRun} run @returns {Promise<Observation>} */
    async observe(run) {
      const body = await get(`/actions/runs/${run.id}/jobs?filter=latest&per_page=100`);
      return observationFromJobs(body.jobs ?? []);
    },
  };
}

/**
 * @param {{ mode: string, stale: string[], fields: string[], touched?: string[], decision?: GraceDecision }} input
 * @returns {string}
 */
export function summaryMarkdown({ mode, stale, fields, touched = [], decision }) {
  const lines = ['### Volatile evidence', ''];
  lines.push('| File | State |', '| --- | --- |');
  for (const path of VOLATILE_EVIDENCE) {
    const state = stale.includes(path) ? 'stale' : 'current';
    lines.push(`| \`${path}\` | ${state}${touched.includes(path) ? ' (changed by this pull request)' : ''} |`);
  }
  lines.push('');
  if (fields.length > 0) lines.push(`Changed \`lib/proof-stats.json\` fields: ${fields.map((field) => `\`${field}\``).join(', ')}.`, '');
  if (stale.length === 0) {
    lines.push('All five files match what the official writers produce for this commit.');
  } else if (mode === 'advisory' && stale.some((path) => touched.includes(path))) {
    lines.push(
      'Failing: this pull request changes a volatile file to something the writers do not produce.',
      'Drop that change (main regenerates these files after merge) or regenerate it exactly',
      '(`npm run sync:proof-stats`, then `npm run sync:llm-context`).',
    );
  } else if (mode === 'advisory') {
    lines.push(
      'Advisory only; this never fails the check. Main regenerates these files after merge',
      `(\`.github/workflows/${REFRESH_WORKFLOW}\`), so do not commit them unless the change adds`,
      'or removes a security claim (see CONTRIBUTING.md).',
    );
  } else if (mode === 'strict') {
    lines.push('This is main\'s refresh pull request, so stale content fails: it must equal what CI regenerates.');
  } else if (decision) {
    lines.push(`${decision.verdict === 'pass' ? 'Within grace' : 'Failing'}: ${decision.reason}.`);
  }
  return `${lines.join('\n')}\n`;
}

/**
 * `touched` lists the volatile files the pull request itself changes; in
 * advisory mode a stale one of those fails.
 *
 * @param {{ mode: 'strict' | 'advisory' | 'grace', stale: string[], touched?: string[], sha?: string,
 *   client?: ReturnType<typeof githubClient>, now?: Date }} input
 * @returns {Promise<{ exitCode: number, decision?: GraceDecision, annotation: string }>}
 */
export async function evaluatePolicy({ mode, stale, touched = [], sha, client, now = new Date() }) {
  if (stale.length === 0) return { exitCode: 0, annotation: '' };
  const files = stale.join(', ');
  const wrong = stale.filter((path) => touched.includes(path));
  if (mode === 'advisory' && wrong.length > 0) {
    return {
      exitCode: 1,
      annotation: `::error title=Changed volatile evidence is not current::This pull request changes ${wrong.join(', ')}, but not to what the writers produce for the merge commit. Drop the change (main regenerates these files) or regenerate it exactly.`,
    };
  }
  if (mode === 'advisory') {
    return { exitCode: 0, annotation: `::notice title=Volatile evidence drift (advisory)::${files} differ from the writers' output; main refreshes them after merge.` };
  }
  if (mode === 'strict') {
    return { exitCode: 1, annotation: `::error title=Refresh pull request is stale::${files} differ from what CI regenerates for this merge commit.` };
  }
  if (!sha || !SHA.test(sha)) throw new Error('grace mode needs the checked commit (--sha)');
  if (!client) throw new Error('grace mode needs a GitHub client');
  const decision = await decideGrace({ sha, runs: await client.refreshRuns(), observe: client.observe, now });
  if (decision.verdict === 'pass') {
    return { exitCode: 0, decision, annotation: `::warning title=Volatile evidence is stale on main::${files}; ${decision.reason}.` };
  }
  return { exitCode: 1, decision, annotation: `::error title=Volatile evidence is stale on main::${files}; ${decision.reason}.` };
}

/**
 * The commit message of a volatile refresh commit. It carries COMMIT_TRAILER,
 * which dco.yml requires for the evidence autopilot exemption.
 *
 * @param {string} sourceSha
 * @param {string} runUrl
 * @returns {{ headline: string, body: string }}
 */
export function refreshCommitMessage(sourceSha, runUrl) {
  return {
    headline: REFRESH_TITLE,
    body: [
      `Regenerated from main at ${sourceSha} by ${REFRESH_WORKFLOW} with the`,
      'official writers (sync:proof-stats, then sync:llm-context). Only the',
      'five volatile evidence files change. The publisher checked the bundle\'s',
      'shape and transit integrity; the required checks on this commit, which',
      'fail a stale file on this pull request, decide whether it is correct.',
      '',
      COMMIT_TRAILER,
      `Evidence-Autopilot-Run: ${runUrl}`,
      '',
    ].join('\n'),
  };
}

/**
 * The refresh pull request's description. It interpolates only the source
 * commit, the run URL and allowlisted paths, never bundle content.
 *
 * @param {{ sourceSha: string, runUrl: string, paths: string[] }} input
 * @returns {string}
 */
export function refreshPullRequestBody({ sourceSha, runUrl, paths }) {
  return [
    `Automated refresh from \`.github/workflows/${REFRESH_WORKFLOW}\` ([run](${runUrl})).`,
    '',
    `Regenerates the volatile evidence from main at ${sourceSha} with the official writers`,
    '(`sync:proof-stats`, then `sync:llm-context`):',
    '',
    ...staleList(paths).map((path) => `- \`${path}\``),
    '',
    'Nothing else changes. The single commit is created by the evidence autopilot App through',
    '`createCommitOnBranch`, so GitHub signs it and `dco.yml` exempts it on that evidence. Unlike',
    'other pull requests, this one fails CI when a volatile file is stale, so auto-merge lands only',
    'content the required checks re-derived for the merge commit.',
    '',
    'The next refresh that finds main stale opens a newer pull request and closes this one. Closing',
    'it by hand is harmless; the next refresh run opens a new one.',
    '',
  ].join('\n');
}

/**
 * @param {string} sourceSha
 * @returns {string}
 */
export function refreshBranch(sourceSha) {
  if (!SHA.test(sourceSha)) throw new Error('source sha must be a 40-character lowercase hex commit');
  return `${REFRESH_BRANCH_PREFIX}${sourceSha.slice(0, 12)}`;
}

/**
 * @param {string[]} argv
 * @returns {Record<string, string[]>}
 */
function parseOptions(argv) {
  /** @type {Record<string, string[]>} */
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`expected --option value pairs, got ${JSON.stringify(argv)}`);
    }
    (options[key.slice(2)] ??= []).push(value);
  }
  return options;
}

/**
 * @param {Record<string, string[]>} options
 * @param {string} name
 * @returns {string}
 */
function one(options, name) {
  const values = options[name] ?? [];
  if (values.length > 1) throw new Error(`--${name} may be given once`);
  return values[0] ?? '';
}

/**
 * @param {string[]} argv
 * @param {{ env?: NodeJS.ProcessEnv, fetchImpl?: typeof fetch, now?: Date }} [context]
 * @returns {Promise<number>} exit code
 */
export async function main(argv, { env = process.env, fetchImpl = fetch, now = new Date() } = {}) {
  const [command, ...rest] = argv;
  const options = parseOptions(rest);
  const output = one(options, 'github-output');
  if (command === 'policy') {
    const reports = options.report ?? [];
    const staleJson = one(options, 'stale');
    if ((reports.length > 0) === Boolean(staleJson)) throw new Error('policy takes --report files or --stale, not both');
    const merged = reports.length > 0
      ? mergeDriftReports(reports.map((file) => JSON.parse(readFileSync(file, 'utf8'))))
      : { stale: staleList(JSON.parse(staleJson)), fields: [] };
    const event = one(options, 'event');
    const mode = policyMode({ event, ref: one(options, 'ref'), headRef: one(options, 'head-ref') });
    const touchedBase = one(options, 'touched-base');
    // Only a pull request's own changes count; a merge-queue candidate may be
    // stale only because of the pull requests queued ahead of it.
    const touched = mode === 'advisory' && event === 'pull_request' && touchedBase
      ? touchedVolatile(touchedBase, one(options, 'repo') || process.cwd())
      : [];
    const client = mode === 'grace' && merged.stale.length > 0
      ? githubClient({
        token: env.GH_TOKEN || env.GITHUB_TOKEN || '',
        repository: one(options, 'repository'),
        apiUrl: env.GITHUB_API_URL || undefined,
        fetchImpl,
      })
      : undefined;
    const result = await evaluatePolicy({ mode, stale: merged.stale, touched, sha: one(options, 'sha'), client, now });
    const summary = summaryMarkdown({ mode, stale: merged.stale, fields: merged.fields, touched, decision: result.decision });
    if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, summary);
    console.log(summary);
    if (result.annotation) console.log(result.annotation);
    return result.exitCode;
  }
  if (command === 'collect') {
    const manifest = collect({
      repo: one(options, 'repo') || process.cwd(),
      sourceSha: one(options, 'source-sha'),
      out: one(options, 'out'),
      allowlist: VOLATILE_EVIDENCE,
    });
    const stale = manifest.files.map((file) => file.path);
    console.log(stale.length > 0
      ? `VOLATILE EVIDENCE: ${stale.length} file(s) regenerated:\n${stale.map((path) => `  ${path}`).join('\n')}`
      : 'VOLATILE EVIDENCE: main is current');
    if (output) appendFileSync(output, `changed=${stale.length > 0}\nstale=${JSON.stringify(stale)}\n`);
    return 0;
  }
  if (command === 'request') {
    const out = one(options, 'out');
    if (!out) throw new Error('request requires --out <file>');
    const sourceSha = one(options, 'source-sha');
    const runUrl = one(options, 'run-url');
    const branch = refreshBranch(sourceSha);
    const request = commitRequest({
      bundle: one(options, 'bundle'),
      sourceSha,
      repository: one(options, 'repository'),
      branch,
      runUrl,
      allowlist: VOLATILE_EVIDENCE,
      message: refreshCommitMessage(sourceSha, runUrl),
    });
    writeFileSync(out, JSON.stringify(request));
    const paths = request.variables.input.fileChanges.additions.map((file) => file.path);
    const bodyOut = one(options, 'pr-body-out');
    if (bodyOut) writeFileSync(bodyOut, refreshPullRequestBody({ sourceSha, runUrl, paths }));
    console.log(`VOLATILE EVIDENCE: createCommitOnBranch request for ${branch} at ${sourceSha}:\n${paths.map((path) => `  ${path}`).join('\n')}`);
    if (output) appendFileSync(output, `branch=${branch}\ntitle=${REFRESH_TITLE}\n`);
    return 0;
  }
  throw new Error('usage: volatile-evidence.mjs policy|collect|request --option value ...');
}

// CI may run this file through a symlinked path; compare resolved paths.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (error) => {
      console.error(`VOLATILE EVIDENCE: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    },
  );
}
