#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Volatile evidence: policy and main-branch refresh tooling.
 *
 * Five derived files are regenerated on main after merge: lib/proof-stats.json
 * and the four LLM context artifacts rendered from it. Only one part of them
 * changes on almost every merge: the measured test counts
 * (ADVISORY_DRIFT). Requiring every pull request to carry exact counts made
 * each merge conflict every other open pull request and forced a ~25 minute
 * regeneration plus a full CI re-run, so main owns the counts:
 *
 *   - Deny by default. The only drift that is not a failure is drift in the
 *     fields ADVISORY_DRIFT lists, the lib/proof-stats.json test counts. Every
 *     other proof-stats field is derived from the security case and the
 *     formal, conformance, external and red-team evidence, and drift in any
 *     of them fails in every mode, as does any stale LLM context file (those
 *     are rendered only from checked-in inputs, so `npm run sync:llm-context`
 *     always fixes them without the suite). check:proof-stats and
 *     check:llm-context with --drift-report already fail on that drift; this
 *     policy checks the reports again.
 *   - On pull_request and merge_group, test-count drift is reported in the
 *     job summary and does not fail. A pull request that changes
 *     lib/proof-stats.json must leave the counts and their generatedAt exactly
 *     as the base has them (sync:proof-stats -- --bootstrap-derived-evidence)
 *     or make them exact; it may not set any other count or timestamp.
 *   - Main's own refresh pull request (head branch REFRESH_BRANCH_PREFIX...)
 *     is strict: any stale file fails, and so does any changed path outside
 *     the five files, so auto-merge lands only the writers' output that CI
 *     re-derived itself.
 *   - .github/workflows/volatile-evidence-refresh.yml runs on every push to
 *     main and twice a day. It regenerates the five files with the official
 *     writers in an unprivileged job, and a privileged job publishes them as
 *     ONE open pull request (REFRESH_TITLE) through the evidence autopilot
 *     App, with a compare-and-swap createCommitOnBranch commit that dco.yml
 *     exempts from sign-off only on GitHub's own evidence, and enables
 *     auto-merge. `plan` decides which open refresh pull requests it may
 *     reuse or close.
 *   - On main (push, schedule, manual), test-count drift fails once it is
 *     older than GRACE_HOURS. The clock starts at the first trusted refresh
 *     run created after the latest one that found main current, so staleness
 *     cannot persist silently when the App is unprovisioned, the refresh pull
 *     request is stuck, or the workflow is off. On a quiet main the first run
 *     that can see an expired grace is a scheduled one, so the failure
 *     appears within about GRACE_HOURS plus one 12-hour schedule interval
 *     (about 36 hours) of the push that staled the files, later if GitHub
 *     delays the scheduled run.
 *
 * Usage:
 *   node scripts/ci/volatile-evidence.mjs policy --event <name> --ref <ref>
 *     (--report <drift.json> --report <drift.json> | --stale <json array>)
 *     [--head-ref <branch>] [--touched-base <rev>] [--sha <commit>] [--repository <owner/name>]
 *   node scripts/ci/volatile-evidence.mjs collect --source-sha <sha> --out <dir> [--github-output <file>]
 *   node scripts/ci/volatile-evidence.mjs request --bundle <dir> --source-sha <sha> \
 *     --repository <owner/name> --run-url <url> --out <file> [--pr-body-out <file>] [--github-output <file>]
 *   node scripts/ci/volatile-evidence.mjs plan --source-sha <sha> --repository <owner/name> \
 *     --bot-login <login> [--github-output <file>]      (GH_TOKEN: the App token)
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
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

const PROOF_STATS = 'lib/proof-stats.json';

/**
 * The advisory allowlist, deny by default: per volatile file, the drifted
 * fields that may lag instead of failing. Only the measured test counts are
 * listed. Every other lib/proof-stats.json field (formalEvidenceCoverage,
 * tamarin, tla, alloy, formalScenarioConformance, securityCase, conformance,
 * externalImplementation, redTeamCases, tests.policy, anything added later)
 * and every LLM context file has no entry, so its drift fails.
 * scripts/generate-proof-stats.mts ADVISORY_PROOF_STATS_FIELDS is the same
 * list (a node test pins the two).
 */
export const ADVISORY_DRIFT = Object.freeze({
  [PROOF_STATS]: Object.freeze(['tests.files', 'tests.total']),
});

export const DRIFT_REPORT_VERSION = 'EP-VOLATILE-EVIDENCE-DRIFT-v1';
export const DRIFT_WRITERS = Object.freeze(['sync:proof-stats', 'sync:llm-context']);
export const REFRESH_WORKFLOW = 'volatile-evidence-refresh.yml';
export const REFRESH_BRANCH_PREFIX = 'automation/volatile-evidence-';
/** The only branch names the refresh creates, reuses, closes or deletes. */
export const REFRESH_BRANCH = /^automation\/volatile-evidence-[0-9a-f]{12}$/;
export const REFRESH_TITLE = 'chore(evidence): refresh volatile evidence';
export const REGENERATE_JOB = 'regenerate';
export const PUBLISH_JOB = 'publish';
/** One refresh cycle: the workflow runs on every push to main and every 12 hours. */
export const GRACE_HOURS = 24;
/** Refresh runs that can date staleness on main; pull_request and other events never can. */
export const TRUSTED_RUN_EVENTS = Object.freeze(['push', 'schedule', 'workflow_dispatch']);
/** Clock skew allowed between a contributor's writer and CI for a new generatedAt. */
export const GENERATED_AT_SKEW_MINUTES = 10;
const RUNS_PER_PAGE = 100;
const MAX_RUN_PAGES = 10;
const PULLS_PER_PAGE = 100;
const MAX_PULL_PAGES = 10;

const SHA = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const BOT_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$/;
const NODE_ID = /^[A-Za-z0-9_=-]{1,200}$/;
const HOUR_MS = 60 * 60 * 1000;

/**
 * @typedef {{ '@version': string, writer: string, current: boolean, stale: string[], fields?: string[] }} DriftReport
 * @typedef {{ id: number, created_at: string, status: string, conclusion: string | null, head_sha: string,
 *   event: string, head_branch?: string, head_repository?: { full_name?: string } | null, html_url?: string }} RefreshRun
 * @typedef {'current' | 'stale' | 'unknown'} Observation
 * @typedef {{ verdict: 'pass' | 'fail', staleSince: string | null, ageHours: number | null, reason: string }} GraceDecision
 * @typedef {{ stale: string[], fields: string[] | null }} MergedDrift
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
 * reached its comparison cannot read as current. `fields` are the
 * lib/proof-stats.json fields that drifted, or null when that report did not
 * say (which classifyDrift treats as outside the allowlist).
 *
 * @param {DriftReport[]} reports
 * @returns {MergedDrift}
 */
export function mergeDriftReports(reports) {
  const writers = reports.map((report) => report?.writer).sort();
  if (JSON.stringify(writers) !== JSON.stringify([...DRIFT_WRITERS].sort())) {
    throw new Error(`expected one drift report from each of ${DRIFT_WRITERS.join(' and ')}, got ${JSON.stringify(writers)}`);
  }
  const stale = [];
  /** @type {string[] | null} */
  let fields = [];
  for (const report of reports) {
    if (report['@version'] !== DRIFT_REPORT_VERSION) throw new Error(`${report.writer}: unsupported drift report version`);
    if (typeof report.current !== 'boolean') throw new Error(`${report.writer}: current must be a boolean`);
    const paths = staleList(report.stale);
    if (report.current !== (paths.length === 0)) throw new Error(`${report.writer}: current contradicts stale`);
    stale.push(...paths);
    if (report.writer === 'sync:proof-stats') {
      if (Array.isArray(report.fields) && report.fields.every((field) => typeof field === 'string')) {
        fields = [...new Set(report.fields)].sort();
      } else if (report.fields !== undefined || paths.length > 0) {
        fields = null;
      }
    } else if (Array.isArray(report.fields) && report.fields.length > 0) {
      throw new Error(`${report.writer}: only the proof-stats report names drifted fields`);
    }
  }
  return { stale: [...new Set(stale)].sort(), fields };
}

/**
 * Splits drift into what the allowlist tolerates and what it denies. A stale
 * lib/proof-stats.json is advisory only when the report names its drifted
 * fields and every one is in ADVISORY_DRIFT; a stale file with no allowlist
 * entry (every LLM context file) is denied.
 *
 * @param {MergedDrift} drift
 * @returns {{ advisory: string[], denied: Array<{ path: string, fields: string[] }> }}
 */
export function classifyDrift({ stale, fields }) {
  const advisory = [];
  const denied = [];
  for (const path of stale) {
    const allowed = Object.hasOwn(ADVISORY_DRIFT, path) ? ADVISORY_DRIFT[path] : [];
    const drifted = path === PROOF_STATS ? fields : null;
    if (drifted === null || drifted.length === 0) {
      denied.push({ path, fields: drifted ?? [] });
      continue;
    }
    const outside = drifted.filter((field) => !allowed.includes(field));
    if (outside.length > 0) denied.push({ path, fields: outside });
    else advisory.push(path);
  }
  return { advisory, denied };
}

/**
 * @param {string} base
 */
function assertRevision(base) {
  if (!/^[A-Za-z0-9][A-Za-z0-9^~._/-]*$/.test(base)) throw new Error(`refusing base revision ${JSON.stringify(base)}`);
}

/**
 * Every path `git diff base..HEAD` reports, with no pathspec. On a
 * pull_request run HEAD is GitHub's merge commit and its first parent
 * (HEAD^1) is the base, so this is exactly what merging the pull request
 * changes.
 *
 * @param {string} base
 * @param {string} [repo]
 * @returns {string[]}
 */
export function changedPaths(base, repo = process.cwd()) {
  assertRevision(base);
  const output = execFileSync(
    'git',
    ['diff', '--name-only', '-z', '--no-renames', base, 'HEAD'],
    { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return [...new Set(output.split('\0').filter(Boolean))].sort();
}

/**
 * The volatile files a pull request changes.
 *
 * @param {string} base
 * @param {string} [repo]
 * @returns {string[]}
 */
export function touchedVolatile(base, repo = process.cwd()) {
  return changedPaths(base, repo).filter((path) => VOLATILE_EVIDENCE.includes(path));
}

/**
 * @param {unknown} value
 * @returns {value is string}
 */
function isCanonicalInstant(value) {
  if (typeof value !== 'string') return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {string} revision
 * @param {string} repo
 * @returns {unknown}
 */
function proofStatsAt(revision, repo) {
  let text;
  try {
    text = execFileSync('git', ['show', `${revision}:${PROOF_STATS}`], {
      cwd: repo,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * What a pull request may write to lib/proof-stats.json beyond the writers'
 * exact output. `generatedAt` records when the test counts were measured and
 * is never compared by check:proof-stats, and the counts may lag, so both
 * are held to the base here:
 *   - generatedAt is a canonical instant, no later than now (plus
 *     GENERATED_AT_SKEW_MINUTES) and no earlier than the base's;
 *   - when the tests block equals the base's, generatedAt equals the base's
 *     (the writer keeps it; see proofStatsFileText);
 *   - when the file's test counts lag the measured suite, they must be the
 *     base's, unchanged: a pull request may carry main's counts but never
 *     set counts of its own that the suite does not produce.
 *
 * @param {{ head: unknown, base: unknown, stale: boolean, now: Date }} input
 * @returns {string[]} problems, empty when the file is acceptable
 */
export function proofStatsChangeProblems({ head, base, stale, now }) {
  const problems = [];
  if (!isPlainObject(head)) return [`${PROOF_STATS} is missing or not a JSON object`];
  if (!isCanonicalInstant(head.generatedAt)) {
    problems.push(`generatedAt ${JSON.stringify(head.generatedAt)} is not a canonical ISO-8601 instant`);
  } else if (Date.parse(head.generatedAt) > now.getTime() + GENERATED_AT_SKEW_MINUTES * 60_000) {
    problems.push(`generatedAt ${head.generatedAt} is in the future`);
  }
  if (!isPlainObject(head.tests)) problems.push('it has no tests block');
  const latest = now.getTime() + GENERATED_AT_SKEW_MINUTES * 60_000;
  // A base timestamp that is itself unusable (or in the future) cannot bound
  // the new one; the checks on the pull request's own value still apply.
  const baseUsable = isPlainObject(base) && isCanonicalInstant(base.generatedAt) && Date.parse(base.generatedAt) <= latest;
  const testsUnchanged = baseUsable && isDeepStrictEqual(head.tests, base.tests);
  if (baseUsable && isCanonicalInstant(head.generatedAt)) {
    if (testsUnchanged && head.generatedAt !== base.generatedAt) {
      problems.push(`the test counts are unchanged, so generatedAt must stay ${base.generatedAt} (it records when they were measured), not ${head.generatedAt}`);
    } else if (Date.parse(head.generatedAt) < Date.parse(base.generatedAt)) {
      problems.push(`generatedAt ${head.generatedAt} is earlier than the base's ${base.generatedAt}`);
    }
  }
  if (stale && !testsUnchanged) {
    problems.push('its test counts are neither what the suite measures for the merge commit nor the base\'s unchanged counts; keep main\'s counts (`npm run sync:proof-stats -- --bootstrap-derived-evidence`) or regenerate them exactly (`npm run sync:proof-stats`)');
  }
  return problems;
}

/**
 * How a run treats drift in the five files.
 *   strict   main's refresh pull request: stale fails, and so does any other
 *            changed path.
 *   advisory any other pull request, merge-queue candidates, other refs:
 *            test-count drift is reported.
 *   grace    main: test-count drift fails after GRACE_HOURS.
 * Drift outside ADVISORY_DRIFT fails in every mode.
 *
 * @param {{ event: string, ref: string, headRef?: string }} run
 * @returns {'strict' | 'advisory' | 'grace'}
 */
export function policyMode({ event, ref, headRef = '' }) {
  if (event === 'pull_request' && headRef.startsWith(REFRESH_BRANCH_PREFIX)) return 'strict';
  if (event === 'pull_request' || event === 'merge_group') return 'advisory';
  if (ref !== 'refs/heads/main') return 'advisory';
  if (!TRUSTED_RUN_EVENTS.includes(event)) return 'advisory';
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
 * Only runs of this repository's own main can date staleness: a pull_request
 * run from a fork's branch named main, which could edit the workflow to fake
 * a "current" observation, never counts.
 *
 * @param {RefreshRun} run
 * @param {string} repository
 * @returns {boolean}
 */
export function trustedRefreshRun(run, repository) {
  return Boolean(run)
    && Number.isSafeInteger(run.id) && run.id > 0
    && TRUSTED_RUN_EVENTS.includes(run.event)
    && run.head_branch === 'main'
    && run.head_repository?.full_name === repository
    && typeof run.created_at === 'string' && Number.isFinite(Date.parse(run.created_at))
    && typeof run.head_sha === 'string';
}

/**
 * Decides whether stale volatile evidence at `sha` is still inside the grace
 * window. `runs` are the trusted refresh runs on main, newest first by
 * creation; `observe` returns the Observation for a completed, successful
 * run. `truncated` says the listing stopped before it reached a run older
 * than the window, so the start of the staleness cannot be dated.
 *
 * @param {{ sha: string, runs: RefreshRun[], observe: (run: RefreshRun) => Promise<Observation>,
 *   now: Date, graceHours?: number, truncated?: boolean }} input
 * @returns {Promise<GraceDecision>}
 */
export async function decideGrace({ sha, runs, observe, now, graceHours = GRACE_HOURS, truncated = false }) {
  const ordered = [...runs].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id);
  if (ordered.length === 0) {
    return {
      verdict: 'fail',
      staleSince: null,
      ageHours: null,
      reason: `${REFRESH_WORKFLOW} has no trusted runs on main, so nothing will refresh this evidence; enable the workflow`,
    };
  }
  const windowStart = now.getTime() - graceHours * HOUR_MS;
  const age = (run) => (now.getTime() - Date.parse(run.created_at)) / HOUR_MS;
  let lastCurrent = -1;
  for (const [index, run] of ordered.entries()) {
    if (run.status === 'completed' && run.conclusion === 'success' && (await observe(run)) === 'current') {
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
    // Every run from the newest down to this one failed or found main stale,
    // so the staleness is at least as old as this run.
    if (Date.parse(run.created_at) < windowStart) {
      const ageHours = age(run);
      return {
        verdict: 'fail',
        staleSince: run.created_at,
        ageHours,
        reason: `stale since at least ${run.created_at} (${ageHours.toFixed(1)} h; grace ${graceHours} h): no refresh landed within one refresh cycle`,
      };
    }
  }
  if (lastCurrent === 0) {
    return {
      verdict: 'fail',
      staleSince: null,
      ageHours: null,
      reason: `no ${REFRESH_WORKFLOW} run exists for any commit after run ${ordered[0].id} found main current; the workflow did not start for later pushes`,
    };
  }
  if (lastCurrent === -1 && truncated) {
    return {
      verdict: 'fail',
      staleSince: null,
      ageHours: null,
      reason: `more than ${MAX_RUN_PAGES * RUNS_PER_PAGE} ${REFRESH_WORKFLOW} runs inside the ${graceHours} h window without one that found main current; the staleness cannot be dated`,
    };
  }
  // The earliest run created after the last current observation marks the
  // first push that could have made the evidence stale. With the complete
  // history and no current observation at all, it is the first run ever.
  const clock = lastCurrent === -1 ? ordered[ordered.length - 1] : ordered[lastCurrent - 1];
  const ageHours = age(clock);
  const since = `stale since ${clock.created_at} (${ageHours.toFixed(1)} h; grace ${graceHours} h)`;
  if (ageHours > graceHours) {
    return { verdict: 'fail', staleSince: clock.created_at, ageHours, reason: `${since}: no refresh landed within one refresh cycle` };
  }
  return { verdict: 'pass', staleSince: clock.created_at, ageHours, reason: `${since}: a refresh is in flight` };
}

/**
 * Minimal GitHub REST client over fetch. Any API failure throws: on main the
 * policy fails closed rather than passing stale evidence it cannot date, and
 * the publisher plans nothing it could not read. Every path segment it
 * interpolates is validated first.
 *
 * @param {{ token: string, repository: string, apiUrl?: string, fetchImpl?: typeof fetch }} options
 */
export function githubClient({ token, repository, apiUrl = 'https://api.github.com', fetchImpl = fetch }) {
  if (!token) throw new Error('GH_TOKEN (or GITHUB_TOKEN) is required');
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
  const sha = (value) => {
    if (typeof value !== 'string' || !SHA.test(value)) throw new Error(`refusing commit ${JSON.stringify(value)}`);
    return value;
  };
  return {
    /**
     * Trusted refresh runs on main, newest first, paged until one is older
     * than `windowStart` (enough for decideGrace) or the history ends.
     *
     * @param {{ windowStart: number }} options
     * @returns {Promise<{ runs: RefreshRun[], truncated: boolean }>}
     */
    async refreshRuns({ windowStart }) {
      const runs = [];
      for (let page = 1; page <= MAX_RUN_PAGES; page += 1) {
        const body = await get(`/actions/workflows/${REFRESH_WORKFLOW}/runs?branch=main&per_page=${RUNS_PER_PAGE}&page=${page}`);
        const listed = Array.isArray(body.workflow_runs) ? body.workflow_runs : [];
        const trusted = listed.filter((run) => trustedRefreshRun(run, repository));
        runs.push(...trusted);
        if (listed.length < RUNS_PER_PAGE || trusted.some((run) => Date.parse(run.created_at) < windowStart)) {
          return { runs, truncated: false };
        }
      }
      return { runs, truncated: true };
    },
    /** @param {RefreshRun} run @returns {Promise<Observation>} */
    async observe(run) {
      if (!Number.isSafeInteger(run.id) || run.id < 1) throw new Error(`refusing run id ${JSON.stringify(run.id)}`);
      const body = await get(`/actions/runs/${run.id}/jobs?filter=latest&per_page=100`);
      return observationFromJobs(body.jobs ?? []);
    },
    /** @returns {Promise<any[]>} */
    async openPullRequests() {
      const pulls = [];
      for (let page = 1; page <= MAX_PULL_PAGES; page += 1) {
        const listed = await get(`/pulls?state=open&base=main&per_page=${PULLS_PER_PAGE}&page=${page}`);
        if (!Array.isArray(listed)) throw new Error('GitHub API /pulls did not answer a list');
        pulls.push(...listed);
        if (listed.length < PULLS_PER_PAGE) return pulls;
      }
      throw new Error(`more than ${MAX_PULL_PAGES * PULLS_PER_PAGE} open pull requests; refusing to plan on a partial list`);
    },
    /** @param {number} number */
    async pullRequest(number) {
      if (!Number.isSafeInteger(number) || number < 1) throw new Error(`refusing pull request ${JSON.stringify(number)}`);
      return get(`/pulls/${number}`);
    },
    /** @param {string} commit */
    async commit(commit) {
      return get(`/commits/${sha(commit)}`);
    },
    /** @param {string} base @param {string} head */
    async compare(base, head) {
      return get(`/compare/${sha(base)}...${sha(head)}`);
    },
  };
}

/**
 * Decides what the publisher may do with the open refresh pull requests
 * before it writes anything. Only same-repository pull requests whose head
 * branch matches REFRESH_BRANCH are considered; nothing else is touched.
 *   - The pull request on this source's own branch is reused only when the
 *     App bot opened it, it has exactly one commit, that commit's single
 *     parent is `sourceSha` and the bot authored it. Otherwise it is
 *     replaced: closed, its branch deleted, and a fresh one created.
 *   - Another refresh pull request is superseded (closed, branch deleted)
 *     only when its source (the single parent of its head commit) is an
 *     ancestor of, or equal to, `sourceSha`.
 *   - When a bot-made refresh pull request has a newer source, the publisher
 *     publishes nothing: an old run (a re-run keeps its original commit)
 *     must not close the current refresh.
 *   - Anything else (diverged or unreadable source, a newer source that the
 *     bot did not make) is left alone and reported.
 *
 * @param {{ client: ReturnType<typeof githubClient>, repository: string, sourceSha: string, botLogin: string }} input
 */
export async function planRefresh({ client, repository, sourceSha, botLogin }) {
  const branch = refreshBranch(sourceSha);
  if (!REPOSITORY.test(repository)) throw new Error(`refusing repository ${JSON.stringify(repository)}`);
  if (typeof botLogin !== 'string' || !BOT_LOGIN.test(botLogin)) {
    throw new Error(`refusing bot login ${JSON.stringify(botLogin)}; set vars.EVIDENCE_AUTOPILOT_BOT_LOGIN`);
  }
  /** @type {{ number: number, nodeId: string, headSha: string } | null} */
  let reuse = null;
  /** @type {{ number: number, ref: string, reason: string } | null} */
  let replace = null;
  /** @type {{ number: number, ref: string, source: string } | null} */
  let newer = null;
  const supersede = [];
  const ignored = [];
  const candidates = (await client.openPullRequests()).filter((pull) =>
    pull?.head?.repo?.full_name === repository
    && typeof pull.head.ref === 'string'
    && REFRESH_BRANCH.test(pull.head.ref));
  for (const listed of candidates) {
    const number = listed.number;
    const ref = listed.head.ref;
    const pull = await client.pullRequest(number);
    if (pull?.number !== number || pull.state !== 'open' || pull.head?.ref !== ref
        || pull.head?.repo?.full_name !== repository || !SHA.test(pull.head?.sha ?? '')) {
      ignored.push({ number, ref, reason: 'its details changed while planning' });
      continue;
    }
    const commit = await client.commit(pull.head.sha);
    const parents = Array.isArray(commit?.parents) ? commit.parents.map((parent) => parent?.sha) : [];
    const source = parents.length === 1 && SHA.test(parents[0] ?? '') ? parents[0] : null;
    const botMade = pull.user?.login === botLogin && pull.commits === 1 && commit?.author?.login === botLogin && source !== null;
    if (ref === branch) {
      if (botMade && source === sourceSha && NODE_ID.test(pull.node_id ?? '')) {
        reuse = { number, nodeId: pull.node_id, headSha: pull.head.sha };
      } else {
        replace = {
          number,
          ref,
          reason: botMade ? `its commit's parent is ${source}, not ${sourceSha}` : 'it is not the App bot\'s single commit',
        };
      }
      continue;
    }
    if (source === null) {
      ignored.push({ number, ref, reason: 'its head commit does not have exactly one parent' });
      continue;
    }
    const { status } = await client.compare(source, sourceSha);
    if (status === 'ahead' || status === 'identical') {
      supersede.push({ number, ref });
    } else if (status === 'behind' && botMade) {
      newer ??= { number, ref, source };
    } else {
      ignored.push({
        number,
        ref,
        reason: status === 'behind'
          ? `its source ${source} is newer, but the App bot did not make it`
          : `its source ${source} is not an ancestor of ${sourceSha} (${status})`,
      });
    }
  }
  return { branch, action: newer ? 'skip' : 'publish', reuse, replace, supersede, newer, ignored };
}

/**
 * @param {{ mode: string, stale: string[], fields: string[] | null, touched?: string[],
 *   denied?: Array<{ path: string, fields: string[] }>, problems?: string[], decision?: GraceDecision }} input
 * @returns {string}
 */
export function summaryMarkdown({ mode, stale, fields, touched = [], denied = [], problems = [], decision }) {
  const lines = ['### Volatile evidence', ''];
  lines.push('| File | State |', '| --- | --- |');
  for (const path of VOLATILE_EVIDENCE) {
    const state = stale.includes(path) ? 'stale' : 'current';
    lines.push(`| \`${path}\` | ${state}${touched.includes(path) ? ' (changed by this pull request)' : ''} |`);
  }
  lines.push('');
  if (fields && fields.length > 0) lines.push(`Drifted \`${PROOF_STATS}\` fields: ${fields.map((field) => `\`${field}\``).join(', ')}.`, '');
  if (problems.length > 0) {
    lines.push('Failing:', '', ...problems.map((problem) => `- ${problem}`), '');
  }
  if (denied.length > 0) {
    lines.push(
      'Failing: drift outside the measured test counts is never advisory.',
      ...denied.map(({ path, fields: outside }) => `- \`${path}\`${outside.length > 0 ? `: ${outside.map((field) => `\`${field}\``).join(', ')}` : ''}`),
      '',
      'Commit your change, then run `npm run sync:proof-stats -- --bootstrap-derived-evidence` (refreshes every derived',
      'proof field and keeps main\'s test counts) when a proof field drifted, and `npm run sync:llm-context`, and commit',
      'the results.',
    );
  } else if (stale.length === 0) {
    lines.push('All five files match what the official writers produce for this commit.');
  } else if (mode === 'advisory' && problems.length === 0) {
    lines.push(
      'Advisory: only the measured test counts lag, and they never fail this check. Main regenerates them after merge',
      `(\`.github/workflows/${REFRESH_WORKFLOW}\`); every other proof field and the LLM context stay strict`,
      '(see CONTRIBUTING.md#volatile-evidence).',
    );
  } else if (mode === 'strict') {
    lines.push('This is main\'s refresh pull request, so stale content fails: it must equal what CI regenerates.');
  } else if (decision) {
    lines.push(`${decision.verdict === 'pass' ? 'Within grace' : 'Failing'}: ${decision.reason}.`);
  }
  return `${lines.join('\n')}\n`;
}

/**
 * @param {{ mode: 'strict' | 'advisory' | 'grace', stale: string[], fields?: string[] | null,
 *   regenerated?: boolean, problems?: string[], sha?: string,
 *   client?: ReturnType<typeof githubClient>, now?: Date }} input
 *   `regenerated` marks `stale` as the refresh's own output (--stale): those
 *   files changed because the writers ran, so only the grace clock applies.
 *   `problems` are failures found before the drift (changed paths, a
 *   proof-stats change the pull request may not make).
 * @returns {Promise<{ exitCode: number, decision?: GraceDecision, denied: Array<{ path: string, fields: string[] }>, annotation: string }>}
 */
export async function evaluatePolicy({ mode, stale, fields = [], regenerated = false, problems = [], sha, client, now = new Date() }) {
  const { denied } = regenerated ? { denied: [] } : classifyDrift({ stale, fields });
  if (problems.length > 0) {
    return {
      exitCode: 1,
      denied,
      annotation: `::error title=Volatile evidence change refused::${problems.join(' ')}`,
    };
  }
  if (stale.length === 0) return { exitCode: 0, denied, annotation: '' };
  const files = stale.join(', ');
  if (denied.length > 0) {
    const named = denied.map(({ path, fields: outside }) => (outside.length > 0 ? `${path} (${outside.join(', ')})` : path)).join('; ');
    return {
      exitCode: 1,
      denied,
      annotation: `::error title=Evidence drift outside the test counts::${named} differ from the writers' output. Only the measured test counts may lag; regenerate the rest (npm run sync:proof-stats -- --bootstrap-derived-evidence, npm run sync:llm-context).`,
    };
  }
  if (mode === 'advisory') {
    return { exitCode: 0, denied, annotation: `::notice title=Test counts lag (advisory)::${files}: only the measured test counts differ; main refreshes them after merge.` };
  }
  if (mode === 'strict') {
    return { exitCode: 1, denied, annotation: `::error title=Refresh pull request is stale::${files} differ from what CI regenerates for this merge commit.` };
  }
  if (!sha || !SHA.test(sha)) throw new Error('grace mode needs the checked commit (--sha)');
  if (!client) throw new Error('grace mode needs a GitHub client');
  const windowStart = now.getTime() - GRACE_HOURS * HOUR_MS;
  const { runs, truncated } = await client.refreshRuns({ windowStart });
  const decision = await decideGrace({ sha, runs, observe: client.observe, now, truncated });
  if (decision.verdict === 'pass') {
    return { exitCode: 0, decision, denied, annotation: `::warning title=Volatile evidence is stale on main::${files}; ${decision.reason}.` };
  }
  return { exitCode: 1, decision, denied, annotation: `::error title=Volatile evidence is stale on main::${files}; ${decision.reason}.` };
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
      'fail a stale file or any other changed path on this pull request,',
      'decide whether it is correct.',
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
    'other pull requests, this one fails CI when a volatile file is stale or when any other path',
    'changes, so auto-merge lands only content the required checks re-derived for the merge commit.',
    'Do not push to this branch.',
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
    const event = one(options, 'event');
    const mode = policyMode({ event, ref: one(options, 'ref'), headRef: one(options, 'head-ref') });
    // --stale is the refresh workflow's own regenerated output, which says
    // nothing about which fields drifted; it only dates staleness on main.
    if (staleJson && mode !== 'grace') throw new Error('policy --stale is for the refresh workflow on main only (grace mode)');
    /** @type {MergedDrift} */
    const merged = reports.length > 0
      ? mergeDriftReports(reports.map((file) => JSON.parse(readFileSync(file, 'utf8'))))
      : { stale: staleList(JSON.parse(staleJson)), fields: null };
    const repo = one(options, 'repo') || process.cwd();
    const touchedBase = one(options, 'touched-base');
    const problems = [];
    let touched = [];
    if (event === 'pull_request') {
      if (!touchedBase) throw new Error('pull_request runs need --touched-base (the merge commit\'s first parent)');
      const changed = changedPaths(touchedBase, repo);
      touched = changed.filter((path) => VOLATILE_EVIDENCE.includes(path));
      if (mode === 'strict') {
        const outside = changed.filter((path) => !VOLATILE_EVIDENCE.includes(path));
        if (outside.length > 0) {
          problems.push(`Main's refresh pull request may change only the five volatile files, but it changes ${outside.join(', ')}.`);
        }
      }
      if (touched.includes(PROOF_STATS)) {
        const found = proofStatsChangeProblems({
          head: proofStatsAt('HEAD', repo),
          base: proofStatsAt(touchedBase, repo),
          stale: merged.stale.includes(PROOF_STATS),
          now,
        });
        problems.push(...found.map((problem) => `This pull request changes ${PROOF_STATS}: ${problem}.`));
      }
    }
    const client = mode === 'grace' && merged.stale.length > 0 && problems.length === 0
      ? githubClient({
        token: env.GH_TOKEN || env.GITHUB_TOKEN || '',
        repository: one(options, 'repository'),
        apiUrl: env.GITHUB_API_URL || undefined,
        fetchImpl,
      })
      : undefined;
    const result = await evaluatePolicy({
      mode,
      stale: merged.stale,
      fields: merged.fields,
      regenerated: Boolean(staleJson),
      problems,
      sha: one(options, 'sha'),
      client,
      now,
    });
    const summary = summaryMarkdown({
      mode,
      stale: merged.stale,
      fields: merged.fields,
      touched,
      denied: result.denied,
      problems,
      decision: result.decision,
    });
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
  if (command === 'plan') {
    const repository = one(options, 'repository');
    const plan = await planRefresh({
      client: githubClient({
        token: env.GH_TOKEN || '',
        repository,
        apiUrl: env.GITHUB_API_URL || undefined,
        fetchImpl,
      }),
      repository,
      sourceSha: one(options, 'source-sha'),
      botLogin: one(options, 'bot-login'),
    });
    for (const { number, ref, reason } of plan.ignored) {
      console.log(`::warning title=Refresh pull request left alone::#${number} (${ref}): ${reason}.`);
    }
    if (plan.replace) console.log(`::warning title=Refresh pull request replaced::#${plan.replace.number} (${plan.replace.ref}): ${plan.replace.reason}.`);
    if (plan.newer) console.log(`::notice title=A newer refresh is open::#${plan.newer.number} carries main at ${plan.newer.source}; nothing to publish.`);
    const lines = [
      `action=${plan.action}`,
      `branch=${plan.branch}`,
      `reuse=${plan.reuse?.number ?? ''}`,
      `reuse_node_id=${plan.reuse?.nodeId ?? ''}`,
      `reuse_head=${plan.reuse?.headSha ?? ''}`,
      `replace=${plan.replace?.number ?? ''}`,
      `supersede=${plan.supersede.map(({ number, ref }) => `${number}:${ref}`).join(' ')}`,
    ];
    console.log(`VOLATILE EVIDENCE: plan\n${lines.map((line) => `  ${line}`).join('\n')}`);
    if (output) appendFileSync(output, `${lines.join('\n')}\n`);
    return 0;
  }
  throw new Error('usage: volatile-evidence.mjs policy|collect|request|plan --option value ...');
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
