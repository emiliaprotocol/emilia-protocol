// SPDX-License-Identifier: Apache-2.0
//
// Two reviewed advisory exceptions. Every other advisory at or above the
// threshold fails the audit.
//
// 1. npm currently describes GHSA-mh99-v99m-4gvg with a range broad enough to
//    include backported, capped implementations. Accept that advisory only when
//    every installed brace-expansion copy is one of the exact reviewed builds
//    and demonstrates both result-count and aggregate-length caps at runtime.
//
// 2. GHSA-vfj7-8cjw-p6xm (braces <=3.0.3, stack exhaustion on deeply nested
//    patterns) has no patched release. See the braces section below for the
//    pinned copy, the reachability review, the probe, and the recheck date.

import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const scope = process.argv[2] ?? 'ROOT';
const minimumSeverity = process.argv[3] ?? 'moderate';
const severityRank = new Map([
  ['low', 1],
  ['moderate', 2],
  ['high', 3],
  ['critical', 4],
]);
const minimumRank = severityRank.get(minimumSeverity);
if (minimumRank === undefined) {
  throw new Error(`Unsupported audit severity threshold: ${minimumSeverity}`);
}

const REVIEWED_ADVISORY = 'https://github.com/advisories/GHSA-mh99-v99m-4gvg';
const REVIEWED_BRACE_EXPANSION = new Set(['2.1.3', '5.0.8']);

// GHSA-vfj7-8cjw-p6xm / CVE-2026-93687: braces through 3.0.3 recurses without a
// depth guard in parse/compile/expand, so a deeply nested pattern under the
// 10000-character input cap throws RangeError (stack exhaustion). No patched
// version exists; 3.0.3 is the latest release on npm.
//
// Reachability (reviewed 2026-10-03): the only installed copy is a dev-only
// transitive of the lint preset:
//   eslint-config-next -> @next/eslint-plugin-next -> fast-glob 3.3.1
//     -> micromatch 4.0.8 -> braces 3.0.3
// @next/eslint-plugin-next calls fast-glob only on settings.next.rootDir from
// the repository's own eslint config. The other consumer of that fast-glob
// copy is tests/route-coverage.test.ts with a fixed literal pattern. No
// application, SDK, or server code imports braces, micromatch, fast-glob, or
// the eslint packages, and next vendors picomatch rather than braces. Patterns
// never come from requests, receipts, or other untrusted input, and the worst
// case is an aborted lint or test run.
//
// The acceptance cannot widen silently. It fails when:
//   * any braces copy other than the pinned path appears, or the pinned path
//     changes version or lockfile integrity, or the lockfile stops marking it
//     dev-only (a production dependency started pulling it in);
//   * the set of packages npm reports through this advisory changes in any
//     way (a new consumer, a new path, a missing one);
//   * the probe below shows anything other than a bounded, catchable failure;
//   * the recheck date passes.
// Recheck: drop this exception once braces ships a release outside <=3.0.3, or
// once eslint-config-next stops depending on fast-glob 3.x. On or after
// BRACES_RECHECK_BY, re-run `gh api /advisories/GHSA-vfj7-8cjw-p6xm` and
// `npm ls braces --all`, repeat the review above, and move the date only if
// it still holds.
const BRACES_ADVISORY = 'https://github.com/advisories/GHSA-vfj7-8cjw-p6xm';
const BRACES_RECHECK_BY = '2026-12-01';
const REVIEWED_BRACES_COPIES = new Map([
  ['node_modules/braces', {
    version: '3.0.3',
    integrity: 'sha512-yQbXgO/OSZVD2IsiLlro+7Hf6Q18EJrKSEsdoMzKePKXct3gvD8oLcOQdIzGupr5Fj+EDe8gO/lxc1BzfMpxvA==',
  }],
]);
const REVIEWED_BRACES_AFFECTED = new Map([
  ['braces', ['node_modules/braces']],
  ['micromatch', ['node_modules/micromatch']],
  ['fast-glob', ['node_modules/fast-glob']],
  ['@next/eslint-plugin-next', ['node_modules/@next/eslint-plugin-next']],
  ['eslint-config-next', ['node_modules/eslint-config-next']],
]);
const REVIEWED_ADVISORIES = new Set([REVIEWED_ADVISORY, BRACES_ADVISORY]);

// npm prints two structurally different JSON payloads on stdout, and its exit
// status does not tell them apart because it is non-zero for both:
//   * an advisory report, which always carries auditReportVersion and a
//     vulnerabilities map;
//   * the advisory-endpoint failure envelope from npm's lib/utils/audit-error.js,
//     which carries the fetch error's top-level message (plus method, uri,
//     headers, statusCode, body when npm has them) and carries no advisory data
//     at all. npm's exit handler then appends a generic
//     {"error":{"summary":"","detail":""}} envelope that says nothing about any
//     package.
// The second case is a transport failure, not a security finding, so it is
// retried rather than reported as an advisory. It is never treated as a pass:
// an unreachable endpoint means the audit did not happen, which is not the same
// as an audit that found nothing.
const AUDIT_ATTEMPTS = 3;
// Overridable only so the unit tests do not sleep; it changes retry pacing, not
// the pass/fail decision.
const RETRY_DELAY_MS = Number.parseInt(process.env.EP_AUDIT_RETRY_DELAY_MS ?? '5000', 10);
// Bound each attempt. npm's default fetch-timeout is 5 minutes, so a single
// stalled request otherwise burns the whole job and still yields no answer.
const AUDIT_ARGS = ['audit', '--json', '--fetch-timeout=60000', '--fetch-retries=2'];

function sleepSync(milliseconds) {
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function isEndpointFailure(payload) {
  return payload !== null
    && typeof payload === 'object'
    && !Array.isArray(payload)
    && !('auditReportVersion' in payload)
    && !('vulnerabilities' in payload)
    && typeof payload.message === 'string';
}

function describeEndpointFailure(payload) {
  const parts = [payload.message];
  if (typeof payload.statusCode === 'number') parts.push(`statusCode=${payload.statusCode}`);
  if (typeof payload.uri === 'string') parts.push(`uri=${payload.uri}`);
  return parts.join('; ');
}

function runAudit() {
  try {
    return JSON.parse(execFileSync('npm', AUDIT_ARGS, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }));
  } catch (error) {
    const stdout = error?.stdout;
    if (typeof stdout !== 'string' || stdout.length === 0) throw error;
    return JSON.parse(stdout);
  }
}

let report;
let endpointFailure = null;
for (let attempt = 1; attempt <= AUDIT_ATTEMPTS; attempt += 1) {
  const payload = runAudit();
  if (!isEndpointFailure(payload)) {
    report = payload;
    endpointFailure = null;
    break;
  }
  endpointFailure = describeEndpointFailure(payload);
  console.error(
    `npm audit advisory endpoint unreachable (attempt ${attempt}/${AUDIT_ATTEMPTS}): ${endpointFailure}`,
  );
  if (attempt < AUDIT_ATTEMPTS) sleepSync(RETRY_DELAY_MS);
}
if (endpointFailure !== null) {
  throw new Error(
    `npm audit could not reach the advisory endpoint after ${AUDIT_ATTEMPTS} attempts, `
    + `so no advisory data was obtained: ${endpointFailure}`,
  );
}

if (report === null || typeof report !== 'object' || Array.isArray(report)) {
  throw new Error('npm audit did not return an object report');
}
if ('error' in report) {
  throw new Error(`npm audit returned an error report: ${JSON.stringify(report.error)}`);
}
if (report.auditReportVersion !== 2) {
  throw new Error(`unsupported npm audit report version: ${String(report.auditReportVersion)}`);
}
if (
  !Object.prototype.hasOwnProperty.call(report, 'vulnerabilities')
  || report.vulnerabilities === null
  || typeof report.vulnerabilities !== 'object'
  || Array.isArray(report.vulnerabilities)
) {
  throw new Error('npm audit report omitted the vulnerabilities map');
}
const summary = report.metadata?.vulnerabilities;
if (summary === null || typeof summary !== 'object' || Array.isArray(summary)) {
  throw new Error('npm audit report omitted the vulnerability summary');
}
for (const field of ['info', 'low', 'moderate', 'high', 'critical', 'total']) {
  if (!Number.isSafeInteger(summary[field]) || summary[field] < 0) {
    throw new Error(`npm audit report has an invalid ${field} count`);
  }
}
const summedSeverityCount = summary.info + summary.low + summary.moderate + summary.high + summary.critical;
if (summary.total !== summedSeverityCount) {
  throw new Error('npm audit report vulnerability counts do not reconcile');
}

const observed = new Set();
for (const vulnerability of Object.values(report.vulnerabilities)) {
  for (const cause of vulnerability.via ?? []) {
    if (typeof cause !== 'object' || cause === null) continue;
    const rank = severityRank.get(cause.severity) ?? 0;
    if (rank >= minimumRank && typeof cause.url === 'string') observed.add(cause.url);
  }
}

const unexpected = [...observed].filter((url) => !REVIEWED_ADVISORIES.has(url));
if (unexpected.length > 0) {
  throw new Error(JSON.stringify({ unexpected }, null, 2));
}

if (observed.has(REVIEWED_ADVISORY)) {
  const packagePaths = execFileSync(
    'npm',
    ['ls', 'brace-expansion', '--all', '--parseable'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).trim().split(/\r?\n/).filter(Boolean);
  if (packagePaths.length === 0) throw new Error('brace-expansion advisory observed without an installed package');

  const require = createRequire(import.meta.url);
  for (const packagePath of packagePaths) {
    const manifest = JSON.parse(readFileSync(join(packagePath, 'package.json'), 'utf8'));
    if (!REVIEWED_BRACE_EXPANSION.has(manifest.version)) {
      throw new Error(`unreviewed brace-expansion version under advisory: ${manifest.version}`);
    }
    const loaded = require(packagePath);
    const expand = typeof loaded === 'function' ? loaded : loaded?.expand;
    if (typeof expand !== 'function') throw new Error(`brace-expansion ${manifest.version} has no callable expansion API`);

    const max = 64;
    const maxLength = 4096;
    const expanded = expand('{a,b}'.repeat(16), { max, maxLength });
    const totalLength = expanded.reduce((sum, value) => sum + value.length, 0);
    if (expanded.length > max || totalLength > maxLength) {
      throw new Error(`brace-expansion ${manifest.version} failed the executable resource-cap check`);
    }
  }
}

if (observed.has(BRACES_ADVISORY)) {
  const recheckBy = Date.parse(`${BRACES_RECHECK_BY}T00:00:00Z`);
  if (!Number.isFinite(recheckBy) || Date.now() >= recheckBy) {
    throw new Error(
      `braces advisory exception reached its recheck date (${BRACES_RECHECK_BY}); `
      + 'repeat the reachability review in scripts/audit-root.mjs before extending it',
    );
  }

  const root = process.cwd();

  // Every package npm attributes to this advisory, directly or through a
  // dependency chain, with the exact install locations it reports.
  const affected = new Map();
  let grew = true;
  while (grew) {
    grew = false;
    for (const [name, vulnerability] of Object.entries(report.vulnerabilities)) {
      if (affected.has(name)) continue;
      const reached = (vulnerability.via ?? []).some((cause) => (
        typeof cause === 'string'
          ? affected.has(cause)
          : cause !== null && typeof cause === 'object' && cause.url === BRACES_ADVISORY
      ));
      if (reached) {
        affected.set(name, [...(vulnerability.nodes ?? [])].sort());
        grew = true;
      }
    }
  }
  const affectedKey = (entries) => JSON.stringify(
    [...entries].map(([name, nodes]) => [name, [...nodes].sort()]).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  if (affectedKey(affected) !== affectedKey(REVIEWED_BRACES_AFFECTED)) {
    throw new Error(`braces advisory reaches an unreviewed package set: ${affectedKey(affected)}`);
  }

  // `npm query` reports each installed copy by its location relative to the
  // project root. Absolute paths are avoided on purpose: npm redacts
  // UUID-shaped path segments in its output, which would make them unusable.
  const installed = JSON.parse(execFileSync(
    'npm',
    ['query', '#braces'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  ));
  if (!Array.isArray(installed)) throw new Error('npm query did not return a package list for braces');
  const installedLocations = installed.map((node) => node?.location).sort();
  if (JSON.stringify(installedLocations) !== JSON.stringify([...REVIEWED_BRACES_COPIES.keys()].sort())) {
    throw new Error(`unreviewed braces copies under advisory: ${JSON.stringify(installedLocations)}`);
  }

  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  const lockedLocations = Object.keys(lock.packages ?? {})
    .filter((location) => location === 'node_modules/braces' || location.endsWith('/node_modules/braces'))
    .sort();
  if (JSON.stringify(lockedLocations) !== JSON.stringify([...REVIEWED_BRACES_COPIES.keys()].sort())) {
    throw new Error(`package-lock.json lists unreviewed braces copies: ${JSON.stringify(lockedLocations)}`);
  }
  for (const node of installed) {
    const repoPath = node.location;
    const pinned = REVIEWED_BRACES_COPIES.get(repoPath);
    const packagePath = join(root, ...repoPath.split('/'));
    const manifest = JSON.parse(readFileSync(join(packagePath, 'package.json'), 'utf8'));
    if (manifest.name !== 'braces' || manifest.version !== pinned.version || node.version !== pinned.version) {
      throw new Error(`unreviewed braces version at ${repoPath}: ${manifest.version}`);
    }
    const locked = lock.packages?.[repoPath];
    if (locked?.version !== pinned.version || locked?.integrity !== pinned.integrity) {
      throw new Error(`braces lockfile entry at ${repoPath} does not match the reviewed version and integrity`);
    }
    if (locked.dev !== true || node.dev !== true) {
      throw new Error(`braces at ${repoPath} is no longer dev-only`);
    }

    // Probe the advisory's input class in a separate, resource-bounded process:
    // the deepest nesting braces accepts must either expand or throw a
    // catchable RangeError, within the time and heap bounds, and input past the
    // length cap must still be rejected before any recursion.
    const probe = [
      "const braces = require(process.argv[1]);",
      "const depth = 4999;",
      "const nested = '{'.repeat(depth) + '}'.repeat(depth);",
      "const outcomes = [];",
      "for (const options of [{}, { expand: true }]) {",
      "  try { braces(nested, options); outcomes.push('expanded'); }",
      "  catch (error) { if (!(error instanceof RangeError)) throw error; outcomes.push('RangeError'); }",
      "}",
      "let lengthCap = 'missing';",
      "try { braces('{a,b}'.repeat(2001)); }",
      "catch (error) { if (error instanceof SyntaxError && /exceeds max characters/.test(error.message)) lengthCap = 'enforced'; }",
      "process.stdout.write(JSON.stringify({ outcomes, lengthCap }));",
    ].join('\n');
    let probeResult;
    try {
      probeResult = JSON.parse(execFileSync(
        process.execPath,
        ['--max-old-space-size=64', '-e', probe, packagePath],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000, killSignal: 'SIGKILL' },
      ));
    } catch (error) {
      throw new Error(`braces ${manifest.version} failed the resource-bounded nesting probe: ${error.message}`);
    }
    if (
      probeResult?.lengthCap !== 'enforced'
      || !Array.isArray(probeResult.outcomes)
      || probeResult.outcomes.length !== 2
      || !probeResult.outcomes.every((outcome) => outcome === 'expanded' || outcome === 'RangeError')
    ) {
      throw new Error(`braces ${manifest.version} failed the resource-bounded nesting probe: ${JSON.stringify(probeResult)}`);
    }
  }
}

const accepted = [];
if (observed.has(REVIEWED_ADVISORY)) accepted.push('brace-expansion range finding constrained to reviewed, cap-enforced builds');
if (observed.has(BRACES_ADVISORY)) accepted.push(`braces finding constrained to the pinned dev-only lint copy until ${BRACES_RECHECK_BY}`);
console.log(
  `${scope} AUDIT: PASS at ${minimumSeverity}+; `
  + (observed.size === 0 ? 'no advisories observed' : accepted.join('; ')),
);
