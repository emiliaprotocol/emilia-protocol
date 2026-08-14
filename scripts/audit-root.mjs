// SPDX-License-Identifier: Apache-2.0
//
// npm currently describes GHSA-mh99-v99m-4gvg with a range broad enough to
// include backported, capped implementations. Accept that advisory only when
// every installed brace-expansion copy is one of the exact reviewed builds and
// demonstrates both result-count and aggregate-length caps at runtime.

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

// GHSA-2v37-7h3g-55p8: nanoid custom generators can loop indefinitely when
// size is zero. Our only dependent is next -> postcss, whose sole call is
// nanoid(6) from nanoid/non-secure (postcss/lib/input.js): the standard
// generator with a fixed nonzero size. The custom-generator zero-size path is
// not reachable from installed code. The fixed 3.3.18 was published
// 2026-08-07T16:41Z; this repository's min-release-age=7 quarantine
// (.npmrc) correctly refuses to resolve it before 2026-08-14T16:41Z, so the
// upgrade cannot land at review time. This acceptance is version-pinned and
// EXPIRES: once the date below passes, the audit fails again until nanoid is
// upgraded and this block is removed.
const REVIEWED_NANOID_ADVISORY = 'https://github.com/advisories/GHSA-2v37-7h3g-55p8';
const REVIEWED_NANOID_VERSIONS = new Set(['3.3.17']);
const REVIEWED_NANOID_EXPIRES_UTC = Date.UTC(2026, 7, 18); // 2026-08-18T00:00Z

let report;
try {
  const stdout = execFileSync('npm', ['audit', '--json'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  report = JSON.parse(stdout);
} catch (error) {
  const stdout = error?.stdout;
  if (typeof stdout !== 'string' || stdout.length === 0) throw error;
  report = JSON.parse(stdout);
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

const unexpected = [...observed].filter(
  (url) => url !== REVIEWED_ADVISORY && url !== REVIEWED_NANOID_ADVISORY,
);
if (unexpected.length > 0) {
  throw new Error(JSON.stringify({ unexpected }, null, 2));
}

if (observed.has(REVIEWED_NANOID_ADVISORY)) {
  if (Date.now() >= REVIEWED_NANOID_EXPIRES_UTC) {
    throw new Error(
      'nanoid advisory acceptance expired: the min-release-age quarantine on '
      + 'nanoid 3.3.18 has lapsed; upgrade nanoid and remove this acceptance',
    );
  }
  // npm redacts token-shaped path segments in its output (a working
  // directory containing a UUID becomes "***"), so absolute paths from
  // `npm ls --parseable` are not trustworthy. Re-anchor each reported
  // location at the first node_modules segment under the current root.
  const nanoidPaths = execFileSync(
    'npm',
    ['ls', 'nanoid', '--all', '--parseable'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).trim().split(/\r?\n/).filter(Boolean).map((reported) => {
    const anchor = reported.indexOf('node_modules');
    return anchor === -1 ? reported : join(process.cwd(), reported.slice(anchor));
  });
  if (nanoidPaths.length === 0) throw new Error('nanoid advisory observed without an installed package');

  const requireNanoid = createRequire(import.meta.url);
  for (const packagePath of nanoidPaths) {
    const manifest = JSON.parse(readFileSync(join(packagePath, 'package.json'), 'utf8'));
    if (!REVIEWED_NANOID_VERSIONS.has(manifest.version)) {
      throw new Error(`unreviewed nanoid version under advisory: ${manifest.version}`);
    }
    // Demonstrate the reviewed usage path: the standard non-secure generator
    // with a fixed nonzero size, exactly as postcss calls it. The vulnerable
    // path requires a custom generator invoked with size zero, which no
    // installed dependent does.
    const { nanoid: standardGenerator } = requireNanoid(join(packagePath, 'non-secure'));
    const sample = standardGenerator(6);
    if (typeof sample !== 'string' || sample.length !== 6) {
      throw new Error(`nanoid ${manifest.version} failed the reviewed-path generation check`);
    }
  }
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

console.log(
  `${scope} AUDIT: PASS at ${minimumSeverity}+; `
  + (observed.size === 0
    ? 'no advisories observed'
    : 'one npm range finding is constrained to reviewed, cap-enforced builds'),
);
