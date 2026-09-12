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

const unexpected = [...observed].filter((url) => url !== REVIEWED_ADVISORY);
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

console.log(
  `${scope} AUDIT: PASS at ${minimumSeverity}+; `
  + (observed.size === 0
    ? 'no advisories observed'
    : 'one npm range finding is constrained to reviewed, cap-enforced builds'),
);
