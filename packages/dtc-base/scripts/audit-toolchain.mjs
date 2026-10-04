// SPDX-License-Identifier: Apache-2.0
// Fail on every critical advisory and every unreviewed high advisory.
// Exceptions, when unavoidable, must be exact advisory URLs and are also
// checked for staleness, for a widened blast radius, and for a recheck date.
// npm run audit:prod separately requires a clean production graph.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// GHSA-ch52-4w7c-c8xp / CVE-2026-93748: http-cache-semantics through 4.2.0
// lets a client max-stale directive override shared-cache reuse prohibitions,
// so a shared cache can hand one user's zeroed Set-Cookie response to another.
//
// Reachability (reviewed 2026-10-04): the only copy is development-only:
//   solhint 6.2.4 -> latest-version 7.0.0 -> package-json 8.1.1 -> got 12.6.1
//     -> cacheable-request 10.2.14 -> http-cache-semantics 4.2.0
// solhint uses latest-version only to look up its own newest release on the
// npm registry (lib/cli/terminal-output.js). package-json calls got without a
// `cache` option, and got routes through cacheable-request only when one is
// set, so the cache-policy code is never executed. Even if it were, it would
// be a private in-process cache in a single-user lint run; the disclosure
// needs a shared cache serving several users. The deployed contracts and the
// receipt-program bridge do not depend on it, and audit:prod stays clean.
//
// Upstream fixed it in http-cache-semantics 4.3.0 (issue #56 closed), which
// is outside the advisory range and inside cacheable-request's ^4.1.1 range,
// but 4.3.0 was published 2026-10-04T02:56Z and this package's
// min-release-age=7 refuses it until 2026-10-11. The lock is not refreshed
// around that quarantine.
//
// Recheck: once 4.3.0 clears the quarantine, run
// `npm update http-cache-semantics --package-lock-only --ignore-scripts`,
// confirm `npm ls http-cache-semantics --all` shows 4.3.0 or later, delete
// this exception, and refresh the artifact manifest. The exception fails the
// gate on HTTP_CACHE_SEMANTICS_RECHECK_BY even if nobody has acted.
const HTTP_CACHE_SEMANTICS_ADVISORY = 'https://github.com/advisories/GHSA-ch52-4w7c-c8xp';
const HTTP_CACHE_SEMANTICS_RECHECK_BY = '2026-10-18';

const ALLOWED_HIGH_ADVISORIES = new Set([HTTP_CACHE_SEMANTICS_ADVISORY]);

// The exact packages npm may report through each accepted advisory, and the
// exact dev-only lockfile copies and direct dependents the review covered. A
// new copy, a new consumer, or a production edge means the reachability review
// above no longer describes the tree.
const REVIEWED_AFFECTED_PACKAGES = new Map([
  [HTTP_CACHE_SEMANTICS_ADVISORY, ['http-cache-semantics']],
]);
const REVIEWED_LOCK_COPIES = new Map([
  [HTTP_CACHE_SEMANTICS_ADVISORY, {
    name: 'http-cache-semantics',
    copies: ['node_modules/http-cache-semantics'],
    dependents: ['node_modules/cacheable-request'],
  }],
]);
const RECHECK_BY = new Map([
  [HTTP_CACHE_SEMANTICS_ADVISORY, HTTP_CACHE_SEMANTICS_RECHECK_BY],
]);

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

const observedHigh = new Set();
const seeds = new Map();
const dependents = new Map();
for (const [name, vulnerability] of Object.entries(report.vulnerabilities ?? {})) {
  for (const cause of vulnerability.via ?? []) {
    if (typeof cause === 'string') {
      if (!dependents.has(cause)) dependents.set(cause, new Set());
      dependents.get(cause).add(name);
      continue;
    }
    if (typeof cause !== 'object' || cause === null) continue;
    if (!['high', 'critical'].includes(cause.severity)) continue;
    if (typeof cause.url !== 'string') continue;
    observedHigh.add(cause.url);
    if (!seeds.has(cause.url)) seeds.set(cause.url, new Set());
    seeds.get(cause.url).add(name);
  }
}

function affectedPackages(url) {
  const queue = [...(seeds.get(url) ?? [])];
  const visited = new Set(queue);
  while (queue.length > 0) {
    const name = queue.shift();
    for (const dependent of dependents.get(name) ?? []) {
      if (visited.has(dependent)) continue;
      visited.add(dependent);
      queue.push(dependent);
    }
  }
  return [...visited].sort();
}

const criticalCount = report.metadata?.vulnerabilities?.critical ?? 0;
const unexpected = [...observedHigh].filter((url) => !ALLOWED_HIGH_ADVISORIES.has(url));
const missing = [...ALLOWED_HIGH_ADVISORIES].filter((url) => !observedHigh.has(url));
const widened = [...ALLOWED_HIGH_ADVISORIES]
  .filter((url) => observedHigh.has(url))
  .map((url) => ({ url, reviewed: REVIEWED_AFFECTED_PACKAGES.get(url) ?? [], live: affectedPackages(url) }))
  .filter(({ reviewed, live }) => JSON.stringify([...reviewed].sort()) !== JSON.stringify(live));
const lockPackages = JSON.parse(
  readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'),
).packages ?? {};
const lockDrift = [...REVIEWED_LOCK_COPIES].flatMap(([url, { name, copies, dependents }]) => {
  const isCopy = (path) => path === `node_modules/${name}` || path.endsWith(`/node_modules/${name}`);
  const liveCopies = Object.keys(lockPackages).filter(isCopy).sort();
  const liveDependents = Object.entries(lockPackages)
    .filter(([, entry]) => entry?.dependencies?.[name] !== undefined || entry?.optionalDependencies?.[name] !== undefined)
    .map(([path]) => path)
    .sort();
  const notDevOnly = liveCopies.filter((path) => lockPackages[path]?.dev !== true);
  if (
    JSON.stringify(liveCopies) === JSON.stringify([...copies].sort())
    && JSON.stringify(liveDependents) === JSON.stringify([...dependents].sort())
    && notDevOnly.length === 0
  ) return [];
  return [{ url, liveCopies, liveDependents, notDevOnly }];
});
const now = Date.now();
const overdue = [...ALLOWED_HIGH_ADVISORIES]
  .filter((url) => {
    const recheckBy = Date.parse(`${RECHECK_BY.get(url)}T00:00:00Z`);
    return !Number.isFinite(recheckBy) || now >= recheckBy;
  })
  .map((url) => ({ url, recheckBy: RECHECK_BY.get(url) ?? null }));
if (
  criticalCount > 0
  || unexpected.length > 0
  || missing.length > 0
  || widened.length > 0
  || lockDrift.length > 0
  || overdue.length > 0
) {
  throw new Error(
    JSON.stringify({ criticalCount, unexpected, missing, widened, lockDrift, overdue }, null, 2),
  );
}

console.log(
  `DTC TOOLCHAIN AUDIT: PASS with ${observedHigh.size} reviewed development-only exceptions `
  + `(${[...ALLOWED_HIGH_ADVISORIES].map((url) => `${url} until ${RECHECK_BY.get(url)}`).join(', ')}); `
  + 'production graph is checked separately',
);
