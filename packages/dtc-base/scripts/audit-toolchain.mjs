// SPDX-License-Identifier: Apache-2.0
// Fail on every critical advisory and every unreviewed high advisory.
// Exceptions, when unavoidable, must be exact advisory URLs and are also
// checked for staleness, for a widened blast radius, and for a recheck date.
// npm run audit:prod separately requires a clean production graph.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// GHSA-mrhx-c7xc-m3w5: zod below 4.6.6 can exhaust memory while validating
// oversized constrained collections. The advisory range includes all of zod 3,
// and Hardhat 3 still depends on zod 3.25.76 (hardhat, hardhat-mocha and
// hardhat-ethers each resolve to that one lockfile copy). There is no
// release of that dependency line outside the range, and the packages npm
// offers as a fix are a semver-major downgrade of the network-helpers plugin.
//
// Reachability (reviewed 2026-10-26): the lockfile marks the zod copy and all
// of its dependents development-only, and `npm run audit:prod` stays clean, so
// zod is not part of the shipped contracts or the receipt-program bridge. The
// exposure is a memory-exhausting input to a local Hardhat compile or test run.
//
// Recheck: when Hardhat ships a release on zod 4.6.6 or later, bump hardhat,
// confirm `npm ls zod --all` shows no copy below 4.6.6, delete this exception,
// and refresh the artifact manifest. The exception fails the gate on
// ZOD_RECHECK_BY even if nobody has acted.
const ZOD_ADVISORY = 'https://github.com/advisories/GHSA-mrhx-c7xc-m3w5';
const ZOD_RECHECK_BY = '2026-11-16';

const ALLOWED_HIGH_ADVISORIES = new Set([ZOD_ADVISORY]);

// The exact packages npm may report through each accepted advisory, and the
// exact dev-only lockfile copies and direct dependents the review covered. A
// new copy, a new consumer, or a production edge means the reachability review
// above no longer describes the tree.
const REVIEWED_AFFECTED_PACKAGES = new Map([
  [ZOD_ADVISORY, [
    '@nomicfoundation/hardhat-ethers',
    '@nomicfoundation/hardhat-ethers-chai-matchers',
    '@nomicfoundation/hardhat-mocha',
    '@nomicfoundation/hardhat-network-helpers',
    '@nomicfoundation/hardhat-zod-utils',
    'hardhat',
    'zod',
  ]],
]);
const REVIEWED_LOCK_COPIES = new Map([
  [ZOD_ADVISORY, {
    name: 'zod',
    copies: ['node_modules/zod'],
    dependents: [
      'node_modules/@nomicfoundation/hardhat-ethers',
      'node_modules/@nomicfoundation/hardhat-mocha',
      'node_modules/hardhat',
    ],
  }],
]);
const RECHECK_BY = new Map([
  [ZOD_ADVISORY, ZOD_RECHECK_BY],
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
