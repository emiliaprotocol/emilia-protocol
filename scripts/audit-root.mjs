// SPDX-License-Identifier: Apache-2.0
// Reject every moderate-or-higher root advisory except an exact, short-lived
// exception for a build/lint transitive whose fix is still inside the
// repository's seven-day package-release quarantine. No untrusted glob pattern
// is accepted by the affected build paths.

import { execFileSync } from 'node:child_process';

const REVIEW_DEADLINE = '2026-08-01';
const ALLOWED_ADVISORIES = new Set([
  'https://github.com/advisories/GHSA-mh99-v99m-4gvg', // eslint tooling -> brace-expansion
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

const observed = new Set();
for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
  for (const cause of vulnerability.via ?? []) {
    if (typeof cause !== 'object' || cause === null) continue;
    if (!['moderate', 'high', 'critical'].includes(cause.severity)) continue;
    if (typeof cause.url === 'string') observed.add(cause.url);
  }
}

const unexpected = [...observed].filter((url) => !ALLOWED_ADVISORIES.has(url));
const missing = [...ALLOWED_ADVISORIES].filter((url) => !observed.has(url));
const expired = Date.now() >= Date.parse(`${REVIEW_DEADLINE}T00:00:00Z`);
if (unexpected.length > 0 || missing.length > 0 || expired) {
  throw new Error(JSON.stringify({ expired, unexpected, missing }, null, 2));
}

console.log(
  `ROOT AUDIT: PASS with ${observed.size} reviewed build-tool advisory; `
  + `exception expires ${REVIEW_DEADLINE}`,
);
