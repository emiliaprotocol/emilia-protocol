// SPDX-License-Identifier: Apache-2.0
// Fail on every critical advisory and every unreviewed high advisory.
// Exceptions, when unavoidable, must be exact advisory URLs and are also
// checked for staleness. The current toolchain requires no exceptions;
// npm run audit:prod separately requires a clean production graph.

import { execFileSync } from 'node:child_process';

const ALLOWED_HIGH_ADVISORIES = new Set([]);

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
for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
  for (const cause of vulnerability.via ?? []) {
    if (typeof cause !== 'object' || cause === null) continue;
    if (!['high', 'critical'].includes(cause.severity)) continue;
    if (typeof cause.url === 'string') observedHigh.add(cause.url);
  }
}

const criticalCount = report.metadata?.vulnerabilities?.critical ?? 0;
const unexpected = [...observedHigh].filter((url) => !ALLOWED_HIGH_ADVISORIES.has(url));
const missing = [...ALLOWED_HIGH_ADVISORIES].filter((url) => !observedHigh.has(url));
if (
  criticalCount > 0
  || unexpected.length > 0
  || missing.length > 0
) {
  throw new Error(
    JSON.stringify({ criticalCount, unexpected, missing }, null, 2),
  );
}

console.log(
  `DTC TOOLCHAIN AUDIT: PASS with ${observedHigh.size} reviewed development-only exceptions; `
  + 'production graph is checked separately',
);
