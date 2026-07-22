// SPDX-License-Identifier: Apache-2.0
// Fail on every critical advisory and every unreviewed high advisory. The
// allow-list is restricted to development-only Hardhat 2 transitive tooling;
// npm run audit:prod separately requires a clean production graph.

import { execFileSync } from 'node:child_process';

const REVIEW_DEADLINE = '2026-08-21';
const ALLOWED_HIGH_ADVISORIES = new Set([
  'https://github.com/advisories/GHSA-xcpc-8h2w-3j85', // hardhat -> adm-zip
  'https://github.com/advisories/GHSA-5c6j-r48x-rmvq', // hardhat -> mocha -> serialize-javascript
  'https://github.com/advisories/GHSA-ph9p-34f9-6g65', // hardhat -> solc -> tmp
  'https://github.com/advisories/GHSA-vrm6-8vpv-qv8q', // hardhat -> undici
  'https://github.com/advisories/GHSA-v9p9-hfj2-hcw8', // hardhat -> undici
  'https://github.com/advisories/GHSA-vxpw-j846-p89q', // hardhat -> undici
]);

if (Date.now() >= Date.parse(`${REVIEW_DEADLINE}T00:00:00Z`)) {
  throw new Error(`DTC toolchain advisory exception expired on ${REVIEW_DEADLINE}`);
}

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
if (criticalCount > 0 || unexpected.length > 0 || missing.length > 0) {
  throw new Error(JSON.stringify({ criticalCount, unexpected, missing }, null, 2));
}

console.log(
  `DTC TOOLCHAIN AUDIT: PASS with ${observedHigh.size} reviewed development-only advisories; `
  + `exception expires ${REVIEW_DEADLINE}; production graph is checked separately`,
);
