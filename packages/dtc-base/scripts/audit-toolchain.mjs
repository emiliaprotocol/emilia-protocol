// SPDX-License-Identifier: Apache-2.0
// Fail on every high or critical advisory. There are no remaining toolchain
// exceptions: http-cache-semantics 4.3.0 fixes GHSA-ch52-4w7c-c8xp and cleared
// the seven-day release quarantine on 2026-10-11. Production is audited
// separately at the low threshold by npm run audit:prod.

import { execFileSync } from 'node:child_process';

let report;
try {
  report = JSON.parse(execFileSync('npm', ['audit', '--json'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 120000,
  }));
} catch (error) {
  const stdout = error?.stdout;
  if (typeof stdout !== 'string' || stdout.length === 0) throw error;
  report = JSON.parse(stdout);
}

// npm also emits JSON when its advisory endpoint fails. Missing or malformed
// data must not be mistaken for a clean graph, including a false zero summary.
const counts = report?.metadata?.vulnerabilities;
if (
  report?.error
  || report?.auditReportVersion !== 2
  || !report.vulnerabilities
  || typeof report.vulnerabilities !== 'object'
  || Array.isArray(report.vulnerabilities)
  || !counts
  || !['info', 'low', 'moderate', 'high', 'critical', 'total']
    .every((level) => Number.isSafeInteger(counts[level]) && counts[level] >= 0)
) {
  throw new Error('npm audit did not return a complete vulnerability report');
}

const observedCounts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
const rejected = [];
for (const [name, vulnerability] of Object.entries(report.vulnerabilities)) {
  if (!vulnerability || !Object.hasOwn(observedCounts, vulnerability.severity)
      || vulnerability.severity === 'total' || !Array.isArray(vulnerability.via)) {
    throw new Error(`malformed vulnerability entry: ${name}`);
  }
  observedCounts[vulnerability.severity] += 1;
  observedCounts.total += 1;
  if (['high', 'critical'].includes(vulnerability.severity)
      || vulnerability.via.some((cause) => cause && typeof cause === 'object'
        && ['high', 'critical'].includes(cause.severity))) {
    rejected.push(name);
  }
}
if (Object.keys(observedCounts).some((level) => counts[level] !== observedCounts[level])) {
  throw new Error('npm audit summary does not match its vulnerability entries');
}
if (rejected.length > 0) {
  throw new Error(`unaccepted high or critical toolchain advisories: ${rejected.join(', ')}`);
}

console.log('DTC TOOLCHAIN AUDIT: PASS with no high or critical advisories and no exceptions; production graph is checked separately');
