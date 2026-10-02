// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { proofStatsTestArgs, securityCaseExecutionArgs } from '../scripts/generate-proof-stats.mjs';

describe('proof-stat security evidence refresh', () => {
  const executedCase = [
    '--import',
    './scripts/ts-loader/register.mjs',
    'scripts/verify-security-case.mjs',
    '--execute',
  ];

  it('writes the case from the same live execution used to refresh statistics', () => {
    expect(securityCaseExecutionArgs(false)).toEqual([
      ...executedCase, '--emit', 'security/security-case.json',
    ]);
  });

  it('keeps check mode executable and read-only rather than repairing stale evidence', () => {
    expect(securityCaseExecutionArgs(true)).toEqual(executedCase);
  });

  it('passes a drift report to the live case only in check mode, never to the writer', () => {
    // check:proof-stats -- --drift-report is the pull-request mode: the live
    // case reports lagging derived digests instead of failing on them, as CI's
    // security-case job does on a pull request. Without a report it stays
    // byte-exact, and the writer always re-emits the whole case.
    expect(securityCaseExecutionArgs(true, '/tmp/security-case-drift.json')).toEqual([
      ...executedCase, '--drift-report', '/tmp/security-case-drift.json',
    ]);
    expect(securityCaseExecutionArgs(false, '/tmp/security-case-drift.json')).toEqual([
      ...executedCase, '--emit', 'security/security-case.json',
    ]);
    expect(securityCaseExecutionArgs(true, undefined)).toEqual(executedCase);
  });

  it('does not let mutations of a returned command affect a later check', () => {
    securityCaseExecutionArgs(false).push('--security-case-preverified');
    expect(securityCaseExecutionArgs(true)).toEqual(executedCase);
  });

  it('can enforce coverage in the same complete run without changing the inventory or budgets', () => {
    const normal = proofStatsTestArgs('/tmp/report.json');
    expect(normal).toEqual([
      'vitest', 'run', '--silent', '--maxWorkers=4', '--testTimeout=60000',
      '--hookTimeout=60000', '--reporter=json', '--outputFile=/tmp/report.json',
    ]);
    expect(proofStatsTestArgs('/tmp/report.json', true)).toEqual([...normal, '--coverage']);
  });
});
