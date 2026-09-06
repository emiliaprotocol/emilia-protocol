// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { securityCaseExecutionArgs } from '../scripts/generate-proof-stats.mjs';

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

  it('does not let mutations of a returned command affect a later check', () => {
    securityCaseExecutionArgs(false).push('--security-case-preverified');
    expect(securityCaseExecutionArgs(true)).toEqual(executedCase);
  });
});
