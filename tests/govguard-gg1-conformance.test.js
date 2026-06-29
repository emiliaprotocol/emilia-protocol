// SPDX-License-Identifier: Apache-2.0
// GovGuard GG-1 conformance — the public badge is earned by this CI check.

import { describe, expect, it } from 'vitest';
import { GG1_CHECKS } from '../lib/govguard-evidence-packet.js';
import { runGovGuardGg1Reference } from '../lib/govguard-gg1.js';

describe('GovGuard GG-1 conformance', () => {
  it('earns GG-1 across the complete government-fraud control checklist', () => {
    const report = runGovGuardGg1Reference();
    expect(report.standard).toBe('GG-1');
    expect(report.passed).toBe(true);
    expect(report.badge).toBe('GG-1 Enforced');
    expect(report.summary).toEqual({ passed: GG1_CHECKS.length, total: GG1_CHECKS.length });
    expect(report.checks.map((c) => c.id)).toEqual(GG1_CHECKS.map((c) => c.id));
  });
});
