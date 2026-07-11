// SPDX-License-Identifier: Apache-2.0
import { auditClaimText } from '../scripts/check-public-conformance-claims.mjs';

describe('public conformance claim guard', () => {
  it('accepts the current evidence boundary', () => {
    const text = 'Three same-team ports agree over 16 conformance suites and 163 vectors. The external Rust verifier passes all 163 current vectors; strict independent construction attestation remains pending.';
    expect(auditClaimText(text, 'current.md', { suites: 16, vectors: 163, tests: 5334, testFiles: 264 })).toEqual([]);
  });

  it('refuses independence inflation for same-team ports', () => {
    const findings = auditClaimText('Three independent verifiers (JS/Python/Go) agree.', 'overclaim.md', { suites: 16, vectors: 163, tests: 5334, testFiles: 264 });
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toMatch(/must not be described as independent/);
  });

  it('refuses stale suite and vector counts', () => {
    const findings = auditClaimText('8 conformance suites over all 162 published vectors.', 'stale.md', { suites: 16, vectors: 163, tests: 5334, testFiles: 264 });
    expect(findings.map((item) => item.message)).toEqual([
      'current conformance suite count is 16',
      'current conformance vector count is 163',
    ]);
  });

  it('refuses the obsolete underway status', () => {
    const findings = auditClaimText('A genuinely independent clean-room reimplementation is underway.', 'status.md', { suites: 16, vectors: 163, tests: 5334, testFiles: 264 });
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toMatch(/external Rust implementation now exists/);
  });

  it('does not confuse independent devices with independent implementations', () => {
    expect(auditClaimText('The test drives three independent virtual authenticators.', 'devices.md', { suites: 16, vectors: 163, tests: 5334, testFiles: 264 })).toEqual([]);
  });

  it('accepts an explicit denial of the overclaim', () => {
    expect(auditClaimText('These are not three independent implementations.', 'honesty.md', { suites: 16, vectors: 163, tests: 5334, testFiles: 264 })).toEqual([]);
  });

  it('refuses stale automated-test and file counts', () => {
    const findings = auditClaimText('4,689 automated tests across 226 files.', 'stale-tests.md', {
      suites: 16, vectors: 163, tests: 5334, testFiles: 264,
    });
    expect(findings.map((item) => item.message)).toEqual([
      'current automated-test case count is 5334',
      'current automated-test file count is 264',
    ]);
  });

  const floorExpectations = { suites: 16, vectors: 163, tests: 5334, testFiles: 264 };

  it('accepts a floor stated with a "+" suffix that the true count exceeds', () => {
    expect(auditClaimText('5,000+ automated test cases across 250+ files.', 'floor.md', floorExpectations)).toEqual([]);
    expect(auditClaimText('| Automated test cases | 5,000+ across 250+ files |', 'table.md', floorExpectations)).toEqual([]);
  });

  it('accepts a floor stated with a floor word ("over N") that the true count exceeds', () => {
    expect(auditClaimText('over 5,000 automated test cases across 250+ files.', 'floor-word.md', floorExpectations)).toEqual([]);
  });

  it('still refuses a floor the true count does NOT meet (overstatement is caught)', () => {
    const findings = auditClaimText('6,000+ automated test cases across 300+ files.', 'toohigh.md', floorExpectations);
    expect(findings.map((item) => item.message)).toEqual([
      'current automated-test case count is 5334',
      'current automated-test file count is 264',
    ]);
  });

  it('still requires an exact bare number to match exactly', () => {
    expect(auditClaimText('5,334 automated test cases across 264 files.', 'exact-ok.md', floorExpectations)).toEqual([]);
  });
});
