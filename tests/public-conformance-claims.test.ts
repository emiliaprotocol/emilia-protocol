// SPDX-License-Identifier: Apache-2.0
import { auditClaimText, auditProfileSuites } from '../scripts/check-public-conformance-claims.mjs';

describe('public conformance claim guard', () => {
  it('accepts the current evidence boundary', () => {
    const text = 'Three same-team ports agree over 17 conformance suites and 193 vectors. The external Rust verifier passes the pinned 16-suite/164-vector clean-room bundle; strict independent construction attestation remains pending.';
    expect(auditClaimText(text, 'current.md', {
      suites: 17, vectors: 193, externalSuites: 16, externalVectors: 164,
      tests: 5334, testFiles: 264,
    })).toEqual([]);
  });

  it('refuses inflation of the externally pinned corpus', () => {
    const text = 'The external Rust verifier passes the pinned 17-suite/193-vector clean-room bundle.';
    const findings = auditClaimText(text, 'external-overclaim.md', {
      suites: 17, vectors: 193, externalSuites: 16, externalVectors: 164,
      tests: 5334, testFiles: 264,
    });
    expect(findings.map((item) => item.message)).toEqual([
      'externally pinned conformance suite count is 16',
      'externally pinned conformance vector count is 164',
    ]);
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
  it('refuses advertising Python or Go expression agreement as structured AEC conformance', () => {
    const counts = { suites: 21, vectors: 340, tests: 5334, testFiles: 264 };
    for (const text of [
      'The Python and Go ports implement the structured AEC -07/-08 requirement and replay contract.',
      'Go conforms to the structured requirement contract.',
      'Python passes the structured AEC replay vectors.',
    ]) {
      const findings = auditClaimText(text, 'overclaim.md', counts);
      expect(findings.map((item) => item.message), text).toEqual([
        'Python and Go implement AEC requirement-expression evaluation only, not the structured requirement and replay contract',
      ]);
    }
    expect(auditClaimText('Python and Go do not implement the structured AEC requirement and replay contract.', 'ok.md', counts)).toEqual([]);
    expect(auditClaimText('Python and Go agree on requirement-expression evaluation.', 'ok.md', counts)).toEqual([]);
  });

  it('keeps profile suites recorded, scoped, run by every port, and outside the live totals', () => {
    const registry = [{ file: 'aec-expression.v1.json', claim_scope: 'Expression only; not conformance to the structured contract.' }];
    const manifest = {
      suites: [{ path: 'conformance/vectors/a.json', vectors: 3 }],
      totals: { suites: 1, vectors: 3 },
      profile_suites: [{ path: 'conformance/vectors/aec-expression.v1.json', vectors: 5, claim_scope: registry[0].claim_scope }],
      implementations: [{ implementation_id: 'js', profile_vectors: 5 }, { implementation_id: 'go', profile_vectors: 5 }],
    };
    expect(auditProfileSuites(manifest, registry)).toEqual([]);
    expect(auditProfileSuites({ ...manifest, totals: { suites: 2, vectors: 8 } }, registry))
      .toContain('live totals must count exactly the live suites; profile suites stay outside them');
    expect(auditProfileSuites({ ...manifest, profile_suites: [] }, registry))
      .toContain('profile suite aec-expression.v1.json is not recorded in the conformance manifest');
    expect(auditProfileSuites({ ...manifest, implementations: [{ implementation_id: 'go', profile_vectors: 4 }] }, registry))
      .toContain('go did not run every profile vector');
    expect(auditProfileSuites(manifest, [{ file: 'aec-expression.v1.json', claim_scope: 'Expression conformance.' }]))
      .toContain('profile suite aec-expression.v1.json must say expression agreement is not structured AEC conformance');
  });
});
