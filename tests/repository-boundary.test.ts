// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { findRepositoryBoundaryViolations } from '../scripts/check-repository-boundary.js';

describe('public/private repository boundary', () => {
  it('refuses canonical private paths and confidential document names', () => {
    expect(findRepositoryBoundaryViolations([
      'docs/strategy-private/buyer-map.md',
      'docs/ip/invention-disclosure.md',
      'docs/random/seed-private-deck.pptx',
      'docs/TARGET-LIST-AND-OUTREACH.md',
    ])).toEqual([
      'docs/TARGET-LIST-AND-OUTREACH.md',
      'docs/ip/invention-disclosure.md',
      'docs/random/seed-private-deck.pptx',
      'docs/strategy-private/buyer-map.md',
    ]);
  });

  it('refuses named government meeting briefings', () => {
    expect(findRepositoryBoundaryViolations([
      'docs/briefs/CALIFORNIA-VERIFIABLE-AI-OVERSIGHT-BRIEFING.md',
    ])).toEqual([
      'docs/briefs/CALIFORNIA-VERIFIABLE-AI-OVERSIGHT-BRIEFING.md',
    ]);
  });

  it('allows public standards, evidence, product documentation, and application routes', () => {
    expect(findRepositoryBoundaryViolations([
      'standards/staged/draft-schrock-action-evidence-boundary-00.xml',
      'docs/strategy/PRODUCT-MESSAGE-ARCHITECTURE.md',
      'docs/compliance/AIUC-1-EMILIA-EVIDENCE-CROSSWALK.md',
      'docs/REPOSITORY-BOUNDARIES.md',
      'app/investors/page.tsx',
    ])).toEqual([]);
  });
});
