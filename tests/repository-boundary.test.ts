// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  findPublicKernelSemanticViolations,
  findRepositoryBoundaryViolations,
} from '../scripts/check-repository-boundary.js';

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

  it('keeps commercial strategy and merchandising out of public Claim Assurance kernel paths', () => {
    expect(findPublicKernelSemanticViolations([
      {
        path: 'packages/verify/src/claim-assurance.ts',
        content: 'Competitor comparison. Private equity portfolio authority pricing.',
      },
      {
        path: 'examples/claim-assurance-reference/README.md',
        content: 'Hosted registry, Trust Center, catalogue, and certification mark.',
      },
    ])).toEqual([
      'examples/claim-assurance-reference/README.md:commercial_concept:catalogue_merchandising',
      'examples/claim-assurance-reference/README.md:commercial_concept:certification_ownership',
      'examples/claim-assurance-reference/README.md:commercial_concept:operated_product_family',
      'packages/verify/src/claim-assurance.ts:commercial_concept:commercial_terms',
      'packages/verify/src/claim-assurance.ts:commercial_concept:named_competitor_strategy',
      'packages/verify/src/claim-assurance.ts:commercial_concept:private_capital_strategy',
    ]);
  });

  it('allows neutral kernel semantics and does not scan unrelated public surfaces', () => {
    expect(findPublicKernelSemanticViolations([
      {
        path: 'packages/gate/src/claim-assurance.ts',
        content: 'VERIFIED evidence remains non-authorizing and exact-action bound.',
      },
      {
        path: 'app/pricing/page.tsx',
        content: 'Public product catalogue and pricing.',
      },
    ])).toEqual([]);
  });
});
