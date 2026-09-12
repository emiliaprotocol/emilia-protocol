// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  findPublicKernelSemanticViolations,
  findRepositoryBoundaryViolations,
} from '../scripts/check-repository-boundary.js';

describe('public/private repository boundary', () => {
  it('keeps the operated Works app, tests and migrations in the private company repository', () => {
    const files = [
      'app/works/page.tsx', 'app/api/works/account/route.ts',
      'lib/works/accounts.ts', 'docs/works/deployment.md',
      'tests/works-account.test.ts', 'commercial/emilia-score/server.mjs',
      'supabase/migrations/20260912000000_works_accounts.sql',
      'e2e/marketplace-entry.spec.ts', 'scripts/prepare-works-authority-scan.mjs',
      'scripts/verify-works-operating-postgres.mjs',
      'public/marketplace-tool-inspection-v1.webp',
    ];
    expect(findRepositoryBoundaryViolations(files)).toEqual([...files].sort());
    expect(findRepositoryBoundaryViolations(['./app/works/page.tsx', 'lib\\works\\store.ts']))
      .toEqual(['app/works/page.tsx', 'lib/works/store.ts']);
  });

  it('allows open plugin discovery, compatibility badges and shared database safeguards', () => {
    expect(findRepositoryBoundaryViolations([
      '.claude-plugin/marketplace.json', 'public/badge/works-with-emilia.svg',
      'packages/gate/index.js', 'packages/scan/index.js',
      'supabase/migration-history.v1.json', 'scripts/db-contract.manifest.mts',
      'components/workforce/WorkforceStory.tsx',
    ])).toEqual([]);
  });

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
