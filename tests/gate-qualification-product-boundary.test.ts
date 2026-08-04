// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');
const BOUNDARY = 'Qualification travels. Authorization stays local. Gate controls the consequence.';

describe('Gate Qualification v2 public product boundary', () => {
  it('uses one shared qualification boundary across the public product surfaces', () => {
    const commercialOffer = read('lib/commercial-offer.ts');
    const productBrief = read('docs/EMILIA-GATE-PRODUCT-BRIEF.md');
    const productSurfaces = [
      'app/HomePageClient.tsx',
      'app/gate/page.tsx',
      'app/pricing/page.tsx',
      'app/proof/page.tsx',
    ].map(read);

    expect(commercialOffer).toContain(BOUNDARY);
    expect(productBrief).toContain(BOUNDARY);
    for (const surface of productSurfaces) {
      expect(surface).toContain("from '@/lib/commercial-offer'");
      expect(surface).toContain('GATE_QUALIFICATION.boundaryLine');
      expect(surface).toContain('GATE_QUALIFICATION.disclaimer');
    }
  });

  it('keeps qualification distinct from authorization, certification, and deployment', () => {
    const commercialOffer = read('lib/commercial-offer.ts');
    const gate = read('app/gate/page.tsx');
    const proof = read('app/proof/page.tsx');
    const productBrief = read('docs/EMILIA-GATE-PRODUCT-BRIEF.md');

    expect(commercialOffer).toContain('Qualification is not authorization, certification, deployment evidence');
    expect(gate).toContain('A <code>QUALIFIED</code> result is evidence the local');
    expect(gate).toContain('cannot reserve resources, call a provider');
    expect(proof).toContain('no separate qualification count is hand-maintained');
    expect(proof).toContain('proofStats.generatedAt');
    expect(productBrief).toContain('It does not mean `AUTHORIZED`');
    expect(productBrief).toContain('durable operated integration remains deployment work');
  });

  it('presents Operated Gate only as a deployment-specific quote', () => {
    const commercialOffer = read('lib/commercial-offer.ts');
    const homepage = read('app/HomePageClient.tsx');
    const gate = read('app/gate/page.tsx');
    const pricing = read('app/pricing/page.tsx');
    const investors = read('app/investors/page.tsx');

    expect(commercialOffer).toContain('deployment-specific quote by protected workflow and operating boundary');
    expect(commercialOffer).toContain('not a generally available live service');
    expect(pricing).toContain('PRODUCTION_GATE.scopeLabel');
    expect(pricing).toContain('PRODUCTION_GATE.availabilityLabel');
    expect(pricing).toContain("cta: { label: 'Scope a deployment'");
    expect(investors).toContain('PRODUCTION_GATE.priceLabel');
    expect(investors).toContain('operated Gate follow only after the boundary is accepted');
    expect(homepage).not.toContain('Open the live Gate');
    expect(gate).not.toContain('Open live Gate');
  });
});
