// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');
const BOUNDARY = 'Qualification travels. Authorization stays local. Gate controls the consequence.';

describe('Gate Qualification v2 public product boundary', () => {
  it('uses the shared qualification boundary on Gate offer and proof surfaces, with a bounded workforce entry', () => {
    const commercialOffer = read('lib/commercial-offer.ts');
    const productBrief = read('docs/EMILIA-GATE-PRODUCT-BRIEF.md');
    const productSurfaces = [
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

    const homepage = read('app/HomePageClient.tsx');
    const workforce = read('components/workforce/WorkforceStory.tsx');
    expect(homepage).toContain('<WorkforceFoundation />');
    expect(homepage).toContain('href="/proof"');
    expect(homepage).toContain('Those are engineering results, not customer adoption or proof of a complete deployment.');
    expect(homepage).toContain('private local alpha using synthetic refunds');
    expect(workforce).toContain('href="/gate"');
    expect(workforce).toContain('Enforcement requires completely mediated paths through the credential-owning Gate.');
    expect(workforce).toContain('A signed receipt does not prove the job was done well.');
    for (const surface of [homepage, workforce]) {
      expect(surface).not.toContain('GATE_QUALIFICATION');
      expect(surface).not.toMatch(/qualification (?:authorizes|certifies)|QUALIFIED.*AUTHORIZED/);
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
    expect(pricing).toContain('price: PRODUCTION_GATE.priceLabel');
    expect(pricing).toContain('Evaluation terms are not yet set; the existing Gate offers below do not price this evaluation.');
    expect(investors).toContain('Your AI workforce needs management.');
    expect(investors).toContain('The proposed business is recurring software and operating support for protected work');
    expect(investors).toContain('Prices and willingness to pay need buyer validation.');
    expect(investors).toContain('The external team and provider are not yet selected. Evaluation terms are not yet set.');
    expect(investors.replace(/\s+/g, ' ')).toContain('The workforce workspace is a private local alpha.');
    expect(investors).toContain('currently claims no customer traction, recurring revenue, production deployment,');
    for (const surface of [homepage, investors]) {
      expect(surface).not.toContain("from '@/lib/commercial-offer'");
      expect(surface).not.toMatch(/PRODUCTION_GATE|PROTECTED_WORKFLOW_PILOT|\$250K|\$500K|\$25K|\$25,000/);
    }
    expect(homepage).not.toContain('Open the live Gate');
    expect(gate).not.toContain('Open live Gate');
  });
});
