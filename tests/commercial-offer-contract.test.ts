// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const pricing = readFileSync(resolve(ROOT, 'app/pricing/page.tsx'), 'utf8');
const commercialOffer = readFileSync(resolve(ROOT, 'lib/commercial-offer.ts'), 'utf8');
const pilot = readFileSync(resolve(ROOT, 'app/pilot/page.tsx'), 'utf8');
const pilotMetadata = readFileSync(resolve(ROOT, 'app/pilot/layout.tsx'), 'utf8');
const intake = readFileSync(resolve(ROOT, 'app/api/pilot/request/route.ts'), 'utf8');
const navigation = readFileSync(resolve(ROOT, 'components/SiteNav.tsx'), 'utf8');

describe('commercial offer contract', () => {
  it('has one diagnostic entry offer and a coherent Gate expansion ladder', () => {
    expect(pricing).toContain('MANAGED_PILOT');
    expect(pricing).toContain('GATE_IMPLEMENTATION');
    expect(pricing).toContain('PRODUCTION_GATE');
    expect(pricing).toContain('Amelia I');
    expect(commercialOffer).toContain('$150K');
    expect(commercialOffer).toContain('$250K');
    expect(commercialOffer).toContain('$500K');
    expect(pricing).not.toContain("price: '$499'");
    expect(pricing).not.toContain('Gate Cloud is in early access');
  });

  it('uses the shared pilot offer in every buyer-facing path', () => {
    expect(pilot).toContain("from '@/lib/commercial-offer'");
    expect(intake).toContain("from '@/lib/commercial-offer'");
    expect(pilot).not.toContain("['4 weeks'");
    expect(pilot).not.toContain("['Free'");
    expect(intake).not.toContain('4 weeks, free');
    expect(pilotMetadata).not.toContain('Four Weeks');
    expect(pilotMetadata).not.toContain('Free');
    expect(navigation).not.toContain('href="/partners" className="ep-cta-secondary"');
  });

  it('prices production by protected workflow rather than seats or API calls', () => {
    expect(pricing).toContain('protected workflow');
    expect(pricing).toContain('deployment boundary');
    expect(pricing).toContain('service level');
  });
});
