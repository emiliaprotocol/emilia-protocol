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
  it('has one canonical protected-workflow pilot and a coherent Gate expansion ladder', () => {
    expect(pricing).toContain('PROTECTED_WORKFLOW_PILOT');
    expect(pricing).toContain('GATE_IMPLEMENTATION');
    expect(pricing).toContain('PRODUCTION_GATE');
    expect(commercialOffer.match(/durationDays: 90/g)).toHaveLength(1);
    expect(commercialOffer.match(/priceUsd: 25_000/g)).toHaveLength(1);
    expect(commercialOffer).not.toContain('MANAGED_PILOT');
    expect(commercialOffer).not.toContain('FINANCIAL_AUTHORITY_DESIGN_PARTNER');
    expect(commercialOffer).not.toContain('AGENT_ADOPTION_DESIGN_PARTNER');
    expect(commercialOffer).toContain('$150K');
    expect(commercialOffer).toContain('$250K');
    expect(commercialOffer).toContain('$500K');
    expect(pricing).not.toContain("price: '$499'");
    expect(pricing).not.toContain('Gate Cloud is in early access');
  });

  it('uses the shared canonical pilot offer in every buyer-facing path', () => {
    expect(pilot).toContain("from '@/lib/commercial-offer'");
    expect(intake).toContain("from '@/lib/commercial-offer'");
    expect(pilot).toContain('PROTECTED_WORKFLOW_PILOT');
    expect(intake).toContain('PROTECTED_WORKFLOW_PILOT');
    expect(pilot).not.toContain("['4 weeks'");
    expect(pilot).not.toContain("['Free'");
    expect(intake).not.toContain('4 weeks, free');
    expect(pilotMetadata).not.toContain('Four Weeks');
    expect(pilotMetadata).not.toContain('Free');
    expect(navigation).not.toContain('href="/partners" className="ep-cta-secondary"');
  });

  it('prices production by protected workflow rather than seats or API calls', () => {
    const publicOffer = `${pricing}\n${commercialOffer}`;
    expect(publicOffer).toContain('protected workflow');
    expect(publicOffer).toContain('deployment boundary');
    expect(publicOffer).toContain('service level');
  });

  it('defines one protected-workflow pilot with payer adverse determination as the first profile', () => {
    expect(commercialOffer).toContain("id: 'protected_workflow_pilot_v1'");
    expect(commercialOffer).toContain("name: 'Protected-workflow pilot'");
    expect(commercialOffer).toContain('durationDays: 90');
    expect(commercialOffer).toContain("workflowLabel: '1 protected workflow'");
  });

  it('names payer adverse determination first while keeping other workflows eligible', () => {
    expect(commercialOffer).toContain("firstProfileLabel: 'Payer adverse medical-necessity determination'");
    expect(commercialOffer).toContain("safetyRuleLabel: 'No valid licensed-review evidence, no adverse determination'");
    expect(pilot).toContain('Other consequential workflows remain eligible');
    expect(pilot).toContain('payer_adverse_determination');
    expect(intake).toContain('payer_adverse_determination');
  });
});
