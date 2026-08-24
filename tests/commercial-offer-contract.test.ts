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
const govGuard = readFileSync(resolve(ROOT, 'app/govguard/page.tsx'), 'utf8');
const finGuard = readFileSync(resolve(ROOT, 'app/finguard/page.tsx'), 'utf8');
const home = readFileSync(resolve(ROOT, 'app/HomePageClient.tsx'), 'utf8');
const staticLanding = readFileSync(resolve(ROOT, 'content/landing.html'), 'utf8');
const publicStaticLanding = readFileSync(resolve(ROOT, 'public/landing.html'), 'utf8');
const publicLegacyIndex = readFileSync(resolve(ROOT, 'public/index.html'), 'utf8');
const sitemap = readFileSync(resolve(ROOT, 'app/sitemap.ts'), 'utf8');
const assuranceBrief = readFileSync(resolve(ROOT, 'docs/EMILIA-ASSURANCE-PRODUCT-BRIEF.md'), 'utf8');
const programIntegrity = readFileSync(
  resolve(ROOT, 'app/health/program-integrity/_components/ProgramIntegrityGate.tsx'),
  'utf8',
);

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
    const conversionSurfaces = `${pilotMetadata}\n${govGuard}\n${finGuard}\n${programIntegrity}`;
    expect(conversionSurfaces).not.toMatch(/60[- ]day|60 days/i);
    expect(conversionSurfaces).toContain('90-day protected-workflow pilot');
    expect(conversionSurfaces).toContain('$25K');
    expect(programIntegrity).toContain('href="/pilot?v=health"');
  });

  it('accepts and returns to every server-supported public record id', () => {
    expect(pilot).toContain('(?:arena_share|agent_share|agent_record)_[0-9a-f]{40}');
    expect(pilot).toContain('arena_share_…, agent_share_…, or agent_record_…');
    expect(pilot).toContain("`/arena/r/${encoded}`");
    expect(pilot).toContain("`/adopt/r/${encoded}`");
    expect(pilot).toContain("`/agent-record/r/${encoded}`");
  });

  it('prices production by protected workflow rather than seats or API calls', () => {
    const publicOffer = `${pricing}\n${commercialOffer}`;
    expect(publicOffer).toContain('protected workflow');
    expect(publicOffer).toContain('deployment boundary');
    expect(publicOffer).toContain('service level');
  });

  it('defines one protected-workflow pilot with finance operations as the first profile', () => {
    expect(commercialOffer).toContain("id: 'protected_workflow_pilot_v1'");
    expect(commercialOffer).toContain("name: 'Protected-workflow pilot'");
    expect(commercialOffer).toContain('durationDays: 90');
    expect(commercialOffer).toContain("workflowLabel: '1 assessed consequence boundary'");
    expect(commercialOffer).toContain('Synthetic, read-only, sandbox, or shadow validation only');
    expect(commercialOffer).toContain('any production activation is a separately scoped Gate Implementation');
  });

  it('names the finance boundary first while keeping other workflows eligible', () => {
    expect(commercialOffer).toContain("firstProfileLabel: 'Finance operations vendor bank-detail change or payment release'");
    expect(commercialOffer).toContain("safetyRuleLabel: 'No accepted exact-action authority and required evidence, no provider entry'");
    expect(pilot).toMatch(/Other\s+consequential workflows remain eligible/);
    expect(pilot).toContain("workflow: 'beneficiary_change'");
    expect(pilot).toContain('Vendor / beneficiary bank-detail change · first finance profile');
    expect(pilot).toContain('payer_adverse_determination');
    expect(intake).toContain('payer_adverse_determination');
    expect(finGuard).toContain('PROTECTED_WORKFLOW_PILOT.durationLabel');
    expect(finGuard).not.toContain('Pilot in 30 days');
    expect(home).toContain('Vendor bank-detail changes and payment releases');
    expect(home).not.toContain('Payer adverse medical-necessity determinations contain');
    expect(assuranceBrief).toContain('Finance Operations Assurance');
    expect(assuranceBrief).not.toContain('Adverse Determination Assurance');
  });

  it('keeps legacy static landing and discovery surfaces inside the same offer boundary', () => {
    for (const landing of [staticLanding, publicStaticLanding]) {
      expect(landing).toContain('one $25K, 90-day nonproduction Protected-workflow pilot');
      expect(landing).not.toMatch(/Request (government|financial|enterprise|agent) pilot/i);
      expect(landing).not.toContain('Managed control plane with observability');
      expect(landing).not.toContain('Private deployment with dedicated infrastructure, SLAs');
      expect(landing).not.toMatch(/full audit trail|legal defensibility|Every state transition logged|immutable audit chain/i);
    }
    expect(publicLegacyIndex).toContain('no generally available service or SLA is claimed');
    expect(publicLegacyIndex).not.toMatch(/EMILIA Gate Cloud|Every state transition logged|legal defensibility|Request Pilot/i);
    expect(assuranceBrief).toContain('The only public paid offer is one `$25K`, 90-day, nonproduction');
    expect(assuranceBrief).not.toContain('## What customers can buy now');
    expect(sitemap).not.toContain("{ path: '/network'");
    expect(sitemap).not.toContain("{ path: '/trust-desk'");
  });
});
