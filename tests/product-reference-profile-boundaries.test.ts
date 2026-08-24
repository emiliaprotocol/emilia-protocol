// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

const ROUTES = [
  'cloud',
  'financial-pack',
  'government-pack',
  'agent-governance-pack',
  'accountable-signoff',
] as const;

const pages = Object.fromEntries(ROUTES.map((route) => [
  route,
  read(`app/product/${route}/page.tsx`),
])) as Record<(typeof ROUTES)[number], string>;

const layouts = Object.fromEntries(ROUTES.map((route) => [
  route,
  read(`app/product/${route}/layout.tsx`),
])) as Record<(typeof ROUTES)[number], string>;

describe('product reference-profile commercial boundary', () => {
  it('routes every commercial action to the canonical pilot or a separate implementation inquiry', () => {
    for (const page of Object.values(pages)) {
      expect(page).toContain("from '@/lib/commercial-offer'");
      expect(page).toContain('PROTECTED_WORKFLOW_PILOT');
      expect(page).toContain('GATE_IMPLEMENTATION');
      const hrefs = [...page.matchAll(/href="([^"]+)"/g)].map((match) => match[1]);
      expect(hrefs.length).toBeGreaterThan(0);
      expect(hrefs.every((href) => href.startsWith('/pilot') || href.startsWith('mailto:'))).toBe(true);
    }
    expect(pages['financial-pack']).toContain('href="/pilot?v=fin"');
    expect(pages.cloud).toContain('PRODUCTION_GATE.availabilityLabel');
  });

  it('removes route-specific pilots, access offers, and unlabeled inquiry forms', () => {
    const joined = Object.values(pages).join('\n');
    expect(joined).not.toMatch(/useState|\/api\/inquiries|<input|<textarea|href="#pilot"/);
    expect(joined).not.toMatch(/pilot-(cloud|financial-pack|government-pack|agent-governance-pack|accountable-signoff)/);
    expect(joined).not.toMatch(/Request Cloud Access|Request Financial Pilot|Request Government Pilot|Request Agent Governance Pilot|Pilot the Approver apps/i);
    expect(joined).not.toContain('/pilot/sandbox');
  });

  it('keeps the public pilot nonproduction and production implementation separate', () => {
    for (const page of Object.values(pages)) {
      expect(page).toMatch(/nonproduction|synthetic, sandbox/i);
      expect(page).toMatch(/provider credentials|production credentials/i);
      expect(page).toMatch(/separate(?:ly)?[\s\S]{0,120}(?:GATE_IMPLEMENTATION|Gate Implementation)|Gate Implementation[\s\S]{0,120}separate/i);
    }
    expect(pages['financial-pack']).toContain('does not receive provider credentials, release a payment, or change a bank record');
    expect(pages['agent-governance-pack']).toContain('permission to');
    expect(pages['agent-governance-pack']).toContain('mutate the buyer&apos;s systems');
  });

  it('recasts packs and Cloud as reference profiles with explicit shipped-status boundaries', () => {
    expect(pages['financial-pack']).toContain('Reference solution profile / Finance authority');
    expect(pages['government-pack']).toContain('Reference solution profile / Government authority');
    expect(pages['agent-governance-pack']).toContain('Reference solution profile / Agent action authority');
    expect(pages.cloud).toContain('Reference solution profile / Gate operations');
    expect(pages['accountable-signoff']).toContain('Gate capture surface / Approver reference apps');
    expect(pages.cloud).toContain('not generally available as an operated service');
    expect(pages['accountable-signoff']).toContain('not a standalone');
    expect(pages['government-pack']).toContain('Designed or future scope');
    expect(pages['agent-governance-pack']).toContain('Designed profiles, not shipped defaults');
  });

  it('removes compliance, prevention, speed-to-deploy, managed-availability, and adoption overclaims', () => {
    const joined = Object.values(pages).join('\n');
    expect(joined).not.toMatch(/SOX-ready|IG-ready|satisf(?:y|ies|ied) .*requirements|deploy(?:ed|ment)? (?:in )?weeks|we handle availability|live sanctions-list feeds .* connected|immutable evidence record/i);
    expect(joined).toContain('does not claim compliance');
    expect(joined).toContain('not deployment assurance');
    expect(joined).toContain('No evidenced integrated customer deployment');
    expect(joined).toContain('does not establish public app');
  });

  it('uses truthful route metadata and canonical URLs', () => {
    for (const route of ROUTES) {
      expect(layouts[route]).toContain(`canonical: '/product/${route}'`);
      expect(layouts[route]).toContain('robots: { index: true, follow: true }');
      expect(layouts[route]).toContain("type: 'website'");
      expect(layouts[route]).not.toMatch(/SOX-ready|fraud-control bundle|compliance pack|three-line SDK|managed consequence firewall/i);
    }
    expect(layouts['financial-pack']).toContain('Finance Authority Reference Profile');
    expect(layouts['government-pack']).toContain('Government Authority Reference Profile');
    expect(layouts['agent-governance-pack']).toContain('Agent Action Authority Reference Profile');
    expect(layouts.cloud).toContain('Gate Cloud Operations Profile');
    expect(layouts['accountable-signoff']).toContain('Approver Reference Apps');
  });
});
