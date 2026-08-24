// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  ASSURANCE_BOUNDARY_LINE,
  ASSURANCE_CATALOGUE,
  ASSURANCE_COMMERCIAL_ENTRY,
  TRUST_INDEX,
} from '../lib/assurance-catalog';
import { PROTECTED_WORKFLOW_PILOT } from '../lib/commercial-offer';

const ROOT = resolve(import.meta.dirname, '..');
const assurancePage = readFileSync(resolve(ROOT, 'app/assurance/page.tsx'), 'utf8');
const trustPage = readFileSync(resolve(ROOT, 'app/trust/page.tsx'), 'utf8');
const catalogueSource = readFileSync(resolve(ROOT, 'lib/assurance-catalog.ts'), 'utf8');
const footer = readFileSync(resolve(ROOT, 'components/SiteFooter.tsx'), 'utf8');
const sitemap = readFileSync(resolve(ROOT, 'app/sitemap.ts'), 'utf8');

describe('claim-to-consequence assurance catalogue', () => {
  it('separates implemented artifacts, scoped engagements, and non-operating surfaces', () => {
    expect(ASSURANCE_CATALOGUE.filter((item) => item.status === 'Implemented').map((item) => item.id)).toEqual([
      'open-verification',
      'claim-assurance-reference',
      'portable-records',
    ]);
    expect(ASSURANCE_CATALOGUE.filter((item) => item.status === 'Scoped engagement').map((item) => item.id)).toEqual([
      'deployment-assurance',
      'continuous-assurance',
    ]);
    expect(ASSURANCE_CATALOGUE.filter((item) => item.status === 'Not operating').map((item) => item.id)).toEqual([
      'registry-resolver',
      'certification-program',
    ]);
  });

  it('keeps claims, evidence, and authority separate in exact language', () => {
    expect(ASSURANCE_BOUNDARY_LINE).toBe(
      'Claims become evidence. Evidence can inform Gate. It never becomes authority by itself.',
    );
    expect(assurancePage).toContain('{ASSURANCE_BOUNDARY_LINE}');
    expect(assurancePage).toContain(
      'Synthetic or read-only evaluation is not production deployment, independent certification, or permission to act.',
    );
  });

  it('uses the one canonical protected-workflow offer without defining another assurance price', () => {
    expect(ASSURANCE_COMMERCIAL_ENTRY).toMatchObject({
      offerId: PROTECTED_WORKFLOW_PILOT.id,
      price: '$25K',
      duration: PROTECTED_WORKFLOW_PILOT.durationLabel,
      scope: PROTECTED_WORKFLOW_PILOT.workflowLabel,
    });
    expect((catalogueSource.match(/PROTECTED_WORKFLOW_PILOT\.shortPriceLabel/g) ?? [])).toHaveLength(1);
    expect(assurancePage).not.toMatch(/\$\d+[Kk]?/);
  });

  it('states the certification, mark, and hosted-service nonclaims', () => {
    expect(assurancePage).toContain('No public certification program or mark is operating today.');
    expect(assurancePage).toContain('No general-availability hosted assurance service is represented as deployed.');
    expect(trustPage).toContain('standard DPA or SLA, or deployed hosted assurance service is represented as');
  });

  it('indexes only the verified public procurement routes', () => {
    const hrefs = TRUST_INDEX.flatMap((group) => group.items.map((item) => item.href));
    expect(hrefs).toEqual([
      '/security',
      '/.well-known/security.txt',
      '/legal',
      '/legal/privacy',
      '/legal/terms',
      '/legal/sub-processors',
      'https://github.com/emiliaprotocol/emilia-protocol',
      '/proof',
      '/assurance',
      expect.stringMatching(/^\/assurance\/records\/sha256%3A[0-9a-f]{64}$/),
    ]);
    expect(existsSync(resolve(ROOT, 'public/.well-known/security.txt'))).toBe(true);
    expect(TRUST_INDEX.flatMap((group) => group.items).every((item) => (
      item.status === 'Published' || item.status === 'Public repository'
    ))).toBe(true);
  });

  it('makes the Trust Center discoverable in the footer and sitemap', () => {
    expect(footer).toContain("['/trust', 'Trust Center']");
    expect(sitemap).toContain("{ path: '/trust'");
    expect(sitemap).toContain('CLAIM_ASSURANCE_REFERENCE_PAGE_PATH');
  });
});
