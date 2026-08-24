// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const root = process.cwd();
const read = (relativePath: string): string =>
  fs.readFileSync(path.join(root, relativePath), 'utf8');

describe('Trust Desk archive boundary', () => {
  it('closes public intake and exposes no order, upload, payment, or checkout path', () => {
    const page = read('app/trust-desk/page.tsx');
    const intake = read('app/trust-desk/upload/page.tsx');
    const publicRoutes = `${page}\n${intake}`;

    expect(page).toContain('AI Trust Desk is archived as a product evaluation');
    expect(page).toContain('not a current commercial service or a second EMILIA offer');
    expect(intake).toContain('Trust Desk intake is closed');
    expect(intake).toMatch(/no\s+longer accepts files, questionnaire submissions, orders, or payments/);
    expect(publicRoutes).not.toContain('NEXT_PUBLIC_STRIPE_');
    expect(publicRoutes).not.toContain('/api/trust-desk/intake');
    expect(publicRoutes).not.toContain('redirecting to checkout');
    expect(publicRoutes).not.toMatch(/\$3,500|\$18,000|\$35,000|\$45,000/);
  });

  it('is deindexed and does not publish current Service or Offer structured data', () => {
    const layout = read('app/trust-desk/layout.tsx');

    expect(layout).toContain('robots: { index: false, follow: false, nocache: true }');
    expect(layout).toContain('not a current commercial EMILIA offer');
    expect(layout).not.toContain("'@type': 'Service'");
    expect(layout).not.toContain("'@type': 'Offer'");
    expect(layout).not.toContain('dangerouslySetInnerHTML');
  });

  it('keeps historical source non-routed and explicitly non-importable', () => {
    const offerArchive = read('app/trust-desk/_archive/legacy-offer-page.tsx');
    const uploadArchive = read('app/trust-desk/_archive/legacy-upload-page.tsx');

    expect(offerArchive).toContain('Archived, non-routed evaluation source. Do not import into a public route.');
    expect(uploadArchive).toContain('Archived, non-routed evaluation source. Do not import into a public route.');
  });
});
