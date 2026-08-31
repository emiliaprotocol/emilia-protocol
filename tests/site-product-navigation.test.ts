// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

describe('public product naming and navigation contract', () => {
  it('keeps every top-navigation destination with a slash-form label', () => {
    const navigation = read('components/SiteNav.tsx');
    const expectedLinks = [
      ['/products', '/products'],
      ['/use-cases', '/solutions'],
      ['/docs', '/developers'],
      ['/proof', '/proof'],
      ['/protocol', '/protocol'],
      ['/pricing', '/pricing'],
    ];
    for (const [href, label] of expectedLinks) {
      expect(navigation).toContain(`[\'${href}\', \'${label}\']`);
    }
    for (const promotedExperiment of ['/signal', '/assurance', '/grace', '/model-to-matter']) {
      expect(navigation).not.toContain(`[\'${promotedExperiment}\', \'${promotedExperiment}\']`);
    }
  });

  it('groups the buyer-facing product system under the products navigation item', () => {
    const navigation = read('components/SiteNav.tsx');

    expect(navigation).toContain("'authority-brain'");
    expect(navigation).toContain("'approver'");
    expect(navigation).toContain("'assurance'");
    expect(navigation).toContain("href === '/products'");
    expect(read('app/product/accountable-signoff/page.tsx')).toContain('activePage="approver"');
  });

  it('makes the self-service protection path discoverable and gives it an activation handoff', () => {
    const homepage = read('app/HomePageClient.tsx');
    const sitemap = read('app/sitemap.ts');
    const builder = read('app/protect/ProtectionBuilder.tsx');
    const activationCli = read('packages/gate/bin/ep-protect.mts');
    const gatePackage = JSON.parse(read('packages/gate/package.json')) as { version: string };

    expect(homepage).toContain('href="/products"');
    expect(read('app/products/page.tsx')).toContain('ProductStoryHub');
    expect(sitemap).toContain("{ path: '/protect'");
    expect(sitemap).toContain("{ path: '/products'");
    expect(builder).toContain('ep-protect activate');
    expect(builder).toContain("import gatePackage from '../../packages/gate/package.json'");
    expect(builder).toContain('@emilia-protocol/gate@{gatePackage.version}');
    expect(gatePackage.version).toBe('0.24.0');
    expect(builder).not.toContain('@emilia-protocol/gate@0.23.17');
    expect(builder).toContain('customer-owned-mcp-gateway');
    expect(activationCli).toContain('activateProtectionPlan');
    expect(activationCli).toContain('signProtectionActivation');
  });

  it('keeps stable entry points for the renamed products', () => {
    expect(read('app/signal/page.tsx')).toContain('EMILIA Signal');
    expect(read('app/model-to-matter/layout.tsx')).toContain("canonical: '/model-to-matter'");
    const redirects = read('next.config.js');
    expect(redirects).toContain("source: '/m2m', destination: '/model-to-matter'");
    expect(redirects).toContain("source: '/amelia-i', destination: '/signal'");
  });

  it('does not expose the retired Amelia I or Amelia Grip names in buyer-facing source', () => {
    const buyerFacing = [
      'app/HomePageClient.tsx',
      'app/health/program-integrity/page.tsx',
      'app/health/program-integrity/_components/ProgramIntegrityGate.tsx',
      'app/pilot/page.tsx',
      'app/pilot/layout.tsx',
      'app/pricing/page.tsx',
      'lib/commercial-offer.ts',
    ].map(read).join('\n');
    expect(buyerFacing).not.toMatch(/Amelia I|Amelia Grip/);
    expect(buyerFacing).toContain('EMILIA Signal');
  });
});
