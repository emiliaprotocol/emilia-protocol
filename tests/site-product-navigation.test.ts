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
      ['/authority-brain', '/map'],
      ['/gate', '/gate'],
      ['/use-cases', '/solutions'],
      ['/docs', '/developers'],
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
