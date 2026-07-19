// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..');
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), 'utf8');

describe('public engineering evidence surface', () => {
  it('publishes one canonical, extractable proof page backed by generated evidence', () => {
    const page = read('app/proof/page.js');
    const layout = read('app/proof/layout.js');

    expect(page).toContain("proofStats from '@/lib/proof-stats.json'");
    expect(page).toContain("claimSource from '@/security/claims.v1.json'");
    expect(page).toContain('Security claims you can execute, not architecture you have to trust.');
    expect(page).toContain('Hostile-network composition');
    expect(page).toContain('Stateful enforcement under faults');
    expect(page).toContain('What this evidence does not establish.');
    expect(page).toContain('application/ld+json');
    expect(layout).toContain('Machine-Verifiable Security Case');
  });

  it('makes the proof page discoverable from high-authority site surfaces', () => {
    expect(read('app/HomePageClient.js')).toContain('href="/proof"');
    expect(read('app/security/page.js')).toContain('href="/proof"');
    expect(read('components/SiteFooter.js')).toContain("['/proof', 'Engineering Evidence']");
    expect(read('app/sitemap.js')).toContain("{ path: '/proof'");
    expect(read('app/gate/layout.js')).toContain("url: 'https://www.emiliaprotocol.ai/proof'");
    expect(read('README.md')).toContain('www.emiliaprotocol.ai/proof');
  });
});
