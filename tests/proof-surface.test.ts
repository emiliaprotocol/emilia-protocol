// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..');
// Routes/pages/components are migrating .js -> .ts/.tsx file-by-file; read
// whichever extension actually exists on disk.
const read = (relative) => {
  const full = path.join(ROOT, relative);
  if (!fs.existsSync(full) && relative.endsWith('.js')) {
    for (const ext of ['.ts', '.tsx']) {
      const candidate = path.join(ROOT, `${relative.slice(0, -3)}${ext}`);
      if (fs.existsSync(candidate)) return fs.readFileSync(candidate, 'utf8');
    }
  }
  return fs.readFileSync(full, 'utf8');
};

describe('public engineering evidence surface', () => {
  it('publishes one canonical, extractable proof page backed by generated evidence', () => {
    const page = read('app/proof/page.js');
    const layout = read('app/proof/layout.js');

    expect(page).toMatch(/proofStats from ['"]@\/lib\/proof-stats\.json['"]/);
    expect(page).toMatch(/claimSource from ['"]@\/security\/claims\.v1\.json['"]/);
    expect(page).toContain('Security claims you can execute, not architecture you have to trust.');
    expect(page).toContain('Hostile-network composition');
    expect(page).toContain('Stateful enforcement under faults');
    expect(page).toContain('Executable evidence');
    expect(page).toContain('Formal model scope');
    expect(page).toContain('Verified formal obligations');
    expect(page).toContain('Bounded + selected runtime scenarios');
    expect(page).toContain('Bounded formal evidence');
    expect(page).toContain('Partial symbolic coverage');
    expect(page).toContain('Executable/operational evidence');
    expect(page).toContain('does not mean a refinement proof');
    expect(page).toContain('Acceptance roots, assumptions, exclusions, and exact evidence');
    expect(page).toContain('Exact claim manifest');
    expect(page).toContain('VERCEL_GIT_COMMIT_SHA');
    expect(page).toContain('Source revision:');
    expect(page).toContain('What this evidence does not establish.');
    expect(page).toContain('application/ld+json');
    expect(layout).toContain('Machine-Verifiable Security Case');
  });

  it('renders the five-way formal-evidence taxonomy from executed generated evidence', () => {
    const source = JSON.parse(read('security/claims.v1.json')) as {
      claims: Array<{ claim_id: string }>;
    };
    const stats = JSON.parse(read('lib/proof-stats.json'));
    const page = read('app/proof/page.js');

    const categories = Object.values(stats.formalEvidenceCoverage) as Array<{
      count: number;
      claimIds: string[];
    }>;
    expect(categories.reduce((total, category) => total + category.count, 0)).toBe(
      source.claims.length,
    );
    expect(
      categories.flatMap((category) => category.claimIds).sort(),
    ).toEqual(source.claims.map((claim) => claim.claim_id).sort());
    expect(page).toContain('proofStats.formalEvidenceCoverage[stats].claimIds');
    expect(page).toContain('Generated proof taxonomy does not cover the public claim inventory');
    expect(page).not.toContain('formalCoverage(claim.formal');
    expect(page).toContain('{proofStats.securityCase.claims}/{claimSource.claims.length}');
    for (const claim of source.claims) {
      expect(page).not.toContain(`'${claim.claim_id}'`);
      expect(page).not.toContain(`"${claim.claim_id}"`);
    }
  });

  it('makes the proof page discoverable from high-authority site surfaces', () => {
    expect(read('app/HomePageClient.js')).toContain('href="/proof"');
    expect(read('app/security/page.js')).toContain('href="/proof"');
    expect(read('components/SiteFooter.js')).toContain("['/proof', 'Engineering Evidence']");
    expect(read('app/sitemap.ts')).toContain("{ path: '/proof'");
    expect(read('app/gate/layout.js')).toContain("url: 'https://www.emiliaprotocol.ai/proof'");
    expect(read('README.md')).toContain('www.emiliaprotocol.ai/proof');
  });

  it('reports the bounded Authority Program model as partial, hash-bound formal evidence', () => {
    const source = JSON.parse(read('security/claims.v1.json'));
    const claim = source.claims.find(
      (entry) => entry.claim_id === 'authority-program-composition-is-root-bound-and-closed',
    );
    const [formal] = claim.formal;

    expect(formal.status).toBe('partial');
    expect(formal.method).toBe('bounded_tla_model_checking');
    expect(formal.model).toBe('formal/ep_authority_program.tla');
    expect(formal.runner).toBe('formal/ep_authority_program.cfg');
    expect(formal.obligations).toHaveLength(12);
    expect(formal.scope).toContain('not a refinement proof');
  });
});
