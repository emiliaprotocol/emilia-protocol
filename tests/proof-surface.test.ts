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
    expect(page).toContain('Fully modeled');
    expect(page).toContain('Partial formal coverage');
    expect(page).toContain('Executable evidence only');
    expect(page).toContain('does not mean unimplemented');
    expect(page).toContain('What this evidence does not establish.');
    expect(page).toContain('application/ld+json');
    expect(layout).toContain('Machine-Verifiable Security Case');
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
