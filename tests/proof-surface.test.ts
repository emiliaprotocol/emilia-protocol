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

type FormalEvidence = {
  status: string;
  method?: string;
  trace_evidence?: string;
  trace_runner?: string;
  refinement_evidence?: string;
};

type FormalCategory =
  | 'verified-formal-obligations'
  | 'bounded-runtime-traced'
  | 'bounded-formal-evidence'
  | 'partial-symbolic-coverage'
  | 'executable-operational-evidence';

const classifyFormalEvidence = (formal: FormalEvidence[]): FormalCategory => {
  if (formal.length > 0 && formal.every((entry) => entry.status === 'verified')) {
    return 'verified-formal-obligations';
  }

  const partial = formal.filter((entry) => entry.status === 'partial');
  if (
    partial.some(
      (entry) =>
        entry.method?.startsWith('bounded_') &&
        entry.trace_evidence &&
        entry.trace_runner &&
        entry.refinement_evidence,
    )
  ) {
    return 'bounded-runtime-traced';
  }
  if (partial.some((entry) => entry.method?.startsWith('bounded_'))) {
    return 'bounded-formal-evidence';
  }
  if (partial.length > 0) {
    return 'partial-symbolic-coverage';
  }
  return 'executable-operational-evidence';
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
    expect(page).toContain('Bounded + runtime-traced');
    expect(page).toContain('Bounded formal evidence');
    expect(page).toContain('Partial symbolic coverage');
    expect(page).toContain('Executable/operational evidence');
    expect(page).toContain('does not mean a refinement proof');
    expect(page).toContain('What this evidence does not establish.');
    expect(page).toContain('application/ld+json');
    expect(layout).toContain('Machine-Verifiable Security Case');
  });

  it('derives the five-way formal-evidence taxonomy from claim metadata', () => {
    const source = JSON.parse(read('security/claims.v1.json')) as {
      claims: Array<{ claim_id: string; formal?: FormalEvidence[] }>;
    };
    const page = read('app/proof/page.js');
    const counts = source.claims.reduce<Record<FormalCategory, number>>(
      (result, claim) => {
        result[classifyFormalEvidence(claim.formal || [])] += 1;
        return result;
      },
      {
        'verified-formal-obligations': 0,
        'bounded-runtime-traced': 0,
        'bounded-formal-evidence': 0,
        'partial-symbolic-coverage': 0,
        'executable-operational-evidence': 0,
      },
    );

    expect(counts).toEqual({
      'verified-formal-obligations': 2,
      'bounded-runtime-traced': 9,
      'bounded-formal-evidence': 5,
      'partial-symbolic-coverage': 6,
      'executable-operational-evidence': 11,
    });
    expect(page).toMatch(/formalCoverage\(claim\.formal \|\| \[\]\)/);
    expect(page).toContain("entry.status === 'partial'");
    expect(page).toContain("entry.method?.startsWith('bounded_')");
    expect(page).toContain('entry.trace_evidence');
    expect(page).toContain('entry.trace_runner');
    expect(page).toContain('entry.refinement_evidence');
    expect(page).toContain('{claimSource.claims.length}/{claimSource.claims.length}');
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
