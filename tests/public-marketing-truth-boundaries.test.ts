// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const source = (relativePath: string): string => readFileSync(resolve(ROOT, relativePath), 'utf8');

const LANDMARK_PAGES = [
  'app/eye/page.tsx',
  'app/blog/ai-voice-cloning-fraud-defense/page.tsx',
  'app/use-cases/ai-agent/page.tsx',
  'app/use-cases/enterprise/page.tsx',
  'app/use-cases/financial/page.tsx',
  'app/use-cases/government/page.tsx',
  'app/government/page.tsx',
  'app/financial/page.tsx',
  'app/human-control/page.tsx',
] as const;

const PILOT_SURFACES = [
  'app/eye/page.tsx',
  'app/blog/ai-voice-cloning-fraud-defense/page.tsx',
  'app/use-cases/ai-agent/page.tsx',
  'app/use-cases/enterprise/page.tsx',
  'app/use-cases/financial/page.tsx',
  'app/use-cases/government/page.tsx',
  'app/government/page.tsx',
  'app/financial/page.tsx',
  'app/human-control/page.tsx',
  'app/arena/ArenaExperience.tsx',
] as const;

describe('public marketing truth boundaries', () => {
  it.each(LANDMARK_PAGES)('%s exposes one semantic main landmark', (relativePath) => {
    const page = source(relativePath);
    expect(page.match(/<main(?:\s|>)/g)).toHaveLength(1);
    expect(page.match(/<\/main>/g)).toHaveLength(1);
    expect(page.indexOf('<main')).toBeLessThan(page.indexOf('<SiteFooter'));
  });

  it.each(PILOT_SURFACES)('%s derives public pilot terms from the canonical offer', (relativePath) => {
    const page = source(relativePath);
    expect(page).toContain("from '@/lib/commercial-offer'");
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.shortPriceLabel');
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.durationLabel');
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.workflowLabel');
  });

  it('keeps Eye advisory-only and gives enforcement to Gate', () => {
    const eye = `${source('app/eye/page.tsx')}\n${source('app/eye/layout.tsx')}`;
    expect(eye).toContain('Eye never authorizes or blocks');
    expect(eye).toContain('Gate owns enforcement');
    expect(eye).not.toMatch(/Full enforcement in ENFORCE mode|blockchain-anchored|No partial states/);
    expect(eye).not.toContain('Roll out enforcement without breaking production traffic');
  });

  it('scopes prevention to completely mediated covered paths', () => {
    for (const relativePath of [
      'app/blog/ai-voice-cloning-fraud-defense/page.tsx',
      'app/use-cases/ai-agent/page.tsx',
      'app/use-cases/enterprise/page.tsx',
      'app/use-cases/financial/page.tsx',
      'app/use-cases/government/page.tsx',
      'app/government/page.tsx',
      'app/financial/page.tsx',
      'app/human-control/page.tsx',
    ]) {
      expect(source(relativePath), relativePath).toMatch(/completely mediated/i);
    }
  });

  it('keeps enrolled credential evidence separate from civil identity and legal compliance', () => {
    const humanControl = source('app/human-control/page.tsx');
    const humanControlMetadata = source('app/human-control/layout.tsx');
    const useCases = [
      source('app/use-cases/ai-agent/page.tsx'),
      source('app/use-cases/enterprise/page.tsx'),
      source('app/use-cases/financial/page.tsx'),
      source('app/use-cases/government/page.tsx'),
      source('app/use-cases/government/layout.tsx'),
    ].join('\n');

    expect(humanControl).toContain('does not establish the approver&apos;s civil identity');
    expect(`${humanControl}\n${humanControlMetadata}`).not.toMatch(/Everyone requires a human|no one can prove it|proving a named human|all mandate meaningful human control|Four instruments mandate it|Directive 3000\.09 compliance/i);
    expect(humanControlMetadata).toContain('a receipt does not establish civil identity or legal compliance');
    expect(useCases).not.toMatch(/satisfy regulatory examination requirements|NIST AI RMF compliance|requirements demand/);
  });

  it('does not turn an uncited voice-fraud scenario into an empirical result', () => {
    const voice = source('app/blog/ai-voice-cloning-fraud-defense/page.tsx');
    const voiceMetadata = source('app/blog/ai-voice-cloning-fraud-defense/layout.tsx');
    expect(voice).toContain('A common attack pattern');
    expect(voiceMetadata).toContain('voice alone is not transaction authority');
    expect(`${voice}\n${voiceMetadata}`).not.toMatch(/Three seconds|3 seconds|reproduces any caller|Voice authentication is broken|well-documented and rising|markedly worse|Pilot deployments take days/i);
  });

  it('keeps the Arena conversion inside the nonproduction pilot boundary', () => {
    const arena = source('app/arena/ArenaExperience.tsx');
    expect(arena).toContain('FROM SYNTHETIC TO ONE PROTECTED-WORKFLOW PILOT');
    expect(arena).not.toContain('FROM SYNTHETIC TO ONE LIVE WORKFLOW');
  });
});
