// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const conversionPages = [
  'app/government/page.tsx',
  'app/financial/page.tsx',
  'app/eye/page.tsx',
  'app/use-cases/ai-agent/page.tsx',
  'app/use-cases/enterprise/page.tsx',
  'app/use-cases/government/page.tsx',
  'app/use-cases/financial/page.tsx',
  'app/arena/ArenaExperience.tsx',
  'app/human-control/page.tsx',
  'app/blog/ai-voice-cloning-fraud-defense/page.tsx',
] as const;

const conversionLayouts = [
  'app/eye/layout.tsx',
  'app/use-cases/ai-agent/layout.tsx',
  'app/use-cases/enterprise/layout.tsx',
  'app/use-cases/government/layout.tsx',
  'app/use-cases/financial/layout.tsx',
] as const;

const solutionProfilePages = [
  'app/finguard/page.tsx',
  'app/govguard/page.tsx',
] as const;

function source(path: string): string {
  return readFileSync(path, 'utf8');
}

describe('public conversion surfaces', () => {
  it.each(conversionPages)('%s uses the canonical nonproduction pilot boundary', (path) => {
    const page = source(path);

    expect(page.match(/<main(?:\s|>)/g)).toHaveLength(1);
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT');
    expect(page).toMatch(/\/pilot/);
    expect(page).toMatch(/synthetic/i);
    expect(page).toMatch(/read-only/i);
    expect(page).toMatch(/sandbox/i);
    expect(page).toMatch(/shadow/i);
    expect(page).toMatch(/production\s+provider\s+credentials/i);
    expect(page).toMatch(/production/i);
    expect(page).toMatch(/actuat/i);
    expect(page).toMatch(/separate\s+Gate\s+Implementation/i);
  });

  it('removes forked pilot intake and high-risk conversion claims', () => {
    const publicCopy = [...conversionPages, ...conversionLayouts].map(source).join('\n');
    const highRiskCopy = [...conversionPages, ...conversionLayouts, ...solutionProfilePages].map(source).join('\n');

    expect(publicCopy).not.toMatch(/type:\s*['"]pilot-/i);
    expect(publicCopy).not.toContain('/api/inquiries');
    expect(publicCopy).not.toContain('/pilot/sandbox');
    expect(publicCopy).not.toMatch(/href=['"]#pilot['"]/i);
    expect(publicCopy).not.toMatch(/pilot deployments take days/i);
    expect(publicCopy).not.toMatch(/production pilot/i);
    expect(highRiskCopy).not.toMatch(/complete audit trail/i);
    expect(highRiskCopy).not.toMatch(/satisf(?:y|ies) regulatory examination requirements/i);
    expect(highRiskCopy).not.toMatch(/SOX-ready|Get protected|procurement-grade/i);
  });

  it.each(solutionProfilePages)('%s remains a reference profile inside the canonical offer', (path) => {
    const page = source(path);

    expect(page.match(/<main(?:\s|>)/g)).toHaveLength(1);
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT');
    expect(page).toMatch(/nonproduction/i);
    expect(page).toMatch(/separate(?:ly scoped)? Gate Implementation/i);
    expect(page).not.toMatch(/Get protected|SOX-ready|procurement-grade/i);
  });

  it('keeps the retained Arena field explicitly associated with its label', () => {
    const arena = source('app/arena/ArenaExperience.tsx');

    expect(arena).not.toContain('<form');
    expect(arena).toContain('htmlFor="agent-name"');
    expect(arena).toContain('id="agent-name"');
  });
});
