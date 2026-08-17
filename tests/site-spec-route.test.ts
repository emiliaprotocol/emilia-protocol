import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const page = readFileSync(resolve(ROOT, 'app/spec/page.tsx'), 'utf8');
const evidenceChainPage = readFileSync(resolve(ROOT, 'app/evidence-chain/page.tsx'), 'utf8');
const evidenceChainLayout = readFileSync(resolve(ROOT, 'app/evidence-chain/layout.tsx'), 'utf8');

describe('/spec source contract', () => {
  it('renders the current posted authorization-receipts revision from an existing file', () => {
    const source = 'standards/posted/draft-schrock-ep-authorization-receipts-12.xml';

    expect(existsSync(resolve(ROOT, source))).toBe(true);
    expect(page).toContain("join(process.cwd(), 'standards', 'posted', 'draft-schrock-ep-authorization-receipts-12.xml')");
    expect(page).toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-12');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-11');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-10');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-09');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-08');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-07');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-06');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-03');
  });

  it('places Receipts -12 at the start of the canonical path without overstating its claim', () => {
    expect(page).toContain('Canonical path · 01 of 04');
    expect(page).toContain('href="/protocol"');
    expect(page).toContain('Next: Human Authorization Binding -00');
    expect(page).toContain('exact material action');
    expect(page).toContain('does not by itself establish scoped authority, evidence satisfaction, local authorization,');
    expect(page).toContain('execution, or complete mediation');
  });
});

describe('/evidence-chain source contract', () => {
  it('presents AEC -05 as document 04 and keeps satisfaction separate from authorization', () => {
    expect(evidenceChainPage).toContain("draft-schrock-ep-authorization-evidence-chain-05");
    expect(evidenceChainPage).toContain('Canonical path · 04 of 04');
    expect(evidenceChainPage).toContain('The executor separately decides whether');
    expect(evidenceChainPage).toContain('local authorization, execution, or complete mediation');
    expect(evidenceChainLayout).toContain('Authorization Evidence Chain -05');
    expect(evidenceChainLayout).toContain('SATISFIED is evidence, not local authorization');
  });
});
