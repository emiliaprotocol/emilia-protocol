import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

type CanonicalDocument = { draft: string; revision: string; source: string; snapshot_sha256: string };
type ActiveEntry = { draft: string; revision: string };

const ROOT = resolve(import.meta.dirname, '..');
const page = readFileSync(resolve(ROOT, 'app/spec/page.tsx'), 'utf8');
const evidenceChainPage = readFileSync(resolve(ROOT, 'app/evidence-chain/page.tsx'), 'utf8');
const evidenceChainLayout = readFileSync(resolve(ROOT, 'app/evidence-chain/layout.tsx'), 'utf8');
const status = JSON.parse(readFileSync(resolve(ROOT, 'standards/STATUS.json'), 'utf8')) as {
  canonical_four_document_surface: { documents: CanonicalDocument[] };
  active_datatracker: ActiveEntry[];
};
const RECEIPTS = 'draft-schrock-ep-authorization-receipts';
const surfaceReceipts = status.canonical_four_document_surface.documents.find((document) => document.draft === RECEIPTS);
const activeReceipts = status.active_datatracker.find((entry) => entry.draft === RECEIPTS);

describe('/spec source contract', () => {
  it('renders the current posted authorization-receipts revision named by STATUS.json', () => {
    expect(surfaceReceipts).toBeDefined();
    expect(activeReceipts).toBeDefined();
    const { revision, source, snapshot_sha256: snapshotSha256 } = surfaceReceipts!;
    expect(revision).toBe(activeReceipts!.revision);
    expect(source).toBe(`standards/posted/${RECEIPTS}-${revision}.xml`);
    expect(existsSync(resolve(ROOT, source))).toBe(true);
    const bytes = readFileSync(resolve(ROOT, source));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(snapshotSha256);
    expect(bytes.toString('utf8')).toContain(`docName="${RECEIPTS}-${revision}"`);

    expect(page).toContain("import standardsStatus from '@/standards/STATUS.json'");
    expect(page).toContain('standardsStatus.canonical_four_document_surface.documents.find');
    // The literal directory and prefix keep the file traceable into the server bundle.
    expect(page).toContain("join(process.cwd(), 'standards', 'posted', `draft-schrock-ep-authorization-receipts-${RECEIPTS_REVISION}.xml`)");
    expect(page).toContain('RECEIPTS.source !== `standards/posted/${RECEIPTS_DRAFT}.xml`');
    expect(page).not.toMatch(/authorization-receipts-\d{2}/i);
  });

  it('places Receipts at the start of the canonical path without overstating its claim', () => {
    expect(page).toContain('Canonical path · 01 of 04');
    expect(page).toContain('href="/protocol"');
    expect(page).toContain('Next: Human Authorization Binding -00');
    expect(page).toContain('exact material action');
    expect(page).toContain('does not by itself establish scoped authority, evidence satisfaction, local authorization,');
    expect(page).toContain('execution, or complete mediation');
  });
});

describe('/evidence-chain source contract', () => {
  it('presents AEC -06 as document 04 and keeps satisfaction separate from authorization', () => {
    expect(evidenceChainPage).toContain("draft-schrock-ep-authorization-evidence-chain-06");
    expect(evidenceChainPage).not.toContain('draft-schrock-ep-authorization-evidence-chain-05');
    expect(evidenceChainPage).toContain('Canonical path · 04 of 04');
    expect(evidenceChainPage).toContain('The executor separately decides whether');
    expect(evidenceChainPage).toContain('local authorization, execution, or complete mediation');
    expect(evidenceChainLayout).toContain('Authorization Evidence Chain -06');
    expect(evidenceChainLayout).toContain('SATISFIED is evidence, not local authorization');
  });
});
