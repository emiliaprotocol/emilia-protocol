import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

type CanonicalDocument = {
  order: number;
  label: string;
  draft: string;
  revision: string;
  datatracker: string;
};

const ROOT = resolve(import.meta.dirname, '..');
const protocolPage = readFileSync(resolve(ROOT, 'app/protocol/page.tsx'), 'utf8');
const sitemapPage = readFileSync(resolve(ROOT, 'app/sitemap.ts'), 'utf8');
const status = JSON.parse(readFileSync(resolve(ROOT, 'standards/STATUS.json'), 'utf8')) as {
  canonical_four_document_surface: { documents: CanonicalDocument[] };
};
const documents = status.canonical_four_document_surface.documents;

describe('/protocol canonical four-document hub', () => {
  it('renders the STATUS.json presentation path in order at the current revisions', () => {
    expect(documents).toHaveLength(4);
    expect(protocolPage).toContain("import standardsStatus from '@/standards/STATUS.json'");
    expect(protocolPage).toContain('standardsStatus.canonical_four_document_surface.documents.map');
    for (const document of documents) {
      expect(protocolPage).toContain(`'${document.draft}':`);
    }
    expect(protocolPage).toContain('draft: `${document.draft}-${document.revision}`');
  });

  it('uses local explainers for Receipts and AEC and Datatracker for the two middle documents', () => {
    expect(protocolPage).toContain("href: '/spec'");
    expect(protocolPage).toContain("href: 'https://datatracker.ietf.org/doc/draft-schrock-human-authorization-binding/'");
    expect(protocolPage).toContain("href: 'https://datatracker.ietf.org/doc/draft-schrock-ep-authority-introduction/'");
    expect(protocolPage).toContain("href: '/evidence-chain'");
  });

  it('leads with Gate while bounding exact-action and complete-mediation claims', () => {
    expect(protocolPage).toContain('Gate exact actions before consequences.');
    expect(protocolPage).toContain('one exact material action');
    expect(protocolPage).toContain('A protected path is not proof of complete mediation.');
    expect(protocolPage).toContain('a verified bypass overrides a successful blocked-path demonstration');
    expect(protocolPage).not.toContain('Every ceremony. No exceptions.');
  });

  it('groups the two local document routes immediately behind the hub in the sitemap', () => {
    const protocolIndex = sitemapPage.indexOf("path: '/protocol'");
    const receiptsIndex = sitemapPage.indexOf("path: '/spec'");
    const aecIndex = sitemapPage.indexOf("path: '/evidence-chain'");

    expect(protocolIndex).toBeGreaterThan(-1);
    expect(receiptsIndex).toBeGreaterThan(protocolIndex);
    expect(aecIndex).toBeGreaterThan(receiptsIndex);
    expect(sitemapPage.match(/path: '\/evidence-chain'/g)).toHaveLength(1);
  });
});
