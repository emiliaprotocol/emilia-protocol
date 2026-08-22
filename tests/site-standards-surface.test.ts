// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');
const status = JSON.parse(read('standards/STATUS.json'));
const page = read('app/standards/page.tsx');
const protocolPage = read('app/protocol/page.tsx');

describe('canonical standards presentation surface', () => {
  it('keeps one ordered four-document reader path without consolidating the portfolio', () => {
    expect(status.canonical_four_document_surface.documents.map((document: { draft: string }) => document.draft)).toEqual([
      'draft-schrock-ep-authorization-receipts',
      'draft-schrock-human-authorization-binding',
      'draft-schrock-ep-authority-introduction',
      'draft-schrock-ep-authorization-evidence-chain',
    ]);
    expect(status.canonical_four_document_surface.status).toBe('presentation_only_no_consolidation');
    expect(status.active_profile_portfolio.active_datatracker_count).toBe(status.active_datatracker_count);
    expect(status.active_datatracker).toHaveLength(status.active_datatracker_count);
    expect(status.active_schrock_datatracker_count).toBe(
      status.active_datatracker.filter((entry: { draft: string }) => entry.draft.startsWith('draft-schrock-')).length,
    );
    expect(status.active_profile_portfolio.sole_authored_datatracker_count).toBe(20);
    expect(status.active_profile_portfolio.coauthored_datatracker_count).toBe(4);
    expect(status.active_datatracker).toContainEqual(expect.objectContaining({
      draft: 'draft-schrock-kintzele-grid-curtailment',
      revision: '00',
    }));
  });

  it('makes the website consume the governed revision source instead of hardcoding revisions', () => {
    expect(page).toContain("import standardsStatus from '@/standards/STATUS.json'");
    expect(page).toContain('standardsStatus.canonical_four_document_surface.documents.map');
    expect(page).not.toMatch(/draft-schrock-ep-authorization-receipts-\d{2}/);
  });

  it('keeps every visible protocol-hub revision aligned with the governed surface', () => {
    expect(protocolPage).toContain("import standardsStatus from '@/standards/STATUS.json'");
    expect(protocolPage).toContain('standardsStatus.canonical_four_document_surface.documents.map');
    for (const document of status.canonical_four_document_surface.documents) {
      expect(protocolPage).toContain(`'${document.draft}':`);
    }
    expect(protocolPage).toContain('draft: `${document.draft}-${document.revision}`');
    expect(protocolPage).toContain('A protected path is not proof of complete mediation.');
  });

  it('keeps the Gate claim inside the complete-mediation boundary', () => {
    expect(page).toContain('Let agents act within limits you approve in advance.');
    expect(page).toContain('Prevention applies only to configured action paths under complete mediation.');
    expect(page).not.toContain('Let your agents run unattended without giving them unlimited authority.');
  });

  it('freezes new names while allowing maintenance of active drafts', () => {
    expect(status.new_filing_freeze).toMatchObject({
      state: 'in_effect',
      start_date: '2026-08-04',
      through_date: '2026-11-01',
      through_date_inclusive: true,
    });
    expect(status.new_filing_freeze.maintenance_revisions).toContain('Allowed');
  });
});
