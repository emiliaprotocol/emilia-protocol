// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import sitemap from '../app/sitemap';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (relative: string): string => fs.readFileSync(path.join(ROOT, relative), 'utf8');

describe('CAID public discovery', () => {
  it('lists the exact-action playground in the sitemap', () => {
    const paths = sitemap().map((entry) => new URL(entry.url).pathname);
    expect(paths).toContain('/caid');
  });

  it('links the playground from developer documentation and the global footer', () => {
    expect(read('app/docs/page.tsx')).toContain("href: '/caid'");
    expect(read('components/SiteFooter.tsx')).toContain("['/caid', 'CAID Playground']");
  });

  it('uses the provisional registration as a standards composition entry point', () => {
    const page = read('app/standards/page.tsx');
    expect(page).toContain('october_5_2026_canactid_iana_registration');
    expect(page).toContain('href="/caid"');
    expect(page).toContain('See the IANA record');
    expect(page).toContain('It does not authorize the action');
  });
});
