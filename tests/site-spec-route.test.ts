import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const page = readFileSync(resolve(ROOT, 'app/spec/page.tsx'), 'utf8');

describe('/spec source contract', () => {
  it('renders the current posted authorization-receipts revision from an existing file', () => {
    const source = 'standards/posted/draft-schrock-ep-authorization-receipts-07.txt';

    expect(existsSync(resolve(ROOT, source))).toBe(true);
    expect(page).toContain("join(process.cwd(), 'standards', 'posted', 'draft-schrock-ep-authorization-receipts-07.txt')");
    expect(page).toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-07');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-06');
    expect(page).not.toContain('DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-03');
  });
});
