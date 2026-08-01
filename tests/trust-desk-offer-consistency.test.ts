// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const root = process.cwd();
const read = (relativePath: string): string =>
  fs.readFileSync(path.join(root, relativePath), 'utf8');

describe('Trust Desk offer consistency', () => {
  it('does not promise publication before the mandatory named-human review', () => {
    const intake = read('app/trust-desk/upload/page.tsx');

    expect(intake).not.toContain('most publish within minutes');
    expect(intake).toContain('nothing publishes until a named reviewer signs off');
    expect(intake).toContain('Gap Scan — $3,500');
  });

  it('provisions the same paid offers and prices shown on the landing page', () => {
    const page = read('app/trust-desk/page.tsx');
    const setup = read('scripts/stripe-setup.mts');

    for (const [name, displayedPrice, cents] of [
      ['Gap Scan', '$3,500', '350000'],
      ['Full Completion', '$18,000', '1800000'],
      ['AI Trust Packet', '$35,000', '3500000'],
      ['Retainer', '$18,000', '1800000'],
    ] as const) {
      expect(page).toContain(`name="${name}" price="${displayedPrice}"`);
      expect(setup).toMatch(
        new RegExp(`name: 'AI Trust Desk — ${name}'.*amount: ${cents}`),
      );
    }

    expect(setup).toContain("expand: ['line_items']");
    expect(setup).toContain('existingPriceId === price.id');
    expect(setup).toContain("paymentLinks.update(existingId, { active: false })");
  });
});
