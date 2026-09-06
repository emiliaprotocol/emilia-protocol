// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { GATE_QUOTE_EMAIL, GATE_QUOTE_MAILTO, MARKETPLACE_GATE_OFFER } from '../lib/works/gate-offer';

describe('marketplace Gate offer', () => {
  it('requires an agreed quote and does not invent a price or enable charging', () => {
    expect(MARKETPLACE_GATE_OFFER).toMatchObject({ status: 'QUOTE_REQUIRED', checkoutEnabled: false, price: null });
    expect(MARKETPLACE_GATE_OFFER.scope).toBe('One agreed action in one supported tool integration.');
    expect(MARKETPLACE_GATE_OFFER.exclusions).toContain('No certification');
  });
  it('composes an editable inquiry to the fixed recipient, with no automatic scan attachment', () => {
    const url = new URL(GATE_QUOTE_MAILTO);
    expect(url.protocol).toBe('mailto:');
    expect(url.pathname).toBe(GATE_QUOTE_EMAIL);
    expect(Array.from(url.searchParams.keys()).sort()).toEqual(['body', 'subject']);
    expect(url.searchParams.get('body')).toContain('before any work or charge');
    expect(url.searchParams.get('body')).toContain('not in this email');
    expect(GATE_QUOTE_MAILTO).not.toMatch(/attachment|token=|evidence=|scan=/i);
  });
  it('keeps the offer immutable and payment separate from evidence decisions', () => {
    expect(Object.isFrozen(MARKETPLACE_GATE_OFFER)).toBe(true);
    expect(Object.keys(MARKETPLACE_GATE_OFFER)).not.toContain('qualified');
    expect(Object.keys(MARKETPLACE_GATE_OFFER)).not.toContain('certified');
  });
  it('provides real free and quoted paths without a checkout or safety badge', () => {
    const source = readFileSync('app/works/gate/page.tsx', 'utf8');
    expect(source).toContain('if (!isWorksV0Enabled()) notFound()');
    expect(source).toContain('href={GATE_QUOTE_MAILTO}');
    expect(source).toContain('href="/scan#run-local"');
    expect(source).toContain('href="/works/qualification"');
    expect(source).toContain('The test result is not for sale.');
    expect(source).toContain('Self-service checkout is not open.');
    expect(source).not.toMatch(/api\/works\/.*billing|checkout\.stripe|buy\.stripe/);
  });
});
