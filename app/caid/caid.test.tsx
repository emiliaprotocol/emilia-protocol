// SPDX-License-Identifier: Apache-2.0

import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import CaidPlayground from './CaidPlayground';
import { buildCaidComparison } from './model';
import { BASELINE_CAID_INPUT, type CaidComparison } from './types';
import { POST } from '../api/caid/route';

describe('/caid exact-action playground', () => {
  it('recomputes the same exact typed action to the same registered URI', () => {
    const result = buildCaidComparison(BASELINE_CAID_INPUT);

    expect(result.approvedCaid).toMatch(
      /^canactid:1:payment\.release\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/,
    );
    expect(result.proposedCaid).toBe(result.approvedCaid);
    expect(result.recomputedCaid).toBe(result.approvedCaid);
    expect(result.matchesApprovedAction).toBe(true);
    expect(result.canonicalAction).toMatchObject({
      action_type: 'payment.release.1',
      amount: '82000.00',
      currency: 'USD',
      payment_instruction_id: 'pi-demo-1042',
    });
  });

  it('changes the identifier and refuses the approval match when amount changes', () => {
    const result = buildCaidComparison({
      ...BASELINE_CAID_INPUT,
      amount: '82500.00',
    });

    expect(result.proposedCaid).not.toBe(result.approvedCaid);
    expect(result.matchesApprovedAction).toBe(false);
    expect(result.changedFields).toEqual(['amount']);
  });

  it('changes the identifier and refuses the approval match when destination changes', () => {
    const result = buildCaidComparison({
      ...BASELINE_CAID_INPUT,
      destinationReference: 'Acme Supply / settlement / account 9981',
    });

    expect(result.proposedCaid).not.toBe(result.approvedCaid);
    expect(result.matchesApprovedAction).toBe(false);
    expect(result.changedFields).toEqual(['destination']);
    expect(result.canonicalAction.beneficiary_account).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('refuses malformed or oversized public inputs before CAID computation', () => {
    expect(() => buildCaidComparison({ ...BASELINE_CAID_INPUT, amount: '82,000' }))
      .toThrow('Enter an amount such as 82000.00');
    expect(() => buildCaidComparison({ ...BASELINE_CAID_INPUT, destinationReference: ' ' }))
      .toThrow('Enter a destination reference');
    expect(() => buildCaidComparison({
      ...BASELINE_CAID_INPUT,
      destinationReference: 'x'.repeat(257),
    })).toThrow('Destination references must be 256 UTF-8 bytes or fewer');
  });

  it('states the useful claim and every important non-claim in plain language', () => {
    const comparison: CaidComparison = buildCaidComparison(BASELINE_CAID_INPUT);
    const html = renderToStaticMarkup(<CaidPlayground initialComparison={comparison} />);

    expect(html).toContain('One exact action.');
    expect(html).toContain('One portable identifier.');
    expect(html).toContain('Same action, same identifier');
    expect(html).toContain('Change the amount');
    expect(html).toContain('Change the destination');
    expect(html).toContain('content correlation');
    expect(html).toContain('does not authorize');
    expect(html).toContain('does not prove execution');
    expect(html).toContain('does not prevent replay');
    expect(html).toContain('not a URL to fetch');
    expect(html).toContain('provisionally registered');
    expect(html).toContain('not IETF adoption, endorsement, or permanent status');
  });

  it('exposes the bounded reference comparison through the public route', async () => {
    const response = await POST(new Request('https://example.test/api/caid', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(BASELINE_CAID_INPUT),
    }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body.matchesApprovedAction).toBe(true);
    expect(body.proposedCaid).toMatch(/^canactid:1:/);
  });

  it('returns bounded public errors without exposing internals', async () => {
    const malformed = await POST(new Request('https://example.test/api/caid', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{',
    }));
    const invalid = await POST(new Request('https://example.test/api/caid', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...BASELINE_CAID_INPUT, amount: '82,000' }),
    }));

    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({ error: 'Request body must be JSON' });
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toEqual({ error: 'Enter an amount such as 82000.00' });
  });

  it('enforces the body limit even when content-length is absent', async () => {
    const request = new Request('https://example.test/api/caid', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: '1', destinationReference: 'x'.repeat(5000) }),
    });

    expect(request.headers.get('content-length')).toBeNull();
    const response = await POST(request);
    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: 'Request is too large' });
  });
});
