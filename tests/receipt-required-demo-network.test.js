// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from 'vitest';
import { postReceiptRequiredDemo } from '../app/try/receipt-required/post-demo.js';

describe('receipt-required demo transport boundary', () => {
  it('preserves the normal structured response', async () => {
    const fetchImpl = vi.fn(async () => new Response(
      JSON.stringify({ title: 'receipt required' }),
      {
        status: 428,
        headers: {
          'content-type': 'application/json',
          'receipt-required': 'payment.release',
        },
      },
    ));

    await expect(postReceiptRequiredDemo({ demo: 'release_funds' }, fetchImpl)).resolves.toEqual({
      status: 428,
      data: { title: 'receipt required' },
      receiptRequired: 'payment.release',
    });
  });

  it('turns a rejected request into a result the UI can unlock from', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('connection reset');
    });

    await expect(postReceiptRequiredDemo({ demo: 'release_funds' }, fetchImpl)).resolves.toEqual({
      status: 0,
      data: {
        title: 'network error',
        error: 'connection reset',
      },
      receiptRequired: null,
    });
  });

  it('turns a non-JSON gateway response into a bounded result', async () => {
    const fetchImpl = vi.fn(async () => new Response('upstream unavailable', {
      status: 502,
      headers: { 'content-type': 'text/plain' },
    }));

    await expect(postReceiptRequiredDemo({ demo: 'release_funds' }, fetchImpl)).resolves.toEqual({
      status: 502,
      data: {
        title: 'non-JSON response',
        error: 'gate returned 502',
      },
      receiptRequired: null,
    });
  });
});
