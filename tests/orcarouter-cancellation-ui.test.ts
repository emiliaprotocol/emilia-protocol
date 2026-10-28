// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from 'vitest';
import { requestOrcaCancellation } from '../app/internal/trust-desk/providers/orcarouter-cancellation';

describe('OrcaRouter cancellation feedback', () => {
  it('reports confirmed cancellation and names the provider-side key boundary', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ cancelled: true }), { status: 200 }));
    const result = await requestOrcaCancellation('attempt-one', fetcher);
    expect(result.outcome).toBe('cancelled');
    expect(result.message).toMatch(/already issued/);
    expect(fetcher).toHaveBeenCalledWith('/api/orcarouter/connect/cancel', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ attempt_id: 'attempt-one' }),
    }));
  });

  it('does not call an already-ended attempt cancelled', async () => {
    const result = await requestOrcaCancellation('attempt-two', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ cancelled: false }), { status: 200 }),
    ));
    expect(result.outcome).toBe('ended');
    expect(result.message).toMatch(/already ended/);
  });

  it.each(['conflict', 'network', 'malformed'])('does not claim success when cancellation is %s', async (scenario) => {
    const fetcher = vi.fn();
    if (scenario === 'conflict') fetcher.mockResolvedValue(new Response('{}', { status: 409 }));
    if (scenario === 'network') fetcher.mockRejectedValue(new Error('offline'));
    if (scenario === 'malformed') fetcher.mockResolvedValue(new Response('{}', { status: 200 }));
    const result = await requestOrcaCancellation('attempt-three', fetcher);
    expect(result.outcome).toBe('unconfirmed');
    expect(result.message).toMatch(/could not confirm/i);
  });
});
