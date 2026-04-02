import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';

// Mock @/lib/supabase before importing the module under test
vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(),
}));

import {
  registerEndpoint,
  disableEndpoint,
  computeSignature,
  deliverWebhook,
  retryFailedDeliveries,
} from '../lib/cloud/webhooks.js';
import { getServiceClient } from '@/lib/supabase';

// ── Mock builder helpers ──────────────────────────────────────────────────────

function makeChain(resolved) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    is: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    lte: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolved),
    maybeSingle: vi.fn().mockResolvedValue(resolved),
    then: (resolve, reject) => Promise.resolve(resolved).then(resolve, reject),
  };
  return chain;
}

function makeSupabase(tableMap, defaultResolved = { data: null, error: null }) {
  return {
    from: vi.fn((table) => {
      const entry = tableMap[table];
      if (entry === undefined) return makeChain(defaultResolved);
      if (typeof entry.select === 'function') return entry;
      return makeChain(entry);
    }),
  };
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

const ENDPOINT = {
  endpoint_id: 'ep-1',
  tenant_id: 'tenant-1',
  url: 'https://example.com/webhook',
  secret: 'mysecret',
  events: ['receipt.created'],
  status: 'active',
  failure_count: 0,
};

const DELIVERY = {
  delivery_id: 'del-1',
  endpoint_id: 'ep-1',
  event_type: 'receipt.created',
  payload: { id: 'evt-1', type: 'receipt.created' },
  attempts: 0,
  status: 'pending',
};

// ── computeSignature ──────────────────────────────────────────────────────────

describe('computeSignature', () => {
  it('returns a hex string', () => {
    const sig = computeSignature('secret', 1234567890, { foo: 'bar' });
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces deterministic output for same inputs', () => {
    const payload = { event: 'test', id: '1' };
    const sig1 = computeSignature('secret', 1000, payload);
    const sig2 = computeSignature('secret', 1000, payload);
    expect(sig1).toBe(sig2);
  });

  it('produces different signatures for different timestamps', () => {
    const payload = { event: 'test' };
    const sig1 = computeSignature('secret', 1000, payload);
    const sig2 = computeSignature('secret', 2000, payload);
    expect(sig1).not.toBe(sig2);
  });

  it('produces different signatures for different secrets', () => {
    const payload = { event: 'test' };
    const sig1 = computeSignature('secret1', 1000, payload);
    const sig2 = computeSignature('secret2', 1000, payload);
    expect(sig1).not.toBe(sig2);
  });

  it('produces different signatures for different payloads', () => {
    const sig1 = computeSignature('secret', 1000, { a: 1 });
    const sig2 = computeSignature('secret', 1000, { a: 2 });
    expect(sig1).not.toBe(sig2);
  });

  it('matches manually computed HMAC-SHA256', () => {
    const secret = 'mysecret';
    const timestamp = 1700000000;
    const payload = { event: 'test.event' };
    const message = `${timestamp}.${JSON.stringify(payload)}`;
    const expected = crypto.createHmac('sha256', secret).update(message).digest('hex');
    expect(computeSignature(secret, timestamp, payload)).toBe(expected);
  });
});

// ── registerEndpoint ──────────────────────────────────────────────────────────

describe('registerEndpoint', () => {
  beforeEach(() => vi.clearAllMocks());

  it('registers a valid endpoint and returns secret', async () => {
    const endpointRow = { ...ENDPOINT };
    const chain = makeChain({ data: endpointRow, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await registerEndpoint('tenant-1', 'https://example.com/hook', ['receipt.created']);
    expect(result.endpoint).toEqual(endpointRow);
    expect(result.secret).toMatch(/^whsec_/);
  });

  it('returns 422 for localhost URL (SSRF protection)', async () => {
    getServiceClient.mockReturnValue({ from: vi.fn() });

    const result = await registerEndpoint('tenant-1', 'http://localhost/hook', []);
    expect(result.status).toBe(422);
    expect(result.error).toMatch(/private|internal/i);
  });

  it('returns 422 for private IP 10.x.x.x', async () => {
    const result = await registerEndpoint('tenant-1', 'http://10.0.0.1/hook', []);
    expect(result.status).toBe(422);
  });

  it('returns 422 for private IP 192.168.x.x', async () => {
    const result = await registerEndpoint('tenant-1', 'http://192.168.1.1/hook', []);
    expect(result.status).toBe(422);
  });

  it('returns 422 for 172.16.x.x private range', async () => {
    const result = await registerEndpoint('tenant-1', 'http://172.16.0.1/hook', []);
    expect(result.status).toBe(422);
  });

  it('returns 422 for .internal hostname', async () => {
    const result = await registerEndpoint('tenant-1', 'http://myservice.internal/hook', []);
    expect(result.status).toBe(422);
  });

  it('returns 422 for .local hostname', async () => {
    const result = await registerEndpoint('tenant-1', 'http://myhost.local/hook', []);
    expect(result.status).toBe(422);
  });

  it('returns 422 for non-http(s) protocol', async () => {
    const result = await registerEndpoint('tenant-1', 'ftp://example.com/hook', []);
    expect(result.status).toBe(422);
  });

  it('returns 422 for invalid URL', async () => {
    const result = await registerEndpoint('tenant-1', 'not-a-url', []);
    expect(result.status).toBe(422);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'db error' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await registerEndpoint('tenant-1', 'https://example.com/hook', []);
    expect(result.status).toBe(500);
  });

  it('generates unique secrets on each call', async () => {
    const chain1 = makeChain({ data: ENDPOINT, error: null });
    const chain2 = makeChain({ data: ENDPOINT, error: null });

    getServiceClient.mockReturnValueOnce({ from: vi.fn(() => chain1) });
    getServiceClient.mockReturnValueOnce({ from: vi.fn(() => chain2) });

    const r1 = await registerEndpoint('tenant-1', 'https://example.com/hook', []);
    const r2 = await registerEndpoint('tenant-1', 'https://example.com/hook', []);
    expect(r1.secret).not.toBe(r2.secret);
  });
});

// ── disableEndpoint ───────────────────────────────────────────────────────────

describe('disableEndpoint', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns success: true on success', async () => {
    const chain = makeChain({ data: {}, error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await disableEndpoint('ep-1');
    expect(result.success).toBe(true);
  });

  it('returns 500 on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'db error' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await disableEndpoint('ep-1');
    expect(result.status).toBe(500);
    expect(result.error).toMatch(/Failed to disable/i);
  });
});

// ── deliverWebhook ────────────────────────────────────────────────────────────

describe('deliverWebhook', () => {
  let originalFetch;

  beforeEach(() => {
    vi.clearAllMocks();
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns 404 when endpoint is not found', async () => {
    const epChain = makeChain({ data: null, error: null });
    const supabase = { from: vi.fn(() => epChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await deliverWebhook('ep-missing', 'receipt.created', {});
    expect(result.status).toBe(404);
  });

  it('returns 422 when endpoint is not active', async () => {
    const epChain = makeChain({ data: { ...ENDPOINT, status: 'disabled' }, error: null });
    const supabase = { from: vi.fn(() => epChain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await deliverWebhook('ep-1', 'receipt.created', {});
    expect(result.status).toBe(422);
    expect(result.error).toMatch(/not active/i);
  });

  it('returns 500 when delivery record cannot be created', async () => {
    const epChain = makeChain({ data: ENDPOINT, error: null });
    const deliveryChain = makeChain({ data: null, error: { message: 'insert failed' } });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_endpoints') return epChain;
        if (table === 'webhook_deliveries') return deliveryChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await deliverWebhook('ep-1', 'receipt.created', {});
    expect(result.status).toBe(500);
  });

  it('delivers successfully and marks delivery as delivered', async () => {
    const updatedDelivery = { ...DELIVERY, status: 'delivered', attempts: 1 };

    // Mock fetch to return a 200 OK response
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => 'OK',
    });

    const epChain = makeChain({ data: ENDPOINT, error: null });
    const deliveryInsertChain = makeChain({ data: DELIVERY, error: null });
    const deliveryUpdateChain = makeChain({ data: updatedDelivery, error: null });
    const endpointUpdateChain = makeChain({ data: {}, error: null });

    let deliveryCallCount = 0;
    let endpointCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_endpoints') {
          endpointCallCount++;
          // First call = fetch endpoint, second call = update success stats
          if (endpointCallCount === 1) return epChain;
          return endpointUpdateChain;
        }
        if (table === 'webhook_deliveries') {
          deliveryCallCount++;
          if (deliveryCallCount === 1) return deliveryInsertChain;
          return deliveryUpdateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await deliverWebhook('ep-1', 'receipt.created', { id: 'evt-1' });
    expect(result.delivery).toBeDefined();
    expect(result.delivery.status).toBe('delivered');
  });

  it('sets status to retrying on HTTP failure', async () => {
    const retriedDelivery = { ...DELIVERY, status: 'retrying', attempts: 1 };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => 'Server Error',
    });

    const epChain = makeChain({ data: ENDPOINT, error: null });
    const deliveryInsertChain = makeChain({ data: DELIVERY, error: null });
    const deliveryUpdateChain = makeChain({ data: retriedDelivery, error: null });

    let deliveryCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_endpoints') return epChain;
        if (table === 'webhook_deliveries') {
          deliveryCallCount++;
          if (deliveryCallCount === 1) return deliveryInsertChain;
          return deliveryUpdateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await deliverWebhook('ep-1', 'receipt.created', { id: 'evt-1' });
    expect(result.delivery.status).toBe('retrying');
  });

  it('sets status to failed after max retries exhausted', async () => {
    const failedDelivery = { ...DELIVERY, status: 'failed', attempts: 6 };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => 'Unavailable',
    });

    // Simulate a delivery that already has 5 attempts (retryIndex = 5 >= RETRY_INTERVALS_MS.length = 5)
    const exhaustedDelivery = { ...DELIVERY, attempts: 5 };
    const epChain = makeChain({ data: ENDPOINT, error: null });
    const deliveryInsertChain = makeChain({ data: exhaustedDelivery, error: null });
    const deliveryUpdateChain = makeChain({ data: failedDelivery, error: null });

    let deliveryCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_endpoints') return epChain;
        if (table === 'webhook_deliveries') {
          deliveryCallCount++;
          if (deliveryCallCount === 1) return deliveryInsertChain;
          return deliveryUpdateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await deliverWebhook('ep-1', 'receipt.created', { id: 'evt-1' });
    expect(result.delivery.status).toBe('failed');
  });

  it('handles network timeout / fetch error', async () => {
    const retriedDelivery = { ...DELIVERY, status: 'retrying', attempts: 1 };

    globalThis.fetch = vi.fn().mockRejectedValue(new Error('fetch failed'));

    const epChain = makeChain({ data: ENDPOINT, error: null });
    const deliveryInsertChain = makeChain({ data: DELIVERY, error: null });
    const deliveryUpdateChain = makeChain({ data: retriedDelivery, error: null });

    let deliveryCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_endpoints') return epChain;
        if (table === 'webhook_deliveries') {
          deliveryCallCount++;
          if (deliveryCallCount === 1) return deliveryInsertChain;
          return deliveryUpdateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await deliverWebhook('ep-1', 'receipt.created', { id: 'evt-1' });
    expect(result.delivery).toBeDefined();
  });

  it('sends correct headers including X-EP-Signature', async () => {
    const capturedHeaders = {};

    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      Object.assign(capturedHeaders, opts.headers);
      return { ok: true, status: 200, text: async () => 'OK' };
    });

    const updatedDelivery = { ...DELIVERY, status: 'delivered', attempts: 1 };
    const epChain = makeChain({ data: ENDPOINT, error: null });
    const deliveryInsertChain = makeChain({ data: DELIVERY, error: null });
    const deliveryUpdateChain = makeChain({ data: updatedDelivery, error: null });

    let deliveryCallCount = 0;
    let endpointCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_endpoints') {
          endpointCallCount++;
          if (endpointCallCount === 1) return epChain;
          return makeChain({ data: {}, error: null });
        }
        if (table === 'webhook_deliveries') {
          deliveryCallCount++;
          if (deliveryCallCount === 1) return deliveryInsertChain;
          return deliveryUpdateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    await deliverWebhook('ep-1', 'receipt.created', { id: 'evt-1' });

    expect(capturedHeaders['X-EP-Signature']).toBeDefined();
    expect(capturedHeaders['X-EP-Timestamp']).toBeDefined();
    expect(capturedHeaders['X-EP-Event']).toBe('receipt.created');
    expect(capturedHeaders['Content-Type']).toBe('application/json');
  });

  it('blocks SSRF at delivery time for private URL', async () => {
    // Endpoint has a private URL (bypassed registration somehow)
    const privateEndpoint = { ...ENDPOINT, url: 'http://127.0.0.1/internal' };
    const retriedDelivery = { ...DELIVERY, status: 'retrying', attempts: 1 };

    const epChain = makeChain({ data: privateEndpoint, error: null });
    const deliveryInsertChain = makeChain({ data: DELIVERY, error: null });
    const deliveryUpdateChain = makeChain({ data: retriedDelivery, error: null });

    let deliveryCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_endpoints') return epChain;
        if (table === 'webhook_deliveries') {
          deliveryCallCount++;
          if (deliveryCallCount === 1) return deliveryInsertChain;
          return deliveryUpdateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    // Should not actually make a fetch request
    globalThis.fetch = vi.fn();

    const result = await deliverWebhook('ep-1', 'receipt.created', {});
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(result.delivery).toBeDefined();
  });
});

// ── retryFailedDeliveries ─────────────────────────────────────────────────────

describe('retryFailedDeliveries', () => {
  let originalFetch;

  beforeEach(() => {
    vi.clearAllMocks();
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns zero counts when no deliveries are due', async () => {
    const chain = makeChain({ data: [], error: null });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await retryFailedDeliveries();
    expect(result).toEqual({ processed: 0, succeeded: 0, failed: 0 });
  });

  it('returns zero counts on DB error', async () => {
    const chain = makeChain({ data: null, error: { message: 'db error' } });
    const supabase = { from: vi.fn(() => chain) };
    getServiceClient.mockReturnValue(supabase);

    const result = await retryFailedDeliveries();
    expect(result).toEqual({ processed: 0, succeeded: 0, failed: 0 });
  });

  it('marks delivery as failed when its endpoint is disabled', async () => {
    const deliveryWithDisabledEp = {
      ...DELIVERY,
      webhook_endpoints: { ...ENDPOINT, status: 'disabled' },
    };

    const listChain = makeChain({ data: [deliveryWithDisabledEp], error: null });
    const updateChain = makeChain({ data: { ...DELIVERY, status: 'failed' }, error: null });

    let listCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_deliveries') {
          listCallCount++;
          if (listCallCount === 1) return listChain;
          return updateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await retryFailedDeliveries();
    expect(result.processed).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.succeeded).toBe(0);
  });

  it('marks delivery as failed when endpoint is null', async () => {
    const deliveryNoEp = { ...DELIVERY, webhook_endpoints: null };

    const listChain = makeChain({ data: [deliveryNoEp], error: null });
    const updateChain = makeChain({ data: { ...DELIVERY, status: 'failed' }, error: null });

    let listCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_deliveries') {
          listCallCount++;
          if (listCallCount === 1) return listChain;
          return updateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await retryFailedDeliveries();
    expect(result.failed).toBe(1);
  });

  it('retries active endpoint and counts succeeded', async () => {
    const deliveryWithActiveEp = {
      ...DELIVERY,
      webhook_endpoints: ENDPOINT,
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => 'OK',
    });

    const updatedDelivery = { ...DELIVERY, status: 'delivered', attempts: 1 };
    const listChain = makeChain({ data: [deliveryWithActiveEp], error: null });
    const deliveryUpdateChain = makeChain({ data: updatedDelivery, error: null });
    const endpointUpdateChain = makeChain({ data: {}, error: null });

    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_deliveries') {
          // We need to distinguish the list query vs update queries
          // The list chain is awaitable directly
          return listChain;
        }
        if (table === 'webhook_endpoints') return endpointUpdateChain;
        return makeChain({ data: null, error: null });
      }),
    };

    // The tricky part: the same table (webhook_deliveries) is used for both
    // listing and updating. We track calls to distinguish.
    let wdCallCount = 0;
    const supabase2 = {
      from: vi.fn((table) => {
        if (table === 'webhook_deliveries') {
          wdCallCount++;
          if (wdCallCount === 1) return listChain;
          return deliveryUpdateChain;
        }
        if (table === 'webhook_endpoints') return endpointUpdateChain;
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase2);

    const result = await retryFailedDeliveries();
    expect(result.processed).toBe(1);
    expect(result.succeeded).toBe(1);
    expect(result.failed).toBe(0);
  });

  it('counts failed when retry attempt fails (non-2xx)', async () => {
    const deliveryWithActiveEp = {
      ...DELIVERY,
      webhook_endpoints: ENDPOINT,
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => 'Error',
    });

    const retriedDelivery = { ...DELIVERY, status: 'retrying', attempts: 1 };
    const listChain = makeChain({ data: [deliveryWithActiveEp], error: null });
    const deliveryUpdateChain = makeChain({ data: retriedDelivery, error: null });

    let wdCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_deliveries') {
          wdCallCount++;
          if (wdCallCount === 1) return listChain;
          return deliveryUpdateChain;
        }
        if (table === 'webhook_endpoints') return makeChain({ data: {}, error: null });
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await retryFailedDeliveries();
    expect(result.processed).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.succeeded).toBe(0);
  });

  it('processes multiple deliveries in one batch', async () => {
    const deliveries = [
      { ...DELIVERY, delivery_id: 'del-1', webhook_endpoints: null },
      { ...DELIVERY, delivery_id: 'del-2', webhook_endpoints: null },
      { ...DELIVERY, delivery_id: 'del-3', webhook_endpoints: null },
    ];

    const listChain = makeChain({ data: deliveries, error: null });
    const updateChain = makeChain({ data: { ...DELIVERY, status: 'failed' }, error: null });

    let wdCallCount = 0;
    const supabase = {
      from: vi.fn((table) => {
        if (table === 'webhook_deliveries') {
          wdCallCount++;
          if (wdCallCount === 1) return listChain;
          return updateChain;
        }
        return makeChain({ data: null, error: null });
      }),
    };
    getServiceClient.mockReturnValue(supabase);

    const result = await retryFailedDeliveries();
    expect(result.processed).toBe(3);
    expect(result.failed).toBe(3);
  });
});
