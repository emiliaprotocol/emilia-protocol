// SPDX-License-Identifier: Apache-2.0
//
// The webhook deliverer and the SSO fetcher pin each connection to the address
// they validated by handing node:https a custom `lookup`. Since Node 20 the
// socket layer defaults to autoSelectFamily and calls that lookup with
// { all: true }, expecting an array. The pinned lookups answered with the
// single-address form, so every delivery and every SSO fetch failed with
// "Invalid IP address: undefined" before a socket was opened.
//
// These cases open REAL sockets. The only relaxation is that the address
// policy treats 127.0.0.1 as public in this file, so the pinned connection can
// land on a local listener; pinnedLookup and node:https are the real ones.

import net from 'node:net';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(async () => [{ address: '127.0.0.1', family: 4 }]),
}));

vi.mock('../lib/net/public-address.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/net/public-address.js')>();
  return { ...actual, isPublicAddress: (value: unknown) => value === '127.0.0.1' || actual.isPublicAddress(value) };
});

vi.mock('@/lib/supabase', () => ({ getServiceClient: vi.fn() }));

const { deliverWebhook } = await import('../lib/cloud/webhooks.js');
const { safePinnedFetch } = await import('../lib/sso/pinned-fetch.js');
const { getServiceClient } = await import('@/lib/supabase');

let server: net.Server;
let port = 0;
let connections = 0;

beforeAll(async () => {
  // Plain TCP: the lookup bug fires before TLS, so reaching the listener is the
  // property under test. The handshake then fails, which both callers report.
  server = net.createServer((socket) => {
    connections++;
    socket.destroy();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  port = (server.address() as net.AddressInfo).port;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

function supabaseRecording(url: string, deliveryUpdates: Record<string, unknown>[]) {
  const endpoint = {
    endpoint_id: 'ep-1', tenant_id: 'tenant-1', url, secret: 'whsec_test',
    events: ['receipt.created'], status: 'active', failure_count: 0,
  };
  const delivery = {
    delivery_id: 'del-1', endpoint_id: 'ep-1', event_type: 'receipt.created',
    payload: { id: 'evt-1' }, attempts: 0, status: 'pending',
  };
  let endpointReads = 0;
  let deliveryReads = 0;
  function chain(resolved: unknown, onUpdate?: (payload: Record<string, unknown>) => void) {
    const c: Record<string, unknown> = {};
    for (const method of ['select', 'insert', 'eq', 'is', 'in', 'lte', 'order', 'limit']) c[method] = () => c;
    c.update = (payload: Record<string, unknown>) => { onUpdate?.(payload); return c; };
    c.single = async () => resolved;
    c.maybeSingle = async () => resolved;
    c.then = (onFulfilled: (v: unknown) => unknown, onRejected: (e: unknown) => unknown) =>
      Promise.resolve(resolved).then(onFulfilled, onRejected);
    return c;
  }
  return {
    from(table: string) {
      if (table === 'webhook_endpoints') {
        return chain(++endpointReads === 1 ? { data: endpoint, error: null } : { data: {}, error: null });
      }
      if (table === 'webhook_deliveries') {
        return chain(++deliveryReads === 1 ? { data: delivery, error: null } : { data: delivery, error: null },
          (payload) => deliveryUpdates.push(payload));
      }
      return chain({ data: null, error: null });
    },
  };
}

describe('pinned lookup under the default autoSelectFamily', () => {
  it('webhook delivery connects to the pinned address', async () => {
    const before = connections;
    const updates: Record<string, unknown>[] = [];
    (getServiceClient as unknown as { mockReturnValue(v: unknown): void })
      .mockReturnValue(supabaseRecording(`https://hooks.test:${port}/hook`, updates));

    await deliverWebhook('ep-1', 'receipt.created', { id: 'evt-1' });

    expect(connections).toBe(before + 1);
    expect(updates[0]?.response_body).not.toMatch(/Invalid IP address/);
  });

  it('SSO fetch connects to the pinned address', async () => {
    const before = connections;
    const lookup = async () => [{ address: '127.0.0.1', family: 4 }];

    const error = await safePinnedFetch(`https://idp.test:${port}/.well-known/openid-configuration`, {}, { lookup: lookup as never })
      .then(() => null, (err: Error) => err);

    expect(connections).toBe(before + 1);
    expect(error?.message ?? '').not.toMatch(/Invalid IP address/);
  });
});
