// SPDX-License-Identifier: Apache-2.0
//
// /api/works/* route contract: the WORKS_V0 flag 404s the whole surface,
// unauthenticated create/edit is rejected, and malformed input comes back as
// a typed problem response — never an unhandled throw.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
}));

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: mocks.authenticate,
}));

const collectionRoute = await import('../app/api/works/[collection]/route.ts');
const recordRoute = await import('../app/api/works/[collection]/[id]/route.ts');

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'works-routes-'));
  process.env.WORKS_DATA_DIR = dir;
  process.env.WORKS_V0 = '1';
  mocks.authenticate.mockReset();
  mocks.authenticate.mockResolvedValue(null);
});

afterEach(() => {
  delete process.env.WORKS_DATA_DIR;
  delete process.env.WORKS_V0;
  fs.rmSync(dir, { recursive: true, force: true });
});

const BASE = 'https://www.emiliaprotocol.ai/api/works';

function jsonRequest(url: string, method: string, body?: unknown): Request {
  return new Request(url, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const ctx = (collection: string) => ({ params: Promise.resolve({ collection }) });
const ctxId = (collection: string, id: string) => ({ params: Promise.resolve({ collection, id }) });

function builderBody(id = 'route-builder') {
  return {
    builder_id: id,
    kind: 'person',
    name: 'Route Test Builder',
    contact_route: 'mailto:builder@example.com',
  };
}

describe('feature flag', () => {
  it('404s every method when WORKS_V0 is off', async () => {
    delete process.env.WORKS_V0;
    const list = await collectionRoute.GET(
      jsonRequest(`${BASE}/listings`, 'GET') as any, ctx('listings'));
    expect(list.status).toBe(404);

    const create = await collectionRoute.POST(
      jsonRequest(`${BASE}/builders`, 'POST', builderBody()) as any, ctx('builders'));
    expect(create.status).toBe(404);

    const read = await recordRoute.GET(
      jsonRequest(`${BASE}/listings/ep-gate`, 'GET') as any, ctxId('listings', 'ep-gate'));
    expect(read.status).toBe(404);

    const edit = await recordRoute.PATCH(
      jsonRequest(`${BASE}/listings/ep-gate`, 'PATCH', {}) as any, ctxId('listings', 'ep-gate'));
    expect(edit.status).toBe(404);
    // The flag gate runs before auth: the surface is invisible, not just locked.
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });

  it('404s any non-1 flag value', async () => {
    process.env.WORKS_V0 = 'true';
    const list = await collectionRoute.GET(
      jsonRequest(`${BASE}/listings`, 'GET') as any, ctx('listings'));
    expect(list.status).toBe(404);
  });
});

describe('reads with the flag on', () => {
  it('lists seed records', async () => {
    const response = await collectionRoute.GET(
      jsonRequest(`${BASE}/listings`, 'GET') as any, ctx('listings'));
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(Array.isArray(body.records)).toBe(true);
    expect(body.records.length).toBeGreaterThanOrEqual(6);
  });

  it('reads a single seed record and 404s unknown ids and collections', async () => {
    const found = await recordRoute.GET(
      jsonRequest(`${BASE}/listings/ep-gate`, 'GET') as any, ctxId('listings', 'ep-gate'));
    expect(found.status).toBe(200);

    const missing = await recordRoute.GET(
      jsonRequest(`${BASE}/listings/nope-nope`, 'GET') as any, ctxId('listings', 'nope-nope'));
    expect(missing.status).toBe(404);

    const badCollection = await collectionRoute.GET(
      jsonRequest(`${BASE}/leaderboard`, 'GET') as any, ctx('leaderboard'));
    expect(badCollection.status).toBe(404);
  });
});

describe('authenticated create/edit', () => {
  it('rejects unauthenticated create with a typed 401', async () => {
    const response = await collectionRoute.POST(
      jsonRequest(`${BASE}/builders`, 'POST', builderBody()) as any, ctx('builders'));
    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.type).toBe('https://emiliaprotocol.ai/errors/unauthorized');
  });

  it('rejects unauthenticated edit with a typed 401', async () => {
    const response = await recordRoute.PATCH(
      jsonRequest(`${BASE}/builders/route-builder`, 'PATCH', { name: 'X' }) as any,
      ctxId('builders', 'route-builder'));
    expect(response.status).toBe(401);
  });

  it('creates with a valid key and stamps the tenant as owner', async () => {
    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-a', environment: 'test', permissions: [], keyId: 'key-1',
    });
    const response = await collectionRoute.POST(
      jsonRequest(`${BASE}/builders`, 'POST', builderBody()) as any, ctx('builders'));
    expect(response.status).toBe(201);
    const body = await response.json();
    expect(body.record.owner_tenant_id).toBe('tenant-a');
  });

  it('refuses cross-tenant edits with 403', async () => {
    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-a', environment: 'test', permissions: [], keyId: 'key-1',
    });
    await collectionRoute.POST(
      jsonRequest(`${BASE}/builders`, 'POST', builderBody()) as any, ctx('builders'));

    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-b', environment: 'test', permissions: [], keyId: 'key-2',
    });
    const response = await recordRoute.PATCH(
      jsonRequest(`${BASE}/builders/route-builder`, 'PATCH', { name: 'Hijack' }) as any,
      ctxId('builders', 'route-builder'));
    expect(response.status).toBe(403);
    const body = await response.json();
    expect(body.type).toBe('https://emiliaprotocol.ai/errors/forbidden_not_owner');
  });

  it('refuses edits to read-only example seeds with 403', async () => {
    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-a', environment: 'test', permissions: [], keyId: 'key-1',
    });
    const response = await recordRoute.PATCH(
      jsonRequest(`${BASE}/listings/ep-gate`, 'PATCH', { summary: 'Defaced' }) as any,
      ctxId('listings', 'ep-gate'));
    expect(response.status).toBe(403);
    const body = await response.json();
    expect(body.type).toBe('https://emiliaprotocol.ai/errors/seed_immutable');
  });

  it('returns a typed 400 problem for malformed JSON, never an unhandled throw', async () => {
    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-a', environment: 'test', permissions: [], keyId: 'key-1',
    });
    const response = await collectionRoute.POST(new Request(`${BASE}/builders`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not json',
    }) as any, ctx('builders'));
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
    const body = await response.json();
    expect(typeof body.type).toBe('string');
  });

  it('returns the validator problem for a hostile record body', async () => {
    mocks.authenticate.mockResolvedValue({
      tenantId: 'tenant-a', environment: 'test', permissions: [], keyId: 'key-1',
    });
    const response = await collectionRoute.POST(
      jsonRequest(`${BASE}/cards`, 'POST', {
        card_id: 'hostile-card',
        builder_id: 'route-builder',
        claim: {
          statement: 'Best and most trustworthy agent.',
          status: 'VERIFIED',
          scope: 'everywhere',
          source: { kind: 'claimant', reference: 'mailto:me@example.com' },
          observed_at: '2026-08-08T00:00:00Z',
        },
      }) as any, ctx('cards'));
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.type).toBe('https://emiliaprotocol.ai/errors/verified_requires_source');
  });
});
