// SPDX-License-Identifier: Apache-2.0
//
// /api/works/* route contract: public reads behind WORKS_V0, regular EMILIA
// entity API-key writes, narrow owner projection, and typed problem responses.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
}));

vi.mock('@/lib/supabase', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/supabase.ts')>();
  return { ...actual, authenticateRequest: mocks.authenticate };
});

const collectionRoute = await import('../app/api/works/[collection]/route.ts');
const recordRoute = await import('../app/api/works/[collection]/[id]/route.ts');

let dir: string;

const OWNER_A = '11111111-1111-4111-8111-111111111111';
const OWNER_B = '22222222-2222-4222-8222-222222222222';
const BASE = 'https://www.emiliaprotocol.ai/api/works';

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'works-routes-'));
  process.env.WORKS_DATA_DIR = dir;
  process.env.WORKS_V0 = '1';
  mocks.authenticate.mockReset();
  mocks.authenticate.mockResolvedValue({
    error: 'Missing or invalid API key', code: 'missing_key', status: 401,
  });
});

afterEach(() => {
  delete process.env.WORKS_DATA_DIR;
  delete process.env.WORKS_V0;
  fs.rmSync(dir, { recursive: true, force: true });
});

function authenticate(
  id = OWNER_A,
  displayName = 'Route Test Entity',
  permissions: string[] = [],
) {
  mocks.authenticate.mockResolvedValue({
    entity: { id, display_name: displayName },
    permissions,
  });
}

function jsonRequest(url: string, method: string, body?: unknown, authenticated = false): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (authenticated) headers.authorization = 'Bearer ep_live_test-key-never-returned';
  return new Request(url, {
    method,
    headers,
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

function listingBody(id = 'route-listing', builderId = 'route-builder') {
  return {
    listing_id: id,
    builder_id: builderId,
    kind: 'agent',
    name: 'Route Agent',
    summary: 'A route test listing.',
  };
}

async function post(collection: string, body: unknown) {
  return collectionRoute.POST(
    jsonRequest(`${BASE}/${collection}`, 'POST', body, true) as any,
    ctx(collection),
  );
}

describe('feature flag and public reads', () => {
  it('404s every method before authentication when WORKS_V0 is off', async () => {
    delete process.env.WORKS_V0;
    expect((await collectionRoute.GET(
      jsonRequest(`${BASE}/listings`, 'GET') as any, ctx('listings'))).status).toBe(404);
    expect((await post('builders', builderBody())).status).toBe(404);
    expect((await recordRoute.GET(
      jsonRequest(`${BASE}/listings/ep-gate`, 'GET') as any,
      ctxId('listings', 'ep-gate'))).status).toBe(404);
    expect((await recordRoute.PATCH(
      jsonRequest(`${BASE}/listings/ep-gate`, 'PATCH', {}) as any,
      ctxId('listings', 'ep-gate'))).status).toBe(404);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });

  it('keeps GET unauthenticated while the exact flag value is 1', async () => {
    const response = await collectionRoute.GET(
      jsonRequest(`${BASE}/listings`, 'GET') as any, ctx('listings'));
    expect(response.status).toBe(200);
    expect(mocks.authenticate).not.toHaveBeenCalled();

    process.env.WORKS_V0 = 'true';
    expect((await collectionRoute.GET(
      jsonRequest(`${BASE}/listings`, 'GET') as any, ctx('listings'))).status).toBe(404);
  });

  it('reads examples and returns typed 404s for unknown records/collections', async () => {
    expect((await recordRoute.GET(
      jsonRequest(`${BASE}/listings/ep-gate`, 'GET') as any,
      ctxId('listings', 'ep-gate'))).status).toBe(200);
    expect((await recordRoute.GET(
      jsonRequest(`${BASE}/listings/nope-nope`, 'GET') as any,
      ctxId('listings', 'nope-nope'))).status).toBe(404);
    expect((await collectionRoute.GET(
      jsonRequest(`${BASE}/leaderboard`, 'GET') as any,
      ctx('leaderboard'))).status).toBe(404);
  });
});

describe('regular entity API-key authentication', () => {
  it('returns typed authentication failures and preserves service-unavailable status', async () => {
    const unauthorized = await post('builders', builderBody());
    expect(unauthorized.status).toBe(401);
    expect((await unauthorized.json()).type).toBe('https://emiliaprotocol.ai/errors/missing_key');

    mocks.authenticate.mockResolvedValue({
      error: 'Authentication service unavailable',
      code: 'auth_service_unavailable',
      status: 503,
    });
    const unavailable = await post('builders', builderBody());
    expect(unavailable.status).toBe(503);
    const body = await unavailable.json();
    expect(body.type).toBe('https://emiliaprotocol.ai/errors/auth_service_unavailable');
    expect(JSON.stringify(body)).not.toContain('test-key-never-returned');
  });

  it('rejects auth results without a stable entity DB UUID', async () => {
    authenticate('entity-public-slug');
    const response = await post('builders', builderBody());
    expect(response.status).toBe(401);
    expect((await response.json()).type).toBe('https://emiliaprotocol.ai/errors/invalid_actor');
  });

  it('uses the projected entity DB id internally without exposing owner/key identity', async () => {
    authenticate();
    const response = await post('builders', builderBody());
    expect(response.status).toBe(201);
    const body = await response.json();
    expect(body.record.owner_entity_id).toBeUndefined();
    expect(body.record.owner_tenant_id).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('test-key-never-returned');
  });
});

describe('write safety', () => {
  it('binds opportunity posted_by to the authenticated display name', async () => {
    authenticate(OWNER_A, 'Bound Entity Name');
    const response = await post('opportunities', {
      opportunity_id: 'route-opportunity',
      kind: 'challenge',
      title: 'Route challenge',
      description: 'A bounded challenge.',
      posted_by: 'Body-Controlled Impostor',
      contact_route: 'mailto:buyer@example.com',
      claims: [],
    });
    expect(response.status).toBe(201);
    expect((await response.json()).record.posted_by).toBe('Bound Entity Name');
  });

  it('rejects VERIFIED claims even when a self-service caller supplies URL and hash', async () => {
    authenticate();
    expect((await post('builders', builderBody())).status).toBe(201);
    const response = await post('cards', {
      card_id: 'hostile-card',
      builder_id: 'route-builder',
      claim: {
        statement: 'Best and most trustworthy agent.',
        status: 'VERIFIED',
        scope: 'everywhere',
        source: {
          kind: 'content_addressed_artifact',
          reference: 'https://example.com/evidence.json',
          sha256: '70896da9789ab31f144ffdb8ac4b82bf4900d7a79f6de7666516ed72023acc80',
        },
        observed_at: '2026-08-08T00:00:00Z',
      },
    });
    expect(response.status).toBe(400);
    expect((await response.json()).type)
      .toBe('https://emiliaprotocol.ai/errors/verified_claim_forbidden');
  });

  it('rejects example=true and missing same-owner references', async () => {
    authenticate();
    const example = await post('builders', { ...builderBody(), example: true });
    expect(example.status).toBe(400);
    expect((await example.json()).type).toBe('https://emiliaprotocol.ai/errors/example_reserved');

    const listing = await post('listings', listingBody());
    expect(listing.status).toBe(400);
    expect((await listing.json()).type).toBe('https://emiliaprotocol.ai/errors/reference_not_found');
  });

  it('returns a typed error for submissions to example opportunities', async () => {
    authenticate();
    expect((await post('builders', builderBody())).status).toBe(201);
    expect((await post('listings', listingBody())).status).toBe(201);
    const response = await post('submissions', {
      submission_id: 'seed-target-submission',
      opportunity_id: 'ex-reproduce-conformance',
      builder_id: 'route-builder',
      listing_id: 'route-listing',
      proposal: 'This must target a durable opportunity.',
    });
    expect(response.status).toBe(400);
    expect((await response.json()).type)
      .toBe('https://emiliaprotocol.ai/errors/seed_reference_forbidden');
  });

  it('enforces owner-only edits and rechecks cross-owner PATCH references', async () => {
    authenticate(OWNER_A, 'Entity A');
    expect((await post('builders', builderBody())).status).toBe(201);
    expect((await post('listings', listingBody())).status).toBe(201);

    authenticate(OWNER_B, 'Entity B');
    expect((await post('builders', builderBody('foreign-builder'))).status).toBe(201);
    expect((await post('listings', listingBody('foreign-listing', 'foreign-builder'))).status).toBe(201);

    const ownership = await recordRoute.PATCH(
      jsonRequest(`${BASE}/builders/route-builder`, 'PATCH', { name: 'Hijack' }, true) as any,
      ctxId('builders', 'route-builder'));
    expect(ownership.status).toBe(403);
    expect((await ownership.json()).type)
      .toBe('https://emiliaprotocol.ai/errors/forbidden_not_owner');

    authenticate(OWNER_A, 'Entity A');
    const refs = await recordRoute.PATCH(
      jsonRequest(`${BASE}/listings/route-listing`, 'PATCH', {
        builder_id: 'foreign-builder',
      }, true) as any,
      ctxId('listings', 'route-listing'));
    expect(refs.status).toBe(403);
    expect((await refs.json()).type)
      .toBe('https://emiliaprotocol.ai/errors/forbidden_reference_owner');
  });

  it('returns typed validation problems for malformed JSON', async () => {
    authenticate();
    const response = await collectionRoute.POST(new Request(`${BASE}/builders`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ep_live_test' },
      body: '{not json',
    }) as any, ctx('builders'));
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
    expect(typeof (await response.json()).type).toBe('string');
  });
});

describe('submission privacy', () => {
  it('does not expose the unmarked example submission anonymously', async () => {
    const listed = await collectionRoute.GET(
      jsonRequest(`${BASE}/submissions`, 'GET') as any,
      ctx('submissions'));
    expect(listed.status).toBe(200);
    expect((await listed.json()).records.some((record: any) => (
      record.submission_id === 'ex-submission-conformance'
    ))).toBe(false);

    const found = await recordRoute.GET(
      jsonRequest(`${BASE}/submissions/ex-submission-conformance`, 'GET') as any,
      ctxId('submissions', 'ex-submission-conformance'));
    expect(found.status).toBe(404);
  });

  it('does not expose private submissions on unauthenticated list/get', async () => {
    authenticate(OWNER_A, 'Builder Entity');
    expect((await post('builders', builderBody())).status).toBe(201);
    expect((await post('listings', listingBody())).status).toBe(201);

    authenticate(OWNER_B, 'Opportunity Entity');
    expect((await post('opportunities', {
      opportunity_id: 'route-opportunity',
      kind: 'challenge',
      title: 'Route challenge',
      description: 'A bounded challenge.',
      posted_by: 'ignored',
      contact_route: 'mailto:buyer@example.com',
      claims: [],
    })).status).toBe(201);

    authenticate(OWNER_A, 'Builder Entity');
    const base = {
      opportunity_id: 'route-opportunity',
      builder_id: 'route-builder',
      listing_id: 'route-listing',
      proposal: 'A bounded proposal.',
    };
    expect((await post('submissions', {
      ...base, submission_id: 'private-submission',
    })).status).toBe(201);
    expect((await post('submissions', {
      ...base, submission_id: 'public-submission', visibility: 'public',
    })).status).toBe(201);

    mocks.authenticate.mockClear();
    const listed = await collectionRoute.GET(
      jsonRequest(`${BASE}/submissions`, 'GET') as any, ctx('submissions'));
    expect(listed.status).toBe(200);
    const records = (await listed.json()).records;
    expect(records.some((record: any) => record.submission_id === 'private-submission')).toBe(false);
    expect(records.some((record: any) => record.submission_id === 'public-submission')).toBe(true);

    const privateGet = await recordRoute.GET(
      jsonRequest(`${BASE}/submissions/private-submission`, 'GET') as any,
      ctxId('submissions', 'private-submission'));
    expect(privateGet.status).toBe(404);
    expect((await recordRoute.GET(
      jsonRequest(`${BASE}/submissions/public-submission`, 'GET') as any,
      ctxId('submissions', 'public-submission'))).status).toBe(200);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });

  it('allows private reads only to the submitter, opportunity owner, or existing admin permission', async () => {
    authenticate(OWNER_A, 'Builder Entity');
    expect((await post('builders', builderBody())).status).toBe(201);
    expect((await post('listings', listingBody())).status).toBe(201);

    authenticate(OWNER_B, 'Opportunity Entity');
    expect((await post('opportunities', {
      opportunity_id: 'route-opportunity',
      kind: 'challenge',
      title: 'Route challenge',
      description: 'A bounded challenge.',
      posted_by: 'ignored',
      contact_route: 'mailto:buyer@example.com',
      claims: [],
    })).status).toBe(201);

    authenticate(OWNER_A, 'Builder Entity');
    expect((await post('submissions', {
      submission_id: 'private-submission',
      opportunity_id: 'route-opportunity',
      builder_id: 'route-builder',
      listing_id: 'route-listing',
      proposal: 'A private proposal.',
    })).status).toBe(201);

    for (const id of [OWNER_A, OWNER_B]) {
      authenticate(id);
      const response = await recordRoute.GET(
        jsonRequest(`${BASE}/submissions/private-submission`, 'GET', undefined, true) as any,
        ctxId('submissions', 'private-submission'));
      expect(response.status).toBe(200);
    }

    authenticate('33333333-3333-4333-8333-333333333333', 'Unrelated Entity');
    const unrelated = await recordRoute.GET(
      jsonRequest(`${BASE}/submissions/private-submission`, 'GET', undefined, true) as any,
      ctxId('submissions', 'private-submission'));
    expect(unrelated.status).toBe(404);

    authenticate('33333333-3333-4333-8333-333333333333', 'Admin Entity', ['admin']);
    const admin = await recordRoute.GET(
      jsonRequest(`${BASE}/submissions/private-submission`, 'GET', undefined, true) as any,
      ctxId('submissions', 'private-submission'));
    expect(admin.status).toBe(200);
  });
});
