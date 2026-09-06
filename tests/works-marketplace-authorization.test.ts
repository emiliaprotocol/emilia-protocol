// SPDX-License-Identifier: Apache-2.0
// Independent abuse tests: real record relationships/storage, mocked key identity.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import OpportunityForm from '../app/works/OpportunityForm';
import RequestAuthorityRecord from '../app/works/records/[recordId]/RequestAuthorityRecord';
import QualificationForm from '../app/works/qualification/QualificationForm';

const auth = vi.hoisted(() => ({ authenticate: vi.fn() }));
vi.mock('@/lib/supabase', async importOriginal => {
  const actual = await importOriginal<typeof import('../lib/supabase.ts')>();
  return { ...actual, authenticateRequest: auth.authenticate };
});

const { createWorksRecord } = await import('../lib/works/store');
const ownedRoute = await import('../app/api/works/[collection]/[id]/owned/route');
const inboxRoute = await import('../app/api/works/opportunities/[id]/inbox/route');
const ordinaryRoute = await import('../app/api/works/[collection]/[id]/route');
const { publishRecordWithRecovery } = await import('../app/works/join/owned-record');
const { sendOrCheckSubmission } = await import('../app/works/SubmissionForm');

const SELLER = '11111111-1111-4111-8111-111111111111';
const BUYER = '22222222-2222-4222-8222-222222222222';
const OTHER = '33333333-3333-4333-8333-333333333333';
const ADMIN = '44444444-4444-4444-8444-444444444444';
const identities: Record<string, { id: string; permissions?: string[] }> = {
  seller: { id: SELLER }, buyer: { id: BUYER }, other: { id: OTHER },
  admin: { id: ADMIN, permissions: ['admin'] },
};
const BASE = 'https://www.emiliaprotocol.ai/api/works';
let directory: string;

function request(route: string, key?: string) {
  return new NextRequest(`${BASE}/${route}`, { headers: {
    ...(key ? { authorization: `Bearer ${key}` } : {}),
    'x-owner-entity-id': BUYER, 'x-admin': 'true',
  } });
}
function owned(collection = 'builders', id = 'security-builder', key?: string) {
  return ownedRoute.GET(request(`${collection}/${id}/owned`, key), {
    params: Promise.resolve({ collection, id }),
  });
}
function inbox(id = 'buyer-job', key?: string, query = '') {
  return inboxRoute.GET(request(`opportunities/${id}/inbox${query}`, key), {
    params: Promise.resolve({ id }),
  });
}
async function create(collection: string, record: unknown, ownerEntityId: string) {
  const result = await createWorksRecord(collection, record, { ownerEntityId });
  expect(result.ok).toBe(true);
}
function privateHeaders(response: Response) {
  expect(response.headers.get('cache-control')).toContain('no-store');
  expect(response.headers.get('cache-control')).toContain('private');
  expect(response.headers.get('vary')?.toLowerCase()).toContain('authorization');
}

beforeEach(async () => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'emilia-market-auth-'));
  vi.stubEnv('WORKS_DATA_DIR', directory);
  vi.stubEnv('WORKS_V0', '1');
  auth.authenticate.mockReset();
  auth.authenticate.mockImplementation(async (incoming: Request) => {
    const actor = identities[incoming.headers.get('authorization')?.replace(/^Bearer /, '') ?? ''];
    return actor ? { entity: { id: actor.id, display_name: 'Authenticated actor' }, permissions: actor.permissions ?? [] }
      : { error: 'Authentication refused', status: 401, code: 'unauthorized' };
  });
  await create('builders', {
    builder_id: 'security-builder', kind: 'person', name: 'Real builder',
    contact_route: 'mailto:builder@example.com', owner_entity_id: BUYER, api_key: 'INPUT_SECRET_NOT_A_FIELD',
  }, SELLER);
  await create('listings', {
    listing_id: 'security-agent', builder_id: 'security-builder', kind: 'agent',
    name: 'Worker', summary: 'Declared worker.',
  }, SELLER);
  for (const [opportunity_id, owner] of [['buyer-job', BUYER], ['other-job', OTHER]]) {
    await create('opportunities', {
      opportunity_id, kind: 'problem', title: 'A customer job', description: 'A bounded job.',
      posted_by: 'Customer', contact_route: 'mailto:customer@example.com', claims: [],
    }, owner);
  }
  for (const [submission_id, opportunity_id, visibility, proposal] of [
    ['buyer-private', 'buyer-job', 'private', 'PRIVATE_BUYER_PROPOSAL'],
    ['buyer-public', 'buyer-job', 'public', 'PUBLIC_BUYER_PROPOSAL'],
    ['other-private', 'other-job', 'private', 'PRIVATE_OTHER_PROPOSAL'],
  ]) {
    await create('submissions', { submission_id, opportunity_id, visibility, proposal,
      builder_id: 'security-builder', listing_id: 'security-agent', team: ['Declared teammate'],
    }, SELLER);
  }
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  fs.rmSync(directory, { recursive: true, force: true });
});

describe('seller recovery does not infer ownership from public equality', () => {
  const profile = {
    builder_id: 'security-builder', kind: 'person' as const, name: 'Real builder',
    affiliations: [], contact_route: 'mailto:builder@example.com',
  };

  it.each([
    { collection: 'builders', owned: false, record: profile },
    { collection: 'listings', owned: true, record: profile },
    { collection: 'builders', owned: true, record: { ...profile, builder_id: 'other-profile' } },
    { collection: 'builders', owned: true, record: { ...profile, contact_route: 'mailto:changed@example.com' } },
  ])('refuses unowned, wrong-scope or changed-content success bodies after a duplicate %j', async body => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('{}', { status: 409 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(body), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(publishRecordWithRecovery('builders', 'SYNTHETIC_SECRET_KEY', profile, new AbortController().signal)).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1][0]).toBe('/api/works/builders/security-builder/owned');
    for (const [url, init] of fetcher.mock.calls) {
      expect(url).not.toContain('SYNTHETIC_SECRET_KEY');
      expect(init.body ?? '').not.toContain('SYNTHETIC_SECRET_KEY');
    }
  });

  it('recovers only an identical record returned by the authenticated owner-only route', async () => {
    const fetcher = vi.fn().mockRejectedValueOnce(new Error('Response lost after write'))
      .mockResolvedValueOnce(new Response(JSON.stringify({ collection: 'builders', owned: true,
        record: { ...profile, created_at: '2026-09-06T00:00:00Z' },
      }), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(publishRecordWithRecovery('builders', 'SYNTHETIC_SECRET_KEY', profile, new AbortController().signal)).resolves.toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1][0]).toBe('/api/works/builders/security-builder/owned');
    expect(fetcher.mock.calls[1][1].headers.authorization).toBe('Bearer SYNTHETIC_SECRET_KEY');
  });

  it('never recovers through an anonymous/public fallback or starts a new write after owner read refusal', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('{}', { status: 409 }))
      .mockResolvedValueOnce(new Response('{"detail":"PRIVATE_OWNER_ERROR"}', { status: 404 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(publishRecordWithRecovery('builders', 'SYNTHETIC_SECRET_KEY', profile, new AbortController().signal)).rejects.toThrow('not assumed to be yours');
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.map(call => call[0])).toEqual([
      '/api/works/builders', '/api/works/builders/security-builder/owned',
    ]);
  });
});

describe('builder proposal recovery stays separate from the employer inbox', () => {
  const payload = {
    submission_id: 'buyer-private', opportunity_id: 'buyer-job', builder_id: 'security-builder',
    listing_id: 'security-agent', proposal: 'PRIVATE_BUYER_PROPOSAL', team: ['Declared teammate'],
    visibility: 'private' as const,
  };

  it('checks only the named proposal without a new POST or access to the buyer inbox', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ collection: 'submissions', record: payload }), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(sendOrCheckSubmission(payload, 'SYNTHETIC_SECRET_KEY', true)).resolves.toBeUndefined();
    expect(fetcher).toHaveBeenCalledExactlyOnceWith('/api/works/submissions/buyer-private', {
      method: 'GET', headers: { authorization: 'Bearer SYNTHETIC_SECRET_KEY', 'content-type': 'application/json' },
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    });
  });

  it('reconciles a duplicate ID only against the exact original proposal and visibility', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('{}', { status: 409 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ collection: 'submissions', record: payload }), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(sendOrCheckSubmission(payload, 'SYNTHETIC_SECRET_KEY')).resolves.toBeUndefined();
    expect(fetcher.mock.calls.map(([url, init]) => [url, init.method])).toEqual([
      ['/api/works/submissions', 'POST'], ['/api/works/submissions/buyer-private', 'GET'],
    ]);
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual(payload);
  });

  it.each([
    { ...payload, visibility: 'public' }, { ...payload, opportunity_id: 'other-job' },
    { ...payload, builder_id: 'other-builder' }, { ...payload, team: ['Different teammate'] },
  ])('cannot confirm a record whose proposal scope or consent changed: %j', async record => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ collection: 'submissions', record }), { status: 200 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(sendOrCheckSubmission(payload, 'SYNTHETIC_SECRET_KEY', true)).rejects.toThrow('submission_confirmation_missing');
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it.each([401, 403, 404, 503])('does not report HTTP %i as acceptance or expose its private error detail', async status => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response('{"detail":"PRIVATE_SERVER_DETAIL"}', { status })));
    await expect(sendOrCheckSubmission(payload, 'SYNTHETIC_SECRET_KEY', true)).rejects.toThrow(/^submission_(?:access_refused|confirmation_missing)$/);
  });
});

describe('owner-only listing/profile recovery', () => {
  it('requires authentication even for an otherwise public profile', async () => {
    const response = await owned();
    expect(response.status).toBe(401);
    privateHeaders(response);
    expect(await response.text()).not.toContain('Real builder');
  });

  it.each(['builders', 'listings'])('returns only the actual %s owner projection, never key or custody metadata', async collection => {
    const id = collection === 'builders' ? 'security-builder' : 'security-agent';
    const response = await owned(collection, id, 'seller');
    expect(response.status).toBe(200);
    privateHeaders(response);
    const body = await response.json();
    expect(body.owned).toBe(true);
    expect(body.collection).toBe(collection);
    expect(JSON.stringify(body)).not.toMatch(/INPUT_SECRET_NOT_A_FIELD|owner_entity_id|owner_tenant_id|api_key/);
    expect(JSON.stringify(body)).not.toContain(SELLER);
  });

  it('does not treat matching public content, spoofed headers or admin status as profile ownership', async () => {
    const responses = await Promise.all([
      owned('builders', 'security-builder', 'buyer'), owned('builders', 'missing-builder', 'buyer'),
      owned('builders', 'security-builder', 'admin'),
    ]);
    const bodies: string[] = [];
    for (const response of responses) {
      expect(response.status).toBe(404); privateHeaders(response); bodies.push(await response.text());
    }
    expect(new Set(bodies).size).toBe(1);
  });

  it('fails closed on auth service errors without disclosing or caching error details', async () => {
    auth.authenticate.mockRejectedValueOnce(new Error('PRIVATE_BACKEND_AUTH_DETAIL'));
    const response = await owned('builders', 'security-builder', 'seller');
    expect(response.status).toBe(503); privateHeaders(response);
    expect(await response.text()).not.toContain('PRIVATE_BACKEND_AUTH_DETAIL');
  });
});

describe('private forms before hydration', () => {
  it('renders sponsor keys, requester email and evidence controls disabled with a native POST fallback', () => {
    for (const element of [
      createElement(OpportunityForm),
      createElement(RequestAuthorityRecord, { recordId: 'record-under-review', verifiedRequesters: 0, verifiedOrganizations: 0 }),
      createElement(QualificationForm),
    ]) {
      const html = renderToStaticMarkup(element);
      expect(html).toMatch(/<form[^>]*method="post"/);
      expect(html).toMatch(/<fieldset[^>]*disabled=""/);
      expect(html).toMatch(/<button(?=[^>]*type="submit")(?=[^>]*disabled="")[^>]*>/);
      expect(html).toContain('JavaScript is required');
      expect(html).not.toMatch(/<form[^>]*method="get"/);
    }
  });
});

describe('exact-job private proposal inbox', () => {
  it('checks the feature flag before identity or records on both private routes', async () => {
    vi.stubEnv('WORKS_V0', '0');
    for (const response of await Promise.all([owned('builders', 'security-builder', 'seller'), inbox('buyer-job', 'buyer')])) {
      expect(response.status).toBe(404); privateHeaders(response);
    }
    expect(auth.authenticate).not.toHaveBeenCalled();
  });

  it('does not accept a public request, query actor or spoofed owner header as authority', async () => {
    const response = await inbox('buyer-job', undefined, `?viewerEntityId=${BUYER}&isAdmin=true`);
    expect(response.status).toBe(401); privateHeaders(response);
    expect(await response.text()).not.toContain('PRIVATE_BUYER_PROPOSAL');
    expect(auth.authenticate).not.toHaveBeenCalled();
  });

  it('makes foreign and missing jobs indistinguishable, even when the submitter can read their own proposal elsewhere', async () => {
    const ordinary = await ordinaryRoute.GET(request('submissions/buyer-private', 'seller'), {
      params: Promise.resolve({ collection: 'submissions', id: 'buyer-private' }),
    });
    expect(ordinary.status).toBe(200);
    const responses = await Promise.all([
      inbox('buyer-job', 'seller'), inbox('missing-job', 'seller'),
      inbox('buyer-job', 'other', `?ownerEntityId=${BUYER}&viewerEntityId=${BUYER}&isAdmin=true`),
    ]);
    const bodies: string[] = [];
    for (const response of responses) {
      expect(response.status).toBe(404); privateHeaders(response); bodies.push(await response.text());
    }
    expect(new Set(bodies).size).toBe(1);
  });

  it('returns only the exact job to its owner, with no stable identity/key fields', async () => {
    const response = await inbox('buyer-job', 'buyer', '?opportunity_id=other-job');
    expect(response.status).toBe(200); privateHeaders(response);
    const body = await response.json();
    expect(body.opportunity_id).toBe('buyer-job');
    expect(body.access).toBe('owner');
    expect(body.records.map((record: { submission_id: string }) => record.submission_id).sort()).toEqual(['buyer-private', 'buyer-public']);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toMatch(/PRIVATE_OTHER_PROPOSAL|owner_entity_id|owner_tenant_id|api_key/);
    expect(serialized).not.toContain(BUYER);
    expect(serialized).not.toContain(SELLER);
  });

  it('separately labels existing administrator authority and still restricts the returned job', async () => {
    const response = await inbox('buyer-job', 'admin');
    expect(response.status).toBe(200); privateHeaders(response);
    const body = await response.json();
    expect(body.access).toBe('administrator');
    expect(body.records).toHaveLength(2);
    expect(JSON.stringify(body)).not.toContain('PRIVATE_OTHER_PROPOSAL');
  });

  it.each(['?offset=-1', '?offset=0&offset=50', '?offset=1e3', '?offset=1000000'])('rejects ambiguous or unbounded pagination %s without private data', async query => {
    const response = await inbox('buyer-job', 'buyer', query);
    expect(response.status).toBe(400); privateHeaders(response);
    expect(await response.text()).not.toContain('PRIVATE_BUYER_PROPOSAL');
  });

  it('rejects slug-only identity and does not turn an authentication outage into an empty inbox', async () => {
    auth.authenticate.mockResolvedValueOnce({ entity: { id: 'buyer-slug' }, permissions: ['admin'] });
    const invalid = await inbox('buyer-job', 'buyer');
    expect(invalid.status).toBe(401); privateHeaders(invalid);
    auth.authenticate.mockRejectedValueOnce(new Error('PRIVATE_BACKEND_INBOX_DETAIL'));
    const failed = await inbox('buyer-job', 'buyer');
    expect(failed.status).toBe(503); privateHeaders(failed);
    const body = await failed.text();
    expect(body).not.toContain('PRIVATE_BACKEND_INBOX_DETAIL');
    expect(body).not.toContain('"records":[]');
  });
});
