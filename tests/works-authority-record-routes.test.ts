// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
  createDraft: vi.fn(),
  claim: vi.fn(),
  listPublic: vi.fn(),
  getPublic: vi.fn(),
  getOwner: vi.fn(),
  revise: vi.fn(),
  approve: vi.fn(),
  withdraw: vi.fn(),
}));

vi.mock('@/lib/supabase', async (original) => {
  const actual = await original<typeof import('../lib/supabase.ts')>();
  return { ...actual, authenticateRequest: mocks.authenticate };
});
vi.mock('@/lib/works/authority-record-store', () => ({
  createSupabaseAuthorityRecordStore: () => ({ mocked: true }),
}));
vi.mock('@/lib/works/authority-record-service', async (original) => {
  const actual = await original<typeof import('../lib/works/authority-record-service.ts')>();
  return {
    ...actual,
    createAuthorityRecordDraft: mocks.createDraft,
    claimAuthorityRecord: mocks.claim,
    listPublicAuthorityRecords: mocks.listPublic,
    getPublicAuthorityRecord: mocks.getPublic,
    getOwnerAuthorityRecord: mocks.getOwner,
    reviseAuthorityRecord: mocks.revise,
    approveAuthorityRecord: mocks.approve,
    withdrawAuthorityRecord: mocks.withdraw,
  };
});

const draftsRoute = await import('../app/api/works/authority-records/drafts/route.ts');
const claimRoute = await import('../app/api/works/authority-records/claim/route.ts');
const listRoute = await import('../app/api/works/authority-records/route.ts');
const recordRoute = await import('../app/api/works/authority-records/[recordId]/route.ts');
const approveRoute = await import('../app/api/works/authority-records/[recordId]/approve/route.ts');
const withdrawRoute = await import('../app/api/works/authority-records/[recordId]/withdraw/route.ts');

const BASE = 'https://www.emiliaprotocol.ai/api/works/authority-records';
const RECORD_ID = 'authority-record-acme-agent';

function request(url: string, method = 'GET', body?: unknown, token?: string) {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  return new Request(url, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const context = { params: Promise.resolve({ recordId: RECORD_ID }) };

beforeEach(() => {
  process.env.WORKS_V0 = '1';
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.authenticate.mockResolvedValue({
    entity: { id: '11111111-1111-4111-8111-111111111111' }, permissions: ['admin'],
  });
  mocks.createDraft.mockResolvedValue({ record_id: RECORD_ID, invitation_token: `ari1_${'a'.repeat(64)}` });
  mocks.claim.mockResolvedValue({ record_id: RECORD_ID, owner_token: `aro1_${'b'.repeat(64)}` });
  mocks.listPublic.mockResolvedValue([]);
  mocks.getPublic.mockResolvedValue(null);
  mocks.getOwner.mockResolvedValue({ record_id: RECORD_ID, status: 'CLAIMED_PRIVATE' });
  mocks.revise.mockResolvedValue({ record_id: RECORD_ID, version: 2 });
  mocks.approve.mockResolvedValue({ record_id: RECORD_ID, status: 'PUBLISHED' });
  mocks.withdraw.mockResolvedValue({ record_id: RECORD_ID, status: 'WITHDRAWN' });
});

describe('Authority Record route boundary', () => {
  it('404s every surface before auth or storage when the Marketplace flag is off', async () => {
    delete process.env.WORKS_V0;
    expect((await draftsRoute.POST(request(`${BASE}/drafts`, 'POST', {}) as any)).status).toBe(404);
    expect((await claimRoute.POST(request(`${BASE}/claim`, 'POST', {}) as any)).status).toBe(404);
    expect((await listRoute.GET()).status).toBe(404);
    expect((await recordRoute.GET(request(`${BASE}/${RECORD_ID}`) as any, context)).status).toBe(404);
    expect(mocks.authenticate).not.toHaveBeenCalled();
    expect(mocks.createDraft).not.toHaveBeenCalled();
    expect(mocks.claim).not.toHaveBeenCalled();
  });

  it('restricts private draft preparation to a stable admin entity', async () => {
    mocks.authenticate.mockResolvedValue({
      entity: { id: '11111111-1111-4111-8111-111111111111' }, permissions: [],
    });
    expect((await draftsRoute.POST(request(`${BASE}/drafts`, 'POST', {
      projection: {}, contact_route: 'mailto:owner@example.com',
    }, 'ep_live_test') as any)).status).toBe(403);
    expect(mocks.createDraft).not.toHaveBeenCalled();

    mocks.authenticate.mockResolvedValue({
      entity: { id: '11111111-1111-4111-8111-111111111111' }, permissions: ['admin'],
    });
    const response = await draftsRoute.POST(request(`${BASE}/drafts`, 'POST', {
      projection: { record_id: RECORD_ID }, contact_route: 'mailto:owner@example.com',
    }, 'ep_live_test') as any);
    expect(response.status).toBe(201);
    expect(mocks.createDraft).toHaveBeenCalledWith(expect.objectContaining({
      actor: { entityId: '11111111-1111-4111-8111-111111111111', isAdmin: true },
      siteOrigin: 'https://www.emiliaprotocol.ai',
    }));
  });

  it('keeps the claim route public but bounded and returns one-time owner material no-store', async () => {
    const response = await claimRoute.POST(request(`${BASE}/claim`, 'POST', {
      invitation_token: `ari1_${'a'.repeat(64)}`,
      proof_url: `https://raw.githubusercontent.com/acme/agent/${'a'.repeat(40)}/.well-known/emilia-authority-record.json`,
    }) as any);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect((await response.json()).owner_token).toMatch(/^aro1_/);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });

  it('serves only approved public records without requiring authentication', async () => {
    mocks.listPublic.mockResolvedValue([{ record_id: RECORD_ID }]);
    mocks.getPublic.mockResolvedValue({ record_id: RECORD_ID });
    expect((await listRoute.GET()).status).toBe(200);
    const response = await recordRoute.GET(request(`${BASE}/${RECORD_ID}`) as any, context);
    expect(response.status).toBe(200);
    expect(mocks.authenticate).not.toHaveBeenCalled();

    mocks.getPublic.mockResolvedValue(null);
    expect((await recordRoute.GET(request(`${BASE}/${RECORD_ID}`) as any, context)).status).toBe(404);
  });

  it('uses the owner token only from Authorization for inspect, revise, approve, and withdraw', async () => {
    const ownerToken = `aro1_${'b'.repeat(64)}`;
    expect((await recordRoute.POST(request(`${BASE}/${RECORD_ID}`, 'POST', undefined, ownerToken) as any, context)).status).toBe(200);
    expect((await recordRoute.PATCH(request(`${BASE}/${RECORD_ID}`, 'PATCH', {
      projection: { record_id: RECORD_ID }, owner_token: 'body-token-forbidden',
    }, ownerToken) as any, context)).status).toBe(400);
    expect(mocks.revise).not.toHaveBeenCalled();

    expect((await recordRoute.PATCH(request(`${BASE}/${RECORD_ID}`, 'PATCH', {
      projection: { record_id: RECORD_ID },
    }, ownerToken) as any, context)).status).toBe(200);
    expect((await approveRoute.POST(request(`${BASE}/${RECORD_ID}/approve`, 'POST', {
      record_digest: `sha256:${'a'.repeat(64)}`,
    }, ownerToken) as any, context)).status).toBe(200);
    expect((await withdrawRoute.POST(request(`${BASE}/${RECORD_ID}/withdraw`, 'POST', {}, ownerToken) as any, context)).status).toBe(200);
    expect(JSON.stringify(mocks.revise.mock.calls)).toContain(ownerToken);
  });

  it('maps service failures to typed problems without echoing credentials', async () => {
    const { AuthorityRecordServiceError } = await import('../lib/works/authority-record-service.ts');
    mocks.claim.mockRejectedValue(new AuthorityRecordServiceError(422, 'authority_record_proof_invalid', 'bad proof'));
    const token = `ari1_${'f'.repeat(64)}`;
    const response = await claimRoute.POST(request(`${BASE}/claim`, 'POST', {
      invitation_token: token, proof_url: 'https://example.com',
    }) as any);
    expect(response.status).toBe(422);
    expect(JSON.stringify(await response.json())).not.toContain(token);
  });
});
