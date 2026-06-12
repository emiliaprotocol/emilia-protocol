/**
 * SCIM 2.0 routes — integration test with an in-memory store.
 *
 * Drives the real route handlers (no HTTP server) through a full provisioning
 * lifecycle the way an IdP would: authenticate, create a user, list/filter,
 * fetch by id, deprovision via PATCH active=false, then delete — plus the
 * security-critical auth gate (no token / wrong-prefix token → 401).
 *
 * The Supabase client is replaced with a minimal in-memory implementation that
 * supports exactly the chain the routes use.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// ── In-memory Supabase mock ──────────────────────────────────────────────────
const store = { scim_provisioning_tokens: [], scim_users: [], scim_groups: [] };
let idSeq = 0;
const newId = () => `00000000-0000-0000-0000-${String(++idSeq).padStart(12, '0')}`;

class Query {
  constructor(table) { this.table = table; this.filters = []; this.op = null; this.payload = null; this._range = null; }
  select() { return this; }
  insert(row) { this.op = 'insert'; this.payload = row; return this; }
  update(patch) { this.op = 'update'; this.payload = patch; return this; }
  delete() { this.op = 'delete'; return this; }
  eq(col, val) { this.filters.push([col, val]); return this; }
  is(col, val) { this.filters.push([col, val]); return this; }
  order() { return this; }
  range(start, end) { this._range = [start, end]; return this; }

  _match() {
    return store[this.table].filter((row) => this.filters.every(([c, v]) => row[c] === v));
  }
  _applyInsert() {
    const row = { id: newId(), version: 1, created_at: '2026-06-11T00:00:00Z', updated_at: '2026-06-11T00:00:00Z', ...this.payload };
    // Enforce the (tenant_id, user_name) / (tenant_id, display_name) unique keys.
    const uniq = this.table === 'scim_users' ? 'user_name' : this.table === 'scim_groups' ? 'display_name' : null;
    if (uniq && store[this.table].some((r) => r.tenant_id === row.tenant_id && r[uniq] === row[uniq])) {
      return { data: null, error: { code: '23505', message: 'unique_violation' } };
    }
    store[this.table].push(row);
    return { data: row, error: null };
  }
  _applyUpdate() {
    const rows = this._match();
    if (!rows.length) return { data: null, error: null };
    Object.assign(rows[0], this.payload);
    return { data: rows[0], error: null };
  }
  async single() {
    if (this.op === 'insert') return this._applyInsert();
    if (this.op === 'update') return this._applyUpdate();
    const rows = this._match();
    return { data: rows[0] ?? null, error: null };
  }
  async maybeSingle() { const rows = this._match(); return { data: rows[0] ?? null, error: null }; }
  // Awaitable terminal for list selects and deletes.
  then(resolve, reject) {
    try {
      if (this.op === 'delete') {
        const keep = store[this.table].filter((row) => !this.filters.every(([c, v]) => row[c] === v));
        store[this.table] = keep;
        return resolve({ data: null, error: null });
      }
      let rows = this._match();
      const count = rows.length;
      if (this._range) rows = rows.slice(this._range[0], this._range[1] + 1);
      return resolve({ data: rows, count, error: null });
    } catch (e) { return reject(e); }
  }
}

const mockClient = { from: (table) => new Query(table) };
vi.mock('@/lib/write-guard', () => ({ getGuardedClient: () => mockClient }));

// Import AFTER mocks are registered.
const { authenticateScim, hashScimToken } = await import('../lib/scim/auth.js');
const Users = await import('../app/api/scim/v2/Users/route.js');
const UserById = await import('../app/api/scim/v2/Users/[id]/route.js');

// A request helper.
function req(method, url, { token, body } = {}) {
  const headers = new Headers();
  if (token) headers.set('authorization', `Bearer ${token}`);
  if (body) headers.set('content-type', 'application/json');
  return new Request(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
}

const TENANT = 'ep_entity_acme';
const TOKEN = 'ep_scim_testtoken0000000000000000000000000000000000000000000000000000';

beforeEach(() => {
  store.scim_provisioning_tokens = [{ id: 't1', tenant_id: TENANT, token_hash: hashScimToken(TOKEN), revoked_at: null }];
  store.scim_users = [];
  store.scim_groups = [];
  idSeq = 0;
});

describe('SCIM auth gate', () => {
  it('rejects a request with no token (401)', async () => {
    const r = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users'));
    expect(r.status).toBe(401);
  });
  it('rejects a non-SCIM bearer token (401)', async () => {
    const r = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: 'ep_live_not_a_scim_token' }));
    expect(r.status).toBe(401);
  });
  it('resolves a valid SCIM token to its tenant', async () => {
    const r = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: TOKEN }));
    expect(r.tenantId).toBe(TENANT);
  });
  it('rejects a revoked token', async () => {
    store.scim_provisioning_tokens[0].revoked_at = '2026-06-11T00:00:00Z';
    const r = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: TOKEN }));
    expect(r.status).toBe(401);
  });
});

describe('SCIM User lifecycle', () => {
  const base = 'https://x/api/scim/v2/Users';

  it('POST creates a user (201) and rejects duplicates (409)', async () => {
    const res = await Users.POST(req('POST', base, { token: TOKEN, body: { userName: 'bjensen@example.com', name: { givenName: 'Barbara' }, active: true } }));
    expect(res.status).toBe(201);
    const created = await res.json();
    expect(created.userName).toBe('bjensen@example.com');
    expect(created.id).toBeTruthy();

    const dup = await Users.POST(req('POST', base, { token: TOKEN, body: { userName: 'bjensen@example.com' } }));
    expect(dup.status).toBe(409);
    expect((await dup.json()).scimType).toBe('uniqueness');
  });

  it('POST without auth is 401', async () => {
    const res = await Users.POST(req('POST', base, { body: { userName: 'x@example.com' } }));
    expect(res.status).toBe(401);
  });

  it('GET lists and filters by userName eq', async () => {
    await Users.POST(req('POST', base, { token: TOKEN, body: { userName: 'a@example.com' } }));
    await Users.POST(req('POST', base, { token: TOKEN, body: { userName: 'b@example.com' } }));

    const all = await (await Users.GET(req('GET', base, { token: TOKEN }))).json();
    expect(all.totalResults).toBe(2);
    expect(all.schemas[0]).toContain('ListResponse');

    const filtered = await (await Users.GET(req('GET', `${base}?filter=${encodeURIComponent('userName eq "a@example.com"')}`, { token: TOKEN }))).json();
    expect(filtered.totalResults).toBe(1);
    expect(filtered.Resources[0].userName).toBe('a@example.com');
  });

  it('rejects an unsupported filter with 400 invalidFilter', async () => {
    const res = await Users.GET(req('GET', `${base}?filter=${encodeURIComponent('userName co "a"')}`, { token: TOKEN }));
    expect(res.status).toBe(400);
    expect((await res.json()).scimType).toBe('invalidFilter');
  });

  it('PATCH active=false deprovisions (the Azure offboarding path)', async () => {
    const created = await (await Users.POST(req('POST', base, { token: TOKEN, body: { userName: 'leaver@example.com', active: true } }))).json();
    const id = created.id;

    const res = await UserById.PATCH(req('PATCH', `${base}/${id}`, {
      token: TOKEN,
      body: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: false }] },
    }), { params: Promise.resolve({ id }) });
    expect(res.status).toBe(200);
    const patched = await res.json();
    expect(patched.active).toBe(false);
    // The stored row reflects the deprovision.
    expect(store.scim_users.find((u) => u.id === id).active).toBe(false);
  });

  it('GET by id then DELETE removes the user (204 then 404)', async () => {
    const created = await (await Users.POST(req('POST', base, { token: TOKEN, body: { userName: 'temp@example.com' } }))).json();
    const id = created.id;
    const params = { params: Promise.resolve({ id }) };

    const got = await UserById.GET(req('GET', `${base}/${id}`, { token: TOKEN }), params);
    expect(got.status).toBe(200);

    const del = await UserById.DELETE(req('DELETE', `${base}/${id}`, { token: TOKEN }), params);
    expect(del.status).toBe(204);
    expect(store.scim_users.find((u) => u.id === id)).toBeUndefined();

    const gone = await UserById.GET(req('GET', `${base}/${id}`, { token: TOKEN }), params);
    expect(gone.status).toBe(404);
  });
});
