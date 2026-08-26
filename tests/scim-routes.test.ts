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

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// ── In-memory Supabase mock ──────────────────────────────────────────────────
const store = { entities: [], scim_provisioning_tokens: [], scim_users: [], scim_groups: [], approver_credentials: [], audit_events: [] };
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
  // Awaitable terminal for list selects, deletes, bulk updates, bare inserts.
  then(resolve, reject) {
    try {
      if (this.op === 'delete') {
        const keep = store[this.table].filter((row) => !this.filters.every(([c, v]) => row[c] === v));
        store[this.table] = keep;
        return resolve({ data: null, error: null });
      }
      if (this.op === 'insert') {
        return resolve(this._applyInsert());
      }
      if (this.op === 'update') {
        // Bulk update: apply to every matching row (e.g. credential revocation
        // across all of an approver's keys).
        const rows = this._match();
        for (const row of rows) Object.assign(row, this.payload);
        return resolve({ data: rows.map((r) => ({ id: r.id })), error: null });
      }
      let rows = this._match();
      const count = rows.length;
      if (this._range) rows = rows.slice(this._range[0], this._range[1] + 1);
      return resolve({ data: rows, count, error: null });
    } catch (e) { return reject(e); }
  }
}

const mockClient = {
  from: (table) => new Query(table),
  async rpc(name, args) {
    const token = store.scim_provisioning_tokens.find((row) => row.id === args.p_token_id);
    const tokenAuthorized = Boolean(token
      && token.revoked_at === null
      && token.tenant_id === args.p_tenant_id
      && token.organization_id === args.p_organization_id);
    if (name === 'create_scim_user_authorized') {
      if (!tokenAuthorized) return { data: { error: 'token_authority_invalid' }, error: null };
      const inserted = new Query('scim_users').insert({
        ...args.p_fields,
        tenant_id: args.p_tenant_id,
      })._applyInsert();
      if (inserted.error) return inserted;
      return { data: { status: 'created', user: inserted.data }, error: null };
    }
    if (name === 'apply_scim_group_authorized') {
      if (!tokenAuthorized) return { data: { error: 'token_authority_invalid' }, error: null };
      if (!args.p_group_id) {
        const inserted = new Query('scim_groups').insert({
          display_name: args.p_fields.display_name,
          external_id: args.p_fields.external_id,
          members: args.p_fields.members,
          tenant_id: args.p_tenant_id,
        })._applyInsert();
        if (inserted.error) return inserted;
        return { data: { status: 'created', group: inserted.data }, error: null };
      }
      const group = store.scim_groups.find(
        (row) => row.tenant_id === args.p_tenant_id && row.id === args.p_group_id,
      );
      if (!group) return { data: { error: 'group_not_found' }, error: null };
      if ((group.version ?? 1) !== args.p_expected_version) {
        return { data: { error: 'version_conflict' }, error: null };
      }
      if (args.p_delete) {
        store.scim_groups = store.scim_groups.filter((row) => row !== group);
        return { data: { status: 'deleted' }, error: null };
      }
      Object.assign(group, {
        display_name: args.p_fields.display_name,
        external_id: args.p_fields.external_id,
        members: args.p_fields.members,
        version: (group.version ?? 1) + 1,
        updated_at: '2026-06-11T00:01:00Z',
      });
      return { data: { status: 'updated', group }, error: null };
    }
    if (name !== 'apply_scim_user_and_authority_atomic') {
      return { data: null, error: { message: `unknown rpc ${name}` } };
    }
    if (!tokenAuthorized) return { data: { error: 'token_authority_invalid' }, error: null };
    const user = store.scim_users.find(
      (row) => row.tenant_id === args.p_tenant_id && row.id === args.p_user_id,
    );
    if (!user) return { data: { error: 'user_not_found' }, error: null };
    if ((user.version ?? 1) !== args.p_expected_version) {
      return { data: { error: 'version_conflict' }, error: null };
    }
    const org = args.p_organization_id || args.p_tenant_id;
    const revoke = () => {
      let count = 0;
      for (const credential of store.approver_credentials) {
        if (credential.organization_id === org
            && credential.approver_id === user.user_name
            && credential.revoked_at === null) {
          credential.revoked_at = '2026-06-11T00:01:00Z';
          count += 1;
        }
      }
      store.audit_events.push({
        id: newId(),
        event_type: 'scim.approver.deprovisioned',
        target_id: user.user_name,
        after_state: { credentials_revoked: count },
      });
      return count;
    };
    if (args.p_delete) {
      const count = revoke();
      store.scim_users = store.scim_users.filter((row) => row !== user);
      return { data: { status: 'deleted', credentials_revoked: count }, error: null };
    }
    const wasActive = user.active !== false;
    Object.assign(user, args.p_fields, {
      version: (user.version ?? 1) + 1,
      updated_at: '2026-06-11T00:01:00Z',
    });
    const active = user.active !== false;
    const count = wasActive && !active ? revoke() : 0;
    return {
      data: {
        status: 'updated',
        credentials_revoked: count,
        user,
        reactivated: !wasActive && active,
      },
      error: null,
    };
  },
};
vi.mock('@/lib/write-guard', () => ({ getGuardedClient: () => mockClient }));

// Import AFTER mocks are registered.
const { authenticateScim, hashScimToken } = await import('../lib/scim/auth.js');
const { SCIM, SCIM_LIMITS } = await import('../lib/scim/core.js');
const Users = await import('../app/api/scim/v2/Users/route.ts');
const UserById = await import('../app/api/scim/v2/Users/[id]/route.ts');
const Groups = await import('../app/api/scim/v2/Groups/route.ts');
const GroupById = await import('../app/api/scim/v2/Groups/[id]/route.ts');

// A request helper.
function req(method, url, { token, body } = {}) {
  const headers = new Headers();
  if (token) headers.set('authorization', `Bearer ${token}`);
  if (body) headers.set('content-type', 'application/json');
  return new Request(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
}

const TENANT = 'ep_entity_acme';
const ORGANIZATION = '@org:93b24223-2468-4fe3-aa99-c23132566cd6';
const TOKEN = 'ep_scim_testtoken0000000000000000000000000000000000000000000000000000';

beforeEach(() => {
  store.entities = [{ entity_id: TENANT, organization_id: ORGANIZATION, status: 'active' }];
  store.scim_provisioning_tokens = [{ id: 't1', tenant_id: TENANT, organization_id: ORGANIZATION, token_hash: hashScimToken(TOKEN), revoked_at: null }];
  store.scim_users = [];
  store.scim_groups = [];
  store.approver_credentials = [];
  store.audit_events = [];
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
    expect(r.organizationId).toBe(ORGANIZATION);
  });
  it('rejects a token whose live tenant was disabled or rebound to another organization', async () => {
    store.entities[0].organization_id = '@org:attacker';
    const rebound = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: TOKEN }));
    expect(rebound.status).toBe(403);
    store.entities[0].organization_id = ORGANIZATION;
    store.entities[0].status = 'disabled';
    const disabled = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: TOKEN }));
    expect(disabled.status).toBe(403);
  });
  it('does not promote a legacy NULL token organization from its tenant slug', async () => {
    store.entities[0].organization_id = TENANT;
    store.scim_provisioning_tokens[0].organization_id = null;
    const legacy = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: TOKEN }));
    expect(legacy.status).toBe(403);
  });
  it('rejects a legacy self-org token even when the live row still has that shape', async () => {
    store.entities[0].organization_id = TENANT;
    store.scim_provisioning_tokens[0].organization_id = TENANT;
    const squatted = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: TOKEN }));
    expect(squatted.status).toBe(403);
  });
  it('rejects a token whose stored organization differs from its live entity binding', async () => {
    store.scim_provisioning_tokens[0].organization_id = '@org:attacker';
    const mismatched = await authenticateScim(req('GET', 'https://x/api/scim/v2/Users', { token: TOKEN }));
    expect(mismatched.status).toBe(403);
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

describe('SCIM hostile payload rejection', () => {
  const usersBase = 'https://x/api/scim/v2/Users';
  const groupsBase = 'https://x/api/scim/v2/Groups';

  it('returns a SCIM invalidValue error for oversized user input without writing', async () => {
    const res = await Users.POST(req('POST', usersBase, {
      token: TOKEN,
      body: { userName: 'u'.repeat(SCIM_LIMITS.userName + 1) },
    }));
    const error = await res.json();
    expect(res.status).toBe(400);
    expect(error.schemas).toEqual([SCIM.ERROR]);
    expect(error.scimType).toBe('invalidValue');
    expect(store.scim_users).toHaveLength(0);
  });

  it('rejects a deep raw extension with a SCIM error', async () => {
    let extension = 'leaf';
    for (let i = 0; i < SCIM_LIMITS.extensionDepth + 2; i += 1) extension = { next: extension };
    const res = await Users.POST(req('POST', usersBase, {
      token: TOKEN,
      body: { userName: 'deep@example.com', [SCIM.ENTERPRISE_USER]: extension },
    }));
    expect(res.status).toBe(400);
    expect((await res.json()).scimType).toBe('invalidValue');
    expect(store.scim_users).toHaveLength(0);
  });

  it('validates the post-PATCH user and leaves the stored row unchanged on rejection', async () => {
    const created = await (await Users.POST(req('POST', usersBase, {
      token: TOKEN,
      body: { userName: 'stable@example.com' },
    }))).json();
    const res = await UserById.PATCH(req('PATCH', `${usersBase}/${created.id}`, {
      token: TOKEN,
      body: {
        Operations: [{
          op: 'replace',
          path: 'userName',
          value: 'u'.repeat(SCIM_LIMITS.userName + 1),
        }],
      },
    }), { params: Promise.resolve({ id: created.id }) });
    expect(res.status).toBe(400);
    expect((await res.json()).scimType).toBe('invalidValue');
    expect(store.scim_users[0].user_name).toBe('stable@example.com');
  });

  it('returns tooMany for an oversized PATCH operation set', async () => {
    const created = await (await Users.POST(req('POST', usersBase, {
      token: TOKEN,
      body: { userName: 'patch@example.com' },
    }))).json();
    const Operations = Array.from(
      { length: SCIM_LIMITS.patchOperations + 1 },
      () => ({ op: 'replace', path: 'active', value: true }),
    );
    const res = await UserById.PATCH(req('PATCH', `${usersBase}/${created.id}`, {
      token: TOKEN,
      body: { Operations },
    }), { params: Promise.resolve({ id: created.id }) });
    expect(res.status).toBe(400);
    expect((await res.json()).scimType).toBe('tooMany');
  });

  it('rejects malformed and oversized group/member payloads without writing', async () => {
    const malformed = await Groups.POST(req('POST', groupsBase, {
      token: TOKEN,
      body: { displayName: 'Approvers', members: [{ value: { id: 'u1' } }] },
    }));
    expect(malformed.status).toBe(400);
    expect((await malformed.json()).scimType).toBe('invalidValue');

    const oversized = await Groups.POST(req('POST', groupsBase, {
      token: TOKEN,
      body: { displayName: 'g'.repeat(SCIM_LIMITS.displayName + 1), members: [] },
    }));
    expect(oversized.status).toBe(400);
    expect((await oversized.json()).scimType).toBe('invalidValue');
    expect(store.scim_groups).toHaveLength(0);
  });
});

describe('SCIM exact-bearer mutation RPCs', () => {
  it('passes the authenticated token id into user creation and every group mutation', async () => {
    const rpc = vi.spyOn(mockClient, 'rpc');
    const user = await Users.POST(req('POST', 'https://x/api/scim/v2/Users', {
      token: TOKEN,
      body: { userName: 'rpc-bound@example.com', active: true },
    }));
    expect(user.status).toBe(201);
    expect(rpc).toHaveBeenCalledWith('create_scim_user_authorized', expect.objectContaining({
      p_token_id: 't1',
      p_tenant_id: TENANT,
      p_organization_id: ORGANIZATION,
    }));

    const createdResponse = await Groups.POST(req('POST', 'https://x/api/scim/v2/Groups', {
      token: TOKEN,
      body: { displayName: 'Reviewers', members: [] },
    }));
    expect(createdResponse.status).toBe(201);
    const created = await createdResponse.json();
    const params = { params: Promise.resolve({ id: created.id }) };
    const replaced = await GroupById.PUT(req('PUT', `https://x/api/scim/v2/Groups/${created.id}`, {
      token: TOKEN,
      body: { displayName: 'Senior Reviewers', members: [] },
    }), params);
    expect(replaced.status).toBe(200);
    const deleted = await GroupById.DELETE(
      req('DELETE', `https://x/api/scim/v2/Groups/${created.id}`, { token: TOKEN }),
      params,
    );
    expect(deleted.status).toBe(204);
    const groupCalls = rpc.mock.calls.filter(([name]) => name === 'apply_scim_group_authorized');
    expect(groupCalls).toHaveLength(3);
    expect(groupCalls.every(([, args]) => args.p_token_id === 't1')).toBe(true);
    rpc.mockRestore();
  });

  it('returns 401 when the exact bearer loses authority before the RPC commit', async () => {
    const original = mockClient.rpc;
    mockClient.rpc = vi.fn(async (name, args) => {
      if (name === 'create_scim_user_authorized') {
        return { data: { error: 'token_authority_invalid' }, error: null };
      }
      return original.call(mockClient, name, args);
    });
    const response = await Users.POST(req('POST', 'https://x/api/scim/v2/Users', {
      token: TOKEN,
      body: { userName: 'revoked-during-write@example.com' },
    }));
    expect(response.status).toBe(401);
    expect(store.scim_users).toHaveLength(0);
    mockClient.rpc = original;
  });
});

describe('SCIM → approver linkage', () => {
  // The SCIM→approver linkage is opt-in (T3): a compromised SCIM token must not
  // auto-mint approvers. These tests exercise the feature with it explicitly on.
  beforeEach(() => { process.env.EP_SCIM_AUTO_APPROVER = 'true'; });
  afterEach(() => { delete process.env.EP_SCIM_AUTO_APPROVER; });

  const base = 'https://x/api/scim/v2/Users';
  const provision = async (userName) => {
    const res = await Users.POST(req('POST', base, { token: TOKEN, body: { userName, active: true } }));
    return (await res.json()).id;
  };
  const enrollCredential = (userName) => {
    store.approver_credentials.push({
      id: `cred_${userName}`, organization_id: ORGANIZATION, approver_id: userName, credential_id: `cid_${userName}`,
      public_key_spki: 'spki', key_class: 'A', revoked_at: null,
    });
  };

  it('provision records the human as enrollment-eligible', async () => {
    await provision('signer@example.com');
    const ev = store.audit_events.find((e) => e.event_type === 'scim.approver.provisioned');
    expect(ev).toBeTruthy();
    expect(ev.target_id).toBe('signer@example.com');
    expect(ev.after_state.enrollment_eligible).toBe(true);
  });

  it('does NOT grant approver eligibility by default (T3: auto-approver off)', async () => {
    delete process.env.EP_SCIM_AUTO_APPROVER; // simulate the secure default
    await provision('default-off@example.com');
    const ev = store.audit_events.find(
      (e) => e.event_type === 'scim.approver.provisioned' && e.target_id === 'default-off@example.com',
    );
    expect(ev).toBeFalsy();
  });

  it('deprovision (PATCH active=false) revokes the approver credentials in the same write', async () => {
    const id = await provision('leaver@example.com');
    enrollCredential('leaver@example.com');

    await UserById.PATCH(req('PATCH', `${base}/${id}`, {
      token: TOKEN,
      body: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: false }] },
    }), { params: Promise.resolve({ id }) });

    const cred = store.approver_credentials.find((c) => c.approver_id === 'leaver@example.com');
    expect(cred.revoked_at).toBeTruthy();
    const ev = store.audit_events.find((e) => e.event_type === 'scim.approver.deprovisioned');
    expect(ev.after_state.credentials_revoked).toBe(1);
  });

  it('DELETE revokes credentials too (hard offboard)', async () => {
    const id = await provision('gone@example.com');
    enrollCredential('gone@example.com');

    await UserById.DELETE(req('DELETE', `${base}/${id}`, { token: TOKEN }), { params: Promise.resolve({ id }) });

    const cred = store.approver_credentials.find((c) => c.approver_id === 'gone@example.com');
    expect(cred.revoked_at).toBeTruthy();
  });

  it('re-activation makes the human eligible again but never resurrects revoked keys', async () => {
    const id = await provision('rejoiner@example.com');
    enrollCredential('rejoiner@example.com');
    const params = { params: Promise.resolve({ id }) };
    const patch = (value) => UserById.PATCH(req('PATCH', `${base}/${id}`, {
      token: TOKEN, body: { Operations: [{ op: 'replace', path: 'active', value }] },
    }), params);

    await patch(false);
    const revokedAt = store.approver_credentials.find((c) => c.approver_id === 'rejoiner@example.com').revoked_at;
    expect(revokedAt).toBeTruthy();

    await patch(true);
    const cred = store.approver_credentials.find((c) => c.approver_id === 'rejoiner@example.com');
    expect(cred.revoked_at).toBe(revokedAt); // still revoked — re-enroll required
    const eligible = store.audit_events.filter((e) => e.event_type === 'scim.approver.provisioned');
    expect(eligible.length).toBeGreaterThanOrEqual(2); // initial + re-activation
  });

  it('deprovision with no enrolled credentials still audits (0 revoked)', async () => {
    const id = await provision('never-enrolled@example.com');
    await UserById.PATCH(req('PATCH', `${base}/${id}`, {
      token: TOKEN, body: { Operations: [{ op: 'replace', path: 'active', value: false }] },
    }), { params: Promise.resolve({ id }) });
    const ev = store.audit_events.find((e) => e.event_type === 'scim.approver.deprovisioned');
    expect(ev.after_state.credentials_revoked).toBe(0);
  });

  it('deprovision revokes only credentials scoped to the SCIM tenant', async () => {
    const id = await provision('shared@example.com');
    enrollCredential('shared@example.com');
    store.approver_credentials.push({
      id: 'cred_other_tenant',
      organization_id: 'ep_entity_other',
      approver_id: 'shared@example.com',
      credential_id: 'cid_other_tenant',
      public_key_spki: 'spki',
      key_class: 'A',
      revoked_at: null,
    });

    await UserById.PATCH(req('PATCH', `${base}/${id}`, {
      token: TOKEN,
      body: { Operations: [{ op: 'replace', path: 'active', value: false }] },
    }), { params: Promise.resolve({ id }) });

    expect(store.approver_credentials.find((c) => c.id === 'cred_shared@example.com').revoked_at).toBeTruthy();
    expect(store.approver_credentials.find((c) => c.id === 'cred_other_tenant').revoked_at).toBeNull();
  });
});
