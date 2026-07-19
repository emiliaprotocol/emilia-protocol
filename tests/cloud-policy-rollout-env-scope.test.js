// SPDX-License-Identifier: Apache-2.0
//
// Regression test for Sentrix HIGH finding on
//   app/api/cloud/policies/[policyId]/rollout/route.js
//
// Vuln (a): a tenant_api_key scoped to environment X could POST
// {environment:'production'} and flip a production rollout active, because the
// route never compared auth.environment (the key's scope) to body.environment.
//
// These tests prove:
//   1. ATTACK REFUSED  — a staging-scoped key rolling out to 'production' gets a
//      403 environment_scope_mismatch and NO rollout row is written.
//   2. LEGIT PATH WORKS — a staging-scoped key rolling out to 'staging' succeeds
//      and writes the active rollout row.
//   3. UNSCOPED KEY     — a key with no environment scope may roll out anywhere.

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── mocks ────────────────────────────────────────────────────────────────────

const mockAuthenticate = vi.fn();
const mockGetGuardedClient = vi.fn();
const mockLoadPolicyById = vi.fn();
const mockReadEpJson = vi.fn();

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: (...a) => mockAuthenticate(...a),
}));

// Use the REAL authorize layer (requirePermission) so the permission model under
// test is genuine; the mocked auth context carries permissions:['admin'].
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...a) => mockGetGuardedClient(...a),
}));

vi.mock('@/lib/handshake/policy', () => ({
  loadPolicyById: (...a) => mockLoadPolicyById(...a),
}));

vi.mock('@/lib/http/route-body', () => ({
  readEpJson: (...a) => mockReadEpJson(...a),
}));

const { POST } = await import(
  '../app/api/cloud/policies/[policyId]/rollout/route.js'
);

// ── test doubles ───────────────────────────────────────────────────────────

// Minimal chainable supabase double. Records every insert/update so the test can
// assert whether a rollout was actually written. Terminal calls (.maybeSingle /
// .single) resolve; the immediate-supersede UPDATE chain is thenable/awaitable.
function makeClient() {
  const calls = { inserts: [], updates: [] };

  function versionBuilder() {
    const b = {
      select: () => b,
      eq: () => b,
      maybeSingle: () =>
        Promise.resolve({
          data: { policy_id: 'pol-v2', policy_key: 'strict', version: 2 },
          error: null,
        }),
    };
    return b;
  }

  function rolloutBuilder() {
    const state = {};
    const b = {
      select: () => b,
      eq: () => b,
      in: () => b,
      update(patch) {
        state.op = 'update';
        calls.updates.push({ patch });
        return b; // update()...eq()...eq() is awaited directly
      },
      insert(payload) {
        calls.inserts.push({ payload });
        return {
          select: () => ({
            single: () =>
              Promise.resolve({
                data: { rollout_id: 'roll-1', canary_pct: null, ...payload },
                error: null,
              }),
          }),
        };
      },
      // makes the superseding update chain awaitable
      then(resolve) {
        return Promise.resolve({ data: null, error: null }).then(resolve);
      },
    };
    return b;
  }

  function keyVersionsBuilder() {
    const b = {
      select: () => b,
      eq: () => b,
      then(resolve) {
        return Promise.resolve({
          data: [{ policy_id: 'pol-v2' }],
          error: null,
        }).then(resolve);
      },
    };
    return b;
  }

  return {
    calls,
    from(table) {
      if (table === 'handshake_policies') {
        // The route queries handshake_policies twice: once for the target version
        // (.maybeSingle) and once for the key's version set (immediate supersede).
        // Return a builder that satisfies both shapes.
        const b = {
          select: () => b,
          eq: () => b,
          maybeSingle: () =>
            Promise.resolve({
              data: { policy_id: 'pol-v2', policy_key: 'strict', version: 2 },
              error: null,
            }),
          then(resolve) {
            return Promise.resolve({
              data: [{ policy_id: 'pol-v2' }],
              error: null,
            }).then(resolve);
          },
        };
        return b;
      }
      if (table === 'policy_rollouts') return rolloutBuilder();
      throw new Error(`unexpected table ${table}`);
    },
  };
}

function req(body) {
  return {
    headers: { get: () => 'Bearer ept_test' },
    json: () => Promise.resolve(body ?? {}),
  };
}

const params = Promise.resolve({ policyId: 'pol-v2' });

beforeEach(() => {
  vi.clearAllMocks();
  mockLoadPolicyById.mockResolvedValue({
    policy_id: 'pol-v2',
    policy_key: 'strict',
    version: 2,
  });
  mockReadEpJson.mockImplementation(async (request) => ({
    ok: true,
    value: await request.json(),
  }));
});

describe('cloud policy rollout — environment-scope enforcement (Sentrix HIGH a)', () => {
  it('REFUSES a staging-scoped key rolling out to production (403, no write)', async () => {
    mockAuthenticate.mockResolvedValue({
      tenantId: 'tenant-1',
      environment: 'staging',
      permissions: ['admin'],
      operatorId: 'op-1',
    });
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(
      req({ version: 2, environment: 'production', strategy: 'immediate' }),
      { params },
    );

    expect(res.status).toBe(403);
    const bodyJson = await res.json();
    expect(bodyJson.type).toContain('environment_scope_mismatch');
    // The attack must not have activated ANY rollout.
    expect(client.calls.inserts).toHaveLength(0);
    expect(client.calls.updates).toHaveLength(0);
  });

  it('ALLOWS a staging-scoped key rolling out to staging (legit path still works)', async () => {
    mockAuthenticate.mockResolvedValue({
      tenantId: 'tenant-1',
      environment: 'staging',
      permissions: ['admin'],
      operatorId: 'op-1',
    });
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(
      req({ version: 2, environment: 'staging', strategy: 'immediate' }),
      { params },
    );

    expect(res.status).toBe(200);
    const bodyJson = await res.json();
    expect(bodyJson.status).toBe('active');
    expect(bodyJson.environment).toBe('staging');
    // The legit rollout was actually written.
    expect(client.calls.inserts).toHaveLength(1);
    expect(client.calls.inserts[0].payload.environment).toBe('staging');
  });

  it('ALLOWS an unscoped key (no environment) to roll out to any environment', async () => {
    mockAuthenticate.mockResolvedValue({
      tenantId: 'tenant-1',
      environment: null, // key not scoped to a single environment
      permissions: ['admin'],
      operatorId: 'op-1',
    });
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(
      req({ version: 2, environment: 'production', strategy: 'immediate' }),
      { params },
    );

    expect(res.status).toBe(200);
    const bodyJson = await res.json();
    expect(bodyJson.environment).toBe('production');
    expect(client.calls.inserts).toHaveLength(1);
  });
});

// ── operator attribution in the rollout audit trail ─────────────────────────
//
// The route recorded `initiated_by: auth.operatorId || auth.principalId ||
// 'unknown'`, but authenticateCloudRequest() returns only {tenantId,
// environment, permissions, keyId} — it has never returned operatorId or
// principalId. So every rollout ever initiated was attributed to 'unknown',
// and a policy rollout is exactly the action whose audit trail has to name who
// initiated it.
//
// The bug survived because the doubles ABOVE mock auth with `operatorId:'op-1'`,
// a field the real function never produces — a test double more generous than
// reality. These cases deliberately mock the REAL auth shape.

describe('cloud policy rollout — operator attribution', () => {
  /** The exact object authenticateCloudRequest returns (lib/cloud/auth.js). */
  function realAuthShape(overrides = {}) {
    return {
      tenantId: 'tenant-1',
      environment: null,
      permissions: ['admin'],
      keyId: 'key-abc123',
      ...overrides,
    };
  }

  it('attributes the rollout to the authenticated API key, not "unknown"', async () => {
    mockAuthenticate.mockResolvedValue(realAuthShape());
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(
      req({ version: 2, environment: 'production', strategy: 'immediate' }),
      { params },
    );

    expect(res.status).toBe(200);
    expect(client.calls.inserts).toHaveLength(1);
    const { initiated_by: initiatedBy } = client.calls.inserts[0].payload;
    expect(initiatedBy).toBe('key:key-abc123');
    expect(initiatedBy).not.toBe('unknown');
  });

  it('does not depend on operatorId/principalId, which auth never returns', async () => {
    // Guards against a future refactor reintroducing the phantom fields: even
    // when they are explicitly absent, attribution must still resolve.
    const auth = realAuthShape();
    expect(auth.operatorId).toBeUndefined();
    expect(auth.principalId).toBeUndefined();

    mockAuthenticate.mockResolvedValue(auth);
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    await POST(
      req({ version: 2, environment: 'staging', strategy: 'immediate' }),
      { params },
    );

    expect(client.calls.inserts[0].payload.initiated_by).toBe('key:key-abc123');
  });

  it('falls back to "unknown" only when no key identity exists (column is NOT NULL)', async () => {
    mockAuthenticate.mockResolvedValue(realAuthShape({ keyId: undefined }));
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    await POST(
      req({ version: 2, environment: 'staging', strategy: 'immediate' }),
      { params },
    );

    // policy_rollouts.initiated_by is TEXT NOT NULL (migration 068), so the
    // fallback must be a string rather than null/undefined.
    expect(client.calls.inserts[0].payload.initiated_by).toBe('unknown');
  });
});
