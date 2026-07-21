// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticate = vi.fn();
const mockGetGuardedClient = vi.fn();
const mockLoadPolicyById = vi.fn();
const mockReadEpJson = vi.fn();
const mockVerifyAuthorization = vi.fn();

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: (...args) => mockAuthenticate(...args),
}));
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));
vi.mock('@/lib/handshake/policy', () => ({
  loadPolicyById: (...args) => mockLoadPolicyById(...args),
}));
vi.mock('@/lib/http/route-body', () => ({
  readEpJson: (...args) => mockReadEpJson(...args),
}));
vi.mock('@/lib/cloud/policy-rollout-authorization.js', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    verifyPolicyRolloutAuthorization: (...args) => mockVerifyAuthorization(...args),
  };
});

const { POST } = await import('../app/api/cloud/policies/[policyId]/rollout/route.js');

const RECEIPT_ID = `tr_${'a'.repeat(32)}`;
const ACTION_HASH = 'b'.repeat(64);
const POLICY_ID = '11111111-1111-4111-8111-111111111111';
const RULES = { threshold: 0.9, deny: ['compromised'] };

function requestBody(overrides = {}) {
  return {
    version: 2,
    environment: 'staging',
    strategy: 'immediate',
    metadata: { ticket: 'CAB-42' },
    ...overrides,
  };
}

function authorizedBody(overrides = {}) {
  return {
    ...requestBody(overrides),
    authorization: { receipt_id: RECEIPT_ID },
  };
}

function request(body) {
  return {
    headers: { get: () => 'Bearer ept_test' },
    json: () => Promise.resolve(body),
  };
}

function makeClient({
  activeRollouts = [],
  events = [],
  rpcError = null,
  policyStatus = 'active',
  quorumTemplate = null,
} = {}) {
  const calls = { rpcs: [], selects: [] };
  return {
    calls,
    from(table) {
      calls.selects.push(table);
      if (table === 'handshake_policies') {
        const builder = {
          select: () => builder,
          eq: () => builder,
          maybeSingle: () => Promise.resolve({
            data: {
              policy_id: POLICY_ID,
              policy_key: 'strict',
              version: 2,
              mode: 'mutual',
              status: policyStatus,
              rules: RULES,
            },
            error: null,
          }),
          then(resolve) {
            return Promise.resolve({
              data: [{ policy_id: POLICY_ID }],
              error: null,
            }).then(resolve);
          },
        };
        return builder;
      }
      if (table === 'policy_rollouts') {
        const builder = {
          select: () => builder,
          eq: () => builder,
          in: () => builder,
          then(resolve) {
            return Promise.resolve({ data: activeRollouts, error: null }).then(resolve);
          },
        };
        return builder;
      }
      if (table === 'audit_events') {
        const builder = {
          select: () => builder,
          eq: () => builder,
          order: () => Promise.resolve({ data: events, error: null }),
        };
        return builder;
      }
      if (table === 'org_quorum_policies') {
        const builder = {
          select: () => builder,
          eq: () => builder,
          limit: () => Promise.resolve({
            data: quorumTemplate ? [quorumTemplate] : [],
            error: null,
          }),
        };
        return builder;
      }
      throw new Error(`unexpected table ${table}`);
    },
    rpc(name, payload) {
      calls.rpcs.push({ name, payload });
      return {
        single: () => Promise.resolve({
          data: rpcError ? null : {
            rollout_id: '22222222-2222-4222-8222-222222222222',
            canary_pct: payload.p_canary_pct,
            initiated_at: '2026-07-19T20:00:00.000Z',
            authorization_execution_reference_id:
              'policy-rollout:22222222-2222-4222-8222-222222222222',
          },
          error: rpcError,
        }),
      };
    },
  };
}

const params = Promise.resolve({ policyId: POLICY_ID });

beforeEach(() => {
  vi.clearAllMocks();
  mockAuthenticate.mockResolvedValue({
    tenantId: '33333333-3333-4333-8333-333333333333',
    environment: 'staging',
    permissions: ['admin'],
    keyId: 'key-abc123',
  });
  mockLoadPolicyById.mockResolvedValue({
    policy_id: POLICY_ID,
    policy_key: 'strict',
    version: 2,
  });
  mockReadEpJson.mockImplementation(async (req) => ({ ok: true, value: await req.json() }));
  mockVerifyAuthorization.mockResolvedValue({
    ok: true,
    actionHash: ACTION_HASH,
    authorityIds: ['55555555-5555-4555-8555-555555555555'],
    authority: {
      authority_id: '55555555-5555-4555-8555-555555555555',
      assurance_class: 'A',
      authority_check: 'ok',
      action_scope: 'policy_rollout',
      role: 'policy_admin',
      user_verification: 'verified',
    },
  });
});

describe('cloud policy rollout authorization boundary', () => {
  it('refuses a staging-scoped key targeting production before any write', async () => {
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(authorizedBody({ environment: 'production' })), { params });

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('environment_scope_mismatch');
    expect(client.calls.rpcs).toHaveLength(0);
  });

  it('returns the exact short-lived receipt request when signoff is absent', async () => {
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(requestBody()), { params });
    const json = await res.json();

    expect(res.status).toBe(428);
    expect(json.type).toContain('accountable_signoff_required');
    expect(json.authorization_request).toMatchObject({
      organization_id: '33333333-3333-4333-8333-333333333333',
      action_type: 'policy_rollout',
      target_resource_id: 'policy:strict',
      executing_key_id: 'key-abc123',
      rollout_policy_id: POLICY_ID,
      rollout_policy_key: 'strict',
      rollout_policy_version: 2,
      rollout_policy_rules: RULES,
      rollout_policy_mode: 'mutual',
      rollout_policy_status: 'active',
      rollout_environment: 'staging',
      rollout_strategy: 'immediate',
      rollout_canary_pct: null,
      expires_in_sec: 900,
      enforcement_mode: 'enforce',
      before_state: { active_rollouts: [] },
    });
    expect(json.authorization_request.after_state).toMatchObject({
      policy_id: POLICY_ID,
      policy_key: 'strict',
      policy_version: 2,
      policy_rules: RULES,
      policy_mode: 'mutual',
      policy_status: 'active',
      environment: 'staging',
      strategy: 'immediate',
      canary_pct: null,
      metadata: { ticket: 'CAB-42' },
    });
    expect(client.calls.rpcs).toHaveLength(0);
  });

  it('re-verifies an unconsumed receipt and atomically activates through the RPC', async () => {
    const active = [{
      rollout_id: '44444444-4444-4444-8444-444444444444',
      policy_id: POLICY_ID,
      version: 1,
      environment: 'staging',
      strategy: 'immediate',
      canary_pct: null,
      metadata: {},
      authorization_receipt_id: null,
    }];
    const client = makeClient({ activeRollouts: active, events: [{ event_type: 'created' }] });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(authorizedBody()), { params });
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(mockVerifyAuthorization).toHaveBeenCalledOnce();
    const expected = mockVerifyAuthorization.mock.calls[0][0].expected;
    expect(expected.executingKeyId).toBe('key-abc123');
    expect(expected.policyRules).toEqual(RULES);
    expect(expected.beforeState.active_rollouts[0].rollout_id)
      .toBe('44444444-4444-4444-8444-444444444444');
    expect(client.calls.rpcs).toHaveLength(1);
    expect(client.calls.rpcs[0]).toMatchObject({
      name: 'activate_policy_rollout_authorized',
      payload: {
        p_tenant_id: '33333333-3333-4333-8333-333333333333',
        p_policy_id: POLICY_ID,
        p_initiated_by: 'key:key-abc123',
        p_receipt_id: RECEIPT_ID,
        p_action_hash: ACTION_HASH,
        p_authority_ids: ['55555555-5555-4555-8555-555555555555'],
        p_quorum_policy: null,
      },
    });
    expect(json.authorization_execution_reference_id)
      .toBe('policy-rollout:22222222-2222-4222-8222-222222222222');
  });

  it('materializes a mandatory org-pinned quorum in the 428 request', async () => {
    const quorumTemplate = {
      organization_id: '33333333-3333-4333-8333-333333333333',
      action_type: 'policy_rollout',
      min_required: 2,
      max_window_sec: 600,
      require_distinct_humans: true,
      quorum_required: true,
      allowed_approvers: [
        { role: 'change_control', approver: 'approver-1' },
        { role: 'security', approver: 'approver-2' },
      ],
      allowed_modes: ['threshold'],
    };
    const client = makeClient({ quorumTemplate });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(requestBody()), { params });
    expect(res.status).toBe(428);
    expect((await res.json()).authorization_request.quorum_policy).toEqual({
      mode: 'threshold',
      required: 2,
      approvers: quorumTemplate.allowed_approvers,
      distinct_humans: true,
      window_sec: 600,
    });
  });

  it('fails closed before 428 when a mandatory quorum has no concrete roster', async () => {
    const client = makeClient({
      quorumTemplate: {
        organization_id: '33333333-3333-4333-8333-333333333333',
        action_type: 'policy_rollout',
        min_required: 2,
        max_window_sec: 600,
        require_distinct_humans: true,
        quorum_required: true,
        allowed_approvers: null,
        allowed_modes: ['threshold'],
      },
    });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(requestBody()), { params });
    expect(res.status).toBe(409);
    expect((await res.json()).type).toContain('policy_rollout_quorum_roster_required');
  });

  it('fails closed when consume-time WebAuthn or authority verification fails', async () => {
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyAuthorization.mockResolvedValue({
      ok: false,
      status: 403,
      code: 'authority_invalid',
      detail: 'Policy rollout approver authority failed: wrong_scope',
    });

    const res = await POST(request(authorizedBody()), { params });

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('authority_invalid');
    expect(client.calls.rpcs).toHaveLength(0);
  });

  it('refuses to issue authorization for an inactive policy version', async () => {
    const client = makeClient({ policyStatus: 'deprecated' });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(requestBody()), { params });

    expect(res.status).toBe(409);
    expect((await res.json()).type).toContain('policy_version_inactive');
    expect(client.calls.rpcs).toHaveLength(0);
  });

  it.each([
    ['policy_rollout_receipt_unavailable', 409, 'rollout_authorization_replayed'],
    ['policy_rollout_signed_state_stale', 409, 'rollout_authorization_stale'],
    ['policy_rollout_authorization_expired', 410, 'rollout_authorization_expired'],
    ['policy_rollout_version_mismatch', 409, 'rollout_version_changed'],
    ['policy_rollout_authority_invalid', 403, 'rollout_authorization_invalid'],
    ['invalid_policy_rollout_activation', 400, 'invalid_rollout_activation'],
  ])('maps atomic RPC refusal %s without turning it into a 500', async (message, status, code) => {
    const client = makeClient({ rpcError: { code: 'P0001', message } });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(authorizedBody()), { params });

    expect(res.status).toBe(status);
    expect((await res.json()).type).toContain(code);
  });

  it('allows an unscoped cloud key to target production but still requires signoff', async () => {
    mockAuthenticate.mockResolvedValue({
      tenantId: '33333333-3333-4333-8333-333333333333',
      environment: null,
      permissions: ['admin'],
      keyId: 'key-abc123',
    });
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(requestBody({ environment: 'production' })), { params });

    expect(res.status).toBe(428);
    expect(client.calls.rpcs).toHaveLength(0);
  });

  it('refuses a cloud auth context that cannot name its executing key', async () => {
    mockAuthenticate.mockResolvedValue({
      tenantId: '33333333-3333-4333-8333-333333333333',
      environment: 'staging',
      permissions: ['admin'],
    });
    const client = makeClient();
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(request(requestBody()), { params });

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('cloud_key_identity_required');
    expect(client.calls.rpcs).toHaveLength(0);
  });
});
