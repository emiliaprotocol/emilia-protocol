// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import {
  authenticateGuardRequest,
  isCloudGuardPrincipal,
} from '../lib/guard-auth.js';

function request(token) {
  return new Request('https://example.test/api/v1/trust-receipts', {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

describe('Guard authentication bridge', () => {
  it('preserves the standard EP entity authentication path', async () => {
    const protocol = vi.fn(async () => ({ entity: { entity_id: 'ep:entity:1' } }));
    const cloud = vi.fn();

    const auth = await authenticateGuardRequest(request('ep_live_abc'), {
      authenticateProtocol: protocol,
      authenticateCloud: cloud,
    });

    expect(auth.entity.entity_id).toBe('ep:entity:1');
    expect(protocol).toHaveBeenCalledOnce();
    expect(cloud).not.toHaveBeenCalled();
    expect(isCloudGuardPrincipal(auth)).toBe(false);
  });

  it.each([['admin'], ['policy_rollout'], ['approval_request']])(
    'projects a %s tenant key into an org-bound, attributable principal',
    async (permission) => {
    const protocol = vi.fn();
    const auth = await authenticateGuardRequest(request('ept_live_abc'), {
      authenticateProtocol: protocol,
      authenticateCloud: async () => ({
        tenantId: '33333333-3333-4333-8333-333333333333',
        environment: 'production',
        permissions: [permission],
        keyId: 'key-abc123',
      }),
    });

    expect(protocol).not.toHaveBeenCalled();
    expect(auth).toMatchObject({
      entity: {
        entity_id: 'ep:cloud-key:key-abc123',
        organization_id: '33333333-3333-4333-8333-333333333333',
      },
      auth_strength: 'service_account',
      permissions: [permission],
      guard_cloud: {
        key_id: 'key-abc123',
        environment: 'production',
      },
    });
    expect(isCloudGuardPrincipal(auth)).toBe(true);
    },
  );

  it('fails a tenant key closed when authentication or a Guard capability is absent', async () => {
    const failed = await authenticateGuardRequest(request('ept_live_bad'), {
      authenticateCloud: async () => null,
    });
    expect(failed).toMatchObject({ status: 401, code: 'cloud_auth_failed' });

    const unprivileged = await authenticateGuardRequest(request('ept_live_read'), {
      authenticateCloud: async () => ({
        tenantId: 'tenant-1',
        environment: 'staging',
        permissions: ['read'],
        keyId: 'key-read',
      }),
    });
    expect(unprivileged).toMatchObject({
      status: 403,
      code: 'cloud_guard_permission_required',
    });
  });
});
