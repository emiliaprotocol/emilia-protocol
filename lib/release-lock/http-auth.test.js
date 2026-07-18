// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { hasPermission } from '../procedural-justice.js';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  resolveAuthorizedOrg: vi.fn(),
}));

vi.mock('../supabase.js', () => ({
  authenticateRequest: (...args) => mocks.authenticateRequest(...args),
  authEntityId: (auth) => auth?.entity?.entity_id || '',
}));

vi.mock('../tenant-binding.js', () => ({
  resolveAuthorizedOrg: (...args) => mocks.resolveAuthorizedOrg(...args),
}));

const { authenticateReleaseLockOrg } = await import('./http.js');

const REQUEST = new Request('https://www.emiliaprotocol.ai/api/v1/release-locks', {
  headers: { authorization: 'Bearer ep_live_test' },
});

beforeEach(() => {
  mocks.authenticateRequest.mockReset();
  mocks.resolveAuthorizedOrg.mockReset().mockImplementation(
    (auth, bodyOrganizationId) => ({
      organizationId: bodyOrganizationId || auth?.entity?.organization_id,
    }),
  );
});

describe('Release Lock organization authorization', () => {
  it('types authentication failures without leaking or inventing authority', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      error: 'API key refused',
      status: 418,
      code: 'credential_refused',
    });
    await expect(authenticateReleaseLockOrg(
      REQUEST,
      'org_builder',
    )).rejects.toMatchObject({
      status: 418,
      code: 'credential_refused',
      detail: 'API key refused',
    });

    mocks.authenticateRequest.mockResolvedValueOnce({ error: 'API key refused' });
    await expect(authenticateReleaseLockOrg(
      REQUEST,
      'org_builder',
    )).rejects.toMatchObject({
      status: 401,
      code: 'unauthorized',
    });
  });

  it('refuses a read-only API key at a mutation boundary', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      entity: {
        entity_id: 'entity_contractor',
        organization_id: 'org_builder',
      },
      permissions: ['read'],
    });

    await expect(authenticateReleaseLockOrg(
      REQUEST,
      'org_builder',
      { requiredPermission: 'write' },
    )).rejects.toMatchObject({
      status: 403,
      code: 'insufficient_permissions',
    });
  });

  it('permits a read-only key only at the evidence read boundary', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      entity: {
        entity_id: 'entity_auditor',
        organization_id: 'org_builder',
      },
      permissions: ['read'],
    });

    await expect(authenticateReleaseLockOrg(
      REQUEST,
      undefined,
      { requiredPermission: 'read' },
    )).resolves.toMatchObject({
      organizationId: 'org_builder',
      entityId: 'entity_auditor',
    });
  });

  it('fails closed on tenant-resolution refusal or a missing authenticated entity', async () => {
    mocks.authenticateRequest.mockResolvedValueOnce({
      entity: { entity_id: 'entity_auditor', organization_id: 'org_builder' },
      permissions: ['read'],
    });
    mocks.resolveAuthorizedOrg.mockReturnValueOnce({
      error: {
        status: 403,
        code: 'tenant_scope_mismatch',
        detail: 'Tenant mismatch.',
      },
    });
    await expect(authenticateReleaseLockOrg(
      REQUEST,
      'org_other',
    )).rejects.toMatchObject({
      status: 403,
      code: 'tenant_scope_mismatch',
    });

    mocks.authenticateRequest.mockResolvedValueOnce({
      entity: { organization_id: 'org_builder' },
      permissions: ['read'],
    });
    await expect(authenticateReleaseLockOrg(
      REQUEST,
      'org_builder',
    )).rejects.toMatchObject({
      status: 403,
      code: 'authenticated_entity_invalid',
    });
  });


  it('pins route permission classes and keeps reconciliation operator-only', () => {
    const root = new URL('../../', import.meta.url);
    const mutationFiles = [
      'app/api/v1/release-locks/route.js',
      'app/api/v1/release-locks/[lockId]/draw-release/route.js',
      'app/api/v1/release-locks/[lockId]/amendments/route.js',
    ];
    for (const file of mutationFiles) {
      expect(readFileSync(new URL(file, root), 'utf8'))
        .toContain("requiredPermission: 'write'");
    }
    expect(readFileSync(
      new URL('app/api/v1/release-locks/[lockId]/evidence/route.js', root),
      'utf8',
    )).toContain("requiredPermission: 'read'");
    const reconcile = readFileSync(
      new URL('app/api/internal/release-lock/reconcile/route.js', root),
      'utf8',
    );
    expect(reconcile).toContain('authenticateOperator');
    expect(reconcile).toContain("hasPermission(operator.role, 'release_lock.reconcile')");
    expect(reconcile).not.toContain('authenticateReleaseLockOrg');
    expect(hasPermission('operator', 'release_lock.reconcile')).toBe(true);
    for (const role of ['host_verifier', 'reviewer', 'appeal_reviewer']) {
      expect(hasPermission(role, 'release_lock.reconcile')).toBe(false);
    }
  });
});
