// SPDX-License-Identifier: Apache-2.0
//
// GET /api/sso/oidc/login must not be a tenant-existence oracle.
//
// The route is unauthenticated. If "unknown tenant", "tenant with no OIDC
// connection" and "config store unavailable" produce distinguishable responses,
// anyone can walk the tenant namespace from the outside. The SAML ACS route
// already unifies these (app/api/sso/saml/acs/route.ts) with one status and one
// generic body; this proves the OIDC login route matches it.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';

const mocks = vi.hoisted(() => ({ loadConnection: vi.fn() }));

vi.mock('@/lib/write-guard', () => ({ getGuardedClient: vi.fn() }));
vi.mock('@/lib/sso/config', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/sso/config.js')>()),
  loadConnection: mocks.loadConnection,
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { GET } from '../app/api/sso/oidc/login/route.js';

function login(tenant: string) {
  return GET(new NextRequest(
    `https://login.emiliaprotocol.ai/api/sso/oidc/login?tenant=${encodeURIComponent(tenant)}`,
  ));
}

beforeEach(() => {
  vi.stubEnv('EP_PUBLIC_BASE_URL', '');
  vi.stubEnv('NEXT_PUBLIC_SITE_URL', '');
  vi.stubEnv('NEXT_PUBLIC_APP_URL', 'https://login.emiliaprotocol.ai');
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe('OIDC login tenant enumeration', () => {
  it('answers identically for an unknown tenant, an unconfigured tenant, and a store failure', async () => {
    // Unknown tenant: loadConnection resolves with no row.
    mocks.loadConnection.mockResolvedValueOnce({ connection: null });
    const unknown = await login('tenant_does_not_exist');
    const unknownBody = await unknown.json();

    // Known tenant, no OIDC connection configured.
    mocks.loadConnection.mockResolvedValueOnce({ connection: { tenant_id: 'tenant_1' } });
    const unconfigured = await login('tenant_1');
    const unconfiguredBody = await unconfigured.json();

    // Config store failure.
    mocks.loadConnection.mockResolvedValueOnce({ error: { message: 'boom' } });
    const unavailable = await login('tenant_1');
    const unavailableBody = await unavailable.json();

    expect(unknown.status).toBe(404);
    expect(unconfigured.status).toBe(unknown.status);
    expect(unavailable.status).toBe(unknown.status);
    expect(unconfiguredBody).toEqual(unknownBody);
    expect(unavailableBody).toEqual(unknownBody);
  });

  it('never echoes the requested tenant back to an unauthenticated caller', async () => {
    mocks.loadConnection.mockResolvedValue({ connection: null });
    const res = await login('acme-holdings');
    expect(JSON.stringify(await res.json())).not.toContain('acme-holdings');
  });
});
