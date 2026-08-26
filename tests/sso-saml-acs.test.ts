// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';

const mocks = vi.hoisted(() => ({
  loadConnection: vi.fn(),
  buildSamlSp: vi.fn(() => ({ kind: 'saml-sp' })),
  validateSamlResponse: vi.fn(),
}));

vi.mock('@/lib/write-guard', () => ({ getGuardedClient: vi.fn() }));
vi.mock('@/lib/sso/config', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/sso/config.js')>()),
  loadConnection: mocks.loadConnection,
}));
vi.mock('@/lib/sso/saml', () => ({
  buildSamlSp: mocks.buildSamlSp,
  validateSamlResponse: mocks.validateSamlResponse,
}));
vi.mock('@/lib/sso/session', () => ({
  mintSession: vi.fn(),
  SESSION_COOKIE: 'ep_session',
  SESSION_COOKIE_OPTIONS: {},
}));
vi.mock('@/lib/scim/core', () => ({ normalizeUserName: (value: string) => value }));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('@/lib/http/body-limit', () => ({
  readLimitedText: vi.fn(async () => ({
    ok: true,
    text: 'SAMLResponse=c2lnbmVkLXJlc3BvbnNl&RelayState=state-token',
  })),
}));
vi.mock('@/lib/sso/state', () => ({
  verifyState: vi.fn(() => ({ tenant: 'tenant_1' })),
  SAML_STATE_COOKIE: 'ep_saml_state',
}));

import { POST } from '../app/api/sso/saml/acs/route.js';

beforeEach(() => {
  vi.stubEnv('EP_PUBLIC_BASE_URL', '');
  vi.stubEnv('NEXT_PUBLIC_SITE_URL', '');
  vi.stubEnv('NEXT_PUBLIC_APP_URL', 'https://login.emiliaprotocol.ai');
  mocks.loadConnection.mockResolvedValue({
    connection: {
      saml_idp_entry_point: 'https://idp.example/sso',
      saml_idp_cert: 'fixture-cert',
      saml_want_response_signed: false,
    },
  });
  mocks.validateSamlResponse.mockResolvedValue({
    valid: false,
    error: 'fixture stops after validation contract',
  });
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe('SAML ACS endpoint binding', () => {
  it('uses the configured ACS URL, requires a signed Response, and passes the same target to validation', async () => {
    const request = new NextRequest('https://request-host.example/api/sso/saml/acs', {
      method: 'POST',
      headers: { cookie: 'ep_saml_state=state-token' },
    });

    const response = await POST(request);

    expect(response.status).toBe(401);
    expect(mocks.buildSamlSp).toHaveBeenCalledWith(expect.objectContaining({
      spEntityId: 'https://login.emiliaprotocol.ai/api/sso/saml/metadata',
      acsUrl: 'https://login.emiliaprotocol.ai/api/sso/saml/acs',
      wantAuthnResponseSigned: true,
    }));
    expect(mocks.validateSamlResponse).toHaveBeenCalledWith(
      { kind: 'saml-sp' },
      'c2lnbmVkLXJlc3BvbnNl',
      { expectedAcsUrl: 'https://login.emiliaprotocol.ai/api/sso/saml/acs' },
    );
  });
});
