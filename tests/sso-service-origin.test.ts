// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/write-guard', () => ({ getGuardedClient: vi.fn() }));
vi.mock('@/lib/crypto/secret-box', () => ({ open: vi.fn((value) => value) }));

import { spOrigin } from '../lib/sso/config.js';

function clearConfiguredOrigins() {
  vi.stubEnv('EP_PUBLIC_BASE_URL', '');
  vi.stubEnv('NEXT_PUBLIC_APP_URL', '');
  vi.stubEnv('NEXT_PUBLIC_SITE_URL', '');
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('SSO canonical service origin', () => {
  it('uses validated deployment configuration and ignores the request origin', () => {
    clearConfiguredOrigins();
    vi.stubEnv('NEXT_PUBLIC_APP_URL', 'https://login.emiliaprotocol.ai/');

    expect(spOrigin(new Request('https://attacker.example/api/sso/saml/login')))
      .toBe('https://login.emiliaprotocol.ai');
  });

  it('has one deterministic loopback origin in development and tests', () => {
    clearConfiguredOrigins();
    vi.stubEnv('NODE_ENV', 'test');

    expect(spOrigin(new Request('https://one.example/sso'))).toBe('http://localhost:3000');
    expect(spOrigin(new Request('https://two.example/sso'))).toBe('http://localhost:3000');
  });

  it('fails closed when production has no configured origin', () => {
    clearConfiguredOrigins();
    vi.stubEnv('NODE_ENV', 'production');

    expect(() => spOrigin(new Request('https://request-host.example/sso')))
      .toThrow(/not configured/);
  });

  it.each([
    'http://public.example',
    'https://user:password@public.example',
    'https://public.example/sso',
    'https://public.example/?tenant=other',
    'not a URL',
  ])('rejects an unsafe configured service origin: %s', (configured) => {
    clearConfiguredOrigins();
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('NEXT_PUBLIC_APP_URL', configured);

    expect(() => spOrigin()).toThrow(/SSO service origin/);
  });

  it('allows HTTP only for an explicit loopback origin outside production', () => {
    clearConfiguredOrigins();
    vi.stubEnv('NODE_ENV', 'development');
    vi.stubEnv('NEXT_PUBLIC_APP_URL', 'http://127.0.0.1:4100/');

    expect(spOrigin()).toBe('http://127.0.0.1:4100');
  });
});
