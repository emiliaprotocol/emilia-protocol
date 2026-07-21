// SPDX-License-Identifier: Apache-2.0
//
// Regression for the OIDC DNS-rebinding TOCTOU: server-side SSO fetches
// (discovery, token, JWKS) must validate AND pin to the resolved public IP, so
// a host that resolves to a private / cloud-metadata address is refused before
// any connection is made. safePinnedFetch validates+resolves in one step; these
// pin the refusal behavior. (The happy path — a real pinned TLS connection — is
// covered by the discover/exchangeCode fixture tests in sso-oidc.test.js.)

import { describe, it, expect } from 'vitest';
import { safePinnedFetch } from '../lib/sso/pinned-fetch.js';

describe('safePinnedFetch — DNS-rebind / SSRF defense', () => {
  it('refuses a host that resolves to the cloud-metadata IP (no connection attempted)', async () => {
    const rebind = async () => [{ address: '169.254.169.254', family: 4 }];
    await expect(
      safePinnedFetch('https://issuer.attacker.test/.well-known/openid-configuration', {}, { lookup: rebind }),
    ).rejects.toThrow(/SSRF-blocked/);
  });

  it('refuses a host that resolves to an RFC1918 private IP', async () => {
    const priv = async () => [{ address: '10.1.2.3', family: 4 }];
    await expect(
      safePinnedFetch('https://idp.attacker.test/token', { method: 'POST', body: 'x' }, { lookup: priv }),
    ).rejects.toThrow(/SSRF-blocked/);
  });

  it('refuses a host that resolves to loopback', async () => {
    const loop = async () => [{ address: '127.0.0.1', family: 4 }];
    await expect(safePinnedFetch('https://jwks.attacker.test/keys', {}, { lookup: loop })).rejects.toThrow(/SSRF-blocked/);
  });

  it('refuses a non-https URL before any DNS resolution', async () => {
    await expect(safePinnedFetch('http://idp.example.com/x', {})).rejects.toThrow(/SSRF-blocked/);
  });
});
