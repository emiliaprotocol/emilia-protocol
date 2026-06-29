// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { validateOidcRedirectUri, validateSsoProviderUrl } from '../lib/sso/url-policy.js';

const publicLookup = async () => [{ address: '203.0.113.10', family: 4 }];
const privateLookup = async () => [{ address: '10.0.0.7', family: 4 }];

describe('SSO provider URL policy', () => {
  it('allows normal public https provider URLs', async () => {
    const result = await validateSsoProviderUrl('https://idp.example.com/sso/', 'saml_idp_entry_point', { lookup: publicLookup });
    expect(result.valid).toBe(true);
    expect(result.url).toBe('https://idp.example.com/sso');
  });

  it('rejects non-https provider URLs', async () => {
    const result = await validateSsoProviderUrl('http://idp.example.com/sso', 'saml_idp_entry_point', { lookup: publicLookup });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('https');
  });

  it('rejects credentials embedded in provider URLs', async () => {
    const result = await validateSsoProviderUrl('https://user:pass@idp.example.com/sso', 'oidc_issuer', { lookup: publicLookup });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('credentials');
  });

  it.each([
    'https://localhost/sso',
    'https://127.0.0.1/sso',
    'https://10.0.0.5/sso',
    'https://172.16.0.5/sso',
    'https://192.168.1.10/sso',
    'https://169.254.169.254/latest/meta-data/',
    'https://metadata.google.internal/computeMetadata/v1/',
    'https://[::1]/sso',
    'https://[fd00::1]/sso',
  ])('rejects private or metadata host %s', async (url) => {
    const result = await validateSsoProviderUrl(url, 'provider', { lookup: publicLookup });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('blocked or private');
  });

  it('rejects hostnames that resolve to private addresses', async () => {
    const result = await validateSsoProviderUrl('https://idp.attacker.test/sso', 'saml_idp_entry_point', { lookup: privateLookup });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('resolves to a blocked or private host');
  });

  it('fails closed when a hostname cannot be resolved', async () => {
    const result = await validateSsoProviderUrl('https://missing.attacker.test/sso', 'oidc_issuer', {
      lookup: async () => { throw new Error('NXDOMAIN'); },
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('could not be resolved safely');
  });
});

describe('OIDC redirect URI policy', () => {
  const origin = 'https://www.emiliaprotocol.ai';

  it('accepts the exact service callback URI', () => {
    const result = validateOidcRedirectUri('https://www.emiliaprotocol.ai/api/sso/oidc/callback', origin);
    expect(result).toEqual({
      valid: true,
      url: 'https://www.emiliaprotocol.ai/api/sso/oidc/callback',
    });
  });

  it('accepts the relative canonical callback and normalizes to an absolute URL', () => {
    const result = validateOidcRedirectUri('/api/sso/oidc/callback', origin);
    expect(result).toEqual({
      valid: true,
      url: 'https://www.emiliaprotocol.ai/api/sso/oidc/callback',
    });
  });

  it('treats missing redirect URI as default callback', () => {
    expect(validateOidcRedirectUri(null, origin)).toEqual({ valid: true, url: null });
  });

  it.each([
    ['external origin', 'https://attacker.example/callback'],
    ['wrong path', 'https://www.emiliaprotocol.ai/evil/callback'],
    ['query data', 'https://www.emiliaprotocol.ai/api/sso/oidc/callback?next=https://attacker.example'],
    ['fragment data', 'https://www.emiliaprotocol.ai/api/sso/oidc/callback#token'],
    ['credentials', 'https://user:pass@www.emiliaprotocol.ai/api/sso/oidc/callback'],
  ])('rejects unsafe redirect URI: %s', (_label, value) => {
    const result = validateOidcRedirectUri(value, origin);
    expect(result.valid).toBe(false);
  });

  it('property: any accepted non-empty redirect normalizes to the exact callback', () => {
    fc.assert(fc.property(fc.string({ maxLength: 300 }), (value) => {
      const result = validateOidcRedirectUri(value, origin);
      if (!result.valid || result.url === null) return true;
      expect(result.url).toBe('https://www.emiliaprotocol.ai/api/sso/oidc/callback');
      return true;
    }), { numRuns: 1000 });
  });
});
