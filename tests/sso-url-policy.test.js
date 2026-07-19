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

  // Regression: IPv4-mapped IPv6 literals (::ffff:a.b.c.d) are net.isIP()===6, so
  // the old guard routed them through the v6-only range checks and let the
  // embedded private/link-local v4 (e.g. the cloud-metadata IP) through.
  it.each([
    'https://[::ffff:169.254.169.254]/latest/meta-data/', // link-local metadata, dotted
    'https://[::ffff:127.0.0.1]/sso',                      // loopback, dotted
    'https://[::ffff:10.0.0.1]/sso',                       // RFC1918, dotted
    'https://[::ffff:a9fe:a9fe]/latest/meta-data/',        // metadata, hex form
    'https://[::ffff:c0a8:0101]/sso',                      // 192.168.1.1, hex form
    'https://[0:0:0:0:0:ffff:7f00:1]/sso',                 // loopback, expanded form
  ])('rejects IPv4-mapped IPv6 private/link-local literal %s', async (url) => {
    const result = await validateSsoProviderUrl(url, 'provider', { lookup: publicLookup });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('blocked or private');
  });

  it('rejects a hostname that resolves to an IPv4-mapped IPv6 private address', async () => {
    const result = await validateSsoProviderUrl('https://idp.attacker.test/sso', 'oidc_issuer', {
      lookup: async () => [{ address: '::ffff:169.254.169.254', family: 6 }],
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('resolves to a blocked or private host');
  });

  it('still accepts a normal public https provider host', async () => {
    const result = await validateSsoProviderUrl('https://idp.example.com/sso/', 'oidc_issuer', {
      lookup: async () => [{ address: '203.0.113.10', family: 4 }],
    });
    expect(result.valid).toBe(true);
    expect(result.url).toBe('https://idp.example.com/sso');
  });

  it('does not misclassify a genuine public IPv6 that contains an ffff group', async () => {
    // 2001:db8::ffff:a9fe:a9fe is NOT an IPv4-mapped address; it must not be
    // rewritten to an embedded v4 and must pass as a public literal.
    const result = await validateSsoProviderUrl('https://[2001:db8::ffff:a9fe:a9fe]/sso', 'provider', {
      lookup: publicLookup,
    });
    expect(result.valid).toBe(true);
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
