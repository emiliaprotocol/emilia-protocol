// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { validateSsoProviderUrl } from '../lib/sso/url-policy.js';

describe('SSO provider URL policy', () => {
  it('allows normal public https provider URLs', () => {
    const result = validateSsoProviderUrl('https://idp.example.com/sso/', 'saml_idp_entry_point');
    expect(result.valid).toBe(true);
    expect(result.url).toBe('https://idp.example.com/sso');
  });

  it('rejects non-https provider URLs', () => {
    const result = validateSsoProviderUrl('http://idp.example.com/sso', 'saml_idp_entry_point');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('https');
  });

  it('rejects credentials embedded in provider URLs', () => {
    const result = validateSsoProviderUrl('https://user:pass@idp.example.com/sso', 'oidc_issuer');
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
  ])('rejects private or metadata host %s', (url) => {
    const result = validateSsoProviderUrl(url, 'provider');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('blocked or private');
  });
});
