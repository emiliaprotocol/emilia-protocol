// SPDX-License-Identifier: Apache-2.0
// The same-origin client-data rule every online WebAuthn call site runs
// before @simplewebauthn/server (lib/webauthn-client-data.ts).

import { describe, expect, it } from 'vitest';
import { assertSameOriginWebAuthnResponse } from '../lib/webauthn-client-data.js';

function withClientData(clientData: unknown) {
  const encoded = typeof clientData === 'string'
    ? clientData
    : Buffer.from(JSON.stringify(clientData), 'utf8').toString('base64url');
  return { id: 'cred', rawId: 'cred', type: 'public-key', response: { clientDataJSON: encoded } };
}

const BASE = { type: 'webauthn.get', challenge: 'Y2hhbGxlbmdl', origin: 'https://example.com' };

describe('assertSameOriginWebAuthnResponse', () => {
  it.each([
    ['no crossOrigin member', BASE],
    ['crossOrigin: false', { ...BASE, crossOrigin: false }],
  ])('admits client data with %s', (_label, clientData) => {
    expect(() => assertSameOriginWebAuthnResponse(withClientData(clientData))).not.toThrow();
  });

  it.each([
    ['crossOrigin: true', { ...BASE, crossOrigin: true }, /cross-origin/],
    ['crossOrigin: "true"', { ...BASE, crossOrigin: 'true' }, /cross-origin/],
    ['crossOrigin: null', { ...BASE, crossOrigin: null }, /cross-origin/],
    ['crossOrigin: 1', { ...BASE, crossOrigin: 1 }, /cross-origin/],
    ['crossOrigin + topOrigin', { ...BASE, crossOrigin: true, topOrigin: 'https://evil.example' }, /cross-origin/],
    ['topOrigin alone', { ...BASE, topOrigin: 'https://evil.example' }, /top origin/],
    ['topOrigin equal to the RP origin', { ...BASE, crossOrigin: false, topOrigin: BASE.origin }, /top origin/],
    ['a JSON array', [BASE], /not a JSON object/],
    ['JSON null', null, /not a JSON object/],
    ['bytes that are not JSON', Buffer.from('{', 'utf8').toString('base64url'), /not valid base64url JSON/],
  ])('refuses client data with %s', (_label, clientData, reason) => {
    expect(() => assertSameOriginWebAuthnResponse(withClientData(clientData))).toThrow(reason);
  });

  it('leaves a missing or non-string clientDataJSON to the library, which refuses it', () => {
    for (const response of [undefined, null, {}, { response: {} }, { response: { clientDataJSON: 7 } }]) {
      expect(() => assertSameOriginWebAuthnResponse(response)).not.toThrow();
    }
  });
});
