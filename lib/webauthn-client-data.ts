// SPDX-License-Identifier: Apache-2.0
// Same-origin rule for the WebAuthn ceremonies EP verifies online.
//
// EP never runs a WebAuthn ceremony inside a cross-origin iframe: its pages are
// served with `frame-ancestors 'none'`, and its offline verifiers
// (packages/verify, packages/mobile, packages/require-receipt) refuse client
// data whose `crossOrigin` is true. @simplewebauthn/server does not enforce
// that on its own. v14 refuses a cross-origin authentication response only when
// the browser also reports `topOrigin` (Safari omits it), and it never looks at
// either member on a registration response. Every online call site runs this
// check first, so the server admits exactly the client data its own offline
// verifiers accept.
//
// The client data is decoded with the library's own decoder, so this reads the
// same bytes verifyRegistrationResponse / verifyAuthenticationResponse will.

import { decodeClientDataJSON } from '@simplewebauthn/server/helpers';

export function assertSameOriginWebAuthnResponse(response: unknown): void {
  const encoded = (response as { response?: { clientDataJSON?: unknown } } | null)?.response?.clientDataJSON;
  // A missing or non-string clientDataJSON is left to the library, which
  // refuses it.
  if (typeof encoded !== 'string') return;
  let clientData: unknown;
  try {
    clientData = decodeClientDataJSON(encoded);
  } catch {
    throw new Error('WebAuthn client data is not valid base64url JSON');
  }
  if (!clientData || typeof clientData !== 'object' || Array.isArray(clientData)) {
    throw new Error('WebAuthn client data is not a JSON object');
  }
  const { crossOrigin, topOrigin } = clientData as { crossOrigin?: unknown; topOrigin?: unknown };
  if (crossOrigin !== undefined && crossOrigin !== false) {
    throw new Error('Refused a cross-origin WebAuthn response: EP ceremonies run only in a top-level, same-origin page');
  }
  if (topOrigin !== undefined) {
    throw new Error('Refused a cross-origin WebAuthn response: client data carries a top origin (topOrigin)');
  }
}
