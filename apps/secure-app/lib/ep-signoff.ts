/**
 * EP Secure App — Class-A signoff core.
 *
 * Pure, cross-platform (Web Crypto: Expo/React Native, browser, Node 18+). This
 * is the part that MUST be correct: the challenge the device signs is
 * SHA-256(JCS(context)) using the exact same canonicalization as
 * @emilia-protocol/verify, so an attestation this app produces verifies offline
 * under the protocol's own verifier with no special-casing.
 *
 * The actual signing is delegated to a platform signer:
 *   - on a real device, the OS secure enclave / passkey (Face ID / biometric);
 *   - in Expo Go or tests, a software signer (see ep-signoff.test.ts).
 *
 * @license Apache-2.0
 */

const subtle = globalThis.crypto?.subtle;

// Recursive canonical JSON — byte-identical to packages/verify/index.js
// canonicalize(). Signer and verifier MUST agree on these bytes.
export function canonicalize(value: any): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function bytesToB64u(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  // btoa exists in RN (Hermes via polyfill), browsers, and Node 18+.
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * The WebAuthn challenge for a signoff context: base64url(SHA-256(JCS(context))).
 * This is exactly what @emilia-protocol/verify recomputes and compares against
 * clientDataJSON.challenge.
 */
export async function challengeFromContext(context: any): Promise<string> {
  if (!subtle) throw new Error('Web Crypto subtle unavailable in this runtime');
  const data = new TextEncoder().encode(canonicalize(context));
  const digest = new Uint8Array(await subtle.digest('SHA-256', data));
  return bytesToB64u(digest);
}

interface WebAuthnData {
  authenticator_data: string;
  client_data_json: string;
  signature: string;
}

interface BuildAttestationArgs {
  context: any;
  webauthn: WebAuthnData;
  approverId?: string;
}

interface SignoffAttestation {
  '@version': string;
  key_class: string;
  approver_id?: string;
  context: any;
  webauthn: WebAuthnData;
}

/**
 * Assemble the Class-A signoff attestation to POST to the gate. `webauthn` is
 * the platform authenticator's assertion (base64url fields), produced by signing
 * the challenge above.
 */
export function buildAttestation({ context, webauthn, approverId }: BuildAttestationArgs): SignoffAttestation {
  if (!context || !webauthn) throw new Error('buildAttestation requires context and webauthn');
  return {
    '@version': 'EP-SIGNOFF-v1',
    key_class: 'A',
    approver_id: approverId,
    context,
    webauthn,
  };
}
