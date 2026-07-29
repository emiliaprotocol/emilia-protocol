/**
 * EP Secure App — signoff byte-binding core.
 *
 * Pure, cross-platform (Web Crypto: Expo/React Native, browser, Node 18+). This
 * is the part that MUST be correct: the challenge the device signs is
 * SHA-256(JCS(context)) using the exact same canonicalization as
 * @emilia-protocol/verify. Cryptographic verification does not establish key
 * provenance or assurance class. The relying party derives those properties
 * from its trusted enrollment directory and platform evidence, never from a
 * client-supplied label.
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
  approver_id?: string;
  context: any;
  webauthn: WebAuthnData;
}

/**
 * Assemble transport-neutral signoff evidence. It intentionally carries no
 * key_class or assurance claim; a server may classify accepted evidence only
 * from a separately trusted enrollment record.
 */
export function buildAttestation({ context, webauthn, approverId }: BuildAttestationArgs): SignoffAttestation {
  if (!context || !webauthn) throw new Error('buildAttestation requires context and webauthn');
  return {
    '@version': 'EP-SIGNOFF-v1',
    approver_id: approverId,
    context,
    webauthn,
  };
}
