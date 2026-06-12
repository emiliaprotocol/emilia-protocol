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
 *   - in Expo Go or tests, a software signer (see ep-signoff.test.mjs).
 *
 * @license Apache-2.0
 */

const subtle = globalThis.crypto?.subtle;

// Recursive canonical JSON — byte-identical to packages/verify/index.js
// canonicalize(). Signer and verifier MUST agree on these bytes.
export function canonicalize(value) {
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

function bytesToB64u(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  // btoa exists in RN (Hermes via polyfill), browsers, and Node 18+.
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * The WebAuthn challenge for a signoff context: base64url(SHA-256(JCS(context))).
 * This is exactly what @emilia-protocol/verify recomputes and compares against
 * clientDataJSON.challenge.
 *
 * @param {object} context - the canonical Authorization Context
 * @returns {Promise<string>} base64url challenge
 */
export async function challengeFromContext(context) {
  if (!subtle) throw new Error('Web Crypto subtle unavailable in this runtime');
  const data = new TextEncoder().encode(canonicalize(context));
  const digest = new Uint8Array(await subtle.digest('SHA-256', data));
  return bytesToB64u(digest);
}

/**
 * Assemble the Class-A signoff attestation to POST to the gate. `webauthn` is
 * the platform authenticator's assertion (base64url fields), produced by signing
 * the challenge above.
 *
 * @param {object} args
 * @param {object} args.context
 * @param {{ authenticator_data:string, client_data_json:string, signature:string }} args.webauthn
 * @param {string} [args.approverId]
 * @returns {object} signoff document ({ context, webauthn }) the verifier accepts
 */
export function buildAttestation({ context, webauthn, approverId }) {
  if (!context || !webauthn) throw new Error('buildAttestation requires context and webauthn');
  return {
    '@version': 'EP-SIGNOFF-v1',
    key_class: 'A',
    approver_id: approverId,
    context,
    webauthn,
  };
}
