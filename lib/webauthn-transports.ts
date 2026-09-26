// SPDX-License-Identifier: Apache-2.0
// WebAuthn authenticator transport hints EP accepts on a stored credential.
//
// @simplewebauthn v14 removed its closed `AuthenticatorTransportFuture` union
// and now types `transports` as plain `string[]`. EP keeps the closed set: a
// transport hint read back from the credential store, or replayed into
// `allowCredentials` / `excludeCredentials`, stays a validated value rather
// than whatever string a row happens to hold. The members are exactly the
// v13 union, so no hint that validated before this migration is refused now
// and no new one is admitted.

export const WEBAUTHN_AUTHENTICATOR_TRANSPORTS = Object.freeze([
  'ble',
  'cable',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb',
] as const);

export type WebAuthnAuthenticatorTransport = (typeof WEBAUTHN_AUTHENTICATOR_TRANSPORTS)[number];

const TRANSPORT_SET: ReadonlySet<string> = new Set(WEBAUTHN_AUTHENTICATOR_TRANSPORTS);

export function isWebAuthnAuthenticatorTransport(value: unknown): value is WebAuthnAuthenticatorTransport {
  return typeof value === 'string' && TRANSPORT_SET.has(value);
}
