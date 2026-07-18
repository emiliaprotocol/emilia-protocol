// SPDX-License-Identifier: Apache-2.0

/**
 * Verified authentication-strength projection.
 *
 * `auth_strength` is populated only by the server-side authentication RPC from
 * the credential record. Callers must not raise it with request-body fields,
 * role hints, or entity metadata. Until a credential is explicitly labeled,
 * the safe result is password and policy evaluation may escalate to signoff.
 */

export const AUTH_STRENGTHS = Object.freeze({
  PASSWORD: 'password',
  MFA: 'mfa',
  PHISHING_RESISTANT_MFA: 'phishing_resistant_mfa',
  SERVICE_ACCOUNT: 'service_account',
});

const VALID_AUTH_STRENGTHS = new Set(Object.values(AUTH_STRENGTHS));

export function resolveVerifiedAuthStrength(auth) {
  const candidate = auth?.auth_strength;
  return VALID_AUTH_STRENGTHS.has(candidate)
    ? candidate
    : AUTH_STRENGTHS.PASSWORD;
}

export function isVerifiedAuthStrength(value) {
  return VALID_AUTH_STRENGTHS.has(value);
}
