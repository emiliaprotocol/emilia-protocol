/**
 * ep_verify_receipt / ep_verify_signoff tool implementations for the MCP
 * route. Kept out of route.ts: a Next.js App Router route file may only
 * export the HTTP method handlers and its documented config fields, and
 * this module needs a plain named export for direct unit testing.
 *
 * @license Apache-2.0
 */

import { verifyReceipt, verifyWebAuthnSignoff } from '@/lib/verify-web';

export async function verifyReceiptTool({ document, public_key }: { document: unknown; public_key?: unknown }): Promise<Record<string, unknown>> {
  if (typeof public_key !== 'string' || !public_key) {
    return {
      valid: false,
      accepted: null,
      scope: 'cryptographic_integrity',
      error: 'A caller-supplied issuer key is required. Artifact-embedded keys cannot establish their own trust.',
    };
  }
  const result = await verifyReceipt(document, public_key);
  return {
    ...result,
    accepted: null,
    scope: 'cryptographic_integrity',
    key_source: 'caller_supplied',
    limitation: 'This verifies bytes under the supplied key. It does not establish who controls that key, issuer authority, policy acceptance, or legal reliance.',
  };
}

export async function verifySignoffTool({ signoff, approver_public_key, rp_id, allowed_origins }: { signoff: unknown; approver_public_key?: unknown; rp_id?: unknown; allowed_origins?: unknown }): Promise<Record<string, unknown>> {
  if (typeof approver_public_key !== 'string' || !approver_public_key) {
    return {
      valid: false,
      accepted: null,
      scope: 'scoped_webauthn_integrity',
      error: 'A caller-supplied approver key is required. Artifact-embedded keys cannot establish their own identity.',
    };
  }
  if (typeof rp_id !== 'string' || !rp_id
      || !Array.isArray(allowed_origins) || allowed_origins.length === 0
      || allowed_origins.some((origin) => typeof origin !== 'string' || !origin)) {
    return {
      valid: false,
      accepted: null,
      scope: 'scoped_webauthn_integrity',
      error: 'rp_id and at least one exact allowed_origins entry are required for WebAuthn verification.',
    };
  }
  const result = await verifyWebAuthnSignoff(signoff, approver_public_key, {
    rpId: rp_id,
    allowedOrigins: allowed_origins,
  });
  return {
    ...result,
    accepted: null,
    scope: 'scoped_webauthn_integrity',
    key_source: 'caller_supplied',
    limitation: 'This verifies a user-present, user-verified ceremony under the supplied key and WebAuthn scope. It does not prove legal identity, perception, authority, or relying-party acceptance.',
  };
}
