// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — real WebAuthn user-verification (UV) signal for a
// single Class-A signoff decision at consume time.
//
// WHY THIS EXISTS
// The consume gate for a `required_assurance: 'A'` receipt used to admit a
// single signoff whenever the RECORDED decision was LABELLED `key_class: 'A'`.
// That label is written by the approve-webauthn route, which does verify UV at
// decision time (verifyAuthenticationResponse({ requireUserVerification: true }))
// — but the consume gate trusted the label, not the underlying signal. A label
// is an assumption; the security property is the WebAuthn user-verification (UV)
// flag actually set in the authenticator data the approver's device signed.
//
// This helper re-derives that REAL signal from the stored assertion at consume,
// using the SAME offline EP primitive (verifyWebAuthnSignoff in
// packages/verify/index.js) that the multi-party quorum gate and the
// cross-language conformance suite already use. No second/forked verifier: it
// reconstructs the exact EP-SIGNOFF-v1 object (context + webauthn assertion)
// the way lib/signoff/attestation-members.js does, hands it to
// verifyWebAuthnSignoff, and reports whether the assertion genuinely proves user
// verification (biometric/PIN), that it binds this receipt's action, and that it
// verifies against the approver's enrolled key.
//
// FAIL CLOSED. Every missing/incomplete/invalid input yields `verified: false`.
// A Class-A label with no UV-bearing, action-bound, signature-valid assertion is
// treated as NOT sufficient — never admitted on the label alone.

import { verifyWebAuthnSignoff } from '../packages/verify/index.js';

/**
 * Re-derive the real WebAuthn UV verdict from a stored single-signoff decision.
 *
 * @param {object} [params]
 * @param {object} [params.decision]      the `guard.signoff.approved` after_state:
 *                                       { context, webauthn:{ credential_id,
 *                                       authenticator_data, client_data_json,
 *                                       signature }, key_class, ... }
 * @param {string} [params.approverPublicKeySpki]  enrolled SPKI (base64url) from
 *                                       approver_credentials.public_key_spki
 * @param {string} [params.expectedActionHash]     the receipt-issued action_hash;
 *                                       the signed context MUST bind it
 * @param {string} [params.rpId]        expected WebAuthn relying-party id (scopes
 *                                       the assertion when supplied)
 * @param {string[]} [params.allowedOrigins] exact WebAuthn origins accepted by
 *                                       the relying party
 * @returns {{ verified: boolean, reason: string, checks?: object }}
 *   verified=true ONLY when the assertion is present, binds expectedActionHash,
 *   verifies against the key, asserts user presence AND user verification, and
 *   (when rpId supplied) is scoped to the expected RP.
 */
type SignoffDecision = {
  context?: Record<string, any>;
  webauthn?: {
    authenticator_data?: string;
    client_data_json?: string;
    signature?: string;
  };
};

export function deriveSignoffUserVerification({
  decision,
  approverPublicKeySpki,
  expectedActionHash,
  rpId,
  allowedOrigins,
}: {
  decision?: SignoffDecision | null;
  approverPublicKeySpki?: string;
  expectedActionHash?: string;
  rpId?: string;
  allowedOrigins?: string[];
} = {}) {
  if (!decision || typeof decision !== 'object') {
    return { verified: false, reason: 'missing_decision' };
  }
  const context = decision.context;
  const webauthn = decision.webauthn;
  if (!context || !webauthn) {
    // A Class-A label without the signed context + assertion is unverifiable.
    return { verified: false, reason: 'missing_assertion_evidence' };
  }
  if (!webauthn.authenticator_data || !webauthn.client_data_json || !webauthn.signature) {
    return { verified: false, reason: 'incomplete_assertion' };
  }
  if (!approverPublicKeySpki) {
    // No enrolled key to check the signature against — cannot prove control.
    return { verified: false, reason: 'missing_approver_key' };
  }

  // The signed context MUST bind the exact action being consumed. The approve
  // route already checks this at decision time; re-checking here means consume
  // never relies solely on issuance, and a decision whose stored context binds a
  // different action can never satisfy the gate.
  if (expectedActionHash && context.action_hash !== expectedActionHash) {
    return { verified: false, reason: 'action_hash_mismatch' };
  }

  // Reconstruct the portable EP-SIGNOFF-v1 object exactly as the quorum bridge
  // does (lib/signoff/attestation-members.js), then verify with the shared EP
  // primitive. verifyWebAuthnSignoff derives user_verified straight from the
  // authenticator-data flags byte (FLAG_UV = 0x04) — the real signal.
  const signoff = {
    '@type': 'ep.signoff',
    context,
    webauthn: {
      authenticator_data: webauthn.authenticator_data,
      client_data_json: webauthn.client_data_json,
      signature: webauthn.signature,
    },
  };

  const result = verifyWebAuthnSignoff(signoff, approverPublicKeySpki, {
    ...(rpId ? { rpId } : {}),
    ...(Array.isArray(allowedOrigins) ? { allowedOrigins } : {}),
  });
  // `valid` already requires challenge_binding && client_data_type &&
  // user_present && user_verified && signature (&& rp scope when provided). We
  // additionally surface user_verified explicitly so the caller's refusal reason
  // is precise (a signature-valid but non-UV assertion is a distinct failure).
  if (!result.valid) {
    const reason = result.checks && result.checks.user_verified === false
      ? 'user_verification_absent'
      : 'assertion_invalid';
    return { verified: false, reason, checks: result.checks };
  }
  return { verified: true, reason: 'user_verified', checks: result.checks };
}
