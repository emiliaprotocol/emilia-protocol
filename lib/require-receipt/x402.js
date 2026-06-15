/**
 * EP × x402 — the demand-side rail.
 *
 * @license Apache-2.0
 *
 * Speaks the x402 (HTTP 402) shape so an x402/AP2-aware agent client recognizes
 * the demand natively: when a service guards an irreversible action, it answers
 * `402` with an `accepts` block describing the authorization proof to bring. The
 * "payment" is not money — it is a **verifiable EMILIA authorization proof**:
 *
 *   - an `EP-ENVELOPE-v1` for ANY registered profile  → verified via the registry
 *     verifier (verifyEnvelope). This is the keystone as the demand currency: a
 *     single rail that accepts the whole protocol family.
 *   - a bare `EP-RECEIPT-v1` authorization receipt     → verified via
 *     @emilia-protocol/require-receipt (action-bound, fresh, outcome-checked).
 *
 * The proof is carried in the x402 `X-PAYMENT` header (base64 JSON). Verification
 * is offline; a missing/invalid proof yields `402` + a machine-readable reason so
 * a well-behaved agent self-serves a proof and retries (like a browser on 401).
 * Fail closed: only a valid proof releases the action.
 */

import { verifyEnvelope } from '../envelope/index.js';
import { verifyEmiliaReceipt } from '../../packages/require-receipt/index.js';

export const X402_VERSION = 1;
export const EP_X402_SCHEME = 'emilia-receipt';

/**
 * Build the x402 402-challenge body telling an agent exactly what proof to bring.
 * @param {object} o
 * @param {string} [o.resource] the protected resource URL
 * @param {string} [o.action] the action_type the proof must be bound to
 * @param {string} [o.profile] the EP profile URN expected (default: the core receipt)
 * @param {string} [o.description]
 */
export function x402ReceiptChallenge({ resource = null, action = null, profile = 'urn:ep:profile:receipt:v1', description } = {}) {
  return {
    x402Version: X402_VERSION,
    error: 'EMILIA authorization proof required',
    accepts: [
      {
        scheme: EP_X402_SCHEME,
        network: 'offline',
        resource,
        description: description || 'Present a verifiable EMILIA authorization proof that a named human approved this exact irreversible action.',
        // Not a monetary payment: the "amount" is a valid receipt. Kept for x402
        // client compatibility (clients expect these fields).
        maxAmountRequired: '0',
        asset: 'ep-authorization-receipt',
        payTo: null,
        extra: {
          action_type: action,
          profile,
          accepted_proofs: ['EP-ENVELOPE-v1', 'EP-RECEIPT-v1'],
          present_via: 'X-PAYMENT: base64(<EP-ENVELOPE-v1 or EP-RECEIPT-v1 JSON>)',
          registry: '/.well-known/ep-profiles.json',
          how: 'Obtain a proof (emilia-gate / SDK / POST /api/trust/gate), base64 it, resend with the X-PAYMENT header.',
          learn_more: 'https://www.emiliaprotocol.ai/agent-guard',
        },
      },
    ],
  };
}

/** Decode an x402 X-PAYMENT header (base64 JSON) → object, or null. */
export function decodeX402Payment(headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return null;
  try {
    return JSON.parse(Buffer.from(headerValue, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Verify a presented x402 authorization proof. Fail closed.
 *
 * @param {string|object} payment - the X-PAYMENT header value (base64 JSON) or an
 *   already-decoded proof object.
 * @param {object} opts - verifier context: for an envelope, the per-profile opts
 *   (e.g. pinnedKeys/target/action); for a bare receipt, require-receipt opts
 *   (trustedKeys/allowInlineKey/action/maxAgeSec/allowedOutcomes).
 * @returns {{ ok:boolean, valid:boolean, profile?:string, reason?:string, detail?:string,
 *            checks?:object, errors?:string[], settlement?:object }}
 */
export function verifyX402Proof(payment, opts = {}) {
  const obj = typeof payment === 'string' ? decodeX402Payment(payment) : payment;
  if (!obj || typeof obj !== 'object') {
    return { ok: false, valid: false, reason: 'no_or_malformed_payment' };
  }

  // EP-ENVELOPE-v1 → registry-dispatched verification (the keystone rail).
  if (obj.ep === 'EP-ENVELOPE-v1') {
    const r = verifyEnvelope(obj, opts);
    if (r.valid) return { ok: true, valid: true, profile: r.profile, settlement: settlement(EP_X402_SCHEME, r.profile) };
    return { ok: false, valid: false, profile: r.profile, reason: 'envelope_invalid', checks: r.checks, errors: r.errors };
  }

  // Bare EP-RECEIPT-v1 authorization receipt → action-bound verification.
  if (obj['@version'] === 'EP-RECEIPT-v1') {
    const v = verifyEmiliaReceipt(obj, opts);
    if (v.ok) return { ok: true, valid: true, profile: 'urn:ep:profile:receipt:v1', receipt: v, settlement: settlement(EP_X402_SCHEME, 'urn:ep:profile:receipt:v1') };
    return { ok: false, valid: false, reason: v.reason, detail: v.detail };
  }

  return { ok: false, valid: false, reason: 'unrecognized_proof', detail: 'expected EP-ENVELOPE-v1 or EP-RECEIPT-v1' };
}

/** The x402 X-PAYMENT-RESPONSE analogue the service returns on a 200 release. */
function settlement(scheme, profile) {
  return { success: true, scheme, profile, network: 'offline' };
}

const epx402 = { X402_VERSION, EP_X402_SCHEME, x402ReceiptChallenge, decodeX402Payment, verifyX402Proof };
export default epx402;
