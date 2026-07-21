// SPDX-License-Identifier: Apache-2.0
//
// A WIMSE Policy Enforcement Point obligation: per-action human authorization.
//
// Where this sits in draft-ietf-wimse-arch-08:
//   - Section 3.3 (PEP/PDP). WIMSE has already authenticated the workload
//     identity (WIT/WIC) upstream. This function is ONE additional obligation the
//     PEP applies to a request whose workload identity is already established. It
//     does not authenticate the workload and does not replace WIMSE identity or
//     delegation; it is an obligation the PEP enforces on top of them.
//   - Section 3.4.11 (AI/ML intermediaries). A delegated agent operates within a
//     standing delegation: that says the agent MAY act. This obligation says a
//     named human authorized THIS exact consequential action. Delegation is
//     necessary but not sufficient for the irreversible / high-consequence subset;
//     the receipt is the sufficiency proof, evaluated at the enforcement point.
//
// The obligation calls EP's REAL verifier (verifyEmiliaReceipt from
// @emilia-protocol/require-receipt) over a RELATIVE path, so it runs from a fresh
// clone with only Node and no npm install. It is fail-closed: allow=true only
// when the receipt verifies against a PINNED issuer key, binds the EXACT action,
// and is inside its validity window. Every other outcome is allow=false with a
// precise, machine-readable reason.
//
// HONESTY: this proves a named human accountably authorized this action and that
// the evidence is integrity-protected. That is necessary, not sufficient, for a
// safe execution. It does not replace WIMSE workload identity or delegation, and
// the receipt is non-bearer and single-use (consumption is enforced elsewhere in
// the PEP, e.g. @emilia-protocol/gate), so a leaked copy conveys no replayable
// authority.

import { verifyEmiliaReceipt } from '../../packages/require-receipt/index.js';

/**
 * @param {object}   o
 * @param {string}   o.action             the exact action_type this request performs
 * @param {object}   o.presentedReceipt    the EP-RECEIPT-v1 the agent brought (or null)
 * @param {string[]} o.pinnedIssuerKeys    base64url SPKI-DER issuer keys the PEP trusts
 * @param {number}   [o.now]               current epoch ms (injectable for tests)
 * @param {number}   [o.maxAgeSec=900]     reject receipts older than this
 * @returns {{allow: boolean, reason: string, receipt_id?: string, subject?: string, detail?: string}}
 */
export function enforceHumanAuthorizationObligation({ action, presentedReceipt, pinnedIssuerKeys, now = Date.now(), maxAgeSec = 900 }: { action?: string; presentedReceipt?: any; pinnedIssuerKeys?: string[]; now?: number; maxAgeSec?: number } = {}) {
  if (!action) return { allow: false, reason: 'no_action_specified' };            // misconfigured PEP: cannot bind
  if (!Array.isArray(pinnedIssuerKeys) || pinnedIssuerKeys.length === 0) return { allow: false, reason: 'no_pinned_issuer_keys' };
  if (!presentedReceipt) return { allow: false, reason: 'missing_receipt' };      // delegation alone is not sufficient

  const v = verifyEmiliaReceipt(presentedReceipt, {              // EP's real offline Ed25519-over-JCS verifier
    trustedKeys: pinnedIssuerKeys,                              // trust is PINNED by the PEP, never inline
    action,                                                     // must bind THIS exact action_type
    maxAgeSec,                                                  // must be inside its validity window (fail-closed on undated)
  });
  if (v.ok) return { allow: true, reason: 'authorized', receipt_id: v.receipt_id, subject: v.subject };

  const REASON: Record<string, string> = {                                              // map EP's verifier reasons to precise PEP reasons
    malformed_receipt: 'malformed_receipt',
    payload_outside_ijson_profile: 'malformed_receipt',
    bad_signature_encoding: 'malformed_receipt',
    no_trusted_keys_configured: 'no_pinned_issuer_keys',
    untrusted_or_invalid_signature: 'wrong_issuer_key',        // no pinned key verified this signature
    receipt_expired: 'expired',
    action_mismatch: 'action_mismatch',
    outcome_not_accepted: 'outcome_not_accepted',
  };
  return { allow: false, reason: REASON[(v as any).reason] || (v as any).reason, detail: (v as any).detail }; // fail closed on anything unmapped
}

export default enforceHumanAuthorizationObligation;
