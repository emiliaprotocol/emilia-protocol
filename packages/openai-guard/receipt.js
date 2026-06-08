// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/openai-guard/receipt — EMILIA's real v1 signoff ceremony.
 *
 * Thin, faithful clients for the live v1 endpoints (verified against the actual
 * route handlers in the repo — not invented):
 *
 *   mintReceipt    → POST /api/v1/trust-receipts            (runs the verified policy engine server-side)
 *   requestSignoff → POST /api/v1/signoffs/request          (on a signoff_required receipt)
 *   approveSignoff → POST /api/v1/signoffs/{signoffId}/approve   (a NAMED, DIFFERENT human)
 *   rejectSignoff  → POST /api/v1/signoffs/{signoffId}/reject
 *
 * Flow: mint a pre-action receipt → if `signoff_required`, request signoff → a
 * named human approves (EMILIA enforces separation of duty: the approver must be
 * a different principal than the initiator) → proceed. Offline-verify a signed
 * EP-RECEIPT-v1 with @emilia-protocol/verify.
 *
 * Every call needs an EP API key (Authorization: Bearer …).
 */

const DEFAULT_BASE = 'https://www.emiliaprotocol.ai';

async function epPost(base, pathname, apiKey, body, fetchImpl) {
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) throw new Error('no fetch implementation available; pass { fetchImpl }');
  const res = await doFetch(`${base}${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`EMILIA ${pathname} ${res.status}: ${data.detail || data.title || JSON.stringify(data).slice(0, 160)}`);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return data;
}

/**
 * Mint a pre-action trust receipt. The server runs the formally-verified
 * evaluateGuardPolicy and returns { receipt_id, decision, signoff_required,
 * action_hash, policy_hash, canonical_action, ... }.
 *
 * @param {object} o organization_id, action_type (a GUARD_ACTION_TYPES value),
 *   target_resource_id (all required); plus optional amount, currency,
 *   target_changed_fields, risk_flags, before_state, after_state, enforcement_mode.
 */
export function mintReceipt({ apiKey, base = DEFAULT_BASE, fetchImpl, ...receipt } = {}) {
  if (!apiKey) throw new Error('mintReceipt: apiKey is required');
  for (const f of ['organization_id', 'action_type', 'target_resource_id']) {
    if (!receipt[f]) throw new Error(`mintReceipt: ${f} is required`);
  }
  return epPost(base, '/api/v1/trust-receipts', apiKey, receipt, fetchImpl);
}

/** Request signoff on a receipt that came back signoff_required=true. */
export function requestSignoff({ apiKey, base = DEFAULT_BASE, fetchImpl, receipt_id, comment, expires_in_minutes } = {}) {
  if (!apiKey) throw new Error('requestSignoff: apiKey is required');
  if (!receipt_id) throw new Error('requestSignoff: receipt_id is required');
  return epPost(base, '/api/v1/signoffs/request', apiKey, { receipt_id, comment, expires_in_minutes }, fetchImpl);
}

/**
 * A NAMED human approves the signoff. Authenticate as a DIFFERENT principal than
 * the initiator — EMILIA enforces separation of duty server-side.
 */
export function approveSignoff({ apiKey, base = DEFAULT_BASE, fetchImpl, signoff_id, comment } = {}) {
  if (!apiKey) throw new Error("approveSignoff: apiKey is required (the approving human's key)");
  if (!signoff_id) throw new Error('approveSignoff: signoff_id is required');
  return epPost(base, `/api/v1/signoffs/${encodeURIComponent(signoff_id)}/approve`, apiKey, { comment }, fetchImpl);
}

/** Reject a signoff. */
export function rejectSignoff({ apiKey, base = DEFAULT_BASE, fetchImpl, signoff_id, comment } = {}) {
  if (!apiKey) throw new Error('rejectSignoff: apiKey is required');
  if (!signoff_id) throw new Error('rejectSignoff: signoff_id is required');
  return epPost(base, `/api/v1/signoffs/${encodeURIComponent(signoff_id)}/reject`, apiKey, { comment }, fetchImpl);
}

/**
 * Offline-verify a signed EP-RECEIPT-v1 document. Kept optional so this package
 * stays dependency-free — install @emilia-protocol/verify to use it.
 */
export async function verifyReceipt(doc, publicKeyBase64url) {
  let verify;
  try {
    ({ verifyReceipt: verify } = await import('@emilia-protocol/verify'));
  } catch {
    throw new Error('verifyReceipt: run `npm i @emilia-protocol/verify` to verify receipts offline');
  }
  return verify(doc, publicKeyBase64url);
}

export default { mintReceipt, requestSignoff, approveSignoff, rejectSignoff, verifyReceipt };
