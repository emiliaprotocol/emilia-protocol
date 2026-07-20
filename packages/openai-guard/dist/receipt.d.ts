/**
 * @emilia-protocol/openai-guard/receipt — EMILIA's real v1 signoff ceremony.
 *
 * Thin, faithful clients for the live v1 endpoints (verified against the actual
 * route handlers in the repo — not invented):
 *
 *   mintReceipt    → POST /api/v1/trust-receipts            (runs the verified policy engine server-side)
 *   requestSignoff → POST /api/v1/signoffs/request          (on a signoff_required receipt)
 *   approveSignoff → POST /api/v1/signoffs/{signoffId}/approve   (a different authenticated principal)
 *   rejectSignoff  → POST /api/v1/signoffs/{signoffId}/reject
 *
 * Flow: mint a pre-action receipt → if `signoff_required`, request signoff → a
 * different authenticated principal approves (EMILIA enforces separation of
 * duty) → proceed. This bearer-authenticated route does not by itself establish
 * human presence or user verification. Offline-verify a signed
 * EP-RECEIPT-v1 with @emilia-protocol/verify.
 *
 * Every call needs an EP API key (Authorization: Bearer …).
 */
type AnyRecord = Record<string, any>;
/**
 * Mint a pre-action trust receipt. The server runs the formally-verified
 * evaluateGuardPolicy and returns { receipt_id, decision, signoff_required,
 * action_hash, policy_hash, canonical_action, ... }.
 *
 * @param {object} o organization_id, action_type (a GUARD_ACTION_TYPES value),
 *   target_resource_id (all required); plus optional amount, currency,
 *   target_changed_fields, risk_flags, before_state, after_state, enforcement_mode.
 */
export declare function mintReceipt({ apiKey, base, fetchImpl, allowInsecureHttp, ...receipt }?: AnyRecord): Promise<AnyRecord>;
/**
 * Request signoff on a receipt that came back signoff_required=true.
 *
 * @param {{ apiKey?: string, base?: string, fetchImpl?: typeof fetch, allowInsecureHttp?: boolean, receipt_id?: string, comment?: string, expires_in_minutes?: number }} [o]
 */
export declare function requestSignoff({ apiKey, base, fetchImpl, allowInsecureHttp, receipt_id, comment, expires_in_minutes }?: AnyRecord): Promise<AnyRecord>;
/**
 * A DIFFERENT authenticated principal approves the signoff. This software/API-key
 * path enforces separation of duty, but does not prove human presence. Use the
 * WebAuthn approval route or mobile ceremony when Class-A evidence is required.
 *
 * @param {{ apiKey?: string, base?: string, fetchImpl?: typeof fetch, allowInsecureHttp?: boolean, signoff_id?: string, comment?: string }} [o]
 */
export declare function approveSignoff({ apiKey, base, fetchImpl, allowInsecureHttp, signoff_id, comment }?: AnyRecord): Promise<AnyRecord>;
/**
 * Reject a signoff.
 *
 * @param {{ apiKey?: string, base?: string, fetchImpl?: typeof fetch, allowInsecureHttp?: boolean, signoff_id?: string, comment?: string }} [o]
 */
export declare function rejectSignoff({ apiKey, base, fetchImpl, allowInsecureHttp, signoff_id, comment }?: AnyRecord): Promise<AnyRecord>;
/**
 * Offline-verify a signed EP-RECEIPT-v1 document. Kept optional so this package
 * stays dependency-free — install @emilia-protocol/verify to use it.
 */
export declare function verifyReceipt(doc: AnyRecord, publicKeyBase64url: string): Promise<any>;
declare const _default: {
    mintReceipt: typeof mintReceipt;
    requestSignoff: typeof requestSignoff;
    approveSignoff: typeof approveSignoff;
    rejectSignoff: typeof rejectSignoff;
    verifyReceipt: typeof verifyReceipt;
};
export default _default;
//# sourceMappingURL=receipt.d.ts.map