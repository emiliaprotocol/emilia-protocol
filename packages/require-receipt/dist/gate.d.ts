/**
 * @emilia-protocol/require-receipt — makeReceiptGate
 * @license Apache-2.0
 *
 * The canonical, hardened Receipt-Required gate. Encodes, in ONE reviewed place,
 * the three properties that are easy to get wrong when hand-rolling a guard:
 *
 *   1. TARGET BINDING — a receipt is bound to the exact resource, not just the
 *      action type, so a valid receipt for resource A cannot act on resource B.
 *   2. CONSUME-BEFORE-RETRY (+ replay safety) — a receipt is RESERVED before the
 *      side effect and permanently COMMITTED after any execution attempt. Once
 *      execution begins, an exception cannot distinguish "nothing happened"
 *      from "the effect happened but its response was lost", so automatic retry
 *      would risk duplicating an irreversible action.
 *   3. SANITIZED REJECTIONS — a refusal returns only a `{ reason }` code, never
 *      the verified receipt's signer/subject/library detail.
 *
 * Prefer `gate.run(receipt, { target }, fn)` — it orchestrates verify → reserve →
 * attempt → commit so a caller cannot get the ordering wrong. Use the lower-level
 * `check` / `commit` / `release` only when you can prove the effect has not begun.
 */
import { receiptAssuranceTier } from './index.js';
type AnyRecord = Record<string, any>;
export { receiptAssuranceTier };
/**
 * Build a hardened Receipt-Required gate for one action type.
 *
 * @param {object} [opts]
 * @param {string|((target:any)=>string)} [opts.action]  base action_type, or a fn
 *   that derives the fully-bound action from the target. Required at runtime
 *   (throws when absent); optional in the type so a `{}` default is well-formed.
 * @param {string[]} [opts.trustedKeys]      issuer SPKI keys you trust (recommended).
 * @param {boolean} [opts.allowInlineKey=false] also accept the receipt's own key
 *   (proves integrity, NOT issuer trust) — demo only; leave off in production.
 * @param {number} [opts.maxAgeSec=900]
 * @param {string[]} [opts.allowedOutcomes]
 * @param {number} [opts.statusCode=428]
 * @param {string} [opts.manifestUrl]
 * @param {string} [opts.assuranceClass]
 * @param {object} [opts.quorum]
 * @param {{authorization_endpoint:string,flow:'EP-APPROVAL-v1'}} [opts.authorization]
 *   relying-party-pinned acquisition descriptor exposed in challenges.
 * @param {string[]} [opts.requiredFields] exact material action fields an
 *   acquisition request and later execution observation must bind.
 * @param {{field:string}} [opts.caidSelector] CAID field required by the
 *   acquisition contract. CAID identifies content; it never grants authority.
 * @param {object} [opts.quorumPolicy] relying-party-pinned organizational quorum rule
 * @param {Record<string, any>} [opts.approverKeys] pinned approver keys (assurance eval).
 * @param {Record<string, any>} [opts.approver_keys] snake_case alias of approverKeys.
 * @param {(receipt:any, requiredTier:string, ctx:any)=>any} [opts.verifyAssurance]
 *   optional override for assurance evaluation.
 * @param {string} [opts.rpId] expected WebAuthn RP ID for Class-A assurance checks.
 * @param {string[]} [opts.allowedOrigins] allowed WebAuthn origins for Class-A checks.
 * @param {{reserve:(id:string)=>Promise<boolean>|boolean,
 *   commit:(id:string)=>Promise<boolean>|boolean,
 *   release:(id:string)=>Promise<boolean>|boolean}} [opts.store]
 *   Atomic ownership-fenced consumption store; defaults to process-local memory.
 *   Fleet stores MUST make reserve() an atomic insert-if-absent and MUST leave an
 *   uncertain reservation closed until operator reconciliation.
 */
export declare function makeReceiptGate(opts?: AnyRecord): {
    check: (receipt: AnyRecord | null | undefined, { target, observedAction, }?: {
        target?: any;
        observedAction?: AnyRecord;
    }) => Promise<{
        ok: boolean;
        status: any;
        body: {
            type: string;
            title: string;
            status: any;
            detail: string;
            required: {
                action: string | null;
                action_hash: any;
                manifest: any;
                status: any;
                challenge_header: string;
                proof_header: any;
                header: string;
                acceptable_issuers: any;
                assurance_class: any;
                quorum: any;
                max_age_sec: any;
                authorization: {
                    authorization_endpoint: string;
                    flow: typeof import("./acquisition.js").EP_APPROVAL_FLOW;
                } | null;
                required_fields: string[] | null;
                caid_selector: {
                    field: string;
                } | null;
                how: string;
                learn_more: string;
            };
        };
        receiptId?: undefined;
        outcome?: undefined;
        signer?: undefined;
        subject?: undefined;
        boundAction?: undefined;
    } | {
        ok: boolean;
        receiptId: string;
        outcome: any;
        signer: string;
        subject: any;
        boundAction: string;
        status?: undefined;
        body?: undefined;
    }>;
    commit: (receiptId: string) => Promise<void>;
    release: (receiptId: string) => Promise<void>;
    run: (receipt: AnyRecord | null | undefined, ctx?: AnyRecord | ((checkResult: AnyRecord) => unknown), fn?: (checkResult: AnyRecord) => unknown) => Promise<{
        ok: boolean;
        status: any;
        body: {
            type: string;
            title: string;
            status: any;
            detail: string;
            required: {
                action: string | null;
                action_hash: any;
                manifest: any;
                status: any;
                challenge_header: string;
                proof_header: any;
                header: string;
                acceptable_issuers: any;
                assurance_class: any;
                quorum: any;
                max_age_sec: any;
                authorization: {
                    authorization_endpoint: string;
                    flow: typeof import("./acquisition.js").EP_APPROVAL_FLOW;
                } | null;
                required_fields: string[] | null;
                caid_selector: {
                    field: string;
                } | null;
                how: string;
                learn_more: string;
            };
        };
        receiptId?: undefined;
        outcome?: undefined;
        signer?: undefined;
        subject?: undefined;
        boundAction?: undefined;
    } | {
        ok: boolean;
        receiptId: string;
        outcome: any;
        signer: string;
        subject: any;
        boundAction: string;
        status?: undefined;
        body?: undefined;
    } | {
        ok: boolean;
        receiptId: string;
        outcome: any;
        signer: string;
        result: unknown;
    }>;
    boundActionFor: (target: any) => string;
};
//# sourceMappingURL=gate.d.ts.map