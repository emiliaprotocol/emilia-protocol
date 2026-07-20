type AnyRecord = Record<string, any>;
type AssuranceTier = 'software' | 'class_a' | 'quorum';
type AssuranceOptions = AnyRecord;
type ChallengeOptions = AnyRecord;
type VerifyOptions = AnyRecord;
type Selector = AnyRecord;
type ReceiptGateOptions = AnyRecord;
export declare const LEGACY_RECEIPT_REQUIRED_STATUS = 402;
export declare const RECEIPT_REQUIRED_STATUS = 428;
export declare const RECEIPT_REQUIRED_HEADER = "Receipt-Required";
export declare const RECEIPT_PROOF_HEADER = "X-EMILIA-Receipt";
export declare const ACTION_RISK_MANIFEST_VERSION = "EP-ACTION-RISK-MANIFEST-v0.1";
export declare const DEFAULT_ACTION_RISK_MANIFEST = "/.well-known/agent-actions.json";
export declare const ASSURANCE_TIERS: string[];
export declare const ASSURANCE_PROOF_VERSION = "EP-ASSURANCE-PROOF-v1";
export declare const MAX_RECEIPT_CARRIER_BYTES: number;
/**
 * Decode an HTTP/MCP receipt carrier without inheriting Buffer's permissive
 * base64 behavior. The bytes must use one canonical alphabet, be valid UTF-8,
 * contain strict JSON (no duplicate member names), and decode to an object.
 */
export declare function parseReceiptCarrier(value: unknown, { maxBytes }?: {
    maxBytes?: number;
}): AnyRecord | null;
/**
 * EP canonicalization profile: JCS over an I-JSON value subset. Signed receipt
 * payloads must contain only strings, booleans, null, arrays, objects, and safe
 * integers. Non-finite numbers, floats, BigInt, undefined, functions, and
 * symbols are rejected before signature verification so implementations never
 * diverge on canonical bytes.
 */
export declare function isCanonicalizable(value: any): boolean;
/**
 * Validate the quorum rule supplied by the relying party. The policy is a trust
 * input, not evidence: a receipt creator's own threshold or roster never
 * establishes the organization's actual two-person rule.
 */
export declare function validatePinnedQuorumPolicy(policy: AnyRecord): AnyRecord;
export declare function receiptAssuranceTier(doc: AnyRecord, opts?: AssuranceOptions): AssuranceTier;
export declare function evaluateReceiptAssurance(doc: AnyRecord, required: string, opts?: AssuranceOptions): AnyRecord;
/** Build the compact Receipt-Required challenge header value for HTTP 428. */
export declare function receiptRequiredHeader(opts?: ChallengeOptions): string;
/**
 * Verify an EP-RECEIPT-v1 document.
 * @param {object} doc the receipt document
 * @param {object} opts
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER public keys you trust as issuers
 * @param {boolean} [opts.allowInlineKey=false] also accept the receipt's own inline key (proves integrity, NOT trust)
 * @param {string|null} [opts.action] require the receipt to be bound to this action_type
 * @param {number} [opts.maxAgeSec=900] reject receipts older than this
 * @param {()=>number} [opts.now=Date.now] trusted clock used for freshness
 * @param {string[]} [opts.allowedOutcomes] acceptable claim.outcome values
 * @returns {{ok:boolean, reason?:string, detail?:string, outcome?:string, subject?:string, receipt_id?:string, signer?:string}}
 */
export declare function verifyEmiliaReceipt(doc: any, opts?: VerifyOptions): {
    ok: boolean;
    reason: string;
    detail?: undefined;
    outcome?: undefined;
    subject?: undefined;
    receipt_id?: undefined;
    signer?: undefined;
} | {
    ok: boolean;
    reason: string;
    detail: string;
    outcome?: undefined;
    subject?: undefined;
    receipt_id?: undefined;
    signer?: undefined;
} | {
    ok: boolean;
    outcome: any;
    subject: any;
    receipt_id: any;
    signer: string;
    reason?: undefined;
    detail?: undefined;
};
/**
 * Build the challenge body that tells an agent exactly what receipt to bring.
 *
 * Backward-compatible default: status 402, matching the original demand loop.
 * New Receipt Required rail: pass `{ status: 428 }` or `{ statusCode: 428 }`.
 */
export declare function receiptChallenge(action: string | null, reason: string, opts?: number | ChallengeOptions): {
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
        how: string;
        learn_more: string;
    };
};
/** Validate a .well-known/agent-actions.json Action Risk Manifest. */
export declare function validateActionRiskManifest(manifest: AnyRecord): {
    ok: boolean;
    errors: string[];
};
/**
 * Find the first manifest entry matching an action selector.
 * Selectors may use { id }, { action_type } / { action }, or protocol fields
 * such as { protocol: 'mcp', tool: 'release_payment' }.
 */
export declare function findActionRequirement(manifest: AnyRecord, selector?: Selector): any;
/**
 * Express/Connect middleware: demand a valid EMILIA receipt for the route.
 * @param {object} opts verify options + { action?: string | (req)=>string, statusCode?: 402|428 }
 */
export declare function requireEmiliaReceipt(opts?: ReceiptGateOptions): (req: AnyRecord, res: AnyRecord, next: () => unknown) => any;
/**
 * Receipt Required conformance harness. Exercises a guarded dispatcher against
 * the four normative behaviors and returns a structured report. The badge is
 * EARNED by passing this — never self-asserted. (Don't trust us; run the check.)
 *
 * Level RR-1 requires all of: a Receipt-Required challenge on a missing receipt,
 * the action running on a valid action-bound receipt, replay of the same receipt
 * refused (one-time consumption), and a forged receipt refused.
 *
 * @param {object} p
 * @param {(name:string, args:object, receipt:object|null)=>Promise<{status:number, body?:object}>} p.dispatch
 * @param {string} p.tool       receipt-required tool/route name to probe
 * @param {object} [p.args]     arguments passed to the tool
 * @param {string} p.action     canonical action_type the receipt must bind
 * @param {(action:string)=>(object|Promise<object>)} p.issueReceipt  mints a FRESH
 *   valid EP-RECEIPT-v1 bound to `action` (passed in) that this dispatcher accepts
 * @param {object} [p.manifest] optional Action Risk Manifest to validate
 * @returns {Promise<{level:string, passed:boolean, checks:object, detail:object}>}
 */
export declare function receiptRequiredConformance({ dispatch, tool, args, action, issueReceipt, manifest }: AnyRecord): Promise<{
    level: string;
    passed: boolean;
    checks: AnyRecord;
    detail: AnyRecord;
}>;
declare const requireReceiptExports: {
    verifyEmiliaReceipt: typeof verifyEmiliaReceipt;
    requireEmiliaReceipt: typeof requireEmiliaReceipt;
    receiptChallenge: typeof receiptChallenge;
    receiptRequiredHeader: typeof receiptRequiredHeader;
    validateActionRiskManifest: typeof validateActionRiskManifest;
    findActionRequirement: typeof findActionRequirement;
    receiptRequiredConformance: typeof receiptRequiredConformance;
};
export default requireReceiptExports;
export { makeReceiptGate } from './gate.js';
export { strictJsonGate } from './strict-json.js';
export { serializeReceiptJws, verifyReceiptJws, deriveKid, JWS_PROFILE_VERSION, JWS_ALG, JWS_TYP, } from './jws.js';
//# sourceMappingURL=index.d.ts.map