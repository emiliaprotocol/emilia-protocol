/**
 * @emilia-protocol/langchain — guard LangChain.js tools with EMILIA Protocol.
 * @license Apache-2.0
 *
 * Two ways to gate a LangChain tool:
 *
 *  1. requireReceiptForLangChainTool(tool, { action | actionFor, trustedKeys })
 *     — the RECOMMENDED, offline path. A high-risk tool call runs only when it
 *     arrives with a valid EMILIA authorization receipt (EP-RECEIPT-v1) bound to
 *     the exact action: missing -> refused, valid -> runs, replay -> refused,
 *     forged -> refused (RR-1). Verification is offline Ed25519 over canonical
 *     JSON via @emilia-protocol/require-receipt's makeReceiptGate — zero network,
 *     no vendor in the loop. This is the lane that makes the approval *portable
 *     evidence* an auditor can check without trusting you.
 *
 *  2. guardAction / withGuard — the LEGACY hosted path. Calls a remote policy
 *     gate (POST /api/trust/gate) for an allow/deny/signoff decision. Convenient,
 *     but the decision is the operator's word, not offline-verifiable evidence.
 *     Kept for back-compat; prefer (1) for anything irreversible.
 *
 * Necessary-not-sufficient: the gate composes with — never replaces — the
 * resource owner's own checks.
 *
 * See: draft-schrock-ep-authorization-receipts, draft-schrock-ep-enforcement-point.
 */
type Obj = Record<string, any>;
type Tool = any;
/** Reset consumed receipts. Test/ops helper — not a production control. */
export declare function _resetConsumed(): void;
/**
 * Wrap a LangChain tool so every `.invoke()` requires a valid, action-bound
 * EMILIA receipt before the underlying tool runs. Preserves the tool's identity,
 * name, description, and schema (thin Proxy — works with StructuredTool,
 * DynamicStructuredTool, or anything exposing `.invoke(input, config)`).
 *
 * @template {{invoke?: (input:any, config?:any, ...rest:any[]) => any}} T
 * @param {T} tool a tool exposing `.invoke(input, config?)`
 * @param {object} opts
 * @param {string} [opts.action] canonical action_type the receipt must bind
 *   (use this OR opts.actionFor).
 * @param {(input:any)=>string} [opts.actionFor] derive the bound action_type
 *   from the call input — RECOMMENDED so one receipt can't be reused across
 *   distinct calls (e.g. (input)=>`payment.release:${input.to}`).
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER issuer keys you trust.
 * @param {boolean} [opts.allowInlineKey=false] also accept the receipt's own key
 *   (proves integrity, NOT issuer trust) — demo only.
 * @param {number} [opts.maxAgeSec=900]
 * @param {(input:any, config:any)=>(object|null|undefined)} [opts.getReceipt]
 * @param {{reserve:(id:string)=>Promise<boolean>|boolean,
 *   commit:(id:string)=>Promise<boolean>|boolean,
 *   release:(id:string)=>Promise<boolean>|boolean}} [opts.store]
 * @returns {T}
 */
export declare function requireReceiptForLangChainTool(tool: Tool, opts?: Obj): Tool;
/** Lower-level: get the underlying makeReceiptGate for advanced orchestration. */
export declare function makeLangChainReceiptGate(opts?: Obj): Obj;
/**
 * LEGACY: ask a hosted EMILIA gate whether an action may proceed. The decision
 * is the operator's word, not offline-verifiable evidence — prefer
 * requireReceiptForLangChainTool for irreversible actions.
 * @param {object} [opts]
 * @param {string} [opts.actor]
 * @param {string} [opts.action]
 * @param {object} [opts.context]
 * @param {string} [opts.gateUrl]
 * @param {typeof fetch} [opts.fetchImpl]
 */
export declare function guardAction({ actor, action, context, gateUrl, fetchImpl }?: Obj): Promise<Obj>;
/** LEGACY hosted-gate wrapper. Prefer requireReceiptForLangChainTool. */
export declare function withGuard(tool: Tool, opts?: Obj): Tool;
declare const _default: {
    requireReceiptForLangChainTool: typeof requireReceiptForLangChainTool;
    makeLangChainReceiptGate: typeof makeLangChainReceiptGate;
    _resetConsumed: typeof _resetConsumed;
    guardAction: typeof guardAction;
    withGuard: typeof withGuard;
};
export default _default;
//# sourceMappingURL=index.d.ts.map