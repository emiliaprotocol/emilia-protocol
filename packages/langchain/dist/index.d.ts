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
 *  2. guardAction / withGuard — the LEGACY hosted precheck path. It can inspect
 *     a remote policy decision, but withGuard always refuses execution because
 *     a hosted boolean or callback is not exact-action authority. Kept only for
 *     migration compatibility; use (1) for execution.
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
 * @param {string} [opts.action] canonical base action_type. The wrapper always
 *   adds a digest of the actual tool name and complete executor-side input.
 * @param {(input:any)=>string} [opts.actionFor] derive the base action_type from
 *   the call input. Exact input binding remains automatic and cannot be disabled.
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
/**
 * LEGACY hosted-gate wrapper. It is now precheck-only and always refuses
 * execution because a hosted boolean or application callback is not portable,
 * exact-action execution authority. Use requireReceiptForLangChainTool.
 */
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