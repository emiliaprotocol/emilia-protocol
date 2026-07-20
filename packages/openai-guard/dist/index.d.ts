/**
 * @emilia-protocol/openai-guard — guard OpenAI-compatible tool calls with EMILIA.
 *
 * Works with ANY OpenAI-style tool-calling API (OpenAI, xAI Grok, Together,
 * Fireworks, Groq, …). Before an irreversible tool call executes, it routes
 * through the EMILIA trust gate:
 *   allow → run · deny → throw · signoff_required → wait for a named human, then run.
 *
 * The offline receipt path is the production default. The hosted policy client
 * remains for compatibility and accepts only an explicit, durable allow.
 */
type AnyRecord = Record<string, any>;
type ToolFunction = (...args: any[]) => any;
export declare function _resetConsumed(): void;
/**
 * Ask EMILIA whether an action may proceed.
 * @param {object} [opts]
 * @param {string} [opts.actor]
 * @param {string} [opts.entityId]
 * @param {string} [opts.action]
 * @param {object} [opts.context]
 * @param {string} [opts.apiKey]
 * @param {string} [opts.gateUrl]
 * @param {typeof fetch} [opts.fetchImpl]
 * @param {boolean} [opts.allowInsecureHttp]
 * @returns {Promise<{allow:boolean, deny:boolean, signoffRequired:boolean, decision:string, reason?:string, raw:object}>}
 */
export declare function guardAction({ actor, entityId, action, context, apiKey, gateUrl, fetchImpl, allowInsecureHttp, }?: AnyRecord): Promise<AnyRecord>;
/**
 * Production path: require a pinned, exact-action receipt before one OpenAI-style
 * tool implementation runs. `actionFor` should include every material argument.
 */
export declare function requireReceiptForOpenAITool(fn: ToolFunction, opts?: AnyRecord): ToolFunction;
/**
 * The simplest possible gate. `await guard(action)` → `{ allowed, reason }`.
 *
 * `action` is a canonical action string ('payment.release') or an object
 * { action, context, actor }. Reads EP_API_KEY from the environment by default.
 *
 *   import { guard } from '@emilia-protocol/openai-guard';
 *   const result = await guard('payment.release');
 *   if (!result.allowed) return result.reason;
 *
 * @returns {Promise<{allowed:boolean, reason?:string, decision:string, signoffRequired:boolean, raw:object}>}
 */
export declare function guard(action: string | AnyRecord, opts?: AnyRecord): Promise<AnyRecord>;
/**
 * Wrap a single tool implementation so it routes through EMILIA before running.
 *
 * @param {Function} fn   your async tool implementation: (args) => result
 * @param {object} opts
 * @param {string} [opts.action]             canonical EMILIA action (required), e.g. 'payment.release'
 * @param {string} [opts.actor]              defaults to fn.name
 * @param {string} [opts.entityId]
 * @param {(args:any)=>object|object} [opts.context]
 * @param {(decision:object, args:any)=>Promise<{approved:true}>} [opts.onSignoff]
 * @param {string} [opts.apiKey]             EP API key (Authorization: Bearer …)
 * @param {string} [opts.gateUrl]
 * @param {typeof fetch} [opts.fetchImpl]
 * @param {boolean} [opts.allowInsecureHttp]
 * @returns {(args:any)=>Promise<any>} a guarded function
 */
export declare function withGuard(fn: ToolFunction, opts?: AnyRecord): ToolFunction;
/**
 * Run a model's tool_calls through EMILIA and return tool-result messages you
 * can feed straight back to the model.
 *
 * @param {Array} toolCalls  `message.tool_calls` from an OpenAI-compatible response
 * @param {Record<string, {fn:Function, action?:string, actionFor?:Function, context?:Function, readOnly?:boolean}>} tools
 *        map of toolName → { fn, action|actionFor } or { fn, readOnly:true }
 * @param {object} [opts] receipt-gate options plus receipts keyed by call id/name
 * @returns {Promise<Array<{role:'tool', tool_call_id:string, name:string, content:string}>>}
 */
export declare function runToolCalls(toolCalls?: any[], tools?: AnyRecord, opts?: AnyRecord): Promise<any[]>;
declare const _default: {
    guard: typeof guard;
    guardAction: typeof guardAction;
    requireReceiptForOpenAITool: typeof requireReceiptForOpenAITool;
    withGuard: typeof withGuard;
    runToolCalls: typeof runToolCalls;
};
export default _default;
//# sourceMappingURL=index.d.ts.map