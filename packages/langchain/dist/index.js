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
// Monorepo: import the sibling package by relative path (same convention as
// @emilia-protocol/openai-agents and @emilia-protocol/gate). When installed from
// npm, the published build resolves the bare "@emilia-protocol/require-receipt"
// specifier; both point at the same canonical makeReceiptGate.
import { makeReceiptGate } from '../../require-receipt/gate.js';
import { bindToolAction, snapshotToolArguments } from '../../require-receipt/index.js';
// ── (1) Offline receipt gate — the recommended path ──────────────────────────
/** Process-local atomic receipt state shared across gates in this process. */
const consumed = new Map();
const sharedStore = {
    ownershipFenced: true,
    async reserve(id) {
        if (consumed.has(id))
            return false;
        consumed.set(id, 'reserved');
        return true;
    },
    async commit(id) {
        if (consumed.get(id) !== 'reserved')
            throw new Error('reservation_not_owned');
        consumed.set(id, 'committed');
        return true;
    },
    async release(id) {
        if (consumed.get(id) !== 'reserved')
            throw new Error('reservation_not_owned');
        consumed.delete(id);
        return true;
    },
};
/** Reset consumed receipts. Test/ops helper — not a production control. */
export function _resetConsumed() {
    consumed.clear();
}
/**
 * Pull the receipt a caller attached to this tool invocation. The receipt is
 * out-of-band call metadata, so by default we read it from the LangChain
 * RunnableConfig (`config.configurable.emiliaReceipt`) and fall back to the
 * input object. Override with opts.getReceipt(input, config) for custom transport.
 */
function defaultGetReceipt(input, config) {
    const fromConfig = config?.configurable?.emiliaReceipt ??
        config?.configurable?.emilia_receipt;
    if (fromConfig != null)
        return fromConfig;
    if (input && typeof input === 'object') {
        return input.emiliaReceipt ?? input.emilia_receipt ?? null;
    }
    return null;
}
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
export function requireReceiptForLangChainTool(tool, opts = {}) {
    const { action, actionFor, trustedKeys = [], allowInlineKey = false, maxAgeSec = 900, getReceipt = defaultGetReceipt, store = sharedStore, ...gateOptions } = opts;
    if (typeof actionFor !== 'function' && (typeof action !== 'string' || !action)) {
        throw new TypeError('requireReceiptForLangChainTool: provide opts.action (string) or opts.actionFor (input)=>action_type');
    }
    const originalInvoke = typeof tool?.invoke === 'function' ? tool.invoke : null;
    if (!originalInvoke) {
        throw new Error('requireReceiptForLangChainTool: tool must expose an .invoke(input, config) method');
    }
    // Derive the action exactly once per invocation. Evaluating a caller-supplied
    // mapper twice creates a TOCTOU surface if it is stateful or nondeterministic.
    const gates = new Map();
    const gateFor = (boundAction) => {
        if (!gates.has(boundAction)) {
            gates.set(boundAction, makeReceiptGate({
                action: boundAction,
                trustedKeys,
                allowInlineKey,
                maxAgeSec,
                store,
                ...gateOptions,
            }));
        }
        return gates.get(boundAction);
    };
    const gatedInvoke = async (input, config, ...rest) => {
        const receipt = getReceipt(input, config);
        let executionInput;
        try {
            executionInput = snapshotToolArguments(input);
        }
        catch {
            const err = new Error('EMILIA blocked tool call: action_binding_invalid');
            err.emilia = { status: 428, reason: 'action_binding_invalid' };
            throw err;
        }
        /** @type {string | null | undefined} */
        let baseAction = action;
        if (actionFor) {
            try {
                baseAction = actionFor(snapshotToolArguments(executionInput));
            }
            catch {
                baseAction = null;
            }
        }
        let boundAction;
        try {
            if (typeof baseAction !== 'string' || !baseAction)
                throw new TypeError('action_binding_invalid');
            boundAction = bindToolAction(tool?.name || 'langchain.tool', executionInput, baseAction);
        }
        catch {
            const err = new Error('EMILIA blocked tool call: action_binding_invalid');
            err.emilia = { status: 428, reason: 'action_binding_invalid' };
            throw err;
        }
        const gate = gateFor(boundAction);
        const r = await gate.run(receipt, {}, async () => originalInvoke.call(tool, executionInput, config, ...rest));
        if (!r.ok) {
            const reason = r.body?.rejected?.reason || (r.body?.required ? 'receipt_required' : 'refused');
            const err = new Error(`EMILIA blocked "${boundAction}": ${reason}`);
            err.emilia = { status: r.status, reason, body: r.body };
            throw err;
        }
        return r.result;
    };
    return new Proxy(tool, {
        get(t, prop, receiver) {
            if (prop === 'invoke')
                return gatedInvoke;
            const value = Reflect.get(t, prop, receiver);
            return typeof value === 'function' ? value.bind(t) : value;
        },
    });
}
/** Lower-level: get the underlying makeReceiptGate for advanced orchestration. */
export function makeLangChainReceiptGate(opts = {}) {
    const { action, actionFor, toolName, input, store = sharedStore, ...gateOptions } = opts;
    if (typeof actionFor !== 'function' && (typeof action !== 'string' || !action)) {
        throw new TypeError('makeLangChainReceiptGate: provide opts.action or opts.actionFor');
    }
    if (typeof toolName !== 'string' || !toolName || !Object.prototype.hasOwnProperty.call(opts, 'input')) {
        throw new TypeError('makeLangChainReceiptGate: opts.toolName and opts.input are required for exact binding');
    }
    const baseAction = typeof actionFor === 'function' ? actionFor(input) : action;
    const boundAction = bindToolAction(toolName, input, baseAction);
    return makeReceiptGate({ action: boundAction, ...gateOptions, store });
}
// ── (2) Legacy hosted policy gate — kept for back-compat ─────────────────────
const DEFAULT_GATE = 'https://www.emiliaprotocol.ai/api/trust/gate';
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
export async function guardAction({ actor, action, context = {}, gateUrl = DEFAULT_GATE, fetchImpl } = {}) {
    if (!action)
        throw new Error('guardAction: `action` is required');
    const doFetch = fetchImpl || globalThis.fetch;
    if (!doFetch)
        throw new Error('guardAction: no fetch implementation available; pass { fetchImpl }');
    let res;
    let raw;
    try {
        res = await doFetch(gateUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ actor, action, context }),
        });
        raw = await res.json().catch(() => ({}));
    }
    catch {
        return { allow: false, deny: true, signoffRequired: false, reason: 'gate_unavailable', raw: {} };
    }
    const decision = String(raw.decision || raw.verdict || '');
    const httpOk = res?.ok === true
        || (res?.ok === undefined && Number.isInteger(res?.status) && res.status >= 200 && res.status < 300);
    const signoffRequired = raw.signoff_required === true
        || decision === 'allow_with_signoff'
        || decision === 'signoff_required'
        || decision === 'review';
    const allow = httpOk && decision === 'allow' && raw.allowed !== false && !signoffRequired;
    const deny = !allow && !signoffRequired;
    const reason = raw.reason || (!httpOk ? 'gate_unavailable' : (!allow && !signoffRequired ? 'unrecognized_gate_decision' : undefined));
    return { allow, deny, signoffRequired, reason, raw };
}
/**
 * LEGACY hosted-gate wrapper. It is now precheck-only and always refuses
 * execution because a hosted boolean or application callback is not portable,
 * exact-action execution authority. Use requireReceiptForLangChainTool.
 */
export function withGuard(tool, opts = {}) {
    const { action, actor, context, onSignoff, gateUrl, fetchImpl } = opts;
    if (!action)
        throw new Error('withGuard: opts.action is required');
    const originalInvoke = typeof tool?.invoke === 'function' ? tool.invoke : null;
    if (!originalInvoke)
        throw new Error('withGuard: tool must expose an .invoke(input) method');
    const run = async (input, ...rest) => {
        const decision = await guardAction({
            actor: actor || tool?.name || 'langchain-agent',
            action,
            context: typeof context === 'function' ? context(input) : (context || { input }),
            gateUrl,
            fetchImpl,
        });
        if (decision.signoffRequired) {
            if (typeof onSignoff === 'function') {
                try {
                    await onSignoff(decision, input);
                }
                catch { /* notification failure stays closed */ }
            }
            throw new Error(`EMILIA blocked legacy hosted signoff for "${action}": use requireReceiptForLangChainTool with an exact-action receipt`);
        }
        const suffix = decision.reason ? `: ${decision.reason}` : '';
        throw new Error(`EMILIA blocked legacy hosted gate execution for "${action}"${suffix}; use requireReceiptForLangChainTool`);
    };
    return new Proxy(tool, {
        get(target, prop, receiver) {
            if (prop === 'invoke')
                return run;
            const value = Reflect.get(target, prop, receiver);
            return typeof value === 'function' ? value.bind(target) : value;
        },
    });
}
export default {
    requireReceiptForLangChainTool,
    makeLangChainReceiptGate,
    _resetConsumed,
    guardAction,
    withGuard,
};
//# sourceMappingURL=index.js.map