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

// Monorepo: import the sibling package by relative path (same convention as
// @emilia-protocol/openai-agents and @emilia-protocol/gate). When installed from
// npm, the published build resolves the bare "@emilia-protocol/require-receipt"
// specifier; both point at the same canonical makeReceiptGate.
import { makeReceiptGate } from '../require-receipt/gate.js';

// ── (1) Offline receipt gate — the recommended path ──────────────────────────

/** Process-local consumed-receipt store shared across gates in this process, so
 *  one receipt is spent at most once. Pass `store` for a durable/shared store. */
const consumed = new Set();
const sharedStore = { has: (id) => consumed.has(id), add: (id) => consumed.add(id) };

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
  const fromConfig =
    config?.configurable?.emiliaReceipt ??
    config?.configurable?.emilia_receipt;
  if (fromConfig != null) return fromConfig;
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
 * @template T
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
 * @param {{has:(id:string)=>boolean, add:(id:string)=>void}} [opts.store]
 * @returns {T}
 */
export function requireReceiptForLangChainTool(tool, opts = {}) {
  const {
    action,
    actionFor,
    trustedKeys = [],
    allowInlineKey = false,
    maxAgeSec = 900,
    getReceipt = defaultGetReceipt,
    store = sharedStore,
  } = opts;

  if (!action && typeof actionFor !== 'function') {
    throw new TypeError('requireReceiptForLangChainTool: provide opts.action (string) or opts.actionFor (input)=>action_type');
  }
  const originalInvoke = typeof tool?.invoke === 'function' ? tool.invoke : null;
  if (!originalInvoke) {
    throw new Error('requireReceiptForLangChainTool: tool must expose an .invoke(input, config) method');
  }

  // Function action folds the target in itself; string action binds via :target.
  const gate = makeReceiptGate({
    action: actionFor || action,
    trustedKeys,
    allowInlineKey,
    maxAgeSec,
    store,
  });

  const gatedInvoke = async (input, config, ...rest) => {
    const receipt = getReceipt(input, config);
    const target = actionFor ? input : undefined;
    const r = await gate.run(receipt, { target }, async () =>
      originalInvoke.call(tool, input, config, ...rest),
    );
    if (!r.ok) {
      const reason = r.body?.rejected?.reason || (r.body?.required ? 'receipt_required' : 'refused');
      const err = new Error(`EMILIA blocked "${gate.boundActionFor(target)}": ${reason}`);
      err.emilia = { status: r.status, reason, body: r.body };
      throw err;
    }
    return r.result;
  };

  return new Proxy(tool, {
    get(t, prop, receiver) {
      if (prop === 'invoke') return gatedInvoke;
      const value = Reflect.get(t, prop, receiver);
      return typeof value === 'function' ? value.bind(t) : value;
    },
  });
}

/** Lower-level: get the underlying makeReceiptGate for advanced orchestration. */
export function makeLangChainReceiptGate(opts = {}) {
  const { action, actionFor, trustedKeys = [], allowInlineKey = false, maxAgeSec = 900, store = sharedStore } = opts;
  if (!action && typeof actionFor !== 'function') {
    throw new TypeError('makeLangChainReceiptGate: provide opts.action or opts.actionFor');
  }
  return makeReceiptGate({ action: actionFor || action, trustedKeys, allowInlineKey, maxAgeSec, store });
}

// ── (2) Legacy hosted policy gate — kept for back-compat ─────────────────────

const DEFAULT_GATE = 'https://www.emiliaprotocol.ai/api/trust/gate';

/**
 * LEGACY: ask a hosted EMILIA gate whether an action may proceed. The decision
 * is the operator's word, not offline-verifiable evidence — prefer
 * requireReceiptForLangChainTool for irreversible actions.
 */
export async function guardAction({ actor, action, context = {}, gateUrl = DEFAULT_GATE, fetchImpl } = {}) {
  if (!action) throw new Error('guardAction: `action` is required');
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) throw new Error('guardAction: no fetch implementation available; pass { fetchImpl }');

  const res = await doFetch(gateUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ actor, action, context }),
  });
  const raw = await res.json().catch(() => ({}));

  const decision = String(raw.decision || raw.verdict || '');
  const deny = decision === 'deny' || raw.allowed === false;
  const signoffRequired = raw.signoff_required === true
    || decision === 'allow_with_signoff'
    || decision === 'signoff_required';
  const allow = !deny && !signoffRequired;
  return { allow, deny, signoffRequired, reason: raw.reason, raw };
}

/** LEGACY hosted-gate wrapper. Prefer requireReceiptForLangChainTool. */
export function withGuard(tool, opts = {}) {
  const { action, actor, context, onSignoff, gateUrl, fetchImpl } = opts;
  if (!action) throw new Error('withGuard: opts.action is required');

  const originalInvoke = typeof tool?.invoke === 'function' ? tool.invoke : null;
  if (!originalInvoke) throw new Error('withGuard: tool must expose an .invoke(input) method');

  const run = async (input, ...rest) => {
    const decision = await guardAction({
      actor: actor || tool?.name || 'langchain-agent',
      action,
      context: typeof context === 'function' ? context(input) : (context || { input }),
      gateUrl,
      fetchImpl,
    });
    if (decision.deny) {
      throw new Error(`EMILIA blocked action "${action}"${decision.reason ? `: ${decision.reason}` : ''}`);
    }
    if (decision.signoffRequired) {
      if (typeof onSignoff === 'function') await onSignoff(decision, input);
      else throw new Error(`EMILIA requires human signoff for "${action}" before it can run`);
    }
    return originalInvoke.call(tool, input, ...rest);
  };

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === 'invoke') return run;
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
