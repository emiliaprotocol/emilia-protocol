// SPDX-License-Identifier: Apache-2.0
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

import { isCanonicalizable } from '../require-receipt/index.js';
import { makeReceiptGate } from '../require-receipt/gate.js';
import { strictJsonGate } from '../require-receipt/strict-json.js';

const DEFAULT_GATE = 'https://www.emiliaprotocol.ai/api/trust/gate';

const receiptStates = new Map();
const processLocalStore = {
  ownershipFenced: true,
  async reserve(id) {
    if (receiptStates.has(id)) return false;
    receiptStates.set(id, 'reserved');
    return true;
  },
  async commit(id) {
    if (receiptStates.get(id) !== 'reserved') throw new Error('reservation_not_owned');
    receiptStates.set(id, 'committed');
    return true;
  },
  async release(id) {
    if (receiptStates.get(id) !== 'reserved') throw new Error('reservation_not_owned');
    receiptStates.delete(id);
    return true;
  },
};

export function _resetConsumed() {
  receiptStates.clear();
}

function denyResult(reason, raw = {}) {
  return { allow: false, deny: true, signoffRequired: false, decision: 'deny', reason, raw };
}

function normalizedHttpsEndpoint(value, allowInsecureHttp = false) {
  const endpoint = new URL(value);
  if (!['https:', 'http:'].includes(endpoint.protocol)
      || endpoint.username || endpoint.password || endpoint.hash) {
    throw new Error('invalid_gate_url');
  }
  const host = endpoint.hostname.replace(/\.$/, '').toLowerCase();
  const loopback = host === 'localhost' || host.endsWith('.localhost')
    || host === '127.0.0.1' || host === '::1';
  if (endpoint.protocol === 'http:' && !loopback && allowInsecureHttp !== true) {
    throw new Error('insecure_gate_url');
  }
  return endpoint.toString();
}

function snapshotJson(value) {
  if (!isCanonicalizable(value)) throw new Error('action_binding_invalid');
  return JSON.parse(JSON.stringify(value));
}

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
export async function guardAction({
  actor,
  entityId,
  action,
  context = {},
  apiKey,
  gateUrl = DEFAULT_GATE,
  fetchImpl,
  allowInsecureHttp = false,
} = {}) {
  if (!action) throw new Error('guardAction: `action` is required');
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) throw new Error('guardAction: no fetch implementation available; pass { fetchImpl }');

  if (!apiKey) return denyResult('api_key_required');
  const entity_id = entityId || actor;
  if (typeof entity_id !== 'string' || !entity_id) return denyResult('entity_id_required');

  let endpoint;
  try {
    endpoint = normalizedHttpsEndpoint(gateUrl, allowInsecureHttp);
  } catch (error) {
    return denyResult(error.message || 'invalid_gate_url');
  }

  const headers = { 'content-type': 'application/json' };
  headers.authorization = `Bearer ${apiKey}`;

  let res;
  let raw;
  try {
    res = await doFetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        entity_id,
        action,
        ...(context && typeof context === 'object' && !Array.isArray(context) ? context : {}),
      }),
    });
    raw = await res.json().catch(() => null);
  } catch {
    return denyResult('gate_unavailable');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return denyResult('malformed_gate_response');

  const decision = String(raw.decision || raw.verdict || '');
  const signoffRequired =
    raw.signoff_required === true
    || decision === 'allow_with_signoff'
    || decision === 'signoff_required'
    || decision === 'review';
  const httpOk = res?.ok === true
    || (res?.ok === undefined && Number.isInteger(res?.status) && res.status >= 200 && res.status < 300);
  const durableCommit = typeof raw.commit_ref === 'string' && raw.commit_ref.length > 0;
  const allow = httpOk && decision === 'allow' && raw.allowed !== false && durableCommit && !signoffRequired;
  const deny = !allow && !signoffRequired;
  return {
    allow,
    deny,
    signoffRequired,
    decision: allow ? 'allow' : signoffRequired ? 'review' : 'deny',
    reason: raw.reason || (!httpOk ? 'gate_unavailable'
      : decision === 'allow' && !durableCommit ? 'durable_commit_required'
        : !signoffRequired ? 'unrecognized_gate_decision' : undefined),
    raw,
  };
}

/**
 * Production path: require a pinned, exact-action receipt before one OpenAI-style
 * tool implementation runs. `actionFor` should include every material argument.
 */
export function requireReceiptForOpenAITool(fn, opts = {}) {
  if (typeof fn !== 'function') throw new TypeError('requireReceiptForOpenAITool: fn must be a function');
  const {
    action,
    actionFor,
    getReceipt = (args, call = {}) => call.receipt ?? args?.__ep?.receipt ?? null,
    store = processLocalStore,
    ...gateOptions
  } = opts;
  if (typeof actionFor !== 'function' && (typeof action !== 'string' || !action)) {
    throw new TypeError('requireReceiptForOpenAITool: provide opts.action or opts.actionFor');
  }
  const gates = new Map();
  const gateFor = (boundAction) => {
    if (!gates.has(boundAction)) {
      gates.set(boundAction, makeReceiptGate({ action: boundAction, store, ...gateOptions }));
    }
    return gates.get(boundAction);
  };

  return async function receiptGuarded(args = {}, call = {}) {
    let snapshot;
    let boundAction;
    try {
      snapshot = snapshotJson(args);
      boundAction = typeof actionFor === 'function' ? actionFor(snapshot, call) : action;
    } catch {
      boundAction = null;
    }
    if (typeof boundAction !== 'string' || !boundAction) {
      throw new Error('EMILIA blocked tool call: action_binding_invalid');
    }
    const receipt = getReceipt(snapshot, call);
    const executionArgs = snapshot && typeof snapshot === 'object' && !Array.isArray(snapshot)
      ? Object.fromEntries(Object.entries(snapshot).filter(([key]) => key !== '__ep'))
      : snapshot;
    const result = await gateFor(boundAction).run(receipt, {}, () => fn(executionArgs));
    if (!result.ok) {
      const reason = result.body?.rejected?.reason || (result.body?.required ? 'receipt_required' : 'refused');
      const error = /** @type {Error & {emilia?: {status:any, reason:any, body:any}}} */ (new Error(`EMILIA blocked "${boundAction}": ${reason}`));
      error.emilia = { status: result.status, reason, body: result.body };
      throw error;
    }
    return result.result;
  };
}

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
export async function guard(action, opts = {}) {
  const spec = typeof action === 'string' ? { action } : { ...(action || {}) };
  const env = typeof process !== 'undefined' && process.env ? process.env : {};
  const d = await guardAction({
    action: spec.action,
    actor: spec.actor ?? opts.actor,
    entityId: spec.entityId ?? spec.entity_id ?? opts.entityId ?? opts.entity_id,
    context: spec.context ?? opts.context,
    apiKey: opts.apiKey ?? spec.apiKey ?? env.EP_API_KEY,
    gateUrl: opts.gateUrl ?? spec.gateUrl,
    fetchImpl: opts.fetchImpl ?? spec.fetchImpl,
    allowInsecureHttp: opts.allowInsecureHttp ?? spec.allowInsecureHttp,
  });
  return {
    allowed: d.allow,
    reason: d.reason ?? (d.deny ? 'denied by policy' : d.signoffRequired ? 'human signoff required' : undefined),
    decision: d.decision,
    signoffRequired: d.signoffRequired,
    raw: d.raw,
  };
}

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
export function withGuard(fn, opts = {}) {
  if (typeof fn !== 'function') throw new Error('withGuard: first argument must be your tool function');
  const { action, actor, entityId, context, onSignoff, apiKey, gateUrl, fetchImpl, allowInsecureHttp } = opts;
  if (!action) throw new Error('withGuard: opts.action is required');

  return async function guarded(args = {}) {
    let snapshot;
    try { snapshot = snapshotJson(args); }
    catch { throw new Error('EMILIA blocked tool call: action_binding_invalid'); }
    const decision = await guardAction({
      actor: actor || fn.name || 'openai-agent',
      entityId,
      action,
      context: typeof context === 'function' ? context(snapshot) : context || { args: snapshot },
      apiKey,
      gateUrl,
      fetchImpl,
      allowInsecureHttp,
    });
    if (decision.deny) {
      throw new Error(`EMILIA blocked "${action}"${decision.reason ? `: ${decision.reason}` : ''}`);
    }
    if (decision.signoffRequired) {
      if (typeof onSignoff === 'function') {
        const signoff = await onSignoff(decision, snapshot);
        if (signoff?.approved !== true) throw new Error(`EMILIA did not receive explicit signoff for "${action}"`);
      } else {
        throw new Error(`EMILIA requires human signoff for "${action}" before it can run`);
      }
    }
    return fn(snapshot);
  };
}

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
export async function runToolCalls(toolCalls = [], tools = {}, opts = {}) {
  /** @type {Array<{role:'tool', tool_call_id:string, name:string, content:string}>} */
  const out = [];
  for (const tc of toolCalls) {
    const name = tc.function?.name;
    let args = {};
    const rawArgs = tc.function?.arguments || '{}';
    const parseGate = strictJsonGate(rawArgs);
    const parsed = parseGate.ok;
    if (parsed) args = JSON.parse(rawArgs);

    const t = tools[name];
    let content;
    if (!parsed) {
      content = { error: 'tool arguments refused: invalid or duplicate-member JSON' };
    } else if (!t || typeof t.fn !== 'function') {
      content = { error: `no handler registered for tool "${name}"` };
    } else if (t.readOnly === true) {
      content = await t.fn(snapshotJson(args));
    } else if (!t.action && typeof t.actionFor !== 'function') {
      content = { error: `tool "${name}" is not explicitly read-only and has no action binding` };
    } else {
      try {
        const receipts = opts.receipts;
        const receipt = receipts instanceof Map
          ? (receipts.get(tc.id) ?? receipts.get(name))
          : receipts && typeof receipts === 'object'
            ? (Object.hasOwn(receipts, tc.id) ? receipts[tc.id] : receipts[name])
            : null;
        const guarded = requireReceiptForOpenAITool(t.fn, {
          ...opts,
          action: t.action,
          actionFor: t.actionFor,
          getReceipt: () => receipt,
        });
        content = await guarded(args, { toolCall: tc, receipt });
      } catch (e) {
        content = { error: e.message };
      }
    }
    out.push({
      role: 'tool',
      tool_call_id: tc.id,
      name,
      content: typeof content === 'string' ? content : JSON.stringify(content),
    });
  }
  return out;
}

export default { guard, guardAction, requireReceiptForOpenAITool, withGuard, runToolCalls };
