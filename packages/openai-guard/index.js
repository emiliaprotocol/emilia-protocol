// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/openai-guard — guard OpenAI-compatible tool calls with EMILIA.
 *
 * Works with ANY OpenAI-style tool-calling API (OpenAI, xAI Grok, Together,
 * Fireworks, Groq, …). Before an irreversible tool call executes, it routes
 * through the EMILIA trust gate:
 *   allow → run · deny → throw · signoff_required → wait for a named human, then run.
 *
 * Zero dependencies — global fetch only. Mirrors @emilia-protocol/langchain.
 */

const DEFAULT_GATE = 'https://www.emiliaprotocol.ai/api/trust/gate';

/**
 * Ask EMILIA whether an action may proceed.
 * @returns {Promise<{allow:boolean, deny:boolean, signoffRequired:boolean, decision:string, reason?:string, raw:object}>}
 */
export async function guardAction({ actor, action, context = {}, apiKey, gateUrl = DEFAULT_GATE, fetchImpl } = {}) {
  if (!action) throw new Error('guardAction: `action` is required');
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) throw new Error('guardAction: no fetch implementation available; pass { fetchImpl }');

  const headers = { 'content-type': 'application/json' };
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;

  const res = await doFetch(gateUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ actor, action, context }),
  });
  const raw = await res.json().catch(() => ({}));

  const decision = String(raw.decision || raw.verdict || '');
  const deny = decision === 'deny' || raw.allowed === false;
  const signoffRequired =
    raw.signoff_required === true || decision === 'allow_with_signoff' || decision === 'signoff_required';
  return {
    allow: !deny && !signoffRequired,
    deny,
    signoffRequired,
    decision: decision || (deny ? 'deny' : signoffRequired ? 'allow_with_signoff' : 'allow'),
    reason: raw.reason,
    raw,
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
    context: spec.context ?? opts.context,
    apiKey: opts.apiKey ?? spec.apiKey ?? env.EP_API_KEY,
    gateUrl: opts.gateUrl ?? spec.gateUrl,
    fetchImpl: opts.fetchImpl ?? spec.fetchImpl,
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
 * @param {string} opts.action               canonical EMILIA action (required), e.g. 'payment.release'
 * @param {string} [opts.actor]              defaults to fn.name
 * @param {(args:any)=>object|object} [opts.context]
 * @param {(decision:object, args:any)=>Promise<boolean|void>} [opts.onSignoff]  return false to reject
 * @param {string} [opts.apiKey]             EP API key (Authorization: Bearer …)
 * @param {string} [opts.gateUrl]
 * @param {typeof fetch} [opts.fetchImpl]
 * @returns {(args:any)=>Promise<any>} a guarded function
 */
export function withGuard(fn, opts = {}) {
  if (typeof fn !== 'function') throw new Error('withGuard: first argument must be your tool function');
  const { action, actor, context, onSignoff, apiKey, gateUrl, fetchImpl } = opts;
  if (!action) throw new Error('withGuard: opts.action is required');

  return async function guarded(args = {}) {
    const decision = await guardAction({
      actor: actor || fn.name || 'openai-agent',
      action,
      context: typeof context === 'function' ? context(args) : context || { args },
      apiKey,
      gateUrl,
      fetchImpl,
    });
    if (decision.deny) {
      throw new Error(`EMILIA blocked "${action}"${decision.reason ? `: ${decision.reason}` : ''}`);
    }
    if (decision.signoffRequired) {
      if (typeof onSignoff === 'function') {
        const ok = await onSignoff(decision, args);
        if (ok === false) throw new Error(`EMILIA: human signoff declined for "${action}"`);
      } else {
        throw new Error(`EMILIA requires human signoff for "${action}" before it can run`);
      }
    }
    return fn(args);
  };
}

/**
 * Run a model's tool_calls through EMILIA and return tool-result messages you
 * can feed straight back to the model.
 *
 * @param {Array} toolCalls  `message.tool_calls` from an OpenAI-compatible response
 * @param {Record<string, {fn:Function, action?:string, context?:Function}>} tools
 *        map of toolName → { fn (impl), action (omit = read-only/ungated), context }
 * @param {object} [opts] { actor, onSignoff, apiKey, gateUrl, fetchImpl }
 * @returns {Promise<Array<{role:'tool', tool_call_id:string, name:string, content:string}>>}
 */
export async function runToolCalls(toolCalls = [], tools = {}, opts = {}) {
  const out = [];
  for (const tc of toolCalls) {
    const name = tc.function?.name;
    let args = {};
    try {
      args = JSON.parse(tc.function?.arguments || '{}');
    } catch {
      /* leave {} */
    }

    const t = tools[name];
    let content;
    if (!t || typeof t.fn !== 'function') {
      content = { error: `no handler registered for tool "${name}"` };
    } else if (!t.action) {
      content = await t.fn(args); // read-only / non-accountable tool — runs freely
    } else {
      try {
        const guarded = withGuard(t.fn, { action: t.action, context: t.context, ...opts });
        content = await guarded(args);
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

export default { guard, guardAction, withGuard, runToolCalls };
