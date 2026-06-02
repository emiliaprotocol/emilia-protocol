/**
 * @emilia-protocol/langchain — guard LangChain.js tools with EMILIA Protocol.
 * @license Apache-2.0
 *
 * Wrap any LangChain tool so a high-risk call routes through the EMILIA trust
 * gate before it executes. On `deny` it throws; on `signoff_required` it waits
 * for your `onSignoff` handler (or throws if none); otherwise it proceeds.
 *
 * Zero hard dependencies — uses global fetch and a thin Proxy, so it works with
 * StructuredTool, DynamicStructuredTool, or any object exposing `.invoke()`.
 */

const DEFAULT_GATE = 'https://www.emiliaprotocol.ai/api/trust/gate';

/**
 * Ask EMILIA whether an action may proceed.
 * @param {object} opts
 * @param {string} opts.action canonical action, e.g. 'payment.release'
 * @param {string} [opts.actor]
 * @param {object} [opts.context]
 * @param {string} [opts.gateUrl]
 * @param {typeof fetch} [opts.fetchImpl]
 * @returns {Promise<{allow:boolean, deny:boolean, signoffRequired:boolean, reason?:string, raw:object}>}
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

/**
 * Wrap a LangChain tool so every `.invoke()` is gated by EMILIA first.
 * Preserves the tool's identity, name, description, and schema.
 *
 * @template T
 * @param {T} tool a tool exposing `.invoke(input)`
 * @param {object} opts
 * @param {string} opts.action canonical action name (required)
 * @param {string} [opts.actor] defaults to the tool's name
 * @param {(input:any)=>object|object} [opts.context] static context or a deriver
 * @param {(decision:object, input:any)=>Promise<void>} [opts.onSignoff] resolve once a human approves
 * @param {string} [opts.gateUrl]
 * @param {typeof fetch} [opts.fetchImpl]
 * @returns {T}
 */
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

export default { guardAction, withGuard };
