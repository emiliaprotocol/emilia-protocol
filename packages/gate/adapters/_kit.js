// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — System-of-Record adapter kit. One enforcement contract shared by
 * every adapter (GitHub, Stripe, Supabase, AWS, ...): map a destructive op to a
 * gate selector + the observed system-of-record fields, run it through
 * gate.run(), and FAIL CLOSED — if the gate refuses, the real client call is
 * never made and we throw EMILIA_RECEIPT_REQUIRED.
 *
 * An op spec is: { selector, observed(params) -> {fields...}, perform(client, params) -> result }.
 * `observed` must return the same material fields the action pack binds, drawn
 * from the call params (the system-of-record facts), so a receipt for resource A
 * cannot authorize a mutation of resource B.
 */
import { hashCanonical } from '../execution-binding.js';

export { hashCanonical };

/** Build an EP-ACTION-RISK-MANIFEST-v0.1 from a frozen action pack (deep-copied). */
export function manifestFromPack(pack, extraActions = []) {
  return {
    '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
    actions: [
      ...pack.map((a) => ({
        ...a,
        match: { ...a.match },
        execution_binding: a.execution_binding
          ? { ...a.execution_binding, required_fields: [...a.execution_binding.required_fields] }
          : undefined,
      })),
      ...extraActions,
    ],
  };
}

/**
 * Create an adapter from a system name + op map.
 * @returns {{ ops:object, OPS:string[], guard:(gate,client,{op,params,receipt})=>Promise<{result,reliance,execution}> }}
 */
export function createAdapter({ system, ops }) {
  if (!system || !ops || typeof ops !== 'object') throw new Error('createAdapter requires { system, ops }');
  const OPS = Object.freeze(Object.keys(ops));

  async function guard(gate, client, { op, params = {}, receipt = null } = {}) {
    if (!gate || typeof gate.run !== 'function') throw new Error(`${system} adapter requires an EMILIA Gate (with .run)`);
    const spec = ops[op];
    if (!spec) throw new Error(`${system} adapter: unknown op "${op}" (expected one of: ${OPS.join(', ')})`);
    const observedAction = spec.observed(params);
    const out = await gate.run({ selector: spec.selector, receipt, observedAction }, () => spec.perform(client, params));
    if (!out.ok) {
      const e = new Error(`EMILIA Gate refused ${system}:${op} — ${out.authorization.reason}`);
      e.code = 'EMILIA_RECEIPT_REQUIRED';
      e.status = out.status;
      e.gate = out.authorization;
      e.challenge = out.body;
      throw e;
    }
    return { result: out.result, reliance: out.packet, execution: out.execution };
  }

  return { ops, OPS, guard };
}

export default { createAdapter, manifestFromPack, hashCanonical };
