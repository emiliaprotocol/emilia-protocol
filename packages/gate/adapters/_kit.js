// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — System-of-Record adapter kit. One enforcement contract shared by
 * every adapter (GitHub, Stripe, Supabase, AWS, ...): map a destructive op to a
 * gate selector + the observed system-of-record fields, run it through
 * gate.run(), and FAIL CLOSED — if the gate refuses, the real client call is
 * never made and we throw EMILIA_RECEIPT_REQUIRED.
 *
 * An op spec is: { selector, observed(params) -> {fields...},
 * actuator?(params, observed) -> {fields...}, perform(client, actuator) -> result }.
 * `observed` must return the same material fields the action pack binds, drawn
 * from the call params (the system-of-record facts), so a receipt for resource A
 * cannot authorize a mutation of resource B.
 */
import { canonicalize, hashCanonical } from '../execution-binding.js';

export { hashCanonical };

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Canonical plain-data snapshot used at the actuator boundary. */
export function canonicalActuatorObject(value) {
  return deepFreeze(JSON.parse(canonicalize(value)));
}

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
        ...(a.business_authorization
          ? { business_authorization: canonicalActuatorObject(a.business_authorization) }
          : {}),
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
    if (!receipt) {
      const refused = await gate.run(
        { selector: spec.selector, receipt: null, observedAction: null },
        () => { throw new Error('unreachable_adapter_effect'); },
      );
      const e = new Error(`EMILIA Gate refused ${system}:${op} — ${refused.authorization.reason}`);
      e.code = 'EMILIA_RECEIPT_REQUIRED';
      e.status = refused.status;
      e.gate = refused.authorization;
      e.challenge = refused.body;
      throw e;
    }
    // Snapshot before any asynchronous verification. Caller-owned params may be
    // mutated while gate.run() awaits evidence/storage; neither the observation
    // nor the eventual provider call may follow that mutable reference.
    const input = canonicalActuatorObject(params);
    const observedAction = canonicalActuatorObject(spec.observed(input));
    // Default to the verified fields only. Operations that need a preimage for a
    // bound digest (SQL, RLS, secret values, queries) must opt in with an explicit
    // actuator() constructor. The unrestricted caller object is never passed.
    const actuator = canonicalActuatorObject(
      typeof spec.actuator === 'function' ? spec.actuator(input, observedAction) : observedAction,
    );
    const out = await gate.run(
      { selector: spec.selector, receipt, observedAction },
      () => spec.perform(client, actuator),
    );
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

export default { createAdapter, manifestFromPack, hashCanonical, canonicalActuatorObject };
