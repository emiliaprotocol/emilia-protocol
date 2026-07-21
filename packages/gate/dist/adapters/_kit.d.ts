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
import { hashCanonical } from '../execution-binding.js';
export { hashCanonical };
/** Canonical plain-data snapshot used at the actuator boundary. */
export declare function canonicalActuatorObject(value: any): any;
/** Build an EP-ACTION-RISK-MANIFEST-v0.1 from a frozen action pack (deep-copied). */
export declare function manifestFromPack(pack: any, extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
/**
 * Create an adapter from a system name + op map.
 * @returns {{ ops:object, OPS:readonly string[], guard:(gate,client,{op,params,receipt})=>Promise<{result,reliance,execution}> }}
 */
export declare function createAdapter({ system, ops }: {
    system: any;
    ops: any;
}): {
    ops: any;
    OPS: readonly string[];
    guard: (gate: any, client: any, { op, params, receipt }?: {
        op?: string;
        params?: object;
        receipt?: any;
    }) => Promise<{
        result: any;
        reliance: any;
        execution: any;
    }>;
};
declare const _default: {
    createAdapter: typeof createAdapter;
    manifestFromPack: typeof manifestFromPack;
    hashCanonical: typeof hashCanonical;
    canonicalActuatorObject: typeof canonicalActuatorObject;
};
export default _default;
//# sourceMappingURL=_kit.d.ts.map