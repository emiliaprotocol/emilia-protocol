// SPDX-License-Identifier: Apache-2.0
/**
 * Machine-checked source map for the explicit formal-to-runtime bridge.
 *
 * This is a coverage binding, not a compiler: the monitor remains reviewed
 * JavaScript and the TLA+ model remains the source of the formal theorem.
 */
export const FORMAL_RUNTIME_BRIDGE_VERSION = 'EP-FORMAL-RUNTIME-BRIDGE-v1';
export const FORMAL_RUNTIME_SPEC = 'formal/ep_handshake.tla';
export const FORMAL_RUNTIME_CONFIG = 'formal/ep_handshake.cfg';
export const FORMAL_RUNTIME_INVARIANT_MAP = Object.freeze([
    Object.freeze({ runtime: 'ConsumeOnceSafety', formal: 'ConsumeOnceSafety', transition: 'consumptionCommitted' }),
    Object.freeze({ runtime: 'WriteBypassSafety', formal: 'WriteBypassSafety', transition: 'beginExecution' }),
    Object.freeze({ runtime: 'SignoffBindingMatch', formal: 'SignoffBindingMatch', transition: 'recordDecision' }),
]);
export default {
    FORMAL_RUNTIME_BRIDGE_VERSION,
    FORMAL_RUNTIME_SPEC,
    FORMAL_RUNTIME_CONFIG,
    FORMAL_RUNTIME_INVARIANT_MAP,
};
//# sourceMappingURL=formal-runtime-map.js.map