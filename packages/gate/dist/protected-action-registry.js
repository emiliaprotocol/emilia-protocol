// @ts-nocheck
/**
 * Sealed protected-action registry.
 *
 * Applications register reviewed handlers during trusted startup, seal the
 * registry, and then let Gate select the handler from its pinned manifest.
 * Agent-carried action names never participate in handler selection.
 *
 * @license Apache-2.0
 */
import { canonicalizeFiniteJson } from '@emilia-protocol/require-receipt';
export const PROTECTED_ACTION_REGISTRY_VERSION = 'EP-PROTECTED-ACTION-REGISTRY-v1';
const states = new WeakMap();
const ACTION_NAME = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/;
function snapshot(value) {
    return JSON.parse(canonicalizeFiniteJson(value));
}
/** Internal strict-JSON snapshot used to freeze the local adapter selector. */
export function snapshotProtectedActionValue(value) {
    return deepFreeze(snapshot(value));
}
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    for (const child of Object.values(value))
        deepFreeze(child);
    return Object.freeze(value);
}
function stateFor(registry) {
    if (!registry || typeof registry !== 'object')
        return null;
    return states.get(registry) ?? null;
}
/** Create a registry that can be populated only before trusted-startup sealing. */
export function createProtectedActionRegistry() {
    const entries = new Map();
    const state = { sealed: false, entries };
    const registry = Object.freeze({
        register(action, validate, handler) {
            if (state.sealed)
                throw new Error('protected_action_registry_sealed');
            if (typeof action !== 'string' || action.length > 160 || !ACTION_NAME.test(action)) {
                throw new Error('protected_action_name_invalid');
            }
            if (entries.has(action))
                throw new Error('protected_action_duplicate');
            if (typeof validate !== 'function')
                throw new Error('protected_action_validator_invalid');
            if (typeof handler !== 'function')
                throw new Error('protected_action_handler_invalid');
            entries.set(action, Object.freeze({ validate, handler }));
            return registry;
        },
        seal() {
            if (state.sealed)
                throw new Error('protected_action_registry_sealed');
            state.sealed = true;
            return registry;
        },
        describe() {
            return Object.freeze({
                version: PROTECTED_ACTION_REGISTRY_VERSION,
                sealed: state.sealed,
                actions: Object.freeze([...entries.keys()].sort()),
            });
        },
    });
    states.set(registry, state);
    return registry;
}
/**
 * Internal Gate preflight. This is intentionally not re-exported by the
 * package root: public callers can inspect a handler-free manifest, not obtain
 * or redirect handlers.
 */
export function prepareProtectedActionInvocation(registry, action, parameters) {
    const state = stateFor(registry);
    if (!state)
        return Object.freeze({ ok: false, reason: 'protected_action_registry_invalid' });
    if (!state.sealed)
        return Object.freeze({ ok: false, reason: 'protected_action_registry_unsealed' });
    if (typeof action !== 'string' || !state.entries.has(action)) {
        return Object.freeze({ ok: false, reason: 'protected_action_unknown' });
    }
    let frozenParameters;
    try {
        frozenParameters = snapshotProtectedActionValue(parameters);
    }
    catch {
        return Object.freeze({ ok: false, reason: 'protected_action_parameters_invalid' });
    }
    const entry = state.entries.get(action);
    let valid = false;
    try {
        valid = entry.validate(frozenParameters) === true;
    }
    catch {
        valid = false;
    }
    if (!valid)
        return Object.freeze({ ok: false, reason: 'protected_action_parameters_invalid' });
    return Object.freeze({ ok: true, parameters: frozenParameters, handler: entry.handler });
}
//# sourceMappingURL=protected-action-registry.js.map