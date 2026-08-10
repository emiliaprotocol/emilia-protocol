// SPDX-License-Identifier: Apache-2.0
/**
 * Optional OAuth/RAR profile for EP-AUTHORIZATION-BUNDLE-v1.
 *
 * This module validates and compares the closed projection carried in an
 * Authorization Context. It does not validate an OAuth token, signed
 * transaction challenge, delegation, workload identity, or RAR semantics.
 * Callers must derive `expected` from those natively verified inputs first.
 */
import { canonicalizeAeb } from './aeb-adapter-contract.js';
export const OAUTH_RAR_AUTHORIZATION_BINDING_VERSION = 'EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1';
const REQUIRED_KEYS = new Set([
    'profile',
    'authorization_server',
    'transaction_id',
    'actor',
    'authorization_details_digest',
    'action_mapping_profile',
]);
const ALLOWED_KEYS = new Set([...REQUIRED_KEYS, 'delegated_subject']);
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
function dataRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return null;
    try {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null)
            return null;
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const keys = Reflect.ownKeys(descriptors);
        if (keys.some((key) => typeof key !== 'string'))
            return null;
        const record = {};
        for (const key of keys) {
            const descriptor = descriptors[key];
            if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))
                return null;
            record[key] = descriptor.value;
        }
        return record;
    }
    catch {
        return null;
    }
}
function nonEmptyString(value) {
    return typeof value === 'string'
        && value.length > 0
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function absoluteUri(value) {
    if (!nonEmptyString(value))
        return false;
    try {
        return new URL(value).protocol.length > 1;
    }
    catch {
        return false;
    }
}
/** Return a safe normalized copy of the closed OAuth/RAR projection. */
export function parseOAuthRarAuthorizationBinding(value) {
    const record = dataRecord(value);
    if (!record)
        return null;
    const keys = Object.keys(record);
    if (!keys.every((key) => ALLOWED_KEYS.has(key))
        || ![...REQUIRED_KEYS].every((key) => Object.hasOwn(record, key))
        || record.profile !== OAUTH_RAR_AUTHORIZATION_BINDING_VERSION
        || !absoluteUri(record.authorization_server)
        || !nonEmptyString(record.transaction_id)
        || !nonEmptyString(record.actor)
        || !absoluteUri(record.action_mapping_profile)
        || typeof record.authorization_details_digest !== 'string'
        || !DIGEST_RE.test(record.authorization_details_digest)
        || (record.delegated_subject !== undefined
            && !nonEmptyString(record.delegated_subject))) {
        return null;
    }
    const normalized = {
        profile: OAUTH_RAR_AUTHORIZATION_BINDING_VERSION,
        authorization_server: record.authorization_server,
        transaction_id: record.transaction_id,
        actor: record.actor,
        authorization_details_digest: record.authorization_details_digest,
        action_mapping_profile: record.action_mapping_profile,
    };
    if (record.delegated_subject !== undefined) {
        normalized.delegated_subject = record.delegated_subject;
    }
    return normalized;
}
/**
 * Compare a presented projection with one independently derived from a
 * natively verified OAuth/RAR transaction. Missing or malformed expected input
 * is indeterminate; malformed presented input and unequal projections are hard
 * mismatches.
 */
export function matchOAuthRarAuthorizationBinding(presented, expected) {
    const actual = parseOAuthRarAuthorizationBinding(presented);
    if (!actual) {
        return { verdict: 'MISMATCH', binding: null, reason: 'oauth_rar_binding_malformed' };
    }
    const independentlyDerived = parseOAuthRarAuthorizationBinding(expected);
    if (!independentlyDerived) {
        return {
            verdict: 'INDETERMINATE',
            binding: null,
            reason: 'native_oauth_rar_binding_unavailable',
        };
    }
    try {
        if (canonicalizeAeb(actual) !== canonicalizeAeb(independentlyDerived)) {
            return { verdict: 'MISMATCH', binding: null, reason: 'oauth_rar_binding_mismatch' };
        }
    }
    catch {
        return { verdict: 'MISMATCH', binding: null, reason: 'oauth_rar_binding_malformed' };
    }
    return { verdict: 'MATCH', binding: independentlyDerived, reason: null };
}
export default Object.freeze({
    OAUTH_RAR_AUTHORIZATION_BINDING_VERSION,
    parseOAuthRarAuthorizationBinding,
    matchOAuthRarAuthorizationBinding,
});
//# sourceMappingURL=oauth-rar-authorization-binding.js.map