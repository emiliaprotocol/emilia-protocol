// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
const verifier = await import('@emilia-protocol/verify');
const { canonicalize, isCanonicalizable } = verifier;
export const MOBILE_ACTION_CAID_TYPE = 'emilia.mobile.authorized-action.1';
export const MOBILE_ACTION_CAID_PATTERN = /^caid:1:emilia\.mobile\.authorized-action\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ACTION_REFERENCE = /^[A-Za-z0-9:_.@-]{8,256}$/;
const DEFINITION = Object.freeze({
    action_type: MOBILE_ACTION_CAID_TYPE,
    status: 'active',
    risk_class: 'external-communication',
    summary: 'Exact authoritative action presented for a device-bound EMILIA decision.',
    required_fields: Object.freeze([
        Object.freeze({ name: 'source_action_type', type: 'string' }),
        Object.freeze({ name: 'source_action_digest', type: 'digest' }),
    ]),
    optional_fields: Object.freeze([]),
    digest_notes: 'The source digest commits the complete authoritative action object.',
    references: Object.freeze([]),
});
function record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function sourceActionType(action) {
    for (const candidate of [action?.action_type, action?.['@type'], action?.type]) {
        if (typeof candidate === 'string'
            && candidate.length > 0
            && [...candidate].length <= 256) {
            return candidate;
        }
    }
    return 'application.action';
}
export function mobileActionFingerprint(actionCaid) {
    if (!MOBILE_ACTION_CAID_PATTERN.test(actionCaid || ''))
        return null;
    try {
        const digest = actionCaid.split(':').at(-1);
        if (!digest)
            return null;
        const hex = Buffer.from(digest, 'base64url').toString('hex').slice(0, 16).toUpperCase();
        if (!/^[0-9A-F]{16}$/.test(hex))
            return null;
        const groups = hex.match(/.{4}/g);
        return groups ? groups.join('-') : null;
    }
    catch {
        return null;
    }
}
export function buildMobileActionIdentity({ actionReference, action, } = {}) {
    if (!ACTION_REFERENCE.test(actionReference || '') || !record(action)) {
        throw new TypeError('a valid action reference and authoritative action object are required');
    }
    if (!isCanonicalizable(action))
        throw new TypeError('action is not canonicalizable');
    const canonical = canonicalize(action);
    const actionDigest = `sha256:${crypto.createHash('sha256')
        .update(canonical, 'utf8').digest('hex')}`;
    const wrapper = {
        action_type: MOBILE_ACTION_CAID_TYPE,
        source_action_type: sourceActionType(action),
        source_action_digest: actionDigest,
    };
    const digestBytes = crypto.createHash('sha256')
        .update(canonicalize(wrapper), 'utf8').digest();
    const actionCaid = `caid:1:${MOBILE_ACTION_CAID_TYPE}:jcs-sha256:${digestBytes.toString('base64url')}`;
    const fingerprint = mobileActionFingerprint(actionCaid);
    if (fingerprint === null)
        throw new TypeError('computed mobile action identity is malformed');
    return Object.freeze({
        action_caid: actionCaid,
        action_digest: actionDigest,
        caid_digest: `sha256:${digestBytes.toString('hex')}`,
        fingerprint,
    });
}
export function verifyMobileActionIdentity({ actionReference, action, actionCaid, actionDigest, } = {}) {
    try {
        const computed = buildMobileActionIdentity({ actionReference, action });
        return {
            valid: computed.action_caid === actionCaid && computed.action_digest === actionDigest,
            computed,
        };
    }
    catch {
        return { valid: false, computed: null };
    }
}
export const _internals = Object.freeze({ DEFINITION });
//# sourceMappingURL=action-identity.js.map