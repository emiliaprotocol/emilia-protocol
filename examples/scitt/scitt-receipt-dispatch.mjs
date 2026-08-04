// SPDX-License-Identifier: Apache-2.0
// Generated from scitt-receipt-dispatch.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// RFC 9942 receipt-profile dispatch boundary.
//
// This module deliberately does not pretend that one generic verifier can
// verify every Verifiable Data Structure. It reads the protected `vds` header
// and invokes only the relying-party-pinned native verifier for that profile.
// Unsupported profiles remain INDETERMINATE; malformed Receipts fail.
import { decodeCbor } from './ep-receipt-scitt-conformance.mjs';
export const SCITT_VDS = Object.freeze({
    RFC9162_SHA256: 1,
    CCF: 2,
    MMR: 3,
});
function inspectReceiptVds(receipt) {
    const bytes = Buffer.from(receipt);
    let decoded;
    try {
        decoded = decodeCbor(bytes);
    }
    catch {
        return { ok: false, reason: 'malformed_receipt' };
    }
    if (decoded.offset !== bytes.length || decoded.value?.tag !== 18) {
        return { ok: false, reason: 'malformed_receipt' };
    }
    const cose = decoded.value.value;
    if (!Array.isArray(cose) || cose.length !== 4 || !Buffer.isBuffer(cose[0])) {
        return { ok: false, reason: 'malformed_receipt' };
    }
    let protectedHeader;
    try {
        protectedHeader = decodeCbor(cose[0]);
    }
    catch {
        return { ok: false, reason: 'malformed_protected_header' };
    }
    if (!(protectedHeader.value instanceof Map) || protectedHeader.offset !== cose[0].length) {
        return { ok: false, reason: 'malformed_protected_header' };
    }
    const vds = protectedHeader.value.get(395);
    if (!Number.isInteger(vds))
        return { ok: false, reason: 'missing_vds' };
    return { ok: true, vds };
}
/**
 * Dispatch a COSE Receipt to a native profile verifier selected by protected
 * header label 395. Native verifier results are preserved; this layer never
 * upgrades profile verification to AEB satisfaction or Gate authorization.
 */
export function verifyScittReceiptByVds({ receipt, statement, profiles }) {
    const inspected = inspectReceiptVds(receipt);
    if (!inspected.ok) {
        return {
            native_verification: 'FAILED',
            vds: null,
            profile_id: null,
            reasons: [inspected.reason],
        };
    }
    const profile = profiles instanceof Map ? profiles.get(inspected.vds) : undefined;
    if (!profile || typeof profile.id !== 'string' || typeof profile.verify !== 'function') {
        return {
            native_verification: 'INDETERMINATE',
            vds: inspected.vds,
            profile_id: null,
            reasons: ['unsupported_vds'],
        };
    }
    try {
        const native = profile.verify({
            receipt: Buffer.from(receipt),
            statement: Buffer.from(statement),
            vds: inspected.vds,
        });
        if (!native || !['VERIFIED', 'FAILED', 'INDETERMINATE'].includes(native.native_verification)) {
            return {
                native_verification: 'INDETERMINATE',
                vds: inspected.vds,
                profile_id: profile.id,
                reasons: ['invalid_native_verifier_result'],
            };
        }
        return {
            ...native,
            vds: inspected.vds,
            profile_id: profile.id,
            reasons: Array.isArray(native.reasons) ? native.reasons : [],
        };
    }
    catch {
        return {
            native_verification: 'INDETERMINATE',
            vds: inspected.vds,
            profile_id: profile.id,
            reasons: ['native_verifier_error'],
        };
    }
}
export { inspectReceiptVds };
