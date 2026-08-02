// SPDX-License-Identifier: Apache-2.0
// Generated from canonical-json.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { canonicalizeFiniteJson, canonicalizeStrictJson, isStrictCanonicalJson, } from './strict-json.js';
/**
 * Report whether a value is inside the EP I-JSON canonicalization profile.
 * Signed material is limited to strings, booleans, null, arrays, objects, and
 * safe integers so JS/Python/Go cannot serialize the same value differently.
 */
export function isCanonicalizable(value) {
    return isStrictCanonicalJson(value);
}
/**
 * Recursive canonical JSON used for hashes that bind security-sensitive
 * protocol state. Undefined and other out-of-profile values are refused before
 * rendering; otherwise an omitted/empty member could create bytes that the
 * Python and Go implementations cannot reproduce.
 */
export function canonicalize(value) {
    try {
        return canonicalizeStrictJson(value);
    }
    catch (cause) {
        throw new TypeError('value is outside the EP canonicalization profile', { cause });
    }
}
/**
 * Recursive canonical JSON for closed records that intentionally carry finite
 * decimal measurements (for example, policy thresholds). Structural ghost
 * state is still refused; only the safe-integer restriction is relaxed.
 */
export function canonicalizeFinite(value) {
    try {
        return canonicalizeFiniteJson(value);
    }
    catch (cause) {
        throw new TypeError('value is outside the finite EP canonicalization profile', { cause });
    }
}
