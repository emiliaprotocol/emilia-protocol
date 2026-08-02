// SPDX-License-Identifier: Apache-2.0

import {
  canonicalizeFiniteJson,
  canonicalizeStrictJson,
  isStrictCanonicalJson,
} from './strict-json.js';

/**
 * Values admitted by the EP canonicalization profile.
 */
export type CanonicalValue =
  | null
  | string
  | boolean
  | number
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

/**
 * Report whether a value is inside the EP I-JSON canonicalization profile.
 * Signed material is limited to strings, booleans, null, arrays, objects, and
 * safe integers so JS/Python/Go cannot serialize the same value differently.
 */
export function isCanonicalizable(value: unknown): value is CanonicalValue {
  return isStrictCanonicalJson(value);
}

/**
 * Recursive canonical JSON used for hashes that bind security-sensitive
 * protocol state. Undefined and other out-of-profile values are refused before
 * rendering; otherwise an omitted/empty member could create bytes that the
 * Python and Go implementations cannot reproduce.
 */
export function canonicalize(value: unknown): string {
  try {
    return canonicalizeStrictJson(value);
  } catch (cause) {
    throw new TypeError('value is outside the EP canonicalization profile', { cause });
  }
}

/**
 * Recursive canonical JSON for closed records that intentionally carry finite
 * decimal measurements (for example, policy thresholds). Structural ghost
 * state is still refused; only the safe-integer restriction is relaxed.
 */
export function canonicalizeFinite(value: unknown): string {
  try {
    return canonicalizeFiniteJson(value);
  } catch (cause) {
    throw new TypeError('value is outside the finite EP canonicalization profile', { cause });
  }
}
