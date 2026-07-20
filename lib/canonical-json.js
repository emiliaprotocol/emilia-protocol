// SPDX-License-Identifier: Apache-2.0

/**
 * Values admitted by the EP canonicalization profile.
 *
 * @typedef {null | string | boolean | number | unknown[] | Record<string, unknown>} CanonicalValue
 */

/**
 * Report whether a value is inside the EP I-JSON canonicalization profile.
 * Signed material is limited to strings, booleans, null, arrays, objects, and
 * safe integers so JS/Python/Go cannot serialize the same value differently.
 *
 * @param {unknown} value
 * @returns {value is CanonicalValue}
 */
export function isCanonicalizable(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isInteger(value) && Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(isCanonicalizable);
  if (typeof value === 'object') return Object.values(value).every(isCanonicalizable);
  return false;
}

/**
 * @param {CanonicalValue} value
 * @returns {string}
 */
function canonicalizeValue(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalizeValue(/** @type {CanonicalValue} */ (entry))).join(',')}]`;
  }
  if (typeof value === 'object') {
    const object = /** @type {Record<string, CanonicalValue>} */ (value);
    return `{${Object.keys(object)
      .sort()
      .map((key) => JSON.stringify(key) + ':' + canonicalizeValue(object[key]))
      .join(',')}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError('value is outside the EP canonicalization profile');
  return encoded;
}

/**
 * Recursive canonical JSON used for hashes that bind security-sensitive
 * protocol state. Undefined and other out-of-profile values are refused before
 * rendering; otherwise an omitted/empty member could create bytes that the
 * Python and Go implementations cannot reproduce.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  if (!isCanonicalizable(value)) {
    throw new TypeError('value is outside the EP canonicalization profile');
  }
  return canonicalizeValue(value);
}
