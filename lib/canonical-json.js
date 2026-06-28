// SPDX-License-Identifier: Apache-2.0

/**
 * Recursive canonical JSON used for hashes that bind security-sensitive
 * protocol state. This intentionally matches the verifier/issuer canonicalizer:
 * object keys are sorted at every depth and arrays preserve order.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => JSON.stringify(key) + ':' + canonicalize(value[key]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
