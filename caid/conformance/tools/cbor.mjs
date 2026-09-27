// SPDX-License-Identifier: Apache-2.0
//
// Deterministic CBOR (RFC 8949 Section 4.2.1, core deterministic encoding)
// over the CAID data model, as draft-schrock-canonical-action-identifier-04
// Section 3.1 maps it for the cbor-sha256 suite: an object is a map whose
// keys are text strings, an array an array, a string a text string, a
// number (always an integer of magnitude at most 2^53-1) major type 0 or 1,
// and true, false and null the simple values 21, 20 and 22. No tag, byte
// string or floating-point value appears. Every head uses its shortest
// form, and map entries are sorted by the bytewise lexicographic order of
// their encoded keys, which puts shorter keys first.
//
// Dev-time only. The three ports do not implement cbor-sha256 (support is
// OPTIONAL); this encoder computes the expectations of the corpus vectors
// that apply only to an implementation that does. Its output for the
// Appendix C.1 object was checked against the Python cbor2 library's
// canonical encoder (cbor2 6.1.4, dumps(obj, canonical=True)): both give
// the same 207 octets.

/**
 * @param {number} major
 * @param {number | bigint} n
 * @returns {Buffer}
 */
function head(major, n) {
  const m = BigInt(n);
  if (m < 24n) return Buffer.from([(major << 5) | Number(m)]);
  if (m < 0x100n) return Buffer.from([(major << 5) | 24, Number(m)]);
  if (m < 0x10000n) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(Number(m), 1);
    return b;
  }
  if (m < 0x100000000n) {
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(Number(m), 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = (major << 5) | 27;
  b.writeBigUInt64BE(m, 1);
  return b;
}

/**
 * The core deterministic CBOR encoding of a data-model value.
 * @param {any} value
 * @returns {Buffer}
 */
export function encodeCbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === false) return Buffer.from([0xf4]);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error(`not a data-model number: ${value}`);
    // -0 is the integer 0.
    return value >= 0 ? head(0, value === 0 ? 0 : value) : head(1, -1 - value);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encodeCbor)]);
  if (typeof value === 'object') {
    const entries = Object.keys(value).map((k) => [encodeCbor(k), encodeCbor(value[k])]);
    entries.sort((a, b) => Buffer.compare(a[0], b[0]));
    return Buffer.concat([head(5, entries.length), ...entries.flat()]);
  }
  throw new Error(`not a data-model value: ${typeof value}`);
}
