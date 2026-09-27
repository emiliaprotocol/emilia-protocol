// SPDX-License-Identifier: Apache-2.0
//
// The native lane of the CAID conformance corpora: an encoding, inside the
// corpus JSON, of host-language values that no conforming JSON text decoder
// produces. Every runner builds the same host value from it and calls the
// port's native entry point (computeCaid, verifyCaid) directly. The corpus
// file itself stays strict JSON: it holds no lone surrogate, no
// noncharacter and no nesting deeper than the decoder allows.
//
// A native value is any JSON value, read as itself, except these tagged
// objects (an object whose only member name starts with "$"):
//
//   {"$units": [u, ...]}      a string made of these UTF-16 code units, so
//                             it can hold a lone surrogate. Python builds
//                             the code points (chr(0xD800)); Go builds the
//                             generalized UTF-8 bytes (WTF-8), which are not
//                             valid UTF-8.
//   {"$object": [[k, v], ...]} an object with these members in this order;
//                             a key may itself be a {"$units"} string.
//   {"$nest": {"depth": n, "container": "array" | "object", "leaf": v}}
//                             n nested arrays (or objects whose only member
//                             is "a") around leaf.
//   {"$dag": {"depth": n, "leaf": v}}
//                             n nested two-element arrays around leaf, both
//                             elements one shared array: 2^(n+1) - 1 values
//                             in n + 1 distinct containers and leaves, for
//                             the value budget of -04 Section 2.6.
//   {"$fill": {"n": n, "v": v}}
//                             an array of n elements, each the value v,
//                             built once (a container v is one shared
//                             object or array, reached n times): n + 1
//                             values for a scalar v. With n of 2^24 or more
//                             it is an array too long for V8 to list its
//                             keys at once, which a port must still read
//                             (-04 Section 2.5).
//   {"$repeat": {"unit": s, "count": n}}
//                             the string s repeated n times, for a value too
//                             large to write into the corpus.
//   {"$host": "nan"}          the binary64 NaN
//   {"$host": "infinity"}     the binary64 +infinity
//   {"$host": "-infinity"}    the binary64 -infinity
//   {"$host": "negative_zero"} the binary64 -0.0
//   {"$host": "cyclic"}       a reference to the nearest enclosing object or
//                             array, which makes the value cyclic
//   {"$host": "opaque"}       a host value with no counterpart in the data
//                             model: JavaScript new Map(), Python set(), Go
//                             struct{}{}
//
// The definitions of a native-lane vector are native-lane encodings too, so
// a definition can hold a value no JSON text carries (a member nested
// deeper than 64, an opaque host value). A plain definition, which has no
// tagged object, builds to itself.
//
// The expected results are the same in every language.

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

/** True when v is a tagged native value (one "$"-prefixed member). */
export function tagOf(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return null;
  const keys = Object.keys(v);
  return keys.length === 1 && keys[0].startsWith('$') ? keys[0] : null;
}

/**
 * Builds the JavaScript host value for a native-lane encoding.
 * @param {any} encoded
 * @returns {any}
 */
export function buildNative(encoded) {
  const build = (v, enclosing) => {
    const tag = tagOf(v);
    if (tag === '$units') return String.fromCharCode(...v.$units);
    if (tag === '$object') {
      const out = {};
      for (const [k, x] of v.$object) {
        const key = typeof k === 'string' ? k : build(k, enclosing);
        Object.defineProperty(out, key, { value: undefined, enumerable: true, writable: true, configurable: true });
        out[key] = build(x, out);
      }
      return out;
    }
    if (tag === '$repeat') return v.$repeat.unit.repeat(v.$repeat.count);
    if (tag === '$fill') return new Array(v.$fill.n).fill(build(v.$fill.v, enclosing));
    if (tag === '$nest') {
      const { depth, container, leaf } = v.$nest;
      let value = build(leaf, enclosing);
      for (let i = 0; i < depth; i += 1) value = container === 'object' ? { a: value } : [value];
      return value;
    }
    if (tag === '$dag') {
      let value = build(v.$dag.leaf, enclosing);
      for (let i = 0; i < v.$dag.depth; i += 1) value = [value, value];
      return value;
    }
    if (tag === '$host') {
      switch (v.$host) {
        case 'nan': return NaN;
        case 'infinity': return Infinity;
        case '-infinity': return -Infinity;
        case 'negative_zero': return -0;
        case 'cyclic': return enclosing;
        case 'opaque': return new Map();
        default: throw new Error(`unknown $host ${v.$host}`);
      }
    }
    if (Array.isArray(v)) {
      const out = [];
      for (const x of v) out.push(build(x, out));
      return out;
    }
    if (v !== null && typeof v === 'object') {
      const out = {};
      for (const k of Object.keys(v)) {
        Object.defineProperty(out, k, { value: undefined, enumerable: true, writable: true, configurable: true });
        out[k] = build(v[k], out);
      }
      return out;
    }
    return v;
  };
  return build(encoded, undefined);
}

/**
 * Bytes of a corpus input form: {json}, {json_b64} or {json_repeat}.
 * @param {any} input
 * @returns {Uint8Array | null}
 */
export function inputBytes(input) {
  if (own(input, 'json')) return new Uint8Array(Buffer.from(input.json, 'utf8'));
  if (own(input, 'json_b64')) return new Uint8Array(Buffer.from(input.json_b64, 'base64'));
  if (own(input, 'json_repeat')) {
    const { prefix, unit, count, suffix } = input.json_repeat;
    const p = Buffer.from(prefix, 'utf8');
    const u = Buffer.from(unit, 'utf8');
    const s = Buffer.from(suffix, 'utf8');
    const out = Buffer.allocUnsafe(p.length + u.length * count + s.length);
    p.copy(out, 0);
    if (u.length === 1) out.fill(u[0], p.length, p.length + count);
    else for (let i = 0; i < count; i += 1) u.copy(out, p.length + i * u.length);
    s.copy(out, p.length + u.length * count);
    return new Uint8Array(out.buffer, out.byteOffset, out.length);
  }
  return null;
}
