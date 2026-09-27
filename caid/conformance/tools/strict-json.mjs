// SPDX-License-Identifier: Apache-2.0
//
// Dev-time oracle for the -04 JSON text input rules (draft Section 2.4),
// used to build and check the conformance corpora and as the fuzz oracle.
// It is not a port and ships in no package.
//
// The input is octets. It is refused, always with the single reason
// malformed_json, when:
//   - it is longer than the size limit (core.json json_text_octets for
//     action objects and mapping sources; no cap for definitions, registries
//     and snapshots);
//   - it is not UTF-8, or it starts with a byte order mark;
//   - it is not exactly one RFC 8259 JSON text surrounded only by the four
//     JSON whitespace characters;
//   - a member name or string contains an unescaped control character, an
//     escape denoting an unpaired surrogate, or a noncharacter (I-JSON,
//     RFC 7493 Section 2.1);
//   - an object has two members whose names are the same code points;
//   - nesting is deeper than 64 (core.json nesting_depth).
// A number token is never refused here: its value is the binary64 value
// nearest the token (JavaScript Number(), correctly rounded), which can be
// Infinity or 0; the data-model number rule decides it later.
//
// Objects are built with a null prototype and defineProperty, so a member
// named "__proto__" is an ordinary own member. The walk is iterative.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const core = JSON.parse(readFileSync(path.join(ROOT, 'caid/spec/core.json'), 'utf8'));
const limit = (id) => core.limits.find((l) => l.id === id).value;

export const JSON_TEXT_OCTETS = limit('json_text_octets');
export const NESTING_DEPTH = limit('nesting_depth');
const BOM = core.json_text.byte_order_mark;
const WHITESPACE = new Set(core.json_text.whitespace);

/** True for a Unicode noncharacter code point (U+FDD0..U+FDEF, U+nFFFE, U+nFFFF). */
export const isNoncharacter = (cp) => (cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe;

/** True when a JavaScript string holds a lone surrogate code unit. */
export const hasLoneSurrogate = (s) => /\p{Cs}/u.test(s);

/** True when a JavaScript string holds a noncharacter. */
export function hasNoncharacter(s) {
  for (const ch of s) if (isNoncharacter(ch.codePointAt(0))) return true;
  return false;
}

class Refusal extends Error {}

/**
 * @param {Uint8Array} bytes
 * @param {{maxOctets?: number | null}} [options] maxOctets null means no cap
 * @returns {{ok: true, value: any} | {ok: false, refusals: ['malformed_json'], detail: string}}
 */
export function decodeStrict(bytes, { maxOctets = JSON_TEXT_OCTETS } = {}) {
  /** @returns {{ok: false, refusals: ['malformed_json'], detail: string}} */
  const refuse = (detail) => ({ ok: false, refusals: ['malformed_json'], detail });
  if (!(bytes instanceof Uint8Array)) return refuse('input is not octets');
  if (maxOctets !== null && bytes.length > maxOctets) return refuse(`input is ${bytes.length} octets; the limit is ${maxOctets}`);
  if (bytes.length >= 3 && bytes[0] === BOM[0] && bytes[1] === BOM[1] && bytes[2] === BOM[2]) return refuse('byte order mark');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return refuse('not UTF-8');
  }
  try {
    return { ok: true, value: parse(text) };
  } catch (e) {
    if (e instanceof Refusal) return refuse(e.message);
    throw e;
  }
}

function parse(text) {
  let i = 0;
  const n = text.length;
  /** @type {(msg: string) => never} */
  const fail = (msg) => { throw new Refusal(`${msg} at offset ${i}`); };
  const ws = () => { while (i < n && WHITESPACE.has(text.charCodeAt(i))) i += 1; };
  const hex4 = () => {
    const h = text.slice(i, i + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(h)) fail('bad \\u escape');
    i += 4;
    return parseInt(h, 16);
  };
  const str = () => {
    i += 1; // opening quote
    let out = '';
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) { i += 1; break; }
      if (c < 0x20) fail('unescaped control character');
      if (c !== 0x5c) {
        const cp = text.codePointAt(i);
        const ch = String.fromCodePoint(cp);
        if (isNoncharacter(cp)) fail('noncharacter');
        out += ch;
        i += ch.length;
        continue;
      }
      const e = text[i + 1];
      i += 2;
      if (e === 'u') {
        let cp = hex4();
        if (cp >= 0xdc00 && cp <= 0xdfff) fail('unpaired low surrogate escape');
        if (cp >= 0xd800 && cp <= 0xdbff) {
          if (text[i] !== '\\' || text[i + 1] !== 'u') fail('unpaired high surrogate escape');
          i += 2;
          const lo = hex4();
          if (lo < 0xdc00 || lo > 0xdfff) fail('unpaired high surrogate escape');
          cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        }
        if (isNoncharacter(cp)) fail('noncharacter escape');
        out += String.fromCodePoint(cp);
      } else {
        const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[e];
        if (simple === undefined) fail('bad escape');
        out += simple;
      }
    }
    return out;
  };
  const num = () => {
    const m = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
    m.lastIndex = i;
    const r = m.exec(text);
    if (!r || r[0] === '' || r[0] === '-') fail('bad number');
    i += r[0].length;
    return Number(r[0]);
  };
  const scalar = () => {
    const c = text[i];
    if (c === '"') return str();
    if (c === '-' || (c >= '0' && c <= '9')) return num();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    return fail('unexpected character');
  };
  const addMember = (obj, key, value) => {
    if (Object.prototype.hasOwnProperty.call(obj, key)) fail('duplicate member name');
    Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
  };

  // Iterative walk: a stack of open containers.
  /** @type {{kind: 'o' | 'a', value: any, key?: string}[]} */
  const stack = [];
  let result;
  let haveResult = false;
  ws();
  for (;;) {
    // Parse one value start.
    if (i >= n) fail('unexpected end of input');
    const c = text[i];
    let value;
    let opened = false;
    if (c === '{' || c === '[') {
      if (stack.length + 1 > NESTING_DEPTH) fail(`nesting deeper than ${NESTING_DEPTH}`);
      i += 1;
      /** @type {{kind: 'a' | 'o', value: any, key?: string}} */
      const container = c === '{' ? { kind: 'o', value: Object.create(null) } : { kind: 'a', value: [] };
      ws();
      if (text[i] === (c === '{' ? '}' : ']')) {
        i += 1;
        value = container.value;
      } else {
        stack.push(container);
        opened = true;
        if (container.kind === 'o') {
          if (text[i] !== '"') fail('expected member name');
          container.key = str();
          ws();
          if (text[i] !== ':') fail('expected colon');
          i += 1;
          ws();
        }
      }
    } else {
      value = scalar();
    }
    if (opened) continue;
    // Attach the finished value, closing containers as they end.
    for (;;) {
      const top = stack[stack.length - 1];
      if (!top) { result = value; haveResult = true; break; }
      if (top.kind === 'o') addMember(top.value, /** @type {string} */ (top.key), value);
      else top.value.push(value);
      ws();
      const d = text[i];
      if (d === ',') {
        i += 1;
        ws();
        if (top.kind === 'o') {
          if (text[i] !== '"') fail('expected member name');
          top.key = str();
          ws();
          if (text[i] !== ':') fail('expected colon');
          i += 1;
          ws();
        }
        break;
      }
      if ((top.kind === 'o' && d === '}') || (top.kind === 'a' && d === ']')) {
        i += 1;
        stack.pop();
        value = top.value;
        continue;
      }
      fail('expected comma or close');
    }
    if (haveResult) break;
  }
  ws();
  if (i !== n) fail('trailing content');
  return result;
}
