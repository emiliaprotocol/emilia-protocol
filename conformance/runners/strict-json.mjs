// SPDX-License-Identifier: Apache-2.0
// Generated from strict-json.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Strict-parse gate for the EP-CANONICALIZATION-v1 differential suite.
//
// The EP verify packages receive already-parsed values, so parse-time
// malleability (duplicate member names, unpaired surrogate escapes, unbounded
// nesting) has to be pinned at the parse boundary. Each conformance runner
// implements this SAME gate (JS here; Python in run_py.py; Go in
// packages/go-verify/cmd/conformance/main.go) so all three languages produce
// identical verdicts on the same raw JSON text:
//
//   1. reject any \u escape sequence encoding an UNPAIRED UTF-16 surrogate
//      (I-JSON, RFC 7493: strings must be valid Unicode);
//   2. reject a repeated member name within one object, compared AFTER escape
//      decoding (RFC 8785 section 3.1 / I-JSON: names must be unique);
//   3. reject container nesting depth greater than MAX_DEPTH (a suite-pinned
//      bound: native limits differ across languages, so the conformance
//      boundary enforces one shared limit).
//
// Fail-closed: any scan failure refuses; there is no lenient mode. The caller
// MUST run its language's standard JSON parser first (syntax gate); this
// scanner assumes syntactically valid JSON.
export const MAX_DEPTH = 64;
/**
 * @param {string} raw syntactically valid JSON text
 * @returns {{ok: boolean, reason?: string}}
 */
export function strictParseGate(raw) {
    let i = 0;
    const n = raw.length;
    const stack = [];
    let reason = null;
    const ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
    const readString = () => {
        i++; // opening quote
        let out = '';
        while (i < n) {
            const c = raw[i];
            if (c === '"') {
                i++;
                return out;
            }
            if (c === '\\') {
                const e = raw[i + 1];
                if (e === 'u') {
                    const cu = parseInt(raw.slice(i + 2, i + 6), 16);
                    i += 6;
                    if (cu >= 0xd800 && cu <= 0xdbff) {
                        if (raw[i] === '\\' && raw[i + 1] === 'u') {
                            const cu2 = parseInt(raw.slice(i + 2, i + 6), 16);
                            if (cu2 >= 0xdc00 && cu2 <= 0xdfff) {
                                i += 6;
                                out += String.fromCharCode(cu, cu2);
                                continue;
                            }
                        }
                        reason = 'unpaired high surrogate escape';
                        return null;
                    }
                    if (cu >= 0xdc00 && cu <= 0xdfff) {
                        reason = 'unpaired low surrogate escape';
                        return null;
                    }
                    out += String.fromCharCode(cu);
                }
                else {
                    out += ESCAPES[e] ?? '';
                    i += 2;
                }
            }
            else {
                out += c;
                i++;
            }
        }
        reason = 'unterminated string';
        return null;
    };
    while (i < n) {
        const c = raw[i];
        if (c === '{') {
            stack.push({ obj: true, keys: new Set(), expectKey: true });
            if (stack.length > MAX_DEPTH)
                return { ok: false, reason: `nesting depth exceeds ${MAX_DEPTH}` };
            i++;
        }
        else if (c === '[') {
            stack.push({ obj: false });
            if (stack.length > MAX_DEPTH)
                return { ok: false, reason: `nesting depth exceeds ${MAX_DEPTH}` };
            i++;
        }
        else if (c === '}' || c === ']') {
            stack.pop();
            i++;
        }
        else if (c === ',') {
            const top = stack[stack.length - 1];
            if (top?.obj)
                top.expectKey = true;
            i++;
        }
        else if (c === '"') {
            const top = stack[stack.length - 1];
            const isKey = Boolean(top?.obj && top.expectKey);
            const s = readString();
            if (reason)
                return { ok: false, reason };
            if (isKey) {
                // isKey is only true when top?.obj was truthy, i.e. top was pushed via
                // the `{ obj: true, keys: new Set(), ... }` branch, which always sets
                // `keys`. TS can't correlate that through the isKey flag, so assert
                // the type the invariant already guarantees (no runtime effect).
                const keys = top.keys;
                if (keys.has(s))
                    return { ok: false, reason: 'duplicate object member name' };
                keys.add(s);
                top.expectKey = false;
            }
        }
        else {
            i++; // whitespace, colons handled implicitly, primitive tokens
        }
    }
    return { ok: true };
}
