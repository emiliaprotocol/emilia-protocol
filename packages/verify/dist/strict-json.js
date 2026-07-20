// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
// Duplicate-name and Unicode-scalar gate for signed nested JSON such as
// WebAuthn clientDataJSON. JSON.parse remains the syntax gate.
export const MAX_JSON_DEPTH = 64;
export function strictJsonGate(raw) {
    if (typeof raw !== 'string')
        return { ok: false, reason: 'JSON input must be text' };
    const input = raw;
    try {
        JSON.parse(input);
    }
    catch {
        return { ok: false, reason: 'invalid JSON syntax' };
    }
    let index = 0;
    const stack = [];
    let reason = null;
    const escapes = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
    function readString() {
        index += 1;
        let output = '';
        while (index < input.length) {
            const character = input[index];
            if (character === '"') {
                index += 1;
                return output;
            }
            if (character !== '\\') {
                output += character;
                index += 1;
                continue;
            }
            const escape = input[index + 1];
            if (escape !== 'u') {
                output += escapes[escape] ?? '';
                index += 2;
                continue;
            }
            const first = Number.parseInt(input.slice(index + 2, index + 6), 16);
            index += 6;
            if (first >= 0xd800 && first <= 0xdbff) {
                if (input[index] === '\\' && input[index + 1] === 'u') {
                    const second = Number.parseInt(input.slice(index + 2, index + 6), 16);
                    if (second >= 0xdc00 && second <= 0xdfff) {
                        output += String.fromCharCode(first, second);
                        index += 6;
                        continue;
                    }
                }
                reason = 'unpaired high surrogate escape';
                return null;
            }
            if (first >= 0xdc00 && first <= 0xdfff) {
                reason = 'unpaired low surrogate escape';
                return null;
            }
            output += String.fromCharCode(first);
        }
        reason = 'unterminated string';
        return null;
    }
    while (index < input.length) {
        const character = input[index];
        if (character === '{') {
            stack.push({ object: true, keys: new Set(), expectsKey: true });
            if (stack.length > MAX_JSON_DEPTH)
                return { ok: false, reason: `nesting depth exceeds ${MAX_JSON_DEPTH}` };
            index += 1;
        }
        else if (character === '[') {
            stack.push({ object: false });
            if (stack.length > MAX_JSON_DEPTH)
                return { ok: false, reason: `nesting depth exceeds ${MAX_JSON_DEPTH}` };
            index += 1;
        }
        else if (character === '}' || character === ']') {
            stack.pop();
            index += 1;
        }
        else if (character === ',') {
            const top = stack.at(-1);
            if (top?.object)
                top.expectsKey = true;
            index += 1;
        }
        else if (character === '"') {
            const top = stack.at(-1);
            const isKey = Boolean(top?.object && top.expectsKey);
            const value = readString();
            if (reason)
                return { ok: false, reason };
            if (isKey) {
                // isKey is only true when top?.object && top.expectsKey was truthy above,
                // which guarantees top is the object-frame variant here; TS can't
                // correlate that through the intermediate `isKey` boolean.
                const frame = top;
                if (value === null)
                    return { ok: false, reason: 'invalid string member name' };
                if (frame.keys.has(value))
                    return { ok: false, reason: 'duplicate object member name' };
                frame.keys.add(value);
                frame.expectsKey = false;
            }
        }
        else {
            index += 1;
        }
    }
    return { ok: true };
}
const strictJson = { strictJsonGate, MAX_JSON_DEPTH };
export default strictJson;
//# sourceMappingURL=strict-json.js.map
