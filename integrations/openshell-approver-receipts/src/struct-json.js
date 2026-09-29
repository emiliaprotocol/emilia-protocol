// SPDX-License-Identifier: Apache-2.0
// Generated from struct-json.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// google.protobuf.Struct (as protobufjs toObject renders it with oneofs) to
// plain JSON. protobufjs defines the well-known types itself, with
// lowerCamelCase member names (stringValue, structValue, ...), whatever
// keepCase says for the rest of the schema. The gateway delivers every
// interceptor payload as a Struct, so this is the first place hostile or
// unexpected shapes land. It never throws: every input yields a value or a
// refusal with a reason.
const MAX_DEPTH = 32;
const MAX_NODES = 20_000;
function isPlainObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
export function structToJson(struct) {
    const state = { nodes: 0 };
    try {
        const value = convertStruct(struct, '$', 0, state);
        return { ok: true, value };
    }
    catch (error) {
        return { ok: false, reason: error instanceof Error ? error.message : String(error) };
    }
}
function convertStruct(struct, at, depth, state) {
    if (struct === undefined || struct === null)
        return {};
    if (!isPlainObject(struct))
        throw new Error(`${at}: Struct is not an object`);
    if (depth > MAX_DEPTH)
        throw new Error(`${at}: nesting deeper than ${MAX_DEPTH}`);
    const fields = struct.fields;
    if (fields === undefined)
        return {};
    if (!isPlainObject(fields))
        throw new Error(`${at}: Struct.fields is not a map`);
    // Null-prototype output: a member named __proto__ stays an own data member
    // and can never reach Object.prototype.
    const out = Object.create(null);
    for (const key of Object.keys(fields)) {
        out[key] = convertValue(fields[key], `${at}.${key}`, depth + 1, state);
    }
    return out;
}
function convertValue(value, at, depth, state) {
    state.nodes += 1;
    if (state.nodes > MAX_NODES)
        throw new Error(`payload has more than ${MAX_NODES} values`);
    if (depth > MAX_DEPTH)
        throw new Error(`${at}: nesting deeper than ${MAX_DEPTH}`);
    if (!isPlainObject(value))
        throw new Error(`${at}: Value is not an object`);
    const kind = value.kind;
    switch (kind) {
        case 'nullValue':
            return null;
        case 'numberValue': {
            const n = value.numberValue;
            if (typeof n !== 'number' || !Number.isFinite(n))
                throw new Error(`${at}: number is not finite`);
            return n;
        }
        case 'stringValue':
            if (typeof value.stringValue !== 'string')
                throw new Error(`${at}: stringValue is not a string`);
            return value.stringValue;
        case 'boolValue':
            return value.boolValue === true;
        case 'structValue':
            return convertStruct(value.structValue, at, depth + 1, state);
        case 'listValue': {
            const list = value.listValue;
            if (list === undefined || list === null)
                return [];
            if (!isPlainObject(list))
                throw new Error(`${at}: listValue is not an object`);
            const values = list.values;
            if (values === undefined)
                return [];
            if (!Array.isArray(values))
                throw new Error(`${at}: listValue.values is not a list`);
            return values.map((item, index) => convertValue(item, `${at}[${index}]`, depth + 1, state));
        }
        default:
            throw new Error(`${at}: Value has no kind`);
    }
}
