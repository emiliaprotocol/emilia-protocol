// SPDX-License-Identifier: Apache-2.0
// Generated from canonical.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Canonical forms and digests.
//
// JCS: RFC 8785 over the strict EMILIA JSON domain (strings, booleans, null,
// arrays, plain objects, safe integers), from @emilia-protocol/verify.
//
// Canonical rule: the proto3 JSON form of openshell.sandbox.v1.NetworkPolicyRule
// with ORIGINAL proto field names, enum values as names, and fields that carry
// no presence omitted when they hold their default value (empty string, 0,
// false, the zero enum, empty list, empty map). Inputs may use either the
// original or the lowerCamelCase JSON name for a field, as proto3 JSON allows;
// the output always uses the original name. Anything outside the message
// schema is refused rather than dropped, so two different inputs can never
// collapse to one digest silently.
import crypto from 'node:crypto';
import protobuf from 'protobufjs';
import { canonicalizeStrictJson } from '@emilia-protocol/verify/strict-json';
import { lookupType } from './protos.ts';
export const RULE_TYPE = 'openshell.sandbox.v1.NetworkPolicyRule';
export function jcs(value) {
    return canonicalizeStrictJson(value);
}
export function sha256Hex(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}
export function b64u(bytes) {
    return Buffer.from(bytes).toString('base64url');
}
/** Canonical base64url (no padding, re-encodes to itself) or null. */
export function fromB64u(value) {
    if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    const bytes = Buffer.from(value, 'base64url');
    return bytes.toString('base64url') === value ? bytes : null;
}
function lowerCamel(name) {
    return name.replace(/_([a-z0-9])/g, (_m, c) => c.toUpperCase());
}
function isPlainObject(value) {
    if (typeof value !== 'object' || value === null || Array.isArray(value))
        return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}
function hasPresence(field) {
    // proto3 `optional` and real oneof members track presence; everything else
    // is omitted from canonical JSON when it holds its default value.
    return Boolean(field.partOf) || field.options?.proto3_optional === true;
}
const UINT32_MAX = 0xffff_ffff;
const INT32_MIN = -0x8000_0000;
const INT32_MAX = 0x7fff_ffff;
function normalizeScalar(field, value, at) {
    const type = field.type;
    switch (type) {
        case 'string':
            if (typeof value !== 'string')
                throw new Error(`${at}: expected a string`);
            return value;
        case 'bool':
            if (typeof value !== 'boolean')
                throw new Error(`${at}: expected a boolean`);
            return value;
        case 'uint32':
        case 'fixed32':
            if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > UINT32_MAX) {
                throw new Error(`${at}: expected an integer in [0, ${UINT32_MAX}]`);
            }
            return value;
        case 'int32':
        case 'sint32':
        case 'sfixed32':
            if (typeof value !== 'number' || !Number.isInteger(value) || value < INT32_MIN || value > INT32_MAX) {
                throw new Error(`${at}: expected a 32-bit integer`);
            }
            return value;
        default:
            // The rule schema at the pinned commit only uses string, bool, uint32,
            // enums and messages. Anything else (64-bit, floating point, bytes) is
            // refused instead of guessed at.
            throw new Error(`${at}: field type ${type} is not supported by the canonical rule form`);
    }
}
function isDefault(field, value) {
    if (field.resolvedType instanceof protobuf.Enum) {
        return value === field.resolvedType.valuesById[0];
    }
    if (field.resolvedType instanceof protobuf.Type)
        return false;
    return value === '' || value === 0 || value === false;
}
function normalizeEnum(enumType, value, at) {
    if (typeof value === 'string') {
        if (!Object.prototype.hasOwnProperty.call(enumType.values, value))
            throw new Error(`${at}: unknown ${enumType.name} value ${JSON.stringify(value)}`);
        return value;
    }
    if (typeof value === 'number' && Number.isInteger(value) && Object.prototype.hasOwnProperty.call(enumType.valuesById, value)) {
        return enumType.valuesById[value];
    }
    throw new Error(`${at}: expected a ${enumType.name} name`);
}
function normalizeSingle(field, value, at, depth) {
    const resolved = field.resolvedType;
    if (resolved instanceof protobuf.Type)
        return normalizeMessage(resolved, value, at, depth + 1);
    if (resolved instanceof protobuf.Enum)
        return normalizeEnum(resolved, value, at);
    return normalizeScalar(field, value, at);
}
function normalizeMessage(type, input, at, depth) {
    if (depth > 16)
        throw new Error(`${at}: nesting deeper than 16`);
    if (!isPlainObject(input))
        throw new Error(`${at}: expected an object for ${type.name}`);
    const byJsonName = new Map();
    for (const field of type.fieldsArray) {
        field.resolve();
        byJsonName.set(field.name, field);
        byJsonName.set(lowerCamel(field.name), field);
    }
    const out = {};
    const seen = new Set();
    for (const key of Object.keys(input).sort()) {
        const field = byJsonName.get(key);
        if (!field)
            throw new Error(`${at}.${key}: not a field of ${type.fullName.replace(/^\./, '')}`);
        if (seen.has(field.name))
            throw new Error(`${at}.${key}: field ${field.name} given twice`);
        seen.add(field.name);
        const value = input[key];
        const fieldAt = `${at}.${field.name}`;
        if (value === null) {
            // proto3 JSON: null means "not set".
            continue;
        }
        if (field.map) {
            if (!isPlainObject(value))
                throw new Error(`${fieldAt}: expected a map object`);
            if (field.keyType !== 'string')
                throw new Error(`${fieldAt}: only string map keys are supported`);
            const entries = Object.keys(value).sort();
            if (entries.length === 0)
                continue;
            const map = {};
            for (const entryKey of entries)
                map[entryKey] = normalizeSingle(field, value[entryKey], `${fieldAt}[${JSON.stringify(entryKey)}]`, depth);
            out[field.name] = map;
            continue;
        }
        if (field.repeated) {
            if (!Array.isArray(value))
                throw new Error(`${fieldAt}: expected a list`);
            if (value.length === 0)
                continue;
            out[field.name] = value.map((item, index) => normalizeSingle(field, item, `${fieldAt}[${index}]`, depth));
            continue;
        }
        const normalized = normalizeSingle(field, value, fieldAt, depth);
        if (!hasPresence(field) && isDefault(field, normalized))
            continue;
        out[field.name] = normalized;
    }
    return out;
}
/** Canonical proto3 JSON object for a NetworkPolicyRule, or a refusal. */
export function canonicalRule(input) {
    try {
        const rule = normalizeMessage(lookupType(RULE_TYPE), input, '$', 0);
        jcs(rule); // assert it is inside the strict canonical JSON domain
        return { ok: true, value: rule };
    }
    catch (error) {
        return { ok: false, reason: `proposed_rule is not a canonical ${RULE_TYPE}: ${error instanceof Error ? error.message : String(error)}` };
    }
}
/** "sha256:<hex>" over JCS(canonicalRule(input)), or a refusal. */
export function ruleDigest(input) {
    const rule = canonicalRule(input);
    if (!rule.ok)
        return rule;
    return { ok: true, value: `sha256:${sha256Hex(jcs(rule.value))}` };
}
