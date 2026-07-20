// SPDX-License-Identifier: Apache-2.0
// Execution-field binding for EMILIA Gate. This is the executor-side control
// that prevents "the signed claim said X, the system mutated Y".

import crypto from 'node:crypto';

export const EXECUTION_BINDING_VERSION = 'EP-GATE-EXECUTION-BINDING-v1';

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 50000;
const MAX_JSON_STRING_BYTES = 1024 * 1024;

function validUnicodeString(value) {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Match the hardened EP canonical JSON safety profile: valid Unicode strings,
 * booleans, null, safe integers, dense arrays, and plain data objects. Object
 * identity is unique across the graph, so cycles and aliases both refuse.
 */
function assertCanonicalJson(value) {
  const stack = [{ value, depth: 0 }];
  const seen = new WeakSet();
  let nodes = 0;
  let stringBytes = 0;

  while (stack.length) {
    // stack.length > 0 here guarantees pop() returns an element, but
    // Array#pop()'s type is always T | undefined.
    const current = stack.pop()!;
    if (++nodes > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH) {
      throw new TypeError('value exceeds the EP canonical JSON resource profile');
    }
    const v = current.value;
    if (v === null || typeof v === 'boolean') continue;
    if (typeof v === 'string') {
      if (!validUnicodeString(v)) throw new TypeError('value contains invalid Unicode');
      stringBytes += Buffer.byteLength(v, 'utf8');
      if (stringBytes > MAX_JSON_STRING_BYTES) throw new TypeError('value exceeds the EP canonical JSON string limit');
      continue;
    }
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) throw new TypeError('value contains a non-safe integer');
      continue;
    }
    if (!Array.isArray(v) && !isPlainObject(v)) {
      throw new TypeError('value contains a non-plain JSON object');
    }
    if (seen.has(v)) throw new TypeError('value contains a cycle or alias');
    seen.add(v);

    if (Array.isArray(v)) {
      const ownKeys = Reflect.ownKeys(v);
      if (ownKeys.length !== v.length + 1 || !ownKeys.includes('length')) {
        throw new TypeError('value contains a sparse or extended array');
      }
      for (let i = 0; i < v.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(v, String(i));
        if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
          throw new TypeError('value contains a sparse or accessor array');
        }
        stack.push({ value: descriptor.value, depth: current.depth + 1 });
      }
      continue;
    }

    for (const key of Reflect.ownKeys(v)) {
      if (typeof key !== 'string' || !validUnicodeString(key)) {
        throw new TypeError('value contains a non-JSON object key');
      }
      const descriptor = Object.getOwnPropertyDescriptor(v, key);
      if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError('value contains a non-data JSON property');
      }
      stringBytes += Buffer.byteLength(key, 'utf8');
      if (stringBytes > MAX_JSON_STRING_BYTES) throw new TypeError('value exceeds the EP canonical JSON string limit');
      stack.push({ value: descriptor.value, depth: current.depth + 1 });
    }
  }
}

function canonicalizeValidated(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return `[${v.map(canonicalizeValidated).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalizeValidated(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

export function canonicalize(v) {
  assertCanonicalJson(v);
  return canonicalizeValidated(v);
}

export function hashCanonical(v) {
  return crypto.createHash('sha256').update(canonicalize(v)).digest('hex');
}

function fieldValue(container, field) {
  if (!isPlainObject(container)) return { state: 'invalid' };
  const descriptor = Object.getOwnPropertyDescriptor(container, field);
  if (!descriptor) return { state: 'missing' };
  if (descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return { state: 'invalid' };
  if (descriptor.value === null) return { state: 'missing' };
  try {
    assertCanonicalJson(descriptor.value);
    return { state: 'valid', value: descriptor.value };
  } catch {
    return { state: 'invalid' };
  }
}

function equalValue(a, b) {
  return canonicalize(a) === canonicalize(b);
}

export function materialFieldsFor(requirement) {
  const fields = requirement?.execution_binding?.required_fields;
  return Array.isArray(fields) ? [...new Set(fields.filter(Boolean))] : [];
}

/**
 * Verifies that the signed claim and the executor-observed mutation fields
 * match for the action pack. The executor must pass `observedAction` from the
 * system of record, not from the agent request body.
 */
export function verifyExecutionBinding({ requirement, receipt, observedAction }: {
  requirement?: any;
  receipt?: any;
  observedAction?: any;
} = {}) {
  const requiredFields = materialFieldsFor(requirement);
  if (requiredFields.length === 0) {
    return { ok: true, required: false, required_fields: [], signed_hash: null, observed_hash: null };
  }

  const signed = receipt?.payload?.claim || {};
  const observed = observedAction || {};
  const missingSigned: string[] = [];
  const missingObserved: string[] = [];
  const invalidSigned: string[] = [];
  const invalidObserved: string[] = [];
  const mismatched: string[] = [];
  const signedValues = {};
  const observedValues = {};

  for (const field of requiredFields) {
    const expected = fieldValue(signed, field);
    const actual = fieldValue(observed, field);
    if (expected.state === 'missing') {
      missingSigned.push(field);
    } else if (expected.state === 'invalid') {
      invalidSigned.push(field);
    } else {
      signedValues[field] = expected.value;
    }
    if (actual.state === 'missing') {
      missingObserved.push(field);
    } else if (actual.state === 'invalid') {
      invalidObserved.push(field);
    } else {
      observedValues[field] = actual.value;
    }
    if (expected.state === 'valid' && actual.state === 'valid'
        && !equalValue(expected.value, actual.value)) mismatched.push(field);
  }

  // Per-field checks do not see one object reused by two required fields.
  // Validate the aggregate graphs before computing either digest.
  try { assertCanonicalJson(signedValues); } catch {
    for (const field of Object.keys(signedValues)) {
      if (!invalidSigned.includes(field)) invalidSigned.push(field);
    }
  }
  try { assertCanonicalJson(observedValues); } catch {
    for (const field of Object.keys(observedValues)) {
      if (!invalidObserved.includes(field)) invalidObserved.push(field);
    }
  }

  return {
    '@version': EXECUTION_BINDING_VERSION,
    ok: missingSigned.length === 0 && missingObserved.length === 0
      && invalidSigned.length === 0 && invalidObserved.length === 0 && mismatched.length === 0,
    required: true,
    required_fields: requiredFields,
    missing_signed_fields: missingSigned,
    missing_observed_fields: missingObserved,
    invalid_signed_fields: invalidSigned,
    invalid_observed_fields: invalidObserved,
    mismatched_fields: mismatched,
    signed_hash: invalidSigned.length === 0 ? hashCanonical(signedValues) : null,
    observed_hash: invalidObserved.length === 0 ? hashCanonical(observedValues) : null,
    note: 'Executor MUST provide observedAction from the system of record; request-body fields are not a trust source.',
  };
}

export default {
  EXECUTION_BINDING_VERSION,
  canonicalize,
  hashCanonical,
  materialFieldsFor,
  verifyExecutionBinding,
};
