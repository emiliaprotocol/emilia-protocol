// SPDX-License-Identifier: Apache-2.0
// Execution-field binding for EMILIA Gate. This is the executor-side control
// that prevents "the signed claim said X, the system mutated Y".

import crypto from 'node:crypto';

export const EXECUTION_BINDING_VERSION = 'EP-GATE-EXECUTION-BINDING-v1';

export function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

export function hashCanonical(v) {
  return crypto.createHash('sha256').update(canonicalize(v)).digest('hex');
}

function hasValue(v) {
  return v !== undefined && v !== null;
}

function normalize(v) {
  if (Array.isArray(v)) return [...new Set(v.map((x) => String(x)))].sort();
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, normalize(v[k])]));
  }
  return v;
}

function equalValue(a, b) {
  return hashCanonical(normalize(a)) === hashCanonical(normalize(b));
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
export function verifyExecutionBinding({ requirement, receipt, observedAction } = {}) {
  const requiredFields = materialFieldsFor(requirement);
  if (requiredFields.length === 0) {
    return { ok: true, required: false, required_fields: [], signed_hash: null, observed_hash: null };
  }

  const signed = receipt?.payload?.claim || {};
  const observed = observedAction || {};
  const missingSigned = [];
  const missingObserved = [];
  const mismatched = [];
  const signedValues = {};
  const observedValues = {};

  for (const field of requiredFields) {
    const expected = signed[field];
    const actual = observed[field];
    if (!hasValue(expected)) {
      missingSigned.push(field);
      continue;
    }
    signedValues[field] = normalize(expected);
    if (!hasValue(actual)) {
      missingObserved.push(field);
      continue;
    }
    observedValues[field] = normalize(actual);
    if (!equalValue(expected, actual)) mismatched.push(field);
  }

  return {
    '@version': EXECUTION_BINDING_VERSION,
    ok: missingSigned.length === 0 && missingObserved.length === 0 && mismatched.length === 0,
    required: true,
    required_fields: requiredFields,
    missing_signed_fields: missingSigned,
    missing_observed_fields: missingObserved,
    mismatched_fields: mismatched,
    signed_hash: hashCanonical(signedValues),
    observed_hash: hashCanonical(observedValues),
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
