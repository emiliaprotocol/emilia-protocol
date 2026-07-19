// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from 'node:util';
import {
  EXACT_EXTERNAL_RESULT_KINDS,
  LIVE_SUITE_EXECUTION_FILES,
} from './suites.mjs';

const plainObject = (value) => value && typeof value === 'object' && !Array.isArray(value);

export function executionSuiteFile(suiteFile) {
  return LIVE_SUITE_EXECUTION_FILES[suiteFile] || suiteFile;
}

function vectorMap(suiteFile, suite) {
  if (!plainObject(suite) || !Array.isArray(suite.vectors) || suite.vectors.length === 0) {
    throw new Error(`${suiteFile}: suite must contain a non-empty vectors array`);
  }
  const vectors = new Map();
  for (const vector of suite.vectors) {
    if (!plainObject(vector) || typeof vector.id !== 'string' || !vector.id
        || !plainObject(vector.expect) || vectors.has(vector.id)) {
      throw new Error(`${suiteFile}: malformed or duplicate vector`);
    }
    vectors.set(vector.id, vector);
  }
  return vectors;
}

export function buildSuiteContract(suiteFile, suite, executionSuite = suite) {
  const official = vectorMap(suiteFile, suite);
  const executionFile = executionSuiteFile(suiteFile);
  const executable = vectorMap(executionFile, executionSuite);
  if (official.size !== executable.size) {
    throw new Error(`${suiteFile}: execution companion vector count mismatch`);
  }

  const exact = executionFile !== suiteFile
    || Object.hasOwn(EXACT_EXTERNAL_RESULT_KINDS, suiteFile);
  const expectations = new Map();
  for (const [id, vector] of official) {
    const executionVector = executable.get(id);
    if (!executionVector) throw new Error(`${suiteFile}: execution companion missing ${id}`);
    if (executionFile !== suiteFile) {
      for (const [key, value] of Object.entries(vector.expect)) {
        if (!isDeepStrictEqual(executionVector.expect[key], value)) {
          throw new Error(`${suiteFile}#${id}: catalogue/exec expectation mismatch at ${key}`);
        }
      }
    }
    expectations.set(id, executionFile === suiteFile ? vector.expect : executionVector.expect);
  }
  return { suiteFile, executionFile, exact, expectations };
}

function resultValue(row) {
  const value = { ...row };
  delete value.id;
  return value;
}

export function compareResultRow(contract, row) {
  if (!plainObject(row) || typeof row.id !== 'string' || !row.id) {
    return { ok: false, detail: 'malformed result row' };
  }
  const expect = contract.expectations.get(row.id);
  if (!expect) return { ok: false, detail: 'unknown vector id' };
  const actual = resultValue(row);

  if (contract.exact) {
    return isDeepStrictEqual(actual, expect)
      ? { ok: true }
      : { ok: false, detail: 'exact typed result mismatch' };
  }

  if (typeof expect.reason_contains === 'string') {
    const expectedFields = { ...expect };
    delete expectedFields.reason_contains;
    const actualFields = {};
    for (const key of Object.keys(expectedFields)) actualFields[key] = actual[key];
    const extra = Object.keys(actual).filter((key) => !Object.hasOwn(expectedFields, key));
    const reasons = extra.length === 1 && extra[0] === 'reasons' && Array.isArray(actual.reasons)
      && actual.reasons.every((reason) => typeof reason === 'string')
      ? actual.reasons
      : null;
    if (!isDeepStrictEqual(actualFields, expectedFields) || !reasons) {
      return { ok: false, detail: 'typed result/reasons shape mismatch' };
    }
    return reasons.join(' ').includes(expect.reason_contains)
      ? { ok: true }
      : { ok: false, detail: `reason missing ${expect.reason_contains}` };
  }

  return isDeepStrictEqual(actual, expect)
    ? { ok: true }
    : { ok: false, detail: 'typed result mismatch' };
}

export function validateResultRows(contract, rows) {
  if (!Array.isArray(rows) || rows.length !== contract.expectations.size) {
    throw new Error(`${contract.suiteFile}: runner returned wrong result count`);
  }
  const byId = new Map();
  for (const row of rows) {
    if (!plainObject(row) || typeof row.id !== 'string' || !row.id || byId.has(row.id)) {
      throw new Error(`${contract.suiteFile}: runner emitted a malformed or duplicate result`);
    }
    if (!contract.expectations.has(row.id)) {
      throw new Error(`${contract.suiteFile}: runner emitted unknown id ${row.id}`);
    }
    byId.set(row.id, row);
  }
  for (const id of contract.expectations.keys()) {
    if (!byId.has(id)) throw new Error(`${contract.suiteFile}: runner omitted ${id}`);
  }
  return byId;
}
