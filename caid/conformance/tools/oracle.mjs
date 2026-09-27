// SPDX-License-Identifier: Apache-2.0
//
// The spec oracle for the conformance corpora and the fuzz harness: the
// dev-time reference validator (caid/spec/reference.mjs, built from the
// generated spec data), the JSON text oracle (./strict-json.mjs), and the
// entry-point rules of the -04 draft:
//
//   decode(bytes)                         {ok, value} | {ok: false, refusals}
//   computeText(bytes, options)           compute from JSON text
//   verifyText(bytes, caid, options)      verify from JSON text
//   compute(value, options)               compute from a data-model value
//   verify(value, caid, options)          verify from a data-model value
//   parse(string)                         strict CAID parse
//   definitionSha256(definition)          {definition_sha256} | {refusals}
//
// Options use the corpus spelling: suite, definitions, enum_snapshots,
// expected_definition_sha256. An option of the wrong type counts as absent.
//
// A string holding a Unicode noncharacter is outside the data model on
// every entry point (RFC 8785 Section 3.1 requires I-JSON input; RFC 7493
// Section 2.1): the byte path refuses it as malformed_json
// (strict-json.mjs) and the reference refuses it natively as
// unsupported_value.

import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSpec } from '../../spec/gen.mjs';
import { createReference } from '../../spec/reference.mjs';
import { decodeStrict } from './strict-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

export const spec = buildSpec(ROOT);
export const reference = createReference(spec);

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

function computeOptions(options) {
  const o = isPlainObject(options) ? options : {};
  return {
    suite: typeof o.suite === 'string' ? o.suite : undefined,
    definitions: Array.isArray(o.definitions) ? o.definitions : undefined,
    enumSnapshots: Array.isArray(o.enum_snapshots) ? o.enum_snapshots : undefined,
  };
}

function verifyOptions(options) {
  const o = isPlainObject(options) ? options : {};
  return {
    definitions: Array.isArray(o.definitions) ? o.definitions : undefined,
    enumSnapshots: Array.isArray(o.enum_snapshots) ? o.enum_snapshots : undefined,
    expectedDefinitionSha256: typeof o.expected_definition_sha256 === 'string' ? o.expected_definition_sha256 : undefined,
  };
}

export function compute(value, options) {
  return reference.compute(value, computeOptions(options));
}

export function verify(value, caid, options) {
  return reference.verify(value, caid, verifyOptions(options));
}

export const parse = (s) => reference.parse(s);

/**
 * @param {Uint8Array} bytes
 * @param {{maxOctets?: number | null}} [options]
 */
export function decode(bytes, { maxOctets } = {}) {
  const r = decodeStrict(bytes, maxOctets === undefined ? {} : { maxOctets });
  return r.ok ? { ok: true, value: r.value } : { ok: false, refusals: r.refusals };
}

export function computeText(bytes, options) {
  const d = decodeStrict(bytes);
  if (!d.ok) return { refusals: ['malformed_json'] };
  return compute(d.value, options);
}

export function verifyText(bytes, caid, options) {
  const p = reference.parse(caid);
  if (!p.ok) return reference.verify(null, caid, verifyOptions(options));
  const d = decodeStrict(bytes);
  if (!d.ok) {
    const detail = spec.verify_details.reasons.malformed_json;
    return { valid: false, reasons: ['malformed_json'], details: [{ reason: 'malformed_json', field: detail.field, rule: detail.rule, observed: null }] };
  }
  return verify(d.value, caid, options);
}

export function definitionSha256(definition) {
  if (!isPlainObject(definition) || reference.conformance(definition).length) return { refusals: ['invalid_definition'] };
  const digest = reference.definitionSha256(definition);
  return digest === null ? { refusals: ['invalid_definition'] } : { definition_sha256: digest };
}

/** sha256:<hex> of a JavaScript string's UTF-8 bytes. */
export const sha256Utf8 = (s) => 'sha256:' + createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
