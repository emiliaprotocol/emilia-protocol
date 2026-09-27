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
// One rule is applied here on top of the reference: a string holding a
// Unicode noncharacter is outside the data model on every entry point.
// RFC 8785 Section 3.1 requires JCS input to be I-JSON, and I-JSON
// (RFC 7493 Section 2.1) excludes noncharacters, so the byte path refuses
// them as malformed_json (strict-json.mjs) and the native path as
// unsupported_value. The reference accepts them natively; the request to
// fold the rule into caid/spec/reference.mjs is in the I6 request file.
// Once it lands, withNoncharacterRule becomes the identity.

import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSpec } from '../../spec/gen.mjs';
import { createReference } from '../../spec/reference.mjs';
import { decodeStrict, hasNoncharacter, NESTING_DEPTH } from './strict-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

export const spec = buildSpec(ROOT);
export const reference = createReference(spec);

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
const GATES = new Set(spec.gates.compute.flat());

/** True when a noncharacter string occurs within the first 64 levels of a data-model value. */
function containsNoncharacter(value) {
  const stack = [[value, 0]];
  const seen = new Set();
  while (stack.length) {
    const [v, depth] = /** @type {[any, number]} */ (stack.pop());
    if (typeof v === 'string') { if (hasNoncharacter(v)) return true; continue; }
    if (v === null || typeof v !== 'object' || seen.has(v)) continue;
    if (depth + 1 > NESTING_DEPTH) continue;
    seen.add(v);
    if (Array.isArray(v)) { for (const x of v) stack.push([x, depth + 1]); continue; }
    if (!isPlainObject(v)) continue;
    for (const k of Object.keys(v)) {
      if (hasNoncharacter(k)) return true;
      stack.push([v[k], depth + 1]);
    }
  }
  return false;
}

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

const detailOf = (reason, value) => {
  const d = spec.verify_details.reasons[reason];
  const observed = d.observed === 'member' ? (isPlainObject(value) ? 'absent' : 'unsupported') : null;
  return { reason, field: d.field === 'param' ? null : d.field, rule: d.rule, observed };
};

export function compute(value, options) {
  const r = reference.compute(value, computeOptions(options));
  if (!containsNoncharacter(value)) return r;
  if (r.refusals && r.refusals.length === 1 && GATES.has(r.refusals[0])) return r;
  const refusals = r.refusals ? [...r.refusals] : [];
  if (!refusals.includes('unsupported_value')) refusals.push('unsupported_value');
  return { refusals };
}

export function verify(value, caid, options) {
  const opts = verifyOptions(options);
  const r = reference.verify(value, caid, opts);
  if (!containsNoncharacter(value) || !isPlainObject(value) || !reference.parse(caid).ok) return r;
  // The object does not canonicalize: the digest is not compared, and the
  // expanded compute reasons gain unsupported_value unless a gate stopped
  // them.
  const computed = compute(value, { suite: 'jcs-sha256', definitions: opts.definitions, enum_snapshots: opts.enumSnapshots });
  const gated = computed.refusals && computed.refusals.length === 1 && GATES.has(computed.refusals[0]);
  const reasons = r.reasons.filter((x) => x !== 'digest_mismatch' && x !== 'invalid_object');
  const details = r.details.filter((x) => x.reason !== 'digest_mismatch');
  if (!gated && !details.some((x) => x.reason === 'unsupported_value')) details.push(detailOf('unsupported_value', value));
  reasons.push('invalid_object');
  const out = { valid: false, reasons, details };
  if (r.definition_sha256 !== undefined) out.definition_sha256 = r.definition_sha256;
  return out;
}

export const parse = (s) => reference.parse(s);

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
