#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Builds the CAID core conformance corpus, version 5
// (caid/conformance/vectors.json), from:
//   - the frozen version 4 corpus (caid/conformance/history/vectors.v4.json),
//     every vector converted to exact JSON text input;
//   - one vector per registry type (caid/registry/action-types.json);
//   - the hand-written cases in ./core-cases.mjs.
//
//   node caid/conformance/tools/build-core.mjs           write vectors.json
//   node caid/conformance/tools/build-core.mjs --check   exit 1 unless the
//                                                        file is current
//
// Every expectation is computed by the spec oracle (./oracle.mjs) and then
// checked against what the case states: a version 4 vector must keep its
// version 4 result unless it is listed in V4_CHANGES with the -04 rule that
// changes it, and a hand-written case must match its stated refusals,
// reasons or outcome. Any disagreement stops the build.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { coreCases } from './core-cases.mjs';
import { minify, rawSpans } from './jsontext.mjs';
import * as oracle from './oracle.mjs';
import { decodeStrict } from './strict-json.mjs';
import { buildNative, inputBytes } from '../runners/native.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../../..');
const OUT = path.join(ROOT, 'caid/conformance/vectors.json');
const V4_PATH = 'caid/conformance/history/vectors.v4.json';
const V4_SHA256 = 'sha256:7a201c872737ad83be8151b80374f720a82d2d5f8bbc597165737bbe2d40a66f';

// Version 4 vectors whose result changes under -04, and the rule that
// changes it. Every other version 4 vector keeps its result exactly.
export const V4_CHANGES = {
  'refuse-lone-surrogate-string-value': { to: ['malformed_json'], rule: 'Section 2.4: JSON text with an unpaired-surrogate escape is malformed_json. The native lane keeps unsupported_value (native-lone-surrogate-string-value).' },
  'refuse-lone-surrogate-member-name': { to: ['malformed_json'], rule: 'Section 2.4, as above (native twin: native-lone-surrogate-member-name).' },
  'verify-lone-surrogate-against-replacement-caid': { to: ['malformed_json'], rule: 'Section 2.4, as above (native twin: native-verify-lone-surrogate-against-replacement-caid).' },
  'refuse-suite-unregistered': { to: ['unknown_suite'], rule: 'Section 3.4 step 2: a suite that matches the suite rule but is not registered parses to unknown_suite.' },
  'refuse-suite-unregistered-unchecked-digest': { to: ['unknown_suite'], rule: 'Section 3.4 step 2, as above; the registry check precedes the digest check.' },
  'verify-malformed-unregistered-suite': { to: ['unknown_suite'], rule: 'Section 3.4 step 2, as above, as the verification gate.' },
};

const sha256 = (buf) => 'sha256:' + createHash('sha256').update(buf).digest('hex');
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x)
  ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
const same = (a, b) => stable(a) === stable(b);
const problems = [];
const problem = (id, msg) => problems.push(`${id}: ${msg}`);

// ---------------------------------------------------------------- envelope data
const registry = JSON.parse(readFileSync(path.join(ROOT, 'caid/registry/action-types.json'), 'utf8'));
const enumSnapshots = registry.enum_snapshot_files.map((entry) => {
  const file = JSON.parse(readFileSync(path.join(ROOT, 'caid/registry', entry.path), 'utf8'));
  return { values_ref: file.values_ref, values_snapshot: file.values_snapshot, values_sha256: file.values_sha256, values: file.values };
});
const v4Bytes = readFileSync(path.join(ROOT, V4_PATH));
if (sha256(v4Bytes) !== V4_SHA256) throw new Error(`${V4_PATH} is not the frozen version 4 corpus`);
const v4Text = v4Bytes.toString('utf8');
const v4 = JSON.parse(v4Text);
const v4Spans = rawSpans(v4Text, (p) => p.length === 4 && p[0] === 'vectors' && p[2] === 'input' && p[3] === 'object');

// ---------------------------------------------------------------- evaluation
function inputValue(input) {
  if (Object.prototype.hasOwnProperty.call(input, 'native')) return { native: buildNative(input.native) };
  return { bytes: inputBytes(input) };
}

function evaluate(kind, input, definitions) {
  /** @type {Record<string, any>} */
  const opts = { definitions, enum_snapshots: enumSnapshots };
  if (kind === 'decode') {
    const bytes = inputBytes(input);
    if (!bytes) throw new Error('decode vector without JSON text input');
    const r = oracle.decode(bytes);
    return r.ok ? { ok: true } : { ok: false, refusals: r.refusals };
  }
  if (kind === 'parse') return oracle.parse(input.caid);
  if (kind === 'definition') return oracle.definitionSha256(input.definition);
  const v = inputValue(input);
  if (kind === 'compute') {
    const o = { ...opts };
    if (Object.prototype.hasOwnProperty.call(input, 'suite')) o.suite = input.suite;
    return v.native !== undefined || Object.prototype.hasOwnProperty.call(input, 'native') ? oracle.compute(v.native, o) : oracle.computeText(v.bytes, o);
  }
  if (kind === 'verify') {
    const o = { ...opts };
    if (Object.prototype.hasOwnProperty.call(input, 'expected_definition_sha256')) o.expected_definition_sha256 = input.expected_definition_sha256;
    return Object.prototype.hasOwnProperty.call(input, 'native') ? oracle.verify(v.native, input.caid, o) : oracle.verifyText(v.bytes, input.caid, o);
  }
  throw new Error(`unknown kind ${kind}`);
}

// Canonical member order of each expectation shape.
function shapeExpect(kind, r) {
  if (kind === 'decode') return r.ok ? { ok: true } : { ok: false, refusals: r.refusals };
  if (kind === 'parse') return r.ok ? { ok: true, caid: r.caid } : { ok: false, refusals: r.refusals };
  if (kind === 'definition') return r.definition_sha256 ? { definition_sha256: r.definition_sha256 } : { refusals: r.refusals };
  if (kind === 'compute') return r.caid ? { caid: r.caid, digest: r.digest, definition_sha256: r.definition_sha256 } : { refusals: r.refusals };
  const out = { valid: r.valid, reasons: r.reasons, details: r.details };
  if (r.definition_sha256 !== undefined) out.definition_sha256 = r.definition_sha256;
  return out;
}

// ---------------------------------------------------------------- version 4 vectors
const vectors = [];
const v4Results = new Map();
v4.vectors.forEach((old, index) => {
  const change = V4_CHANGES[old.id];
  const input = {};
  if (old.kind === 'compute' || old.kind === 'verify') {
    const raw = v4Spans.get(JSON.stringify(['vectors', index, 'input', 'object']));
    if (raw === undefined) throw new Error(`no raw text for ${old.id}`);
    input.json = minify(raw);
  }
  for (const [k, x] of Object.entries(old.input)) if (k !== 'object') input[k] = x;
  const r = evaluate(old.kind, input, old.definitions);
  const expect = shapeExpect(old.kind, r);
  // Compare with the version 4 result.
  if (old.kind === 'compute') {
    if (old.expect.caid !== undefined) {
      if (expect.caid !== old.expect.caid || expect.digest !== old.expect.digest) problem(old.id, `version 4 CAID ${old.expect.caid} not reproduced: ${JSON.stringify(expect)}`);
      else v4Results.set(old.id, old.expect.caid);
    } else if (!same(expect.refusals, change ? change.to : old.expect.refusals)) problem(old.id, `refusals ${JSON.stringify(expect.refusals)}, version 4 ${JSON.stringify(old.expect.refusals)}`);
  } else if (old.kind === 'verify') {
    if (expect.valid !== (change ? false : old.expect.valid) || !same(expect.reasons, change ? change.to : old.expect.reasons)) problem(old.id, `verify ${JSON.stringify(expect.reasons)}, version 4 ${JSON.stringify(old.expect.reasons)}`);
  } else if (old.kind === 'parse') {
    const want = change ? { ok: false, refusals: change.to } : old.expect;
    if (!same(expect, want)) problem(old.id, `parse ${JSON.stringify(expect)}, version 4 ${JSON.stringify(old.expect)}`);
  }
  const description = change ? `${old.description} Version 5: ${change.rule}` : old.description;
  const out = { id: old.id, kind: old.kind, description };
  if (old.definitions && old.kind !== 'parse') out.definitions = old.definitions;
  out.input = input;
  out.expect = expect;
  if (old.relation) out.relation = old.relation;
  vectors.push(out);
});

// ---------------------------------------------------------------- registry types
const CODE_SAMPLES = {
  'icd-10-cm': 'A00', 'ndc-11': '00002322730', 'ndc-10-hyphenated': '0002-3227-30', cpt: '99213', 'hcpcs-level-ii': 'J1234',
  hcpcs: 'J1234', 'iso-3166-1-alpha-2': 'US', 'iso-3166-2': 'US-CA', 'iso20022-external-code': 'AC01', 'nacha-sec': 'PPD',
};
function sampleValue(field) {
  switch (field.type) {
    case 'string': return 'x';
    case 'amount-string': return '1.00';
    case 'digest': return 'sha256:' + '0'.repeat(64);
    case 'timestamp': return '2026-09-26T00:00:00Z';
    case 'integer': return 1;
    case 'boolean': return true;
    case 'object': return {};
    case 'array': return [];
    case 'code': return CODE_SAMPLES[field.format];
    case 'enum': {
      if (Array.isArray(field.values)) return field.values[0];
      if (typeof field.values_ref === 'string' && field.values_ref.startsWith('inline:')) return field.values_ref.slice(7).split('|')[0].trim();
      const snap = enumSnapshots.find((s) => s.values_ref === field.values_ref && s.values_snapshot === field.values_snapshot && s.values_sha256 === field.values_sha256);
      return snap ? snap.values[0] : undefined;
    }
    default: return undefined;
  }
}
for (const type of registry.types) {
  const object = { action_type: type.action_type };
  for (const [list, required] of [[type.required_fields ?? [], true], [type.optional_fields ?? [], false]]) {
    for (const field of list) {
      const v = sampleValue(field);
      if (v !== undefined) object[field.name] = v;
      else if (required) object[field.name] = 'x';
    }
  }
  const input = { json: JSON.stringify(object), suite: 'jcs-sha256' };
  const expect = shapeExpect('compute', evaluate('compute', input, [type]));
  if (type.status === 'active' && !expect.caid) problem(`registry-${type.action_type}`, `active type does not compute: ${JSON.stringify(expect)}`);
  vectors.push({
    id: `registry-${type.action_type}`,
    kind: 'compute',
    description: `registry version ${registry.meta.registry_version} type ${type.action_type} (${type.status}) with every field it can resolve${type.status === 'deprecated' ? '; status never gates computation' : ''}`,
    definitions: [type],
    input,
    expect,
  });
}

// ---------------------------------------------------------------- hand-written cases
const limits = oracle.spec.limits;
for (const c of coreCases({ limits: { json_text_octets: limits.json_text_octets, canonical_octets: limits.canonical_octets } })) {
  const input = { ...c.input };
  if (input.caid_of) {
    const of = input.caid_of;
    const r = of.native !== undefined
      ? oracle.compute(buildNative(of.native), { suite: 'jcs-sha256', definitions: of.definitions, enum_snapshots: enumSnapshots })
      : oracle.computeText(Buffer.from(of.json, 'utf8'), { suite: 'jcs-sha256', definitions: of.definitions, enum_snapshots: enumSnapshots });
    if (!r.caid) throw new Error(`${c.id}: caid_of does not compute: ${JSON.stringify(r)}`);
    delete input.caid_of;
    input.caid = r.caid;
  }
  if (input.expected_definition_sha256 && typeof input.expected_definition_sha256 === 'object') {
    input.expected_definition_sha256 = oracle.definitionSha256(input.expected_definition_sha256.of).definition_sha256;
  }
  // Member order: forms first, then caid / expected / suite.
  const ordered = {};
  for (const k of ['json', 'json_b64', 'json_repeat', 'native', 'caid', 'expected_definition_sha256', 'definition', 'suite']) {
    if (Object.prototype.hasOwnProperty.call(input, k)) ordered[k] = input[k];
  }
  const r = evaluate(c.kind, ordered, c.definitions);
  const expect = shapeExpect(c.kind, r);
  const s = c.expect;
  const bad = (msg) => problem(c.id, `${msg}; oracle ${JSON.stringify(expect).slice(0, 400)}`);
  if (c.kind === 'decode') { if (expect.ok !== s) bad(`stated ${s}`); }
  else if (c.kind === 'parse') { if (s === 'ok' ? !expect.ok : !same(expect.refusals, s.refusals)) bad(`stated ${JSON.stringify(s)}`); }
  else if (c.kind === 'definition') { if ((s === 'ok') !== Boolean(expect.definition_sha256)) bad(`stated ${s}`); }
  else if (c.kind === 'compute') { if (s === 'ok' ? !expect.caid : !same(expect.refusals, s.refusals)) bad(`stated ${JSON.stringify(s)}`); }
  else if (c.kind === 'verify') { if (s === 'valid' ? !expect.valid : (expect.valid || !same(expect.reasons, s.reasons))) bad(`stated ${JSON.stringify(s)}`); }
  const out = { id: c.id, kind: c.kind, description: c.description };
  if (c.definitions !== undefined && c.kind !== 'parse' && c.kind !== 'decode' && c.kind !== 'definition') out.definitions = c.definitions;
  out.input = ordered;
  out.expect = expect;
  if (c.relation) out.relation = c.relation;
  if (c.time_budget_ms) out.time_budget_ms = c.time_budget_ms;
  out._same = c.same_definition_sha256_as;
  out._different = c.different_definition_sha256_from;
  vectors.push(out);
}

// ---------------------------------------------------------------- cross-vector checks
const byId = new Map();
for (const v of vectors) {
  if (byId.has(v.id)) problem(v.id, 'duplicate id');
  byId.set(v.id, v);
}
for (const v of vectors) {
  if (v.relation) {
    const other = byId.get(v.relation.same_caid_as ?? v.relation.different_caid_from);
    if (!other || !v.expect.caid || !other.expect.caid) problem(v.id, 'relation needs two computed CAIDs');
    else if (v.relation.same_caid_as && v.expect.caid !== other.expect.caid) problem(v.id, `same_caid_as ${other.id} fails`);
    else if (v.relation.different_caid_from && v.expect.caid === other.expect.caid) problem(v.id, `different_caid_from ${other.id} fails`);
  }
  for (const [key, want] of [['_same', true], ['_different', false]]) {
    if (!v[key]) continue;
    const other = byId.get(v[key]);
    if (!other || (v.expect.definition_sha256 === other.expect.definition_sha256) !== want) problem(v.id, `${key} ${v[key]} fails`);
  }
  delete v._same;
  delete v._different;
}
// Registry digests: every registry vector's definition_sha256 equals digests.json.
const digests = JSON.parse(readFileSync(path.join(ROOT, 'caid/registry/digests.json'), 'utf8'));
const digestOf = new Map((digests.types ?? digests.digests ?? []).map((d) => [d.action_type, d.definition_sha256]));
for (const v of vectors) {
  if (!v.id.startsWith('registry-') || !v.expect.definition_sha256) continue;
  const want = digestOf.get(v.id.slice('registry-'.length));
  if (want !== v.expect.definition_sha256) problem(v.id, `definition_sha256 ${v.expect.definition_sha256} differs from digests.json ${want}`);
}

if (problems.length) {
  process.stderr.write(`build-core: ${problems.length} problem(s)\n${problems.map((p) => `  ${p}`).join('\n')}\n`);
  process.exit(1);
}

// ---------------------------------------------------------------- write
const counts = {};
for (const v of vectors) {
  const lane = v.input.native !== undefined ? 'native' : 'text';
  const key = v.kind === 'compute' || v.kind === 'verify' ? `${v.kind}:${lane}` : v.kind;
  counts[key] = (counts[key] ?? 0) + 1;
}
const envelope = {
  '@version': 'CAID-CORE-VECTORS',
  version: 5,
  suite_note: 'Shared cross-language CAID conformance vectors for draft-schrock-canonical-action-identifier-04. Each vector carries its own inline type definitions and never references the public registry, except the registry-* vectors, which copy one registry entry each. CAID carries no trust semantics: these vectors test identification only, not authorization, identity, or proof.',
  format: {
    kinds: 'decode: decode the input octets as JSON text (Section 2.4); expect {ok} or {ok:false, refusals:["malformed_json"]}. parse: strict CAID parse of input.caid. compute: compute over the input with options suite (input.suite, passed as given, whatever its JSON type; absent means no suite), definitions (the vector member, passed as given) and enum_snapshots (this file); expect {caid, digest, definition_sha256} or {refusals}. verify: verify the input against input.caid with definitions, enum_snapshots and, when present, expected_definition_sha256 (passed as given); expect {valid, reasons, details, definition_sha256?}. definition: definition_sha256 of input.definition; expect {definition_sha256} or {refusals:["invalid_definition"]}.',
    inputs: 'Exactly one input form: input.json is a string whose UTF-8 encoding is the JSON text; input.json_b64 is the exact octets, base64; input.json_repeat {prefix, unit, count, suffix} is UTF-8(prefix) + count copies of UTF-8(unit) + UTF-8(suffix); input.native is a native-lane value (caid/conformance/runners/native.mjs describes the encoding). A runner calls the byte entry point for the first three forms and, when the octets decode, also the native entry point on the decoded value, and requires identical results. For input.native it builds the host value and calls the native entry point only.',
    relations: 'relation.same_caid_as / different_caid_from compare the CAIDs the implementation computes for two vectors. time_budget_ms bounds the wall time of the byte entry-point call.',
  },
  counts,
  previous_versions: [
    ...v4.previous_versions,
    {
      version: 4,
      vectors: v4.vectors.length,
      sha256: V4_SHA256,
      history: V4_PATH,
      note: `Byte digest of the version 4 corpus as last published on main (pull request #815), kept byte for byte at ${V4_PATH}. Version 5 carries every version 4 vector under the same id with its object as exact JSON text; each of the ${v4Results.size} version 4 vectors that computed a CAID reproduces it (checked by caid/conformance/check-v4.mjs). Results change for six vectors, each by a named -04 rule: three unpaired-surrogate vectors are malformed_json on the byte path (their native-lane twins keep unsupported_value), and the three unregistered-suite vectors are unknown_suite at parse. Every successful compute adds definition_sha256, and every verification adds details and, when a definition resolved, definition_sha256.`,
    },
  ],
  enum_snapshots: enumSnapshots,
};
const head = JSON.stringify(envelope, null, 2);
const body = vectors.map((v) => '    ' + JSON.stringify(v)).join(',\n');
const text = `${head.slice(0, -2)},\n  "vectors": [\n${body}\n  ]\n}\n`;
// The corpus itself must pass the strict decoder it tests.
const self = decodeStrict(new Uint8Array(Buffer.from(text, 'utf8')), { maxOctets: null });
if (!self.ok) throw new Error(`vectors.json is not strict I-JSON: ${self.detail}`);
if (process.argv.includes('--check')) {
  let current = '';
  try { current = readFileSync(OUT, 'utf8'); } catch { /* missing */ }
  if (current !== text) {
    process.stderr.write('build-core: caid/conformance/vectors.json is not current; run node caid/conformance/tools/build-core.mjs\n');
    process.exit(1);
  }
  console.log(`PASS core corpus v5 is current (${vectors.length} vectors, ${JSON.stringify(counts)})`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote caid/conformance/vectors.json: ${vectors.length} vectors ${JSON.stringify(counts)}; ${v4Results.size} version 4 CAIDs reproduced`);
}
