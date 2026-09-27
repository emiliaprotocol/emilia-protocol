#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Builds the curated grammar boundary corpus
// (caid/conformance/grammar-vectors.json).
//
//   node caid/conformance/tools/build-grammar.mjs           write it
//   node caid/conformance/tools/build-grammar.mjs --check   exit 1 unless current
//   ... --cases FILE   reuse the case list caid/spec/abnf-check.mjs --out
//                      already wrote (CI's grammar proof step writes one)
//                      instead of running it again; the list is the same
//                      with or without --js-only and --no-timing
//
// The corpus tests each port through its public entry points, never its
// generated regular expressions (review D-3): every ABNF rule the ports
// enforce has a driver that places the case string into a one-field type
// definition and action object (compute) or into a CAID string (parse).
// Cases are a deterministic, evenly spread subset of the membership cases
// caid/spec/abnf-check.mjs generates, plus curated astral, lone-surrogate
// (native lane), invalid-UTF-8 (byte lane), noncharacter and long cases.
// Each case records the ABNF interpreter's verdict ("grammar") and the exact
// expected result, computed by the spec oracle. The builder fails when a
// result contradicts the grammar verdict in a way the driver does not
// explain.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { matches } from '../../spec/abnf.mjs';
import { loadCaidGrammar } from '../../spec/gen.mjs';
import * as oracle from './oracle.mjs';
import { decodeStrict, hasLoneSurrogate, hasNoncharacter } from './strict-json.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../../..');
const OUT = path.join(ROOT, 'caid/conformance/grammar-vectors.json');
const PER_VERDICT = 40;
const VALID_DIGEST = 'liLG9pKgkLt3silrjf1wa0xIHz5YFrBB9HI-arxrO1Y';
const { rules } = loadCaidGrammar(ROOT);
const CODE_SYSTEMS = {
  'icd-10-cm': 'http://hl7.org/fhir/sid/icd-10-cm',
  'ndc-11': 'http://hl7.org/fhir/sid/ndc',
  'ndc-10-hyphenated': 'http://hl7.org/fhir/sid/ndc',
  cpt: 'http://www.ama-assn.org/go/cpt',
  'hcpcs-level-ii': 'https://www.cms.gov/Medicare/Coding/HCPCSReleaseCodeSets',
  hcpcs: 'https://www.cms.gov/Medicare/Coding/HCPCSReleaseCodeSets',
  'iso-3166-2': 'urn:iso:std:iso:3166:-2',
  'iso20022-external-code': 'https://www.iso20022.org/catalogue-messages/additional-content-messages/external-code-sets',
  'nacha-sec': 'https://www.nacha.org/rules/standard-entry-class-codes',
};

// ---------------------------------------------------------------- drivers
const oneField = (type, extra = {}) => {
  const at = `grammar.${type}.1`;
  return { definition: { action_type: at, required_fields: [{ name: 'f', type, ...extra }] }, object: { action_type: at, f: '$CASE' } };
};
const DRIVERS = {
  caid: { rule: 'caid', source: 'pattern:caid', operation: 'parse', caid: { prefix: '', suffix: '' } },
  'action-type.compute': { rule: 'action-type', source: 'pattern:action_type', operation: 'compute', definition: { action_type: '$CASE', required_fields: [{ name: 'f', type: 'string' }] }, object: { action_type: '$CASE', f: 'x' } },
  'action-type.parse': { rule: 'action-type', source: 'pattern:action_type', operation: 'parse', caid: { prefix: 'caid:1:', suffix: `:jcs-sha256:${VALID_DIGEST}` } },
  'suite.parse': { rule: 'suite', source: 'pattern:suite', operation: 'parse', caid: { prefix: 'caid:1:a.1:', suffix: `:${VALID_DIGEST}` } },
  'suite.compute': { rule: 'suite', source: 'pattern:suite', operation: 'compute', definition: { action_type: 'grammar.suite.1', required_fields: [{ name: 'f', type: 'string' }] }, object: { action_type: 'grammar.suite.1', f: 'x' }, suite: '$CASE' },
  'digest-256.parse': { rule: 'digest-256', source: 'suite_digest:jcs-sha256', operation: 'parse', caid: { prefix: 'caid:1:a.1:jcs-sha256:', suffix: '' } },
  'amount-string': { rule: 'amount-string', source: 'pattern:amount_string', operation: 'compute', ...oneField('amount-string') },
  'digest-field': { rule: 'digest-field', source: 'pattern:digest_field', operation: 'compute', ...oneField('digest') },
  timestamp: { rule: 'timestamp', source: 'pattern:timestamp', operation: 'compute', ...oneField('timestamp') },
  ...Object.fromEntries(Object.keys(CODE_SYSTEMS).map((format) => [`code.${format}`, {
    rule: format, source: `code_format:${format}`, operation: 'compute', ...oneField('code', { code_system: CODE_SYSTEMS[format], format }),
  }])),
  'format-name': {
    rule: 'format-name', source: 'pattern:format_name', operation: 'compute',
    definition: { action_type: 'grammar.format-name.1', required_fields: [{ name: 'f', type: 'code', code_system: 'http://example.org/codes', format: '$CASE' }] },
    object: { action_type: 'grammar.format-name.1', f: 'A00' },
  },
  'code-system': {
    rule: 'code-system', source: 'pattern:code_system', operation: 'compute',
    definition: { action_type: 'grammar.code-system.1', required_fields: [{ name: 'f', type: 'code', code_system: '$CASE', format: 'icd-10-cm' }] },
    object: { action_type: 'grammar.code-system.1', f: 'A00' },
  },
  'field-name': {
    rule: 'field-name', source: null, operation: 'compute',
    definition: { action_type: 'grammar.field-name.1', required_fields: [{ name: '$CASE', type: 'string' }] },
    object: { action_type: 'grammar.field-name.1', $CASE: 'x' },
  },
};

// ---------------------------------------------------------------- case sources
const casesArg = process.argv.indexOf('--cases');
let generated;
if (casesArg !== -1) {
  generated = JSON.parse(readFileSync(path.resolve(process.argv[casesArg + 1] ?? ''), 'utf8')).cases;
} else {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'caid-grammar-'));
  const listPath = path.join(tmp, 'cases.json');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'caid/spec/abnf-check.mjs'), '--js-only', '--no-timing', '--out', listPath], { encoding: 'utf8', maxBuffer: 64 << 20 });
  if (r.status !== 0) { process.stderr.write(r.stdout + r.stderr); process.exit(1); }
  generated = JSON.parse(readFileSync(listPath, 'utf8')).cases;
  rmSync(tmp, { recursive: true, force: true });
}
const byRule = new Map();
for (const c of generated) {
  if (!byRule.has(c.rule)) byRule.set(c.rule, []);
  byRule.get(c.rule).push(c);
}

const spread = (list, n) => {
  if (list.length <= n) return list;
  const out = [];
  for (let i = 0; i < n; i += 1) out.push(list[Math.floor((i * list.length) / n)]);
  return out;
};
const units = (s) => ({ $units: Array.from({ length: s.length }, (_, i) => s.charCodeAt(i)) });
const isAstral = (s) => /[\u{10000}-\u{10FFFF}]/u.test(s);

// Curated extras per driver: [case string, lane] or [{repeat}|{b64}, lane].
const rep = (prefix, unit, count, suffix = '') => ({ repeat: { prefix, unit, count, suffix } });
const EXTRAS = {
  // The length limits of Section 2.6: an action type of at most 512 octets
  // and a CAID of at most 1024, each checked before any pattern runs. Cases
  // at the limit and one octet over it, and strings of millions of
  // characters, which a backtracking engine could not match.
  caid: [[rep('caid:1:', 'a', 510, `.1:jcs-sha256:${VALID_DIGEST}`), 'text'], [rep('caid:1:', 'a', 511, `.1:jcs-sha256:${VALID_DIGEST}`), 'text'],
    [rep('caid:1:', 'a', 8000000, `.1:jcs-sha256:${VALID_DIGEST}`), 'text'], [rep('caid:1:A', 'a', 70000, `.1:jcs-sha256:${VALID_DIGEST}`), 'text'], [`caid:1:a.1:jcs-sha256:${VALID_DIGEST.slice(0, 42)}\u{1F600}`, 'text']],
  'action-type.compute': [[rep('a', 'b', 509, '.1'), 'text'], [rep('a', 'b', 510, '.1'), 'text'], [rep('a.', '9', 510), 'text'], [rep('a.', '9', 511), 'text'], [rep('a', 'b', 8000000, '.1'), 'text'],
    [rep('A', 'b', 70000, '.1'), 'text'], [rep('a', 'b', 70000, '.01'), 'text'], ['a\u{1F600}.1', 'text'], ['a.1\u{1F600}', 'text'], ['a\ud800.1', 'native'], ['a.\udfff1', 'native'], ['a￾.1', 'text']],
  'action-type.parse': [['a\ud800.1', 'native'], [rep('a', 'b', 509, '.1'), 'text'], [rep('a', 'b', 510, '.1'), 'text'], [rep('a', 'b', 8000000, '.1'), 'text'], [rep('a', 'b', 70000, '.1.'), 'text']],
  'suite.parse': [['jcs-sha256\u{1F600}', 'text'], ['jcs\ud800', 'native'], [rep('x', 'y', 70000), 'text']],
  'suite.compute': [['jcs-sha256\n', 'text'], ['JCS-SHA256', 'text'], ['jcs-sha256\u0000', 'text'], ['jcs-sha256\ud800', 'native'], ['cbor-sha256', 'text']],
  'digest-256.parse': [[VALID_DIGEST, 'text'], [`${VALID_DIGEST.slice(0, 42)}\ud800`, 'native'], [rep('', 'A', 70000), 'text']],
  'amount-string': [[rep('1', '0', 70000), 'text'], [rep('0.', '0', 70000), 'text'], [rep('', '1', 70000, 'x'), 'text'], ['1\u{1F600}', 'text'], ['1\ud800', 'native'], ['\udc001', 'native'], ['1￿', 'text']],
  'digest-field': [[`sha256:${'a'.repeat(63)}\u{1F600}`, 'text'], [`sha256:${'a'.repeat(63)}\ud800`, 'native'], [rep('sha256:', 'a', 70000), 'text']],
  timestamp: [[rep('2026-07-08T09:30:00.', '1', 70000, 'Z'), 'text'], ['2026-07-08T09:30:00\u{1F600}Z', 'text'], ['2026-07-08T09:30:00Z\ud800', 'native'], ['2026-02-29T00:00:00Z', 'text'], ['2024-02-29T00:00:00Z', 'text'], ['2026-04-31T00:00:00Z', 'text']],
  'format-name': [['icd-10-cm', 'text'], ['cpt', 'text'], ['loinc', 'text'], ['ICD-10-CM', 'text'], ['icd_10_cm', 'text'], ['icd\ud800', 'native'], [rep('a', 'b', 70000), 'text']],
  'code-system': [['http://hl7.org/fhir/sid/icd-10-cm', 'text'], ['urn:oid:2.16.840.1.113883.6.90', 'text'], ['icd-10-cm', 'text'], ['http://example.org/#frag', 'text'], ['http://example.org/%zz', 'text'], ['http://exämple.org', 'text'], ['http://example.org/\ud800', 'native'],
    [rep('urn:', 'x', 2044), 'text'], [rep('urn:', 'x', 2045), 'text'], [rep('urn:', 'x', 70000), 'text'], [rep('urn:', 'x', 9000000), 'text']],
  'field-name': [
    ['f', 'text'], ['@version', 'text'], ['_', 'text'], ['-', 'text'], ['0', 'text'], ['a b', 'text'], ['Café', 'text'], ['\u{1F600}', 'text'],
    ['toString', 'text'], ['__proto__', 'text'], ['constructor', 'text'], ['hasOwnProperty', 'text'], ['Action_type', 'text'], [' action_type', 'text'],
    ['action_type ', 'text'], ['\u0000', 'text'], ['tab\there', 'text'], [' ', 'text'], ['﻿', 'text'], ['�', 'text'],
    ['', 'text'], [':', 'text'], ['a:b', 'text'], ['action_type', 'text'], ['：', 'text'], ['￾', 'text'], ['﷐', 'native'],
    ['a\ud800', 'native'], ['\udc00', 'native'], [rep('', 'x', 70000), 'text'], [rep('', '\u{1F600}', 20000), 'text'],
  ],
};
for (const format of Object.keys(CODE_SYSTEMS)) {
  EXTRAS[`code.${format}`] = [['A00\u{1F600}', 'text'], ['A0\ud800', 'native'], [rep('', 'A', 70000), 'text'], ['Ａ００', 'text']];
}
const BAD_UTF8 = [[0xff], [0xc3], [0xed, 0xa0, 0x80], [0xc0, 0xaf], [0xf4, 0x90, 0x80, 0x80]];
const MAX = oracle.spec.pattern_max_octets;
const LENGTH_LIMITS = {
  'action-type.compute': { max: MAX.action_type, refusal: 'invalid_action_type' },
  'action-type.parse': { max: MAX.action_type, refusal: 'malformed_caid' },
  'code-system': { max: MAX.code_system, refusal: 'invalid_definition' },
};

// ---------------------------------------------------------------- evaluation
const PLACEHOLDER = '@@CASE@@';
function substitute(template, value) {
  if (template === '$CASE') return value;
  if (Array.isArray(template)) return template.map((x) => substitute(x, value));
  if (template && typeof template === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(template)) {
      const key = k === '$CASE' ? value : k;
      Object.defineProperty(out, key, { value: substitute(v, value), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return template;
}
const caseString = (c) => (typeof c === 'string' ? c : c.$units ? String.fromCharCode(...c.$units)
  : c.repeat ? c.repeat.prefix + c.repeat.unit.repeat(c.repeat.count) + c.repeat.suffix : null);

function run(driver, encodedCase, lane) {
  const d = DRIVERS[driver];
  const opts = (defs) => ({ definitions: defs, enum_snapshots: [] });
  if (d.operation === 'parse') return oracle.parse(d.caid.prefix + caseString(encodedCase) + d.caid.suffix);
  if (lane === 'bytes') {
    const def = substitute(d.definition, PLACEHOLDER);
    const text = JSON.stringify(substitute(d.object, PLACEHOLDER));
    const raw = Buffer.from(encodedCase.b64, 'base64');
    const parts = text.split(PLACEHOLDER).map((p) => Buffer.from(p, 'utf8'));
    const bytes = Buffer.concat(parts.flatMap((p, i) => (i ? [raw, p] : [p])));
    return oracle.computeText(new Uint8Array(bytes), { ...opts([def]), suite: d.suite === '$CASE' ? PLACEHOLDER : 'jcs-sha256' });
  }
  const s = caseString(encodedCase);
  const def = substitute(d.definition, s);
  const obj = substitute(d.object, s);
  const suite = d.suite === '$CASE' ? s : 'jcs-sha256';
  if (lane === 'native') return oracle.compute(obj, { ...opts([def]), suite });
  const text = JSON.stringify(obj);
  return oracle.computeText(new Uint8Array(Buffer.from(text, 'utf8')), { ...opts([def]), suite });
}

function shape(operation, r) {
  if (operation === 'parse') return r.ok ? { ok: true, caid: r.caid } : { ok: false, refusals: r.refusals };
  // The core corpus pins the whole result shape; here the CAID stands for it.
  return r.caid ? { caid: r.caid } : { refusals: r.refusals };
}

// ---------------------------------------------------------------- selection
const cases = [];
const problems = [];
const seen = new Set();
function addCase(driver, encoded, lane, grammarVerdict) {
  const key = JSON.stringify([driver, encoded, lane]);
  if (seen.has(key)) return;
  seen.add(key);
  const d = DRIVERS[driver];
  if (lane === 'bytes' && !JSON.stringify(d.object ?? null).includes('$CASE')) return;
  const expect = shape(d.operation, run(driver, encoded, lane));
  const entry = { driver, lane, case: encoded };
  if (grammarVerdict !== undefined) entry.grammar = grammarVerdict;
  entry.expect = expect;
  // The result must follow the grammar verdict, except where the driver's
  // other rules decide first: the registry and digest syntax at parse, the
  // calendar for timestamps, format registration, the suite registry,
  // JSON text refusals, and data-model refusals of the case string itself.
  if (grammarVerdict !== undefined && lane === 'text') {
    const s = caseString(encoded);
    const accepted = d.operation === 'parse' ? expect.ok : Boolean(expect.caid);
    const refusal = expect.refusals ? expect.refusals[0] : null;
    let explained = refusal === 'malformed_json' || hasNoncharacter(s);
    // A string the grammar accepts but that is over its length limit
    // (Section 2.6) is refused by the limit.
    const limit = LENGTH_LIMITS[driver];
    if (grammarVerdict && !accepted && limit && s.length > limit.max) explained ||= refusal === limit.refusal;
    if (grammarVerdict && !accepted && d.operation === 'parse' && (d.caid.prefix + s + d.caid.suffix).length > MAX.caid) explained ||= refusal === 'malformed_caid';
    if (grammarVerdict && !accepted) {
      if (driver === 'caid') explained ||= refusal === 'unknown_suite' || refusal === 'malformed_caid';
      if (driver === 'suite.parse' || driver === 'suite.compute') explained ||= refusal === 'unknown_suite';
      if (driver === 'timestamp') explained ||= refusal === 'mistyped_field:f';
      if (driver === 'format-name') explained ||= refusal === 'mistyped_field:f' || refusal === 'invalid_code:f';
      // As a member name, "action_type" replaces the object's action type.
      if (driver === 'field-name') explained ||= s === 'action_type' && refusal === 'invalid_action_type';
    }
    if (accepted !== grammarVerdict && !explained) problems.push(`${driver} ${JSON.stringify(s).slice(0, 80)}: grammar ${grammarVerdict}, result ${JSON.stringify(expect).slice(0, 120)}`);
  }
  cases.push(entry);
}
const encodeString = (s) => (hasLoneSurrogate(s) || hasNoncharacter(s) ? units(s) : s);

for (const [driver, d] of Object.entries(DRIVERS)) {
  if (d.source) {
    const list = byRule.get(d.source) ?? [];
    if (!list.length) throw new Error(`abnf-check produced no cases for ${d.source}`);
    const plain = list.filter((c) => c.input.length <= 512);
    const pick = [
      ...spread(plain.filter((c) => c.match), PER_VERDICT),
      ...spread(plain.filter((c) => !c.match), PER_VERDICT),
      ...spread(plain.filter((c) => isAstral(c.input)), 3),
      ...spread(plain.filter((c) => /[^\x00-\x7f]/.test(c.input) && !isAstral(c.input) && !hasLoneSurrogate(c.input)), 4),
    ];
    for (const c of pick) {
      if (hasLoneSurrogate(c.input)) continue;
      addCase(driver, encodeString(c.input), 'text', c.match);
    }
    for (const c of spread(plain.filter((x) => hasLoneSurrogate(x.input)), 3)) addCase(driver, units(c.input), 'native', c.match);
  }
  for (const [c, lane] of EXTRAS[driver] ?? []) {
    const s = caseString(c);
    const verdict = d.rule && rules.has(d.rule) && s.length < 200000 ? matches(rules, d.rule, s) : undefined;
    addCase(driver, typeof c === 'string' ? encodeString(c) : c, lane, verdict);
  }
  if (d.operation === 'compute') for (const b of BAD_UTF8) addCase(driver, { b64: Buffer.from([0x78, ...b]).toString('base64') }, 'bytes');
}

if (problems.length) {
  process.stderr.write(`build-grammar: ${problems.length} problem(s)\n${problems.map((p) => `  ${p}`).join('\n')}\n`);
  process.exit(1);
}

// ---------------------------------------------------------------- write
const counts = {};
for (const c of cases) counts[c.driver] = (counts[c.driver] ?? 0) + 1;
const envelope = {
  '@version': 'CAID-GRAMMAR-VECTORS',
  version: 1,
  description: 'Curated grammar boundary cases for draft-schrock-canonical-action-identifier-04 Appendix A, run through each implementation\'s public entry points (parse and compute with one-field type definitions), never its generated regular expressions. grammar is the ABNF interpreter\'s verdict for the case string alone; expect is the exact result, which the driver\'s other rules (suite registry, digest syntax, calendar, format registration, JSON text and data-model refusals) can decide first.',
  format: {
    drivers: 'A parse driver parses caid.prefix + CASE + caid.suffix. A compute driver computes over object with definitions [definition] and the suite (jcs-sha256 unless the driver names "$CASE"), where every string "$CASE", as a value or a member name, is replaced by the case string.',
    cases: 'case is a string, {"$units": [UTF-16 code units]} (a string that may hold lone surrogates or noncharacters), {"repeat": {prefix, unit, count, suffix}}, or {"b64": octets}. Lane text: serialize the substituted object as JSON text (any correct encoder), call the byte entry point, and when the text decodes also the native entry point on the decoded value; the results must be identical. Lane native: build the host values and call the native entry point only. Lane bytes: serialize the object with the case replaced by the placeholder @@CASE@@, replace each occurrence of @@CASE@@ in the text with the raw case octets, and call the byte entry point. A compute expectation is {caid} (compare the computed CAID only; the core corpus pins the rest of the result) or {refusals} (compare exactly); a parse expectation is the exact parse result.',
  },
  source: 'node caid/spec/abnf-check.mjs --out (membership cases), spread deterministically; curated extras in caid/conformance/tools/build-grammar.mjs',
  counts,
  placeholder: PLACEHOLDER,
  drivers: Object.fromEntries(Object.entries(DRIVERS).map(([k, d]) => {
    const { source, ...rest } = d;
    return [k, rest];
  })),
};
const head = JSON.stringify(envelope, null, 2);
const text = `${head.slice(0, -2)},\n  "cases": [\n${cases.map((c) => '    ' + JSON.stringify(c)).join(',\n')}\n  ]\n}\n`;
const self = decodeStrict(new Uint8Array(Buffer.from(text, 'utf8')), { maxOctets: null });
if (!self.ok) throw new Error(`grammar-vectors.json is not strict I-JSON: ${self.detail}`);
if (process.argv.includes('--check')) {
  let current = '';
  try { current = readFileSync(OUT, 'utf8'); } catch { /* missing */ }
  if (current !== text) {
    process.stderr.write('build-grammar: caid/conformance/grammar-vectors.json is not current; run node caid/conformance/tools/build-grammar.mjs\n');
    process.exit(1);
  }
  console.log(`PASS grammar corpus is current (${cases.length} cases)`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote caid/conformance/grammar-vectors.json: ${cases.length} cases ${JSON.stringify(counts)}`);
}
