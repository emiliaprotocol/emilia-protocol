#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Checks the staged draft-schrock-canonical-action-identifier-04 packet
// (standards/staged/NEXT-CAID-04) against the sources it restates:
//
//   - Appendix A equals caid/spec/caid.abnf byte for byte;
//   - Appendix D (the initial CAID Action Types) equals the registry and
//     digests.json;
//   - Appendix B (core and mapping reasons), the verification detail table
//     and the limits table equal the tables generated below from
//     caid/spec/core.json;
//   - every value in Appendix C, the identifier example of Section 3.3 and
//     the tool.call.1 example recompute, through the reference validator
//     (caid/spec/reference.mjs) and through hashing done here;
//   - every item of "Changes since -03" that states a processing or registry
//     change maps to conformance vector ids, and every id exists in the
//     corpora (CHANGES-VECTORS.json in the packet);
//   - the normative references, registry version 5 and its counts, the
//     examples the prose cites against the ABNF, text that must be gone,
//     both renders, and SHA256SUMS.txt.
//
//   node scripts/check-caid-04.mjs          run every check; exit 1 on any failure
//   node scripts/check-caid-04.mjs --emit   print the generated tables as XML,
//                                           for pasting into the draft
//   node scripts/check-caid-04.mjs --emit-json   the same tables as one JSON object
//
// Every failure is collected and printed, so one run lists all of them.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadGrammar, matches } from '../caid/spec/abnf.mjs';
import { buildSpec } from '../caid/spec/gen.mjs';
import { createReference } from '../caid/spec/reference.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packetRel = 'standards/staged/NEXT-CAID-04';
const packet = path.join(root, packetRel);
const DOC = 'draft-schrock-canonical-action-identifier-04';
const sourceRel = `UPLOAD-THIS/${DOC}.xml`;
const textRel = `RENDERS/${DOC}.txt`;
const htmlRel = `RENDERS/${DOC}.html`;
const read = (rel) => readFileSync(path.join(root, rel), 'utf8');
const readJson = (rel) => JSON.parse(read(rel));

const core = readJson('caid/spec/core.json');
const abnfText = read('caid/spec/caid.abnf');

// ---------------------------------------------------------------------------
// Generated tables (also printed by --emit)
// ---------------------------------------------------------------------------

const OPERATIONS = ['decode', 'parse', 'compute', 'verify'];
const xmlEscape = (s) => String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

function tableXml(anchor, name, head, rows) {
  const cells = (tag, row) => row.map((c) => `<${tag}>${xmlEscape(c)}</${tag}>`).join('');
  return [
    `<table anchor="${anchor}">`,
    `  <name>${xmlEscape(name)}</name>`,
    `  <thead><tr>${cells('th', head)}</tr></thead>`,
    '  <tbody>',
    ...rows.map((row) => `    <tr>${cells('td', row)}</tr>`),
    '  </tbody>',
    '</table>',
  ].join('\n');
}

// Decoding and parsing are single steps, not phases: they are named without
// a number. A code that computation and mapping stage A share appears once,
// in the core table, with its stage.
function coreReasonRows() {
  return core.reasons.map(({ code, param }) => {
    const where = [];
    for (const op of OPERATIONS) {
      for (const phase of core.operations[op]) {
        if (!phase.reasons.includes(code)) continue;
        where.push(op === 'decode' || op === 'parse' ? op : `${op} ${phase.rank}${phase.gate ? ' (gate)' : ''}`);
      }
    }
    const stage = core.mapping.stages.find((st) => st.reasons.includes(code));
    if (stage) where.push(`mapping stage ${stage.stage}`);
    return [code, param, where.join('; ')];
  });
}

function mappingReasonRows() {
  const m = core.mapping;
  const coreCodes = new Set(core.reasons.map((r) => r.code));
  return m.reasons.filter(({ code }) => !coreCodes.has(code)).map(({ code, param }) => {
    const stage = m.stages.find((st) => st.reasons.includes(code));
    return [code, param, stage ? stage.stage : 'comparison'];
  });
}

function detailRows() {
  const d = core.verify_details.reasons;
  const fieldText = (f) => (f === null ? 'null' : f === 'param' ? 'the parameter' : f);
  const observedText = (o) => (o === null ? 'null' : o === 'member' ? 'the member' : 'the CAID argument');
  return core.reasons.map((r) => r.code).filter((code) => code in d)
    .map((code) => [code, d[code].rule, fieldText(d[code].field), observedText(d[code].observed)]);
}

// The limits table: one row per limit of scope caid or caid-mapping, a
// minimum and maximum of one quantity sharing a row. Labels are draft text.
const LIMIT_ROWS = [
  { ids: ['json_text_octets'], label: 'JSON text', unit: 'octets', applies: 'an action object or a mapping source received as JSON text (decode)', refusal: 'malformed_json' },
  { ids: ['nesting_depth'], label: 'Nesting depth', unit: 'levels', applies: 'every decoded document and every host value', refusal: 'malformed_json (JSON text); unsupported_value (host value)' },
  { ids: ['canonical_octets'], label: 'Canonical encoding', unit: 'octets', applies: 'an action object', refusal: 'unsupported_value' },
  { ids: ['max_safe_integer'], label: 'Integer magnitude', unit: '', applies: 'every number', refusal: 'unsupported_number', display: (v) => (v === 2 ** 53 - 1 ? '2^53-1' : null) },
  { ids: ['value_count'], label: 'Value count', unit: 'values', applies: 'a host value, each value counted once for every path that reaches it', refusal: 'unsupported_value, and no unsupported_number' },
  { ids: ['document_canonical_octets'], label: 'Document encoding', unit: 'octets', applies: 'the RFC 8785 encoding of a validation projection, an enum value array, or a mapping source', refusal: 'the reason of the step that needs the encoding' },
  { ids: ['caid_octets'], label: 'Identifier', unit: 'octets', applies: 'a CAID string', refusal: 'malformed_caid' },
  { ids: ['action_type_octets'], label: 'Action type', unit: 'octets', applies: 'an action type in a CAID, an action object, or a definition', refusal: 'malformed_caid; invalid_action_type; invalid_definition' },
  { ids: ['code_system_octets'], label: 'Code system', unit: 'octets', applies: 'the code_system of a code field', refusal: 'invalid_definition' },
  { ids: ['mapping_rules_min', 'mapping_rules_max'], label: 'Mapping rules', unit: 'rules', applies: 'rules of a mapping profile', refusal: 'invalid_mapping_profile' },
  { ids: ['mapping_pointer_octets_max'], label: 'Source path', unit: 'octets', applies: 'each source path of a mapping profile', refusal: 'invalid_mapping_profile' },
  { ids: ['mapping_string_octets_min', 'mapping_string_octets_max'], label: 'Profile string', unit: 'octets', applies: 'profile_id, media_type, schema, version, and target_action_type', refusal: 'invalid_mapping_profile' },
  { ids: ['mapping_omission_reason_octets_min', 'mapping_omission_reason_octets_max'], label: 'Omission reason', unit: 'octets', applies: 'each omission reason', refusal: 'invalid_mapping_profile' },
];

function limitRows() {
  const byId = Object.fromEntries(core.limits.map((l) => [l.id, l]));
  const num = (n) => n.toLocaleString('en-US');
  const covered = new Set(LIMIT_ROWS.flatMap((r) => r.ids));
  const missing = core.limits.filter((l) => (l.scope === 'caid' || l.scope === 'caid-mapping') && !covered.has(l.id));
  if (missing.length) throw new Error(`CAID-04: limits table has no row for ${missing.map((l) => l.id).join(', ')}`);
  return LIMIT_ROWS.map((row) => {
    const values = row.ids.map((id) => {
      if (!byId[id]) throw new Error(`CAID-04: core.json has no limit ${id}`);
      return byId[id].value;
    });
    let value;
    if (row.display) {
      value = row.display(values[0]);
      if (value === null) throw new Error(`CAID-04: limit ${row.ids[0]} changed; update its display`);
    } else if (row.ids.length === 2) value = `${num(values[0])} to ${num(values[1])}`;
    else if (row.ids[0].endsWith('_max')) value = `at most ${num(values[0])}`;
    else value = num(values[0]);
    return [row.label, row.unit ? `${value} ${row.unit}` : value, row.applies, row.refusal];
  });
}

// IANA initial contents, from the registries and core.json.
function suiteRows() {
  const suites = readJson('caid/registry/suites.json').suites;
  return suites.map((s) => [
    s.suite,
    s.canonicalization.reference.replace(/ section /, ', Section '),
    `${s.digest.name}, ${s.digest.reference}`,
    String(s.digest_octets),
    s.status,
  ]);
}

function fieldTypeRows() {
  return core.field_types.map((t) => {
    const refusals = [...new Set([t.pattern_refusal, t.format_refusal].filter((r) => r && r !== core.unknown_field_type_refusal))];
    refusals.push(core.unknown_field_type_refusal);
    return [t.type, t.json, t.members.length ? t.members.join(', ') : 'none', refusals.join(', ')];
  });
}

function codeFormatRows(spec) {
  return core.grammar.code_formats.map(({ format, reference }) => {
    const a = spec._analysis[`code_format:${format}`];
    if (typeof reference !== 'string' || !reference) throw new Error(`CAID-04: code format ${format} has no reference in core.json`);
    return [format, String(a.max_length), reference];
  });
}

// Appendix D: the initial contents of the CAID Action Types registry, as a
// listing (a 64-digit digest does not fit a table row in 69 columns). Each
// entry is the action type, its status and, for a deprecated type, its
// successor, then the hexadecimal part of its definition_sha256 indented
// on the next line.
function actionTypeListing() {
  const reg = readJson('caid/registry/action-types.json');
  const dig = new Map(readJson('caid/registry/digests.json').types.map((t) => [t.action_type, t.definition_sha256]));
  return reg.types.map((t) => {
    const d = dig.get(t.action_type);
    if (!d) throw new Error(`CAID-04: digests.json has no definition_sha256 for ${t.action_type}`);
    const head = `${t.action_type} ${t.status}${t.superseded_by ? ` superseded_by ${t.superseded_by}` : ''}`;
    return `${head}\n  ${d.slice('sha256:'.length)}\n`;
  }).join('');
}
const LISTINGS = {
  'appendix-d-types': actionTypeListing,
};

const TRANSFORM_OUTPUT = {
  copy: 'the value',
  'sha256-utf8': '"sha256:" and the SHA-256 of its UTF-8 octets',
  'sha256-jcs': '"sha256:" and the SHA-256 of its RFC 8785 encoding',
  'sha256-hex-to-digest': '"sha256:" and the string',
};
function transformRows() {
  const ruleOf = Object.fromEntries(core.grammar.patterns.map((p) => [p.id, p.rule]));
  return core.mapping.transforms.map((t) => {
    if (!TRANSFORM_OUTPUT[t.transform]) throw new Error(`CAID-04: no output text for transform ${t.transform}`);
    const accepts = t.input === 'any' ? 'any value of the data model'
      : t.pattern ? `a string matching ${ruleOf[t.pattern]}` : 'a string';
    const refusal = t.input === 'any' ? 'source_value_not_canonicalizable' : 'source_value_type_mismatch';
    return [t.transform, accepts, TRANSFORM_OUTPUT[t.transform], refusal];
  });
}

function lossPolicyRows() {
  const constraint = { absent_or_empty: 'absent or empty', non_empty: 'non-empty' };
  return core.mapping.loss_policies.map((p) => [
    p.policy,
    constraint[p.omitted_source_fields],
    p.stage_reason ? `INDETERMINATE, reason ${p.stage_reason}` : 'none',
  ]);
}

let specCache;
const specOnce = () => { specCache ??= buildSpec(root); return specCache; };

const TABLES = {
  'tab-limits': () => tableXml('tab-limits', 'Limits', ['Limit', 'Value', 'Applies to', 'Refusal'], limitRows()),
  'tab-suites': () => tableXml('tab-suites', 'CAID Suites: Initial Contents', ['Suite', 'Canonicalization', 'Digest', 'Octets', 'Status'], suiteRows()),
  'tab-field-types': () => tableXml('tab-field-types', 'CAID Field Types: Initial Contents', ['Field type', 'JSON kind', 'Members', 'Refusals'], fieldTypeRows()),
  'tab-code-formats': () => tableXml('tab-code-formats', 'CAID Code Formats: Initial Contents', ['Code format', 'Maximum length', 'Syntax reference'], codeFormatRows(specOnce())),
  'tab-transforms': () => tableXml('tab-transforms', 'CAID Mapping Transforms: Initial Contents', ['Transform', 'Accepts', 'Output', 'Refusal'], transformRows()),
  'tab-loss-policies': () => tableXml('tab-loss-policies', 'CAID Mapping Loss Policies: Initial Contents', ['Policy', 'Omissions', 'Effect'], lossPolicyRows()),
  'tab-details': () => tableXml('tab-details', 'Verification Detail Rules', ['Reason', 'rule', 'field', 'observed'], detailRows()),
  'tab-core-reasons': () => tableXml('tab-core-reasons', 'Core Reasons', ['Reason', 'Parameter', 'Operations and phases'], coreReasonRows()),
  'tab-mapping-reasons': () => tableXml('tab-mapping-reasons', 'Mapping Reasons', ['Reason', 'Parameter', 'Stage'], mappingReasonRows()),
};

if (process.argv.includes('--emit')) {
  for (const make of Object.values(TABLES)) console.log(`${make()}\n`);
  for (const [anchor, make] of Object.entries(LISTINGS)) console.log(`<sourcecode anchor="${anchor}"><![CDATA[\n${make()}]]></sourcecode>\n`);
  process.exit(0);
}
if (process.argv.includes('--emit-json')) {
  console.log(JSON.stringify({
    ...Object.fromEntries(Object.entries(TABLES).map(([k, make]) => [k, make()])),
    ...Object.fromEntries(Object.entries(LISTINGS).map(([k, make]) => [k, make()])),
  }));
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

const errors = [];
const check = (condition, message) => { if (!condition) errors.push(message); };
const source = readFileSync(path.join(packet, sourceRel), 'utf8');
const text = readFileSync(path.join(packet, textRel), 'utf8');
const html = readFileSync(path.join(packet, htmlRel), 'utf8');
const flat = (s) => s.replace(/\s+/g, ' ');
const registry = readJson('caid/registry/action-types.json');
const digests = readJson('caid/registry/digests.json');
const snapshots = registry.enum_snapshot_files.map((f) => readJson(`caid/registry/${f.path}`));
const spec = specOnce();
const ref = createReference(spec);
const rules = loadGrammar([{ text: abnfText, source: 'caid.abnf' }]);
const sha256Hex = (s) => createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const regOptions = { suite: 'jcs-sha256', definitions: registry.types, enumSnapshots: snapshots };

/** The body of the section with this anchor, nested sections included. */
function section(anchor) {
  const start = source.indexOf(`<section anchor="${anchor}"`);
  if (start < 0) { errors.push(`no section ${anchor}`); return ''; }
  const re = /<section\b|<\/section>/g;
  re.lastIndex = start;
  let depth = 0;
  for (let m = re.exec(source); m; m = re.exec(source)) {
    depth += m[0] === '</section>' ? -1 : 1;
    if (depth === 0) return source.slice(start, m.index);
  }
  errors.push(`section ${anchor} is not closed`);
  return '';
}

/** The CDATA text of the sourcecode with this anchor, without its first line break. */
function code(anchor) {
  const re = new RegExp(`<sourcecode\\b[^>]*\\banchor="${anchor}"[^>]*>\\s*<!\\[CDATA\\[\\n?([\\s\\S]*?)\\]\\]>\\s*</sourcecode>`);
  const m = re.exec(source);
  if (!m) { errors.push(`no sourcecode ${anchor}`); return ''; }
  return m[1];
}

// RFC 8792 single-backslash unfolding.
const FOLD_HEADER = /^=* *NOTE: '\\' line wrapping per RFC 8792 *=*\n\n/;
function unfold(s) {
  if (!FOLD_HEADER.test(s)) return s;
  return s.replace(FOLD_HEADER, '').replace(/\\\n */g, '');
}
const codeJson = (anchor) => {
  const raw = unfold(code(anchor));
  try { return JSON.parse(raw); } catch (e) { errors.push(`sourcecode ${anchor} is not JSON after unfolding: ${e.message}`); return undefined; }
};
const codeText = (anchor) => unfold(code(anchor)).replace(/\n$/, '');

// ---------------------------------------------------------------------------
// Header, references, registry
// ---------------------------------------------------------------------------

check(source.includes(`docName="${DOC}"`), 'wrong source revision');
check(source.includes(`<seriesInfo name="Internet-Draft" value="${DOC}"/>`), 'seriesInfo does not name -04');
check(source.includes('category="std"'), 'candidate is not Standards Track');
check(!source.includes('submissionType='), 'an individual draft must not claim a document stream');
const dateMatch = /<date year="(\d{4})" month="([A-Z][a-z]+)" day="(\d{1,2})"\/>/.exec(source.slice(0, source.indexOf('</front>')));
check(dateMatch, 'the document date is not a full year, month and day');
if (dateMatch) {
  const [, y, mo, d] = dateMatch;
  const parsed = new Date(`${mo} ${d}, ${y} 00:00:00 UTC`);
  check(!Number.isNaN(parsed.getTime()) && parsed.getUTCDate() === Number(d), 'the document date is not a calendar date');
  check(text.includes(`${Number(d)} ${mo} ${y}`), 'the TXT render does not carry the source date');
}
check(text.includes('Intended status: Standards Track'), 'TXT render has the wrong intended status');

const referenceSection = (name) => {
  const m = new RegExp(`<name>${name}</name>([\\s\\S]*?)</references>`).exec(source);
  return m ? m[1] : '';
};
const normative = referenceSection('Normative References');
const informative = referenceSection('Informative References');
const rfcs = (block) => new Set([...block.matchAll(/reference\.RFC\.(\d{4})\.xml/g)].map((m) => m[1]));
const normativeRfcs = rfcs(normative);
const informativeRfcs = rfcs(informative);
for (const n of ['2119', '8174', '8785', '8949', '6234', '4648', '3339', '5234', '7405', '6901', '8259', '3629', '7493', '3986']) {
  check(normativeRfcs.has(n), `normative reference RFC ${n} missing`);
}
for (const n of ['7595', '7942', '8126', '8792']) check(informativeRfcs.has(n), `informative reference RFC ${n} missing`);
for (const n of normativeRfcs) check(source.includes(`target="RFC${n}"`), `normative RFC ${n} is never cited`);
for (const n of informativeRfcs) check(source.includes(`target="RFC${n}"`), `informative RFC ${n} is never cited`);
// The cited revisions are the latest on Datatracker when the packet was
// last validated (VALIDATION.md records the check).
for (const retained of [
  'draft-schrock-ep-authorization-receipts-13',
  'draft-schrock-action-evidence-boundary-07',
  'draft-schrock-ep-authorization-evidence-chain-06',
  'draft-thallapelly-oasnt-caid-01',
]) check(source.includes(retained), `missing retained reference ${retained}`);
for (const anchor of ['IEEE754', 'UNICODE']) check(source.includes(`<reference anchor="${anchor}"`) && source.includes(`target="${anchor}"`), `reference ${anchor} is missing or never cited`);

check(registry.meta.registry_version === 5, 'reference registry is not version 5');
check(digests.registry_version === 5, 'digests.json is not for registry version 5');
const active = registry.types.filter((t) => t.status === 'active').length;
const deprecated = registry.types.filter((t) => t.status === 'deprecated').length;
check(active + deprecated === registry.types.length, 'registry has a status other than active and deprecated');
for (const phrase of [
  'registry version 5',
  `${registry.types.length} type versions`,
  `${active} active`,
  `${deprecated} deprecated`,
]) check(flat(source).includes(phrase), `draft does not state "${phrase}"`);
const v5File = digests.registry_files.find((f) => f.registry_version === 5);
const v5Sha = `sha256:${createHash('sha256').update(readFileSync(path.join(root, 'caid/registry', v5File.path))).digest('hex')}`;
check(v5File.sha256 === v5Sha, 'digests.json does not pin the bytes of action-types.json');
check(flat(source).includes(v5Sha.slice('sha256:'.length)), 'the registry reference does not carry the SHA-256 of registry version 5');
const v4File = digests.registry_files.find((f) => f.registry_version === 4);
check(v4File?.sha256 === 'sha256:73a31f4a4156e3de02e1c3a9ef355f73c07ba25e6b1bb3da8fde8677c2e23d26', 'history v4 pin moved');

// ---------------------------------------------------------------------------
// Appendix A: byte-equal to caid/spec/caid.abnf
// ---------------------------------------------------------------------------

const appendixA = code('abnf-collected');
check(appendixA === abnfText, 'Appendix A differs from caid/spec/caid.abnf');
check(!source.replace(code('abnf-collected'), '').includes('<sourcecode type="abnf"'), 'ABNF appears outside Appendix A');
for (const line of abnfText.split('\n').filter((l) => l.length)) {
  check(text.includes(`\n   ${line}\n`), `TXT render lacks Appendix A line ${JSON.stringify(line)}`);
}

// ---------------------------------------------------------------------------
// Appendix B, the detail table, the limits table: generated from core.json
// ---------------------------------------------------------------------------

for (const [anchor, make] of Object.entries(TABLES)) {
  check(source.includes(make()), `table ${anchor} differs from the one generated from caid/spec/core.json (run with --emit)`);
}
check(source.match(/<table anchor="tab-core-reasons">/g)?.length === 1, 'core reason table appears more than once');
for (const [anchor, make] of Object.entries(LISTINGS)) {
  check(code(anchor) === make(), `listing ${anchor} differs from the one generated from the registry and digests.json (run with --emit)`);
}
for (const { code: c } of [...core.reasons, ...core.mapping.reasons]) {
  check(flat(text).includes(c), `TXT render lacks reason ${c}`);
}

// ---------------------------------------------------------------------------
// Examples cited in prose, against the ABNF
// ---------------------------------------------------------------------------

const cites = (s) => flat(source).includes(`"${s}"`);
for (const s of ['0', '0.50', '-0', '-0.50']) check(cites(s) && matches(rules, 'amount-string', s), `amount example ${s} not cited or not matching`);
for (const s of ['01.5', '00', '+1', '1e3', '.5', '1.', '1,000']) check(cites(s) && !matches(rules, 'amount-string', s), `amount counterexample ${s} not cited or matching`);
for (const s of ['2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00Z']) check(cites(s) && matches(rules, 'timestamp', s), `timestamp example ${s}`);
check(cites('G47.33') && matches(rules, 'icd-10-cm', 'G47.33'), 'icd-10-cm example');
check(cites('G4733') && !matches(rules, 'icd-10-cm', 'G4733'), 'icd-10-cm counterexample');
check(matches(rules, 'reason', 'mapped_action:missing_material_field:amount')
  && matches(rules, 'reason', 'left:mapped_action:invalid_amount:amount'), 'reason rule refuses a nested reason');
for (const s of ['mapped_action:missing_material_field:amount', 'left:mapped_action:invalid_amount:amount']) check(flat(source).includes(s), `draft does not cite nested reason ${s}`);
for (const entry of readJson('caid/registry/suites.json').suites) {
  check(matches(rules, 'suite', entry.suite), `registered suite ${entry.suite} does not match the suite rule of Appendix A`);
  check(entry.digest_octets === 32 && entry.digest?.name === 'SHA-256', `registered suite ${entry.suite} is not a 32-octet SHA-256 suite, as Section 3.1 states`);
}
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const finals = [...B64URL].filter((_, value) => (value & 3) === 0).map((c) => `"${c}"`);
check(flat(source).includes(`${finals.slice(0, -1).join(', ')}, or ${finals.at(-1)}`), 'draft does not list the 16 final digest characters');
check(finals.every((f) => matches(rules, 'b64url-z2', f.slice(1, -1))) && finals.length === 16, 'b64url-z2 differs from the listed characters');

// ---------------------------------------------------------------------------
// Worked examples recompute
// ---------------------------------------------------------------------------

const reasonsOk = (list) => Array.isArray(list) && list.every((r) => matches(rules, 'reason', r));
const b64 = (hex) => Buffer.from(hex, 'hex').toString('base64url');

// C.1 computation.
const payment = codeJson('exc-payment-object');
const paymentCanonical = codeText('exc-payment-canonical');
const paymentResult = codeJson('exc-payment-result');
const c1 = ref.canonicalize(payment);
check(c1.ok && c1.canonical === paymentCanonical, 'C.1 canonical encoding does not recompute');
check(flat(source).includes(`is ${Buffer.byteLength(paymentCanonical, 'utf8')} octets`), 'C.1 octet count not stated');
const c1Hex = sha256Hex(paymentCanonical);
check(paymentResult?.digest === `sha256:${c1Hex}`, 'C.1 digest does not recompute');
check(paymentResult?.caid === `caid:1:${payment?.action_type}:jcs-sha256:${b64(c1Hex)}`, 'C.1 CAID does not recompute');
check(same(ref.compute(payment, regOptions), paymentResult), 'C.1 result differs from the reference validator');
const digestOf = (type) => digests.types.find((t) => t.action_type === type)?.definition_sha256;
check(paymentResult?.definition_sha256 === digestOf('payment.release.1'), 'C.1 definition_sha256 differs from digests.json');
check(unfold(code('ex-identifier')).trim() === paymentResult?.caid, 'Section 3.3 example is not the C.1 CAID');

// C.2 refusal.
const refused = codeJson('exc-refusal-object');
const refusedResult = codeJson('exc-refusal-result');
check(same(ref.compute(refused, regOptions), refusedResult), 'C.2 refusal differs from the reference validator');
check(reasonsOk(refusedResult?.refusals), 'C.2 has a reason outside the reason rule');

// C.3 verification.
const verifyResult = codeJson('exc-verify-result');
check(same(ref.verify(refused, paymentResult?.caid, regOptions), verifyResult), 'C.3 verification differs from the reference validator');
check(reasonsOk(verifyResult?.reasons) && reasonsOk(verifyResult?.details?.map((d) => d.reason)), 'C.3 has a reason outside the reason rule');
check(verifyResult?.details?.every((d) => same(Object.keys(d), core.verify_details.members)), 'C.3 detail shape is not reason, field, rule, observed');

// C.4 definition digest.
const toolDef = registry.types.find((t) => t.action_type === 'tool.call.1');
const projection = codeText('exc-projection');
const projectionDigest = codeText('exc-projection-digest');
const p = ref.canonicalize(ref.projection(toolDef));
check(p.ok && p.canonical === projection, 'C.4 projection does not recompute');
check(projectionDigest === `sha256:${sha256Hex(projection)}`, 'C.4 digest does not recompute');
check(projectionDigest === ref.definitionSha256(toolDef) && projectionDigest === digestOf('tool.call.1'), 'C.4 digest differs from the reference and digests.json');

// C.5 code fields.
const coded = codeJson('exc-code-object');
const codedResult = codeJson('exc-code-result');
check(same(ref.compute(coded, regOptions), codedResult), 'C.5 result differs from the reference validator');
check(codedResult?.definition_sha256 === digestOf(coded?.action_type), 'C.5 definition_sha256 differs from digests.json');
const codedBad = codeJson('exc-code-refusal-object');
const codedBadResult = codeJson('exc-code-refusal-result');
check(same(ref.compute(codedBad, regOptions), codedBadResult), 'C.5 refusal differs from the reference validator');
for (const v of [coded?.service_code, coded?.diagnosis_code, codedBad?.service_code, codedBad?.diagnosis_code]) {
  check(typeof v === 'string' && !matches(rules, 'cpt', v), `C.5 value ${v} has CPT syntax; examples carry no CPT-shaped code`);
}

// C.6 mapping, recomputed here from the rules of Section 8, then computed
// through the reference validator.
const profile = codeJson('ex-map-profile');
const mapSource = codeJson('exc-map-source');
const projected = codeJson('exc-map-projected');
const mapResult = codeJson('exc-map-result');
const jcsHex = (v) => { const c = ref.canonicalize(v); return c.ok ? sha256Hex(c.canonical) : null; };
const pointer = (doc, ptr) => ptr.slice(1).split('/').map((t) => t.replaceAll('~1', '/').replaceAll('~0', '~'))
  .reduce((cur, token) => (cur !== null && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, token) ? cur[token] : undefined), doc);
const transforms = {
  copy: (v) => v,
  'sha256-utf8': (v) => `sha256:${sha256Hex(v)}`,
  'sha256-jcs': (v) => `sha256:${jcsHex(v)}`,
  'sha256-hex-to-digest': (v) => `sha256:${v}`,
};
if (profile && mapSource) {
  const built = { action_type: profile.target_action_type };
  for (const rule of profile.rules) built[rule.target_field] = transforms[rule.transform](pointer(mapSource, rule.source_path));
  check(same(built, projected), 'C.6 projected object does not recompute');
  const computed = ref.compute(built, regOptions);
  check(mapResult?.profile_digest === `sha256:${jcsHex(profile)}`, 'C.6 profile digest does not recompute');
  check(mapResult?.source_digest === `sha256:${jcsHex(mapSource)}`, 'C.6 source digest does not recompute');
  check(mapResult?.caid === computed.caid, 'C.6 CAID does not recompute');
}

// Section 4.7 tool.call.1 example.
const toolObject = codeJson('ex-tool-object');
const toolCaid = unfold(code('ex-tool-caid')).trim();
check(ref.compute(toolObject, regOptions).caid === toolCaid, 'tool.call.1 example does not reproduce its CAID');
check(ref.compute({ ...toolObject, target: 'https://shadow.example' }, regOptions).caid !== toolCaid, 'tool.call.1 target does not discriminate');
check(same(toolDef.required_fields.map((f) => f.name), ['target', 'tool', 'args']), 'tool.call.1 required fields changed');

// Every folded example unfolds; no sourcecode line exceeds 69 columns.
for (const m of source.matchAll(/<sourcecode\b[^>]*>\s*<!\[CDATA\[([\s\S]*?)\]\]>/g)) {
  for (const line of m[1].split('\n')) check(line.length <= 69, `sourcecode line over 69 columns: ${line.slice(0, 40)}...`);
}

// ---------------------------------------------------------------------------
// Changes since -03: every processing or registry claim maps to vectors
// ---------------------------------------------------------------------------

const changes = section('changes-03');
const claimAnchors = [...changes.matchAll(/<li anchor="(chg-[a-z0-9-]+)"/g)].map((m) => m[1]);
const editorialAnchors = [...changes.matchAll(/<li anchor="(ed-[a-z0-9-]+)"/g)].map((m) => m[1]);
const listItems = [...changes.matchAll(/<li\b/g)].length;
check(claimAnchors.length > 0, 'Changes since -03 has no anchored claims');
check(claimAnchors.length + editorialAnchors.length === listItems, 'a Changes since -03 item has no chg- or ed- anchor');
check(new Set(claimAnchors).size === claimAnchors.length, 'duplicate claim anchor');
const mapFile = JSON.parse(readFileSync(path.join(packet, 'CHANGES-VECTORS.json'), 'utf8'));
const corpusIds = {};
for (const [name, rel] of Object.entries(mapFile.corpora)) {
  const corpus = existsSync(path.join(root, rel)) ? readJson(rel) : { vectors: [] };
  corpusIds[name] = new Set((corpus.vectors ?? []).map((v) => v.id));
}
const missingVectors = [];
for (const anchor of claimAnchors) {
  const entry = mapFile.claims[anchor];
  check(entry, `claim ${anchor} has no entry in CHANGES-VECTORS.json`);
  if (!entry) continue;
  const ids = Object.entries(entry).flatMap(([corpus, list]) => list.map((id) => [corpus, id]));
  check(ids.length > 0, `claim ${anchor} maps to no vector`);
  for (const [corpus, id] of ids) {
    check(corpus in corpusIds, `claim ${anchor} names unknown corpus ${corpus}`);
    if (corpusIds[corpus] && !corpusIds[corpus].has(id)) missingVectors.push(`${anchor} -> ${corpus}:${id}`);
  }
}
for (const anchor of Object.keys(mapFile.claims)) check(claimAnchors.includes(anchor), `CHANGES-VECTORS.json entry ${anchor} has no claim in the draft`);
check(missingVectors.length === 0, `claims map to vector ids absent from the corpora (${missingVectors.length}):\n    ${missingVectors.join('\n    ')}`);

// ---------------------------------------------------------------------------
// Text that must be present or gone (the change logs may name removed text)
// ---------------------------------------------------------------------------

const outsideChanges = source.replace(changes, '').replace(section('changes'), '');

for (const [needle, what] of [
  ['No other normative text changes', 'the -03 no-other-changes sentence'],
  ['accept-unregistered', 'the accept-unregistered option'],
  ['treated as public values', 'the public-values sentence'],
  ['pending adoption', 'the self-maintenance sentence'],
  ['One narrow correction is permitted', 'the narrow-correction rule'],
  ['is never such a correction', 'the no-added-values sentence'],
  ['qL8R4QIcQ', 'the orphan identifier example'],
  ['requests no immediate IANA actions', 'the no-IANA-actions sentence'],
  ['until this revision', 'revision-relative wording'],
]) check(!outsideChanges.includes(needle), `source still carries ${what}`);
for (const [needle, what] of [
  ['MUST NOT be abbreviated', 'truncation rule'],
  ['no replay protection', 'replay statement'],
  ['MUST verify every CAID', 'multiple-CAID rule'],
  ['MUST cover the complete CAID string', 'signature coverage rule'],
  ['same confidentiality as its action object', 'confidentiality statement'],
  ['linear in the length', 'code format matching bound'],
  ['Provisional', 'provisional URI scheme'],
  ['registers no media type', 'media type decision'],
  ['none of them is independent', 'implementation independence statement'],
  ['reproductions', 'reproduction statement'],
]) check(flat(source).includes(needle), `source lacks the ${what}`);
for (const name of ['CAID Suites', 'CAID Action Types', 'CAID Field Types', 'CAID Code Formats', 'CAID Reason Codes', 'CAID Mapping Transforms', 'CAID Mapping Loss Policies']) {
  check(source.includes(`<name>${name}</name>`), `IANA registry ${name} missing`);
}
const prose = text + source;
check(!/[\u2013\u2014]/.test(prose), 'an en or em dash appears in the draft');
check(!/[^\n!-]--[^>-]/.test(source.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '')), 'a double hyphen appears in prose');
check(!/[^\x09\x0a\x20-\x7e]/.test(source), 'the XML source is not printable ASCII');

// ---------------------------------------------------------------------------
// Renders and checksums
// ---------------------------------------------------------------------------

const decodeHtml = (s) => s.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&#39;', "'").replaceAll('&amp;', '&');
const htmlText = decodeHtml(html);
check(htmlText.includes(abnfText.split('\n')[6]), 'HTML render lacks Appendix A');
check(htmlText.includes(code('exc-payment-canonical').split('\n')[2]), 'HTML render lacks Appendix C');
check(text.includes(code('exc-payment-canonical').split('\n')[2]), 'TXT render lacks Appendix C');

const sums = readFileSync(path.join(packet, 'SHA256SUMS.txt'), 'utf8').trim().split('\n');
const expectedPaths = new Set([sourceRel, textRel, htmlRel]);
for (const line of sums) {
  const match = line.match(/^([0-9a-f]{64}) {2}(.+)$/);
  check(match, `malformed checksum line ${line}`);
  if (!match) continue;
  const [, expectedHash, relative] = match;
  check(expectedPaths.delete(relative), `unexpected or duplicate checksum path ${relative}`);
  if (!existsSync(path.join(packet, relative))) continue;
  const actual = createHash('sha256').update(readFileSync(path.join(packet, relative))).digest('hex');
  check(actual === expectedHash, `checksum mismatch for ${relative}`);
}
check(expectedPaths.size === 0, `missing checksum path ${[...expectedPaths].join(', ')}`);

if (errors.length) {
  console.error(`CAID-04 packet: ${errors.length} failure(s)`);
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
console.log(`CAID-04: Appendix A (${abnfText.split('\n').length - 1} lines) equals caid.abnf; Appendix B, detail, limits and IANA tables (Appendix D included) equal their sources; Appendix C and the examples recompute; ${claimAnchors.length} change claims map to vectors; registry v5 (${registry.types.length} types); references, renders and checksums PASS.`);
