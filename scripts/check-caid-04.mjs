#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Checks the staged draft-schrock-canonical-action-identifier-04 packet
// (standards/staged/NEXT-CAID-04) against the sources it restates:
//
//   - Appendix A equals caid/spec/caid.abnf byte for byte;
//   - Appendix D lists every type of reference registry version 5 with its
//     definition_sha256 from digests.json, split into D.1, the initial
//     entries IANA is asked to register, and D.2, the entries that are not
//     requested of IANA (IANA_EXCLUDED below); Section 12.2 and both
//     subsections state the counts of that split, and no page of the TXT
//     render separates an entry's name line from its digest line;
//   - Appendix B (core and mapping reasons), the verification detail table
//     and the limits table equal the tables generated below from
//     caid/spec/core.json;
//   - every value in Appendix C, the identifier example of Section 3.3, the
//     type definition example of Section 4.2 and the tool.call.1 example
//     recompute, through the reference validator (caid/spec/reference.mjs)
//     and through hashing done here; the cbor-sha256 values of C.1
//     recompute through the deterministic CBOR encoder below;
//   - every item of "Changes since -03" that states a processing or registry
//     change maps to conformance vector ids, and every id exists in the
//     corpora (CHANGES-VECTORS.json in the packet);
//   - the Section 4.7 registration is the registry entry for tool.call.1,
//     member for member;
//   - the normative references, the [CAID-REGISTRY] pin, registry version 5
//     and its counts, the registries the Abstract and Section 12 name, the
//     examples the prose cites against the ABNF, BCP 14 markup, text the
//     pre-filing review and the audit of its fixes require, text that must
//     be gone, banned wording, both renders (and, with xml2rfc 3.34.0 on
//     PATH, that they equal a fresh render), table rows split across a
//     page, and SHA256SUMS.txt;
//   - with --prefiling, that origin/main carries this tree's caid/ and the
//     vendored caid.mjs byte for byte, so Sections 2.2, 2.5, 8.3 and 13 and
//     Appendix A hold at tree/main/caid.
//
//   node scripts/check-caid-04.mjs          run every check; exit 1 on any failure
//   node scripts/check-caid-04.mjs --emit   print the generated tables and
//                                           Appendix D lists as XML, for
//                                           pasting into the draft
//   node scripts/check-caid-04.mjs --emit-json   the same as one JSON object
//   node scripts/check-caid-04.mjs --renders     every check, and fail unless
//                                           xml2rfc 3.34.0 is on PATH and its
//                                           renders of the source equal
//                                           RENDERS/ (without the flag the
//                                           renders are compared whenever
//                                           that xml2rfc is on PATH)
//   node scripts/check-caid-04.mjs --prefiling   every check with --renders,
//                                           plus the filing gate against
//                                           origin/main, which must equal
//                                           the remote main (run git fetch
//                                           origin first)
//
// Every failure is collected and printed, so one run lists all of them.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
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
// The row order is the draft's: the Code system row precedes the Action
// type row so that the TXT page break inside Table 1 falls on a border
// line, not inside a row (checked below).
// The nesting and value-count rows name the reasons the limit itself yields
// for an action object; any other value too deep, or past the count, is
// refused by the step that reads it, as all three ports do:
// invalid_definition for a host definition, invalid_mapping_profile for a
// host profile, source_not_canonicalizable for a host mapping source. The
// count stops at the nesting limit: a container deeper than 64 counts as
// one value and nothing inside it is counted (the native vectors
// native-value-count-* pin both), and a reference back to an enclosing
// object or array counts as one value (native-cyclic-*-with-fraction).
// Past the count a host action object yields unsupported_value and no
// unsupported_number, and phases 3 and 4 still run
// (native-value-count-with-phase-3-and-4), so the row does not say
// "alone" (R3-VALUECOUNT-ALONE). Phase 6 examines numbers only down to
// depth 64 (R3-REG-2) and only in a value within the count, and a number
// outside the model in any value but an action object is refused by the
// step that reads it (F2-ITEMS-1).
const LIMIT_ROWS = [
  { ids: ['json_text_octets'], label: 'JSON text', unit: 'octets', applies: 'an action object or a mapping source received as JSON text (decode)', refusal: 'malformed_json' },
  { ids: ['nesting_depth'], label: 'Nesting depth', unit: 'levels', applies: 'every value', refusal: 'malformed_json (action object or mapping source as JSON text); unsupported_value (host action object); otherwise the reason of the step that reads the value' },
  { ids: ['canonical_octets'], label: 'Canonical encoding', unit: 'octets', applies: 'an action object', refusal: 'unsupported_value' },
  { ids: ['max_safe_integer'], label: 'Integer magnitude', unit: '', applies: 'every number held at depth 64 or less in a value within the value count', refusal: 'unsupported_number (action object); otherwise the reason of the step that reads the value', display: (v) => (v === 2 ** 53 - 1 ? '2^53-1' : null) },
  { ids: ['value_count'], label: 'Value count', unit: 'values', applies: 'a host value, each value counted once per path; an object or array nested deeper than 64, or a reference back to an enclosing one, counts as one value', refusal: 'unsupported_value and no unsupported_number (host action object); otherwise the reason of the step that reads the value' },
  { ids: ['document_canonical_octets'], label: 'Document encoding', unit: 'octets', applies: 'the RFC 8785 encoding of a validation projection, an enum value array, or a mapping source', refusal: 'the reason of the step that needs the encoding' },
  { ids: ['caid_octets'], label: 'Identifier', unit: 'octets', applies: 'a CAID string', refusal: 'malformed_caid' },
  { ids: ['code_system_octets'], label: 'Code system', unit: 'octets', applies: 'the code_system of a code field', refusal: 'invalid_definition' },
  { ids: ['action_type_octets'], label: 'Action type', unit: 'octets', applies: 'an action type in a CAID, an action object, or a definition', refusal: 'malformed_caid; invalid_action_type; invalid_definition' },
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

// Appendix D: every type of reference registry version 5, split in two.
//
// Registry version 5 stays byte for byte: its SHA-256 is pinned by the
// draft, and removing a type would break the monotone rule of Section 4.1,
// the conformance vectors, and the software that already emits the type.
// What changes is only what IANA is asked to register. D.1 lists the
// initial IANA entries, whose reference is the draft and whose change
// controller is the IETF. D.2 lists the registry entries that are not
// requested of IANA; each may later be registered under the Specification
// Required policy of Section 12.2 with its own specification and change
// controller. Both listings print every definition_sha256, so all 62
// digests stay in the document and Appendix C still recomputes.
//
// IANA_EXCLUDED is the whole D.2 list. Each entry says why the type is not
// an IETF initial entry, and names text of the registry entry that shows
// it; the check below fails if that text is gone, so the reason cannot go
// stale without the check noticing.
const IANA_EXCLUDED = new Map([
  // Named for the author's product. Its meaning comes from a vendor
  // specification (the mobile ceremony of the author's software), and the
  // draft does not define it.
  ['emilia.mobile.authorized-action.1', {
    reason: 'named for a product; defined by a vendor specification',
    shows: { member: 'summary', text: 'EMILIA' },
  }],
  // The four agent.state types are defined by EP-PORTABLE-STATE-HANDOFF-v0.1,
  // a specification the draft does not cite.
  ['agent.state.export.1', {
    reason: 'defined by another specification',
    shows: { member: 'references', text: 'EP-PORTABLE-STATE-HANDOFF-v0.1' },
  }],
  ['agent.state.import.1', {
    reason: 'defined by another specification',
    shows: { member: 'references', text: 'EP-PORTABLE-STATE-HANDOFF-v0.1' },
  }],
  ['agent.state.key-release.1', {
    reason: 'defined by another specification',
    shows: { member: 'references', text: 'EP-PORTABLE-STATE-HANDOFF-v0.1' },
  }],
  ['agent.state.retire-source.1', {
    reason: 'defined by another specification',
    shows: { member: 'references', text: 'EP-PORTABLE-STATE-HANDOFF-v0.1' },
  }],
  // Defined by the Model-to-Matter Internet-Draft, which the draft does
  // not cite.
  ['science.bio.experiment.execute.1', {
    reason: 'defined by another specification',
    shows: { member: 'references', text: 'draft-schrock-model-to-matter-' },
  }],
  // Defined by the SILP Internet-Draft, another author's document, which
  // the draft does not cite. Its change controller is not ours to name.
  ['travel.cancel-notify.1', {
    reason: 'defined by another specification',
    shows: { member: 'references', text: 'draft-hwang-silp-protocol-' },
  }],
  // The name reads as a DNS zone transfer (AXFR/IXFR, RFC 5936 and RFC
  // 1995), but the type is an EPP registrar transfer of a domain (RFC 5730).
  // A registered name is never reassigned, so the misnomer stays out of
  // the IANA registry.
  ['dns.zone.transfer.1', {
    reason: 'named as a DNS zone transfer; defines an EPP registrar transfer (RFC 5730)',
    shows: { member: 'references', text: 'RFC 5730' },
  }],
]);

// The split the author decided (M1 of the pre-filing review): 54 initial
// IANA entries, 45 active and 9 deprecated, and 8 entries in D.2. The
// counts are also derived from the registry below; this pins the decision
// so that a change to either side is a failure, not a silent new split.
const EXPECTED_SPLIT = { iana: { total: 54, active: 45, deprecated: 9 }, other: { total: 8, active: 8, deprecated: 0 } };

function actionTypeSplit() {
  const reg = readJson('caid/registry/action-types.json');
  const byName = new Map(reg.types.map((t) => [t.action_type, t]));
  for (const [name, { shows }] of IANA_EXCLUDED) {
    const t = byName.get(name);
    if (!t) throw new Error(`CAID-04: IANA_EXCLUDED names ${name}, which registry version 5 does not carry`);
    const value = t[shows.member];
    const found = Array.isArray(value) ? value.some((v) => String(v).includes(shows.text)) : String(value ?? '').includes(shows.text);
    if (!found) throw new Error(`CAID-04: the stated reason for excluding ${name} no longer holds: its ${shows.member} lacks "${shows.text}"`);
  }
  const iana = reg.types.filter((t) => !IANA_EXCLUDED.has(t.action_type));
  const other = reg.types.filter((t) => IANA_EXCLUDED.has(t.action_type));
  // No initial IANA entry names the author's company or cites one of its
  // specifications (those are named EP-...).
  for (const t of iana) {
    if (/EMILIA|\bemilia\b|\bEP-[A-Z]/.test(JSON.stringify(t))) {
      throw new Error(`CAID-04: ${t.action_type} names a vendor or a vendor specification but is an initial IANA entry; add it to IANA_EXCLUDED`);
    }
  }
  // Succession stays inside each list: an initial IANA entry never names a
  // type that IANA is not asked to register, and the reverse.
  for (const t of reg.types) {
    for (const link of [t.supersedes, t.superseded_by].flat().filter(Boolean)) {
      if (IANA_EXCLUDED.has(t.action_type) !== IANA_EXCLUDED.has(link)) {
        throw new Error(`CAID-04: ${t.action_type} and ${link} are linked by succession but fall on different sides of the IANA split`);
      }
    }
  }
  const count = (list) => ({
    total: list.length,
    active: list.filter((t) => t.status === 'active').length,
    deprecated: list.filter((t) => t.status === 'deprecated').length,
  });
  const counts = { iana: count(iana), other: count(other) };
  if (JSON.stringify(counts) !== JSON.stringify(EXPECTED_SPLIT)) {
    throw new Error(`CAID-04: the IANA split is ${JSON.stringify(counts)}, not the decided ${JSON.stringify(EXPECTED_SPLIT)}`);
  }
  return { all: reg.types, iana, other, counts };
}

// A definition list, not a table (a 64-digit digest does not fit a table
// row). Each term is the action type, its status and, for a deprecated
// type, its successor; its description is the hexadecimal part of its
// definition_sha256, which the TXT render indents on the next line.
// xml2rfc keeps a term on the page of its description, so no page separates
// an entry's two lines (the TXT check below enforces it). Registry order is
// kept.
// A term longer than 66 characters would wrap in the TXT render (69
// columns with its indent), and a wrapped successor would read as an entry.
const entryHead = (t) => {
  const head = `${t.action_type} ${t.status}${t.superseded_by ? `, successor ${t.superseded_by}` : ''}`;
  if (head.length > 66) throw new Error(`CAID-04: the Appendix D term "${head}" would wrap in the TXT render`);
  return head;
};
function actionTypeList(anchor, types) {
  const dig = new Map(readJson('caid/registry/digests.json').types.map((t) => [t.action_type, t.definition_sha256]));
  const items = types.map((t) => {
    const d = dig.get(t.action_type);
    if (!d) throw new Error(`CAID-04: digests.json has no definition_sha256 for ${t.action_type}`);
    return `  <dt>${xmlEscape(entryHead(t))}</dt>\n  <dd><tt>${d.slice('sha256:'.length)}</tt></dd>`;
  });
  return [`<dl anchor="${anchor}" newline="true" spacing="compact">`, ...items, '</dl>'].join('\n');
}

// Anchors the draft uses for Appendix D and its two subsections.
const APPENDIX_D = {
  parent: 'appendix-action-types',
  // D.2 lists entries that are not initial entries, so the appendix is
  // named for the registry version it lists, not for the initial contents.
  parentName: 'Action Types of Reference Registry Version 5',
  iana: { section: 'appendix-action-types-initial', listing: 'appendix-d1-types', name: 'Initial IANA Entries' },
  other: { section: 'appendix-action-types-reference-only', listing: 'appendix-d2-types', name: 'Reference-Registry Entries Not Requested of IANA' },
};
let splitCache;
const splitOnce = () => { splitCache ??= actionTypeSplit(); return splitCache; };
const LISTINGS = {
  [APPENDIX_D.iana.listing]: () => actionTypeList(APPENDIX_D.iana.listing, splitOnce().iana),
  [APPENDIX_D.other.listing]: () => actionTypeList(APPENDIX_D.other.listing, splitOnce().other),
};

// ---------------------------------------------------------------------------
// cbor-sha256 (Section 3.1): core deterministic CBOR of a data-model value
// ---------------------------------------------------------------------------

// The data model maps to CBOR as Section 3.1 states: an object is a map
// with text-string keys, an array an array, a string a text string, a
// number (always an integer of magnitude at most 2^53-1) major type 0 or 1,
// and true, false and null the simple values 21, 20 and 22. Every argument
// takes its shortest form, and map keys sort by the bytewise order of their
// encodings (Section 4.2.1 of RFC 8949). Written here from RFC 8949 alone
// and self-tested against its Appendix A below. The C.1 values it gives
// were also reproduced with the Python cbor2 library in canonical mode
// before they went into the draft.
function cborHead(major, n) {
  const v = BigInt(n);
  const lead = major << 5;
  if (v < 24n) return Buffer.from([lead | Number(v)]);
  if (v < 0x100n) return Buffer.from([lead | 24, Number(v)]);
  if (v < 0x10000n) { const b = Buffer.alloc(3); b[0] = lead | 25; b.writeUInt16BE(Number(v), 1); return b; }
  if (v < 0x100000000n) { const b = Buffer.alloc(5); b[0] = lead | 26; b.writeUInt32BE(Number(v), 1); return b; }
  const b = Buffer.alloc(9); b[0] = lead | 27; b.writeBigUInt64BE(v, 1); return b;
}
function cborEncode(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === false) return Buffer.from([0xf4]);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error(`CAID-04: ${value} is not a number of the data model`);
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === 'string') {
    // A lone surrogate: a high surrogate not followed by a low one, or a low
    // surrogate not preceded by a high one (String.prototype.isWellFormed is
    // ES2024, past the es2022 library the type check uses).
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) throw new Error('CAID-04: a lone surrogate is not a string of the data model');
    const utf8 = Buffer.from(value, 'utf8');
    return Buffer.concat([cborHead(3, utf8.length), utf8]);
  }
  if (Array.isArray(value)) return Buffer.concat([cborHead(4, value.length), ...value.map(cborEncode)]);
  if (typeof value === 'object') {
    const members = Object.keys(value).map((k) => [cborEncode(k), cborEncode(value[k])]);
    members.sort((a, b) => Buffer.compare(a[0], b[0]));
    return Buffer.concat([cborHead(5, members.length), ...members.flat()]);
  }
  throw new Error(`CAID-04: ${typeof value} is not a value of the data model`);
}
// RFC 8949 Appendix A examples inside the data model, plus the two ends of
// the integer range and a key-order case.
const CBOR_SELF_TEST = [
  [0, '00'], [1, '01'], [10, '0a'], [23, '17'], [24, '1818'], [25, '1819'], [100, '1864'],
  [1000, '1903e8'], [1000000, '1a000f4240'], [1000000000000, '1b000000e8d4a51000'],
  [-1, '20'], [-10, '29'], [-100, '3863'], [-1000, '3903e7'],
  [2 ** 53 - 1, '1b001fffffffffffff'], [-(2 ** 53 - 1), '3b001ffffffffffffe'],
  [false, 'f4'], [true, 'f5'], [null, 'f6'],
  ['', '60'], ['a', '6161'], ['IETF', '6449455446'], ['"\\', '62225c'],
  ['ü', '62c3bc'], ['水', '63e6b0b4'], ['𐅑', '64f0908591'],
  [[], '80'], [[1, 2, 3], '83010203'], [[1, [2, 3], [4, 5]], '8301820203820405'],
  [{}, 'a0'], [{ a: 1, b: [2, 3] }, 'a26161016162820203'], [['a', { b: 'c' }], '826161a161626163'],
  [{ a: 'A', b: 'B', c: 'C', d: 'D', e: 'E' }, 'a56161614161626142616361436164614461656145'],
  [{ aa: 0, b: 0 }, 'a261620062616100'],
];
for (const [value, hex] of CBOR_SELF_TEST) {
  const got = cborEncode(value).toString('hex');
  if (got !== hex) throw new Error(`CAID-04: the CBOR encoder gives ${got} for ${JSON.stringify(value)}, not ${hex}`);
}

// RFC 8792 single-backslash folding at 69 columns, in the style of the
// draft's other folded examples; unfold() below reverses it.
const FOLD_NOTE = "=============== NOTE: '\\' line wrapping per RFC 8792 ================";
function fold(text) {
  const lines = text.split('\n');
  if (lines.every((l) => l.length <= 69)) return text;
  const out = [];
  for (let line of lines) {
    while (line.length > 69) {
      // Unfolding drops the leading spaces of a continuation line.
      if (line[68] === ' ') throw new Error(`CAID-04: cannot fold at a space: ${line.slice(0, 40)}...`);
      out.push(`${line.slice(0, 68)}\\`);
      line = `  ${line.slice(68)}`;
    }
    out.push(line);
  }
  return `${FOLD_NOTE}\n\n${out.join('\n')}`;
}

// The cbor-sha256 values of the C.1 object: its encoding as hexadecimal,
// 32 octets to a line, and the computation result under cbor-sha256.
function cborExample(dataModelObject, definitionSha256) {
  const bytes = cborEncode(dataModelObject);
  const hex = createHash('sha256').update(bytes).digest('hex');
  const result = {
    caid: `caid:1:${dataModelObject.action_type}:cbor-sha256:${Buffer.from(hex, 'hex').toString('base64url')}`,
    digest: `sha256:${hex}`,
    definition_sha256: definitionSha256,
  };
  return {
    bytes,
    result,
    hexListing: `${bytes.toString('hex').match(/.{1,64}/g).join('\n')}\n`,
    resultListing: `${fold(JSON.stringify(result, null, 2))}\n`,
  };
}

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

// RFC 8792 single-backslash unfolding.
const FOLD_HEADER = /^=* *NOTE: '\\' line wrapping per RFC 8792 *=*\n\n/;
function unfold(s) {
  if (!FOLD_HEADER.test(s)) return s;
  return s.replace(FOLD_HEADER, '').replace(/\\\n */g, '');
}

// The C.1 object, read from the draft, as the value of the data model that
// cbor-sha256 encodes (the RFC 8785 text of the reference validator parsed
// back: the same members, integers as numbers).
const sourceFile = path.join(packet, sourceRel);
function c1DataModel(src) {
  const m = /<sourcecode\b[^>]*\banchor="exc-payment-object"[^>]*>\s*<!\[CDATA\[\n?([\s\S]*?)\]\]>/.exec(src);
  if (!m) return { error: 'no sourcecode exc-payment-object' };
  let object;
  try { object = JSON.parse(unfold(m[1])); } catch (e) { return { error: `exc-payment-object is not JSON: ${e.message}` }; }
  const c = createReference(specOnce()).canonicalize(object);
  if (!c.ok) return { error: 'exc-payment-object is not a value of the data model' };
  return { value: JSON.parse(c.canonical) };
}
const digestOfType = (type) => readJson('caid/registry/digests.json').types.find((t) => t.action_type === type)?.definition_sha256;

/** @returns {Record<string, any>} */
function emitted() {
  /** @type {Record<string, any>} */
  const out = { ...Object.fromEntries(Object.entries(TABLES).map(([k, make]) => [k, make()])) };
  for (const [k, make] of Object.entries(LISTINGS)) out[k] = make();
  const { counts, all } = splitOnce();
  out['appendix-d-counts'] = { registry_version_5: all.length, ...counts };
  const c1 = c1DataModel(readFileSync(sourceFile, 'utf8'));
  if (c1.error) throw new Error(`CAID-04: ${c1.error}`);
  const cbor = cborExample(c1.value, digestOfType(c1.value.action_type));
  out['exc-payment-cbor'] = cbor.hexListing;
  out['exc-payment-cbor-result'] = cbor.resultListing;
  out['exc-payment-cbor-octets'] = cbor.bytes.length;
  return out;
}

if (process.argv.includes('--emit')) {
  const e = emitted();
  for (const anchor of Object.keys(TABLES)) console.log(`${e[anchor]}\n`);
  const { iana, other, registry_version_5: total } = e['appendix-d-counts'];
  console.log(`<!-- Appendix D: registry version 5 has ${total} type versions. D.1 (section ${APPENDIX_D.iana.section}, "${APPENDIX_D.iana.name}"): ${iana.total} initial IANA entries, ${iana.active} active and ${iana.deprecated} deprecated. D.2 (section ${APPENDIX_D.other.section}, "${APPENDIX_D.other.name}"): ${other.total} entries, ${other.active} active. Section 12.2 states the D.1 counts. -->\n`);
  for (const anchor of Object.keys(LISTINGS)) console.log(`${e[anchor]}\n`);
  console.log(`<!-- Appendix C.1, cbor-sha256: the core deterministic CBOR encoding of exc-payment-object is ${e['exc-payment-cbor-octets']} octets, shown in hexadecimal, 32 octets to a line. -->\n`);
  console.log(`<sourcecode anchor="exc-payment-cbor"><![CDATA[\n${e['exc-payment-cbor']}]]></sourcecode>\n`);
  console.log(`<sourcecode anchor="exc-payment-cbor-result" type="json"><![CDATA[\n${e['exc-payment-cbor-result']}]]></sourcecode>\n`);
  process.exit(0);
}
if (process.argv.includes('--emit-json')) {
  console.log(JSON.stringify(emitted()));
  process.exit(0);
}
const prefiling = process.argv.includes('--prefiling');
const rendersRequired = prefiling || process.argv.includes('--renders');

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

const errors = [];
const check = (condition, message) => { if (!condition) errors.push(message); };
const source = readFileSync(sourceFile, 'utf8');
const text = readFileSync(path.join(packet, textRel), 'utf8');
const html = readFileSync(path.join(packet, htmlRel), 'utf8');
const flat = (s) => s.replace(/\s+/g, ' ');
// XML as the reader sees it: CDATA kept as text, inline markup dropped (so
// <bcp14>MUST</bcp14> reads MUST and <tt>args</tt> reads args), every other
// tag read as a space, the five entities decoded, and whitespace
// collapsed. Text checks run on this.
const plain = (xml) => flat(xml
  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (_, c) => c.replaceAll('<', '\u0001'))
  .replace(/<\/?(?:bcp14|tt|em|strong|sub|sup|xref|eref|iref|relref|u)\b[^>]*>/g, '')
  .replace(/<[^>]*>/g, ' ')
  .replaceAll('\u0001', '<')
  .replaceAll('&#8209;', '-')
  .replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&apos;', "'").replaceAll('&amp;', '&'));
const sourcePlain = plain(source);
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

/** The body of the list item with this anchor (a change-log item). */
function item(anchor) {
  const m = new RegExp(`<li anchor="${anchor}">([\\s\\S]*?)</li>`).exec(source);
  if (!m) { errors.push(`no list item ${anchor}`); return ''; }
  return m[1];
}
/** A section or, for a chg- or ed- anchor, a change-log item. */
const part = (anchor) => (/^(?:chg|ed)-/.test(anchor) ? item(anchor) : section(anchor));

/** The CDATA text of the sourcecode with this anchor, without its first line break. */
function code(anchor) {
  const re = new RegExp(`<sourcecode\\b[^>]*\\banchor="${anchor}"[^>]*>\\s*<!\\[CDATA\\[\\n?([\\s\\S]*?)\\]\\]>\\s*</sourcecode>`);
  const m = re.exec(source);
  if (!m) { errors.push(`no sourcecode ${anchor}`); return ''; }
  return m[1];
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
// RFC 7696 (BCP 201): Section 10.1 says how each SHA-256 value migrates.
// RFC 6920 and RFC 8141: Section 12.8 says why the caid scheme is defined
// instead of an ni URI or a URN namespace.
for (const n of ['7595', '7942', '8126', '8792', '7696', '6920', '8141']) check(informativeRfcs.has(n), `informative reference RFC ${n} missing`);
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
// F1-DIG-TWO-V4-FILES: two files on main declared registry version 4
// (2c0cd467f, 61e8d58b3). history/action-types.v4.json is the later one, the
// file digests.json pins, and Section 14.4 names it.
const v4Path = v4File?.path ?? '';
check(v4Path === 'history/action-types.v4.json' && `sha256:${createHash('sha256').update(readFileSync(path.join(root, 'caid/registry', v4Path))).digest('hex')}` === v4File?.sha256,
  'caid/registry/history/action-types.v4.json is not the registry version 4 file that digests.json pins');
// F1-DIG-D2-BYTE-FOR-BYTE: Appendix D.2 says its entries are unchanged
// member for member from registry version 4, so their RFC 8785 encodings
// are identical. The two files differ in layout, so it says nothing of
// octets.
{
  const v4 = readJson(`caid/registry/${v4Path || 'history/action-types.v4.json'}`);
  for (const name of IANA_EXCLUDED.keys()) {
    const a = ref.canonicalize(v4.types.find((t) => t.action_type === name));
    const b = ref.canonicalize(registry.types.find((t) => t.action_type === name));
    check(a.ok && b.ok && a.canonical === b.canonical, `Appendix D.2 says ${name} is unchanged from registry version 4, but its RFC 8785 encodings differ`);
  }
}
// The counts of the whole registry belong to Section 14.4, which describes
// registry version 5; Section 12.2 and Appendix D.1 state the IANA split.
{
  const registrySection = plain(section('changes-03-registry'));
  for (const phrase of [`${registry.types.length} type versions`, `${active} active`, `${deprecated} deprecated`]) {
    check(registrySection.includes(phrase), `Section 14.4 (changes-03-registry) does not state "${phrase}" for registry version 5`);
  }
}

// [CAID-REGISTRY]: a fixed commit, the file's raw octets, and the pinned
// digest. The digest covers the octets of action-types.json, which a blob
// URL does not serve (it serves an HTML page), so the reference targets the
// raw.githubusercontent.com URL of the file at that commit: both renders
// then print it as the reference's URL, in angle brackets in the TXT and
// as a link in the HTML.
const registryRef = /<reference anchor="CAID-REGISTRY"[\s\S]*?<\/reference>/.exec(source)?.[0] ?? '';
check(registryRef, 'no [CAID-REGISTRY] reference');
const REPO = 'emiliaprotocol/emilia-protocol';
const pinnedCommit = new RegExp(`target="https://raw\\.githubusercontent\\.com/${REPO}/([0-9a-f]{40})/caid/registry/action-types\\.json"`).exec(registryRef)?.[1];
check(pinnedCommit, '[CAID-REGISTRY] does not target the raw action-types.json at a full 40-digit commit');
check(!registryRef.includes('github.com/' + REPO + '/blob/'), '[CAID-REGISTRY] still names a blob URL, which serves an HTML page, not the octets the digest covers');
if (pinnedCommit) {
  const raw = `https://raw.githubusercontent.com/${REPO}/${pinnedCommit}/caid/registry/action-types.json`;
  // R2-RAWURL-RENDER: the TXT prints the URL once, inside angle brackets,
  // and line breaks inside it are the only whitespace.
  const shown = /<(https:\/\/raw\.githubusercontent\.com\/[^>]*)>/.exec(text)?.[1]?.replace(/\s+/g, '');
  check(shown === raw, `the TXT render does not print the [CAID-REGISTRY] URL ${raw} in angle brackets (found ${shown ?? 'none'})`);
  check(!/<\/?annotation>[\s\S]*raw\.githubusercontent/.test(registryRef.replace(/target="[^"]*"/, '')), '[CAID-REGISTRY] repeats the raw URL in its annotation, where xml2rfc breaks it with a stray space');
  // The commit must carry the pinned bytes. A shallow clone (CI) may lack
  // the commit; --prefiling requires it.
  let blob = null;
  try { blob = execFileSync('git', ['-C', root, 'show', `${pinnedCommit}:caid/registry/action-types.json`], { stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1 << 26 }); } catch { /* absent */ }
  if (blob) check(`sha256:${createHash('sha256').update(blob).digest('hex')}` === v5Sha, `action-types.json at the [CAID-REGISTRY] commit ${pinnedCommit} is not registry version 5`);
  else if (prefiling) errors.push(`the [CAID-REGISTRY] commit ${pinnedCommit} is not in this clone`);
  else console.log(`CAID-04: note: commit ${pinnedCommit} is not in this clone, so the [CAID-REGISTRY] file digest was not checked at that commit`);
}

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
  check(source.includes(make()), `list ${anchor} differs from the one generated from the registry and digests.json (run with --emit)`);
  check(source.split(`anchor="${anchor}"`).length === 2, `list ${anchor} appears other than once`);
}

// ---------------------------------------------------------------------------
// Appendix D and Section 12.2: the IANA split of registry version 5
// ---------------------------------------------------------------------------

const split = splitOnce();
const NUMBER_WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve'];
// "<n> <noun>" with n in digits, or spelled out when it is twelve or less.
const statesCount = (txt, n, nouns) => {
  const forms = [String(n), ...(n < NUMBER_WORDS.length ? [NUMBER_WORDS[n]] : [])];
  return forms.some((f) => nouns.some((noun) => new RegExp(`(^|[^0-9A-Za-z])${f} ${noun}\\b`, 'i').test(txt)));
};
{
  const d = APPENDIX_D;
  const parent = section(d.parent);
  const d1 = section(d.iana.section);
  const d2 = section(d.other.section);
  check(parent.includes(`<section anchor="${d.iana.section}"`) && parent.includes(`<section anchor="${d.other.section}"`), `Appendix D (${d.parent}) does not hold D.1 (${d.iana.section}) and D.2 (${d.other.section})`);
  check(parent.indexOf(`<section anchor="${d.iana.section}"`) < parent.indexOf(`<section anchor="${d.other.section}"`), 'Appendix D.1 does not precede D.2');
  const nameOf = (body) => /^<section\b[^>]*>\s*<name>([\s\S]*?)<\/name>/.exec(body)?.[1]?.replace(/\s+/g, ' ').trim().toLowerCase();
  check(nameOf(d1) === d.iana.name.toLowerCase(), `Appendix D.1 is not named "${d.iana.name}"`);
  check(nameOf(d2) === d.other.name.toLowerCase(), `Appendix D.2 is not named "${d.other.name}"`);
  check(d1.includes(`anchor="${d.iana.listing}"`), `Appendix D.1 does not hold the listing ${d.iana.listing}`);
  check(d2.includes(`anchor="${d.other.listing}"`), `Appendix D.2 does not hold the listing ${d.other.listing}`);
  check(!source.includes('anchor="appendix-d-types"'), 'the unsplit Appendix D listing appendix-d-types is still in the draft');
  check(nameOf(parent) === d.parentName.toLowerCase(), `Appendix D is not named "${d.parentName}"; it lists entries that are not initial entries (D.2)`);
  // Every type of registry version 5 appears exactly once, with its digest.
  const listBody = (anchor) => new RegExp(`<dl anchor="${anchor}"[\\s\\S]*?</dl>`).exec(source)?.[0] ?? '';
  const listed = [...`${listBody(d.iana.listing)}${listBody(d.other.listing)}`.matchAll(/<dt>([a-z][a-z0-9.-]*\.[1-9][0-9]*) /g)].map((m) => m[1]);
  check(same([...listed].sort(), split.all.map((t) => t.action_type).sort()), `Appendix D.1 and D.2 together do not list each of the ${split.all.length} types of registry version 5 once`);
  const { iana, other } = split.counts;
  const parentText = plain(parent.slice(0, parent.indexOf('<section anchor=', 1)));
  check(statesCount(parentText, split.all.length, ['type versions', 'types', 'entries']), `the Appendix D introduction does not state the ${split.all.length} type versions of registry version 5`);
  const d1Text = plain(d1.replace(/<dl\b[\s\S]*?<\/dl>/g, ''));
  check(statesCount(d1Text, iana.total, ['entries', 'types', 'type versions']), `Appendix D.1 does not state its ${iana.total} entries`);
  check(statesCount(d1Text, iana.active, ['active']) && statesCount(d1Text, iana.deprecated, ['deprecated']), `Appendix D.1 does not state ${iana.active} active and ${iana.deprecated} deprecated`);
  const d2Text = plain(d2.replace(/<dl\b[\s\S]*?<\/dl>/g, ''));
  check(statesCount(d2Text, other.total, ['entries', 'types', 'type versions']), `Appendix D.2 does not state its ${other.total} entries`);
  check(d2Text.includes('Specification Required'), 'Appendix D.2 does not say its entries may be registered under Specification Required');
  // Section 12.2 asks IANA for exactly the D.1 entries.
  const actionTypes = section('iana-action-types');
  const atText = plain(actionTypes);
  check(statesCount(atText, iana.total, ['entries']), `Section 12.2 does not state the ${iana.total} initial entries`);
  check(statesCount(atText, iana.active, ['active']) && statesCount(atText, iana.deprecated, ['deprecated']), `Section 12.2 does not state ${iana.active} active and ${iana.deprecated} deprecated initial entries`);
  check(actionTypes.includes(`<xref target="${d.iana.section}"`), 'Section 12.2 does not point at Appendix D.1 for the initial contents');
  check(actionTypes.includes(`<xref target="${d.other.section}"`), 'Section 12.2 does not point at Appendix D.2 for the entries not requested of IANA');
  check(!statesCount(atText, active, ['active']), `Section 12.2 still states the ${active} active types of the whole registry as IANA contents`);
  check(!atText.includes('The definitions of the initial entries are the file'), 'Section 12.2 still makes the whole registry file the initial contents');
  check(atText.includes('Specification Required'), 'Section 12.2 lacks its registration policy');
  // Section 12: every initial Action Types entry also references
  // [CAID-REGISTRY], which holds its definition; Section 4.7 reproduces the
  // tool.call.1 entry, so the document and the registry give one text for
  // it. The reference registry holds a superset of the initial contents.
  const ianaSection = section('iana');
  const ianaIntro = ianaSection.slice(0, ianaSection.indexOf('<section anchor=', 1));
  check(!plain(ianaIntro).includes('The reference for every initial entry of every registry below is this document, and its change controller is the IETF.'), 'Section 12 still names this document as the only reference of every initial entry');
  check(plain(ianaIntro).includes('tool.call.1') && ianaIntro.includes('<xref target="CAID-REGISTRY"'), 'Section 12 does not say that the initial Action Types entries also reference [CAID-REGISTRY] and where tool.call.1 is reproduced');
  check(plain(ianaIntro).includes('superset') && ianaIntro.includes(`<xref target="${d.other.section}"`), 'Section 12 does not say that the reference registry records a superset of the initial Action Types contents (Appendix D.2)');
  // R1, NUM-R1-1: one definition text for tool.call.1. Section 12.2 and the
  // Appendix D introduction no longer carve tool.call.1 out of "the entry
  // with that name in the registry file"; Section 4.7 prints that entry
  // (checked member for member below).
  for (const [where, body] of [['Section 12', ianaIntro], ['Section 12.2', actionTypes], ['Appendix D', parent.slice(0, parent.indexOf('<section anchor=', 1))]]) {
    check(!plain(body).includes('other than tool.call.1'), `${where} still carves tool.call.1 out of the registry definitions`);
    check(!plain(body).includes('tool.call.1 is defined in'), `${where} still gives tool.call.1 a definition apart from its registry entry`);
  }
  check(plain(parent.slice(0, parent.indexOf('<section anchor=', 1))).includes('reproduces the tool.call.1 entry'), 'the Appendix D introduction does not say that Section 4.7 reproduces the tool.call.1 entry');
  check(plain(actionTypes).includes('reproduces the tool.call.1 entry'), 'Section 12.2 does not say that Section 4.7 reproduces the tool.call.1 entry');
  // R4: D.2 holds seven types defined by other specifications and one whose
  // name misdescribes it; only the seven may be registered later.
  check(plain(actionTypes).includes('one whose name misdescribes it'), 'Section 12.2 calls every D.2 entry a type defined by another specification (dns.zone.transfer.1 is a misnomer)');
  check(plain(actionTypes).includes('Each of the seven types defined by other specifications may be registered'), 'Section 12.2 does not limit later registration to the seven specification-defined D.2 types');
  check(d2Text.includes('Each of the seven types defined by other specifications may be registered') && d2Text.includes('dns.zone.transfer.1 is not to be registered'), 'Appendix D.2 does not limit later registration to the seven specification-defined types and keep dns.zone.transfer.1 out');
  check(!/Each may be registered/.test(d2Text) && !/may be registered under Specification Required with their own/.test(plain(actionTypes)), 'Appendix D.2 or Section 12.2 still lets every D.2 entry, dns.zone.transfer.1 included, be registered');
  // R2, R1-SEC10-RESIDUE: the entropy criterion binds registrations made
  // after this document; the D.1 entries point to Sections 11 and 4.7.
  check(plain(actionTypes).includes('in a registration made after this document, a type whose required fields can all be low-entropy'), 'Section 12.2 applies the 128-bit criterion to the initial entries, which do not meet it');
  check(/registered by\s+this document: <xref target="privacy"\/> states why their identifiers\s+are not required to carry 128 bits of entropy/.test(actionTypes), 'Section 12.2 does not say that Section 11 states why the D.1 identifiers need not carry 128 bits of entropy');
  // R5: the IESG acts for a change controller only when it cannot be
  // reached or does not respond, for suites as for every other entry.
  check(plain(ianaIntro).includes('cannot be reached or does not respond'), 'Section 12 does not bound when the IESG acts for a change controller');
  check(plain(section('iana-suites')).includes('its change controller requests the deprecation, or the IESG does for a controller that cannot be reached or does not respond'), 'Section 12.1 lets the IESG deprecate a suite whose controller can be reached');
  // R1-GOV-ABSOLUTE, R4: GOVERNANCE.md section 7.1 lists the D.2 entries
  // and states neither false absolute.
  const gov = read('caid/registry/GOVERNANCE.md');
  for (const name of IANA_EXCLUDED.keys()) check(gov.includes(`\`${name}\``), `caid/registry/GOVERNANCE.md section 7.1 does not list ${name}`);
  check(!gov.includes('No other type in registry version 5 names a vendor'), 'GOVERNANCE.md still says that no other type names a vendor (package.publish.1 names npm, wire.transfer.1 names SWIFT)');
  check(gov.includes('No other type is named for a vendor or product, or cites a vendor') && gov.includes('each of the seven types defined by another specification can be') && gov.includes('`dns.zone.transfer.1` is not a candidate'), 'GOVERNANCE.md section 7.1 does not limit later registration to the seven specification-defined types');
  check(flat(gov).includes('does not register a name whose first segment is organization-specific unless that organization is the change controller'), 'GOVERNANCE.md section 7.1 does not carry the rule of Section 12.2 for organization-specific names (R2-REG-10)');
  // R2-ISO4217-TERMS: Section 12.2 says each snapshot file records its
  // source and its enum_snapshot_files entry records what is known of its
  // terms (the ISO 4217 file itself carries no terms member).
  for (const f of registry.enum_snapshot_files) {
    const file = readJson(`caid/registry/${f.path}`);
    check(file.source && typeof file.source === 'object' && typeof file.source.url === 'string', `the snapshot file ${f.path} does not record its source, as Section 12.2 says`);
    check(typeof f.license === 'string' && f.license.length > 0, `the enum_snapshot_files entry for ${f.path} records no terms, as Section 12.2 says it does`);
  }
  // R2-GATE-6: the ed-iana change item restates the split; its counts are
  // the split's, as those of Section 12.2 and D.1 are.
  const edIana = plain(item('ed-iana'));
  check(edIana.includes(`Of the ${split.all.length} types of reference registry version 5, IANA is asked to register the ${iana.total} of`) && edIana.includes(`the ${other.total} of`),
    `the ed-iana change item does not state the split: ${split.all.length} types, ${iana.total} registered, ${other.total} not requested`);
  // R2-REG-7: Section 12.2 counts the deprecated initial entries, and each
  // of them has a required external enum with no pinned snapshot, so it
  // computes nothing (the registry-* vectors of those types refuse).
  check(plain(actionTypes).includes(`The ${iana.deprecated} deprecated initial entries`) && plain(actionTypes).includes(`none of the ${iana.deprecated} produces or verifies a CAID`),
    `Section 12.2 does not state that the ${iana.deprecated} deprecated initial entries produce and verify no CAID`);
  const unpinnedRequired = (t) => (t.required_fields ?? []).some((f) => f.type === 'enum' && !Array.isArray(f.values)
    && !(typeof f.values_ref === 'string' && f.values_ref.startsWith('inline:')) && !(f.values_snapshot && f.values_sha256));
  for (const t of split.iana.filter((x) => x.status === 'deprecated')) {
    check(unpinnedRequired(t), `Section 12.2 says every deprecated initial entry has a required enum with no pinned snapshot, but ${t.action_type} does not`);
  }
  const byName = new Map(split.all.map((t) => [t.action_type, t]));
  const enumToCode = split.iana.filter((t) => t.status === 'deprecated' && (t.required_fields ?? []).some((f) => f.type === 'enum'
    && [...(byName.get(t.superseded_by)?.required_fields ?? []), ...(byName.get(t.superseded_by)?.optional_fields ?? [])].some((g) => g.name === f.name && g.type === 'code')));
  check(statesCount(plain(actionTypes), enumToCode.length, ['of them hold as enums values that their successors carry as code fields']),
    `Section 12.2 does not say that ${enumToCode.length} deprecated initial entries hold as enums values their successors carry as code fields (${enumToCode.map((t) => t.action_type).join(', ')})`);

  // R2-REG-4: no page of the TXT render separates an entry's name line from
  // its digest line. Each digest line (six spaces, 64 hexadecimal digits)
  // directly follows its name line, and there is one pair per type.
  const lines = text.split('\n');
  const nameLine = /^ {3}([a-z][a-z0-9.-]*\.[1-9][0-9]*) (?:active|deprecated)\b/;
  let pairs = 0;
  lines.forEach((line, i) => {
    if (!/^ {6}[0-9a-f]{64}$/.test(line)) return;
    const prev = lines[i - 1] ?? '';
    if (nameLine.test(prev)) pairs += 1;
    else errors.push(`the TXT render separates an Appendix D digest from its name line (line ${i + 1}, after "${prev.trim().slice(0, 40)}")`);
  });
  check(pairs === split.all.length, `the TXT render shows ${pairs} Appendix D name and digest pairs, not ${split.all.length}`);
}

// ---------------------------------------------------------------------------
// The registries the document requests, as the Abstract and Section 12 say
// ---------------------------------------------------------------------------

const REGISTRIES = [
  // [registry name, words that name it in the Abstract]
  ['CAID Suites', 'suites'],
  ['CAID Action Types', 'action types'],
  ['CAID Field Types', 'field types'],
  ['CAID Code Formats', 'code formats'],
  ['CAID Reason Codes', 'reason'],
  ['CAID Mapping Transforms', 'transforms'],
  ['CAID Mapping Loss Policies', 'loss policies'],
];
{
  const iana = section('iana');
  const registryNames = [...iana.matchAll(/<section anchor="iana-[^"]*">\s*<name>(CAID [^<]*)<\/name>/g)].map((m) => m[1]);
  check(same(registryNames, REGISTRIES.map(([n]) => n)), `Section 12 creates the registries ${registryNames.join(', ')}, not the seven expected`);
  const ianaIntro = plain(iana.slice(0, iana.indexOf('<section anchor=', 1)));
  check(statesCount(ianaIntro, REGISTRIES.length, ['registries']), `Section 12 does not ask for ${NUMBER_WORDS[REGISTRIES.length]} registries`);
  const abstract = plain(/<abstract>([\s\S]*?)<\/abstract>/.exec(source)?.[1] ?? '').toLowerCase();
  for (const [name, words] of REGISTRIES) check(abstract.includes(words), `the Abstract does not name the ${name} registry ("${words}")`);
  check(!abstract.includes('mapping terms'), 'the Abstract still folds two registries into "mapping terms"');
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

// C.1 under cbor-sha256: the encoding, its octet count, the digest and the
// CAID, recomputed by the encoder above. Support for the suite is OPTIONAL
// (Section 3.1) and no port implements it, so this example is its only
// test value in the document.
{
  const example = section('example-compute');
  const c1 = c1DataModel(source);
  if (c1.error) errors.push(`C.1 cbor-sha256: ${c1.error}`);
  else {
    const cbor = cborExample(c1.value, digestOf(c1.value.action_type));
    const shownHex = code('exc-payment-cbor').replace(/\s+/g, '');
    check(/^[0-9a-f]+$/.test(shownHex) && shownHex === cbor.bytes.toString('hex'), 'C.1 cbor-sha256 encoding does not recompute (run with --emit)');
    check(code('exc-payment-cbor') === cbor.hexListing, 'C.1 cbor-sha256 encoding is not shown as the generated listing, 32 octets to a line (run with --emit)');
    check(same(codeJson('exc-payment-cbor-result'), cbor.result), 'C.1 cbor-sha256 result does not recompute (run with --emit)');
    check(matches(rules, 'caid', cbor.result.caid), 'C.1 cbor-sha256 CAID does not match the caid rule');
    check(example.includes('anchor="exc-payment-cbor"') && example.includes('anchor="exc-payment-cbor-result"'), 'the cbor-sha256 values are not in Appendix C.1');
    check(plain(example).includes(`is ${cbor.bytes.length} octets`), `C.1 does not state that the CBOR encoding is ${cbor.bytes.length} octets`);
  }
}

// Section 4.2: the type definition example is the registry version 5 entry
// for payment.release.1, member for member, with its real values_sha256,
// so its definition_sha256 is the one C.1 prints. Line breaks inside its
// strings are presentation only, so every line break and the indentation
// after it read as one space.
{
  const shown = unfold(code('ex-definition')).replace(/\n\s*/g, ' ');
  let parsed;
  try { parsed = JSON.parse(shown); } catch (e) { errors.push(`the Section 4.2 example (ex-definition) is not JSON once its line breaks are read as spaces: ${e.message}`); }
  if (parsed !== undefined) {
    const entry = registry.types.find((t) => t.action_type === 'payment.release.1');
    const a = ref.canonicalize(parsed);
    const b = ref.canonicalize(entry);
    check(a.ok && b.ok && a.canonical === b.canonical, 'the Section 4.2 example (ex-definition) is not the registry version 5 entry for payment.release.1');
    check(ref.definitionSha256(parsed) === paymentResult?.definition_sha256, 'the Section 4.2 example does not hash to the C.1 definition_sha256');
    check(section('schema').includes('anchor="ex-definition"'), 'the ex-definition example is not in Section 4.2');
  }
}

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

// F1-DIG-PATIENTREF-PREIMAGE: Section 11 says the digest-typed values of
// Appendix C are digests of short example strings and can be recovered by
// guessing. Every digest field of the C.1, C.2 and C.5 objects is the
// SHA-256 of one of these strings; the C.6 values recompute below from the
// C.6 source through the profile's transforms.
{
  const PREIMAGES = ['test', 'patient-0042'];
  const known = new Set(PREIMAGES.map((s) => `sha256:${sha256Hex(s)}`));
  for (const [anchor, object] of [['exc-payment-object', payment], ['exc-refusal-object', refused], ['exc-code-object', coded], ['exc-code-refusal-object', codedBad]]) {
    const definition = registry.types.find((t) => t.action_type === object?.action_type);
    check(definition, `${anchor} names no registry type`);
    for (const field of [...(definition?.required_fields ?? []), ...(definition?.optional_fields ?? [])]) {
      if (field.type !== 'digest' || !Object.prototype.hasOwnProperty.call(object, field.name)) continue;
      check(known.has(object[field.name]), `${anchor}: ${field.name} is not the SHA-256 of a known short example string, so the Section 11 recovery sentence is unverified for it`);
    }
  }
  check(plain(section('privacy')).includes('are digests of short example strings and can be recovered this way'), 'Section 11 no longer says the Appendix C digests can be recovered; update this check');
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

// Section 4.7: the registration is the registry version 5 entry for
// tool.call.1, member for member (summary, notes and digest_notes
// included), so the document and the file IANA stores give one text for
// the entry. Line breaks inside its strings read as one space, as in the
// Section 4.2 example.
{
  const shown = unfold(code('ex-tool-definition')).replace(/\n\s*/g, ' ');
  let parsed;
  try { parsed = JSON.parse(shown); } catch (e) { errors.push(`the Section 4.7 registration (ex-tool-definition) is not JSON once its line breaks are read as spaces: ${e.message}`); }
  if (parsed !== undefined) {
    const a = ref.canonicalize(parsed);
    const b = ref.canonicalize(toolDef);
    check(a.ok && b.ok && a.canonical === b.canonical, 'the Section 4.7 registration (ex-tool-definition) is not the registry version 5 entry for tool.call.1, member for member');
    check(ref.definitionSha256(parsed) === digestOf('tool.call.1'), 'the Section 4.7 registration does not hash to the tool.call.1 definition_sha256');
  }
  check(section('tool-call-type').includes('anchor="ex-tool-definition"'), 'the ex-tool-definition registration is not in Section 4.7');
  // The prose names the executor-binding strings the entry's digest_notes
  // name, not a second spelling of them.
  const prefix = /Existing (base[a-z-]*:sha256:<hex>)/.exec(toolDef.digest_notes)?.[1];
  check(prefix && plain(section('tool-call-type').replace(/<sourcecode[\s\S]*?<\/sourcecode>/g, '')).includes(prefix), `Section 4.7 prose does not name the ${prefix} strings that the tool.call.1 digest_notes name`);
  // R7: occurrence_id is required only when args carries no identifier with
  // the needed property.
  check((plain(section('tool-call-type')).match(/unless args already carries an identifier/g) ?? []).length === 2, 'Section 4.7 requires occurrence_id even when args already carries an identifier with the needed property (R7)');
}

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
// Rules the document keeps. Checked on the plain text, so BCP 14 markup
// around a keyword does not matter.
for (const [needle, what] of [
  ['MUST NOT be abbreviated', 'truncation rule'],
  ['no replay protection', 'replay statement'],
  ['MUST verify every CAID', 'multiple-CAID rule'],
  ['MUST cover the complete CAID string', 'signature coverage rule'],
  ['same confidentiality as its action object', 'confidentiality statement'],
  ['linear in the length', 'code format matching bound'],
  ['registers no media type', 'media type decision'],
  ['none of them is independent', 'implementation independence statement'],
  ['reproductions', 'reproduction statement'],
  ['Support for this suite is OPTIONAL', 'OPTIONAL support for cbor-sha256 (Section 3.1)'],
]) check(sourcePlain.includes(needle), `source lacks the ${what}`);

// ---------------------------------------------------------------------------
// The pre-filing review: text each confirmed finding removes or requires
// ---------------------------------------------------------------------------

// Wording the review found wrong. Checked on the plain text of the whole
// source, the change logs included, because several defects are repeated
// there. A RegExp needle is matched as given.
for (const [needle, what] of [
  ['underflows rounds to zero', 'ART-JSON-1: a nonzero subnormal is not zero (Section 2.3)'],
  ['one that underflows is the integer 0', 'ART-JSON-1: the same claim in Section 14.2'],
  ['unescaped control character', 'ART-JSON-2: name the range U+0000 through U+001F (Sections 2.4, 14.1)'],
  ['hold for the part of the text that encodes', 'SEC-2: the embedded action object sentence (Section 2.4)'],
  ['second-preimage resistance of SHA-256', 'SEC-1: Section 10.1 names only second-preimage resistance'],
  ['a suite whose algorithm weakens is deprecated', 'SEC-1, IANA-8: the Section 12.1 deprecation trigger'],
  ['read one artifact read one value', 'SEC-5: the Section 10.6 one-value claim'],
  ['SHA-256(canonical_bytes', 'SEC-8: the Section 3.2 digest is the suite\'s digest'],
  ['lossy, or ambiguous', 'SEC-9: the undefined "ambiguous" MUST of Section 10.11'],
  ['that affects validation is immutable', 'SEC-7: immutability also covers material meaning (Section 12.2)'],
  ['freely redistributable', 'IANA-4: the Section 4.5 redistribution claim'],
  [/provisional/i, 'IANA-5: the URI scheme is requested as Permanent (Sections 12, 12.8, 14.5)'],
  ['dereferencing it is undefined', 'IANA-15: no operation is defined and a CAID is not dereferenced (Section 12.8)'],
  ['every conforming implementation, at any depth.', 'IMPL-1: numbers beyond depth 64 are not examined (Section 2.3)'],
  ['anywhere in the object, at any depth, is outside', 'IMPL-1: the same in Table 2, phase 6'],
  ['is not the kind that field type accepts', 'IMPL-2: the Section 2.5 host-value kind rule'],
  ['a host value outside the data model is not one', 'IMPL-4: the Table 2 phase 1 parenthetical'],
  ['implementations MAY support it', 'IMPL-6: cbor-sha256 support is OPTIONAL'],
  ['affirmative', 'IMPL-12: "the boolean true" (Sections 8.1, 8.3, C.6)'],
  ['discovery declaration', 'ED-04: Section 1 uses the Section 7 name "discovery document"'],
  ['challenge echo', 'ED-04: Section 1 uses the Section 7 name "authorization challenge"'],
  ['Each of these refuses when absent', 'ED-06: absent enum snapshots do not refuse (Section 5)'],
  ['contains action_type, target, tool, and args', 'ED-08: a tool.call.1 object consists of exactly those members'],
  ['without changing processing', 'ED-10: the Section 12.4 rationale'],
  ['IDentifier', 'ED-13: "Identifier" capitalization'],
  ['the only permitted canonical forms', 'ED-15: conflicts with suite agility'],
  ['states the boundary normatively', 'ED-16: Section 1 wording'],
  ['the registered code formats', 'IANA-10: Appendix A names the code formats this document registers'],
  ['ships in the author', 'CLM-3: the verification package sentence of Section 13'],
  ['cross-format interoperability vectors', 'CLM-4: "candidate cross-format mapping vectors" (Section 13)'],
  ['shared interoperability corpus', 'CLM-4: the same in Section 14.2'],
  ['two adapters shipped by the same project', 'CLM-5: the divergent adapters were the author\'s own (Section 4.7)'],
  ['states the same rule', 'CLM-9: thallapelly reaches the same conclusion (Section 3.6)'],
  // Round 1 of the fix audit.
  ['such a decoder reads 99999.00', 'R1-SEC6-SWIFT: only a case-insensitive decoder reads 99999.00 (Section 10.6)'],
  ['every host number is "number"', 'R1-IMPL2-BINDING: a binding decides which host types are numbers (Section 6.1)'],
  ['The value of a host number is', 'R1-IMPL2-BINDING: the same in Section 2.5'],
  ['in place of the plain digest that the type\'s notes describe', 'R6: a keyed commitment needs a type whose notes specify it (Section 11)'],
  ['will vendor a copy of the JavaScript implementation;', 'R8: the vendored copy carries no mapping (Section 13)'],
  ['its change controller, or the IESG, requests the deprecation', 'R5: the IESG acts only for a controller that cannot be reached (Section 12.1)'],
  ['base-action:sha256', 'R1: Section 4.7 names the base:sha256 strings its digest_notes name'],
  // Round 2 of the fix audit.
  ['counts twice. For such a value', 'R2-VALUECOUNT-DEPTH: the value count stops at depth 64 (Section 2.5)'],
  ['past it, the value is refused as unsupported_value alone', 'R2-VALUECOUNT-REASON: only a host action object past the count is unsupported_value (Section 2.2)'],
  ['When a host value is made of more values than the value count', 'R2-VALUECOUNT-REASON: the same in Section 5'],
  ['Host values that hold more than 33,554,432 values', 'R2-VALUECOUNT-REASON: the same in Section 14.1'],
  ['each snapshot file records its source and what is known of its terms', 'R2-ISO4217-TERMS: the ISO 4217 file records no terms; its enum_snapshot_files entry does (Section 12.2)'],
  ['definition no longer depends on conformance;', 'R2-CHG-PROJECTION: the projection no longer depends on the condition that uses it (Section 14.6)'],
  ['A host definition, mapping profile, or mapping source nested that deep', 'R2-CHG-DEEP-DEF: only a projection nested that deep is refused (Section 14.1)'],
  ['strings are for presentation only, and its long line', 'R2-4.2-LINEBREAKS: Section 4.2 says how a line break inside a string reads'],
  ['names that local deployments use', 'R2-REG-10: Section 12.2 gives the expert a rule for organization-specific names'],
  ['A literal that overflows binary64', 'R2-REG-5: Section 4.3 uses the Section 2.3 infinity boundary'],
  ['Initial CAID Action Types', 'R2-NUM-01: Appendix D lists entries that are not initial entries'],
  // Round 3 of the fix audit.
  ['refused as unsupported_value alone, whatever else it holds', 'R3-VALUECOUNT-ALONE: past the value count phases 3 and 4 still run (Section 2.2)'],
  ['unsupported_value alone (host action object)', 'R3-VALUECOUNT-ALONE: the value-count row of Table 1'],
  ['as one value: unsupported_value alone', 'R3-VALUECOUNT-ALONE: Section 14.1'],
  ['holds a number outside the model is refused as unsupported_number alone', 'R3-VALUECOUNT-ALONE: the canonical-size sentence of Section 2.2'],
  ['but the count is that of the expansion, down to depth 64', 'R3-REG-1: a reference back to an enclosing object or array counts as one value (Section 2.5)'],
  ['phase 6 every number in the data model', 'R3-REG-2: phase 6 examines numbers only down to depth 64 (Section 1.2 figure)'],
  ['have the confidentiality of personal data', 'R3-PRIVACY-WORDING: what a sequential identifier costs (Section 11)'],
  ['read neither member of such a profile', 'R3-STAGEB-HISTORY, R3-REG-4: the earlier JavaScript mapper read both members of most profiles outside the data model (Section 14.2)'],
  // Round 4 of the fix audit.
  ['so deprecated types resolve, compute, and verify', 'F1-REG-DEPRECATED: a deprecated type computes only where its fields resolve (Section 14.2)'],
  ['-03 said that identifiers may be treated as public values', 'F1-ED-LOGGING-03-QUOTE: -03 recommended it (Section 14.5)'],
  ['stay in registry version 5 byte for byte', 'F1-DIG-D2-BYTE-FOR-BYTE: the D.2 entries keep their values, not their octets (Appendix D.2)'],
  ['object, at any depth up to 64, is outside the data model', 'F1-REG-UNIVERSAL-NUMBER: the Table 2 phase 6 row holds only within the value count'],
  // Round 5 of the fix audit.
  ['phase 6 every number, down to depth 64, in the data model', 'F2-ITEMS-1: the Section 1.2 figure scopes phase 6 to the value count'],
  ['fractional number is refused as unsupported_number alone', 'F2-ITEMS-1, F2-REG-UNSCOPED-NUMBER: the Section 4.3 object entry'],
  ['beyond 2^53-1 is type-valid and is refused once, as unsupported_number. A', 'F2-ITEMS-1, F2-REG-UNSCOPED-NUMBER: the Section 4.3 integer entry'],
  ['model: a number outside the model as unsupported_number and anything else as unsupported_value', 'F2-REG-UNSCOPED-NUMBER: the first MUST of Section 2.5'],
  ['whose RFC 8785 encoding is within this limit', 'F2-ITEMS-3: the antecedent of "this limit" (Section 2.2)'],
  ['Where such an identifier is sequential, anyone who holds', 'F2-ITEMS-2: the recovery needs the other members to be guessable too (Section 11)'],
]) check(needle instanceof RegExp ? !needle.test(sourcePlain) : !sourcePlain.includes(needle), `source still carries the wording of ${what}`);
// ED-13: "action object" is lowercase in running text; titles keep title case.
// Sourcecode is left out: the Section 4.7 registration quotes the registry
// entry's digest_notes byte for byte.
check(!/\bAction Objects?\b/.test(plain(source.replace(/<name>[\s\S]*?<\/name>/g, '').replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, ''))), 'source still capitalizes "Action Object" in running text (ED-13)');

// Text the fixes add, where the finding fixes a word or a structure.
for (const [anchor, needle, what] of [
  ['security-digest', 'collision', 'SEC-1: Section 10.1 names collision resistance'],
  ['iana-suites', 'collision', 'SEC-1: Section 12.1 deprecates a suite once collision attacks are practical'],
  ['iana-action-types', 'a type whose required fields can all be low-entropy requires a member that carries at least 128 bits of entropy', 'SEC-10, R3-GATE-2: the material-fields test carries the whole 128-bit criterion'],
  ['local', 'organization-specific first segment', 'IANA-7: Section 4.6 carries the organization-prefix SHOULD'],
  ['iana-code-formats', 'change controller', 'IANA-13: the Code Formats template records a change controller'],
  ['impl-status', 'tree/main/caid', 'M3: Section 13 points at tree/main/caid'],
  ['impl-status', '6.0.0', 'M3, CLM-3: the next major release (6.0.0) of the verification package'],
  ['impl-status', '5.0.0', 'M3, CLM-3: the published 5.0.0 vendors an earlier revision'],
  ['impl-status', 'every operation except mapping', 'R8: the vendored caid.mjs carries no mapping'],
  ['security-parsing', 'a case-insensitive decoder reads 99999.00', 'R1-SEC6-SWIFT: the member-name differential names the decoder that reads 99999.00'],
  ['host-values', 'ECMAScript BigInt or a Go uint64, as values of kind "unsupported"', 'R1-IMPL2-BINDING: a binding may give other numeric host types kind "unsupported"'],
  ['host-values', 'is mistyped_field:<name> and unsupported_value, whatever its value', 'R1-IMPL2-BINDING: the result for such a value in an integer field'],
  ['details', 'every host value that the language binding represents as a number', 'R1-IMPL2-BINDING: the kind "number" of a host value (Section 6.1)'],
  ['terms', 'property of the language binding', 'R1-IMPL2-BINDING: the Kind entry names the binding'],
  ['mapping-algorithm', 'as it does when either has no RFC 8785 encoding or that member is absent', 'R1-IMPL3-DESCRIPTOR: a descriptor with no RFC 8785 encoding is a mismatch'],
  ['privacy', 'uses a type whose notes specify it', 'R6: a keyed commitment needs a type whose notes specify it'],
  // Round 2 of the fix audit. Each is a behavior the three ports show and a
  // vector pins, so a wording drift here is a drift from the code.
  ['host-values', 'except that an object or array nested deeper than 64 counts as one value and nothing inside it is counted', 'R2-VALUECOUNT-DEPTH: native-value-count-stops-at-depth-64, native-value-count-straddles-depth-64'],
  ['host-values', 'a host definition whose validation projection is past it, or a host mapping profile or mapping source past it, is refused by the step that reads it', 'R2-VALUECOUNT-REASON (Section 2.5)'],
  ['data-model', 'are not examined and are not counted toward the value count', 'R2-VALUECOUNT-DEPTH (Section 2.2)'],
  ['data-model', 'past it, a host action object yields unsupported_value from phase 7 and no unsupported_number, whatever else it holds, while phases 3 and 4 still run', 'R2-VALUECOUNT-REASON, R3-VALUECOUNT-ALONE: native-value-count-with-phase-3-and-4 (Section 2.2)'],
  ['limits', 'The nesting limit and the value count apply in the same way to a host value that is not an action object', 'R2-VALUECOUNT-REASON (Section 2.6)'],
  ['limits', 'a host definition whose validation projection nests deeper than 64 or exceeds the value count is invalid_definition, a host mapping profile that does is invalid_mapping_profile and has no digest', 'R2-VALUECOUNT-REASON: native-definition-value-count-in-projection, profile-value-count-abstains'],
  ['limits', 'and a host mapping source that does is source_not_canonicalizable', 'R2-VALUECOUNT-REASON: stage-b-source-value-count-not-canonicalizable'],
  ['computation', 'the value count does not count them', 'R2-VALUECOUNT-DEPTH (Section 5)'],
  ['computation', 'When a host action object is made of more values than the value count', 'R2-VALUECOUNT-REASON (Section 5)'],
  ['host-values', 'a host number beyond 2^53-1 whose correctly rounded value is finite is refused by phase 6 alone (phase 7 alone past the value count)', 'R2-GATE-5, F1-REG-UNIVERSAL-NUMBER: native-integer-beyond-range-in-integer-field'],
  ['impl-status', 'none implements the cbor-sha256 suite', 'R2-GATE-5: the runners skip the vectors that apply only to a cbor-sha256 implementation (checked below)'],
  ['tool-call-type', 'an occurrence_id that carries at least 128 bits of entropy unless args already carries an identifier with at least that entropy', 'R2-GATE-6: the 128-bit occurrence_id requirement (Section 4.7)'],
  ['schema', 'each line break inside a string, and the indentation after it, reads as one space', 'R2-4.2-LINEBREAKS, R2-REG-6: the rule this script applies to the Section 4.2 example'],
  ['fieldtypes', 'A literal whose correctly rounded value is an infinity', 'R2-REG-5: the Section 2.3 boundary (Section 4.3)'],
  ['iana-action-types', 'The expert does not register a name whose first segment is organization-specific', 'R2-REG-10, R2-ORGPREFIX-TENSION: a rule, not a description'],
  ['iana-action-types', 'unless that organization is the change controller', 'R2-REG-10: the rule names the change controller'],
  ['iana-action-types', 'its entry in the enum_snapshot_files member of action-types.json records what is known of its terms', 'R2-ISO4217-TERMS'],
  ['iana-action-types', 'none of the 9 produces or verifies a CAID', 'R2-REG-7: the deprecated initial entries (count checked below)'],
  ['appendix-action-types-reference-only', 'only with that organization as its change controller', 'R2-ORGPREFIX-TENSION: emilia.mobile.authorized-action.1 (Appendix D.2)'],
  ['chg-refused-depth', 'A host definition whose validation projection is nested that deep', 'R2-CHG-DEEP-DEF (Section 14.1)'],
  ['ed-processing-text', 'no longer depends on the conformance condition that uses it', 'R2-CHG-PROJECTION (Section 14.6)'],
  // Round 3 of the fix audit and the author's decisions on it. A reference
  // back to an enclosing object or array counts as one value (rule b), as
  // the JavaScript, Python and Go ports and the spec oracle apply it.
  ['data-model', 'a reference back to an enclosing object or array is a cycle: it counts as one value, and nothing beyond it is counted or examined', 'R3-REG-1: native-cyclic-*-with-fraction (Section 2.2)'],
  ['data-model', 'holds a number outside the model yields unsupported_number and no unsupported_value', 'R3-VALUECOUNT-ALONE: refuse-canonical-size-over-limit-with-phase-3-and-4 (Section 2.2)'],
  ['host-values', 'and a reference back to an enclosing object or array counts as one value and nothing beyond it is counted', 'R3-REG-1 (Section 2.5)'],
  ['host-values', 'phase 7 yields unsupported_value and phase 6 yields no reason, whatever the value holds, while phases 3 and 4 still run', 'R3-VALUECOUNT-ALONE (Section 2.5)'],
  ['host-values', 'the count of a value whose shared references form no cycle is that of the expansion, down to depth 64', 'R3-REG-1: acyclic shared references count by their expansion (Section 2.5)'],
  ['host-values', 'So NaN or 1.5 in an integer field is mistyped_field:<name> and unsupported_number (unsupported_value past the value count)', 'M2, IMPL-2, R3-GATE-1, F1-REG-UNIVERSAL-NUMBER: native-nan-in-integer-field, native-fraction-in-integer-field, native-value-count-with-phase-3-and-4'],
  ['computation', 'or beyond a reference back to an enclosing object or array, and the value count does not count them', 'R3-REG-1 (Section 5)'],
  ['computation', 'phase 6 yields no reason and phase 7 yields unsupported_value, whatever the value holds; phases 3 and 4 still run', 'R3-VALUECOUNT-ALONE (Section 5)'],
  ['chg-refused-value-count', 'or a reference back to an enclosing object or array, counts as one value: unsupported_value and no unsupported_number, while phases 3 and 4 still run', 'R3-REG-1, R3-VALUECOUNT-ALONE (Section 14.1)'],
  ['overview', 'phase 6 every number, down to depth 64 and within the value count, in the data model', 'R3-REG-2, F2-ITEMS-1: the Section 1.2 figure'],
  ['chg-mapping-stage-b', 'read neither member of a profile nested deeper than 64, past the value count, cyclic, or holding a host value of no JSON kind', 'R3-STAGEB-HISTORY, R3-REG-4: what the JavaScript mapper at cea10b85e skipped'],
  ['privacy', 'Where such an identifier is sequential and the other members can be guessed, anyone who holds a CAID of that type can recover its action object, so the CAID needs the protection its action object needs', 'R3-PRIVACY-WORDING, F2-ITEMS-2'],
  ['privacy', 'A CAID is meant to be recomputed by a party that already holds the action object', 'author: a CAID is recomputed by parties that hold the object (Section 11)'],
  ['privacy', 'receipts and other evidence carry it for such parties. It is not designed as a correlation identifier to propagate to parties that do not hold the object', 'author: not a correlation identifier for parties without the object (Section 11)'],
  ['iana-action-types', "A new version of a registered type name is registered by the change controller of its earlier versions, or with that controller's written agreement", 'IANA-8, R3-GATE-3'],
  ['impl-status', 'refuses cbor-sha256 as unknown_suite', 'R3-GATE-4: agrees with the Coverage line and the runner skips checked below'],
  ['impl-status', "The JavaScript implementation uses only the platform's cryptographic library, and the Python and Go implementations use only their standard libraries", 'R3-GATE-4: the imports checked below'],
  ['iana-uri', 'names an object by the digest of its octets, unless a specification defines another input, under an algorithm from the Named Information Hash Algorithm Registry', 'author: the RFC 6920 comparison (Section 12.8), read against RFC 6920 Sections 2, 3 and 9.4'],
  ['iana-uri', 'two ni names that share the algorithm and the digest value refer to the same object whatever else they carry', 'author: RFC 6920 Section 2 compares only the algorithm and the digest value'],
  ['iana-uri', 'URN-equivalence lowercases "urn" and the namespace identifier, ignores the r-, q-, and f-components, and lets a namespace add equivalences but never remove one', 'author: RFC 8141 Section 3.1'],
  ['ed-references', 'RFC 6920, RFC 8141', 'the references Section 12.8 adds'],
  ['ed-references', 'ISO 3166-1 and ISO 4217', 'R3-REG-7: the enum sources Section 4.5 cites'],
  ['ed-uri-utility', 'instead of using an ni URI', 'author: the change entry for the Section 12.8 utility paragraph'],
  ['ed-privacy', 'not propagated as a correlation identifier to parties that do not', 'author: the change entry for the Section 11 paragraph'],
  // Round 4 of the fix audit. Past the value count phase 6 yields no
  // reason, as native-value-count-with-phase-3-and-4 pins, so each rule
  // that names unsupported_number is scoped to an object within the count.
  ['numbers', 'except in a host action object past the value count, which yields unsupported_value instead', 'F1-REG-UNIVERSAL-NUMBER (Section 2.3)'],
  ['computation', 'a number at depth 64 or less in an object within the value count is outside the data model', 'F1-REG-UNIVERSAL-NUMBER: Table 2, phase 6'],
  ['chg-deprecated', 'so a deprecated type resolves, computes, and verifies wherever its fields resolve', 'F1-REG-DEPRECATED: the 9 deprecated initial entries resolve but compute nothing (Section 12.2)'],
  ['ed-logging', 'which reverses the -03 recommendation that identifiers be treated as public values', 'F1-ED-LOGGING-03-QUOTE: -03 said SHOULD'],
  ['ed-type-entropy', 'should require a member that carries at least 128 bits of entropy from the system of record; a later registration without one states why', 'F1-ED-LOGGING-03-QUOTE: the SHOULD of Section 11 and the exception of Section 12.2'],
  ['ed-iana', 'that the IESG may act for a change controller that cannot be reached or does not respond', 'F1-REG-IANA-CHANGES: Sections 12 and 12.1'],
  ['ed-iana', 'registers a new version of a type name only by, or with the written agreement of, the change controller of its earlier versions', 'F1-REG-IANA-CHANGES: Section 12.2'],
  ['appendix-action-types-reference-only', 'stay in registry version 5 unchanged member for member (their RFC 8785 encodings are identical)', 'F1-DIG-D2-BYTE-FOR-BYTE (checked against the version 4 file above)'],
  ['changes-03-registry', 'kept byte for byte as history/action-types.v4.json, the last file that declared registry version 4, which digests.json pins by its SHA-256', 'F1-DIG-TWO-V4-FILES'],
  // Round 5 of the fix audit: the rules that name unsupported_number that
  // round 4 left unscoped. Each result is pinned by a vector.
  ['data-model', 'A number is examined only where an object or array at depth 64 or less holds it, and not at all in a host action object past the value count, which yields unsupported_value instead', 'F2-REG-UNSCOPED-NUMBER: native-deep-fraction-not-examined, native-value-budget-over (Section 2.2)'],
  ['data-model', 'An action object can be canonicalized when it is a value of the data model whose RFC 8785 encoding is at most 16,777,216 octets', 'F2-ITEMS-3 (Section 2.2)'],
  ['host-values', 'In a host action object within the value count below, a number outside the model that an object or array at depth 64 or less holds is refused as unsupported_number, and anything else as unsupported_value', 'F2-REG-UNSCOPED-NUMBER: the first MUST of Section 2.5'],
  ['host-values', 'A host action object past that count is refused as the value count below states, and any other host value by the step that reads it', 'F2-REG-UNSCOPED-NUMBER: native-value-count-integer-beyond-range-in-integer-field, native-definition-opaque-in-projection'],
  ['fieldtypes', 'is refused once, as unsupported_number (unsupported_value in a host action object past the value count', 'F2-ITEMS-1: native-integer-beyond-range-in-integer-field, native-value-count-integer-beyond-range-in-integer-field (Section 4.3)'],
  ['fieldtypes', 'an object field that holds a fractional number fails no field type, and the number is refused as unsupported_number wherever phase 6 examines it', 'F2-ITEMS-1: native-fraction-in-object-field, native-value-count-fraction-in-object-field, native-deep-fraction-in-object-field (Section 4.3)'],
]) check(plain(part(anchor)).includes(needle), `${/^(?:chg|ed)-/.test(anchor) ? 'item' : 'section'} ${anchor} lacks "${needle}" (${what})`);
// R2-GATE-5: Section 13 says none of the three implementations implements
// cbor-sha256 and that each skips the corpus vectors that apply only to an
// implementation of it. The runners decide that as the corpora say
// (suite_probe computed under the suite); run each and require that it
// fails nothing and skips exactly those vectors. A missing toolchain is a
// note, and a failure with --prefiling.
{
  const onlyIfImplemented = (list) => list.filter((v) => v.applies_when?.suite_implemented === 'cbor-sha256').length;
  const want = { core: onlyIfImplemented(readJson('caid/conformance/vectors.json').vectors), grammar: onlyIfImplemented(readJson('caid/conformance/grammar-vectors.json').cases) };
  check(want.core > 0, 'the core corpus has no vector that applies only to a cbor-sha256 implementation, which Section 13 says the ports skip');
  /** @type {[string, string, string[], string][]} */
  const RUNNERS = [
    ['JavaScript', 'node', ['caid/conformance/runners/run.mjs', '--json'], root],
    ['Python', process.env.CAID_PYTHON || 'python3', ['caid/conformance/runners/run.py', '--json'], root],
    ['Go', 'go', ['run', '.', '--json'], path.join(root, 'caid/conformance/runners/go')],
  ];
  for (const [language, command, args, cwd] of RUNNERS) {
    const r = spawnSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 1 << 28 });
    if (r.error) {
      const note = `the ${language} runner could not start (${/** @type {NodeJS.ErrnoException} */ (r.error).code ?? r.error.message}), so its cbor-sha256 skips were not checked`;
      if (prefiling) errors.push(note); else console.log(`CAID-04: note: ${note}`);
      continue;
    }
    let summary = null;
    try { summary = JSON.parse(r.stdout); } catch { /* reported below */ }
    check(summary && summary.fail === 0, `the ${language} core and grammar runner fails (exit ${r.status}), so Section 13 does not hold`);
    const skipped = { core: summary?.per_corpus?.core?.skipped ?? 0, grammar: summary?.per_corpus?.grammar?.skipped ?? 0 };
    check(same(skipped, want), `Section 13 says the ${language} implementation does not implement cbor-sha256 and skips the vectors that apply only to it (${JSON.stringify(want)}); its runner skipped ${JSON.stringify(skipped)}`);
  }
}

// R8: what Section 13 says the next major release vendors is what this
// tree vendors: a byte copy of caid/impl/js/caid.mjs, with no mapping.
{
  const vendored = read('packages/verify/vendor/caid.mjs');
  check(vendored === read('caid/impl/js/caid.mjs'), 'packages/verify/vendor/caid.mjs is not a byte copy of caid/impl/js/caid.mjs, as Section 13 says');
  check(!/\b(?:mapAction|compareMappedActions|mappingProfileHash)\b/.test(vendored), 'the vendored caid.mjs carries mapping, which Section 13 says it does not');
}
// R3-GATE-4: Section 13 says the JavaScript implementation uses only the
// platform's cryptographic library and the Python and Go implementations
// only their standard libraries. The imports of every port module say so.
{
  const jsAllowed = new Set(['node:crypto', './caid.mjs']);
  for (const rel of ['caid/impl/js/caid.mjs', 'caid/impl/js/mapping.mjs']) {
    const found = [...read(rel).matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+['"]([^'"]+)['"]/gm), ...read(rel).matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]);
    const other = found.filter((f) => !jsAllowed.has(f));
    check(other.length === 0, `Section 13 says the JavaScript implementation uses only the platform's cryptographic library, but ${rel} imports ${other.join(', ')}`);
  }
  const pyModules = ['caid/impl/python/caid.py', 'caid/impl/python/mapping.py'].flatMap((rel) => [...read(rel).matchAll(/^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))/gm)]
    .flatMap((m) => (m[1] ? [m[1]] : m[2].split(',').map((x) => x.trim()))).map((name) => [rel, name.split('.')[0]]));
  const py = spawnSync(process.env.CAID_PYTHON || 'python3', ['-c', 'import sys, json; print(json.dumps(sorted(sys.stdlib_module_names)))'], { encoding: 'utf8' });
  if (py.status === 0) {
    const stdlib = new Set([...JSON.parse(py.stdout), '__future__']);
    // The two modules of the port import each other by name.
    const local = new Set(['caid', 'mapping', '_caid_spec', 'caid_spec']);
    for (const [rel, name] of pyModules) check(stdlib.has(name) || local.has(name), `Section 13 says the Python implementation uses only its standard library, but ${rel} imports ${name}`);
  } else {
    const note = 'python3 could not list its standard library, so the Python imports of Section 13 were not checked';
    if (prefiling) errors.push(note); else console.log(`CAID-04: note: ${note}`);
  }
  check(!/^\s*require\b/m.test(read('caid/impl/go/go.mod')), 'Section 13 says the Go implementation uses only its standard library, but caid/impl/go/go.mod requires a module');
  const goFiles = execFileSync('git', ['-C', root, 'ls-files', 'caid/impl/go'], { encoding: 'utf8' }).split('\n').filter((f) => f.endsWith('.go') && !f.endsWith('_test.go'));
  for (const rel of goFiles) {
    const src = read(rel);
    const imports = [...src.matchAll(/^import\s+"([^"]+)"/gm), ...[...src.matchAll(/^import\s*\(([\s\S]*?)^\)/gm)].flatMap((m) => [...m[1].matchAll(/"([^"]+)"/g)])].map((m) => m[1]);
    // A standard library path has no dot in its first element; caid/... is
    // this module.
    const other = imports.filter((i) => i.split('/')[0].includes('.') && !i.startsWith('caid/'));
    check(other.length === 0, `Section 13 says the Go implementation uses only its standard library, but ${rel} imports ${other.join(', ')}`);
  }
}

// R3-GATE-5: the limits the prose restates are the values of
// caid/spec/core.json, the source of the limits table, and every
// comma-grouped number in the source is one of those values, 2^53-1, or
// the cited amount counterexample "1,000".
{
  const L = Object.fromEntries(core.limits.map((l) => [l.id, l.value]));
  const n = (v) => v.toLocaleString('en-US');
  for (const [anchor, needle] of [
    ['host-values', `refuse a host value made of more than ${n(L.value_count)} values`],
    ['chg-refused-value-count', `more than ${n(L.value_count)} values`],
    ['json-text', `It is at most ${n(L.json_text_octets)} octets long`],
    ['chg-refused-text-size', `JSON text longer than ${n(L.json_text_octets)} octets`],
    ['security-dos', `near the ${n(L.json_text_octets)}-octet text limit`],
    ['data-model', `MUST NOT exceed ${n(L.canonical_octets)} octets`],
    ['data-model', `The nesting depth of a value MUST NOT exceed ${L.nesting_depth}.`],
    ['computation', `a canonical encoding beyond ${n(L.canonical_octets)} octets`],
    ['chg-refused-canonical-size', `exceeds ${n(L.canonical_octets)} octets`],
    ['numbers', `at most 2^53-1 (${n(L.max_safe_integer)})`],
  ]) check(plain(part(anchor)).includes(needle), `${/^(?:chg|ed)-/.test(anchor) ? 'item' : 'section'} ${anchor} does not state "${needle}", the value of caid/spec/core.json (R3-GATE-5)`);
  const allowed = new Set([...core.limits.filter((l) => l.scope === 'caid' || l.scope === 'caid-mapping').map((l) => n(l.value)), n(L.max_safe_integer), '1,000']);
  const stray = [...new Set([...sourcePlain.matchAll(/\b\d{1,3}(?:,\d{3})+\b/g)].map((m) => m[0]))].filter((v) => !allowed.has(v));
  check(stray.length === 0, `the source states ${stray.join(', ')}, which is no limit of caid/spec/core.json (R3-GATE-5)`);
}

// R3-REG-3: each change since -03 appears in one list. The requirements on
// other parties are items of Section 14.5, and the Security and Privacy
// items of Section 14.6 describe text alone.
{
  const parties = section('changes-03-parties');
  for (const a of ['ed-number-literals', 'ed-multiple-caids', 'ed-signature-coverage', 'ed-truncation', 'ed-occurrence', 'ed-message-bounds', 'ed-identifier-normalization', 'ed-logging', 'ed-type-entropy', 'ed-keyed-commitment', 'ed-snapshot-files', 'ed-approval-display', 'ed-number-readers', 'ed-suite-deprecation']) {
    check(parties.includes(`<li anchor="${a}">`), `Section 14.5 (changes-03-parties) lacks the requirement ${a} (R3-REG-3)`);
  }
  const edSecurity = plain(item('ed-security'));
  for (const topic of ['truncation', 'replay', 'multiple identifiers', 'signature coverage', 'differential', 'confusable']) {
    check(!edSecurity.includes(topic), `the ed-security item still lists "${topic}", a requirement Section 14.5 lists (R3-REG-3)`);
  }
  check(!plain(item('ed-privacy')).includes('keyed commitment'), 'the ed-privacy item still lists the keyed-commitment rule, which Section 14.5 lists (R3-REG-3)');
}

// Section 12.8: the utility paragraph cites RFC 7595 Section 3.1 and the
// two alternatives it weighs.
{
  const uri = section('iana-uri');
  check(/<xref target="RFC7595" section="3\.1"/.test(uri) && uri.includes('<xref target="RFC6920"/>') && uri.includes('<xref target="RFC8141"/>'), 'Section 12.8 does not cite RFC 7595 Section 3.1, RFC 6920 and RFC 8141 for the utility of the scheme');
}

// R3-REG-5: the reference registry's quality bar carries the Section 12.2
// criteria it could otherwise admit a type without.
{
  const gov = flat(read('caid/registry/GOVERNANCE.md'));
  check(gov.includes('whose required fields can all be low-entropy requires a member that carries at least 128 bits of entropy') && gov.includes('unless its `digest_notes` or its specification state why not'), 'GOVERNANCE.md section 5 lacks the 128-bit criterion of Section 12.2 and its exception (R3-REG-5)');
  check(gov.includes('A proposal that pins an external enum supplies the snapshot file') && gov.includes("what is known of that source's terms"), 'GOVERNANCE.md section 5 lacks the snapshot-file and terms duty of Section 12.2 (R3-REG-5)');
}

// R3-NBHY-COPYPASTE: a non-breaking hyphen survives in the HTML render,
// where a copied type name or file path would then not be the real one. It
// stays only in SHA-384 and SHA-512/256; the type names and paths are ASCII
// in both renders, and the prose around them keeps the TXT from breaking
// them.
{
  const kept = [...source.matchAll(/(.{0,3})&#8209;(.{0,7})/g)].filter((m) => !/SHA$/.test(m[1]) || !/^(?:384|512\/256)/.test(m[2]));
  check(kept.length === 0, `a non-breaking hyphen appears outside SHA-384 and SHA-512/256: "${kept[0]?.[0] ?? ''}" (R3-NBHY-COPYPASTE)`);
  for (const name of ['action‑types', 'value‑sets', 'authorized‑action', 'action&#8209;types', 'value&#8209;sets', 'authorized&#8209;action']) {
    check(!html.includes(name), `the HTML render carries a non-breaking hyphen in "${name.replace('‑', '-').replace('&#8209;', '-')}" (R3-NBHY-COPYPASTE)`);
  }
  check(!/value-\s+sets/.test(text), 'the TXT render breaks "value-sets/" at its hyphen');
}

// ED-07: the paragraph above the limits table names the reasons the
// nesting limit yields for documents other than an action object.
{
  const limits = section('limits');
  const lead = plain(limits.slice(0, limits.indexOf('<table')));
  for (const reason of ['invalid_definition', 'invalid_mapping_profile', 'source_not_canonicalizable']) {
    check(lead.includes(reason), `the paragraph above the limits table does not name ${reason} (ED-07)`);
  }
}
check(!plain(section('iana-code-formats')).includes('nested quantifiers'), 'Section 12.4 restates the linear-matching property instead of citing Section 4.5 (ED-03)');
{
  const security = section('security');
  check(/<t>/.test(security.slice(0, security.indexOf('<section anchor=', 1))), 'Section 10 has no lead-in paragraph before Section 10.1 (SEC-3)');
  const terms = section('terms');
  for (const term of ['Relying party', 'Executor', 'Presenter', 'Mapper']) {
    check(new RegExp(`<dt>${term}:</dt>`, 'i').test(terms), `Terminology does not define ${term} (ED-04)`);
  }
  check(/<dt>Status:<\/dt>\s*<dd>Permanent<\/dd>/.test(section('iana-uri')), 'the URI scheme template does not request Permanent status (IANA-5)');
  for (const anchor of ['changes-03', 'changes']) {
    check(new RegExp(`<section anchor="${anchor}"[^>]*\\sremoveInRFC="true"`).test(source), `section ${anchor} is not marked removeInRFC="true" (ED-03)`);
  }
}
// M3, CLM-3: what Section 13 says about the verification package holds in
// this tree: 5.0.0 is the version in packages/verify, 6.0.0 is the
// unreleased major version, and the copy it will vendor implements -04.
{
  const pkg = readJson('packages/verify/package.json');
  check(pkg.version === '5.0.0', `Section 13 calls 5.0.0 the published verification package, but packages/verify is ${pkg.version}`);
  check(/## Unreleased\s+Version type: major, 6\.0\.0/.test(read('packages/verify/CHANGELOG.md')), 'Section 13 calls 6.0.0 the next major release, but packages/verify/CHANGELOG.md does not');
  check(read('packages/verify/vendor/caid.mjs').includes(`Implements ${DOC}`), 'the vendored copy the next major release will ship does not implement -04');
}

// BCP 14 (ART-JSON-6, ART-JSON-7, ED-16): every keyword outside code is
// marked with <bcp14>, and <bcp14> marks only keywords.
{
  const KEYWORDS = new Set(['MUST', 'MUST NOT', 'REQUIRED', 'SHALL', 'SHALL NOT', 'SHOULD', 'SHOULD NOT', 'RECOMMENDED', 'NOT RECOMMENDED', 'MAY', 'OPTIONAL']);
  const noCode = source.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '');
  const marked = [...noCode.matchAll(/<bcp14>([\s\S]*?)<\/bcp14>/g)].map((m) => m[1].replace(/\s+/g, ' ').trim());
  const notKeywords = [...new Set(marked.filter((k) => !KEYWORDS.has(k)))];
  check(notKeywords.length === 0, `<bcp14> marks text that is not a BCP 14 keyword: ${notKeywords.join(', ')}`);
  const bare = noCode.replace(/<bcp14>[\s\S]*?<\/bcp14>/g, '\u0000');
  const unmarked = [...bare.matchAll(/\b(?:MUST|REQUIRED|SHALL|SHOULD|RECOMMENDED|MAY|OPTIONAL)\b/g)];
  check(unmarked.length === 0, `${unmarked.length} BCP 14 keyword(s) lack <bcp14> markup, the first: "${unmarked[0] ? flat(bare.slice(Math.max(0, unmarked[0].index - 40), unmarked[0].index + 20)) : ''}"`);
  check(!/\u0000\s+NOT\b|\bNOT\s+\u0000/.test(bare), 'a NOT sits outside the <bcp14> markup of its keyword');
}

const prose = text + source;
check(!/[\u2013\u2014]/.test(prose), 'an en or em dash appears in the draft');

// Wording the author's standards text never uses: no claim of IETF
// adoption, no post-quantum or FIPS claim, no tool attribution. And
// "independent implementation" and "endorse" appear only in the sentences
// that deny them: Section 13's disclaimers and the endorsement disclaimer
// of the acknowledgments.
{
  const BANNED = [/\badopt(?:ed|ion)\b/i, /quantum[- ]safe/i, /FIPS[- ]compliant/i, /SCITT[- ]integrated/i];
  for (const re of BANNED) {
    check(!re.test(sourcePlain) && !re.test(flat(text)), `the draft uses banned wording matching ${re}`);
  }
  const DISCLAIMERS = [
    ['impl-status', 'does not imply endorsement by the IETF.'],
    ['impl-status', 'No independent implementation is known to the author.'],
    ['impl-status', 'such external re-runs are reproductions, not independent implementations.'],
    ['acknowledgments', 'do not imply endorsement of this document.'],
  ];
  let rest = sourcePlain;
  for (const [anchor, sentence] of DISCLAIMERS) {
    check(plain(section(anchor)).includes(sentence), `section ${anchor} lacks the disclaimer "${sentence}"`);
    rest = rest.replace(sentence, '');
  }
  for (const re of [/independent implementation/i, /\bendors/i]) {
    const m = re.exec(rest);
    check(!m, `"${m?.[0]}" appears outside the disclaimers of Section 13 and the acknowledgments: "...${m ? rest.slice(Math.max(0, m.index - 50), m.index + 40) : ''}..."`);
  }
}
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
// IANA-16, ED-20, CLM-10: xml2rfc broke "history/action-types.v4.json" at
// its hyphen and printed "action- types"; a path in <tt> is not broken.
check(!/action-\s+types/.test(text), 'the TXT render splits a path at "action-types" (wrap the path in <tt>)');
// An action type broken at a hyphen at a line end reads as two words; a
// non-breaking hyphen (&#8209;) keeps it whole.
{
  const broken = text.split('\n').filter((l) => /[a-z0-9_]\.[a-z0-9_.]*-$/.test(l));
  check(broken.length === 0, `the TXT render breaks an action type at a hyphen: "${broken[0]?.trim()}"`);
}
// F1-TXT-TOKEN-BREAKS: the same defect for every closed-set value with a
// hyphen (field types, transforms, loss policies, code formats, parameter
// kinds, suites): xml2rfc breaks after a hyphen at a line end, and a reader
// who copies "sha256-hex-to- digest" or "field- name" gets no registry
// value. A line that ends inside one fails, across a page break too.
{
  const TOKENS = [...new Set([
    ...core.field_types.map((t) => t.type),
    ...core.mapping.transforms.map((t) => t.transform),
    ...core.mapping.loss_policies.map((l) => l.policy),
    ...core.grammar.code_formats.map((f) => f.format),
    ...core.reasons.map((r) => r.param),
    ...core.mapping.reasons.map((r) => r.param),
    ...readJson('caid/registry/suites.json').suites.map((s) => s.suite),
  ].filter((t) => typeof t === 'string' && t.includes('-')))];
  check(['sha256-hex-to-digest', 'declared-source-semantic-loss', 'field-name', 'amount-string', 'icd-10-cm', 'cbor-sha256'].every((t) => TOKENS.includes(t)), 'the TXT token-break check lost a closed set');
  const lines = text.split('\n').map((l) => l.replaceAll('\f', '')).filter((l) => !/\[Page \d+\]\s*$/.test(l) && !/^Internet-Draft\s/.test(l));
  const broken = [];
  lines.forEach((line, i) => {
    const tail = /(\S*-)\s*$/.exec(line)?.[1];
    if (!tail) return;
    let j = i + 1;
    while (j < lines.length && !lines[j].trim()) j += 1;
    const joined = tail + (/^\s*(\S*)/.exec(lines[j] ?? '')?.[1] ?? '');
    for (const token of TOKENS) {
      for (let k = joined.indexOf(token); k !== -1; k = joined.indexOf(token, k + 1)) {
        if (k < tail.length && tail.length < k + token.length) broken.push(`${token} in "${line.trim()}" / "${(lines[j] ?? '').trim()}"`);
      }
    }
  });
  check(broken.length === 0, `the TXT render breaks a registry value at a hyphen (${broken.length}): ${broken.join('; ')}`);
}
// The same wrapping defect after a slash: xml2rfc refills a <tt> path broken
// after "/" with a space inside it.
for (const p of ['history/action-types.v4.json', 'caid/registry/action-types.json']) {
  check(!new RegExp(p.replaceAll('/', '/\\s+').replaceAll('.', '\\.')).test(text.replace(/<https:[^>]*>/g, '')), `the TXT render splits the path ${p} after a slash`);
}

// ED-03, R1-ED03-TABLE: no table row of the TXT render is split across a
// page: a page may end on a row's last line or on a border line (+---+),
// but when it ends on a row line the next page starts with a border line,
// never with more lines of that row.
{
  const pages = text.split('\f');
  const bodyLines = (page) => page.split('\n').filter((l) => l.trim() && !/\[Page \d+\]\s*$/.test(l) && !/^Internet-Draft\s/.test(l));
  pages.slice(0, -1).forEach((page, i) => {
    const last = bodyLines(page).at(-1) ?? '';
    const first = bodyLines(pages[i + 1])[0] ?? '';
    check(!(/^\s*\|/.test(last) && /^\s*\|/.test(first)), `the TXT render splits a table row across pages ${i + 1} and ${i + 2} ("${last.trim().slice(0, 48)}...")`);
  });
}

// GATE-2: RENDERS/ is the xml2rfc 3.34.0 render of the source, as
// VALIDATION.md records: --text as is, and --html --no-external-js with
// trailing spaces and tabs removed from each line. Compared whenever that
// xml2rfc is on PATH; --renders and --prefiling require it.
let renderedFresh = false;
{
  const XML2RFC = '3.34.0';
  // The two warnings xml2rfc gives for an individual Standards Track draft
  // that names no stream (VALIDATION.md); any other warning is a failure.
  const EXPECTED_WARNINGS = [/Expected a valid submissionType/, /Setting consensus="true"/];
  const probe = spawnSync('xml2rfc', ['--version'], { encoding: 'utf8' });
  const version = probe.status === 0 ? probe.stdout.trim() : null;
  if (version === `xml2rfc ${XML2RFC}`) {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'caid-04-render-'));
    try {
      const render = (flags, out) => {
        const r = spawnSync('xml2rfc', [...flags, '--out', out, sourceFile], { encoding: 'utf8' });
        if (r.status !== 0) { errors.push(`xml2rfc ${XML2RFC} ${flags.join(' ')} failed: ${(r.stderr || '').trim().split('\n').at(-1)}`); return null; }
        const unexpected = (r.stderr || '').split('\n').filter((l) => /\b(?:Warning|Error):/.test(l) && !EXPECTED_WARNINGS.some((w) => w.test(l)));
        check(unexpected.length === 0, `xml2rfc ${XML2RFC} ${flags.join(' ')} reports: ${unexpected.join(' | ')}`);
        return readFileSync(out, 'utf8');
      };
      const txt = render(['--text'], path.join(dir, `${DOC}.txt`));
      const htm = render(['--html', '--no-external-js'], path.join(dir, `${DOC}.html`));
      if (txt !== null) check(txt === text, `${textRel} is not the xml2rfc ${XML2RFC} --text render of the source (re-render as VALIDATION.md describes)`);
      if (htm !== null) check(htm.replace(/[ \t]+$/gm, '') === html, `${htmlRel} is not the xml2rfc ${XML2RFC} --html --no-external-js render of the source with trailing spaces removed (re-render as VALIDATION.md describes)`);
      renderedFresh = txt !== null && htm !== null;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  } else if (rendersRequired) {
    errors.push(`the render check needs xml2rfc ${XML2RFC} on PATH (found ${version ?? 'none'})`);
  } else {
    console.log(`CAID-04: note: xml2rfc ${XML2RFC} is not on PATH (found ${version ?? 'none'}), so RENDERS/ was not compared with a fresh render; run with --renders before upload`);
  }
}

// R2-REG-3, R2-GATE-4: VALIDATION.md states the page count of the TXT
// render once, and it is the last [Page N] of the render.
{
  const validation = readFileSync(path.join(packet, 'VALIDATION.md'), 'utf8');
  const stated = [...validation.matchAll(/\((\d+) pages\)/g)].map((m) => Number(m[1]));
  const last = Math.max(...[...text.matchAll(/\[Page (\d+)\]/g)].map((m) => Number(m[1])));
  check(stated.length === 1 && stated[0] === last, `VALIDATION.md states ${stated.length ? stated.join(', ') : 'no'} page count(s); the TXT render has ${last} pages`);
}

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

// ---------------------------------------------------------------------------
// --prefiling: the filing gate (M3). Section 13 points at tree/main/caid and
// says the code there implements -04, runs the corpus, and skips the
// cbor-sha256 vectors; Section 8.3 states the mapping rules the ports
// follow; Appendix A is caid.abnf; and [CAID-REGISTRY] cites a commit.
// Those hold at tree/main only when origin/main carries exactly the CAID
// tree this packet was checked against. Reads origin/main as last fetched;
// run git fetch origin first.
// ---------------------------------------------------------------------------

// The paths whose content the draft describes as published at
// tree/main/caid: the ports, the corpora and runners, the spec sources, the
// registry, and the vendored copy Section 13 names.
const FILING_PATHS = ['caid', 'packages/verify/vendor/caid.mjs'];

if (prefiling) {
  const git = (...args) => {
    try { return execFileSync('git', ['-C', root, ...args], { stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1 << 26 }); } catch { return null; }
  };
  const mainCommit = git('rev-parse', '--verify', 'origin/main^{commit}')?.toString().trim();
  check(mainCommit, 'prefiling: origin/main is unknown (run git fetch origin)');
  // R2-GATE-3: origin/main as last fetched can be stale; tree/main is what
  // the remote serves. Other sessions push to main often.
  const remoteMain = git('ls-remote', 'origin', 'refs/heads/main')?.toString().trim().split(/\s+/)[0];
  check(remoteMain, 'prefiling: git ls-remote origin refs/heads/main failed, so origin/main cannot be confirmed current');
  if (mainCommit && remoteMain) check(remoteMain === mainCommit, `prefiling: origin/main (${mainCommit.slice(0, 12)}) is not the remote main (${remoteMain.slice(0, 12)}); run git fetch origin`);
  if (mainCommit) {
    const mainRegistry = git('show', 'origin/main:caid/registry/action-types.json');
    check(mainRegistry && `sha256:${createHash('sha256').update(mainRegistry).digest('hex')}` === v5Sha, `prefiling: caid/registry/action-types.json on origin/main (${mainCommit.slice(0, 12)}) is not registry version 5; merge the -04 pull request first`);
    check(git('cat-file', '-e', 'origin/main:caid/spec/caid.abnf') !== null, 'prefiling: origin/main has no caid/spec/caid.abnf');
    for (const port of ['caid/impl/js/caid.mjs', 'caid/impl/python/caid.py', 'caid/impl/go/caid.go']) {
      check((git('show', `origin/main:${port}`)?.toString() ?? '').includes(DOC), `prefiling: ${port} on origin/main does not implement -04, so Section 13 would be false`);
    }
    if (pinnedCommit) check(git('merge-base', '--is-ancestor', pinnedCommit, 'origin/main') !== null, `prefiling: the [CAID-REGISTRY] commit ${pinnedCommit} is not reachable from origin/main`);
    // R1-M3-GATE, R3, GATE-1: the checks above hold on a main that lacks
    // this tree's CAID changes (the stage B fix of the JavaScript port, the
    // back-reference fix of the Go port, the conditional cbor-sha256 vectors
    // and the runners that skip them, the new vectors, the caid.abnf
    // comment). This one does not: every file
    // under FILING_PATHS on origin/main equals HEAD's, and the working tree
    // that the checks above read equals HEAD there.
    const status = git('status', '--porcelain', '--untracked-files=all', '--', ...FILING_PATHS);
    check(status !== null && status.toString().trim() === '', `prefiling: the working tree differs from HEAD under ${FILING_PATHS.join(', ')}; commit or discard the changes first:\n    ${(status?.toString().trim() ?? 'git status failed').split('\n').join('\n    ')}`);
    const branch = git('rev-parse', '--abbrev-ref', 'HEAD')?.toString().trim() ?? 'HEAD';
    const advice = branch === 'main' || branch === 'HEAD' ? 'Bring this checkout and origin/main to one CAID tree and re-run' : `Merge ${branch} into main and re-run`;
    const differing = git('diff', '--name-only', 'HEAD', 'origin/main', '--', ...FILING_PATHS);
    const compared = FILING_PATHS.map((p) => (p.includes('.') ? p : `${p}/`)).join(' or ');
    const names = differing?.toString().trim().split('\n').filter(Boolean) ?? null;
    check(names !== null && names.length === 0, names === null
      ? 'prefiling: git diff HEAD origin/main failed'
      : `prefiling: origin/main (${mainCommit.slice(0, 12)}) does not carry the CAID tree of ${branch}; ${names.length} file(s) under ${compared} differ, so Sections 2.2, 2.5, 8.3 and 13 and Appendix A would be false at tree/main/caid. ${advice}:\n    ${names.slice(0, 30).join('\n    ')}${names.length > 30 ? `\n    ... and ${names.length - 30} more` : ''}`);
  }
}

if (errors.length) {
  console.error(`CAID-04 packet: ${errors.length} failure(s)`);
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
const { iana: d1, other: d2 } = split.counts;
console.log(`CAID-04: Appendix A (${abnfText.split('\n').length - 1} lines) equals caid.abnf; Appendix B, detail, limits and IANA tables equal their sources; Appendix D lists registry v5 (${registry.types.length} types) as ${d1.total} initial IANA entries (${d1.active} active, ${d1.deprecated} deprecated) and ${d2.total} not requested of IANA; Appendix C (cbor-sha256 included) and the examples recompute; ${claimAnchors.length} change claims map to vectors; review wording, BCP 14 markup, references, renders${renderedFresh ? ' (equal to a fresh xml2rfc 3.34.0 render)' : ''} and checksums${prefiling ? ', and the filing gate against origin/main,' : ''} PASS.`);
