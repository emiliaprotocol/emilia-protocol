#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generates the CAID constants each port compiles in, from the grammar
// (caid.abnf, the draft's Appendix A), the rule data (core.json), and the
// suite registry (caid/registry/suites.json).
//
//   node caid/spec/gen.mjs --write        rewrite the generated files in place
//   node caid/spec/gen.mjs --check        exit 1 unless every generated file
//                                         is byte-identical to a regeneration
//   node caid/spec/gen.mjs --out DIR      write the generated files under DIR,
//                                         mirroring their repository paths
//   node caid/spec/gen.mjs --check --out DIR
//                                         compare DIR instead of the checkout
//   --root DIR                            repository root (default: this
//                                         checkout)
//
// Generated files:
//   caid/impl/js/caid.mjs                 the region between the BEGIN and END
//                                         GENERATED CAID SPEC marker lines
//   caid/impl/python/caid_spec.py         whole file
//   caid/impl/go/spec_gen.go              whole file
//   packages/verify/vendor/caid.mjs       byte copy of caid/impl/js/caid.mjs
//
// Generation refuses inputs that disagree with each other: a pattern that
// is not linear-time safe, a code format that is not finite with no nested
// or overlapping quantifiers, a reason code the reason grammar does not
// accept, a limit that differs from the Verify constant it mirrors, and so
// on. The output depends only on the input files' contents, so two runs
// over the same inputs produce the same bytes. Nothing here runs inside a
// port: the ports stay dependency-free and never read these inputs at run
// time.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  analyzeRegex, compile, digestSyntax, literalAlternatives, loadGrammar, matches, parseRegex,
} from './abnf.mjs';

export const JS_BEGIN = '// BEGIN GENERATED CAID SPEC: node caid/spec/gen.mjs --write. Do not edit by hand.';
export const JS_END = '// END GENERATED CAID SPEC';
export const MAX_ABNF_COLUMNS = 69;

export const TARGETS = {
  js: 'caid/impl/js/caid.mjs',
  python: 'caid/impl/python/caid_spec.py',
  go: 'caid/impl/go/spec_gen.go',
  vendor: 'packages/verify/vendor/caid.mjs',
};

const SOURCES = 'caid/spec/caid.abnf, caid/spec/core.json, caid/registry/suites.json';
const PARAM_KINDS = new Set(['none', 'field-name', 'source-path', 'compute-reason']);

// ---------------------------------------------------------------------------
// Inputs and consistency
// ---------------------------------------------------------------------------

/**
 * Reads caid/spec/caid.abnf and returns its rule set, refusing text the
 * draft appendix could not carry verbatim.
 *
 * @param {string} root
 */
export function loadCaidGrammar(root) {
  const file = 'caid/spec/caid.abnf';
  const text = readFileSync(path.join(root, file), 'utf8');
  text.split('\n').forEach((line, i) => {
    if (/[^\x20-\x7e]/.test(line)) throw new Error(`caid/spec: ${file}:${i + 1} is not printable ASCII`);
    if (line.length > MAX_ABNF_COLUMNS) {
      throw new Error(`caid/spec: ${file}:${i + 1} is ${line.length} columns; the draft appendix allows ${MAX_ABNF_COLUMNS}`);
    }
    if (/\s$/.test(line)) throw new Error(`caid/spec: ${file}:${i + 1} has trailing white space`);
  });
  if (!text.endsWith('\n') || text.endsWith('\n\n')) throw new Error(`caid/spec: ${file} must end with exactly one newline`);
  return { text, rules: loadGrammar([{ text, source: 'caid.abnf' }]) };
}

// The largest code point a parsed expression can match.
function maxCodePoint(node) {
  if (node.t === 'cls') return Math.max(...node.ranges.map((r) => r[1]));
  if (node.t === 'rep') return maxCodePoint(node.item);
  return Math.max(0, ...(node.items ?? []).map(maxCodePoint));
}

/**
 * Reads the inputs, checks them against each other, and returns the port
 * view: the language-neutral data every generated file encodes.
 *
 * @param {string} root repository root
 */
export function buildSpec(root) {
  const read = (rel) => readFileSync(path.join(root, rel), 'utf8');
  const core = JSON.parse(read('caid/spec/core.json'));
  const suites = JSON.parse(read('caid/registry/suites.json'));
  /** @param {string} msg @returns {never} */
  const fail = (msg) => { throw new Error(`caid/spec: ${msg}`); };

  if (core['@version'] !== 'CAID-SPEC-DATA-v1') fail('core.json @version is not CAID-SPEC-DATA-v1');
  if (core.grammar.file !== 'caid.abnf') fail('core.json grammar.file must be caid.abnf');
  const { rules } = loadCaidGrammar(root);

  // Compiled patterns: every one linear-time safe. A pattern with a length
  // limit (max_octets, a core.json limit id) is checked against that limit
  // before it is matched: a backtracking engine keeps one stack entry per
  // repetition of a group, so an unbounded string can exhaust that stack
  // (V8 throws near 6.7 million characters) even though matching is linear
  // in time.
  const patterns = {};
  const patternMaxOctets = {};
  const analysis = {};
  const limitById = Object.fromEntries(core.limits.map((l) => [l.id, l]));
  for (const { id, rule, max_octets: maxOctets, ...rest } of core.grammar.patterns) {
    if (Object.keys(rest).length) fail(`pattern ${id} has unknown members ${Object.keys(rest).join(', ')}`);
    if (!/^[a-z][a-z0-9_]*$/.test(id) || id in patterns) fail(`bad or duplicate pattern id ${id}`);
    patterns[id] = compile(rules, rule);
    analysis[id] = analyzeRegex(patterns[id]);
    if (!analysis[id].linear) fail(`pattern ${id} (${rule}) is not linear-time safe: ${JSON.stringify(analysis[id].conflicts)}`);
    if (maxOctets !== undefined) {
      const limit = limitById[maxOctets];
      if (!limit || limit.scope !== 'caid' || limit.unit !== 'octets') fail(`pattern ${id} names ${maxOctets}, which is not a caid octet limit`);
      if (maxCodePoint(parseRegex(patterns[id])) > 0x7f) fail(`pattern ${id} has a length limit but matches non-ASCII text, whose length in octets differs from its length in characters`);
      patternMaxOctets[id] = limit.value;
    }
  }
  if (!('caid' in patternMaxOctets) || !('action_type' in patternMaxOctets)) fail('the caid and action_type patterns need length limits');
  if (patternMaxOctets.caid < patternMaxOctets.action_type) fail('the caid limit must admit the longest action type');
  for (const rule of core.grammar.interpreted_rules) {
    if (!rules.has(rule)) fail(`interpreted rule ${rule} is not in caid.abnf`);
  }

  // Code formats: finite, no nested or overlapping quantifiers, bounded
  // backtracking. The format name is its rule name.
  const codeFormats = {};
  const formatNameRe = new RegExp(`^(?:${patterns.format_name})$`);
  for (const { format } of core.grammar.code_formats) {
    if (!formatNameRe.test(format) || format in codeFormats) fail(`bad or duplicate code format ${format}`);
    if (!rules.has(format)) fail(`code format ${format} has no rule in caid.abnf`);
    const src = compile(rules, format);
    const a = analyzeRegex(src);
    if (!a.finite) {
      fail(`code format ${format} is not finite with no nested or overlapping quantifiers: ${JSON.stringify({ nesting: a.nesting, conflicts: a.conflicts, step_bound: a.step_bound })}`);
    }
    codeFormats[format] = src;
    analysis[`code_format:${format}`] = a;
  }

  // Suites and their digest syntax.
  const suiteRe = new RegExp(`^(?:${patterns.suite})$`);
  for (const { digest_octets: octets, rule } of core.grammar.suite_digest_rules) {
    if (compile(rules, rule) !== digestSyntax(octets).source) {
      fail(`ABNF rule ${rule} differs from the digest syntax derived for ${octets} octets`);
    }
  }
  const seenSuites = new Set();
  const suiteView = suites.suites.map((entry) => {
    const { suite, digest_octets: octets } = entry;
    if (typeof suite !== 'string' || !suiteRe.test(suite)) fail(`registered suite ${JSON.stringify(suite)} does not match the suite rule`);
    if (seenSuites.has(suite)) fail(`suite ${suite} registered twice`);
    seenSuites.add(suite);
    if (!Number.isSafeInteger(octets) || octets < 32) fail(`suite ${suite} needs an integer digest_octets of at least 32`);
    const syntax = digestSyntax(octets);
    const a = analyzeRegex(syntax.source);
    if (!a.linear) fail(`digest syntax of ${suite} is not linear-time safe`);
    return { suite, digest_octets: octets, digest_length: syntax.length, digest_pattern: syntax.source };
  });

  // Core reasons and operations.
  const codes = new Set();
  const params = {};
  for (const { code, param } of core.reasons) {
    if (!/^[a-z][a-z_]*$/.test(code) || codes.has(code)) fail(`bad or duplicate reason ${code}`);
    if (param !== 'none' && param !== 'field-name') fail(`core reason ${code} has parameter kind ${param}`);
    codes.add(code);
    params[code] = param;
  }
  const sortRank = {};
  const position = {};
  const perPositionMax = {};
  const gates = {};
  for (const [operation, phases] of Object.entries(core.operations)) {
    let last = -1;
    sortRank[operation] = {};
    position[operation] = {};
    perPositionMax[operation] = {};
    gates[operation] = [];
    for (const phase of phases) {
      if (!Number.isSafeInteger(phase.rank) || phase.rank <= last) fail(`${operation} ranks must strictly increase`);
      last = phase.rank;
      for (const code of phase.reasons) if (!codes.has(code)) fail(`${operation} names unregistered reason ${code}`);
      for (const step of phase.steps ?? []) if (!phase.reasons.includes(step.reason)) fail(`${operation} step ${step.check} names a reason outside its phase`);
      if (phase.gate) { gates[operation].push(phase.reasons); continue; }
      for (const code of phase.reasons) {
        if (code in sortRank[operation]) fail(`${operation} ranks ${code} twice after the gates`);
        sortRank[operation][code] = phase.rank;
        if (phase.position) position[operation][code] = phase.position;
        if (phase.per_position_max) perPositionMax[operation][code] = phase.per_position_max;
      }
    }
  }
  for (const code of codes) {
    if (!Object.values(core.operations).some((phases) => phases.some((p) => p.reasons.includes(code)))) fail(`reason ${code} belongs to no operation`);
  }
  // The gates follow from data dependencies, so they are asserted here, not
  // editable: nothing can be read before the JSON text decodes; a type name
  // is needed before a definition can be resolved; fields are checked only
  // against a resolved definition; verification parses the identifier
  // before it reads the object. The ports take the rank of every reason
  // after the gates from sort_rank.
  const gateShape = (operation) => core.operations[operation].filter((p) => p.gate).map((p) => [p.entry ?? null, p.reasons]);
  const expectGates = {
    decode: [[null, ['malformed_json']]],
    parse: [[null, ['malformed_caid', 'unknown_suite']]],
    compute: [['json_text', ['malformed_json']], [null, ['invalid_action_type']], [null, ['unknown_action_type', 'invalid_definition']]],
    verify: [['parse', ['malformed_caid', 'unknown_suite']], ['json_text', ['malformed_json']], [null, ['invalid_object']]],
  };
  for (const [operation, want] of Object.entries(expectGates)) {
    if (JSON.stringify(gateShape(operation)) !== JSON.stringify(want)) fail(`${operation} gates must be ${JSON.stringify(want)}: they follow from data dependencies`);
  }
  for (const operation of ['compute', 'verify']) {
    const ranks = core.operations[operation].map((p) => p.rank);
    const lastGate = Math.max(...core.operations[operation].filter((p) => p.gate).map((p) => p.rank));
    if (core.operations[operation].some((p) => !p.gate && p.rank < lastGate)) fail(`${operation}: every gate precedes every ranked phase`);
    if (new Set(ranks).size !== ranks.length) fail(`${operation} ranks repeat`);
  }

  // Verification details: a closed-shape detail for every reason a
  // verification can report, directly or through an expanded reason.
  const details = core.verify_details;
  if (JSON.stringify(details.members) !== JSON.stringify(['reason', 'field', 'rule', 'observed'])) fail('verify_details members must be reason, field, rule, observed');
  const verifyCodes = new Set(core.operations.verify.flatMap((p) => p.reasons));
  for (const [code, expansion] of Object.entries(details.expand)) {
    if (!verifyCodes.has(code)) fail(`verify_details expands ${code}, which verification never reports`);
    if (!(expansion.operation in core.operations)) fail(`verify_details expands ${code} into unknown operation ${expansion.operation}`);
    for (const c of core.operations[expansion.operation].flatMap((p) => (p.entry === 'json_text' ? [] : p.reasons))) {
      if (!expansion.omit.includes(c)) verifyCodes.add(c);
    }
  }
  for (const code of Object.keys(details.expand)) verifyCodes.delete(code);
  const detailCodes = new Set(Object.keys(details.reasons));
  if (JSON.stringify([...verifyCodes].sort()) !== JSON.stringify([...detailCodes].sort())) {
    fail(`verify_details.reasons must cover exactly the reported reasons ${JSON.stringify([...verifyCodes].sort())}`);
  }
  const ruleIds = new Set();
  for (const [code, d] of Object.entries(details.reasons)) {
    if (JSON.stringify(Object.keys(d)) !== JSON.stringify(['rule', 'field', 'observed'])) fail(`verify_details.reasons.${code} must have exactly rule, field, observed`);
    if (typeof d.rule !== 'string' || !/^[a-z][a-z0-9-]*$/.test(d.rule) || ruleIds.has(d.rule)) fail(`verify_details.reasons.${code} rule is not a unique rule id`);
    ruleIds.add(d.rule);
    if (d.field !== null && !details.field_sources.includes(d.field)) fail(`verify_details.reasons.${code} field source ${d.field} is not registered`);
    if (d.observed !== null && !details.observed_sources.includes(d.observed)) fail(`verify_details.reasons.${code} observed source ${d.observed} is not registered`);
    if ((params[code] === 'field-name') !== (d.field === 'param')) fail(`verify_details.reasons.${code} must take its field from the reason parameter exactly when it has one`);
    if (d.observed === 'member' && d.field === null) fail(`verify_details.reasons.${code} observes a member but names no field`);
  }

  // Result shapes and options.
  for (const [operation, shape] of Object.entries(core.results)) {
    for (const list of Object.values(shape)) {
      if (typeof list === 'string') continue;
      if (!Array.isArray(list) || list.some((m) => typeof m !== 'string' || !/^[a-z][a-z0-9_]*$/.test(m))) fail(`results.${operation} has a malformed member list`);
    }
  }
  for (const [operation, list] of Object.entries(core.options)) {
    if (!(operation in core.operations) || list.some((m) => !/^[a-z][a-z0-9_]*$/.test(m))) fail(`options.${operation} is malformed`);
  }
  if (!core.options.verify.includes('expected_definition_sha256')) fail('verify must accept expected_definition_sha256');
  if (core.options.compute.includes('expected_definition_sha256')) fail('only verify accepts expected_definition_sha256');

  // Field types.
  const typeNames = new Set();
  for (const type of core.field_types) {
    if (typeNames.has(type.type)) fail(`field type ${type.type} listed twice`);
    typeNames.add(type.type);
    if (type.pattern && !(type.pattern in patterns)) fail(`field type ${type.type} names unknown pattern ${type.pattern}`);
    for (const key of ['pattern_refusal', 'format_refusal', 'unregistered_format_refusal']) {
      if (type[key] && !codes.has(type[key])) fail(`field type ${type.type} names unknown reason ${type[key]}`);
    }
    for (const [member, pattern] of Object.entries(type.required_members)) {
      if (!type.members.includes(member)) fail(`field type ${type.type} requires a member it does not list`);
      if (!(pattern in patterns)) fail(`field type ${type.type} member ${member} names unknown pattern ${pattern}`);
    }
    for (const member of type.members) {
      if (core.definition.field_common_members.includes(member)) fail(`field type ${type.type} redeclares common member ${member}`);
    }
  }
  if (!typeNames.has('code') || !typeNames.has('enum')) fail('field types must include enum and code');
  if (!codes.has(core.unknown_field_type_refusal)) fail('unknown_field_type_refusal is not a reason');
  const d = core.definition;
  if (!rules.has(d.field_name.rule)) fail(`definition field_name rule ${d.field_name.rule} is not in caid.abnf`);
  for (const key of ['none', 'conflict', 'nonconforming']) if (!codes.has(d.resolution[key])) fail(`definition resolution ${key} is not a reason`);
  if (d.status_affects_computation !== false) fail('status must not affect computation');
  for (const list of d.field_name.unique_across) if (!d.field_lists.includes(list)) fail(`field names unique across unknown list ${list}`);

  // Mapping.
  const mapping = core.mapping;
  const mappingCodes = new Set();
  const mappingParams = {};
  for (const { code, param } of mapping.reasons) {
    if (!/^[a-z][a-z_]*$/.test(code) || mappingCodes.has(code)) fail(`bad or duplicate mapping reason ${code}`);
    if (!PARAM_KINDS.has(param)) fail(`mapping reason ${code} has unknown parameter kind ${param}`);
    mappingCodes.add(code);
    mappingParams[code] = param;
  }
  const mappingRank = {};
  const stageOf = {};
  let rank = 0;
  for (const stage of mapping.stages) {
    for (const code of stage.reasons) {
      if (!mappingCodes.has(code)) fail(`mapping stage ${stage.stage} names unregistered reason ${code}`);
      if (code in stageOf) fail(`mapping reason ${code} is in two stages`);
      stageOf[code] = stage.stage;
      mappingRank[code] = rank;
      rank += 1;
    }
  }
  for (const code of mapping.comparison.reasons) {
    if (!mappingCodes.has(code) || code in stageOf) fail(`comparison reason ${code} must be a mapping reason outside every stage`);
  }
  for (const code of mappingCodes) {
    if (!(code in stageOf) && !mapping.comparison.reasons.includes(code)) fail(`mapping reason ${code} belongs to no stage`);
  }
  for (const t of mapping.transforms) if (t.pattern && !(t.pattern in patterns)) fail(`transform ${t.transform} names unknown pattern`);
  if (!mappingCodes.has(mapping.null_member_refusal)) fail('mapping null_member_refusal is not a mapping reason');
  for (const p of mapping.loss_policies) if (p.stage_reason && stageOf[p.stage_reason] !== 'B') fail(`loss policy ${p.policy} names a reason outside stage B`);
  if (!mapping.verdicts.includes(mapping.comparison.prefixed_verdict)) fail('mapping comparison prefixed_verdict is not a verdict');
  for (const [code, verdict] of Object.entries(mapping.comparison.reason_verdicts)) {
    if (!mapping.comparison.reasons.includes(code) || !mapping.verdicts.includes(verdict)) fail(`mapping comparison reason_verdicts ${code} is malformed`);
  }
  // Member rules: every path names profile members, every limit and closed
  // set exists, every grammar rule is in caid.abnf.
  const memberPaths = new Set();
  const containerOf = { source_format: 'source_format', rules: 'rule', omitted_source_fields: 'omitted_source_field' };
  for (const r of mapping.member_rules) {
    const key = JSON.stringify(r.path);
    if (memberPaths.has(key)) fail(`mapping member rule ${r.path.join('/')} listed twice`);
    memberPaths.add(key);
    const [head, ...rest] = r.path;
    if (!mapping.members.profile.includes(head)) fail(`mapping member rule ${r.path.join('/')} starts outside the profile members`);
    const tail = rest.filter((s) => s !== '*');
    if (tail.length > 1 || (tail.length === 1 && !mapping.members[containerOf[head]]?.includes(tail[0]))) fail(`mapping member rule ${r.path.join('/')} names an unknown member`);
    if (!['string', 'array'].includes(r.json)) fail(`mapping member rule ${r.path.join('/')} has json ${r.json}`);
    for (const k of ['min_octets', 'max_octets', 'min_items', 'max_items']) if (k in r && !core.limits.some((l) => l.id === r[k])) fail(`mapping member rule ${r.path.join('/')} names unknown limit ${r[k]}`);
    if (r.rule && !rules.has(r.rule)) fail(`mapping member rule ${r.path.join('/')} names unknown ABNF rule ${r.rule}`);
    if (r.closed && !Array.isArray(mapping[r.closed])) fail(`mapping member rule ${r.path.join('/')} names unknown closed set ${r.closed}`);
  }
  const rulePath = (p) => memberPaths.has(JSON.stringify(p)) || fail(`mapping constraint path ${p.join('/')} has no member rule`);
  mapping.unique.forEach(rulePath);
  for (const pair of [...mapping.equal_sets, ...mapping.disjoint]) pair.forEach(rulePath);

  // Limits: one table; the Verify rows mirror packages/verify constants.
  const limitIds = new Set();
  const limits = {};
  for (const limit of core.limits) {
    if (limitIds.has(limit.id)) fail(`limit ${limit.id} listed twice`);
    limitIds.add(limit.id);
    if (!Number.isSafeInteger(limit.value) || limit.value < 0) fail(`limit ${limit.id} is not a non-negative integer`);
    for (const key of ['refusal', 'host_value_refusal']) {
      if (limit[key] && !codes.has(limit[key]) && !mappingCodes.has(limit[key])) fail(`limit ${limit.id} names unregistered reason ${limit[key]}`);
    }
    if (limit.implementation) {
      const actual = readTsConstant(root, limit.implementation.file, limit.implementation.constant);
      if (actual !== limit.value) {
        fail(`limit ${limit.id} is ${limit.value} in core.json but ${limit.implementation.constant} is ${actual} in ${limit.implementation.file}`);
      }
    }
    if (limit.scope === 'caid' || limit.scope === 'caid-mapping') limits[limit.id] = limit.value;
  }
  if (limits.max_safe_integer !== Number.MAX_SAFE_INTEGER) fail('max_safe_integer must be 2^53-1');
  if (limits.value_count < limits.json_text_octets / 2) fail('value_count must exceed the values of any JSON text within json_text_octets');
  if (limits.document_canonical_octets < 4 * limits.json_text_octets) fail('document_canonical_octets must admit the canonical form of any JSON text within json_text_octets');

  // Noncharacters (Unicode Section 23.7): one BMP range, and the last two
  // code points of each of the 17 planes. The ports test code points
  // against these ranges.
  const nc = core.json_text.noncharacters;
  if (JSON.stringify(nc) !== JSON.stringify({ range: [0xfdd0, 0xfdef], plane_final: [0xfffe, 0xffff] })) {
    fail('json_text.noncharacters must be U+FDD0..U+FDEF and the last two code points of every plane');
  }
  const noncharacterRanges = [nc.range];
  for (let plane = 0; plane <= 16; plane += 1) noncharacterRanges.push([plane * 0x10000 + nc.plane_final[0], plane * 0x10000 + nc.plane_final[1]]);

  checkReasonGrammar(rules, core, { codes, params, mappingCodes, mappingParams, sortRank }, fail);

  return {
    draft: core.draft,
    identifier: core.identifier,
    patterns,
    pattern_max_octets: patternMaxOctets,
    code_formats: codeFormats,
    suites: suiteView,
    timestamp_date_offsets: core.grammar.timestamp_date_offsets,
    limits,
    json_text: { byte_order_mark: core.json_text.byte_order_mark, whitespace: core.json_text.whitespace, noncharacter_ranges: noncharacterRanges },
    reasons: core.reasons.map((r) => r.code),
    reason_params: params,
    operations: core.operations,
    gates,
    sort_rank: sortRank,
    position,
    per_position_max: perPositionMax,
    results: core.results,
    options: core.options,
    verify_details: details,
    field_types: core.field_types,
    unknown_field_type_refusal: core.unknown_field_type_refusal,
    definition: core.definition,
    enum: core.enum,
    mapping: {
      ...mapping,
      reason_params: mappingParams,
      reason_rank: mappingRank,
      stage_of: stageOf,
    },
    _analysis: analysis,
  };
}

// Every registered reason, in every form it can take, matches the reason
// rule; the literal code sets of the reason grammar equal core.json's; and
// malformed reason strings do not match.
function checkReasonGrammar(rules, core, { codes, params, mappingCodes, mappingParams, sortRank }, fail) {
  const set = (xs) => JSON.stringify([...xs].sort());
  const lits = (key) => {
    const out = literalAlternatives(rules, core.grammar.reason_rules[key]);
    if (!out) fail(`reason rule ${core.grammar.reason_rules[key]} is not an alternation of case-sensitive strings`);
    return out;
  };
  const computeCodes = new Set(Object.keys(sortRank.compute));
  for (const phase of core.operations.compute) if (phase.gate && phase.entry !== 'json_text') phase.reasons.forEach((c) => computeCodes.add(c));
  const computeBare = [...computeCodes].filter((c) => params[c] === 'none');
  const fieldCodes = [...codes].filter((c) => params[c] === 'field-name');
  if (set(lits('compute_bare')) !== set(computeBare)) fail(`compute-bare lists ${set(lits('compute_bare'))}, core.json compute reasons are ${set(computeBare)}`);
  if (set(lits('field_codes')) !== set(fieldCodes)) fail('field-code differs from the field-name reasons of core.json');
  const comparison = new Set(core.mapping.comparison.reasons);
  const mappingBare = [...mappingCodes].filter((c) => mappingParams[c] === 'none' && !comparison.has(c));
  const coreOnly = [...codes].filter((c) => !computeCodes.has(c));
  if (set(lits('core_only')) !== set(coreOnly)) fail(`core-only lists ${set(lits('core_only'))}, core.json has ${set(coreOnly)} outside compute`);
  const pointerCodes = [...mappingCodes].filter((c) => mappingParams[c] === 'source-path');
  if (set(lits('mapping_bare')) !== set(mappingBare)) fail('mapping-bare differs from the parameterless mapping reasons of core.json');
  if (set(lits('pointer_codes')) !== set(pointerCodes)) fail('pointer-code differs from the source-path mapping reasons of core.json');

  const accept = [];
  const reject = [];
  const field = ['amount', '@version', 'x', 'café', '\u{1F600}', '__proto__'];
  for (const code of codes) {
    if (params[code] === 'none') { accept.push(code); reject.push(`${code}:x`); } else {
      for (const f of field) accept.push(`${code}:${f}`);
      reject.push(code, `${code}:`, `${code}:a:b`);
    }
  }
  const computeForms = [...computeCodes].flatMap((c) => (params[c] === 'none' ? [c] : field.map((f) => `${c}:${f}`)));
  const mappingForms = [];
  for (const code of mappingCodes) {
    if (comparison.has(code)) continue;
    const p = mappingParams[code];
    if (p === 'none') mappingForms.push(code);
    else if (p === 'field-name') field.forEach((f) => mappingForms.push(`${code}:${f}`));
    else if (p === 'source-path') ['/a', '/a:b/~0~1', '/0', '//', '/é'].forEach((s) => mappingForms.push(`${code}:${s}`));
    else if (p === 'compute-reason') computeForms.forEach((r) => mappingForms.push(`${code}:${r}`));
    if (p === 'source-path') reject.push(code, `${code}:`, `${code}:a`, `${code}:/~2`);
    if (p === 'compute-reason') reject.push(code, ...coreOnly.map((c) => `${code}:${c}`), `${code}:${code}:unknown_suite`);
  }
  accept.push(...mappingForms);
  for (const prefix of core.mapping.comparison.prefixes) {
    mappingForms.forEach((r) => accept.push(`${prefix}:${r}`));
    reject.push(`${prefix}:${prefix}:source_not_object`, `${prefix}:`, `${prefix}:material_projection_mismatch`);
  }
  accept.push(...comparison);
  reject.push('', 'bogus', 'MALFORMED_CAID', 'malformed_caid ', 'unknown_suite\n', 'unsupported_value:x', 'mapped_action:invalid_mapped_action', 'unexpected_mapping_error');
  for (const r of accept) if (!matches(rules, 'reason', r)) fail(`the reason rule refuses the registered reason ${JSON.stringify(r)}`);
  for (const r of reject) if (matches(rules, 'reason', r)) fail(`the reason rule accepts ${JSON.stringify(r)}`);
}

function readTsConstant(root, file, name) {
  const text = readFileSync(path.join(root, file), 'utf8');
  const m = new RegExp(`^export const ${name}\\s*=\\s*([0-9_ *]+);`, 'm').exec(text);
  if (!m) throw new Error(`caid/spec: ${file} does not export a numeric ${name}`);
  return m[1].split('*').map((part) => Number(part.trim().replaceAll('_', ''))).reduce((a, b) => a * b, 1);
}

/** The port view without the dev-time analysis. */
export function portView(spec) {
  const { _analysis, ...view } = spec;
  return view;
}

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------

const asciiString = (s) => {
  if (typeof s !== 'string' || /[^\x20-\x7e]/.test(s)) throw new Error(`generated string is not printable ASCII: ${JSON.stringify(s)}`);
  return s;
};
const quote = (s) => `"${asciiString(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function jsValue(value, indent) {
  const pad = '  '.repeat(indent);
  const inner = '  '.repeat(indent + 1);
  if (Array.isArray(value)) {
    if (!value.length) return '[]';
    if (value.every((v) => v === null || typeof v !== 'object')) return `[${value.map((v) => jsValue(v, 0)).join(', ')}]`;
    return `[\n${value.map((v) => inner + jsValue(v, indent + 1)).join(',\n')},\n${pad}]`;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    if (!keys.length) return '{}';
    return `{\n${keys.map((k) => `${inner}${/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) ? k : quote(k)}: ${jsValue(value[k], indent + 1)}`).join(',\n')},\n${pad}}`;
  }
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return String(value);
  throw new Error(`cannot emit ${typeof value}`);
}

function pyValue(value, indent) {
  const pad = '    '.repeat(indent);
  const inner = '    '.repeat(indent + 1);
  if (Array.isArray(value)) {
    if (!value.length) return '()';
    if (value.every((v) => v === null || typeof v !== 'object')) {
      return value.length === 1 ? `(${pyValue(value[0], 0)},)` : `(${value.map((v) => pyValue(v, 0)).join(', ')})`;
    }
    return `(\n${value.map((v) => inner + pyValue(v, indent + 1)).join(',\n')},\n${pad})`;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    if (!keys.length) return '{}';
    return `{\n${keys.map((k) => `${inner}${quote(k)}: ${pyValue(value[k], indent + 1)}`).join(',\n')},\n${pad}}`;
  }
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  if (value === null) return 'None';
  if (typeof value === 'number') return String(value);
  throw new Error(`cannot emit ${typeof value}`);
}

const pascal = (id) => id.split(/[^A-Za-z0-9]+/).filter(Boolean).map((w) => w[0].toUpperCase() + w.slice(1)).join('');

export function emitJsRegion(spec) {
  const view = portView(spec);
  const lines = [
    JS_BEGIN,
    `// Derived from ${SOURCES}.`,
    '// The draft is the normative text; these constants are generated from it.',
    '',
    'function caidSpecData(value) {',
    '  if (Array.isArray(value)) return Object.freeze(value.map(caidSpecData));',
    '  if (value instanceof RegExp) return Object.freeze(value);',
    '  if (value !== null && typeof value === "object") {',
    '    const out = Object.create(null);',
    '    for (const key of Object.keys(value)) out[key] = caidSpecData(value[key]);',
    '    return Object.freeze(out);',
    '  }',
    '  return value;',
    '}',
    '',
    '// Rule data. Every object is frozen and has a null prototype.',
    `export const CAID_SPEC = caidSpecData(${jsValue(view, 0)});`,
    '',
    '// Whole-string matchers: each is ^(?:R)$ over the portable expression R',
    '// in CAID_SPEC.patterns, so a value followed by any further character,',
    '// including a final line feed, does not match. Test only strings: RegExp',
    '// test() converts any other value to a string first.',
    'export const CAID_PATTERNS = caidSpecData({',
    ...Object.entries(view.patterns).map(([id, src]) => `  ${id}: /^(?:${src})$/,`),
    '});',
    '',
    '// Whole-string matcher of each registered code format, keyed by format name.',
    'export const CAID_CODE_FORMATS = caidSpecData({',
    ...Object.entries(view.code_formats).map(([id, src]) => `  ${quote(id)}: /^(?:${src})$/,`),
    '});',
    '',
    '// Digest syntax of each registered suite, keyed by suite name.',
    'export const CAID_SUITE_DIGEST_PATTERNS = caidSpecData({',
    ...view.suites.map((s) => `  ${quote(s.suite)}: /^(?:${s.digest_pattern})$/,`),
    '});',
    JS_END,
  ];
  return lines.join('\n') + '\n';
}

export function emitPython(spec) {
  const view = portView(spec);
  const lines = [
    '# Code generated by caid/spec/gen.mjs; DO NOT EDIT.',
    `# Derived from ${SOURCES}.`,
    '# The draft is the normative text; these constants are generated from it.',
    '# Regenerate with: node caid/spec/gen.mjs --write',
    '',
    'import re',
    'import types',
    '',
    '',
    'def _freeze(value):',
    '    if isinstance(value, dict):',
    '        return types.MappingProxyType({k: _freeze(v) for k, v in value.items()})',
    '    if isinstance(value, (list, tuple)):',
    '        return tuple(_freeze(v) for v in value)',
    '    return value',
    '',
    '',
    '# Rule data, read-only (mappings are MappingProxyType, sequences are tuples).',
    `SPEC = _freeze(${pyValue(view, 0)})`,
    '',
    '# Whole-string matchers: each is \\A(?:R)\\Z over the portable expression R',
    '# in SPEC["patterns"]. They refuse a value followed by a final line feed',
    '# whichever of match, search, or fullmatch is used. Apply them to str only.',
    'PATTERNS = types.MappingProxyType({',
    ...Object.entries(view.patterns).map(([id, src]) => `    ${quote(id)}: re.compile(${quote(`\\A(?:${src})\\Z`)}),`),
    '})',
    '',
    '# Whole-string matcher of each registered code format, keyed by format name.',
    'CODE_FORMATS = types.MappingProxyType({',
    ...Object.entries(view.code_formats).map(([id, src]) => `    ${quote(id)}: re.compile(${quote(`\\A(?:${src})\\Z`)}),`),
    '})',
    '',
    '# Registered suites and their digest lengths in octets.',
    'SUITE_DIGEST_OCTETS = types.MappingProxyType({',
    ...view.suites.map((s) => `    ${quote(s.suite)}: ${s.digest_octets},`),
    '})',
    '',
    '# Digest syntax of each registered suite, keyed by suite name.',
    'SUITE_DIGEST_PATTERNS = types.MappingProxyType({',
    ...view.suites.map((s) => `    ${quote(s.suite)}: re.compile(${quote(`\\A(?:${s.digest_pattern})\\Z`)}),`),
    '})',
    '',
    '# Limits, keyed by core.json limit id.',
    'LIMITS = SPEC["limits"]',
  ];
  return lines.join('\n') + '\n';
}

const goString = (s) => quote(s);
const goStrings = (list) => `[]string{${list.map(goString).join(', ')}}`;
function goRaw(s) {
  asciiString(s);
  if (s.includes('`')) throw new Error('backquote in a Go raw string');
  return '`' + s + '`';
}
const goStringMap = (obj) => `map[string]string{${Object.entries(obj).map(([k, v]) => `${goString(k)}: ${goString(v)}`).join(', ')}}`;
const goIntMap = (obj) => `map[string]int{${Object.entries(obj).map(([k, v]) => `${goString(k)}: ${v}`).join(', ')}}`;
const goStringsMap = (obj) => `map[string][]string{${Object.entries(obj).map(([k, v]) => `${goString(k)}: {${v.map(goString).join(', ')}}`).join(', ')}}`;
const goBytes = (list) => `[]byte{${list.map((b) => '0x' + b.toString(16).toUpperCase().padStart(2, '0')).join(', ')}}`;

// The Go file carries the data the Go port reads, and nothing else: an
// unread declaration would claim a single source for a rule no Go code
// applies. The JavaScript and Python ports receive the whole port view.
export function emitGo(spec) {
  const view = portView(spec);
  const out = [
    '// Code generated by caid/spec/gen.mjs; DO NOT EDIT.',
    '',
    `// Derived from ${SOURCES}.`,
    '// The draft is the normative text; these constants are generated from it.',
    '// Regenerate with: node caid/spec/gen.mjs --write',
    '',
    'package caid',
    '',
    'import "regexp"',
    '',
  ];
  const add = (comment, decl) => { out.push(`// ${comment}`, decl, ''); };
  add('specIdentifierScheme is the caid rule\'s fixed scheme.', `const specIdentifierScheme = ${goString(view.identifier.scheme)}`);
  add('specIdentifierVersion is the caid rule\'s caid-version.', `const specIdentifierVersion = ${goString(view.identifier.version)}`);
  add('specIdentifierSeparator separates the caid rule\'s parts.', `const specIdentifierSeparator = ${goString(view.identifier.separator)}`);
  add('specIdentifierParts is the number of separator-delimited parts of a CAID.', `const specIdentifierParts = ${view.identifier.parts}`);

  out.push('// Whole-string matchers: ^(?:R)$ over each portable expression R. Without');
  out.push('// the m flag, RE2 matches $ only at the end of the text.');
  for (const [id, src] of Object.entries(view.patterns)) {
    out.push(`var specPattern${pascal(id)} = regexp.MustCompile(${goRaw(`^(?:${src})$`)})`, '');
  }
  add('specPatterns is every whole-string matcher above, keyed by core.json pattern id.',
    `var specPatterns = map[string]*regexp.Regexp{${Object.keys(view.patterns).map((id) => `${goString(id)}: specPattern${pascal(id)}`).join(', ')}}`);
  add('specPatternMaxOctets is the length limit, in octets, checked before a pattern is matched.', `var specPatternMaxOctets = ${goIntMap(view.pattern_max_octets)}`);
  add('specCodeFormats is the whole-string matcher of each registered code format.',
    `var specCodeFormats = map[string]*regexp.Regexp{${Object.entries(view.code_formats).map(([id, src]) => `${goString(id)}: regexp.MustCompile(${goRaw(`^(?:${src})$`)})`).join(', ')}}`);
  add('specSuiteDigestPatterns is each registered suite\'s digest syntax.',
    `var specSuiteDigestPatterns = map[string]*regexp.Regexp{${view.suites.map((s) => `${goString(s.suite)}: regexp.MustCompile(${goRaw(`^(?:${s.digest_pattern})$`)})`).join(', ')}}`);
  const off = view.timestamp_date_offsets;
  add('specTimestampYear is the byte range [start, end) of the year in a timestamp.', `var specTimestampYear = [2]int{${off.year.join(', ')}}`);
  add('specTimestampMonth is the byte range [start, end) of the month in a timestamp.', `var specTimestampMonth = [2]int{${off.month.join(', ')}}`);
  add('specTimestampDay is the byte range [start, end) of the day in a timestamp.', `var specTimestampDay = [2]int{${off.day.join(', ')}}`);
  for (const [id, value] of Object.entries(view.limits)) add(`specLimit${pascal(id)} is core.json limit ${id}.`, `const specLimit${pascal(id)} = ${value}`);
  add('specJSONByteOrderMark is the UTF-8 byte order mark a JSON text must not begin with.', `var specJSONByteOrderMark = ${goBytes(view.json_text.byte_order_mark)}`);
  add('specJSONWhitespace is the JSON whitespace set of RFC 8259.', `var specJSONWhitespace = ${goBytes(view.json_text.whitespace)}`);
  add('specNoncharacterRanges lists the noncharacter code points as inclusive ranges.',
    `var specNoncharacterRanges = [][2]rune{${view.json_text.noncharacter_ranges.map(([a, b]) => `{0x${a.toString(16).toUpperCase()}, 0x${b.toString(16).toUpperCase()}}`).join(', ')}}`);
  for (const operation of ['compute', 'verify']) {
    const P = pascal(operation);
    add(`specSortRank${P} is the rank of each reason after the ${operation} gates.`, `var specSortRank${P} = ${goIntMap(view.sort_rank[operation])}`);
  }
  const vd = view.verify_details;
  out.push('// specVerifyDetail is the closed shape of one verification detail. Field');
  out.push('// is "param" (the reason parameter), a fixed field name, or "" (null);');
  out.push('// Observed is "member", "argument", or "" (null).');
  out.push('type specVerifyDetail struct {', '\tRule     string', '\tField    string', '\tObserved string', '}', '');
  add('specVerifyDetails is the detail shape of each reason a verification reports.',
    `var specVerifyDetails = map[string]specVerifyDetail{${Object.entries(vd.reasons).map(([code, d]) => `${goString(code)}: {${goString(d.rule)}, ${goString(d.field ?? '')}, ${goString(d.observed ?? '')}}`).join(', ')}}`);
  add('specVerifyDetailExpandOmit lists, per expanded reason, the operation reasons the expansion leaves out.',
    `var specVerifyDetailExpandOmit = ${goStringsMap(Object.fromEntries(Object.entries(vd.expand).map(([k, v]) => [k, v.omit])))}`);
  add('specFieldTypeJSON is the JSON kind each field type holds.', `var specFieldTypeJSON = ${goStringMap(Object.fromEntries(view.field_types.map((t) => [t.type, t.json])))}`);
  add('specFieldTypeMembers lists the definition members specific to each field type.', `var specFieldTypeMembers = ${goStringsMap(Object.fromEntries(view.field_types.map((t) => [t.type, t.members])))}`);
  const reqMembers = {};
  for (const t of view.field_types) for (const [m, p] of Object.entries(t.required_members)) reqMembers[`${t.type}.${m}`] = p;
  add('specFieldTypeRequiredMembers maps "type.member" to the pattern id its value must match.', `var specFieldTypeRequiredMembers = ${goStringMap(reqMembers)}`);
  add('specFieldTypePattern is the whole-string matcher of each grammar-checked field type.',
    `var specFieldTypePattern = map[string]*regexp.Regexp{${view.field_types.filter((t) => t.pattern).map((t) => `${goString(t.type)}: specPattern${pascal(t.pattern)}`).join(', ')}}`);
  add('specFieldTypeCalendarCheck names the calendar check a field type applies after its grammar.',
    `var specFieldTypeCalendarCheck = ${goStringMap(Object.fromEntries(view.field_types.filter((t) => t.calendar_check).map((t) => [t.type, t.calendar_check])))}`);
  add('specFieldTypePatternRefusal is the reason for a string that fails a field type\'s grammar.',
    `var specFieldTypePatternRefusal = ${goStringMap(Object.fromEntries(view.field_types.filter((t) => t.pattern).map((t) => [t.type, t.pattern_refusal])))}`);
  const code = view.field_types.find((t) => t.type === 'code');
  add('specCodeFormatRefusal is the reason for a string that fails its code format.', `const specCodeFormatRefusal = ${goString(code.format_refusal)}`);
  add('specCodeUnregisteredFormatRefusal is the reason for a present code field whose format is not registered.', `const specCodeUnregisteredFormatRefusal = ${goString(code.unregistered_format_refusal)}`);
  add('specUnknownFieldTypeRefusal is the reason for a present field whose type is not registered.', `const specUnknownFieldTypeRefusal = ${goString(view.unknown_field_type_refusal)}`);
  const d = view.definition;
  add('specDefinitionFieldLists names the two field lists of a definition, in order.', `var specDefinitionFieldLists = ${goStrings(d.field_lists)}`);
  add('specRequiredFieldsMin is the minimum length of required_fields.', `const specRequiredFieldsMin = ${d.required_fields_min}`);
  add('specFieldCommonMembers lists the members every field entry may carry.', `var specFieldCommonMembers = ${goStrings(d.field_common_members)}`);
  add('specFieldNameMinLength is the minimum length of a field name.', `const specFieldNameMinLength = ${d.field_name.min_length}`);
  add('specFieldNameForbiddenCodePoints lists code points a field name must not contain.', `var specFieldNameForbiddenCodePoints = []rune{${d.field_name.forbidden_code_points.join(', ')}}`);
  add('specReservedFieldNames lists names no field entry may take.', `var specReservedFieldNames = ${goStrings(d.field_name.reserved)}`);
  add('specProjectionFieldMembersExcluded lists field-entry members the projection drops.', `var specProjectionFieldMembersExcluded = ${goStrings(d.projection.field_members_excluded)}`);
  add('specDefinitionDigestPrefix prefixes the hexadecimal definition_sha256.', `const specDefinitionDigestPrefix = ${goString(d.projection.prefix)}`);
  add('specResolutionNone is the reason when no definition matches the action type.', `const specResolutionNone = ${goString(d.resolution.none)}`);
  add('specResolutionConflict is the reason when matching definitions differ in definition_sha256.', `const specResolutionConflict = ${goString(d.resolution.conflict)}`);
  add('specResolutionNonconforming is the reason when a matching definition does not conform.', `const specResolutionNonconforming = ${goString(d.resolution.nonconforming)}`);
  add('specEnumInlinePrefix begins the compact inline enum form.', `const specEnumInlinePrefix = ${goString(view.enum.inline_prefix)}`);
  add('specEnumInlineSeparator separates compact inline enum members.', `const specEnumInlineSeparator = ${goString(view.enum.inline_separator)}`);
  add('specEnumInlineTrim lists the characters trimmed from compact inline enum members.', `var specEnumInlineTrim = ${goStrings(view.enum.inline_trim)}`);
  const m = view.mapping;
  add('specMappingProfileVersion is the @version of a v1 mapping profile.', `const specMappingProfileVersion = ${goString(m.profile_version)}`);
  for (const [kind, members] of Object.entries(m.members)) {
    add(`specMapping${pascal(kind)}Members lists the members a mapping ${kind.replaceAll('_', ' ')} may carry.`, `var specMapping${pascal(kind)}Members = ${goStrings(members)}`);
  }
  add('specMappingOptionalProfileMembers lists the profile members that may be absent.', `var specMappingOptionalProfileMembers = ${goStrings(m.optional_members.profile)}`);
  out.push('// specMappingMemberRule constrains the profile member at Path ("*" is every');
  out.push('// array element). Limits are core.json limit values, 0 when absent; Rule is');
  out.push('// an ABNF rule name, Closed a closed set ("transforms", "loss_policies").');
  out.push('type specMappingMemberRule struct {', '\tPath      []string', '\tJSON      string', '\tRule      string', '\tClosed    string', '\tReserved  []string', '\tMinOctets int', '\tMaxOctets int', '\tMinItems  int', '\tMaxItems  int', '}', '');
  const limitValue = (id) => (id === undefined ? 0 : spec.limits[id]);
  add('specMappingMemberRules lists the profile member rules in order.',
    `var specMappingMemberRules = []specMappingMemberRule{\n${m.member_rules.map((r) => `\t{Path: ${goStrings(r.path)}, JSON: ${goString(r.json)}, Rule: ${goString(r.rule ?? '')}, Closed: ${goString(r.closed ?? '')}, Reserved: ${goStrings(r.reserved ?? [])}, MinOctets: ${limitValue(r.min_octets)}, MaxOctets: ${limitValue(r.max_octets)}, MinItems: ${limitValue(r.min_items)}, MaxItems: ${limitValue(r.max_items)}},`).join('\n')}\n}`);
  const paths = (list) => `[][]string{${list.map((p) => goStrings(p)).join(', ')}}`;
  add('specMappingUnique lists the member paths whose values must be distinct.', `var specMappingUnique = ${paths(m.unique)}`);
  add('specMappingEqualSets lists member path pairs whose value sets must be equal.', `var specMappingEqualSets = [][2][]string{${m.equal_sets.map(([a, b]) => `{${goStrings(a)}, ${goStrings(b)}}`).join(', ')}}`);
  add('specMappingDisjoint lists member path pairs whose value sets must not intersect.', `var specMappingDisjoint = [][2][]string{${m.disjoint.map(([a, b]) => `{${goStrings(a)}, ${goStrings(b)}}`).join(', ')}}`);
  add('specMappingTransforms lists the registered transforms.', `var specMappingTransforms = ${goStrings(m.transforms.map((t) => t.transform))}`);
  add('specMappingTransformPattern is the whole-string matcher a transform requires of its string input.',
    `var specMappingTransformPattern = map[string]*regexp.Regexp{${m.transforms.filter((t) => t.pattern).map((t) => `${goString(t.transform)}: specPattern${pascal(t.pattern)}`).join(', ')}}`);
  add('specMappingLossPolicies lists the registered loss policies.', `var specMappingLossPolicies = ${goStrings(m.loss_policies.map((p) => p.policy))}`);
  add('specMappingLossPolicyOmissions is what each loss policy requires of omitted_source_fields.', `var specMappingLossPolicyOmissions = ${goStringMap(Object.fromEntries(m.loss_policies.map((p) => [p.policy, p.omitted_source_fields])))}`);
  add('specMappingReasonRank orders mapping reasons: stages A and B sort together by it.', `var specMappingReasonRank = ${goIntMap(m.reason_rank)}`);
  add('specMappingComparisonPrefixes lists the side prefixes of comparison reasons, in order.', `var specMappingComparisonPrefixes = ${goStrings(m.comparison.prefixes)}`);
  add('specMappingPrefixedVerdict is the verdict of a comparison that carries side-prefixed reasons.', `const specMappingPrefixedVerdict = ${goString(m.comparison.prefixed_verdict)}`);
  add('specMappingReasonVerdicts is the verdict each comparison reason carries.', `var specMappingReasonVerdicts = ${goStringMap(m.comparison.reason_verdicts)}`);
  out.push('// specMappingFaultReasons lists codes a conforming mapper never emits.');
  out.push(`var specMappingFaultReasons = ${goStrings(m.fault_reasons)}`);
  return out.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/**
 * Replaces the generated region of a caid.mjs text, or returns null when the
 * text carries no well-formed region.
 *
 * @param {string} text
 * @param {string} region
 */
export function spliceJsRegion(text, region) {
  const lines = text.split('\n');
  const begin = lines.indexOf(JS_BEGIN);
  const end = lines.indexOf(JS_END);
  if (begin < 0 || end < begin || lines.indexOf(JS_BEGIN, begin + 1) >= 0 || lines.indexOf(JS_END, end + 1) >= 0) return null;
  return [...lines.slice(0, begin), ...region.replace(/\n$/, '').split('\n'), ...lines.slice(end + 1)].join('\n');
}

/**
 * All generated outputs, keyed by repository path. caid.mjs must carry
 * exactly one well-formed generated region.
 *
 * @param {string} root
 */
export function generate(root) {
  const spec = buildSpec(root);
  const region = emitJsRegion(spec);
  const outputs = new Map();
  const jsPath = path.join(root, TARGETS.js);
  const spliced = existsSync(jsPath) ? spliceJsRegion(readFileSync(jsPath, 'utf8'), region) : null;
  if (spliced === null) throw new Error(`${TARGETS.js}: no generated region (add the ${JSON.stringify(JS_BEGIN)} and ${JSON.stringify(JS_END)} lines)`);
  outputs.set(TARGETS.js, spliced);
  outputs.set(TARGETS.vendor, spliced);
  outputs.set(TARGETS.python, emitPython(spec));
  outputs.set(TARGETS.go, emitGo(spec));
  for (const src of [...Object.values(spec.patterns), ...Object.values(spec.code_formats)]) parseRegex(src);
  return { spec, outputs };
}

function main(argv) {
  const args = { write: false, check: false, out: /** @type {string | null} */ (null), root: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..') };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--write') args.write = true;
    else if (a === '--check') args.check = true;
    else if (a === '--out') args.out = path.resolve(argv[++i] ?? '');
    else if (a === '--root') args.root = path.resolve(argv[++i] ?? '');
    else throw new Error(`unknown argument ${a}`);
  }
  if (args.write && args.check) throw new Error('--write and --check are exclusive');
  if (args.write && args.out) throw new Error('--write writes the checkout; use --out DIR alone to write elsewhere');
  if (!args.write && !args.check && !args.out) throw new Error('give --write, --check, or --out DIR');
  const { outputs } = generate(args.root);
  if (args.check) {
    const base = args.out ?? args.root;
    const problems = [];
    const expected = new Map(outputs);
    for (const [rel, text] of expected) {
      const file = path.join(base, rel);
      if (!existsSync(file)) problems.push(`${rel}: missing`);
      else if (readFileSync(file, 'utf8') !== text) problems.push(`${rel}: differs from a regeneration`);
    }
    if (problems.length) {
      process.stderr.write(`caid/spec/gen.mjs --check FAILED\n${problems.map((p) => `  ${p}`).join('\n')}\nRun: node caid/spec/gen.mjs --write\n`);
      process.exit(1);
    }
    console.log(`caid/spec/gen.mjs --check: ${expected.size} generated files match`);
    return;
  }
  const base = /** @type {string} */ (args.write ? args.root : args.out);
  for (const [rel, text] of outputs) {
    const file = path.join(base, rel);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, text);
    console.log(`wrote ${path.relative(process.cwd(), file) || file}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}
