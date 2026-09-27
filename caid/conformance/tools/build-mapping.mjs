#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Builds the CAID mapping conformance corpus, version 2
// (caid/conformance/mapping-vectors.json), from the frozen version 1 corpus
// (caid/conformance/history/mapping-vectors.v1.json) and the cases below.
//
//   node caid/conformance/tools/build-mapping.mjs           write it
//   node caid/conformance/tools/build-mapping.mjs --check   exit 1 unless current
//
// Version 2 keeps the version 1 layout, which the JavaScript, Python and Go
// mapping runners already read, and makes every expectation an exact
// reason list: reason_contains is gone. Each expectation comes from the
// mapping oracle (./mapping-oracle.mjs) and must match what the case
// states; a version 1 vector must keep its verdict and, where version 1
// pinned only a substring, contain it, unless V1_CHANGES names the -04 rule
// that changes it.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareMappedActions, mappingProfileHash } from './mapping-oracle.mjs';
import { decodeStrict } from './strict-json.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../../..');
const OUT = path.join(ROOT, 'caid/conformance/mapping-vectors.json');
const V1_PATH = 'caid/conformance/history/mapping-vectors.v1.json';
const V1_SHA256 = 'sha256:6941463cdb42ad5242d1e44efa6937a9db3edbfa77ea2c5df5573ce301be6f24';

const V1_CHANGES = {
  'target-field-trailing-newline-abstains': {
    rule: 'Section 4.2.1 and 8.2: target_field follows the field-name rule (any non-empty name without ":" other than action_type), so "created_at\\n" is a valid target field and the right profile no longer abstains. It maps one more field than the left profile, so both mappings succeed and their projections differ: NOT_EQUIVALENT with material_projection_mismatch. The id keeps its version 1 spelling.',
  },
};

const sha256 = (buf) => 'sha256:' + createHash('sha256').update(buf).digest('hex');
const v1Bytes = readFileSync(path.join(ROOT, V1_PATH));
if (sha256(v1Bytes) !== V1_SHA256) throw new Error(`${V1_PATH} is not the frozen version 1 corpus`);
const v1 = JSON.parse(v1Bytes.toString('utf8'));
const clone = (v) => structuredClone(v);

// ---------------------------------------------------------------- the runner semantics
function segments(pointer) {
  return pointer.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'));
}
function mutate(root, operation) {
  const parts = segments(operation.path);
  let parent = root;
  for (const part of parts.slice(0, -1)) parent = parent[Array.isArray(parent) ? Number(part) : part];
  const key = Array.isArray(parent) ? Number(parts.at(-1)) : parts.at(-1);
  if (operation.op === 'delete') {
    if (Array.isArray(parent)) parent.splice(key, 1);
    else delete parent[key];
  } else if (operation.op === 'set') {
    if (Array.isArray(parent) && key >= parent.length) throw new Error('a set mutation may not append to an array; set the whole array');
    // "units" carries a string no strict JSON text can hold, as its UTF-16
    // code units; "nest" a value nested deeper than a strict JSON text may
    // be, as leaf inside depth arrays (or objects whose only member is "a").
    const value = Object.prototype.hasOwnProperty.call(operation, 'units') ? String.fromCharCode(...operation.units)
      : Object.prototype.hasOwnProperty.call(operation, 'nest') ? nested(operation.nest) : clone(operation.value);
    Object.defineProperty(parent, key, { value, writable: true, enumerable: true, configurable: true });
  } else throw new Error(`unsupported mutation ${operation.op}`);
}
function nested({ depth, container, leaf }) {
  let value = clone(leaf);
  for (let i = 0; i < depth; i += 1) value = container === 'object' ? { a: value } : [value];
  return value;
}
function buildSide(corpus, descriptor) {
  const profile = clone(corpus.profiles[descriptor.profile]);
  return {
    source: clone(corpus.sources[descriptor.source]),
    profile,
    source_descriptor: clone(profile.source_format),
    expected_profile_hash: descriptor.pin === 'profile' ? mappingProfileHash(profile) : descriptor.pin,
    native_verified: descriptor.native_verified !== false,
  };
}
function run(corpus, vector) {
  const left = buildSide(corpus, vector.left);
  const right = buildSide(corpus, vector.right);
  for (const operation of vector.mutations || []) mutate(operation.side === 'left' ? left[operation.target] : right[operation.target], operation);
  for (const name of vector.repin_after_mutation || []) {
    const side = name === 'left' ? left : right;
    side.expected_profile_hash = mappingProfileHash(side.profile);
  }
  // A vector's own suite, when present, replaces the corpus suite.
  const suite = Object.prototype.hasOwnProperty.call(vector, 'suite') ? vector.suite : corpus.suite;
  const r = compareMappedActions(left, right, { definitions: corpus.definitions, enumSnapshots: corpus.enum_snapshots, suite });
  return { verdict: r.verdict, reasons: r.reasons };
}

// ---------------------------------------------------------------- new cases
const EP = { source: 'ep-order', profile: 'ep-action-v1', pin: 'profile' };
const AP2 = { source: 'ap2-order', profile: 'ap2-checkout-v1', pin: 'profile' };
const set = (side, target, p, value) => ({ side, target, op: 'set', path: p, value });
const setUnits = (side, target, p, units) => ({ side, target, op: 'set', path: p, units });
const setNest = (side, target, p, depth, leaf = 0) => ({ side, target, op: 'set', path: p, nest: { depth, container: 'array', leaf } });
const del = (side, target, p) => ({ side, target, op: 'delete', path: p });
const HEX = 'a'.repeat(64);
const epRules = v1.profiles['ep-action-v1'].rules;
const epMaterial = v1.profiles['ep-action-v1'].material_source_paths;
const manyRules = Array.from({ length: 129 }, (_, i) => ({ source_path: `/x${i}`, target_field: `f${i}`, transform: 'copy' }));
const long = (n, unit = 'a') => unit.repeat(n);

/** @type {any[][]} */
const CASES = [
  // The -04 profile extension, registered.
  ['hex-to-digest-equivalent', 'sha256-hex-to-digest turns 64 lowercase hex characters into a digest field', EP, EP,
    [set('left', 'source', '/target/merchant_id', HEX), set('right', 'source', '/target/merchant_id', HEX),
      set('left', 'profile', '/rules/1/transform', 'sha256-hex-to-digest'), set('right', 'profile', '/rules/1/transform', 'sha256-hex-to-digest')],
    ['left', 'right'], 'EQUIVALENT_UNDER_PROFILE', []],
  ['hex-to-digest-uppercase-abstains', 'uppercase hex is not lowercase hex: source_value_type_mismatch', EP, EP,
    [set('right', 'source', '/target/merchant_id', HEX.toUpperCase()), set('right', 'profile', '/rules/1/transform', 'sha256-hex-to-digest')],
    ['right'], 'INDETERMINATE', ['right:source_value_type_mismatch:/target/merchant_id']],
  ['hex-to-digest-short-abstains', '63 hex characters are refused', EP, EP,
    [set('right', 'source', '/target/merchant_id', HEX.slice(1)), set('right', 'profile', '/rules/1/transform', 'sha256-hex-to-digest')],
    ['right'], 'INDETERMINATE', ['right:source_value_type_mismatch:/target/merchant_id']],
  ['omitted-source-fields-empty-equivalent', 'an empty omitted_source_fields under no-material-field-loss', EP, EP,
    [set('right', 'profile', '/omitted_source_fields', [])], ['right'], 'EQUIVALENT_UNDER_PROFILE', []],
  ['declared-loss-abstains', 'declared-source-semantic-loss with a declared omission always abstains', EP, EP,
    [set('right', 'profile', '/loss_policy', 'declared-source-semantic-loss'), set('right', 'profile', '/omitted_source_fields', [{ source_path: '/ep_version', reason: 'transport version is not material' }])],
    ['right'], 'INDETERMINATE', ['right:declared_source_semantic_loss']],
  ['declared-loss-without-omissions-abstains', 'declared-source-semantic-loss needs at least one omission', EP, EP,
    [set('right', 'profile', '/loss_policy', 'declared-source-semantic-loss')], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:declared_source_semantic_loss']],
  ['omission-under-no-loss-abstains', 'no-material-field-loss with an omission', EP, EP,
    [set('right', 'profile', '/omitted_source_fields', [{ source_path: '/ep_version', reason: 'x' }])], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['omission-is-rule-path-abstains', 'an omitted path may not also be a rule path', EP, EP,
    [set('right', 'profile', '/loss_policy', 'declared-source-semantic-loss'), set('right', 'profile', '/omitted_source_fields', [{ source_path: '/target/checkout_id', reason: 'x' }])],
    ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:declared_source_semantic_loss']],
  ['omitted-source-fields-null-abstains', 'review D2: a member present as null is malformed, never read as []', EP, EP,
    [set('right', 'profile', '/omitted_source_fields', null)], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  // Octet limits (review D3, D4).
  ['profile-id-512-octets-equivalent', 'profile_id of 170 euro signs (510 octets) is within 512', EP, EP,
    [set('right', 'profile', '/profile_id', long(170, '€'))], ['right'], 'EQUIVALENT_UNDER_PROFILE', []],
  ['profile-id-513-octets-abstains', 'profile_id of 171 euro signs is 513 UTF-8 octets, over 512 (171 UTF-16 units)', EP, EP,
    [set('right', 'profile', '/profile_id', long(171, '€'))], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['profile-id-astral-512-octets-equivalent', '128 astral characters are 512 octets', EP, EP,
    [set('right', 'profile', '/profile_id', long(128, '\u{1F600}'))], ['right'], 'EQUIVALENT_UNDER_PROFILE', []],
  ['profile-id-astral-516-octets-abstains', '129 astral characters are 516 octets (only 129 code points)', EP, EP,
    [set('right', 'profile', '/profile_id', long(129, '\u{1F600}'))], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['target-action-type-513-octets-abstains', 'review D4: target_action_type is bounded at 512 octets as a member rule, so it is exactly invalid_mapping_profile', EP, EP,
    [set('right', 'profile', '/target_action_type', `${long(509)}.1.1`)], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['pointer-2049-octets-abstains', 'a source path over 2048 octets', EP, EP,
    [set('right', 'profile', '/rules/0/source_path', `/${long(2048)}`), set('right', 'profile', '/material_source_paths/0', `/${long(2048)}`)],
    ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['pointer-2048-octets-missing', 'a source path of exactly 2048 octets passes the profile checks and is missing from the source', EP, EP,
    [set('right', 'profile', '/rules/0/source_path', `/${long(2047)}`), set('right', 'profile', '/material_source_paths/0', `/${long(2047)}`)],
    ['right'], 'INDETERMINATE', [`right:missing_source_field:/${long(2047)}`]],
  // Source paths through each port's own source-path parser: the rule is
  // interpreted, not compiled, so the grammar proof does not reach it.
  ...[
    ['source-path-without-slash-abstains', 'a source path must begin with "/"', 'target/checkout_id', ['right:invalid_mapping_profile']],
    ['source-path-bad-escape-abstains', '"~" must be followed by "0" or "1"', '/target~2checkout_id', ['right:invalid_mapping_profile']],
    ['source-path-trailing-tilde-abstains', 'a trailing "~" is not an escape', '/target/checkout_id~', ['right:invalid_mapping_profile']],
    ['source-path-escaped-slash-missing', '"~1" is "/" inside one reference token, so the path names the member "target/checkout_id", which is absent', '/target~1checkout_id', ['right:missing_source_field:/target~1checkout_id']],
    ['source-path-empty-token-missing', '"/" is a valid source path whose only token is the empty member name', '/', ['right:missing_source_field:/']],
  ].map(([id, description, sourcePath, reasons]) => [id, description, EP, EP,
    [set('right', 'profile', '/rules/0/source_path', sourcePath), set('right', 'profile', '/material_source_paths/0', sourcePath)],
    ['right'], 'INDETERMINATE', reasons]),
  ['rules-129-abstains', '129 rules is over the limit of 128', EP, EP,
    [set('right', 'profile', '/rules', manyRules), set('right', 'profile', '/material_source_paths', manyRules.map((r) => r.source_path))],
    ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  // Field names and types (review D5, D8, D9).
  ['target-field-at-version-equivalent', 'a target_field of "@version" is a field name', EP, EP,
    [set('left', 'source', '/meta_version', '1'), set('right', 'source', '/meta_version', '1'),
      ...['left', 'right'].flatMap((side) => [
        set(side, 'profile', '/rules', [...epRules, { source_path: '/meta_version', target_field: '@version', transform: 'copy' }]),
        set(side, 'profile', '/material_source_paths', [...epMaterial, '/meta_version'])])],
    ['left', 'right'], 'EQUIVALENT_UNDER_PROFILE', []],
  ['target-field-array-abstains', 'review D5: a target_field that is an array is refused, never coerced to a string', EP, EP,
    [set('right', 'profile', '/rules/0/target_field', ['order_id'])], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['target-field-action-type-abstains', 'a rule may not target action_type', EP, EP,
    [set('right', 'profile', '/rules/0/target_field', 'action_type')], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['target-field-colon-abstains', 'a target field may not contain ":"', EP, EP,
    [set('right', 'profile', '/rules/0/target_field', 'order:id')], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['transform-array-abstains', 'review D8: a transform that is an array is invalid_mapping_profile, never an exception', EP, EP,
    [set('right', 'profile', '/rules/0/transform', ['copy'])], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['loss-policy-array-abstains', 'review D8: a loss_policy that is an array', EP, EP,
    [set('right', 'profile', '/loss_policy', ['no-material-field-loss'])], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['material-path-number-abstains', 'review D9: a material path that is a number beside an unknown target type is exactly invalid_mapping_profile: the member rules are a gate', EP, EP,
    [set('right', 'profile', '/material_source_paths/0', 123), set('right', 'profile', '/target_action_type', 'unknown.type.1')], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['newline-joined-coverage-abstains', 'review D6: one rule path holding two material paths joined by a line feed never stands in for both; coverage compares sets', EP, EP,
    [set('right', 'profile', '/rules/3/source_path', '/parameters/currency\n/parameters/line_items'), del('right', 'profile', '/rules/4')],
    ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:unmapped_material_field:items_digest']],
  ['two-rules-one-path-abstains', 'exactly one rule per material path: two rules on one source path', EP, EP,
    [set('right', 'profile', '/rules', [...epRules, { source_path: '/target/checkout_id', target_field: 'shipping_method', transform: 'copy' }])], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile']],
  ['duplicate-target-field-abstains', 'two rules may not target one field', EP, EP,
    [set('right', 'profile', '/rules/1/target_field', 'order_id')], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:unmapped_material_field:merchant_ref']],
  // The normative stage order.
  ['stage-a-order', 'stage A: invalid_mapping_profile, then the definition reason', EP, EP,
    [set('right', 'profile', '/rules/1/target_field', 'order_id'), set('right', 'profile', '/target_action_type', 'unknown.type.1')], ['right'], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:unknown_action_type']],
  ['stage-a-unmapped-in-required-order', 'unmapped material fields follow required_fields order, not rule order', EP, EP,
    [del('right', 'profile', '/rules/6'), del('right', 'profile', '/rules/0'), del('right', 'profile', '/material_source_paths/6'), del('right', 'profile', '/material_source_paths/0')],
    ['right'], 'INDETERMINATE', ['right:unmapped_material_field:order_id', 'right:unmapped_material_field:fulfillment_ref']],
  ['stage-a-then-b', 'stage B reasons follow stage A, in rank order', { ...EP, pin: 'profile', native_verified: false }, { ...EP, native_verified: false },
    [del('right', 'profile', '/rules/0'), del('right', 'profile', '/material_source_paths/0'), set('right', 'source_descriptor', '/version', '2')],
    [], 'INDETERMINATE', ['left:native_verification_required', 'right:unmapped_material_field:order_id', 'right:native_verification_required', 'right:mapping_profile_unpinned', 'right:source_format_mismatch']],
  ['stage-a-gate-then-b', 'a shape failure is exactly invalid_mapping_profile, and stage B still follows it', EP, { ...EP, native_verified: false },
    [set('right', 'profile', '/authorization', 'allow'), set('right', 'source_descriptor', '/schema', 'x')],
    [], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:native_verification_required', 'right:mapping_profile_unpinned', 'right:source_format_mismatch']],
  ['stage-c-every-rule-reports', 'when the source lacks every material member, each rule reports once, in rule order', EP, EP,
    [set('right', 'source', '/target', 'x'), set('right', 'source', '/parameters', null)],
    [], 'INDETERMINATE', ['/target/checkout_id', '/target/merchant_id', '/parameters/total_amount', '/parameters/currency', '/parameters/line_items', '/target/customer_id', '/target/fulfillment'].map((p) => `right:missing_source_field:${p}`)],
  ['stage-c-rule-order', 'stage C reports one reason per rule in rule order', EP, EP,
    [del('right', 'source', '/target/customer_id'), set('right', 'source', '/target/merchant_id', 7)],
    [], 'INDETERMINATE', ['right:source_value_type_mismatch:/target/merchant_id', 'right:missing_source_field:/target/customer_id']],
  ['stage-c-array-index', 'an array index with a leading zero is invalid_source_path', { source: 'silp-cancel-email', profile: 'silp-cancel-email-v1', pin: 'profile' }, { source: 'silp-cancel-email', profile: 'silp-cancel-email-v1', pin: 'profile' },
    [set('right', 'profile', '/rules/7/source_path', '/constraints/00/time'), set('right', 'profile', '/material_source_paths/7', '/constraints/00/time')], ['right'], 'INDETERMINATE', ['right:invalid_source_path:/constraints/00/time']],
  ['stage-b-source-not-canonicalizable', 'a source outside the data model stops at stage B, before any rule reads it', EP, EP,
    [set('right', 'source', '/parameters/total_amount', 1.5)], [], 'INDETERMINATE', ['right:source_not_canonicalizable']],
  ['stage-b-source-deep-not-canonicalizable', 'the nesting limit on a host mapping source: a member nested 70 deep, beside no rule path, is source_not_canonicalizable (never unsupported_value)', EP, EP,
    [setNest('right', 'source', '/x', 70)], [], 'INDETERMINATE', ['right:source_not_canonicalizable']],
  ['stage-d-compute-order', 'stage D reports the mapped action\'s compute reasons in compute order', EP, EP,
    [set('right', 'source', '/parameters/currency', 'EURO'), set('right', 'source', '/parameters/total_amount', '01.00')],
    [], 'INDETERMINATE', ['right:mapped_action:invalid_amount:total_amount', 'right:mapped_action:mistyped_field:currency']],
  ['stage-d-number-in-amount', 'a copied number in an amount-string field is mistyped_field', EP, EP,
    [set('right', 'source', '/parameters/total_amount', 130)], [], 'INDETERMINATE', ['right:mapped_action:mistyped_field:total_amount']],
  ['comparison-left-then-right', 'left reasons precede right reasons', EP, EP,
    [set('left', 'source', '/target/merchant_id', 1), del('right', 'source', '/parameters/currency')],
    [], 'INDETERMINATE', ['left:source_value_type_mismatch:/target/merchant_id', 'right:missing_source_field:/parameters/currency']],
  ['comparison-target-type-mismatch', 'two profiles that map to different action types', EP, { source: 'silp-cancel-email', profile: 'silp-cancel-email-v1', pin: 'profile' },
    [], [], 'INDETERMINATE', ['target_action_type_mismatch']],
  ['empty-suite-not-defaulted', 'review D10: an empty suite is used as given and refused, never replaced by the default jcs-sha256', EP, EP,
    [], [], 'INDETERMINATE', ['left:mapped_action:unknown_suite', 'right:mapped_action:unknown_suite'], { suite: '' }],
  // A profile outside the data model has no digest, so it fails the stage A
  // shape gate: exactly invalid_mapping_profile, and no stage A check after
  // it runs (here, no unmapped_material_field for the dropped rule).
  ['profile-id-noncharacter-abstains', 'a profile_id holding U+FFFF is outside the data model: exactly invalid_mapping_profile, then mapping_profile_unpinned since the profile has no digest', EP, EP,
    [setUnits('right', 'profile', '/profile_id', [0xffff]), del('right', 'profile', '/rules/0'), del('right', 'profile', '/material_source_paths/0')],
    [], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:mapping_profile_unpinned']],
  ['profile-id-lone-surrogate-abstains', 'a host profile_id holding a lone surrogate is refused the same way', EP, EP,
    [setUnits('right', 'profile', '/profile_id', [0xd800]), del('right', 'profile', '/rules/0'), del('right', 'profile', '/material_source_paths/0')],
    [], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:mapping_profile_unpinned']],
  ['profile-schema-noncharacter-abstains', 'a noncharacter in source_format.schema also leaves the profile outside the data model', EP, EP,
    [setUnits('right', 'profile', '/source_format/schema', [0xfdd0])],
    [], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:mapping_profile_unpinned', 'right:source_format_mismatch']],
  // Stage B reads the profile's source_format and loss_policy members
  // whenever the profile is an object, in the data model or not, and
  // whether or not stage A failed (review IMPL-3). A host profile with a
  // member nested 70 deep has no digest, so it is unpinned; its intact
  // source_format still equals the descriptor, so there is no
  // source_format_mismatch, and its loss_policy is still read.
  ['profile-deep-member-abstains', 'a host profile with an extra member nested 70 deep is outside the data model: invalid_mapping_profile and mapping_profile_unpinned, and no source_format_mismatch, since stage B still reads its intact source_format', EP, EP,
    [setNest('right', 'profile', '/x', 70)],
    [], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:mapping_profile_unpinned']],
  ['profile-deep-member-declared-loss-abstains', 'the same host profile declaring source semantic loss with one omission: stage B still reads its loss_policy and reports declared_source_semantic_loss', EP, EP,
    [set('right', 'profile', '/loss_policy', 'declared-source-semantic-loss'), set('right', 'profile', '/omitted_source_fields', [{ source_path: '/ep_version', reason: 'transport version is not material' }]),
      setNest('right', 'profile', '/x', 70)],
    [], 'INDETERMINATE', ['right:invalid_mapping_profile', 'right:mapping_profile_unpinned', 'right:declared_source_semantic_loss']],
];

// ---------------------------------------------------------------- build
const corpus = clone(v1);
const problems = [];
const vectors = [];
for (const old of v1.vectors) {
  const got = run(v1, old);
  const change = V1_CHANGES[old.id];
  if (!change) {
    if (got.verdict !== old.expect.verdict) problems.push(`${old.id}: verdict ${got.verdict}, version 1 ${old.expect.verdict}`);
    if (old.expect.reason_contains !== undefined && !got.reasons.includes(old.expect.reason_contains)) problems.push(`${old.id}: ${JSON.stringify(got.reasons)} lacks ${old.expect.reason_contains}`);
    if (old.expect.reasons !== undefined && JSON.stringify(got.reasons) !== JSON.stringify(old.expect.reasons)) problems.push(`${old.id}: ${JSON.stringify(got.reasons)}, version 1 ${JSON.stringify(old.expect.reasons)}`);
  }
  const { expect, ...rest } = old;
  const out = { ...rest, expect: { verdict: got.verdict, reasons: got.reasons } };
  if (change) out.change_since_v1 = change.rule;
  vectors.push(out);
}
for (const [id, description, left, right, mutations, repin, verdict, reasons, options] of CASES) {
  /** @type {Record<string, any>} */
  const v = { id, description, left, right };
  if (options && Object.prototype.hasOwnProperty.call(options, 'suite')) v.suite = options.suite;
  if (mutations.length) v.mutations = mutations;
  if (repin.length) v.repin_after_mutation = repin;
  const got = run(corpus, v);
  if (got.verdict !== verdict || JSON.stringify(got.reasons) !== JSON.stringify(reasons)) {
    problems.push(`${id}: oracle ${got.verdict} ${JSON.stringify(got.reasons).slice(0, 600)}; stated ${verdict} ${JSON.stringify(reasons).slice(0, 600)}`);
  }
  v.expect = { verdict: got.verdict, reasons: got.reasons };
  vectors.push(v);
}
const ids = new Set();
for (const v of vectors) { if (ids.has(v.id)) problems.push(`${v.id}: duplicate id`); ids.add(v.id); }
if (problems.length) {
  process.stderr.write(`build-mapping: ${problems.length} problem(s)\n${problems.map((p) => `  ${p}`).join('\n')}\n`);
  process.exit(1);
}
const { vectors: _v, ...envelope } = corpus;
const out = {
  '@version': 'CAID-ACTION-MAPPING-VECTORS-v2',
  version: 2,
  description: `${v1.description} Every expectation is an exact reason list in the -04 stage order (Section 8.5). A vector that carries its own suite member uses it in place of the corpus suite for that comparison. A set mutation carries its value as value, as units (the UTF-16 code units of a string no strict JSON text can hold), or as nest ({depth, container, leaf}: leaf inside depth nested arrays, or objects whose only member is "a", a host value nested deeper than a strict JSON text may be).`,
  previous_versions: [{
    version: 1,
    vectors: v1.vectors.length,
    sha256: V1_SHA256,
    history: V1_PATH,
    note: 'Version 2 keeps the layout and every version 1 vector under the same id. The 10 vectors that pinned only reason_contains now pin the whole list; one vector changes because -04 widens target_field to the field-name rule (change_since_v1).',
  }],
  ...Object.fromEntries(Object.entries(envelope).filter(([k]) => !['@version', 'description'].includes(k))),
};
const head = JSON.stringify(out, null, 1);
const text = `${head.slice(0, -2)},\n "vectors": [\n${vectors.map((v) => '  ' + JSON.stringify(v)).join(',\n')}\n ]\n}\n`;
const self = decodeStrict(new Uint8Array(Buffer.from(text, 'utf8')), { maxOctets: null });
if (!self.ok) throw new Error(`mapping-vectors.json is not strict I-JSON: ${self.detail}`);
if (process.argv.includes('--check')) {
  let current = '';
  try { current = readFileSync(OUT, 'utf8'); } catch { /* missing */ }
  if (current !== text) {
    process.stderr.write('build-mapping: caid/conformance/mapping-vectors.json is not current; run node caid/conformance/tools/build-mapping.mjs\n');
    process.exit(1);
  }
  console.log(`PASS mapping corpus v2 is current (${vectors.length} vectors)`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote caid/conformance/mapping-vectors.json: ${vectors.length} vectors`);
}
