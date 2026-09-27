// SPDX-License-Identifier: Apache-2.0
// CAID Action-Mapping Profile v1 (draft-schrock-canonical-action-identifier-04
// Section 8).
//
// A mapping result is a content-correlation result, not authorization.
// The caller pins the exact mapping profile hash and source descriptor.
// Missing fields, unregistered transforms, or an unpinned profile yield
// INDETERMINATE. No mapping failure is converted into equivalence.
//
// Every closed set, limit, member rule and reason rank below comes from the
// generated CAID_SPEC.mapping data in caid.mjs. Reasons are produced in the
// normative stage order:
//   A  profile checks. A profile that is not an object in the data model
//      (so it has no profile digest), has the wrong @version, an unknown or
//      missing member, or a member that breaks its member rule yields
//      exactly invalid_mapping_profile. Otherwise every
//      remaining check runs: uniqueness, set equality, disjointness and the
//      loss policy (invalid_mapping_profile), definition resolution
//      (unknown_action_type or invalid_definition), and one
//      unmapped_material_field:<f> per unmapped required field.
//   B  pin and source checks, sorted with A by reason rank. The mapping
//      stops if A or B produced any reason.
//   C  one reason at most per rule, in rule order, parameterized by the
//      rule's source path. The mapping stops if C produced any reason.
//   D  mapped_action:<r> for each compute reason, in compute order.
// A comparison reports left: reasons, then right: reasons; then
// target_action_type_mismatch; NOT_EQUIVALENT carries
// material_projection_mismatch.

import { createHash } from 'node:crypto';
import {
  CAID_PATTERNS,
  CAID_SPEC,
  canonicalize,
  computeCaid,
  resolveCaidDefinition,
  toCaidData,
} from './caid.mjs';

const M = CAID_SPEC.mapping;
const LIMITS = CAID_SPEC.limits;

export const MAPPING_PROFILE_VERSION = M.profile_version;
export const MAPPING_VERDICTS = Object.freeze({
  equivalent: M.verdicts[0],
  different: M.verdicts[1],
  indeterminate: M.verdicts[2],
});

const CLOSED_SETS = {
  transforms: new Set(M.transforms.map((t) => t.transform)),
  loss_policies: new Set(M.loss_policies.map((p) => p.policy)),
};
const TRANSFORMS = new Map(M.transforms.map((t) => [t.transform, t]));
const LOSS_POLICIES = new Map(M.loss_policies.map((p) => [p.policy, p]));
const MEMBERS = {
  profile: new Set(M.members.profile),
  source_format: new Set(M.members.source_format),
  rule: new Set(M.members.rule),
  omitted_source_field: new Set(M.members.omitted_source_field),
};
const OPTIONAL_PROFILE_MEMBERS = new Set(M.optional_members.profile);

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const member = (obj, key) => (isObject(obj) && hasOwn(obj, key) ? obj[key] : undefined);
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

// One own data property of a host object, read without invoking a getter
// or throwing; undefined when absent.
function ownData(obj, key) {
  if (typeof obj !== 'object' || obj === null) return undefined;
  try {
    const d = Reflect.getOwnPropertyDescriptor(obj, key);
    return d && hasOwn(d, 'value') ? d.value : undefined;
  } catch {
    return undefined;
  }
}

// True when a host value is an object in the data model's sense (not an
// array, prototype Object.prototype or null), checked without user code.
function isPlainHostObject(value) {
  if (typeof value !== 'object' || value === null) return false;
  try {
    if (Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
}

function defineMember(obj, key, value) {
  Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
}

// The UTF-8 length of a string, or -1 when it is not a sequence of Unicode
// scalar values (a lone surrogate has no UTF-8 encoding).
function utf8Octets(s) {
  let octets = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) octets += 1;
    else if (c < 0x800) octets += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return -1;
      octets += 4;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return -1;
    else octets += 3;
  }
  return octets;
}

// field-name (Appendix A.5): one or more scalar values, none of them ":".
function isFieldName(s) {
  return typeof s === 'string' && s.length > 0 && !s.includes(':') && utf8Octets(s) >= 0;
}

// source-path (Appendix A.6): a JSON Pointer [RFC 6901] other than "", with
// every "~" followed by "0" or "1".
function isSourcePath(s) {
  if (typeof s !== 'string' || s.length === 0 || s[0] !== '/' || utf8Octets(s) < 0) return false;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '~' && s[i + 1] !== '0' && s[i + 1] !== '1') return false;
  }
  return true;
}

const RULE_PREDICATES = { 'source-path': isSourcePath, 'field-name': isFieldName };

function pointerSegments(pointer) {
  return pointer.slice(1).split('/').map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'));
}

// Every value a member-rule path names. "*" ranges over an array's
// elements; a path whose parent is absent names nothing.
function valuesAt(root, path) {
  let current = [root];
  for (const step of path) {
    const next = [];
    for (const value of current) {
      if (step === '*') {
        if (Array.isArray(value)) next.push(...value);
      } else if (isObject(value) && hasOwn(value, step)) {
        next.push(value[step]);
      }
    }
    current = next;
  }
  return current;
}

function jsonKind(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function hasExactMembers(value, allowed, optional = new Set()) {
  if (!isObject(value)) return false;
  for (const key of Object.keys(value)) if (!allowed.has(key)) return false;
  for (const key of allowed) if (!optional.has(key) && !hasOwn(value, key)) return false;
  return true;
}

function limit(id) {
  return id === undefined ? undefined : LIMITS[id];
}

// The shape gate of stage A: an object in the data model (canonicalizable,
// so it has a profile digest), @version, closed members, member rules.
function profileShapeValid(profile, canonicalizable) {
  if (!isObject(profile) || !canonicalizable || member(profile, '@version') !== M.profile_version) return false;
  if (!hasExactMembers(profile, MEMBERS.profile, OPTIONAL_PROFILE_MEMBERS)) return false;
  if (!hasExactMembers(profile.source_format, MEMBERS.source_format)) return false;
  for (const rule of Array.isArray(profile.rules) ? profile.rules : []) {
    if (!hasExactMembers(rule, MEMBERS.rule)) return false;
  }
  const omissions = member(profile, 'omitted_source_fields');
  for (const omission of Array.isArray(omissions) ? omissions : []) {
    if (!hasExactMembers(omission, MEMBERS.omitted_source_field)) return false;
  }
  for (const rule of M.member_rules) {
    for (const value of valuesAt(profile, rule.path)) {
      if (jsonKind(value) !== rule.json) return false;
      if (rule.json === 'string') {
        const octets = utf8Octets(value);
        if (octets < 0) return false;
        const min = limit(rule.min_octets);
        const max = limit(rule.max_octets);
        if (min !== undefined && octets < min) return false;
        if (max !== undefined && octets > max) return false;
        if (rule.closed !== undefined && !CLOSED_SETS[rule.closed].has(value)) return false;
        if (rule.rule !== undefined && !RULE_PREDICATES[rule.rule](value)) return false;
        if (rule.reserved !== undefined && rule.reserved.includes(value)) return false;
      } else if (rule.json === 'array') {
        const min = limit(rule.min_items);
        const max = limit(rule.max_items);
        if (min !== undefined && value.length < min) return false;
        if (max !== undefined && value.length > max) return false;
      }
    }
  }
  return true;
}

// Stage A. Returns [rank, position, reason] entries.
function profileReasons(profile, canonicalizable, definitions) {
  const rank = M.reason_rank;
  if (!profileShapeValid(profile, canonicalizable)) return [[rank.invalid_mapping_profile, 0, 'invalid_mapping_profile']];
  const found = [];
  const invalid = () => found.push([rank.invalid_mapping_profile, 0, 'invalid_mapping_profile']);
  const strings = (path) => valuesAt(profile, path);
  for (const path of M.unique) {
    const values = strings(path);
    if (new Set(values).size !== values.length) invalid();
  }
  for (const [leftPath, rightPath] of M.equal_sets) {
    const left = new Set(strings(leftPath));
    const right = new Set(strings(rightPath));
    if (left.size !== right.size || [...left].some((value) => !right.has(value))) invalid();
  }
  for (const [leftPath, rightPath] of M.disjoint) {
    const right = new Set(strings(rightPath));
    if (strings(leftPath).some((value) => right.has(value))) invalid();
  }
  const policy = LOSS_POLICIES.get(profile.loss_policy);
  const omissionCount = strings(['omitted_source_fields', '*']).length;
  if (policy.omitted_source_fields === 'absent_or_empty' ? omissionCount !== 0 : omissionCount === 0) invalid();

  const resolved = resolveCaidDefinition(profile.target_action_type, definitions);
  if (!resolved.ok) {
    const reason = resolved.refusals[0];
    found.push([rank[reason], 0, reason]);
  } else {
    const targets = new Set(strings(['rules', '*', 'target_field']));
    resolved.definition.required_fields.forEach((field, index) => {
      if (!targets.has(field.name)) {
        found.push([rank.unmapped_material_field, index, 'unmapped_material_field:' + field.name]);
      }
    });
  }
  return found;
}

function hashCanonical(value) {
  const result = canonicalize(value);
  if (!result.ok) return null;
  return 'sha256:' + sha256Hex(Buffer.from(result.canonical, 'utf8'));
}

function descriptorEqual(left, right) {
  const a = canonicalize(left);
  const b = canonicalize(right);
  return a.ok && b.ok && a.canonical === b.canonical;
}

function atPointer(value, pointer) {
  let current = value;
  for (const segment of pointerSegments(pointer)) {
    if (Array.isArray(current)) {
      if (!CAID_PATTERNS.array_index.test(segment)) return { found: false, reason: 'invalid_source_path' };
      const index = Number(segment);
      if (!Number.isSafeInteger(index) || index >= current.length) return { found: false, reason: 'missing_source_field' };
      current = current[index];
    } else if (isObject(current)) {
      if (!hasOwn(current, segment)) return { found: false, reason: 'missing_source_field' };
      current = current[segment];
    } else {
      return { found: false, reason: 'missing_source_field' };
    }
  }
  return { found: true, value: current };
}

function applyTransform(value, transform) {
  const spec = TRANSFORMS.get(transform);
  if (spec === undefined) return { ok: false, reason: 'unknown_transform' };
  if (spec.input === 'string' && typeof value !== 'string') return { ok: false, reason: 'source_value_type_mismatch' };
  if (spec.pattern !== undefined && !CAID_PATTERNS[spec.pattern].test(value)) {
    return { ok: false, reason: 'source_value_type_mismatch' };
  }
  if (transform === 'copy') {
    if (!canonicalize(value).ok) return { ok: false, reason: 'source_value_not_canonicalizable' };
    return { ok: true, value };
  }
  if (transform === 'sha256-utf8') {
    if (utf8Octets(value) < 0) return { ok: false, reason: 'source_value_not_canonicalizable' };
    return { ok: true, value: 'sha256:' + sha256Hex(Buffer.from(value, 'utf8')) };
  }
  if (transform === 'sha256-jcs') {
    const canonical = canonicalize(value);
    if (!canonical.ok) return { ok: false, reason: 'source_value_not_canonicalizable' };
    return { ok: true, value: 'sha256:' + sha256Hex(Buffer.from(canonical.canonical, 'utf8')) };
  }
  // sha256-hex-to-digest: exactly 64 lowercase hex characters.
  return { ok: true, value: 'sha256:' + value };
}

/**
 * The profile hash callers pin: sha256 over the RFC 8785 encoding of the
 * profile, or null when the profile is outside the data model.
 *
 * @param {any} profile
 */
export function mappingProfileHash(profile) {
  return hashCanonical(profile);
}

/**
 * @typedef {Object} MapActionFailure
 * @property {false} ok
 * @property {string[]} reasons
 * @property {string|null} profile_hash
 * @property {string|null} source_digest
 */

/**
 * @typedef {Object} MapActionSuccess
 * @property {true} ok
 * @property {any} action
 * @property {string} caid
 * @property {string} digest
 * @property {string} definition_sha256
 * @property {string} suite
 * @property {string|null} profile_hash
 * @property {string|null} source_digest
 */

/**
 * Maps a native source through a pinned profile to an action object and its
 * CAID. A source received as JSON text must be decoded with decodeCaidJson
 * first. The suite defaults to jcs-sha256 only when it is absent.
 *
 * @param {any} source
 * @param {{profile?: any, sourceDescriptor?: any, expectedProfileHash?: any, nativeVerified?: any, definitions?: any, enumSnapshots?: any, suite?: any}} [params]
 * @returns {MapActionFailure|MapActionSuccess}
 */
export function mapAction(source, params = {}) {
  try {
    const read = (key) => ownData(params, key);
    const suiteOption = read('suite');
    const suite = suiteOption === undefined ? 'jcs-sha256' : suiteOption;
    const definitions = read('definitions');
    const enumSnapshots = read('enumSnapshots');
    const profileData = toCaidData(read('profile'));
    const profile = profileData.ok ? profileData.value : undefined;
    const sourceData = toCaidData(source);
    const sourceValue = sourceData.ok ? sourceData.value : undefined;

    const rank = M.reason_rank;
    const profileHash = profile === undefined ? null : hashCanonical(profile);
    const found = profileReasons(profile, profileHash !== null, definitions);
    const stageB = (reason) => found.push([rank[reason], 0, reason]);
    if (read('nativeVerified') !== true) stageB('native_verification_required');
    const expectedProfileHash = read('expectedProfileHash');
    if (typeof expectedProfileHash !== 'string' || expectedProfileHash !== profileHash) stageB('mapping_profile_unpinned');
    const sourceDescriptor = read('sourceDescriptor');
    if (!isObject(sourceDescriptor) || !isObject(profile) || !descriptorEqual(sourceDescriptor, member(profile, 'source_format'))) {
      stageB('source_format_mismatch');
    }
    const sourceIsObject = isPlainHostObject(source);
    if (!sourceIsObject) stageB('source_not_object');
    const sourceDigest = sourceIsObject && isObject(sourceValue) ? hashCanonical(sourceValue) : null;
    if (sourceDigest === null) stageB('source_not_canonicalizable');
    const policy = LOSS_POLICIES.get(member(profile, 'loss_policy'));
    if (policy !== undefined && policy.stage_reason !== undefined) stageB(policy.stage_reason);
    if (found.length > 0) {
      found.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
      return { ok: false, reasons: [...new Set(found.map((f) => f[2]))], profile_hash: profileHash, source_digest: sourceDigest };
    }

    const action = {};
    defineMember(action, 'action_type', profile.target_action_type);
    const stageC = [];
    for (const rule of profile.rules) {
      const located = atPointer(sourceValue, rule.source_path);
      if (!located.found) {
        stageC.push(located.reason + ':' + rule.source_path);
        continue;
      }
      const transformed = applyTransform(located.value, rule.transform);
      if (!transformed.ok) {
        stageC.push(transformed.reason + ':' + rule.source_path);
        continue;
      }
      defineMember(action, rule.target_field, transformed.value);
    }
    if (stageC.length > 0) {
      return { ok: false, reasons: stageC, profile_hash: profileHash, source_digest: sourceDigest };
    }

    const computed = computeCaid(action, { suite, definitions, enumSnapshots });
    if (typeof computed.caid !== 'string') {
      return {
        ok: false,
        reasons: (computed.refusals || ['invalid_mapped_action']).map((reason) => 'mapped_action:' + reason),
        profile_hash: profileHash,
        source_digest: sourceDigest,
      };
    }
    return {
      ok: true,
      action,
      caid: computed.caid,
      digest: computed.digest,
      definition_sha256: computed.definition_sha256,
      suite,
      profile_hash: profileHash,
      source_digest: sourceDigest,
    };
  } catch {
    return { ok: false, reasons: ['unexpected_mapping_error'], profile_hash: null, source_digest: null };
  }
}

/**
 * @param {any} left
 * @param {any} right
 * @param {{definitions?: any, enumSnapshots?: any, suite?: any}} [params]
 */
export function compareMappedActions(left, right, params = {}) {
  const definitions = ownData(params, 'definitions');
  const enumSnapshots = ownData(params, 'enumSnapshots');
  const suite = ownData(params, 'suite');
  const mapOne = (value) => mapAction(ownData(value, 'source'), {
    profile: ownData(value, 'profile'),
    sourceDescriptor: ownData(value, 'source_descriptor'),
    expectedProfileHash: ownData(value, 'expected_profile_hash'),
    nativeVerified: ownData(value, 'native_verified'),
    definitions,
    enumSnapshots,
    suite,
  });
  const l = mapOne(left);
  const r = mapOne(right);
  if (!l.ok || !r.ok) {
    return {
      verdict: MAPPING_VERDICTS.indeterminate,
      reasons: [
        ...(!l.ok ? l.reasons.map((reason) => M.comparison.prefixes[0] + ':' + reason) : []),
        ...(!r.ok ? r.reasons.map((reason) => M.comparison.prefixes[1] + ':' + reason) : []),
      ],
      left: l,
      right: r,
    };
  }
  if (l.action.action_type !== r.action.action_type) {
    return { verdict: MAPPING_VERDICTS.indeterminate, reasons: ['target_action_type_mismatch'], left: l, right: r };
  }
  const equivalent = l.caid === r.caid;
  return {
    verdict: equivalent ? MAPPING_VERDICTS.equivalent : MAPPING_VERDICTS.different,
    reasons: equivalent ? [] : ['material_projection_mismatch'],
    left: l,
    right: r,
  };
}
