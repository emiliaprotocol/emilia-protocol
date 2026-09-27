// SPDX-License-Identifier: Apache-2.0
//
// Dev-time reference for the Action-Mapping Profile (draft -04 Section 8),
// built from caid/spec/core.json mapping data and the core oracle. It sets
// the expected reasons of mapping corpus version 2 and is the fuzz oracle
// for map and compare cases. It is not a port.
//
// Stages (core.json mapping.stages), each list deduplicated:
//   A  profile checks. A shape failure (not an object, wrong @version, an
//      unknown or missing member, or a member rule failing: JSON type, UTF-8
//      octet bounds, closed sets, the source-path and field-name rules,
//      item counts) yields exactly invalid_mapping_profile. Otherwise every
//      check runs: uniqueness, equal sets, disjointness and the loss policy
//      (each invalid_mapping_profile), then definition resolution of
//      target_action_type (unknown_action_type | invalid_definition), then
//      unmapped_material_field:<f> in required_fields order.
//   B  appended after A, in rank order: native_verification_required,
//      mapping_profile_unpinned, source_format_mismatch, source_not_object,
//      source_not_canonicalizable, declared_source_semantic_loss. Stop when
//      A and B together are non-empty.
//   C  one reason at most per rule, in rule order: invalid_source_path,
//      missing_source_field, source_value_type_mismatch,
//      source_value_not_canonicalizable, unknown_transform, ":<pointer>".
//      Stop when any.
//   D  mapped_action:<reason> for each compute reason, in compute order.
// Comparison: left: reasons then right: reasons (INDETERMINATE); then
// target_action_type_mismatch (INDETERMINATE); then EQUIVALENT_UNDER_PROFILE
// or NOT_EQUIVALENT with material_projection_mismatch.

import { createHash } from 'node:crypto';
import * as oracle from './oracle.mjs';
import { hasLoneSurrogate, hasNoncharacter } from './strict-json.mjs';

const { spec, reference } = oracle;
const M = spec.mapping;
const L = spec.limits;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
const octets = (s) => Buffer.byteLength(s, 'utf8');
const hex = (s) => createHash('sha256').update(s).digest('hex');
const patterns = Object.fromEntries(Object.entries(spec.patterns).map(([k, v]) => [k, new RegExp(`^(?:${v})$`)]));
const cleanString = (s) => typeof s === 'string' && !hasLoneSurrogate(s) && !hasNoncharacter(s);

// source-path = "/" reference-token json-pointer; reference-token excludes
// "/" and "~" except the escapes ~0 and ~1; any other scalar value.
function validSourcePath(s) {
  if (!cleanString(s) || s.length === 0 || s[0] !== '/') return false;
  return !/~(?![01])/u.test(s);
}
function validFieldName(s, reserved = []) {
  return cleanString(s) && s.length > 0 && !s.includes(':') && !reserved.includes(s);
}

function canonical(value) {
  const c = reference.canonicalize(value);
  return c.ok ? c.canonical : null;
}
function hashJson(value) {
  const c = canonical(value);
  return c === null ? null : `sha256:${hex(Buffer.from(c, 'utf8'))}`;
}
export const mappingProfileHash = hashJson;

// Values at a member-rule path: [["rules","*","source_path"]] -> list.
function valuesAt(profile, path) {
  let current = [profile];
  for (const seg of path) {
    const next = [];
    for (const c of current) {
      if (seg === '*') { if (Array.isArray(c)) next.push(...c); } else if (isObject(c) && own(c, seg)) next.push(c[seg]);
    }
    current = next;
  }
  return current;
}

function shapeValid(profile) {
  if (!isObject(profile) || profile['@version'] !== M.profile_version) return false;
  const members = new Set(M.members.profile);
  const optional = new Set(M.optional_members.profile ?? []);
  for (const k of Object.keys(profile)) if (!members.has(k)) return false;
  for (const k of members) if (!optional.has(k) && !own(profile, k)) return false;
  for (const k of Object.keys(profile)) if (profile[k] === null) return false;
  const containers = [
    ['source_format', [profile.source_format], M.members.source_format],
    ['rule', Array.isArray(profile.rules) ? profile.rules : [], M.members.rule],
    ['omitted_source_field', Array.isArray(profile.omitted_source_fields) ? profile.omitted_source_fields : [], M.members.omitted_source_field],
  ];
  for (const [, items, allowed] of containers) {
    for (const item of items) {
      if (!isObject(item)) return false;
      const keys = Object.keys(item);
      if (keys.length !== allowed.length || !allowed.every((k) => own(item, k))) return false;
    }
  }
  for (const r of M.member_rules) {
    const isItemPath = r.path.includes('*');
    const values = valuesAt(profile, r.path);
    if (!isItemPath && r.path.length === 1 && !own(profile, r.path[0])) {
      if ((M.optional_members.profile ?? []).includes(r.path[0])) continue;
      return false;
    }
    for (const v of values) {
      if (r.json === 'string') {
        if (!cleanString(v)) return false;
        if (r.min_octets && octets(v) < L[r.min_octets]) return false;
        if (r.max_octets && octets(v) > L[r.max_octets]) return false;
        if (r.closed && !M[r.closed].some((x) => x.transform === v || x.policy === v)) return false;
        if (r.rule === 'source-path' && !validSourcePath(v)) return false;
        if (r.rule === 'field-name' && !validFieldName(v, r.reserved ?? [])) return false;
      } else if (r.json === 'array') {
        if (!Array.isArray(v)) return false;
        if (r.min_items && v.length < L[r.min_items]) return false;
        if (r.max_items && v.length > L[r.max_items]) return false;
      }
    }
  }
  return true;
}

function stageA(profile, definitions) {
  if (!shapeValid(profile)) return ['invalid_mapping_profile'];
  const out = [];
  let invalid = false;
  for (const path of M.unique) {
    const vs = valuesAt(profile, path);
    if (new Set(vs).size !== vs.length) invalid = true;
  }
  for (const [a, b] of M.equal_sets) {
    const x = new Set(valuesAt(profile, a));
    const y = new Set(valuesAt(profile, b));
    if (x.size !== y.size || [...x].some((v) => !y.has(v))) invalid = true;
  }
  for (const [a, b] of M.disjoint) {
    const y = new Set(valuesAt(profile, b));
    if (valuesAt(profile, a).some((v) => y.has(v))) invalid = true;
  }
  const omissions = profile.omitted_source_fields ?? [];
  const policy = M.loss_policies.find((p) => p.policy === profile.loss_policy);
  if (policy.omitted_source_fields === 'absent_or_empty' && omissions.length !== 0) invalid = true;
  if (policy.omitted_source_fields === 'non_empty' && omissions.length === 0) invalid = true;
  if (invalid) out.push('invalid_mapping_profile');
  const resolved = reference.resolve(profile.target_action_type, definitions);
  if (resolved.reason) out.push(resolved.reason);
  else {
    const targets = new Set(profile.rules.map((r) => r.target_field));
    for (const f of resolved.definition.required_fields) if (!targets.has(f.name)) out.push(`unmapped_material_field:${f.name}`);
  }
  return out;
}

function atPointer(value, pointer) {
  const segments = pointer.slice(1).split('/').map((s) => s.replaceAll('~1', '/').replaceAll('~0', '~'));
  let current = value;
  for (const seg of segments) {
    if (Array.isArray(current)) {
      if (!patterns.array_index.test(seg)) return { reason: 'invalid_source_path' };
      const i = Number(seg);
      if (!Number.isSafeInteger(i) || i >= current.length) return { reason: 'missing_source_field' };
      current = current[i];
    } else if (isObject(current)) {
      if (!own(current, seg)) return { reason: 'missing_source_field' };
      current = current[seg];
    } else return { reason: 'missing_source_field' };
  }
  return { value: current };
}

function transform(value, name) {
  if (name === 'copy') {
    const c = canonical(value);
    return c === null ? { reason: 'source_value_not_canonicalizable' } : { value: JSON.parse(c) };
  }
  if (name === 'sha256-utf8') return typeof value === 'string' && cleanString(value) ? { value: `sha256:${hex(Buffer.from(value, 'utf8'))}` } : { reason: 'source_value_type_mismatch' };
  if (name === 'sha256-jcs') {
    const c = canonical(value);
    return c === null ? { reason: 'source_value_not_canonicalizable' } : { value: `sha256:${hex(Buffer.from(c, 'utf8'))}` };
  }
  if (name === 'sha256-hex-to-digest') return typeof value === 'string' && patterns.hex_sha256.test(value) ? { value: `sha256:${value}` } : { reason: 'source_value_type_mismatch' };
  return { reason: 'unknown_transform' };
}

/**
 * @param {any} source
 * @param {{profile?: any, sourceDescriptor?: any, expectedProfileHash?: any, nativeVerified?: any,
 *          definitions?: any, enumSnapshots?: any, suite?: any, suitePresent?: boolean}} p
 */
export function mapAction(source, p) {
  const profile = p.profile;
  const reasons = stageA(profile, p.definitions);
  if (p.nativeVerified !== true) reasons.push('native_verification_required');
  const profileHash = hashJson(profile);
  if (typeof p.expectedProfileHash !== 'string' || p.expectedProfileHash !== profileHash) reasons.push('mapping_profile_unpinned');
  const sf = isObject(profile) ? profile.source_format : undefined;
  const dc = isObject(p.sourceDescriptor) ? canonical(p.sourceDescriptor) : null;
  const pc = sf === undefined ? null : canonical(sf);
  if (dc === null || pc === null || dc !== pc) reasons.push('source_format_mismatch');
  if (!isObject(source)) reasons.push('source_not_object');
  const sourceDigest = isObject(source) ? hashJson(source) : null;
  if (!sourceDigest) reasons.push('source_not_canonicalizable');
  if (isObject(profile) && profile.loss_policy === 'declared-source-semantic-loss') reasons.push('declared_source_semantic_loss');
  const dedupe = (xs) => [...new Set(xs)];
  if (reasons.length) return { ok: false, reasons: dedupe(reasons), profile_hash: profileHash, source_digest: sourceDigest };
  const action = { action_type: profile.target_action_type };
  const c = [];
  for (const rule of profile.rules) {
    const found = atPointer(source, rule.source_path);
    if (found.reason) { c.push(`${found.reason}:${rule.source_path}`); continue; }
    const t = transform(found.value, rule.transform);
    if (t.reason) { c.push(`${t.reason}:${rule.source_path}`); continue; }
    Object.defineProperty(action, rule.target_field, { value: t.value, enumerable: true, writable: true, configurable: true });
  }
  if (c.length) return { ok: false, reasons: c, profile_hash: profileHash, source_digest: sourceDigest };
  const suite = p.suitePresent === false || p.suite === undefined ? 'jcs-sha256' : p.suite;
  const computed = oracle.compute(action, { suite, definitions: p.definitions, enum_snapshots: p.enumSnapshots });
  if (!computed.caid) return { ok: false, reasons: (computed.refusals || []).map((r) => `mapped_action:${r}`), profile_hash: profileHash, source_digest: sourceDigest };
  return { ok: true, action, caid: computed.caid, digest: computed.digest, suite, profile_hash: profileHash, source_digest: sourceDigest };
}

/**
 * @param {any} left
 * @param {any} right
 * @param {{definitions?: any, enumSnapshots?: any, suite?: any}} [options]
 */
export function compareMappedActions(left, right, { definitions, enumSnapshots, suite } = {}) {
  const side = (s) => mapAction(s?.source, {
    profile: s?.profile, sourceDescriptor: s?.source_descriptor, expectedProfileHash: s?.expected_profile_hash,
    nativeVerified: s?.native_verified, definitions, enumSnapshots, suite,
  });
  /** @type {any} */
  const l = side(left);
  /** @type {any} */
  const r = side(right);
  if (!l.ok || !r.ok) {
    return { verdict: 'INDETERMINATE', reasons: [...(l.ok ? [] : l.reasons.map((x) => `left:${x}`)), ...(r.ok ? [] : r.reasons.map((x) => `right:${x}`))], left: l, right: r };
  }
  if (l.action.action_type !== r.action.action_type) return { verdict: 'INDETERMINATE', reasons: ['target_action_type_mismatch'], left: l, right: r };
  return l.caid === r.caid
    ? { verdict: 'EQUIVALENT_UNDER_PROFILE', reasons: [], left: l, right: r }
    : { verdict: 'NOT_EQUIVALENT', reasons: ['material_projection_mismatch'], left: l, right: r };
}
