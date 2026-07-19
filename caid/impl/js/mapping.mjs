// SPDX-License-Identifier: Apache-2.0
// CAID Action-Mapping Profile v1.
//
// A mapping result is a content-correlation result, not authorization.
// The caller pins the exact mapping profile hash and source descriptor.
// Missing fields, unrecognized transforms, or an unpinned profile yield
// INDETERMINATE. No mapping failure is converted into equivalence.

import { createHash } from 'node:crypto';
import { canonicalize, computeCaid } from './caid.mjs';

export const MAPPING_PROFILE_VERSION = 'CAID-MAPPING-PROFILE-v1';
export const MAPPING_VERDICTS = Object.freeze({
  equivalent: 'EQUIVALENT_UNDER_PROFILE',
  different: 'NOT_EQUIVALENT',
  indeterminate: 'INDETERMINATE',
});

const FIELD_RE = /^[a-z][a-z0-9_]*$/;
const TRANSFORMS = new Set(['copy', 'sha256-utf8', 'sha256-jcs']);
const PROFILE_KEYS = new Set([
  '@version', 'profile_id', 'source_format', 'target_action_type',
  'loss_policy', 'material_source_paths', 'rules',
]);
const SOURCE_FORMAT_KEYS = new Set(['media_type', 'schema', 'version']);
const RULE_KEYS = new Set(['source_path', 'target_field', 'transform']);
const MAX_RULES = 128;
const MAX_POINTER_BYTES = 2048;
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

function hasOnlyKeys(value, allowed) {
  return isObject(value) && Object.keys(value).every((key) => allowed.has(key));
}

function hashJson(value) {
  const result = canonicalize(value);
  if (!result.ok) return null;
  return 'sha256:' + digest(Buffer.from(result.canonical, 'utf8'));
}

function validString(value, max = 512) {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function validPointer(pointer) {
  if (typeof pointer !== 'string' || pointer.length === 0
      || Buffer.byteLength(pointer, 'utf8') > MAX_POINTER_BYTES
      || pointer[0] !== '/') return false;
  return pointer.slice(1).split('/').every((segment) => !/~(?![01])/u.test(segment));
}

function pointerSegments(pointer) {
  if (!validPointer(pointer)) return null;
  return pointer.slice(1).split('/').map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'));
}

function atPointer(value, pointer) {
  const segments = pointerSegments(pointer);
  if (!segments) return { found: false, reason: 'invalid_source_path' };
  let current = value;
  for (const segment of segments) {
    if (Array.isArray(current)) {
      if (!/^(0|[1-9][0-9]*)$/.test(segment)) return { found: false, reason: 'invalid_source_path' };
      const index = Number(segment);
      if (!Number.isSafeInteger(index) || index >= current.length) return { found: false, reason: 'missing_source_field' };
      current = current[index];
    } else if (isObject(current)) {
      if (!own(current, segment)) return { found: false, reason: 'missing_source_field' };
      current = current[segment];
    } else {
      return { found: false, reason: 'missing_source_field' };
    }
  }
  return { found: true, value: current };
}

function descriptorEqual(left, right) {
  const a = canonicalize(left);
  const b = canonicalize(right);
  return a.ok && b.ok && a.canonical === b.canonical;
}

function validateProfile(profile, definitions) {
  const reasons = [];
  if (!isObject(profile) || profile['@version'] !== MAPPING_PROFILE_VERSION
      || !hasOnlyKeys(profile, PROFILE_KEYS)) {
    return ['invalid_mapping_profile'];
  }
  if (!validString(profile.profile_id) || !hasOnlyKeys(profile.source_format, SOURCE_FORMAT_KEYS)
      || !validString(profile.source_format.media_type)
      || !validString(profile.source_format.schema)
      || !validString(profile.source_format.version)
      || !validString(profile.target_action_type)
      || profile.loss_policy !== 'no-material-field-loss'
      || !Array.isArray(profile.rules) || profile.rules.length === 0
      || profile.rules.length > MAX_RULES
      || !Array.isArray(profile.material_source_paths)
      || profile.material_source_paths.length === 0) {
    return ['invalid_mapping_profile'];
  }

  const targets = new Set();
  const ruleSources = [];
  for (const rule of profile.rules) {
    if (!hasOnlyKeys(rule, RULE_KEYS) || !validPointer(rule.source_path)
        || !FIELD_RE.test(rule.target_field)
        || rule.target_field === 'action_type'
        || !TRANSFORMS.has(rule.transform)
        || targets.has(rule.target_field)) {
      reasons.push('invalid_mapping_profile');
      break;
    }
    targets.add(rule.target_field);
    ruleSources.push(rule.source_path);
  }

  const material = profile.material_source_paths;
  if (new Set(material).size !== material.length
      || material.some((path) => !validPointer(path))
      || [...new Set(ruleSources)].sort().join('\n') !== [...material].sort().join('\n')) {
    reasons.push('invalid_mapping_profile');
  }

  const definition = Array.isArray(definitions)
    ? definitions.find((entry) => isObject(entry) && entry.action_type === profile.target_action_type)
    : null;
  if (!definition) {
    reasons.push('unknown_action_type');
  } else {
    const required = Array.isArray(definition.required_fields) ? definition.required_fields : [];
    for (const field of required) {
      if (!isObject(field) || !FIELD_RE.test(field.name) || !targets.has(field.name)) {
        const name = isObject(field) && typeof field.name === 'string' ? field.name : '?';
        reasons.push('unmapped_material_field:' + name);
      }
    }
  }
  return [...new Set(reasons)];
}

function applyTransform(value, transform) {
  if (transform === 'copy') {
    const canonical = canonicalize(value);
    if (!canonical.ok) return { ok: false, reason: 'source_value_not_canonicalizable' };
    return { ok: true, value: JSON.parse(canonical.canonical) };
  }
  if (transform === 'sha256-utf8') {
    if (typeof value !== 'string') return { ok: false, reason: 'source_value_type_mismatch' };
    return { ok: true, value: 'sha256:' + digest(Buffer.from(value, 'utf8')) };
  }
  if (transform === 'sha256-jcs') {
    const canonical = canonicalize(value);
    if (!canonical.ok) return { ok: false, reason: 'source_value_not_canonicalizable' };
    return { ok: true, value: 'sha256:' + digest(Buffer.from(canonical.canonical, 'utf8')) };
  }
  return { ok: false, reason: 'unknown_transform' };
}

export function mappingProfileHash(profile) {
  return hashJson(profile);
}

/**
 * @param {any} source
 * @param {Object} [params]
 * @param {object} [params.profile]
 * @param {object} [params.sourceDescriptor]
 * @param {string} [params.expectedProfileHash]
 * @param {boolean} [params.nativeVerified]
 * @param {any[]} [params.definitions]
 * @param {string} [params.suite]
 */
export function mapAction(source, {
  profile,
  sourceDescriptor,
  expectedProfileHash,
  nativeVerified = false,
  definitions,
  suite = 'jcs-sha256',
} = {}) {
  try {
    const reasons = validateProfile(profile, definitions);
    if (nativeVerified !== true) reasons.push('native_verification_required');
    const profileHash = mappingProfileHash(profile);
    if (!profileHash) reasons.push('invalid_mapping_profile');
    if (typeof expectedProfileHash !== 'string' || expectedProfileHash !== profileHash) {
      reasons.push('mapping_profile_unpinned');
    }
    if (!isObject(sourceDescriptor) || !descriptorEqual(sourceDescriptor, profile?.source_format)) {
      reasons.push('source_format_mismatch');
    }
    if (!isObject(source)) reasons.push('source_not_object');
    const sourceDigest = isObject(source) ? hashJson(source) : null;
    if (!sourceDigest) reasons.push('source_not_canonicalizable');
    if (reasons.length) {
      return { ok: false, reasons: [...new Set(reasons)], profile_hash: profileHash, source_digest: sourceDigest };
    }

    const action = { action_type: profile.target_action_type };
    for (const rule of profile.rules) {
      const found = atPointer(source, rule.source_path);
      if (!found.found) {
        reasons.push(found.reason + ':' + rule.source_path);
        continue;
      }
      const transformed = applyTransform(found.value, rule.transform);
      if (!transformed.ok) {
        reasons.push(transformed.reason + ':' + rule.source_path);
        continue;
      }
      action[rule.target_field] = transformed.value;
    }
    if (reasons.length) {
      return { ok: false, reasons, profile_hash: profileHash, source_digest: sourceDigest };
    }

    const computed = computeCaid(action, { suite, definitions });
    if (!computed.caid) {
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
 * @param {Object} [params]
 * @param {any[]} [params.definitions]
 * @param {string} [params.suite]
 */
export function compareMappedActions(left, right, { definitions, suite = 'jcs-sha256' } = {}) {
  const mapOne = (side) => mapAction(side?.source, {
    profile: side?.profile,
    sourceDescriptor: side?.source_descriptor,
    expectedProfileHash: side?.expected_profile_hash,
    nativeVerified: side?.native_verified,
    definitions,
    suite,
  });
  const l = mapOne(left);
  const r = mapOne(right);
  if (!l.ok || !r.ok) {
    return {
      verdict: MAPPING_VERDICTS.indeterminate,
      reasons: [
        ...(!l.ok ? l.reasons.map((reason) => 'left:' + reason) : []),
        ...(!r.ok ? r.reasons.map((reason) => 'right:' + reason) : []),
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
