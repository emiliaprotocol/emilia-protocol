// SPDX-License-Identifier: Apache-2.0
//
// A dev-time reference validator for CAID computation over data-model
// values, built only from the generated spec data (caid/spec/gen.mjs
// buildSpec): the compiled grammar, the code formats, the limits, the field
// types, the definition rules and the reason ranks. The registry check
// (caid/registry/check.mjs) and the registry tests use it to prove that
// every registered type computes before the ports adopt the -04 features.
//
// It is not a port and ships in no package. It takes already-decoded
// values (no JSON text decoder) and refuses, never throws.

import { createHash } from 'node:crypto';

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const hasLoneSurrogate = (s) => /\p{Cs}/u.test(s);

/**
 * @param {ReturnType<typeof import('./gen.mjs').buildSpec>} spec
 */
export function createReference(spec) {
  const patterns = Object.fromEntries(Object.entries(spec.patterns).map(([k, v]) => [k, new RegExp(`^(?:${v})$`)]));
  const codeFormats = Object.fromEntries(Object.entries(spec.code_formats).map(([k, v]) => [k, new RegExp(`^(?:${v})$`)]));
  const types = Object.fromEntries(spec.field_types.map((t) => [t.type, t]));
  const def = spec.definition;
  const limits = spec.limits;
  const supported = new Set(['jcs-sha256']);

  function kind(v) {
    if (v === null) return 'null';
    if (typeof v === 'boolean') return 'boolean';
    if (typeof v === 'number') return 'number';
    if (typeof v === 'string') return 'string';
    if (Array.isArray(v)) return 'array';
    if (isPlainObject(v)) return 'object';
    return null;
  }

  // RFC 8785 over the data model: integers of magnitude <= 2^53-1 only,
  // scalar-value strings, plain objects and dense arrays, depth <= 64,
  // output <= canonical_octets.
  /** @returns {{ok: true, canonical: string} | {ok: false, refusals: string[]}} */
  function canonicalize(value) {
    let number = false;
    let other = false;
    const out = (v, depth) => {
      const k = kind(v);
      if (k === 'null') return 'null';
      if (k === 'boolean') return v ? 'true' : 'false';
      if (k === 'number') {
        if (!Number.isFinite(v) || !Number.isInteger(v) || Math.abs(v) > limits.max_safe_integer) { number = true; return '0'; }
        return JSON.stringify(v === 0 ? 0 : v);
      }
      if (k === 'string') {
        if (hasLoneSurrogate(v)) { other = true; return '""'; }
        return JSON.stringify(v);
      }
      if (k === 'array' || k === 'object') {
        if (depth + 1 > limits.nesting_depth) { other = true; return 'null'; }
        if (k === 'array') return `[${v.map((x) => out(x, depth + 1)).join(',')}]`;
        return `{${Object.keys(v).sort().map((key) => {
          if (hasLoneSurrogate(key)) other = true;
          return `${JSON.stringify(key)}:${out(v[key], depth + 1)}`;
        }).join(',')}}`;
      }
      other = true;
      return 'null';
    };
    const canonical = out(value, 0);
    if (!number && !other && Buffer.byteLength(canonical, 'utf8') > limits.canonical_octets) other = true;
    if (number || other) return { ok: false, refusals: [...(number ? ['unsupported_number'] : []), ...(other ? ['unsupported_value'] : [])] };
    return { ok: true, canonical };
  }

  const sha256Hex = (s) => createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');

  function validFieldName(name) {
    if (typeof name !== 'string' || name.length < def.field_name.min_length || hasLoneSurrogate(name)) return false;
    if ([...name].some((c) => def.field_name.forbidden_code_points.includes(c.codePointAt(0)))) return false;
    return !def.field_name.reserved.includes(name);
  }

  /** The validation projection, or null when the definition has no field lists. */
  function projection(d) {
    const lists = {};
    for (const list of def.field_lists) {
      const raw = own(d, list) ? d[list] : def.projection.defaults[list];
      if (!Array.isArray(raw)) return null;
      lists[list] = raw.map((entry) => (isPlainObject(entry)
        ? Object.fromEntries(Object.entries(entry).filter(([k]) => !def.projection.field_members_excluded.includes(k)))
        : entry));
    }
    return { action_type: d.action_type, ...lists };
  }

  /** definition_sha256 of a definition, or null when it has none. */
  function definitionSha256(d) {
    if (!isPlainObject(d)) return null;
    const p = projection(d);
    if (!p) return null;
    const c = canonicalize(p);
    return c.ok ? def.projection.prefix + sha256Hex(c.canonical) : null;
  }

  /** Definition conformance; returns a list of problems (empty when it conforms). */
  function conformance(d) {
    const problems = [];
    if (!isPlainObject(d)) return ['not an object'];
    if (typeof d.action_type !== 'string' || !patterns.action_type.test(d.action_type)) problems.push('action_type');
    if (!Array.isArray(d.required_fields) || d.required_fields.length < def.required_fields_min) problems.push('required_fields');
    if (own(d, 'optional_fields') && !Array.isArray(d.optional_fields)) problems.push('optional_fields');
    const names = new Set();
    for (const list of def.field_lists) {
      const entries = Array.isArray(d[list]) ? d[list] : [];
      entries.forEach((entry, i) => {
        const where = `${list}[${i}]`;
        if (!isPlainObject(entry)) { problems.push(`${where} is not an object`); return; }
        if (!validFieldName(entry.name)) problems.push(`${where}.name`);
        else if (names.has(entry.name)) problems.push(`${where}.name repeats`);
        else names.add(entry.name);
        if (typeof entry.type !== 'string') { problems.push(`${where}.type`); return; }
        const t = types[entry.type];
        if (!t) return;
        const allowed = new Set([...def.field_common_members, ...t.members]);
        for (const k of Object.keys(entry)) if (!allowed.has(k)) problems.push(`${where}.${k} is not a ${entry.type} member`);
        for (const [member, pattern] of Object.entries(t.required_members)) {
          if (typeof entry[member] !== 'string' || !patterns[pattern].test(entry[member])) problems.push(`${where}.${member}`);
        }
      });
    }
    if (!problems.length && definitionSha256(d) === null) problems.push('projection is outside the data model');
    return problems;
  }

  function resolve(actionType, definitions) {
    const candidates = Array.isArray(definitions)
      ? definitions.filter((d) => isPlainObject(d) && d.action_type === actionType) : [];
    if (!candidates.length) return { reason: 'unknown_action_type' };
    if (candidates.some((d) => conformance(d).length)) return { reason: 'invalid_definition' };
    const digests = new Set(candidates.map(definitionSha256));
    if (digests.size !== 1) return { reason: 'invalid_definition' };
    return { definition: candidates[0], definition_sha256: [...digests][0] };
  }

  function validEnumValues(values) {
    return Array.isArray(values) && values.length > 0
      && values.every((v) => typeof v === 'string' && v.length > 0) && new Set(values).size === values.length;
  }

  function resolveEnum(field, snapshots) {
    const hasRef = own(field, 'values_ref');
    const hasValues = own(field, 'values');
    const ref = hasRef ? field.values_ref : undefined;
    let declared = hasValues ? field.values : undefined;
    if (typeof ref === 'string' && ref.startsWith(spec.enum.inline_prefix)) {
      const trim = new Set(spec.enum.inline_trim);
      const values = ref.slice(spec.enum.inline_prefix.length).split(spec.enum.inline_separator).map((m) => {
        let a = 0;
        let b = m.length;
        while (a < b && trim.has(m[a])) a += 1;
        while (b > a && trim.has(m[b - 1])) b -= 1;
        return m.slice(a, b);
      });
      if (!validEnumValues(values)) return null;
      if (hasValues && !(Array.isArray(declared) && declared.length === values.length && declared.every((v, i) => v === values[i]))) return null;
      return values;
    }
    if (!hasRef) return validEnumValues(declared) ? declared : null;
    if (typeof ref !== 'string' || !ref.length || typeof field.values_snapshot !== 'string' || !field.values_snapshot.length
        || typeof field.values_sha256 !== 'string' || !patterns.digest_field.test(field.values_sha256)) return null;
    if (!hasValues && Array.isArray(snapshots)) {
      declared = snapshots.find((s) => isPlainObject(s) && s.values_ref === ref
        && s.values_snapshot === field.values_snapshot && s.values_sha256 === field.values_sha256)?.values;
    }
    if (!validEnumValues(declared)) return null;
    const c = canonicalize(declared);
    return c.ok && `sha256:${sha256Hex(c.canonical)}` === field.values_sha256 ? declared : null;
  }

  const daysInMonth = (y, m) => (m === 2 ? ((y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28) : [4, 6, 9, 11].includes(m) ? 30 : 31);

  function checkField(value, field, snapshots) {
    const t = types[field.type];
    if (!t) return 'mistyped_field';
    const k = kind(value);
    if (t.json === 'number') return k === 'number' && Number.isInteger(value) ? null : 'mistyped_field';
    if (k !== t.json) return 'mistyped_field';
    if (t.type === 'enum') return resolveEnum(field, snapshots)?.includes(value) ? null : 'mistyped_field';
    if (t.type === 'code') {
      const matcher = codeFormats[field.format];
      if (!matcher) return t.unregistered_format_refusal;
      return matcher.test(value) ? null : t.format_refusal;
    }
    if (t.pattern) {
      if (!patterns[t.pattern].test(value)) return t.pattern_refusal;
      if (t.calendar_check === 'day_within_month') {
        const o = spec.timestamp_date_offsets;
        const n = (r) => Number(value.slice(r[0], r[1]));
        if (n(o.day) > daysInMonth(n(o.year), n(o.month))) return t.pattern_refusal;
      }
    }
    return null;
  }

  // Runs the compute phases after the entry gate and returns the ordered,
  // deduplicated reasons, the resolved definition and the canonical text.
  // With checkSuite false the suite phase is skipped: verification checks
  // the suite of the CAID it is given instead.
  /**
   * @param {any} object
   * @param {{definitions?: any, enumSnapshots?: any, suite?: any, checkSuite?: boolean}} options
   * @returns {{refusals: string[], resolved?: any, canonical?: string | null}}
   */
  function evaluate(object, { definitions, enumSnapshots, suite, checkSuite = true }) {
    if (!isPlainObject(object) || typeof object.action_type !== 'string' || !patterns.action_type.test(object.action_type)) {
      return { refusals: ['invalid_action_type'] };
    }
    const resolved = resolve(object.action_type, definitions);
    if (resolved.reason) return { refusals: [resolved.reason] };
    const d = resolved.definition;
    const found = [];
    const required = d.required_fields;
    const all = [...required, ...(d.optional_fields ?? [])];
    const present = (name) => own(object, name) && object[name] !== undefined;
    required.forEach((f, i) => { if (!present(f.name)) found.push([spec.sort_rank.compute.missing_material_field, i, `missing_material_field:${f.name}`]); });
    all.forEach((f, i) => {
      if (!present(f.name)) return;
      const r = checkField(object[f.name], f, enumSnapshots);
      if (r) found.push([spec.sort_rank.compute[r], i, `${r}:${f.name}`]);
    });
    if (checkSuite && !(typeof suite === 'string' && supported.has(suite))) found.push([spec.sort_rank.compute.unknown_suite, 0, 'unknown_suite']);
    const c = canonicalize(object);
    if (!c.ok) for (const r of c.refusals) found.push([spec.sort_rank.compute[r], 0, r]);
    found.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    return { refusals: [...new Set(found.map((f) => f[2]))], resolved, canonical: c.ok ? c.canonical : null };
  }

  /**
   * Computes over a data-model value. Returns {caid, digest,
   * definition_sha256} or {refusals} in the -04 reason order.
   */
  function compute(object, options) {
    const opts = isPlainObject(options) ? options : {};
    const suite = typeof opts.suite === 'string' ? opts.suite : undefined;
    const r = evaluate(object, { definitions: opts.definitions, enumSnapshots: opts.enumSnapshots, suite });
    if (r.refusals.length) return { refusals: r.refusals };
    const bytes = createHash('sha256').update(Buffer.from(/** @type {string} */ (r.canonical), 'utf8')).digest();
    return {
      caid: `caid:1:${object.action_type}:${suite}:${bytes.toString('base64url')}`,
      digest: `sha256:${bytes.toString('hex')}`,
      definition_sha256: /** @type {any} */ (r.resolved).definition_sha256,
    };
  }

  /**
   * Strict parse: {ok, caid} or {ok: false, refusals: [one reason]}.
   * @returns {{ok: true, caid: {version: string, action_type: string, suite: string, digest: string}} | {ok: false, refusals: string[]}}
   */
  function parse(input) {
    if (typeof input !== 'string' || !patterns.caid.test(input)) return { ok: false, refusals: ['malformed_caid'] };
    const [, version, actionType, suite, digest] = input.split(':');
    const s = spec.suites.find((x) => x.suite === suite);
    if (!s) return { ok: false, refusals: ['unknown_suite'] };
    if (!new RegExp(`^(?:${s.digest_pattern})$`).test(digest)) return { ok: false, refusals: ['malformed_caid'] };
    return { ok: true, caid: { version, action_type: actionType, suite, digest } };
  }

  // The kind a detail observes: "absent" for a missing own member,
  // "unsupported" for a host value outside the data model.
  const observedKind = (v) => (v === undefined ? 'absent' : kind(v) ?? 'unsupported');

  function detail(reason, value, caidArgument) {
    const colon = reason.indexOf(':');
    const code = colon < 0 ? reason : reason.slice(0, colon);
    const d = spec.verify_details.reasons[code];
    const field = d.field === 'param' ? reason.slice(colon + 1) : d.field;
    let observed = null;
    if (d.observed === 'argument') observed = observedKind(caidArgument);
    else if (d.observed === 'member') {
      observed = isPlainObject(value) ? observedKind(own(value, field) ? value[field] : undefined) : observedKind(value);
    }
    return { reason, field, rule: d.rule, observed };
  }

  /**
   * Verifies a data-model value against a CAID string. Returns {valid,
   * reasons, details} plus definition_sha256 whenever a conforming
   * definition resolved.
   */
  function verify(object, caidString, options) {
    const opts = isPlainObject(options) ? options : {};
    const expected = typeof opts.expectedDefinitionSha256 === 'string' ? opts.expectedDefinitionSha256 : undefined;
    const parsed = parse(caidString);
    if (!parsed.ok) return { valid: false, reasons: parsed.refusals, details: parsed.refusals.map((r) => detail(r, object, caidString)) };
    const expand = spec.verify_details.expand.invalid_object;
    const run = () => evaluate(object, { definitions: opts.definitions, enumSnapshots: opts.enumSnapshots, checkSuite: !expand.omit.includes('unknown_suite') });
    if (!isPlainObject(object)) {
      const r = run();
      return { valid: false, reasons: ['invalid_object'], details: r.refusals.map((x) => detail(x, object, caidString)) };
    }
    const reasons = [];
    const details = [];
    const add = (r) => { reasons.push(r); details.push(detail(r, object, caidString)); };
    if (object.action_type !== parsed.caid.action_type) add('action_type_mismatch');
    const r = run();
    const definitionSha256 = r.resolved && !r.resolved.reason ? r.resolved.definition_sha256 : undefined;
    if (expected !== undefined && definitionSha256 !== undefined && expected !== definitionSha256) add('definition_mismatch');
    const c = canonicalize(object);
    if (!supported.has(parsed.caid.suite)) add('unknown_suite');
    else if (c.ok && createHash('sha256').update(Buffer.from(c.canonical, 'utf8')).digest('base64url') !== parsed.caid.digest) add('digest_mismatch');
    if (r.refusals.length) {
      reasons.push('invalid_object');
      for (const x of r.refusals) details.push(detail(x, object, caidString));
    }
    const out = { valid: reasons.length === 0, reasons, details };
    if (definitionSha256 !== undefined) out.definition_sha256 = definitionSha256;
    return out;
  }

  return { canonicalize, projection, definitionSha256, conformance, resolve, checkField, compute, parse, verify, kind };
}
