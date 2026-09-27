#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Registry check for caid/registry: the invariants every registry version
// must hold, the v4-to-v5 migration rules, and digests.json.
//
//   node caid/registry/check.mjs                  check; exit 1 on any failure
//   node caid/registry/check.mjs --write-digests  regenerate digests.json first
//   node caid/registry/check.mjs --require-port   also require caid/impl/js to
//                                                 compute every active type
//
// It proves, among other things, that every active type computes: for each
// one it builds an object from the definition and runs the code-aware
// reference validator (caid/spec/reference.mjs), which follows the -04
// rules and the generated spec data. Types without a code field must also
// compute to the same CAID under caid/impl/js. A type with a code field is
// reported as pending in the JS port until that port implements code
// fields; --require-port turns pending into a failure.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { matches, prng, sample } from '../spec/abnf.mjs';
import { buildSpec, loadCaidGrammar } from '../spec/gen.mjs';
import { createReference } from '../spec/reference.mjs';
import { computeCaid } from '../impl/js/caid.mjs';
import { loadRegistryEnumSnapshots } from './enum-snapshots.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const HISTORY_V4 = { path: 'history/action-types.v4.json', sha256: 'sha256:73a31f4a4156e3de02e1c3a9ef355f73c07ba25e6b1bb3da8fde8677c2e23d26' };
const LICENSED_SYSTEM_WORDS = /\b(cpt|hcpcs|icd|ndc|nacha|sec code|20022)\b/i;

const argv = new Set(process.argv.slice(2));
const failures = [];
const fail = (msg) => failures.push(msg);
const pass = (msg) => console.log(`PASS ${msg}`);

const sha = (buf) => 'sha256:' + createHash('sha256').update(buf).digest('hex');
const spec = buildSpec(ROOT);
const { rules } = loadCaidGrammar(ROOT);
const ref = createReference(spec);
const jcs = (value) => {
  const c = ref.canonicalize(value);
  if (!c.ok) throw new Error('not canonicalizable');
  return sha(Buffer.from(c.canonical, 'utf8'));
};

const registryBytes = readFileSync(path.join(HERE, 'action-types.json'));
const registry = JSON.parse(registryBytes.toString('utf8'));
const v4Bytes = readFileSync(path.join(HERE, HISTORY_V4.path));
const v4 = JSON.parse(v4Bytes.toString('utf8'));
const types = registry.types;
const byName = new Map(types.map((t) => [t.action_type, t]));
const fieldsOf = (t) => [...(t.required_fields ?? []), ...(t.optional_fields ?? [])];
const typeData = Object.fromEntries(spec.field_types.map((t) => [t.type, t]));
const def = spec.definition;

// 1. History and version.
if (sha(v4Bytes) !== HISTORY_V4.sha256) fail(`${HISTORY_V4.path} is ${sha(v4Bytes)}, not the frozen ${HISTORY_V4.sha256}`);
if (v4.meta?.registry_version !== 4) fail(`${HISTORY_V4.path} is not registry version 4`);
if (registry.meta?.registry_version !== 5) fail('action-types.json is not registry version 5');
if (!failures.length) pass(`registry history: ${HISTORY_V4.path} is byte-identical to published v4 (${HISTORY_V4.sha256.slice(0, 15)}...)`);

// 2. Shape: unique names, conforming and closed-shape entries.
const names = types.map((t) => t.action_type);
if (new Set(names).size !== names.length) fail('duplicate action type in the registry');
let conforming = 0;
for (const t of types) {
  const problems = ref.conformance(t);
  if (problems.length) fail(`${t.action_type} does not conform: ${problems.join('; ')}`);
  else conforming += 1;
  for (const key of Object.keys(t)) if (!def.registry_entry_members.includes(key)) fail(`${t.action_type} has entry member ${key} outside the closed registry shape`);
  if (!def.status_values.includes(t.status)) fail(`${t.action_type} has status ${t.status}`);
  for (const f of fieldsOf(t)) {
    const data = typeData[f.type];
    if (!data) { fail(`${t.action_type}.${f.name} has unregistered field type ${f.type}`); continue; }
    for (const key of Object.keys(f)) if (![...def.field_common_members, ...data.members].includes(key)) fail(`${t.action_type}.${f.name} has member ${key}`);
    if ('notes' in f && typeof f.notes !== 'string') fail(`${t.action_type}.${f.name} notes is not a string`);
  }
}
pass(`registry shape: ${types.length} unique types, ${conforming} conform to the definition rules and the closed registry shape`);

// 2b. Definition conformance closes the fail-open: each malformed
//     definition, and conflicting duplicates, refuse as invalid_definition;
//     duplicates with equal projections (notes may differ) count once.
{
  const good = { action_type: 'acme.wire.1', required_fields: [{ name: 'amount', type: 'amount-string' }] };
  const object = { action_type: 'acme.wire.1', amount: '1.00' };
  const malformed = [
    { action_type: 'acme.wire.1', required_field: good.required_fields },
    { action_type: 'acme.wire.1', required_fields: 'amount' },
    { action_type: 'acme.wire.1', required_fields: ['amount'] },
    { action_type: 'acme.wire.1', required_fields: [{ nmae: 'amount', type: 'amount-string' }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 7, type: 'amount-string' }] },
    { action_type: 'acme.wire.1', required_fields: [] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'a:b', type: 'string' }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: '', type: 'string' }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'action_type', type: 'string' }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'amount', type: 'amount-string' }], optional_fields: [{ name: 'amount', type: 'string' }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'amount', type: 'amount-string' }], optional_fields: {} },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'amount', type: 7 }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'amount', type: 'amount-string', values: ['x'] }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'amount', type: 'code', format: 'nacha-sec' }] },
    { action_type: 'acme.wire.1', required_fields: [{ name: 'amount', type: 'code', code_system: 'not a uri', format: 'nacha-sec' }] },
  ];
  let refused = 0;
  for (const d of malformed) {
    const got = ref.compute(object, { suite: 'jcs-sha256', definitions: [d] });
    if (JSON.stringify(got.refusals) !== '["invalid_definition"]') fail(`malformed definition ${JSON.stringify(d)} gives ${JSON.stringify(got)}`);
    else refused += 1;
  }
  const conflicting = { ...good, required_fields: [{ name: 'amount', type: 'string' }] };
  for (const defs of [[good, conflicting], [conflicting, good]]) {
    const got = ref.compute(object, { suite: 'jcs-sha256', definitions: defs });
    if (JSON.stringify(got.refusals) !== '["invalid_definition"]') fail(`conflicting duplicate definitions give ${JSON.stringify(got)}`);
  }
  const annotated = { ...good, summary: 'x', required_fields: [{ name: 'amount', type: 'amount-string', notes: 'other notes' }] };
  const once = ref.compute(object, { suite: 'jcs-sha256', definitions: [good, annotated] });
  if (!once.caid || once.definition_sha256 !== ref.definitionSha256(good)) fail(`equal-projection duplicates do not resolve once: ${JSON.stringify(once)}`);
  const unknownType = { ...good, required_fields: [{ name: 'amount', type: 'future-type', future_member: 1 }] };
  const forward = ref.compute({ action_type: 'acme.wire.1' }, { suite: 'jcs-sha256', definitions: [{ ...unknownType, required_fields: [{ name: 'x', type: 'string' }], optional_fields: unknownType.required_fields }] });
  if (JSON.stringify(forward.refusals) !== '["missing_material_field:x"]') fail(`an unrecognized optional field type must not make the definition nonconforming: ${JSON.stringify(forward)}`);
  pass(`definition conformance: ${refused} malformed definitions and conflicting duplicates refuse as invalid_definition; equal projections resolve once`);
}

// 3. Code fields: registered format, recorded code system, no snapshot of
//    a code system.
const codeSystems = new Map((registry.code_systems ?? []).map((c) => [c.code_system, c]));
let codeFields = 0;
for (const c of registry.code_systems ?? []) {
  if (!new RegExp(`^(?:${spec.patterns.code_system})$`).test(c.code_system)) fail(`code_systems ${c.code_system} does not match the code-system rule`);
  for (const f of c.formats ?? []) if (!(f in spec.code_formats)) fail(`code_systems ${c.code_system} lists unregistered format ${f}`);
  for (const key of ['title', 'authority', 'license_note']) if (typeof c[key] !== 'string' || !c[key]) fail(`code_systems ${c.code_system} has no ${key}`);
  const sources = [c.identifier_source, ...(c.syntax_sources ?? [])];
  if (!sources.length || sources.some((s) => typeof s?.url !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s?.retrieved ?? ''))) fail(`code_systems ${c.code_system} has a source without url and retrieval date`);
}
for (const t of types) {
  for (const f of fieldsOf(t)) {
    if (f.type !== 'code') continue;
    codeFields += 1;
    const system = codeSystems.get(f.code_system);
    if (!system) fail(`${t.action_type}.${f.name} names code system ${f.code_system}, which code_systems does not record`);
    else if (!system.formats.includes(f.format)) fail(`${t.action_type}.${f.name} uses format ${f.format}, not one code_systems lists for ${f.code_system}`);
  }
}
for (const e of registry.enum_snapshot_files ?? []) {
  if (LICENSED_SYSTEM_WORDS.test(`${e.values_ref} ${e.values_snapshot} ${e.path}`)) fail(`value set ${e.path} snapshots a code system; code systems are pinned by syntax only`);
}
pass(`code fields: ${codeFields} fields name a recorded code system and a registered format; ${codeSystems.size} code systems recorded; no code system snapshotted`);

// 4. Value sets: every pinned file loads under its pins and carries its
//    source, retrieval date and licence.
let snapshots = [];
try {
  snapshots = loadRegistryEnumSnapshots(registry);
} catch (error) {
  fail(`value-set pins: ${error.message}`);
}
for (const e of registry.enum_snapshot_files ?? []) {
  for (const key of ['source_url', 'retrieved', 'license']) if (typeof e[key] !== 'string' || !e[key]) fail(`enum_snapshot_files ${e.path} has no ${key}`);
  const file = JSON.parse(readFileSync(path.join(HERE, e.path), 'utf8'));
  for (const key of ['url', 'published', 'retrieved', 'source_sha256']) if (typeof file.source?.[key] !== 'string') fail(`${e.path} source has no ${key}`);
  if (file.source?.url !== e.source_url) fail(`${e.path} source url differs from its registry entry`);
}
pass(`value sets: ${snapshots.length} pinned files load, each with source, retrieval date and licence`);

// 5. Unresolved enums: exactly the fields without a pinned set, carrying
//    their type's status, none on an active type.
const pinnedSets = new Set((registry.enum_snapshot_files ?? []).map((e) => JSON.stringify([e.values_ref, e.values_snapshot, e.values_sha256])));
const unresolved = [];
for (const t of types) {
  for (const [required, list] of [[true, t.required_fields ?? []], [false, t.optional_fields ?? []]]) {
    for (const f of list) {
      if (f.type !== 'enum') continue;
      const inline = Array.isArray(f.values) && !('values_ref' in f);
      const compact = typeof f.values_ref === 'string' && f.values_ref.startsWith(spec.enum.inline_prefix);
      if (!inline && !compact && !pinnedSets.has(JSON.stringify([f.values_ref, f.values_snapshot, f.values_sha256]))) {
        unresolved.push({ action_type: t.action_type, status: t.status, field: f.name, required });
      }
    }
  }
}
if (JSON.stringify(unresolved) !== JSON.stringify(registry.unresolved_external_enums)) fail('unresolved_external_enums differs from the fields that have no pinned set (or omits their status)');
const activeUnresolved = unresolved.filter((u) => u.status === 'active');
if (activeUnresolved.length) fail(`active types with unresolved enums: ${activeUnresolved.map((u) => `${u.action_type}.${u.field}`).join(', ')}`);
pass(`unresolved enums: ${unresolved.length} listed, all on deprecated types; 0 on active types`);

// 6. Lifecycle links.
for (const t of types) {
  if (t.status === 'deprecated' && t.superseded_by) {
    const next = byName.get(t.superseded_by);
    if (!next || next.supersedes !== t.action_type || next.status !== 'active') fail(`${t.action_type} superseded_by ${t.superseded_by} has no active successor naming it back`);
  }
  if (t.supersedes) {
    const prev = byName.get(t.supersedes);
    if (!prev || prev.superseded_by !== t.action_type) fail(`${t.action_type} supersedes ${t.supersedes}, which does not name it back`);
  }
  if (t.status === 'active' && t.superseded_by) fail(`${t.action_type} is active but superseded`);
}
pass(`lifecycle: ${types.filter((t) => t.status === 'deprecated').length} deprecated types, each linked to its active successor`);

// 7. Every type computes. Build an object from each definition, compute it
//    with the reference validator, and compare the JS port where it can.
function candidate(field, rng) {
  switch (field.type) {
    case 'string': return 'x';
    case 'amount-string': return '1.00';
    case 'digest': return `sha256:${'0'.repeat(64)}`;
    case 'timestamp': return '2026-02-28T00:00:00Z';
    case 'integer': return 1;
    case 'boolean': return true;
    case 'object': return {};
    case 'array': return [];
    case 'code': return sample(rules, field.format, rng);
    case 'enum': {
      if (Array.isArray(field.values)) return field.values[0];
      if (typeof field.values_ref === 'string' && field.values_ref.startsWith(spec.enum.inline_prefix)) {
        return field.values_ref.slice(spec.enum.inline_prefix.length).split(spec.enum.inline_separator)[0].trim();
      }
      const s = snapshots.find((x) => x.values_ref === field.values_ref && x.values_snapshot === field.values_snapshot && x.values_sha256 === field.values_sha256);
      return s ? s.values[0] : 'UNRESOLVED';
    }
    default: return null;
  }
}
const rng = prng(20260926);
const computed = { active: 0, activeFull: 0, deprecated: 0, portSame: 0, portPending: /** @type {string[]} */ ([]) };
const unresolvedKeys = new Set(unresolved.map((u) => `${u.action_type}.${u.field}`));
for (const t of types) {
  const minimal = { action_type: t.action_type };
  for (const f of t.required_fields) minimal[f.name] = candidate(f, rng);
  const full = { ...minimal };
  for (const f of t.optional_fields ?? []) full[f.name] = candidate(f, rng);
  const opts = { suite: 'jcs-sha256', definitions: types, enumSnapshots: snapshots };
  const a = ref.compute(minimal, opts);
  const b = ref.compute(full, opts);
  if (t.status === 'active') {
    if (!a.caid) { fail(`active ${t.action_type} does not compute: ${(a.refusals ?? []).join(', ')}`); continue; }
    if (!b.caid) { fail(`active ${t.action_type} with every optional field does not compute: ${(b.refusals ?? []).join(', ')}`); continue; }
    computed.active += 1;
    computed.activeFull += 1;
    if (a.definition_sha256 !== ref.definitionSha256(t)) fail(`${t.action_type} reports a definition_sha256 other than its own`);
    const hasCode = fieldsOf(t).some((f) => f.type === 'code');
    const port = computeCaid(full, opts);
    if (port.caid === b.caid) computed.portSame += 1;
    else if (hasCode && !port.caid && (port.refusals ?? []).every((r) => fieldsOf(t).some((f) => f.type === 'code' && r === `mistyped_field:${f.name}`))) computed.portPending.push(t.action_type);
    else fail(`${t.action_type}: caid/impl/js gives ${JSON.stringify(port)}, the reference gives ${b.caid}`);
  } else {
    // A deprecated type resolves; it computes unless a required field is
    // unresolved, and then refuses exactly those fields as mistyped.
    const expected = t.required_fields.filter((f) => unresolvedKeys.has(`${t.action_type}.${f.name}`)).map((f) => `mistyped_field:${f.name}`);
    const got = a.caid ? [] : a.refusals;
    if (JSON.stringify(got) !== JSON.stringify(expected)) fail(`deprecated ${t.action_type}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(a.caid ?? a.refusals)}`);
    else computed.deprecated += 1;
  }
}
const activeCount = types.filter((t) => t.status === 'active').length;

// 7b. Code fields refuse by syntax only: a string outside the format is
//     invalid_code:<f>, a non-string is mistyped_field:<f>, a format the
//     implementation does not register is mistyped_field:<f> when present,
//     and nothing is normalized (case, surrounding space, a final line feed).
let codeChecks = 0;
for (const t of types.filter((x) => x.status === 'active')) {
  const codeFields = fieldsOf(t).filter((f) => f.type === 'code');
  if (!codeFields.length) continue;
  const base = { action_type: t.action_type };
  for (const f of t.required_fields) base[f.name] = candidate(f, rng);
  const opts = { suite: 'jcs-sha256', definitions: types, enumSnapshots: snapshots };
  for (const f of codeFields) {
    const good = candidate(f, rng);
    const expectOne = (value, reason) => {
      codeChecks += 1;
      const got = ref.compute({ ...base, [f.name]: value }, opts);
      if (JSON.stringify(got.refusals) !== JSON.stringify([`${reason}:${f.name}`])) {
        fail(`${t.action_type}.${f.name} = ${JSON.stringify(value)}: expected ${reason}, got ${JSON.stringify(got.caid ?? got.refusals)}`);
      }
    };
    for (const bad of [`${good}\n`, ` ${good}`, `${good}${good}`, '', good.toLowerCase() === good ? `${good}!` : good.toLowerCase(), `${good.slice(0, -1)}١`]) {
      if (!matches(rules, f.format, bad)) expectOne(bad, spec.field_types.find((x) => x.type === 'code').format_refusal);
    }
    expectOne(12345, 'mistyped_field');
    expectOne(null, 'mistyped_field');
    const local = structuredClone(t);
    for (const lf of [...local.required_fields, ...(local.optional_fields ?? [])]) if (lf.name === f.name) lf.format = 'not-a-registered-format';
    codeChecks += 1;
    const unregistered = ref.compute({ ...base, [f.name]: good }, { ...opts, definitions: [local] });
    if (JSON.stringify(unregistered.refusals) !== JSON.stringify([`mistyped_field:${f.name}`])) fail(`${t.action_type}.${f.name} with an unregistered format: ${JSON.stringify(unregistered)}`);
  }
}
pass(`code fields: ${codeChecks} refusal checks, syntax only, no normalization; an unregistered format refuses as mistyped_field when present`);
pass(`computation: ${computed.active} of ${activeCount} active types compute under the reference validator, required fields alone and with every optional field`);
pass(`computation: ${computed.deprecated} deprecated types resolve and refuse exactly their unresolved required enums`);
if (computed.portPending.length && argv.has('--require-port')) fail(`caid/impl/js cannot compute ${computed.portPending.join(', ')} (code fields)`);
pass(`caid/impl/js agrees on ${computed.portSame} active types; ${computed.portPending.length} code-field types pending in the port${computed.portPending.length ? ` (${computed.portPending.join(', ')})` : ''}`);

// 8. v4 to v5: every v4 type survives; only first pins or monotone advances
//    change a definition, and status only moves from active to deprecated.
const snapshotValues = (field, pool) => {
  if (Array.isArray(field.values)) return field.values;
  const s = pool.find((x) => x.values_ref === field.values_ref && x.values_snapshot === field.values_snapshot && x.values_sha256 === field.values_sha256);
  return s ? s.values : null;
};
let v4Snapshots = [];
try { v4Snapshots = loadRegistryEnumSnapshots(v4); } catch (error) { fail(`v4 value-set pins: ${error.message}`); }
const allSnapshots = [...snapshots, ...v4Snapshots];
const changed = [];
for (const old of v4.types) {
  const now = byName.get(old.action_type);
  if (!now) { fail(`v4 type ${old.action_type} is missing from v5`); continue; }
  if (old.status !== now.status && !(old.status === 'active' && now.status === 'deprecated')) fail(`${old.action_type} status moved ${old.status} -> ${now.status}`);
  const before = ref.definitionSha256(old);
  const after = ref.definitionSha256(now);
  if (before === after) continue;
  const strip = (t) => JSON.stringify(ref.projection(t), (k, v) => (['values', 'values_ref', 'values_snapshot', 'values_sha256'].includes(k) ? undefined : v));
  if (strip(old) !== strip(now)) { fail(`${old.action_type} changed beyond an enum pin between v4 and v5`); continue; }
  const oldFields = fieldsOf(old);
  fieldsOf(now).forEach((f, i) => {
    const o = oldFields[i];
    if (JSON.stringify(o) === JSON.stringify(f)) return;
    if (f.type !== 'enum' || o.type !== 'enum') { fail(`${old.action_type}.${f.name} changed but is not an enum`); return; }
    const oldValues = snapshotValues(o, allSnapshots);
    const newValues = snapshotValues(f, allSnapshots);
    const firstPin = oldValues === null && v4.unresolved_external_enums.some((u) => u.action_type === old.action_type && u.field === o.name);
    const monotone = oldValues !== null && newValues !== null && oldValues.every((v) => newValues.includes(v));
    if (!newValues || !(firstPin || monotone)) fail(`${old.action_type}.${f.name}: the pin change is neither a first pin nor a monotone advance`);
    else changed.push({ action_type: old.action_type, field: f.name, change: firstPin ? 'first pin' : 'monotone advance', v4_definition_sha256: before, v5_definition_sha256: after });
  });
}
pass(`v4 to v5: all ${v4.types.length} v4 types present; ${changed.length} pin changes (${changed.map((c) => `${c.action_type}.${c.field}: ${c.change}`).join('; ')}); every other v4 definition_sha256 unchanged`);

// 9. digests.json.
const digests = {
  '@version': 'CAID-REGISTRY-DIGESTS-v1',
  registry: registry.meta.registry,
  registry_version: registry.meta.registry_version,
  definition_sha256: 'sha256: followed by the lowercase hexadecimal SHA-256 of the RFC 8785 encoding of the validation projection: action_type, required_fields and optional_fields (absent is []), each field entry without notes (draft-schrock-canonical-action-identifier-04 Section 4.2; caid/spec/core.json definition.projection).',
  registry_files: [
    { registry_version: 4, path: HISTORY_V4.path, sha256: sha(v4Bytes), jcs_sha256: jcs(v4) },
    { registry_version: 5, path: 'action-types.json', sha256: sha(registryBytes), jcs_sha256: jcs(registry) },
  ],
  changed_since_v4: changed,
  types: types.map((t) => ({ action_type: t.action_type, status: t.status, definition_sha256: ref.definitionSha256(t) })),
};
const digestsText = JSON.stringify(digests, null, 2) + '\n';
const digestsPath = path.join(HERE, 'digests.json');
if (argv.has('--write-digests')) writeFileSync(digestsPath, digestsText);
let currentDigests = null;
try { currentDigests = readFileSync(digestsPath, 'utf8'); } catch { /* missing */ }
if (currentDigests !== digestsText) fail('digests.json differs from a regeneration (run node caid/registry/check.mjs --write-digests)');
else pass(`digests.json: ${digests.types.length} definition digests and both registry files match a regeneration`);

if (failures.length) {
  process.stderr.write(`caid/registry/check.mjs FAILED\n${failures.map((f) => `  ${f}`).join('\n')}\n`);
  process.exit(1);
}
console.log(`CAID registry v${registry.meta.registry_version}: ${types.length} types, ${activeCount} active and computing, ${types.length - activeCount} deprecated.`);
