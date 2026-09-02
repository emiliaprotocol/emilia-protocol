#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Mutation-style check for resolve-before-approve.
//
// A green suite proves the code passes its tests. It does not prove any
// individual guard is load-bearing. This harness disables one guard at a
// time in resolve-before-approve.mjs, re-runs a fixed probe set against the
// mutated module, and requires the outcome to CHANGE. A mutant that
// survives is a guard no probe actually exercises.
//
// Mutants declared `redundant` are the inverse assertion: they are
// defense-in-depth checks a later check would catch anyway, and the harness
// requires them to survive. If one of those is killed, the note explaining
// why it is redundant is wrong and must be fixed.
//
//   node caid/resolution/mutation-check.mjs

import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = path.join(HERE, 'resolve-before-approve.mjs');

const PROFILE = 'EP-RESOLVE-BEFORE-APPROVE-v1';
const spec = (...references) => ({ '@profile': PROFILE, references });
const PATH_SPEC = spec({ field: 'target_path', kind: 'filesystem-path' });
const LABEL_SPEC = spec({ field: 'beneficiary_label', kind: 'beneficiary-label' });
const TWO_SPEC = spec(
  { field: 'target_path', kind: 'filesystem-path' },
  { field: 'beneficiary_label', kind: 'beneficiary-label' },
);

const stableResolvers = (identity = '/real#1:1', label = 'ACCT-1111') => ({
  'filesystem-path': () => ({ ok: true, identity }),
  'beneficiary-label': () => ({ ok: true, identity: label }),
});

function digestOf(mod, kind, identity) {
  return mod.referenceIdentityDigest(kind, identity);
}

/**
 * Each probe returns a short signature string. The harness compares the
 * baseline signature to the mutant signature; any difference kills.
 *
 * @type {Array<{name: string, run: (mod: any) => Promise<string>}>}
 */
const PROBES = [
  { name: 'capture-happy', run: async (mod) => {
    const out = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? out.observed : out.refusals);
  } },
  { name: 'capture-domain-separation', run: async (mod) => {
    const out = await mod.freezeResolvedReferences(
      { target_path: '/p', beneficiary_label: 'L' }, TWO_SPEC,
      { 'filesystem-path': () => ({ ok: true, identity: 'SAME' }), 'beneficiary-label': () => ({ ok: true, identity: 'SAME' }) },
    );
    if (!out.ok) return JSON.stringify(out.refusals);
    const bound = out.observed.resolved_references;
    return String(bound.target_path.identity_digest === bound.beneficiary_label.identity_digest);
  } },
  { name: 'capture-frozen', run: async (mod) => {
    const out = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC, stableResolvers());
    return out.ok ? String(Object.isFrozen(out.observed) && Object.isFrozen(out.observed.resolved_references)) : 'refused';
  } },
  { name: 'capture-missing-field', run: async (mod) => {
    const out = await mod.freezeResolvedReferences({}, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'capture-mistyped-field', run: async (mod) => {
    const out = await mod.freezeResolvedReferences({ target_path: 17 }, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'capture-resolution-failed', run: async (mod) => {
    const out = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC,
      { 'filesystem-path': () => ({ ok: false, reason: 'nope' }) });
    return JSON.stringify(out.ok ? ['ACCEPTED', out.observed] : out.refusals);
  } },
  { name: 'capture-resolver-threw', run: async (mod) => {
    const out = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC,
      { 'filesystem-path': () => { throw new Error('boom'); } });
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'capture-unstable', run: async (mod) => {
    let n = 0;
    const out = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC,
      { 'filesystem-path': () => { n += 1; return { ok: true, identity: n === 1 ? '/a#1:1' : '/b#1:2' }; } });
    return JSON.stringify(out.ok ? ['ACCEPTED', out.observed.resolved_references.target_path.identity_digest] : out.refusals);
  } },
  { name: 'capture-preexisting-binding', run: async (mod) => {
    const out = await mod.freezeResolvedReferences(
      { target_path: '/p', resolved_references: { target_path: { kind: 'filesystem-path', identity_digest: `sha256:${'0'.repeat(64)}` } } },
      PATH_SPEC, stableResolvers(),
    );
    return JSON.stringify(out.ok ? ['ACCEPTED', out.observed.resolved_references] : out.refusals);
  } },
  { name: 'capture-resolver-missing', run: async (mod) => {
    const out = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC, {});
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'capture-hostile-prototype', run: async (mod) => {
    const args = Object.assign(Object.create({ inherited: 1 }), { target_path: '/p' });
    const out = await mod.freezeResolvedReferences(args, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'capture-hostile-getter', run: async (mod) => {
    let invoked = false;
    const args = {};
    Object.defineProperty(args, 'target_path', { enumerable: true, get: () => { invoked = true; return '/p'; } });
    const out = await mod.freezeResolvedReferences(args, PATH_SPEC, stableResolvers());
    return JSON.stringify([out.ok ? 'ACCEPTED' : out.refusals, invoked]);
  } },
  { name: 'capture-bad-spec', run: async (mod) => {
    const outcomes = [];
    for (const bad of [
      null,
      {},
      { '@profile': 'other', references: [{ field: 'target_path', kind: 'filesystem-path' }] },
      spec(),
      spec({ field: 'target_path', kind: 'dns-name' }),
      spec({ field: 'target_path', kind: 'filesystem-path' }, { field: 'target_path', kind: 'beneficiary-label' }),
      spec({ field: 'resolved_references', kind: 'filesystem-path' }),
      spec({ field: 'target_path', kind: 'filesystem-path', extra: 1 }),
    ]) {
      const out = await mod.freezeResolvedReferences({ target_path: '/p' }, bad, stableResolvers());
      outcomes.push(out.ok ? 'ACCEPTED' : out.refusals.join(','));
    }
    return JSON.stringify(outcomes);
  } },
  { name: 'dispatch-agrees', run: async (mod) => {
    const captured = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC, stableResolvers());
    if (!captured.ok) return `capture-refused:${captured.refusals.join(',')}`;
    const out = await mod.checkResolvedReferencesAtDispatch(captured.observed, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['OK'] : out.refusals);
  } },
  { name: 'dispatch-diverged', run: async (mod) => {
    const captured = await mod.freezeResolvedReferences({ target_path: '/p' }, PATH_SPEC, stableResolvers('/a#1:1'));
    if (!captured.ok) return `capture-refused:${captured.refusals.join(',')}`;
    const out = await mod.checkResolvedReferencesAtDispatch(captured.observed, PATH_SPEC, stableResolvers('/b#1:2'));
    return JSON.stringify(out.ok ? ['ACCEPTED-A-DIVERGENCE'] : out.refusals);
  } },
  { name: 'dispatch-binding-absent', run: async (mod) => {
    const out = await mod.checkResolvedReferencesAtDispatch({ target_path: '/p' }, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'dispatch-binding-field-dropped', run: async (mod) => {
    const observed = { target_path: '/p', beneficiary_label: 'L', resolved_references: { target_path: { kind: 'filesystem-path', identity_digest: digestOf(mod, 'filesystem-path', '/real#1:1') } } };
    const out = await mod.checkResolvedReferencesAtDispatch(observed, TWO_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'dispatch-binding-extra-field', run: async (mod) => {
    const observed = {
      target_path: '/p',
      resolved_references: {
        target_path: { kind: 'filesystem-path', identity_digest: digestOf(mod, 'filesystem-path', '/real#1:1') },
        shadow: { kind: 'filesystem-path', identity_digest: `sha256:${'0'.repeat(64)}` },
      },
    };
    const out = await mod.checkResolvedReferencesAtDispatch(observed, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'dispatch-binding-kind-swapped', run: async (mod) => {
    const observed = { target_path: '/p', resolved_references: { target_path: { kind: 'beneficiary-label', identity_digest: digestOf(mod, 'filesystem-path', '/real#1:1') } } };
    const out = await mod.checkResolvedReferencesAtDispatch(observed, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'dispatch-binding-entry-extra-key', run: async (mod) => {
    const observed = { target_path: '/p', resolved_references: { target_path: { kind: 'filesystem-path', identity_digest: digestOf(mod, 'filesystem-path', '/real#1:1'), note: 'x' } } };
    const out = await mod.checkResolvedReferencesAtDispatch(observed, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'dispatch-binding-digest-malformed', run: async (mod) => {
    const observed = { target_path: '/p', resolved_references: { target_path: { kind: 'filesystem-path', identity_digest: 'sha256:NOTHEX' } } };
    const out = await mod.checkResolvedReferencesAtDispatch(observed, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'dispatch-reference-removed', run: async (mod) => {
    const observed = { resolved_references: { target_path: { kind: 'filesystem-path', identity_digest: digestOf(mod, 'filesystem-path', '/real#1:1') } } };
    const out = await mod.checkResolvedReferencesAtDispatch(observed, PATH_SPEC, stableResolvers());
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
  { name: 'dispatch-junk-observed', run: async (mod) => {
    const outcomes = [];
    for (const junk of [null, 'text', 42, [], new Map()]) {
      const out = await mod.checkResolvedReferencesAtDispatch(junk, PATH_SPEC, stableResolvers());
      outcomes.push(out.ok ? 'ACCEPTED' : out.refusals.join(','));
    }
    return JSON.stringify(outcomes);
  } },
  { name: 'dispatch-resolution-failed', run: async (mod) => {
    const captured = await mod.freezeResolvedReferences({ beneficiary_label: 'L' }, LABEL_SPEC, stableResolvers());
    if (!captured.ok) return `capture-refused:${captured.refusals.join(',')}`;
    const out = await mod.checkResolvedReferencesAtDispatch(captured.observed, LABEL_SPEC,
      { 'beneficiary-label': () => ({ ok: false }) });
    return JSON.stringify(out.ok ? ['ACCEPTED'] : out.refusals);
  } },
];

/**
 * One entry per guard. `find` must appear exactly once in the source, so a
 * refactor that moves a guard fails this harness loudly instead of silently
 * mutating nothing.
 */
const MUTANTS = [
  {
    name: 'dispatch divergence comparison',
    find: 'if (digest !== binding[field].identity_digest) {',
    replace: 'if (false) {',
  },
  {
    name: 'identity digest domain separation (kind in the preimage)',
    find: 'const preimage = `${RESOLUTION_PROFILE}\\n${kind}\\n${identity}`;',
    replace: 'const preimage = `${RESOLUTION_PROFILE}\\n${identity}`;',
  },
  {
    name: 'capture-time stability probe',
    find: 'if (a !== b) return { ok: false, code: `resolution_unstable:${field}` };',
    replace: 'if (false) return { ok: false, code: `resolution_unstable:${field}` };',
  },
  {
    name: 'caller-supplied binding refusal',
    find: "    return { ok: false, refusals: ['resolution_binding_preexisting'] };",
    replace: '    /* mutated: guard removed */',
  },
  {
    name: 'dispatch binding-absent refusal',
    find: "  if (!Object.prototype.hasOwnProperty.call(observed, BINDING_FIELD) || bindingEntries === null) {\n    return { ok: false, refusals: ['resolution_binding_absent'] };\n  }",
    replace: '  if (false) { /* mutated: guard removed */ }',
  },
  {
    name: 'dispatch bound-field set equality',
    find: '  if (boundFields.length !== declaredFields.length\n      || !declaredFields.every((field) => boundFields.includes(field))) {',
    replace: '  if (false) {',
  },
  {
    name: 'dispatch binding entry shape check (whole condition)',
    find: '    if (entryFields === null\n'
      + '        || entryFields.length !== BINDING_ENTRY_KEYS.size\n'
      + '        || entryFields.some(([key]) => !BINDING_ENTRY_KEYS.has(key))\n'
      + '        || binding[field].kind !== kind\n'
      + "        || typeof binding[field].identity_digest !== 'string'\n"
      + '        || !IDENTITY_DIGEST_RE.test(binding[field].identity_digest)) {',
    replace: '    if (false) {',
  },
  {
    name: 'dispatch binding entry kind equality',
    find: '        || binding[field].kind !== kind\n',
    replace: '        || false\n',
  },
  {
    name: 'dispatch binding entry digest format',
    find: '        || !IDENTITY_DIGEST_RE.test(binding[field].identity_digest)) {',
    replace: '        || false) {',
  },
  {
    name: 'own-key guard against accessors and exotic prototypes',
    find: '    if (!descriptor || descriptor.enumerable !== true || !(\'value\' in descriptor)) return null;',
    replace: '    /* mutated: guard removed */',
  },
  {
    name: 'plain-object prototype check',
    find: '  return prototype === Object.prototype || prototype === null;',
    replace: '  return true;',
  },
  {
    name: 'spec validation',
    find: '  const specRefusals = validateSpec(spec);\n  if (specRefusals.length > 0) return { ok: false, refusals: specRefusals };\n\n  const entries = safeOwnEntries(args);',
    replace: '  const specRefusals = [];\n  if (specRefusals.length > 0) return { ok: false, refusals: specRefusals };\n\n  const entries = safeOwnEntries(args);',
  },
  {
    name: 'reference field presence check',
    find: '  if (!Object.prototype.hasOwnProperty.call(source, field)) {',
    replace: '  if (false) {',
  },
  {
    name: 'reference field type and bounds check',
    find: "  if (typeof value !== 'string' || value.length === 0 || utf8Bytes(value) > MAX_REFERENCE_BYTES) {",
    replace: '  if (false) {',
  },
  {
    name: 'missing-resolver refusal',
    find: '    if (resolver === null) {\n      refusals.push(`resolver_missing:${kind}`);\n      continue;\n    }\n    const read = readReferenceValue(args, field);',
    replace: '    if (false) {\n      refusals.push(`resolver_missing:${kind}`);\n      continue;\n    }\n    const read = readReferenceValue(args, field);',
  },
  {
    name: 'deep freeze of the observed action',
    find: '    observed: deepFreeze(observed),',
    replace: '    observed: observed,',
  },
  {
    name: 'resolver result shape check',
    find: '  if (a === null || b === null) return { ok: false, code: `resolution_failed:${field}` };',
    replace: '  if (false) return { ok: false, code: `resolution_failed:${field}` };',
    redundant: true,
    note: 'A malformed resolver result yields a non-string identity, which referenceIdentityDigest '
      + 'refuses, producing the same resolution_failed refusal one step later. Kept as '
      + 'defense-in-depth so the refusal is attributed at the resolver boundary.',
  },
];

async function signatures(moduleUrl) {
  const mod = await import(moduleUrl);
  const out = [];
  for (const { name, run } of PROBES) {
    try {
      out.push([name, await run(mod)]);
    } catch (error) {
      // A probe that throws is itself a signature: the profile promises
      // refusals, so "threw" must never be the baseline.
      out.push([name, `THREW:${error && error.message}`]);
    }
  }
  return out;
}

const source = readFileSync(SOURCE, 'utf8');
const baseline = await signatures(pathToFileURL(SOURCE).href);

for (const [name, value] of baseline) {
  if (String(value).startsWith('THREW:')) {
    process.stderr.write(`FAIL baseline probe threw: ${name} -> ${value}\n`);
    process.exit(1);
  }
}

const results = [];
for (const [index, mutant] of MUTANTS.entries()) {
  const occurrences = source.split(mutant.find).length - 1;
  if (occurrences !== 1) {
    results.push({ mutant: mutant.name, ok: false, message: `mutation target appears ${occurrences} times, expected exactly 1` });
    continue;
  }
  const mutatedSource = source.replace(mutant.find, mutant.replace);
  const mutantPath = path.join(HERE, `.mutant-${index}.mjs`);
  writeFileSync(mutantPath, mutatedSource);
  let killedBy = [];
  try {
    const mutantSignatures = await signatures(`${pathToFileURL(mutantPath).href}?m=${index}`);
    killedBy = mutantSignatures
      .filter(([name, value], i) => baseline[i][1] !== value && baseline[i][0] === name)
      .map(([name]) => name);
  } catch (error) {
    killedBy = [`module failed to load: ${error && error.message}`];
  } finally {
    rmSync(mutantPath, { force: true });
  }

  if (mutant.redundant) {
    results.push(killedBy.length === 0
      ? { mutant: mutant.name, ok: true, message: `survived as declared redundant. ${mutant.note}` }
      : { mutant: mutant.name, ok: false, message: `declared redundant but KILLED by ${killedBy.join(', ')}; the redundancy note is wrong` });
    continue;
  }
  results.push(killedBy.length > 0
    ? { mutant: mutant.name, ok: true, message: `killed by ${killedBy.length} probe(s): ${killedBy.slice(0, 3).join(', ')}` }
    : { mutant: mutant.name, ok: false, message: 'SURVIVED: no probe changed outcome when this guard was removed' });
}

for (const result of results) {
  process.stdout.write(`${result.ok ? 'PASS' : 'FAIL'} ${result.mutant} - ${result.message}\n`);
}
const failed = results.filter((result) => !result.ok);
if (failed.length > 0) {
  process.stderr.write(`${failed.length} of ${results.length} guards are not proven load-bearing\n`);
  process.exit(1);
}
process.stdout.write(`resolve-before-approve: ${results.length} guards checked against ${PROBES.length} probes\n`);
