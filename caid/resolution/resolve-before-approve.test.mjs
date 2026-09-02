// SPDX-License-Identifier: Apache-2.0
//
// Hostile suite for resolve-before-approve.
//
// The vector corpus (run-vectors.mjs) is hermetic. This suite is the other
// half: it drives the REAL resolvers - a real symlink swapped on a real
// filesystem between approval and dispatch, a real redirect chain, a real
// directory remap - and it joins the profile to real CAID computation to
// show what CAID alone does and does not catch.
//
// Attack class cited as the public rule: Wiz "GhostApproval", Adversa
// "SymJack", and the OWASP AI Agent Security cheat sheet. Cited as prior
// public description only; no review or endorsement by those parties is
// claimed here.
//
// Run: node --test caid/resolution/resolve-before-approve.test.mjs

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { computeCaid, verifyCaid } from '../impl/js/caid.mjs';
import { computeResolvedCaid, verifyResolvedCaidAtDispatch } from './caid-join.mjs';
import {
  beneficiaryLabelResolver,
  filesystemPathResolver,
  urlOriginResolver,
} from './resolvers.mjs';
import {
  BINDING_FIELD,
  checkResolvedReferencesAtDispatch,
  freezeResolvedReferences,
  REFUSAL_CODES,
  referenceIdentityDigest,
  RESOLUTION_PROFILE,
} from './resolve-before-approve.mjs';
import { runCorpus } from './run-vectors.mjs';

const PATH_SPEC = {
  '@profile': RESOLUTION_PROFILE,
  references: [{ field: 'target_path', kind: 'filesystem-path' }],
};
const URL_SPEC = {
  '@profile': RESOLUTION_PROFILE,
  references: [{ field: 'callback_url', kind: 'url-origin' }],
};
const LABEL_SPEC = {
  '@profile': RESOLUTION_PROFILE,
  references: [{ field: 'beneficiary_label', kind: 'beneficiary-label' }],
};

// A locally defined action type. It deliberately does NOT reuse a public
// registry name, so this suite can never be read as re-defining a
// registered type.
const DEFINITIONS = [{
  action_type: 'local.reference-export.1',
  status: 'active',
  risk_class: 'irreversible-data',
  summary: 'Export of a file named by a path reference.',
  required_fields: [{ name: 'target_path', type: 'string' }],
  optional_fields: [],
  references: [],
}];

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-rba-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return fs.realpathSync(dir);
}

function repointSymlink(linkPath, newTarget) {
  fs.unlinkSync(linkPath);
  fs.symlinkSync(newTarget, linkPath);
}

/** Transport whose redirect table can be rewritten between resolutions. */
function mutableTransport(table) {
  return async (url) => {
    if (Object.prototype.hasOwnProperty.call(table, url)) {
      return { status: 302, headers: { get: (name) => (name.toLowerCase() === 'location' ? table[url] : null) } };
    }
    return { status: 200, headers: { get: () => null } };
  };
}

// ---------------------------------------------------------------------------
// The three reference types, end to end, against the real resolvers
// ---------------------------------------------------------------------------

test('filesystem: a symlink swapped between approval and dispatch is refused with a reason', async (t) => {
  const dir = tempDir(t);
  const approved = path.join(dir, 'approved.csv');
  const swapped = path.join(dir, 'payroll.csv');
  const link = path.join(dir, 'current.csv');
  fs.writeFileSync(approved, 'approved rows\n');
  fs.writeFileSync(swapped, 'payroll rows\n');
  fs.symlinkSync(approved, link);

  const resolvers = { 'filesystem-path': filesystemPathResolver() };
  const captured = await freezeResolvedReferences({ target_path: link }, PATH_SPEC, resolvers);
  assert.equal(captured.ok, true, JSON.stringify(captured.refusals));
  assert.equal(captured.report.fields[0].identity.startsWith(approved), true);
  assert.equal(captured.report.fields[0].evidence.indirect, true);

  const before = await checkResolvedReferencesAtDispatch(captured.observed, PATH_SPEC, resolvers);
  assert.equal(before.ok, true);

  repointSymlink(link, swapped);

  const after = await checkResolvedReferencesAtDispatch(captured.observed, PATH_SPEC, resolvers);
  assert.equal(after.ok, false);
  assert.deepEqual(after.refusals, ['resolved_reference_diverged:target_path']);
  // The argument the approval covered never changed.
  assert.equal(captured.observed.target_path, link);
});

test('filesystem: the file replaced in place at the same real path is refused (device and inode are load-bearing)', async (t) => {
  const dir = tempDir(t);
  const target = path.join(dir, 'report.csv');
  fs.writeFileSync(target, 'first\n');

  const resolvers = { 'filesystem-path': filesystemPathResolver() };
  const captured = await freezeResolvedReferences({ target_path: target }, PATH_SPEC, resolvers);
  assert.equal(captured.ok, true);

  // Same path, same name, different file. Real path alone would agree.
  fs.unlinkSync(target);
  fs.writeFileSync(target, 'first\n');

  const after = await checkResolvedReferencesAtDispatch(captured.observed, PATH_SPEC, resolvers);
  assert.equal(after.ok, false);
  assert.deepEqual(after.refusals, ['resolved_reference_diverged:target_path']);
});

test('filesystem: a symlink escaping the approved root fails resolution with a reason, not a throw', async (t) => {
  const dir = tempDir(t);
  const root = path.join(dir, 'approved');
  const outside = path.join(dir, 'outside.csv');
  fs.mkdirSync(root);
  fs.writeFileSync(outside, 'secrets\n');
  const link = path.join(root, 'escape.csv');
  fs.symlinkSync(outside, link);

  const resolvers = { 'filesystem-path': filesystemPathResolver({ root }) };
  const captured = await freezeResolvedReferences({ target_path: link }, PATH_SPEC, resolvers);
  assert.equal(captured.ok, false);
  assert.deepEqual(captured.refusals, ['resolution_failed:target_path']);
});

test('filesystem: a path that does not exist is a refusal, and a relative path is refused unresolved', async (t) => {
  const dir = tempDir(t);
  const resolvers = { 'filesystem-path': filesystemPathResolver() };

  const missing = await freezeResolvedReferences(
    { target_path: path.join(dir, 'nope.csv') }, PATH_SPEC, resolvers,
  );
  assert.equal(missing.ok, false);
  assert.deepEqual(missing.refusals, ['resolution_failed:target_path']);

  const relative = await freezeResolvedReferences({ target_path: 'nope.csv' }, PATH_SPEC, resolvers);
  assert.equal(relative.ok, false);
  assert.deepEqual(relative.refusals, ['resolution_failed:target_path']);
});

test('url: a callback that starts redirecting to another origin is refused at dispatch', async () => {
  const redirects = { 'https://pay.example.test/hook': 'https://pay.example.test/v2/hook' };
  const resolvers = { 'url-origin': urlOriginResolver({ transport: mutableTransport(redirects) }) };

  const captured = await freezeResolvedReferences(
    { callback_url: 'https://pay.example.test/hook' }, URL_SPEC, resolvers,
  );
  assert.equal(captured.ok, true, JSON.stringify(captured.refusals));
  assert.equal(captured.report.fields[0].identity, 'https://pay.example.test');
  assert.deepEqual(captured.report.fields[0].evidence.redirect_chain, [
    'https://pay.example.test/hook',
    'https://pay.example.test/v2/hook',
  ]);

  redirects['https://pay.example.test/v2/hook'] = 'https://collector.attacker.test/drop';
  const after = await checkResolvedReferencesAtDispatch(captured.observed, URL_SPEC, resolvers);
  assert.equal(after.ok, false);
  assert.deepEqual(after.refusals, ['resolved_reference_diverged:callback_url']);
});

test('url: a redirect loop, a missing Location, and a disallowed scheme all refuse with reasons', async () => {
  const loop = { a: 'https://a.example.test/2', b: 'https://a.example.test/1' };
  const looping = {
    'url-origin': urlOriginResolver({
      transport: mutableTransport({
        'https://a.example.test/1': loop.a,
        'https://a.example.test/2': loop.b,
      }),
    }),
  };
  const looped = await freezeResolvedReferences(
    { callback_url: 'https://a.example.test/1' }, URL_SPEC, looping,
  );
  assert.equal(looped.ok, false);
  assert.deepEqual(looped.refusals, ['resolution_failed:callback_url']);

  const headless = {
    'url-origin': urlOriginResolver({
      transport: async () => ({ status: 302, headers: { get: () => null } }),
    }),
  };
  const noLocation = await freezeResolvedReferences(
    { callback_url: 'https://a.example.test/1' }, URL_SPEC, headless,
  );
  assert.equal(noLocation.ok, false);
  assert.deepEqual(noLocation.refusals, ['resolution_failed:callback_url']);

  const plaintext = {
    'url-origin': urlOriginResolver({ transport: async () => ({ status: 200, headers: { get: () => null } }) }),
  };
  const httpScheme = await freezeResolvedReferences(
    { callback_url: 'http://a.example.test/1' }, URL_SPEC, plaintext,
  );
  assert.equal(httpScheme.ok, false);
  assert.deepEqual(httpScheme.refusals, ['resolution_failed:callback_url']);
});

test('url: a transport that throws surfaces as a refusal, not an exception', async () => {
  const resolvers = {
    'url-origin': urlOriginResolver({ transport: async () => { throw new Error('socket died'); } }),
  };
  const captured = await freezeResolvedReferences(
    { callback_url: 'https://a.example.test/1' }, URL_SPEC, resolvers,
  );
  assert.equal(captured.ok, false);
  assert.deepEqual(captured.refusals, ['resolution_failed:callback_url']);
});

test('beneficiary: a label remapped to another account is refused at dispatch', async () => {
  const directory = { 'Acme Supplies': 'acct-1111' };
  const resolvers = {
    'beneficiary-label': beneficiaryLabelResolver({ directory: (label) => directory[label] }),
  };

  const captured = await freezeResolvedReferences(
    { beneficiary_label: 'Acme Supplies', amount: '250.00' }, LABEL_SPEC, resolvers,
  );
  assert.equal(captured.ok, true, JSON.stringify(captured.refusals));
  // Stated normalization: uppercase, ASCII space and hyphen removed.
  assert.equal(captured.report.fields[0].identity, 'ACCT1111');

  directory['Acme Supplies'] = 'acct-9999';
  const after = await checkResolvedReferencesAtDispatch(captured.observed, LABEL_SPEC, resolvers);
  assert.equal(after.ok, false);
  assert.deepEqual(after.refusals, ['resolved_reference_diverged:beneficiary_label']);
});

test('beneficiary: an unmapped label and a directory that throws both refuse with reasons', async () => {
  const unmapped = { 'beneficiary-label': beneficiaryLabelResolver({ directory: () => null }) };
  const missing = await freezeResolvedReferences({ beneficiary_label: 'Nobody' }, LABEL_SPEC, unmapped);
  assert.equal(missing.ok, false);
  assert.deepEqual(missing.refusals, ['resolution_failed:beneficiary_label']);

  const broken = {
    'beneficiary-label': beneficiaryLabelResolver({
      directory: () => { throw new Error('directory unreachable'); },
    }),
  };
  const failed = await freezeResolvedReferences({ beneficiary_label: 'Acme' }, LABEL_SPEC, broken);
  assert.equal(failed.ok, false);
  assert.deepEqual(failed.refusals, ['resolution_failed:beneficiary_label']);
});

test('a directory that answers differently on two consecutive reads is unstable, not a coin flip to freeze', async () => {
  let call = 0;
  const resolvers = {
    'beneficiary-label': beneficiaryLabelResolver({
      directory: () => { call += 1; return call === 1 ? 'ACCT-1111' : 'ACCT-9999'; },
    }),
  };
  const captured = await freezeResolvedReferences({ beneficiary_label: 'Acme' }, LABEL_SPEC, resolvers);
  assert.equal(captured.ok, false);
  assert.deepEqual(captured.refusals, ['resolution_unstable:beneficiary_label']);
});

// ---------------------------------------------------------------------------
// The CAID join: what CAID alone catches, and what it does not
// ---------------------------------------------------------------------------

test('CAID alone still verifies a swapped symlink; the resolution check is what refuses it', async (t) => {
  const dir = tempDir(t);
  const approved = path.join(dir, 'approved.csv');
  const swapped = path.join(dir, 'payroll.csv');
  const link = path.join(dir, 'current.csv');
  fs.writeFileSync(approved, 'approved\n');
  fs.writeFileSync(swapped, 'payroll\n');
  fs.symlinkSync(approved, link);

  const resolvers = { 'filesystem-path': filesystemPathResolver() };
  const options = {
    suite: 'jcs-sha256',
    definitions: DEFINITIONS,
    spec: PATH_SPEC,
    resolvers,
  };
  const approvedAction = await computeResolvedCaid('local.reference-export.1', { target_path: link }, options);
  assert.ok(approvedAction.caid, JSON.stringify(approvedAction.refusals));

  repointSymlink(link, swapped);

  // The Action Object is byte-identical, so plain CAID verification passes.
  // This is the hole, demonstrated rather than asserted.
  const caidOnly = verifyCaid(approvedAction.action, approvedAction.caid, { definitions: DEFINITIONS });
  assert.equal(caidOnly.valid, true);
  assert.deepEqual(caidOnly.reasons, []);

  // The dispatch check refuses, with a stated reason.
  const dispatch = await verifyResolvedCaidAtDispatch(approvedAction.action, approvedAction.caid, options);
  assert.equal(dispatch.valid, false);
  assert.deepEqual(dispatch.reasons, ['resolved_reference_diverged:target_path']);
});

test('the resolved identity is inside the digest: the same arguments over a different target yield a different CAID', async (t) => {
  const dir = tempDir(t);
  const approved = path.join(dir, 'approved.csv');
  const swapped = path.join(dir, 'payroll.csv');
  const link = path.join(dir, 'current.csv');
  fs.writeFileSync(approved, 'approved\n');
  fs.writeFileSync(swapped, 'payroll\n');
  fs.symlinkSync(approved, link);

  const options = {
    suite: 'jcs-sha256',
    definitions: DEFINITIONS,
    spec: PATH_SPEC,
    resolvers: { 'filesystem-path': filesystemPathResolver() },
  };
  const first = await computeResolvedCaid('local.reference-export.1', { target_path: link }, options);
  repointSymlink(link, swapped);
  const second = await computeResolvedCaid('local.reference-export.1', { target_path: link }, options);

  assert.ok(first.caid && second.caid);
  assert.notEqual(first.caid, second.caid);
  assert.equal(first.action.target_path, second.action.target_path);

  // Without the binding, the two are the same identifier. That is the
  // before-and-after of this change in one assertion.
  const bare = (action) => {
    const copy = { ...action };
    delete copy[BINDING_FIELD];
    return computeCaid(copy, { suite: 'jcs-sha256', definitions: DEFINITIONS });
  };
  assert.equal(bare(first.action).caid, bare(second.action).caid);
});

test('the CAID join reports CAID reasons and resolution reasons together, in that order', async () => {
  const options = {
    suite: 'jcs-sha256',
    definitions: DEFINITIONS,
    spec: LABEL_SPEC,
    resolvers: { 'beneficiary-label': beneficiaryLabelResolver({ directory: () => 'ACCT-1111' }) },
  };
  const built = await computeResolvedCaid(
    'local.reference-export.1', { target_path: '/x', beneficiary_label: 'Acme' }, options,
  );
  assert.ok(built.caid, JSON.stringify(built.refusals));

  const tampered = { ...built.action, target_path: '/y' };
  const result = await verifyResolvedCaidAtDispatch(tampered, built.caid, {
    ...options,
    resolvers: { 'beneficiary-label': beneficiaryLabelResolver({ directory: () => 'ACCT-9999' }) },
  });
  assert.equal(result.valid, false);
  assert.deepEqual(result.reasons, ['digest_mismatch', 'resolved_reference_diverged:beneficiary_label']);
});

test('the action type cannot be smuggled in through tool arguments', async () => {
  const options = {
    suite: 'jcs-sha256',
    definitions: DEFINITIONS,
    spec: LABEL_SPEC,
    resolvers: { 'beneficiary-label': beneficiaryLabelResolver({ directory: () => 'ACCT-1111' }) },
  };
  const built = await computeResolvedCaid('local.reference-export.1', {
    action_type: 'local.something-else.1',
    beneficiary_label: 'Acme',
  }, options);
  assert.deepEqual(built.refusals, ['invalid_action_type']);
});

// ---------------------------------------------------------------------------
// Fail-closed: a reason, never a throw
// ---------------------------------------------------------------------------

test('every hostile input shape returns refusals and nothing throws', async () => {
  const resolvers = { 'filesystem-path': filesystemPathResolver() };
  const hostile = [
    null,
    undefined,
    'string',
    42,
    [],
    Object.assign(Object.create({ inherited: true }), { target_path: '/x' }),
    new Map(),
  ];
  for (const args of hostile) {
    const captured = await freezeResolvedReferences(args, PATH_SPEC, resolvers);
    assert.equal(captured.ok, false, `accepted ${String(args)}`);
    assert.equal(Array.isArray(captured.refusals), true);
    assert.equal(captured.refusals.length > 0, true);

    const dispatched = await checkResolvedReferencesAtDispatch(args, PATH_SPEC, resolvers);
    assert.equal(dispatched.ok, false);
    assert.equal(dispatched.refusals.length > 0, true);
  }
});

test('a getter on a reference argument is refused and never invoked', async () => {
  let invoked = false;
  const args = {};
  Object.defineProperty(args, 'target_path', { enumerable: true, get: () => { invoked = true; return '/x'; } });
  const captured = await freezeResolvedReferences(args, PATH_SPEC, { 'filesystem-path': filesystemPathResolver() });
  assert.deepEqual(captured.refusals, ['invalid_arguments']);
  assert.equal(invoked, false);
});

test('a malformed spec is refused alone, and nothing is resolved under it', async () => {
  let called = false;
  const resolvers = { 'filesystem-path': () => { called = true; return { ok: true, identity: '/x' }; } };
  const bad = [
    null,
    {},
    { '@profile': 'other', references: [{ field: 'target_path', kind: 'filesystem-path' }] },
    { '@profile': RESOLUTION_PROFILE, references: [] },
    { '@profile': RESOLUTION_PROFILE, references: [{ field: 'Target_Path', kind: 'filesystem-path' }] },
    { '@profile': RESOLUTION_PROFILE, references: [{ field: 'target_path', kind: 'filesystem-path', extra: 1 }] },
    { '@profile': RESOLUTION_PROFILE, references: [{ field: 'action_type', kind: 'filesystem-path' }] },
    { '@profile': RESOLUTION_PROFILE, references: [{ field: 'target_path', kind: 'filesystem-path' }], extra: 1 },
  ];
  for (const spec of bad) {
    const captured = await freezeResolvedReferences({ target_path: '/x' }, spec, resolvers);
    assert.deepEqual(captured.refusals, ['invalid_resolution_spec'], JSON.stringify(spec));
    const dispatched = await checkResolvedReferencesAtDispatch({ target_path: '/x' }, spec, resolvers);
    assert.deepEqual(dispatched.refusals, ['invalid_resolution_spec']);
  }
  assert.equal(called, false);
});

test('the frozen observed action cannot be edited after approval', async () => {
  const resolvers = { 'beneficiary-label': beneficiaryLabelResolver({ directory: () => 'ACCT-1111' }) };
  const captured = await freezeResolvedReferences({ beneficiary_label: 'Acme' }, LABEL_SPEC, resolvers);
  assert.equal(captured.ok, true);
  assert.equal(Object.isFrozen(captured.observed), true);
  assert.equal(Object.isFrozen(captured.observed[BINDING_FIELD]), true);
  assert.equal(Object.isFrozen(captured.observed[BINDING_FIELD].beneficiary_label), true);
  assert.throws(() => { 'use strict'; captured.observed.beneficiary_label = 'Other'; });
});

test('identity digests are domain-separated by reference kind', () => {
  const asPath = referenceIdentityDigest('filesystem-path', 'SAME');
  const asLabel = referenceIdentityDigest('beneficiary-label', 'SAME');
  assert.notEqual(asPath, asLabel);
  assert.match(asPath, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(referenceIdentityDigest('dns-name', 'SAME'), null);
  assert.equal(referenceIdentityDigest('filesystem-path', ''), null);
});

test('every refusal this suite and the corpus can produce is in the closed code set', async () => {
  const seen = new Set();
  const collect = (refusals) => {
    for (const refusal of refusals) seen.add(String(refusal).split(':')[0]);
  };
  const resolvers = { 'filesystem-path': filesystemPathResolver() };
  collect((await freezeResolvedReferences({}, PATH_SPEC, resolvers)).refusals || []);
  collect((await freezeResolvedReferences({ target_path: 1 }, PATH_SPEC, resolvers)).refusals || []);
  collect((await freezeResolvedReferences({ target_path: '/nope' }, PATH_SPEC, resolvers)).refusals || []);
  collect((await freezeResolvedReferences(null, PATH_SPEC, resolvers)).refusals || []);
  collect((await freezeResolvedReferences({ target_path: '/x' }, PATH_SPEC, {})).refusals || []);
  collect((await checkResolvedReferencesAtDispatch({ target_path: '/x' }, PATH_SPEC, resolvers)).refusals || []);
  for (const code of seen) {
    assert.equal(REFUSAL_CODES.includes(code), true, `refusal code outside the closed set: ${code}`);
  }
  assert.equal(seen.size >= 5, true);
});

test('the frozen vector corpus is green', async () => {
  const results = await runCorpus();
  const failed = results.filter((result) => !result.ok);
  assert.deepEqual(failed, [], JSON.stringify(failed, null, 1));
  assert.equal(results.length >= 30, true);
});
