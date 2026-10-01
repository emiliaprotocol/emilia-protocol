// SPDX-License-Identifier: Apache-2.0
//
// Self-test for scripts/ci/derived-evidence-drift.mjs, the comparison
// scripts/verify-security-case.mts makes between the checked-in security case
// and its fresh resolution. With --drift-report (CI's pull-request mode) stale
// derived digests are reported and pass, while any change to a claim, the
// execution record or the file's shape fails. Without it (main's refresh,
// releases, publishing, local checks) any difference fails, as before.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  DRIFT_REPORT_VERSION,
  SECURITY_CASE,
  SECURITY_CASE_DERIVED_FIELDS,
  SECURITY_CASE_WRITER,
  checkSecurityCase,
  driftEntries,
  fieldAllowed,
  renderPath,
  securityCaseDrift,
  serializeSecurityCase,
  summarizeFields,
} from './derived-evidence-drift.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
// The checked-in case is the writer's own output, so it stands in for a fresh
// resolution; each test moves one side the way a real change would.
const CHECKED_IN = readFileSync(join(ROOT, SECURITY_CASE), 'utf8');
const fresh = () => JSON.parse(CHECKED_IN);
const pr = (recordedText, computed) => checkSecurityCase({ recordedText, computed, driftReport: true });
const strict = (recordedText, computed) => checkSecurityCase({ recordedText, computed, driftReport: false });

/**
 * The resolution after a pull request changed one pinned file and one
 * package source: every digest that depends on them moved, nothing else did.
 */
function movedDigests() {
  const computed = fresh();
  const bundle = 'f'.repeat(64);
  const bundleId = Object.keys(computed.release_artifacts)
    .find((id) => computed.release_artifacts[id].kind === 'content-addressed-evidence-bundle');
  const packageId = Object.keys(computed.release_artifacts)
    .find((id) => computed.release_artifacts[id].kind === 'npm-tarball');
  computed.evidence_bundle_sha256 = bundle;
  computed.evidence_files[0].sha256 = 'e'.repeat(64);
  computed.release_artifacts[bundleId].sha256 = bundle;
  computed.release_artifacts[packageId].sha256 = 'd'.repeat(64);
  for (const claim of computed.claims) {
    for (const hash of claim.release_artifact_hashes) hash.sha256 = computed.release_artifacts[hash.artifact_id].sha256;
  }
  return { computed, bundleId, packageId };
}

test('the checked-in case is current against its own resolution in both modes', () => {
  const computed = fresh();
  assert.equal(serializeSecurityCase(computed), CHECKED_IN, 'the checked-in case is in the writer\'s serialization');
  assert.deepEqual(securityCaseDrift(CHECKED_IN, computed), { current: true, fields: [], denied: [] });
  assert.equal(strict(CHECKED_IN, computed).exitCode, 0);
  const result = pr(CHECKED_IN, computed);
  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.report, {
    '@version': DRIFT_REPORT_VERSION,
    writer: SECURITY_CASE_WRITER,
    current: true,
    stale: [],
    fields: [],
  });
});

test('stale derived digests pass a pull-request run and are reported, and fail a strict run', () => {
  const { computed, bundleId, packageId } = movedDigests();
  const drift = securityCaseDrift(CHECKED_IN, computed);
  assert.equal(drift.current, false);
  assert.deepEqual(drift.denied, []);
  for (const field of [
    'evidence_bundle_sha256',
    'evidence_files[0].sha256',
    `release_artifacts.${bundleId}.sha256`,
    `release_artifacts.${packageId}.sha256`,
  ]) assert.ok(drift.fields.includes(field), field);
  // Every claim bound to the evidence bundle carries a copy of its hash.
  const copies = drift.fields.filter((field) => /^claims\[\d+\]\.release_artifact_hashes\[\d+\]\.sha256$/.test(field));
  assert.equal(copies.length, computed.claims.filter((claim) => claim.release_artifacts.includes(bundleId)).length
    + computed.claims.filter((claim) => claim.release_artifacts.includes(packageId)).length);

  const advisory = pr(CHECKED_IN, computed);
  assert.equal(advisory.exitCode, 0);
  assert.deepEqual(advisory.report, {
    '@version': DRIFT_REPORT_VERSION,
    writer: SECURITY_CASE_WRITER,
    current: false,
    stale: [SECURITY_CASE],
    fields: drift.fields,
  });
  assert.match(advisory.messages.join('\n'), /only derived digests differ/);

  // main's refresh pull request, every release and publish workflow and a
  // plain local check run without --drift-report: the same drift fails.
  const exact = strict(CHECKED_IN, computed);
  assert.equal(exact.exitCode, 1);
  assert.equal(exact.report, null);
  assert.match(exact.messages[0], /security\/security-case\.json is stale; run npm run security-case:emit/);
});

test('a grown pinned file list, a package version bump and new counts are digest drift too', () => {
  const { computed, packageId } = movedDigests();
  computed.evidence_files.push({ path: 'lib/new-pinned-file.ts', sha256: 'c'.repeat(64) });
  computed.evidence_file_count += 1;
  const artifact = computed.release_artifacts[packageId];
  artifact.version = '99.0.0';
  artifact.filename = `${artifact.filename}.next`;
  artifact.file_count += 3;
  const drift = securityCaseDrift(CHECKED_IN, computed);
  assert.deepEqual(drift.denied, []);
  assert.ok(drift.fields.includes('evidence_files'));
  assert.ok(drift.fields.includes(`release_artifacts.${packageId}.version`));
  assert.equal(pr(CHECKED_IN, computed).exitCode, 0);
  assert.equal(strict(CHECKED_IN, computed).exitCode, 1);
});

test('a tampered human-authored claim fails in every mode, stale digests or not', () => {
  // The checked-in case edited by hand: a claim states more than its source.
  const tampered = fresh();
  tampered.claims[0].statement = `${tampered.claims[0].statement} In every deployment.`;
  const handEdited = serializeSecurityCase(tampered);
  for (const computed of [fresh(), movedDigests().computed]) {
    const result = pr(handEdited, computed);
    assert.equal(result.exitCode, 1);
    assert.deepEqual(securityCaseDrift(handEdited, computed).denied, ['claims[0].statement']);
    assert.match(result.messages.join('\n'), /drift outside the derived digests: claims\[0\]\.statement/);
    assert.equal(result.report.current, false);
    assert.equal(strict(handEdited, computed).exitCode, 1);
  }

  // security/claims.v1.json changed (a claim dropped a test) without the case
  // being regenerated: the fresh resolution restates the new claim.
  const edited = movedDigests().computed;
  edited.claims[1].tests = edited.claims[1].tests.slice(1);
  edited.claims[1].assumptions = [...edited.claims[1].assumptions, 'An assumption added in review.'];
  const denied = securityCaseDrift(CHECKED_IN, edited).denied;
  assert.ok(denied.some((field) => field.startsWith('claims[1].tests')), denied.join(', '));
  assert.ok(denied.includes('claims[1].assumptions'), denied.join(', '));
  assert.ok(denied.every((field) => !fieldAllowed(field, SECURITY_CASE_DERIVED_FIELDS)));
  assert.equal(pr(CHECKED_IN, edited).exitCode, 1);
});

test('everything outside the digests is strict: counts, execution, artifact identity, claim bindings', () => {
  const { computed: base, bundleId, packageId } = movedDigests();
  const cases = {
    claim_count: (c) => { c.claim_count += 1; },
    'execution.status': (c) => { c.execution.status = 'not_executed'; },
    'execution.evidence[0].result': (c) => { c.execution.evidence[0].result = 'failed'; },
    attestation_policy: (c) => { c.attestation_policy = 'none'; },
    [`release_artifacts.${bundleId}.kind`]: (c) => { c.release_artifacts[bundleId].kind = 'npm-tarball'; },
    [`release_artifacts.${packageId}.package`]: (c) => { c.release_artifacts[packageId].package = '@evil/verify'; },
    'claims[0].release_artifact_hashes[0].artifact_id': (c) => { c.claims[0].release_artifact_hashes[0].artifact_id = 'other'; },
    'claims[0].release_artifact_hashes': (c) => { c.claims[0].release_artifact_hashes.pop(); },
    'claims[0].release_artifacts': (c) => { c.claims[0].release_artifacts = [...c.claims[0].release_artifacts].reverse(); },
    claims: (c) => { c.claims.pop(); },
  };
  for (const [field, mutate] of Object.entries(cases)) {
    const recorded = structuredClone(base);
    mutate(recorded);
    const drift = securityCaseDrift(serializeSecurityCase(recorded), base);
    assert.ok(drift.denied.some((name) => name === field || name.startsWith(`${field}[`)), `${field}: ${drift.denied.join(', ')}`);
    assert.equal(pr(serializeSecurityCase(recorded), base).exitCode, 1, field);
  }
});

test('added, removed or retyped keys, reformatting and unparseable files are never advisory', () => {
  const { computed } = movedDigests();
  const without = fresh();
  delete without.evidence_bundle_sha256;
  assert.deepEqual(securityCaseDrift(serializeSecurityCase(without), computed).denied,
    ['evidence_bundle_sha256 (key added, removed or retyped)']);
  const retyped = fresh();
  retyped.evidence_file_count = String(retyped.evidence_file_count);
  assert.deepEqual(securityCaseDrift(serializeSecurityCase(retyped), computed).denied,
    ['evidence_file_count (key added, removed or retyped)']);
  const extra = { ...fresh(), unreviewed: true };
  assert.deepEqual(securityCaseDrift(serializeSecurityCase(extra), computed).denied, ['unreviewed (key added, removed or retyped)']);

  // Only digests differ, but the file is not the writer's serialization.
  for (const recordedText of [
    `${JSON.stringify(fresh(), null, 4)}\n`,
    JSON.stringify(fresh(), null, 2),
    serializeSecurityCase(Object.fromEntries(Object.entries(fresh()).reverse())),
  ]) {
    const drift = securityCaseDrift(recordedText, computed);
    assert.deepEqual(drift.denied, ['(serialization)']);
    assert.ok(drift.fields.includes('(serialization)'));
    assert.equal(pr(recordedText, computed).exitCode, 1);
  }
  assert.deepEqual(securityCaseDrift('{"claims": [', computed).denied, ['(unparseable)']);
  const refusing = () => { throw new Error('duplicate key'); };
  assert.deepEqual(securityCaseDrift(CHECKED_IN, computed, refusing).denied, ['(unparseable)']);
});

test('a missing checked-in case fails in both modes', () => {
  for (const driftReport of [false, true]) {
    const result = checkSecurityCase({ recordedText: null, computed: fresh(), driftReport });
    assert.equal(result.exitCode, 1);
    assert.match(result.messages[0], /security\/security-case\.json is missing/);
  }
  assert.deepEqual(checkSecurityCase({ recordedText: null, computed: fresh(), driftReport: true }).report.fields, ['(missing)']);
});

test('allowlist patterns match whole fields only, and odd keys never match a wildcard', () => {
  const allowed = (field) => fieldAllowed(field, SECURITY_CASE_DERIVED_FIELDS);
  for (const field of [
    'evidence_bundle_sha256',
    'evidence_file_count',
    'evidence_files',
    'evidence_files[3].path',
    'evidence_files[263].sha256',
    'release_artifacts.gate-sdk.sha256',
    'release_artifacts.security-evidence.file_count',
    'release_artifacts.verify-sdk.version',
    'release_artifacts.verify-sdk.filename',
    'claims[12].release_artifact_hashes[1].sha256',
  ]) assert.ok(allowed(field), field);
  for (const field of [
    'evidence_bundle_sha256x',
    'xevidence_bundle_sha256',
    'evidence_files[3]',
    'evidence_files[3].sha256.extra',
    'evidence_files[x].sha256',
    'release_artifacts.gate-sdk',
    'release_artifacts.gate-sdk.kind',
    'release_artifacts.gate-sdk.package',
    'release_artifacts["a.b"].sha256',
    'release_artifacts.gate-sdk.nested.sha256',
    'release_artifacts..sha256',
    'claims[1].release_artifact_hashes[0].artifact_id',
    'claims[1].release_artifact_hashes',
    'claims[1].statement',
    'claims',
    'claim_count',
    'execution.status',
    'evidence_bundle_sha256 (key added, removed or retyped)',
    '(serialization)',
    '(root)',
  ]) assert.ok(!allowed(field), field);
  assert.equal(renderPath(['release_artifacts', 'a.b', 'sha256']), 'release_artifacts["a.b"].sha256');
  assert.equal(renderPath(['claims', 2, 'statement']), 'claims[2].statement');
  assert.equal(renderPath([]), '(root)');
  assert.deepEqual(driftEntries({ a: [1, 2] }, { a: [1, 2, 3] }), [{ segments: ['a'], shape: false }]);
  assert.deepEqual(driftEntries(1, '1'), [{ segments: [], shape: true }]);
});

test('summaries group one changed file\'s many claim copies', () => {
  const { computed } = movedDigests();
  const summary = summarizeFields(securityCaseDrift(CHECKED_IN, computed).fields);
  assert.ok(summary.some((entry) => /^claims\[\]\.release_artifact_hashes\[\]\.sha256 \(\d+\)$/.test(entry)), summary.join(', '));
  assert.ok(summary.includes('evidence_bundle_sha256'));
  assert.deepEqual(summarizeFields(['claims[0].statement']), ['claims[0].statement']);
});

test('the security case writer makes exactly this comparison, and --drift-report needs an executed check run', () => {
  const source = readFileSync(join(ROOT, 'scripts/verify-security-case.mts'), 'utf8');
  assert.match(source, /import \{ checkSecurityCase \} from "\.\/ci\/derived-evidence-drift\.mjs";/);
  assert.match(source, /checkSecurityCase\(\{[\s\S]*?driftReport: Boolean\(driftReport\),[\s\S]*?\}\);/);
  assert.ok(!source.includes('checkedIn !== serialized'), 'no second byte comparison bypasses the shared one');
  assert.match(source, /if \(driftReport && !execute\)\s*throw new Error\(/);
  assert.match(source, /if \(driftReport && args\.includes\("--emit"\)\)\s*throw new Error\(/);
  const runtime = readFileSync(join(ROOT, 'scripts/verify-security-case.mjs'), 'utf8');
  assert.match(runtime, /from "\.\/ci\/derived-evidence-drift\.mjs"/);
});
