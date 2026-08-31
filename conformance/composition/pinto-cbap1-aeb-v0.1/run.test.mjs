// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { runCrossingLab } from '../../../packages/verify/dist/crossing-lab.js';
import {
  PROFILE_DEFINITION,
  decodeDeterministicCbor,
  encodeDeterministicCbor,
  validateCbap1HttpsUri,
  verifyCbap1,
} from './workspace/adapter.mjs';
import { buildReport } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKSPACE = join(HERE, 'workspace');
const workspace = JSON.parse(readFileSync(join(WORKSPACE, 'workspace.json'), 'utf8'));
const artifact = JSON.parse(readFileSync(join(WORKSPACE, 'artifact.json'), 'utf8'));
const adapterEntry = workspace.config.adapters[workspace.adapter.id];

function verify(candidateArtifact = artifact, roots = adapterEntry.trust_roots, config = adapterEntry.config) {
  return verifyCbap1({
    artifact: candidateArtifact,
    trust_roots: roots,
    adapter_config: config,
    verification_time: Math.floor(Date.parse(workspace.evaluated_at) / 1_000),
  });
}

function withBundle(bundle) {
  const bytes = encodeDeterministicCbor(bundle);
  return {
    '@version': artifact['@version'],
    bundle_cbor: bytes.toString('base64url'),
    bundle_sha256: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`,
  };
}

test('fixture regeneration is byte-for-byte deterministic', () => {
  const result = spawnSync(process.execPath, [join(HERE, 'generate-fixture.mjs'), '--check'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /deterministic fixture check passed/);
});

test('strict CBAP-1 verification preserves every native positive-result axis', () => {
  const native = verify();
  assert.equal(native.ok, true, JSON.stringify(native));
  assert.deepEqual(native.result, {
    binding: 'valid',
    pre_execution_evidence: 'executor_attested',
    discoverability: 'complete',
    forum_acknowledgement: 'valid_exact',
    forum_operational_status: 'not_checked',
    selection_provenance: 'unilateral',
    access_binding: 'valid',
    notice_evidence: 'not_claimed',
    retrievability: 'not_checked',
    filing_window_status: 'open',
    policy_freshness: 'indeterminate',
    declared_effect: 'none',
    effect_acceptance: 'not_required',
    effect_trigger: 'not_applicable',
    effect_ordering: 'not_applicable',
    effect_application: 'not_applicable',
    reasons: [],
  });
  assert.equal(native.action_digest, 'sha256:583f036629ee9c38330efa6e722f63e86bcfc0a0c5019baddfc15969f07c9559');
  assert.match(native.authorization_digest, /^sha256:[0-9a-f]{64}$/);
});

test('fixture is direct CBAP-1 with exact acceptance, unilateral selection, and no active effect', () => {
  const bundleBytes = Buffer.from(artifact.bundle_cbor, 'base64url');
  const bundle = decodeDeterministicCbor(bundleBytes);
  assert.ok(encodeDeterministicCbor(bundle).equals(bundleBytes));
  const cpoCose = decodeDeterministicCbor(bundle.get(2), { allowTag18: true });
  const cpo = decodeDeterministicCbor(cpoCose.value[2]);
  const terms = cpo.get(3);
  assert.equal(cpo.get(4)[0], 0, 'exact acceptance must be embedded by digest');
  assert.deepEqual(cpo.get(5), [], 'CBAP-1 selection attestations must be empty');
  assert.equal(terms.get(11)[0], 0, 'declared contestation effect must be none');
});

test('CBOR uses CBAP-1 bytewise key ordering and refuses non-deterministic encodings', () => {
  const orderingProbe = encodeDeterministicCbor(new Map([[100, -1], [-1, 100]]));
  assert.equal(orderingProbe.toString('hex'), 'a2186420201864');
  assert.throws(() => decodeDeterministicCbor(Buffer.from('1801', 'hex')), /non-shortest/);
  assert.throws(() => decodeDeterministicCbor(Buffer.from('9f01ff', 'hex')), /indefinite|reserved/);
  assert.throws(() => decodeDeterministicCbor(Buffer.from('a201010102', 'hex')), /duplicate|unordered/);
});

test('native trust roots carry deterministic Ed25519 COSE_Key values, not host-specific SPKI wrappers', () => {
  for (const root of adapterEntry.trust_roots) {
    const key = Buffer.from(root.public_key, 'base64url');
    assert.equal(key.length, 42);
    assert.equal(key.subarray(0, 10).toString('hex'), 'a4010103322006215820');
    assert.equal(key.toString('base64url'), root.public_key);
  }
});

test('CBAP-1 HTTPS parser matches every normative URI probe in draft section 4.13', () => {
  const accepted = [
    'https://forum.example',
    'https://forum.example:443/cases?open=1',
    'https://[2001:db8::1]/cases',
    'https://[v1.a]/cases',
    'https://[V1.a]/cases',
    'https://forum.example/%2Fcase',
  ];
  const rejected = [
    'HTTPS://forum.example/',
    'https://',
    'https://user@forum.example/',
    'https://forum.example:/',
    'https://forum.example:65536/',
    'https://forum.example/%2/',
    'https://forum.example/#part',
    'https://[:::]/',
    'https://[v1.]/',
    'https://[fe80::1%25eth0]/',
    'https://forum.example/a[b]',
    'https://forum.example/?a=[b]',
  ];
  for (const uri of accepted) assert.equal(validateCbap1HttpsUri(uri), true, uri);
  for (const uri of rejected) assert.equal(validateCbap1HttpsUri(uri), false, uri);
});

test('outer bytes, action bytes, policies, and trust substitution fail closed', () => {
  const badOuter = { ...artifact, bundle_sha256: `sha256:${'0'.repeat(64)}` };
  assert.equal(verify(badOuter).reason, 'outer_encoding_invalid');

  const changedActionBundle = decodeDeterministicCbor(Buffer.from(artifact.bundle_cbor, 'base64url'));
  changedActionBundle.set(7, Buffer.from('{"account_ref":"account:mallory","action_type":"account.suspend.1","policy_event_ref":"policy-event:risk-2026-08-29-001"}', 'utf8'));
  assert.equal(verify(withBundle(changedActionBundle)).reason, 'action_digest_mismatch');

  const changedPolicyBundle = decodeDeterministicCbor(Buffer.from(artifact.bundle_cbor, 'base64url'));
  const policies = changedPolicyBundle.get(8);
  policies[0] = [policies[0][0], Buffer.concat([policies[0][1], Buffer.from('tampered')])];
  assert.equal(verify(withBundle(changedPolicyBundle)).reason, 'policy_set_invalid');

  const roots = structuredClone(adapterEntry.trust_roots);
  const issuer = roots.find((root) => root.role === 'issuer');
  issuer.public_key = roots.find((root) => root.role === 'forum').public_key;
  assert.equal(verify(artifact, roots).reason, 'cpo_invalid');
});

test('closed first-failure precedence validates time before malformed bundle bytes', () => {
  const malformed = { '@version': artifact['@version'], bundle_cbor: 'AA', bundle_sha256: `sha256:${'0'.repeat(64)}` };
  const native = verifyCbap1({
    artifact: malformed,
    trust_roots: [],
    adapter_config: {},
    verification_time: '-1',
  });
  assert.deepEqual(native.reasons, ['verification_time_invalid']);
});

test('profile keeps a historical system-evidence role and excludes unimplemented native surfaces', () => {
  assert.equal(PROFILE_DEFINITION.evidence_role, 'contestability-binding');
  assert.equal(PROFILE_DEFINITION.claim_scope, 'historical-contestability-binding-only');
  assert.deepEqual(PROFILE_DEFINITION.excluded_native_features, [
    'active_effects',
    'class_manifest',
    'companion_binding',
    'external_selection',
    'multiparty_selection',
    'notices',
    'same_object_scitt',
  ]);
  assert.equal(workspace.config.registry.entries['role:contestability-binding'].definition.authorization_semantics, false);
  assert.deepEqual(workspace.config.registry.entries['role:contestability-binding'].definition.subject_kinds, ['system']);
});

test('Crossing Lab passes the positive, substitution, status, replay, and harness rows', () => {
  const report = runCrossingLab(WORKSPACE);
  assert.equal(report.lab_passed, true);
  assert.deepEqual(report.summary, {
    adapter_rows: 6,
    passed: 6,
    failed: 0,
    harness_passed: 4,
    harness_failed: 0,
  });
  assert.ok(report.adapter_rows.every((row) => row.passed));
  assert.ok(report.harness_self_tests.every((row) => row.passed));
  assert.ok(report.non_claims.includes('authorization'));
  assert.ok(report.non_claims.includes('native_protocol_equivalence'));
});

test('reference report is deterministic and digest-bound', () => {
  const first = buildReport();
  const second = buildReport();
  const reference = JSON.parse(readFileSync(join(HERE, 'report.reference.json'), 'utf8'));
  assert.deepEqual(first, second);
  assert.deepEqual(first, reference);
  assert.match(first.report_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.claim_boundary.execution_authority, false);
  assert.equal(first.claim_boundary.independent_implementation, false);
});
