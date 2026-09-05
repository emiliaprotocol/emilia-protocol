// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { verifyOutcomeBindingSet } from '../../../packages/verify/index.js';
import {
  PROFILE,
  SOURCE_COMMIT,
  SOURCE_LOCK_DIGEST,
  buildNativeInputs,
  loadPinnedFixture,
  projectLeakedRefusal,
  runPinnedFixture,
  verifyReportDigest,
} from './adapter.mjs';

const SOURCE_LOCK = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
const RESULT_LOCK = JSON.parse(readFileSync(new URL('./result-lock.json', import.meta.url), 'utf8'));

test('the copied source bytes match the exact Cedulon commit lock', () => {
  const fixture = loadPinnedFixture();
  assert.equal(SOURCE_LOCK.commit, SOURCE_COMMIT);
  assert.equal(fixture.commit, SOURCE_COMMIT);
  for (const name of ['policy', 'decisions', 'sent']) {
    const expected = SOURCE_LOCK.files[name];
    const bytes = fixture.raw[name];
    assert.equal(bytes.length, expected.bytes, name);
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), expected.sha256, name);
  }
});

test('the adapter preserves the closed refusal/effect mapping', () => {
  const fixture = loadPinnedFixture();
  const projection = projectLeakedRefusal({
    decision: fixture.decisions[0],
    sent: fixture.sent[0],
    policyDigest: fixture.digests.policy,
  });

  assert.deepEqual(projection.refusal, {
    source_verdict: 'silent',
    decision: 'deny',
    ref: 'leak-1',
    reason_code: 'out-of-scope',
    request_hash: '3d72c0a9749af0024ccc1522c4a284d120248c9788e4716aae0a8b63fad06838',
    policy_hash: '41d79f176661c3ac24181dae71506e8d5738f0470102d9cdda1dd9222cfe0805',
    effect_hash: null,
    effect_class: 'ig-dm-reply',
    decided_at: '2023-11-14T23:13:20.000Z',
  });
  assert.deepEqual(projection.predicted_effect, {
    effect_type: 'ig-dm-reply',
    target: 'cedulon:mizan-ig:ref:leak-1',
    required_source_role: 'system_of_record',
    required_source_class: 'cedulon.mizan.sent-log',
    predicate: { op: 'absent' },
  });
  assert.deepEqual(projection.observed_effect, {
    effect_type: 'ig-dm-reply',
    target: 'cedulon:mizan-ig:ref:leak-1',
    value: 'b15dc10d0cfa6fd508515dd0e28a87f722225b94935852af7a447e73714a597d',
  });
});

test('the full Outcome Binding reader verifies both native signatures and reports divergence', async () => {
  const report = await runPinnedFixture();
  const result = report.outcome_binding;

  assert.equal(report.profile, PROFILE);
  assert.equal(result.checks.receipt_verified, true);
  assert.equal(result.checks.signed_predictions_bound, true);
  assert.equal(result.checks.observations_bound_to_receipt, true);
  assert.equal(result.checks.observation_set_reconciled, true);
  assert.equal(result.receipt_result.valid, true, JSON.stringify(result.receipt_result.errors));
  assert.equal(result.observation_set.observation_results[0].valid, true);
  assert.equal(result.lifecycle_state, 'reconciled');
  assert.equal(result.outcome, 'divergent');
  assert.equal(result.valid, false);
  assert.match(result.result_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.result_digest, RESULT_LOCK.outcome_binding_result_digest);
  assert.equal(result.observation_set.evaluations[0].outcome, 'divergent');
  assert.match(result.observation_set.evaluations[0].reasons.join(' '), /predicted absent/);
  assert.equal(report.claim_boundary.shared_raw_fixture, true);
  assert.equal(report.claim_boundary.native_format_interoperability, false);
  assert.equal(report.claim_boundary.failure_location_proven, false);
  assert.equal(report.claim_boundary.fixture_keys_secret, false);
  assert.equal(report.claim_boundary.real_identity_proven, false);
  assert.equal(report.claim_boundary.temporal_precommitment_proven, false);
});

test('the signed action and report bind the load-bearing source metadata', async () => {
  const native = await buildNativeInputs();
  const parameters = native.receipt.action.parameters;
  assert.equal(parameters.source_lock_digest, SOURCE_LOCK_DIGEST);
  assert.equal(parameters.source_mapping_sha256, SOURCE_LOCK.upstream_mapping.sha256);
  assert.equal(
    parameters.source_decision_profile_sha256,
    SOURCE_LOCK.decision_profile.sha256,
  );

  const report = await runPinnedFixture();
  assert.equal(report.source.source_lock_digest, SOURCE_LOCK_DIGEST);
  assert.equal(report.source.upstream_mapping.sha256, SOURCE_LOCK.upstream_mapping.sha256);
  assert.equal(report.source.decision_profile.sha256, SOURCE_LOCK.decision_profile.sha256);

  const tampered = structuredClone(report);
  tampered.source.upstream_mapping.sha256 = '0'.repeat(64);
  assert.equal(verifyReportDigest(tampered), false);
});

test('the fixture and its result digest are deterministic', async () => {
  const first = await runPinnedFixture();
  const second = await runPinnedFixture();
  assert.equal(first.outcome_binding.result_digest, second.outcome_binding.result_digest);
  assert.equal(first.report_digest, second.report_digest);
  assert.equal(first.report_digest, RESULT_LOCK.report_digest);
  assert.equal(verifyReportDigest(first), true);
});

test('any source-byte drift is refused before JSONL interpretation', () => {
  const fixture = loadPinnedFixture();
  const hostile = {
    ...fixture.raw,
    sent: Buffer.from(fixture.raw.sent.toString('utf8').replace('should-not-have-sent', 'changed-effect')),
  };
  assert.throws(
    () => loadPinnedFixture({ raw: hostile }),
    /source_digest_mismatch:sent/,
  );
});

test('a decision/effect reference substitution is refused by the mapping seam', () => {
  const fixture = loadPinnedFixture();
  assert.throws(
    () => projectLeakedRefusal({
      decision: fixture.decisions[0],
      sent: { ...fixture.sent[0], id: 'leak-2' },
      policyDigest: fixture.digests.policy,
    }),
    /source_ref_mismatch/,
  );
});

test('post-projection target tampering cannot retain a valid native observation', async () => {
  const native = await buildNativeInputs();
  const hostile = structuredClone(native.observations);
  hostile[0].observed_effects[0].target = 'cedulon:mizan-ig:ref:leak-2';

  const result = verifyOutcomeBindingSet(native.receipt, hostile, native.verifier_options);
  assert.equal(result.valid, false);
  assert.equal(result.lifecycle_state, 'indeterminate');
  assert.match(result.errors.join(' '), /outcome_source_signature_invalid/);
});
