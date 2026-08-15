// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'vitest';
import {
  EVALUATOR_PROFILE_ID,
  buildCommitment,
  deriveReadSet,
  materializeCase,
  runCorpus,
  verifyReplay,
} from './run.mjs';

const corpus = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
const sourceLock = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));

test('the corpus pins one evaluator profile and has both construction and verification directions', () => {
  assert.equal(corpus['@version'], 'NOA-POLICY-REPLAY-CORPUS-v0.1');
  assert.equal(corpus.evaluator_profile, EVALUATOR_PROFILE_ID);
  assert.equal(corpus.cases.some((entry) => entry.direction === 'construct'), true);
  assert.equal(corpus.cases.some((entry) => entry.direction === 'verify'), true);
  assert.equal(corpus.cases.some((entry) => entry.expected.status === 'MATCH'), true);
  assert.equal(corpus.cases.some((entry) => entry.expected.status === 'MISMATCH'), true);
  assert.equal(corpus.cases.some((entry) => entry.expected.status === 'UNRESOLVED'), true);
});

test('construction vectors produce the exact four-member NOA compliance commitment', () => {
  for (const entry of corpus.cases.filter((candidate) => candidate.direction === 'construct')) {
    const materialized = materializeCase(corpus, entry);
    const actual = buildCommitment(materialized.policy, materialized.inputs, materialized.evaluator_profile);
    assert.deepEqual(actual, entry.expected.commitment, entry.id);
    assert.deepEqual(Object.keys(actual), ['policyHash', 'readSetHash', 'inputsHash', 'verdict']);
  }
});

test('verification vectors reproduce MATCH, MISMATCH, and explicit UNRESOLVED results', () => {
  for (const entry of corpus.cases.filter((candidate) => candidate.direction === 'verify')) {
    const materialized = materializeCase(corpus, entry);
    const actual = verifyReplay({
      commitment: materialized.commitment,
      policy: materialized.policy,
      inputs: materialized.inputs,
      evaluatorProfile: materialized.evaluator_profile,
    });
    assert.deepEqual(actual, entry.expected, entry.id);
  }
});

test('unknown evaluator profiles and missing material never become a policy DENY or ALLOW', () => {
  const source = corpus.cases.find((entry) => entry.id === 'verify-allow-match');
  const positive = source && materializeCase(corpus, source);
  assert.ok(positive);

  const unknown = verifyReplay({
    commitment: positive.commitment,
    policy: positive.policy,
    inputs: positive.inputs,
    evaluatorProfile: 'unregistered-evaluator/9',
  });
  assert.deepEqual(unknown, {
    status: 'UNRESOLVED',
    reason: 'evaluator_profile_unavailable',
    derived_verdict: null,
    classified_verdict: null,
  });

  const missing = verifyReplay({
    commitment: positive.commitment,
    policy: null,
    inputs: positive.inputs,
    evaluatorProfile: EVALUATOR_PROFILE_ID,
  });
  assert.deepEqual(missing, {
    status: 'UNRESOLVED',
    reason: 'policy_unavailable',
    derived_verdict: null,
    classified_verdict: null,
  });
});

test('the profile rejects ambiguous evaluator inputs before deriving a verdict', () => {
  const policy = structuredClone(corpus.fixtures.policy);
  const inputs = structuredClone(corpus.fixtures.inputs_allow);

  policy.requirement = 'authorization_receipt AND';
  assert.throws(
    () => buildCommitment(policy, inputs, EVALUATOR_PROFILE_ID),
    /policy_requirement_invalid/,
  );

  const badOutcome = structuredClone(corpus.fixtures.inputs_allow);
  badOutcome.bundle.components[0].outcome = 'DENY';
  assert.throws(
    () => buildCommitment(corpus.fixtures.policy, badOutcome, EVALUATOR_PROFILE_ID),
    /inputs_component_invalid/,
  );

  const impossibleDate = structuredClone(corpus.fixtures.inputs_allow);
  impossibleDate.as_of = '2026-02-31T12:05:00Z';
  assert.throws(
    () => buildCommitment(corpus.fixtures.policy, impossibleDate, EVALUATOR_PROFILE_ID),
    /inputs_as_of_invalid/,
  );

  const missingFreshnessEvidence = structuredClone(corpus.fixtures.inputs_allow);
  missingFreshnessEvidence.bundle.components[0].issued_at = null;
  assert.throws(
    () => buildCommitment(corpus.fixtures.policy, missingFreshnessEvidence, EVALUATOR_PROFILE_ID),
    /inputs_freshness_unprovable/,
  );

  const futureEvidence = structuredClone(corpus.fixtures.inputs_allow);
  futureEvidence.bundle.components[0].issued_at = '2026-08-14T12:06:00Z';
  assert.throws(
    () => buildCommitment(corpus.fixtures.policy, futureEvidence, EVALUATOR_PROFILE_ID),
    /inputs_freshness_unprovable/,
  );
});

test('the closed read set pins every decision-relevant input class in deterministic order', () => {
  assert.deepEqual(deriveReadSet(corpus.fixtures.policy), [
    'as_of',
    'bundle.action_digest',
    'bundle.components[].action_digest',
    'bundle.components[].issued_at',
    'bundle.components[].outcome',
    'bundle.components[].revoked',
    'bundle.components[].type',
    'bundle.components[].verified',
  ]);
});

test('the frozen NOA compliance block cannot carry the evaluator profile as an extra receipt member', () => {
  const commitment = {
    ...corpus.fixtures.commitment_allow,
    engine: EVALUATOR_PROFILE_ID,
  };
  assert.deepEqual(verifyReplay({
    commitment,
    policy: corpus.fixtures.policy,
    inputs: corpus.fixtures.inputs_allow,
    evaluatorProfile: EVALUATOR_PROFILE_ID,
  }), {
    status: 'MISMATCH',
    reason: 'commitment_malformed',
    derived_verdict: null,
    classified_verdict: null,
  });
});

test('the source lock pins the exact local evaluator, canonicalizer, adapter, and corpus bytes', () => {
  assert.equal(sourceLock['@version'], 'NOA-POLICY-REPLAY-SOURCE-LOCK-v0.1');
  for (const file of sourceLock.local_files) {
    const bytes = readFileSync(new URL(`../../../${file.path}`, import.meta.url));
    const actual = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(actual, file.sha256, file.path);
  }
});

test('the complete corpus passes and reports self-reproduction, not independent implementation', () => {
  const report = runCorpus(corpus);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.implementation_owner, 'EMILIA Protocol');
  assert.equal(report.independent_implementation, false);
  assert.equal(report.total, corpus.cases.length);
  assert.equal(report.passed_cases, corpus.cases.length);
});
