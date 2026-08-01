// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION,
  AEB_CONSEQUENCE_CONFORMANCE_VERSION,
  AEB_CONSEQUENCE_LIMITS,
  AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
  AebConsequenceConformanceError,
  canonicalizeAebConsequenceConformance,
  digestAebConsequenceCase,
  digestAebConsequenceConformance,
  evaluateAebConsequenceCase,
  evaluateAebConsequenceSuite,
  parseAebConsequenceCase,
  validateAebConsequenceConformanceSuite,
  validateAebConsequenceResult,
  validateAebConsequenceSubmission,
} from './aeb-consequence-conformance.js';

const suite = JSON.parse(fs.readFileSync(
  new URL('../../conformance/vectors/aeb-consequence-conformance.v1.json', import.meta.url),
  'utf8',
));

const REQUIRED_VECTOR_IDS = [
  'authorized_admission',
  'native_verification_failure',
  'same_caid_different_normalized_action',
  'exact_action_mismatch',
  'machine_permit_missing_human_role',
  'duplicate_principal_quorum_refused',
  'initiator_self_approval_refused',
  'executor_self_approval_refused',
  'stale_evidence',
  'revoked_evidence',
  'status_unavailable',
  'unpinned_status_rejected',
  'atomic_reservation_unavailable',
  'operation_replay',
  'native_evidence_rewrapped',
  'timeout_after_dispatch',
  'blind_retry_refused',
  'unauthenticated_reconciliation_refused',
  'authenticated_executed_reconciliation',
  'provider_committed_effect_diverged',
  'provider_unknown_effect_unknown',
  'provider_proven_not_committed',
];

function vector(id: string): any {
  const found = suite.vectors.find((entry: any) => entry.id === id);
  assert.ok(found, `missing vector ${id}`);
  return found;
}

test('publishes the closed local_atomic AEB consequence-admission hostile suite', () => {
  const checked = validateAebConsequenceConformanceSuite(suite);
  assert.equal(checked.valid, true, JSON.stringify(checked));
  assert.equal(suite['@version'], AEB_CONSEQUENCE_CONFORMANCE_VERSION);
  assert.deepEqual(suite.claim_scope, AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE);
  assert.equal(suite.claim_scope.profile, 'local_atomic');
  assert.ok(suite.claim_scope.exclusions.includes('remote_atomicity'));
  assert.ok(suite.claim_scope.exclusions.includes('federated_atomicity'));
  assert.deepEqual(suite.vectors.map((entry: any) => entry.id), REQUIRED_VECTOR_IDS);
});

test('reference evaluator reproduces every exact expected row', () => {
  for (const entry of suite.vectors) {
    assert.deepEqual(evaluateAebConsequenceCase(entry.input), entry.expected, entry.id);
  }
});

test('verification, action match, satisfaction, authorization, reservation, and custody remain distinct', () => {
  const happy = evaluateAebConsequenceCase(vector('authorized_admission').input);
  assert.deepEqual(happy, {
    verification: 'VERIFIED',
    acceptance: 'ACCEPTED',
    action_match: 'MATCH',
    satisfaction: 'SATISFIED',
    authorization: 'AUTHORIZED',
    reservation: 'RESERVED',
    custody: 'RESERVED',
    provider_outcome: 'NOT_INVOKED',
    effect_relation: 'NOT_OBSERVED',
    retry: 'NOT_APPLICABLE',
    reconciliation: 'NOT_APPLICABLE',
    decision: 'ADMIT',
    reasons: [],
  });

  const noHuman = evaluateAebConsequenceCase(vector('machine_permit_missing_human_role').input);
  assert.equal(noHuman.verification, 'VERIFIED');
  assert.equal(noHuman.acceptance, 'ACCEPTED');
  assert.equal(noHuman.action_match, 'MATCH');
  assert.equal(noHuman.satisfaction, 'UNSATISFIED');
  assert.equal(noHuman.authorization, 'NOT_AUTHORIZED');
  assert.equal(noHuman.reservation, 'NOT_ATTEMPTED');
  assert.equal(noHuman.provider_outcome, 'NOT_INVOKED');
  assert.equal(noHuman.effect_relation, 'NOT_OBSERVED');
});

test('CAID and normalized action must both match exactly', () => {
  const sameCaid = vector('same_caid_different_normalized_action');
  assert.equal(sameCaid.input.evidence[0].mapped_caid, sameCaid.input.operation.caid);
  assert.notEqual(
    sameCaid.input.evidence[0].mapped_action_digest,
    sameCaid.input.operation.normalized_action_digest,
  );
  assert.equal(evaluateAebConsequenceCase(sameCaid.input).action_match, 'MISMATCH');

  const otherCaid = vector('exact_action_mismatch');
  assert.notEqual(otherCaid.input.evidence[0].mapped_caid, otherCaid.input.operation.caid);
  assert.equal(evaluateAebConsequenceCase(otherCaid.input).action_match, 'MISMATCH');
});

test('stale and unavailable status are indeterminate while authenticated revocation is unsatisfied', () => {
  const stale = evaluateAebConsequenceCase(vector('stale_evidence').input);
  const unavailable = evaluateAebConsequenceCase(vector('status_unavailable').input);
  const revoked = evaluateAebConsequenceCase(vector('revoked_evidence').input);

  assert.equal(stale.verification, 'VERIFIED');
  assert.equal(stale.acceptance, 'INDETERMINATE');
  assert.equal(stale.satisfaction, 'INDETERMINATE');
  assert.equal(stale.decision, 'INDETERMINATE');
  assert.equal(unavailable.satisfaction, 'INDETERMINATE');
  assert.equal(unavailable.decision, 'INDETERMINATE');
  assert.equal(revoked.verification, 'VERIFIED');
  assert.equal(revoked.acceptance, 'REJECTED');
  assert.equal(revoked.satisfaction, 'UNSATISFIED');
  assert.equal(revoked.decision, 'REFUSE');
});

test('RP acceptance remains explicit and rejects an unpinned status authority', () => {
  const unpinned = evaluateAebConsequenceCase(vector('unpinned_status_rejected').input);
  assert.equal(unpinned.verification, 'VERIFIED');
  assert.equal(unpinned.acceptance, 'REJECTED');
  assert.equal(unpinned.action_match, 'MATCH');
  assert.equal(unpinned.satisfaction, 'UNSATISFIED');
  assert.equal(unpinned.authorization, 'NOT_AUTHORIZED');
});

test('distinct-human quorum and initiator/executor exclusions are executable', () => {
  const duplicate = evaluateAebConsequenceCase(vector('duplicate_principal_quorum_refused').input);
  const initiator = evaluateAebConsequenceCase(vector('initiator_self_approval_refused').input);
  const executor = evaluateAebConsequenceCase(vector('executor_self_approval_refused').input);

  for (const refused of [duplicate, initiator, executor]) {
    assert.equal(refused.verification, 'VERIFIED');
    assert.equal(refused.acceptance, 'ACCEPTED');
    assert.equal(refused.action_match, 'MATCH');
    assert.equal(refused.satisfaction, 'UNSATISFIED');
    assert.equal(refused.authorization, 'NOT_AUTHORIZED');
    assert.equal(refused.decision, 'REFUSE');
  }
  assert.deepEqual(duplicate.reasons, ['distinct_principal_quorum_unsatisfied']);
  assert.deepEqual(initiator.reasons, ['initiator_self_approval_refused']);
  assert.deepEqual(executor.reasons, ['executor_self_approval_refused']);
});

test('local reservation refuses operation replay and native replay across a new wrapper', () => {
  const operationReplay = vector('operation_replay');
  const rewrapped = vector('native_evidence_rewrapped');

  assert.equal(evaluateAebConsequenceCase(operationReplay.input).reservation, 'OPERATION_REPLAY');
  assert.notEqual(
    rewrapped.input.evidence[0].wrapper_digest,
    rewrapped.input.evidence[0].native_replay_unit,
  );
  assert.ok(rewrapped.input.reservation.consumed_native_replay_units.includes(
    rewrapped.input.evidence[0].native_replay_unit,
  ));
  assert.equal(evaluateAebConsequenceCase(rewrapped.input).reservation, 'NATIVE_EVIDENCE_REPLAY');
});

test('INVOKING is consumed custody and timeout cannot be blindly retried', () => {
  const timedOut = evaluateAebConsequenceCase(vector('timeout_after_dispatch').input);
  assert.equal(timedOut.reservation, 'CONSUMED');
  assert.equal(timedOut.custody, 'INVOKING');
  assert.equal(timedOut.provider_outcome, 'INDETERMINATE');
  assert.equal(timedOut.effect_relation, 'INDETERMINATE');
  assert.equal(timedOut.retry, 'REFUSED');
  assert.equal(timedOut.reconciliation, 'REQUIRED');

  const retry = evaluateAebConsequenceCase(vector('blind_retry_refused').input);
  assert.equal(retry.reservation, 'OPERATION_REPLAY');
  assert.equal(retry.custody, 'INVOKING');
  assert.equal(retry.provider_outcome, 'INDETERMINATE');
  assert.equal(retry.effect_relation, 'INDETERMINATE');
  assert.equal(retry.retry, 'REFUSED');
  assert.ok(retry.reasons.includes('blind_retry_refused'));
});

test('provider truth and observed-effect truth are independent axes', () => {
  const diverged = evaluateAebConsequenceCase(vector('provider_committed_effect_diverged').input);
  assert.equal(diverged.provider_outcome, 'COMMITTED');
  assert.equal(diverged.effect_relation, 'DIVERGED');
  assert.equal(diverged.custody, 'TERMINAL');

  const unknown = evaluateAebConsequenceCase(vector('provider_unknown_effect_unknown').input);
  assert.equal(unknown.provider_outcome, 'INDETERMINATE');
  assert.equal(unknown.effect_relation, 'INDETERMINATE');
  assert.equal(unknown.custody, 'INVOKING');

  const notCommitted = evaluateAebConsequenceCase(vector('provider_proven_not_committed').input);
  assert.equal(notCommitted.provider_outcome, 'PROVEN_NOT_COMMITTED');
  assert.equal(notCommitted.effect_relation, 'NOT_OBSERVED');
  assert.equal(notCommitted.custody, 'TERMINAL');

  for (const result of [diverged, unknown, notCommitted]) {
    assert.equal(Object.hasOwn(result, 'effect'), false);
  }
});

test('only authenticated exact-operation evidence reconciles to committed and observed', () => {
  const refused = evaluateAebConsequenceCase(vector('unauthenticated_reconciliation_refused').input);
  assert.equal(refused.reconciliation, 'REFUSED');
  assert.equal(refused.provider_outcome, 'INDETERMINATE');
  assert.equal(refused.effect_relation, 'INDETERMINATE');
  assert.equal(refused.custody, 'INVOKING');

  const executed = evaluateAebConsequenceCase(vector('authenticated_executed_reconciliation').input);
  assert.equal(executed.reconciliation, 'ACCEPTED');
  assert.equal(executed.provider_outcome, 'COMMITTED');
  assert.equal(executed.effect_relation, 'OBSERVED_AS_REQUESTED');
  assert.equal(executed.custody, 'TERMINAL');
  assert.equal(executed.decision, 'RECONCILED');
});

test('case, nested objects, and result schemas reject unknown keys', () => {
  const input = vector('authorized_admission').input;
  const cases = [
    { ...input, surprise: true },
    { ...input, operation: { ...input.operation, surprise: true } },
    { ...input, evidence: [{ ...input.evidence[0], surprise: true }] },
    { ...input, evidence: [{ ...input.evidence[0], status: { ...input.evidence[0].status, surprise: true } }] },
    { ...input, reservation: { ...input.reservation, surprise: true } },
  ];

  for (const malformed of cases) {
    assert.throws(
      () => parseAebConsequenceCase(malformed),
      (error: unknown) => error instanceof AebConsequenceConformanceError
        && error.code === 'unknown_key',
    );
  }

  const observed = vector('provider_committed_effect_diverged').input;
  assert.throws(
    () => parseAebConsequenceCase({ ...observed, observation: { ...observed.observation, surprise: true } }),
    (error: unknown) => error instanceof AebConsequenceConformanceError
      && error.code === 'unknown_key',
  );

  const actual = evaluateAebConsequenceCase(input);
  assert.equal(validateAebConsequenceResult({ ...actual, surprise: true }).valid, false);
});

test('schema limits bound strings, arrays, nodes, and depth', () => {
  const input = vector('authorized_admission').input;
  assert.throws(
    () => parseAebConsequenceCase({ ...input, id: 'x'.repeat(AEB_CONSEQUENCE_LIMITS.max_string_bytes + 1) }),
    (error: unknown) => error instanceof AebConsequenceConformanceError
      && error.code === 'invalid_string',
  );
  assert.throws(
    () => parseAebConsequenceCase({
      ...input,
      evidence: Array.from({ length: AEB_CONSEQUENCE_LIMITS.max_evidence + 1 }, () => input.evidence[0]),
    }),
    (error: unknown) => error instanceof AebConsequenceConformanceError
      && error.code === 'invalid_array',
  );

  let nested: any = null;
  for (let index = 0; index <= AEB_CONSEQUENCE_LIMITS.max_depth; index += 1) nested = [nested];
  assert.throws(
    () => canonicalizeAebConsequenceConformance(nested),
    (error: unknown) => error instanceof AebConsequenceConformanceError
      && error.code === 'max_depth_exceeded',
  );
});

test('canonicalization rejects every property or array state that its bytes cannot cover', () => {
  const hidden = { visible: true } as Record<string, unknown>;
  Object.defineProperty(hidden, 'hidden', { value: 'unsigned', enumerable: false });

  const symbol = { visible: true } as Record<PropertyKey, unknown>;
  symbol[Symbol('unsigned')] = 'unsigned';

  let getterCalls = 0;
  const accessor = {} as Record<string, unknown>;
  Object.defineProperty(accessor, 'secret', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'unsigned';
    },
  });

  const sparse = [1, , 3];
  const extended = [1, 2] as unknown[] & Record<string, unknown>;
  extended.extra = 'unsigned';

  for (const value of [hidden, symbol, accessor, sparse, extended, new Map([['a', 1]])]) {
    assert.throws(
      () => canonicalizeAebConsequenceConformance(value),
      (error: unknown) => error instanceof AebConsequenceConformanceError
        && error.code === 'non_canonical_value',
    );
  }
  assert.equal(getterCalls, 0, 'canonicalization must inspect descriptors without invoking accessors');
});

test('evaluation and digests are deterministic and consume no ambient clock', () => {
  const input = vector('authorized_admission').input;
  const before = evaluateAebConsequenceCase(input);
  const originalNow = Date.now;
  Date.now = () => 0;
  try {
    assert.deepEqual(evaluateAebConsequenceCase(input), before);
  } finally {
    Date.now = originalNow;
  }

  assert.equal(
    canonicalizeAebConsequenceConformance({ b: 2, a: 1 }),
    canonicalizeAebConsequenceConformance({ a: 1, b: 2 }),
  );
  assert.equal(digestAebConsequenceCase(input), digestAebConsequenceCase(structuredClone(input)));
  assert.match(digestAebConsequenceConformance(suite), /^sha256:[0-9a-f]{64}$/);
});

test('self-attested report binds local_atomic scope, suite, implementation identity, and exact rows', () => {
  const report = evaluateAebConsequenceSuite(suite, {
    id: 'example:reference-kernel',
    version: '1.2.3',
    revision: 'git:0123456789abcdef',
  });

  assert.equal(report['@version'], AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION);
  assert.equal(report.suite_digest, digestAebConsequenceConformance(suite));
  assert.deepEqual(report.claim_scope, AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE);
  assert.deepEqual(report.implementation, {
    id: 'example:reference-kernel', version: '1.2.3', revision: 'git:0123456789abcdef',
  });
  assert.deepEqual(report.rows.map((row) => row.id), REQUIRED_VECTOR_IDS);
  assert.deepEqual(report.rows.map((row) => row.expected), suite.vectors.map((entry: any) => entry.expected));
  assert.equal(report.assurance.self_attested, true);
  assert.equal(report.assurance.certification, false);
  assert.equal(report.assurance.statement, 'SELF_ATTESTED_NOT_CERTIFICATION');
  assert.deepEqual(report.summary, { total: REQUIRED_VECTOR_IDS.length, passed: REQUIRED_VECTOR_IDS.length, failed: 0 });
  assert.match(report.report_digest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(report, evaluateAebConsequenceSuite(suite, report.implementation));

  const checked = validateAebConsequenceSubmission(suite, report);
  assert.equal(checked.valid, true, JSON.stringify(checked));
  assert.equal(checked.conformant, true);
});

test('submission validator rejects scope, row, identity, assurance, digest, and unknown-key tampering', () => {
  const report = evaluateAebConsequenceSuite(suite, {
    id: 'example:reference-kernel', version: '1.2.3', revision: 'git:0123456789abcdef',
  });
  const tampered = [
    { ...report, suite_digest: `sha256:${'0'.repeat(64)}` },
    { ...report, claim_scope: { ...report.claim_scope, profile: 'federated' } },
    { ...report, implementation: { ...report.implementation, revision: '' } },
    { ...report, rows: report.rows.slice(1) },
    { ...report, rows: report.rows.map((row, index) => index === 0 ? { ...row, id: 'wrong' } : row) },
    { ...report, assurance: { ...report.assurance, certification: true } },
    { ...report, report_digest: `sha256:${'0'.repeat(64)}` },
    { ...report, unknown: true },
  ];

  for (const submission of tampered) {
    assert.equal(validateAebConsequenceSubmission(suite, submission).valid, false);
  }
});
