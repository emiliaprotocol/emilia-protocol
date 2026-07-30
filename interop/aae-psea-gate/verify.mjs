// SPDX-License-Identifier: Apache-2.0

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const URN_RE = /^urn:[A-Za-z0-9][A-Za-z0-9:._-]+$/;

const VALUES = Object.freeze({
  aae_native: ['ACCEPT', 'REJECT'],
  action_linkage: ['EQUIVALENT', 'NOT_EQUIVALENT', 'INDETERMINATE'],
  principal_linkage: ['SAME', 'DIVERGENT', 'UNRESOLVED'],
  evidence_satisfaction: ['SATISFIED', 'UNSATISFIED', 'NOT_EVALUATED'],
  decision: ['AUTHORIZED', 'REFUSED'],
  admission: ['NONE', 'RESERVED', 'CONSUMED', 'DISPATCH_PENDING', 'INVOKED'],
  outcome: ['EXECUTED', 'FAILED', 'INDETERMINATE', 'NONE'],
});

const ROW_NAMES = Object.freeze(Object.keys(VALUES));
const QUALIFYING_ADMISSIONS = new Set(['CONSUMED', 'DISPATCH_PENDING', 'INVOKED']);
const REQUIRED_CONSTRAINTS = Object.freeze([
  'non_none_outcome_requires_qualifying_admission',
  'indeterminate_outcome_requires_reason',
  'already_consumed_preserves_authorized_decision',
  'attempt_pair_preserves_authority_action_and_evidence',
]);

function fail(message) {
  throw new Error(message);
}

function object(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${path} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, path) {
  const actual = Object.keys(object(value, path)).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${path} fields must be exactly: ${wanted.join(', ')}`);
  }
}

function nonEmpty(value, path) {
  if (typeof value !== 'string' || value.length === 0) fail(`${path} must be a non-empty string`);
}

function digest(value, path) {
  if (typeof value !== 'string' || !SHA256_RE.test(value)) {
    fail(`${path} must be a lowercase sha256 digest`);
  }
}

function urn(value, path) {
  if (typeof value !== 'string' || !URN_RE.test(value)) fail(`${path} must be a URN`);
}

function validateRow(row, name, path) {
  const keys = Object.keys(object(row, path)).sort();
  if (!keys.includes('value') || keys.some((key) => !['value', 'reason', 'status'].includes(key))) {
    fail(`${path} fields must be value, optional reason, and optional status`);
  }
  if (!VALUES[name].includes(row.value)) {
    fail(`${path}.value must be one of: ${VALUES[name].join(', ')}`);
  }
  if ('reason' in row) nonEmpty(row.reason, `${path}.reason`);
  if ('status' in row) {
    if (name !== 'principal_linkage' || row.status !== 'PROPOSED') {
      fail(`${path}.status may only mark principal_linkage PROPOSED`);
    }
  }
}

function validateAttempt(attempt, expectedNumber) {
  const path = `attempts[${expectedNumber - 1}]`;
  exactKeys(attempt, ['attempt', 'rows', 'gate_custody'], path);
  if (attempt.attempt !== expectedNumber) fail(`${path}.attempt must be ${expectedNumber}`);
  exactKeys(attempt.rows, ROW_NAMES, `${path}.rows`);
  for (const name of ROW_NAMES) validateRow(attempt.rows[name], name, `${path}.rows.${name}`);
  exactKeys(
    attempt.gate_custody,
    ['reservation_id', 'execution_right', 'prior_admission'],
    `${path}.gate_custody`,
  );
  urn(attempt.gate_custody.reservation_id, `${path}.gate_custody.reservation_id`);
  if (!['RESERVED', 'RELEASED', 'CONSUMED'].includes(attempt.gate_custody.execution_right)) {
    fail(`${path}.gate_custody.execution_right is invalid`);
  }
  if (
    attempt.gate_custody.prior_admission !== null &&
    !QUALIFYING_ADMISSIONS.has(attempt.gate_custody.prior_admission)
  ) {
    fail(`${path}.gate_custody.prior_admission must be null or a qualifying admission`);
  }
}

function hasQualifyingAdmission(attempts, index) {
  for (let cursor = 0; cursor <= index; cursor += 1) {
    if (QUALIFYING_ADMISSIONS.has(attempts[cursor].rows.admission.value)) return true;
  }
  return false;
}

function validateAttemptSemantics(attempts) {
  for (const [index, attempt] of attempts.entries()) {
    const outcome = attempt.rows.outcome;
    if (outcome.value !== 'NONE' && !hasQualifyingAdmission(attempts, index)) {
      fail(`attempts[${index}]: non-NONE outcome requires a qualifying same-or-prior admission`);
    }
    if (outcome.value === 'INDETERMINATE' && !outcome.reason) {
      fail(`attempts[${index}].rows.outcome: INDETERMINATE requires a reason`);
    }
  }

  const [first, second] = attempts;
  if (first.rows.admission.value !== 'CONSUMED') {
    fail('attempts[0]: the first presentation must consume admission');
  }
  if (second.rows.decision.value !== 'AUTHORIZED') {
    fail('attempts[1]: already-consumed replay must preserve AUTHORIZED decision');
  }
  if (
    second.rows.admission.value !== 'NONE' ||
    second.rows.admission.reason !== 'already_consumed'
  ) {
    fail('attempts[1]: already-consumed replay must withhold admission as NONE/already_consumed');
  }
  if (second.rows.outcome.value !== 'NONE') {
    fail('attempts[1]: already-consumed replay must have outcome NONE');
  }
  if (second.gate_custody.prior_admission !== 'CONSUMED') {
    fail('attempts[1]: already-consumed replay must reference prior CONSUMED admission');
  }
  if (
    first.gate_custody.reservation_id !== second.gate_custody.reservation_id ||
    first.rows.aae_native.value !== second.rows.aae_native.value ||
    first.rows.action_linkage.value !== second.rows.action_linkage.value ||
    first.rows.principal_linkage.value !== second.rows.principal_linkage.value ||
    first.rows.evidence_satisfaction.value !== second.rows.evidence_satisfaction.value ||
    first.rows.decision.value !== second.rows.decision.value
  ) {
    fail('attempt pair must preserve reservation, native result, linkage, evidence, and decision');
  }
}

export function verifyGateAttemptPair(record) {
  exactKeys(
    record,
    [
      '@version',
      'profile',
      'source_fixture',
      'exchange_id',
      'authority_id',
      'authority_digest',
      'action_digest',
      'evidence_digest',
      'attempts',
      'constraints',
      'nonclaims',
    ],
    'record',
  );
  if (record['@version'] !== 'EMILIA-AAE-PSEA-GATE-ATTEMPT-PAIR-v1') {
    fail('unexpected attempt-pair version');
  }
  if (record.profile !== 'aae-psea-seven-field-crosswalk') fail('unexpected profile');
  urn(record.exchange_id, 'record.exchange_id');
  urn(record.authority_id, 'record.authority_id');
  digest(record.authority_digest, 'record.authority_digest');
  digest(record.action_digest, 'record.action_digest');
  digest(record.evidence_digest, 'record.evidence_digest');

  exactKeys(
    record.source_fixture,
    [
      'repository',
      'pull_request',
      'commit',
      'source_vector_commit',
      'path',
      'jws_digest',
      'action_payload_digest',
      'who_axis_status',
    ],
    'record.source_fixture',
  );
  if (record.source_fixture.repository !== 'https://github.com/MoltyCel/aae-conformance-vectors') {
    fail('source fixture repository is not the pinned AAE vector repository');
  }
  if (record.source_fixture.pull_request !== 6) fail('source fixture pull request must be 6');
  if (!/^[0-9a-f]{40}$/.test(record.source_fixture.commit)) {
    fail('source fixture commit must be a full Git commit');
  }
  if (!/^[0-9a-f]{40}$/.test(record.source_fixture.source_vector_commit)) {
    fail('source vector commit must be a full Git commit');
  }
  nonEmpty(record.source_fixture.path, 'record.source_fixture.path');
  digest(record.source_fixture.jws_digest, 'record.source_fixture.jws_digest');
  digest(record.source_fixture.action_payload_digest, 'record.source_fixture.action_payload_digest');
  if (record.source_fixture.who_axis_status !== 'PROPOSED') {
    fail('WHO axis must remain PROPOSED until issuer confirmation');
  }
  for (const [index, attempt] of record.attempts.entries()) {
    if (attempt?.rows?.principal_linkage?.status !== 'PROPOSED') {
      fail(`attempts[${index}].rows.principal_linkage must remain marked PROPOSED`);
    }
  }

  if (!Array.isArray(record.attempts) || record.attempts.length !== 2) {
    fail('record.attempts must contain exactly two attempts');
  }
  validateAttempt(record.attempts[0], 1);
  validateAttempt(record.attempts[1], 2);
  validateAttemptSemantics(record.attempts);

  if (!Array.isArray(record.constraints) || record.constraints.length !== REQUIRED_CONSTRAINTS.length) {
    fail('record.constraints must contain the four required constraints');
  }
  for (const constraint of REQUIRED_CONSTRAINTS) {
    if (!record.constraints.includes(constraint)) fail(`record.constraints is missing ${constraint}`);
  }

  exactKeys(
    record.nonclaims,
    ['psea_conformance', 'who_axis_confirmation', 'execution_order', 'provider_effect'],
    'record.nonclaims',
  );
  if (record.nonclaims.psea_conformance !== 'NOT_ESTABLISHED') {
    fail('PSEA conformance must remain NOT_ESTABLISHED');
  }
  if (record.nonclaims.who_axis_confirmation !== 'NOT_ESTABLISHED') {
    fail('WHO confirmation must remain NOT_ESTABLISHED');
  }
  if (record.nonclaims.execution_order !== 'NOT_ESTABLISHED') {
    fail('execution order must remain NOT_ESTABLISHED');
  }
  if (record.nonclaims.provider_effect !== 'INDETERMINATE') {
    fail('provider effect must remain INDETERMINATE');
  }

  return {
    valid: true,
    exchange_id: record.exchange_id,
    attempts: 2,
    second_admission: 'NONE',
    second_reason: 'already_consumed',
  };
}
