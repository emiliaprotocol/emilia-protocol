// SPDX-License-Identifier: Apache-2.0
/**
 * Source-pinned WIMSE R10 native-mechanism matrix and EMILIA/AEB host-carrier
 * profile.
 *
 * The matrix reports what each pinned source defines today. The runnable
 * carrier is a candidate host profile. It does not add fields to the current
 * Asor, HAMR, AgentEnvelope, OAuth, or WIMSE drafts.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AEB_CONSEQUENCE_CASE_VERSION,
  AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
  canonicalizeAebConsequenceConformance,
  evaluateAebConsequenceCase,
  parseAebConsequenceCase,
} from '../../../packages/verify/dist/aeb-consequence-conformance.js';

export const PROFILE = 'WIMSE-R10-AEB-HOST-CARRIER-v0.1';
export const REPORT_VERSION = 'WIMSE-R10-AEB-REPORT-v0.1';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../../..');
const MATRIX_PATH = resolve(HERE, 'matrix.json');
const SOURCE_LOCK_PATH = resolve(HERE, 'source-lock.json');
const VECTORS_PATH = resolve(HERE, 'vectors.json');
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');

const MATRIX = JSON.parse(readFileSync(MATRIX_PATH, 'utf8'));
const SOURCE_LOCK = JSON.parse(readFileSync(SOURCE_LOCK_PATH, 'utf8'));
const VECTORS = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));

const EXPECTED_SOURCE_PINS = Object.freeze({
  'draft-reece-wimse-cross-org-delegation-02':
    '26dca19bc9c4c284b0c2fcdeab9f2abf9231397b9f6df87cb44f2fcc3adf5186',
  'draft-asor-wimse-agent-delegation-chain-00':
    'c36d32864cbdb0405e766cc1485e9197e20ad840dcd4c5ae653ad016c9074ccf',
  'draft-hamr-oauth-agent-delegation-00':
    'c8b7eff492d0630ebb5dd26c2f603faa6d325dfcae6832329de39d8af6799729',
  'draft-mcphillips-agentenvelope-derived-authority-01':
    '574beda17575ec8d0be512048708f19af4d910269569c6518c051d71ea58c531',
  'draft-schrock-action-evidence-boundary-04':
    '23d4daa5e436c4dc321c5e21e75f20965c6430c9807a3007e9c84762d33df63f',
  'draft-schrock-canonical-action-identifier-02':
    '38b3aa55b58c11a89028a64b7a6dbb911cc9b05efad62bb77a0d8a9891ed3cc2',
  'draft-schrock-ep-authorization-evidence-chain-05':
    'ea906a245e5e193d6edf3ae52e77810ea1ffa6d06bdfd3ab962be602d91662b7',
});

const EXPECTED_LOCAL_PINS = Object.freeze({
  'packages/verify/src/aeb-wimse-oauth-adapter.ts':
    '4002f26e3d4596879b7701f02253e0c37af3fd7fe4ffb0737a297aba857284b4',
  'packages/verify/dist/aeb-consequence-conformance.js':
    '6572b0814c5665ba729a20c3c26fc16857a050ba4360900fa13eb5931d90e98f',
  'packages/verify/src/aeb-adapter-contract.ts':
    '38375c23afb5ecc88006d6ce2725cf6e3a94322ddf07ac4de4e7cf4ad404d66a',
  'standards/archive/draft-schrock-action-evidence-boundary-04.txt':
    '23d4daa5e436c4dc321c5e21e75f20965c6430c9807a3007e9c84762d33df63f',
  'standards/posted/draft-schrock-canonical-action-identifier-02.txt':
    '38b3aa55b58c11a89028a64b7a6dbb911cc9b05efad62bb77a0d8a9891ed3cc2',
  'standards/posted/draft-schrock-ep-authorization-evidence-chain-05.txt':
    'ea906a245e5e193d6edf3ae52e77810ea1ffa6d06bdfd3ab962be602d91662b7',
});

const GRADE_BY_SIGNAL = Object.freeze({
  exact_action: Object.freeze({
    request_bound_class_and_constraints: 'PARTIAL',
    signed_request_opaque_scope: 'PARTIAL',
    complete_canonical_action: 'MET',
    mapped_exact_request: 'MET',
    host_required_action_binding: 'MET',
  }),
  target: Object.freeze({
    native_resource_or_location: 'MET',
    opaque_scope_convention: 'EXTERNAL_PROFILE_REQUIRED',
    mapped_request_target: 'MET',
    host_required_target_binding: 'MET',
  }),
  acting_for_principal: Object.freeze({
    absent: 'NOT_MET',
    root_delegator_not_invariant: 'PARTIAL',
    owner_or_custody_not_r5_chain: 'PARTIAL',
    workload_only: 'NOT_MET',
    explicit_invariant: 'MET',
  }),
  offline_verifiability: Object.freeze({
    full_native_verification: 'MET',
    authority_only: 'PARTIAL',
    pinned_local_inputs: 'MET',
  }),
  execution_time_required_evidence: Object.freeze({
    absent: 'NOT_MET',
    closed_vocabulary: 'NOT_SUPPORTED',
    generic_legitimacy: 'PARTIAL',
    workload_only: 'NOT_MET',
    host_required_human_evidence: 'MET',
  }),
  monotonic_non_droppable_carriage: Object.freeze({
    undefined_extension_point: 'EXTERNAL_PROFILE_REQUIRED',
    closed_vocabulary: 'NOT_SUPPORTED',
    single_hop_required_reference: 'PARTIAL',
    absent: 'NOT_MET',
    recursive_non_droppable: 'MET',
  }),
  at_most_once_local_admission: Object.freeze({
    explicit_side_effect_free: 'NOT_MET',
    explicit_external_replay_state: 'EXTERNAL_PROFILE_REQUIRED',
    external_state_required: 'EXTERNAL_PROFILE_REQUIRED',
    external_aeb_lifecycle: 'EXTERNAL_PROFILE_REQUIRED',
    aeb_local_atomic: 'MET',
  }),
  consume_only_on_admission: Object.freeze({
    absent: 'NOT_MET',
    external_aeb_lifecycle: 'EXTERNAL_PROFILE_REQUIRED',
    aeb_local_atomic: 'MET',
  }),
  indeterminate_state: Object.freeze({
    binary_permit_deny: 'NOT_MET',
    uniform_rejection: 'NOT_MET',
    generic_unavailable_reason: 'PARTIAL',
    typed_indeterminate: 'MET',
  }),
  no_blind_retry: Object.freeze({
    absent: 'NOT_MET',
    external_aeb_lifecycle: 'EXTERNAL_PROFILE_REQUIRED',
    aeb_local_atomic: 'MET',
  }),
});

const KNOWN_REQUIRED_EVIDENCE_PROFILES = new Set(
  VECTORS.known_required_evidence_profiles,
);
const EVALUATED_AT = VECTORS.evaluated_at;
const STATUS_CHECKED_AT = '2026-08-31T19:59:00Z';
const STATUS_VALID_UNTIL = '2026-08-31T21:00:00Z';
const PROVIDER_ID = 'provider:payments-primary';
const INITIATOR_ID = 'agent:treasury-orchestrator';
const EXECUTOR_ID = 'workload:payment-executor';

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha256Digest(bytes) {
  return `sha256:${sha256Hex(bytes)}`;
}

function canonicalBytes(value) {
  return Buffer.from(canonicalizeAebConsequenceConformance(value), 'utf8');
}

function digestJson(value) {
  return sha256Digest(canonicalBytes(value));
}

function sameJson(left, right) {
  return canonicalizeAebConsequenceConformance(left)
    === canonicalizeAebConsequenceConformance(right);
}

function copyJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function actionBinding(action) {
  const bytes = canonicalBytes(action);
  const actionHash = crypto.createHash('sha256').update(bytes).digest();
  return Object.freeze({
    caid: `caid:1:${action.action_type}:jcs-sha256:${actionHash.toString('base64url')}`,
    normalized_action_digest: `sha256:${actionHash.toString('hex')}`,
  });
}

function allDeclaredSourcePins() {
  return [
    SOURCE_LOCK.requirements_source,
    ...SOURCE_LOCK.native_sources,
    ...SOURCE_LOCK.emilia_sources,
  ];
}

export function verifySourceLock() {
  const failures = [];
  const declared = new Map(
    allDeclaredSourcePins().map((entry) => [entry.revision, entry.sha256]),
  );
  for (const [revision, expected] of Object.entries(EXPECTED_SOURCE_PINS)) {
    const actual = declared.get(revision) ?? null;
    if (actual !== expected) failures.push({ source: revision, expected, actual });
  }
  if (declared.size !== Object.keys(EXPECTED_SOURCE_PINS).length) {
    failures.push({
      source: 'declared_source_count',
      expected: Object.keys(EXPECTED_SOURCE_PINS).length,
      actual: declared.size,
    });
  }

  const localDeclared = new Map(
    SOURCE_LOCK.local_files.map((entry) => [entry.path, entry.sha256]),
  );
  for (const [path, expected] of Object.entries(EXPECTED_LOCAL_PINS)) {
    const declaredDigest = localDeclared.get(path) ?? null;
    if (declaredDigest !== expected) {
      failures.push({ source: path, expected, actual: declaredDigest });
      continue;
    }
    const actual = sha256Hex(readFileSync(resolve(REPO_ROOT, path)));
    if (actual !== expected) failures.push({ source: path, expected, actual });
  }
  if (localDeclared.size !== Object.keys(EXPECTED_LOCAL_PINS).length) {
    failures.push({
      source: 'declared_local_file_count',
      expected: Object.keys(EXPECTED_LOCAL_PINS).length,
      actual: localDeclared.size,
    });
  }

  for (const [claim, value] of Object.entries(SOURCE_LOCK.claim_boundary)) {
    if (claim === 'note') continue;
    if (value !== false) failures.push({ source: `claim_boundary.${claim}`, expected: false, actual: value });
  }
  return Object.freeze({ valid: failures.length === 0, failures });
}

export function evaluateMatrix() {
  assert.deepEqual(
    MATRIX.criteria,
    Object.keys(GRADE_BY_SIGNAL),
    'matrix criteria and compiler criteria differ',
  );
  const rows = MATRIX.rows.map((row) => {
    const criteria = {};
    for (const criterion of MATRIX.criteria) {
      const signal = row.signals[criterion];
      const grade = GRADE_BY_SIGNAL[criterion][signal];
      assert.ok(grade, `${row.id}: unsupported ${criterion} signal ${signal}`);
      criteria[criterion] = {
        signal,
        expected: row.expected[criterion],
        actual: grade,
        pass: grade === row.expected[criterion],
      };
    }
    const passed = Object.values(criteria).filter((entry) => entry.pass).length;
    return {
      id: row.id,
      label: row.label,
      revision: row.revision,
      criteria,
      summary: {
        total: MATRIX.criteria.length,
        passed,
        failed: MATRIX.criteria.length - passed,
      },
    };
  });
  return Object.freeze({
    rows,
    summary: {
      total: rows.length,
      passed: rows.filter((row) => row.summary.failed === 0).length,
      failed: rows.filter((row) => row.summary.failed !== 0).length,
    },
  });
}

function requirementTightensOrPreserves(parent, child) {
  if (child.profile !== parent.profile
      || child.role !== parent.role
      || child.principal_kind !== parent.principal_kind
      || child.exact_action_profile !== parent.exact_action_profile) return false;
  if (child.minimum < parent.minimum) return false;
  if (parent.distinct_principals && !child.distinct_principals) return false;
  if (parent.exclude_initiator && !child.exclude_initiator) return false;
  if (parent.exclude_executor && !child.exclude_executor) return false;
  return true;
}

function carrierFor(mutation) {
  const approvedAction = copyJson(VECTORS.fixtures.approved_action);
  const binding = actionBinding(approvedAction);
  const requirement = copyJson(VECTORS.fixtures.required_evidence);
  const chain = VECTORS.fixtures.delegation_hops.map((hopId) => ({
    hop_id: hopId,
    caid: binding.caid,
    normalized_action_digest: binding.normalized_action_digest,
    target: approvedAction.target,
    acting_for_principal: approvedAction.acting_for_principal,
    required_evidence: [copyJson(requirement)],
  }));

  const child = chain.at(-1);
  if (mutation === 'STRIP_REQUIRED_EVIDENCE') child.required_evidence = [];
  else if (mutation === 'DOWNGRADE_REQUIRED_EVIDENCE') {
    child.required_evidence[0].minimum = requirement.minimum - 1;
  } else if (mutation === 'UNKNOWN_REQUIRED_EVIDENCE_PROFILE') {
    child.required_evidence[0].profile = 'example:unknown-human-evidence-profile';
  } else if (mutation !== 'NONE') {
    throw new TypeError(`unsupported carrier mutation: ${mutation}`);
  }
  return chain;
}

function operationActionFor(mutation = 'NONE') {
  const action = copyJson(VECTORS.fixtures.approved_action);
  if (mutation === 'CHANGE_TARGET') action.target = 'account:beneficiary-attacker';
  else if (mutation === 'CHANGE_ACTING_FOR_PRINCIPAL') {
    action.acting_for_principal = 'principal:unrelated-9';
  } else if (mutation !== 'NONE') {
    throw new TypeError(`unsupported operation mutation: ${mutation}`);
  }
  return action;
}

function carrierFailure(preflight, reason) {
  return Object.freeze({ valid: false, preflight, reason });
}

export function validateCarrier(chain, operationAction) {
  if (!Array.isArray(chain) || chain.length === 0) {
    return carrierFailure('REFUSE_REQUIRED_EVIDENCE_STRIPPED', 'required_evidence_stripped');
  }
  const operationBinding = actionBinding(operationAction);
  for (const hop of chain) {
    if (hop.acting_for_principal !== operationAction.acting_for_principal) {
      return carrierFailure(
        'REFUSE_ACTING_FOR_PRINCIPAL_MISMATCH',
        'acting_for_principal_mismatch',
      );
    }
    if (hop.target !== operationAction.target
        || hop.caid !== operationBinding.caid
        || hop.normalized_action_digest !== operationBinding.normalized_action_digest) {
      return carrierFailure(
        'REFUSE_EXACT_ACTION_BINDING_MISMATCH',
        'exact_action_binding_mismatch',
      );
    }
    if (!Array.isArray(hop.required_evidence) || hop.required_evidence.length === 0) {
      return carrierFailure(
        'REFUSE_REQUIRED_EVIDENCE_STRIPPED',
        'required_evidence_stripped',
      );
    }
    for (const requirement of hop.required_evidence) {
      if (!KNOWN_REQUIRED_EVIDENCE_PROFILES.has(requirement.profile)) {
        return carrierFailure(
          'REFUSE_UNKNOWN_REQUIRED_EVIDENCE_PROFILE',
          'unknown_required_evidence_profile',
        );
      }
    }
  }

  for (let index = 1; index < chain.length; index += 1) {
    const parent = chain[index - 1];
    const child = chain[index];
    for (const parentRequirement of parent.required_evidence) {
      const childRequirement = child.required_evidence.find(
        (entry) => entry.id === parentRequirement.id,
      );
      if (!childRequirement) {
        return carrierFailure(
          'REFUSE_REQUIRED_EVIDENCE_STRIPPED',
          'required_evidence_stripped',
        );
      }
      if (!requirementTightensOrPreserves(parentRequirement, childRequirement)) {
        return carrierFailure(
          'REFUSE_REQUIRED_EVIDENCE_DOWNGRADE',
          'required_evidence_downgrade',
        );
      }
    }
  }
  return Object.freeze({ valid: true, preflight: 'PASS', reason: null });
}

function aebRequirement(carrierRequirement) {
  return {
    role: carrierRequirement.role,
    principal_kind: carrierRequirement.principal_kind,
    minimum: carrierRequirement.minimum,
    distinct_principals: carrierRequirement.distinct_principals,
    exclude_initiator: carrierRequirement.exclude_initiator,
    exclude_executor: carrierRequirement.exclude_executor,
  };
}

function evidenceFor(action, nativeVerification = 'VERIFIED') {
  const binding = actionBinding(action);
  return ['human:approver-alice', 'human:approver-bob'].map((principalId, index) => {
    const nativeUnit = digestJson({
      profile: 'draft-schrock-ep-authorization-evidence-chain-05',
      decision_id: `decision:r10:${index + 1}`,
      principal_id: principalId,
      caid: binding.caid,
      normalized_action_digest: binding.normalized_action_digest,
    });
    return {
      wrapper_digest: digestJson({ wrapper: 'AEC-05', native_replay_unit: nativeUnit }),
      native_replay_unit: nativeUnit,
      native_verification: index === 0 ? nativeVerification : 'VERIFIED',
      mapped_caid: binding.caid,
      mapped_action_digest: binding.normalized_action_digest,
      role: 'human-authorization',
      principal_kind: 'HUMAN',
      principal_id: principalId,
      status: {
        verdict: 'CURRENT',
        authority_pinned: true,
        checked_at: STATUS_CHECKED_AT,
        valid_until: STATUS_VALID_UNTIL,
      },
    };
  });
}

function baseAebCase(entry, action, carrierRequirement) {
  const binding = actionBinding(action);
  const evidence = evidenceFor(
    action,
    entry.scenario === 'NATIVE_VERIFICATION_FAILED' ? 'FAILED' : 'VERIFIED',
  );
  const input = {
    '@version': AEB_CONSEQUENCE_CASE_VERSION,
    id: entry.id,
    mode: 'ADMISSION',
    evaluated_at: EVALUATED_AT,
    operation: {
      operation_id: `operation:r10:${entry.id}`,
      provider_id: PROVIDER_ID,
      initiator_id: INITIATOR_ID,
      executor_id: EXECUTOR_ID,
      caid: binding.caid,
      normalized_action_digest: binding.normalized_action_digest,
      requirements: [aebRequirement(carrierRequirement)],
    },
    evidence,
    local_policy: entry.scenario === 'LOCAL_POLICY_DENY' ? 'DENY' : 'PERMIT',
    reservation: {
      atomicity: 'local_atomic',
      prior_operations: [],
      consumed_native_replay_units: entry.scenario === 'NATIVE_EVIDENCE_REPLAY'
        ? [evidence[0].native_replay_unit]
        : [],
    },
    observation: null,
    reconciliation: null,
  };
  return parseAebConsequenceCase(input);
}

function priorOperation(operation, providerOutcome = 'NOT_INVOKED', effectRelation = 'NOT_OBSERVED') {
  return {
    operation_id: operation.operation_id,
    caid: operation.caid,
    normalized_action_digest: operation.normalized_action_digest,
    custody: 'INVOKING',
    provider_outcome: providerOutcome,
    effect_relation: effectRelation,
  };
}

function nextAebCase(admissionInput, mode, prior, observation) {
  return parseAebConsequenceCase({
    ...copyJson(admissionInput),
    mode,
    reservation: {
      atomicity: 'local_atomic',
      prior_operations: [prior],
      consumed_native_replay_units: [],
    },
    observation,
    reconciliation: null,
  });
}

function preflightProjection(carrierCheck) {
  return {
    preflight: carrierCheck.preflight,
    carrier: 'INVALID',
    admission_decision: null,
    reservation: 'NOT_ATTEMPTED',
    consumed_on_admission: false,
    provider_entry: 'REFUSED_BEFORE_ENTRY',
    custody: 'UNRESERVED',
    provider_outcome: 'NOT_INVOKED',
    effect_relation: 'NOT_OBSERVED',
    retry: 'NOT_APPLICABLE',
    reconciliation: 'NOT_APPLICABLE',
    aeb_decision: 'REFUSE',
    modeled_provider_entries_total: 0,
    reasons: [carrierCheck.reason],
  };
}

function admissionProjection(admission, modeledProviderEntriesTotal = 0) {
  return {
    preflight: 'PASS',
    carrier: 'VALID',
    admission_decision: admission.decision,
    reservation: admission.reservation,
    consumed_on_admission:
      admission.decision === 'ADMIT' && modeledProviderEntriesTotal > 0,
    provider_entry: admission.decision === 'ADMIT'
      ? 'AUTHORIZED_NOT_ENTERED'
      : 'REFUSED_BEFORE_ENTRY',
    custody: admission.custody,
    provider_outcome: admission.provider_outcome,
    effect_relation: admission.effect_relation,
    retry: admission.retry,
    reconciliation: admission.reconciliation,
    aeb_decision: admission.decision,
    modeled_provider_entries_total: modeledProviderEntriesTotal,
    reasons: admission.reasons,
  };
}

function lifecycleProjection(admission, outcome, scenario) {
  const providerEntry = scenario === 'LIFECYCLE_COMMIT'
    ? 'ENTERED_ONCE'
    : scenario === 'TIMEOUT_AFTER_DISPATCH'
      ? 'ENTERED_ONCE_OUTCOME_UNKNOWN'
      : 'REENTRY_REFUSED';
  return {
    preflight: 'PASS',
    carrier: 'VALID',
    admission_decision: admission.decision,
    reservation: outcome.reservation,
    consumed_on_admission: true,
    provider_entry: providerEntry,
    custody: outcome.custody,
    provider_outcome: outcome.provider_outcome,
    effect_relation: outcome.effect_relation,
    retry: outcome.retry,
    reconciliation: outcome.reconciliation,
    aeb_decision: outcome.decision,
    modeled_provider_entries_total: 1,
    reasons: outcome.reasons,
  };
}

function evaluateCase(entry) {
  const action = operationActionFor(entry.operation_mutation ?? 'NONE');
  const carrier = carrierFor(entry.carrier_mutation);
  const carrierCheck = validateCarrier(carrier, action);
  if (!carrierCheck.valid) {
    const observed = preflightProjection(carrierCheck);
    return {
      id: entry.id,
      description: entry.description,
      passed: sameJson(observed, entry.expected),
      expected: entry.expected,
      observed,
      details: {
        carrier_digest: digestJson(carrier),
        operation_action_digest: digestJson(action),
        aeb_input_digest: null,
        admission_result: null,
        outcome_result: null,
      },
    };
  }

  const carrierRequirement = carrier.at(-1).required_evidence[0];
  const admissionInput = baseAebCase(entry, action, carrierRequirement);
  const admission = evaluateAebConsequenceCase(admissionInput);
  let outcome = admission;
  let observed = admissionProjection(admission);
  let outcomeInput = null;

  if (entry.scenario === 'LIFECYCLE_COMMIT') {
    assert.equal(admission.decision, 'ADMIT', `${entry.id}: admission must succeed first`);
    outcomeInput = nextAebCase(
      admissionInput,
      'INVOCATION_OBSERVATION',
      priorOperation(admissionInput.operation),
      {
        source: 'PROVIDER_EVIDENCE',
        provider_outcome: 'COMMITTED',
        effect_relation: 'OBSERVED_AS_REQUESTED',
      },
    );
    outcome = evaluateAebConsequenceCase(outcomeInput);
    observed = lifecycleProjection(admission, outcome, entry.scenario);
  } else if (entry.scenario === 'TIMEOUT_AFTER_DISPATCH') {
    assert.equal(admission.decision, 'ADMIT', `${entry.id}: admission must succeed first`);
    outcomeInput = nextAebCase(
      admissionInput,
      'INVOCATION_OBSERVATION',
      priorOperation(admissionInput.operation),
      {
        source: 'TIMEOUT_AFTER_DISPATCH',
        provider_outcome: 'INDETERMINATE',
        effect_relation: 'INDETERMINATE',
      },
    );
    outcome = evaluateAebConsequenceCase(outcomeInput);
    observed = lifecycleProjection(admission, outcome, entry.scenario);
  } else if (entry.scenario === 'BLIND_RETRY') {
    assert.equal(admission.decision, 'ADMIT', `${entry.id}: admission must succeed first`);
    outcomeInput = nextAebCase(
      admissionInput,
      'RETRY',
      priorOperation(admissionInput.operation, 'INDETERMINATE', 'INDETERMINATE'),
      null,
    );
    outcome = evaluateAebConsequenceCase(outcomeInput);
    observed = lifecycleProjection(admission, outcome, entry.scenario);
  }

  return {
    id: entry.id,
    description: entry.description,
    passed: sameJson(observed, entry.expected),
    expected: entry.expected,
    observed,
    details: {
      carrier_digest: digestJson(carrier),
      operation_action_digest: digestJson(action),
      aeb_input_digest: digestJson(admissionInput),
      outcome_input_digest: outcomeInput ? digestJson(outcomeInput) : null,
      admission_result: admission,
      outcome_result: outcomeInput ? outcome : null,
    },
  };
}

export function runSuite() {
  const sourceVerification = verifySourceLock();
  assert.equal(
    sourceVerification.valid,
    true,
    `source lock failed: ${JSON.stringify(sourceVerification.failures)}`,
  );
  const matrix = evaluateMatrix();
  assert.equal(matrix.summary.failed, 0, 'matrix compiler disagrees with checked-in expectations');
  const cases = VECTORS.cases.map(evaluateCase);
  const passed = cases.filter((entry) => entry.passed).length;
  const body = {
    '@version': REPORT_VERSION,
    profile: PROFILE,
    executed_at: EVALUATED_AT,
    implementation: {
      owner: 'EMILIA Protocol',
      revision: 'v0.1',
      same_team_reference: true,
      independent_implementation: false,
      production_mediation: false,
    },
    source_pins: {
      source_lock_digest: sha256Digest(readFileSync(SOURCE_LOCK_PATH)),
      matrix_digest: sha256Digest(readFileSync(MATRIX_PATH)),
      vectors_digest: sha256Digest(readFileSync(VECTORS_PATH)),
      requirements_revision: SOURCE_LOCK.requirements_source.revision,
      requirements_sha256: SOURCE_LOCK.requirements_source.sha256,
      native_revisions: Object.fromEntries(
        SOURCE_LOCK.native_sources.map((entry) => [entry.revision, entry.sha256]),
      ),
      aeb_kernel_sha256:
        EXPECTED_LOCAL_PINS['packages/verify/dist/aeb-consequence-conformance.js'],
    },
    matrix: {
      criteria: MATRIX.criteria,
      grade_vocabulary: MATRIX.grade_vocabulary,
      rows: matrix.rows,
      summary: matrix.summary,
    },
    claim_scope: {
      requirements_source_role: 'NEUTRAL_REQUIREMENTS_SOURCE',
      candidate_carrier_role: 'EMILIA_HOST_PROFILE_PROPOSAL',
      aeb_atomicity: AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
      guarantees: [
        'unknown_required_evidence_profiles_fail_closed',
        'required_evidence_cannot_be_removed_or_relaxed',
        'exact_action_target_and_acting_for_bindings_checked_before_admission',
        'local_atomic_admission_precedes_provider_entry',
        'refusal_does_not_consume_a_new_reliance_unit',
        'post_dispatch_timeout_remains_indeterminate',
        'blind_retry_is_refused_while_the_original_is_unresolved',
      ],
      exclusions: [
        'wimse_adoption',
        'reece_endorsement',
        'freedom_to_operate',
        'independent_implementation',
        'production_mediation',
        'external_provider_invocation_by_this_harness',
        'native_required_evidence_support_in_asor_00',
        'native_required_evidence_support_in_hamr_00',
        'native_recursive_r10_carriage_in_agentenvelope_01',
        'remote_or_federated_atomicity',
        'exactly_once_external_effect',
      ],
    },
    summary: {
      matrix_rows: matrix.summary.total,
      matrix_rows_passed: matrix.summary.passed,
      total: cases.length,
      passed,
      failed: cases.length - passed,
    },
    cases,
  };
  return Object.freeze({ ...body, report_digest: digestJson(body) });
}

function parseArgs(argv) {
  const options = { check: false, emit: false, output: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--check') options.check = true;
    else if (arg === '--emit') options.emit = true;
    else if (arg === '--output') {
      options.output = argv[index + 1];
      index += 1;
    } else throw new TypeError(`unknown argument: ${arg}`);
  }
  if (options.emit && !options.output) throw new TypeError('--emit requires --output');
  return options;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const options = parseArgs(process.argv.slice(2));
  const report = runSuite();
  if (options.check) {
    const reference = JSON.parse(readFileSync(REFERENCE_PATH, 'utf8'));
    assert.deepEqual(report, reference, 'deterministic report differs from reference');
    assert.equal(
      report.summary.failed,
      0,
      JSON.stringify(report.cases.filter((entry) => !entry.passed)),
    );
    process.stdout.write(
      `${PROFILE}: ${report.summary.passed}/${report.summary.total} cases passed; `
      + `${report.summary.matrix_rows_passed}/${report.summary.matrix_rows} matrix rows matched; `
      + 'reference matched\n',
    );
  } else if (options.emit) {
    writeFileSync(resolve(options.output), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  } else {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}
