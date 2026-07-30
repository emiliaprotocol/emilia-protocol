#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Synthetic executable walk-through for EP-BOUNDED-EXECUTION-PROGRAM-v1.
 *
 * All signing, verification, admission, transition, budget, and supersession
 * decisions use the Gate package APIs. The provider and its evidence are
 * deliberately synthetic, and the admission store is the package's test-only
 * in-memory reference implementation.
 */
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';

import {
  ADMISSION_CURRENTNESS_VERSION,
  EXECUTION_PROGRAM_STATUS_VERSION,
  createMemoryAdmissionStore,
} from '../../packages/gate/admission-store.js';
import {
  BOUNDED_EXECUTION_PROGRAM_VERSION,
  signBoundedExecutionProgram,
  verifyBoundedExecutionProgram,
} from '../../packages/gate/bounded-execution-program.js';
import {
  boundedExecutionOccurrenceInventoryDigest,
  boundedExecutionRuntimeStateDigest,
  signBoundedExecutionReport,
  verifyBoundedExecutionReport,
} from '../../packages/gate/bounded-execution-report.js';

const NOW = '2026-07-30T18:00:00.000Z';
const ADMISSION_EXPIRES = '2026-07-30T18:30:00.000Z';
const INPUT_EXPIRES = '2026-07-30T19:00:00.000Z';
const REPORT_END = '2026-07-30T18:10:00.000Z';
const REPORT_GENERATED_AT = '2026-07-30T18:11:00.000Z';
const TENANT_ID = 'tenant:synthetic-lab';
const PROGRAM_ID = 'program:synthetic-remediation:01';
const SUBJECT_ID = 'agent:synthetic-operator:01';
const AUDIENCE = 'gate:synthetic-demo:01';
const AUTHORIZER_ID = 'customer:synthetic-security';
const authorizationDigest = (version) => digest(`synthetic-authorization:v${version}`);

/** @returns {`sha256:${string}`} */
function digest(label) {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

/** @returns {`caid:${string}`} */
function caid(label) {
  return `caid:1:demo.synthetic-action.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`;
}

function keyMaterial() {
  const pair = generateKeyPairSync('ed25519');
  const keyId = 'key:synthetic-program-authorizer';
  return {
    signer: {
      issuer_id: AUTHORIZER_ID,
      key_id: keyId,
      private_key: pair.privateKey,
    },
    policy: {
      trusted_keys: {
        [keyId]: {
          issuer_id: AUTHORIZER_ID,
          public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
          role: 'program_authorizer',
          status: 'ACTIVE',
        },
      },
    },
    context: (version = 1) => ({
      expected_program_id: PROGRAM_ID,
      expected_tenant_id: TENANT_ID,
      expected_authorization_digest: authorizationDigest(version),
      expected_audience: AUDIENCE,
    }),
    verification: (version = 1) => ({
      trusted_keys: {
        [keyId]: {
          issuer_id: AUTHORIZER_ID,
          public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        },
      },
      now: NOW,
      expected_program_id: PROGRAM_ID,
      expected_tenant_id: TENANT_ID,
      expected_authorizer_id: AUTHORIZER_ID,
      expected_authorization_digest: authorizationDigest(version),
      expected_audience: AUDIENCE,
    }),
  };
}

function program(version = 1, supersedesProgramDigest = null) {
  const successor = version > 1;
  return {
    program_id: PROGRAM_ID,
    tenant_id: TENANT_ID,
    version,
    subject_id: SUBJECT_ID,
    audience: AUDIENCE,
    objective_digest: digest('synthetic-objective'),
    authorization_digest: authorizationDigest(version),
    presentation_digest: digest('synthetic-presentation'),
    supersedes_program_digest: supersedesProgramDigest,
    issued_at: '2026-07-30T17:55:00.000Z',
    valid_from: NOW,
    expires_at: '2026-07-30T20:00:00.000Z',
    max_total_occurrences: successor ? 5 : 4,
    budgets: [
      { budget_id: 'attempts', unit: 'attempt', limit: successor ? 4 : 3 },
      { budget_id: 'change-risk', unit: 'risk-point', limit: successor ? 5 : 4 },
    ],
    nodes: [
      {
        node_id: 'inspect',
        action: { mode: 'exact', caid: caid('inspect'), action_digest: digest('action:inspect') },
        trust_program_digest: digest('trust:inspect'),
        depends_on: [],
        max_occurrences: 2,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 1 },
        ],
      },
      {
        node_id: 'remediate',
        action: { mode: 'exact', caid: caid('remediate'), action_digest: digest('action:remediate') },
        trust_program_digest: digest('trust:remediate'),
        depends_on: [{ node_id: 'inspect', outcomes: ['COMMITTED'] }],
        max_occurrences: 1,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 2 },
        ],
      },
      {
        node_id: 'verify',
        action: { mode: 'exact', caid: caid('verify'), action_digest: digest('action:verify') },
        trust_program_digest: digest('trust:verify'),
        depends_on: [{ node_id: 'remediate', outcomes: ['COMMITTED'] }],
        max_occurrences: 1,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 1 },
        ],
      },
    ],
  };
}

/**
 * @param {string} nodeId
 * @param {number} sequence
 * @param {import('../../packages/gate/admission-store.js').AdmissionSnapshotInput['remedy_for']} remedyFor
 * @returns {import('../../packages/gate/admission-store.js').AdmissionSnapshotInput}
 */
function admissionInput(nodeId, sequence, remedyFor = null) {
  const admissionId = `admission:${nodeId}:${sequence}`;
  const operationId = `operation:${nodeId}:${sequence}`;
  /** @type {import('../../packages/gate/admission-store.js').AdmissionInputRole[]} */
  const roleNames = [
    'candidate_manifest', 'runtime_measurement', 'test_result',
    'agent_evaluation_evidence', 'qualification_statement',
    'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
  ];
  const roles = roleNames.map((role) => ({
    role,
    artifact_type: `artifact.synthetic.${role}`,
    subject: role === 'candidate_manifest' ? SUBJECT_ID : `subject:synthetic:${role}`,
    payload_digest: role === 'authorization'
      ? authorizationDigest(1)
      : digest(`payload:${role}:${sequence}`),
    profile_digest: digest(`profile:${role}`),
    verifier_id: `verifier:synthetic:${role}`,
    trust_configuration_digest: digest(`trust-config:${role}`),
    valid_until: INPUT_EXPIRES,
  }));

  return {
    tenant_id: TENANT_ID,
    admission_id: admissionId,
    operation_id: operationId,
    candidate_manifest_digest: digest(`candidate:${sequence}`),
    runtime_measurement_digest: digest(`runtime:${sequence}`),
    candidate_custody: {
      request_construction: 'GATE',
      mutation_credential_custody: 'GATE',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: digest(`custody:${sequence}`),
    },
    assignment_digest: digest(`assignment:${sequence}`),
    qualification_policy_digest: digest(`qualification-policy:${sequence}`),
    test_result_payload_digests: [digest(`payload:test_result:${sequence}`)],
    agent_evaluation_evidence_payload_digests: [
      digest(`payload:agent_evaluation_evidence:${sequence}`),
    ],
    qualification_statement_payload_digest: digest(`payload:qualification_statement:${sequence}`),
    qualification_status: {
      authority_id: 'qualification-authority:synthetic',
      sequence,
      head_payload_digest: digest(`qualification-status:${sequence}`),
      observed_at: NOW,
      expires_at: INPUT_EXPIRES,
    },
    caid: caid(nodeId),
    action_digest: digest(`action:${nodeId}`),
    effect_request_digest: digest(`effect:${nodeId}:${sequence}`),
    provider: {
      provider_id: 'provider:synthetic-lab',
      account_id: 'account:synthetic-lab',
      environment: 'synthetic',
    },
    executor_adapter_digest: digest('executor-adapter:synthetic'),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: digest(`trust:${nodeId}`),
    trust_epoch: 1,
    trust_configuration_digest: digest('trust-configuration:synthetic'),
    configuration_epoch: 1,
    configuration_digest: digest('configuration:synthetic'),
    inputs: roles,
    resource_reservations: [
      {
        kind: 'replay',
        resource_id: `receipt:synthetic:${sequence}`,
        reservation_id: `replay:${admissionId}`,
        digest: digest(`replay:${sequence}`),
        expires_at: INPUT_EXPIRES,
      },
      {
        kind: 'provider_operation',
        resource_id: operationId,
        reservation_id: `provider:${admissionId}`,
        digest: digest(`provider-operation:${sequence}`),
        expires_at: INPUT_EXPIRES,
      },
    ],
    admitted_at: NOW,
    expires_at: ADMISSION_EXPIRES,
    supersedes_admission_id: null,
    remedy_for: remedyFor,
  };
}

/**
 * @param {import('../../packages/gate/admission-store.js').AdmissionSnapshot['body']} snapshot
 * @returns {import('../../packages/gate/admission-store.js').AdmissionCurrentnessObservation}
 */
function currentness(snapshot) {
  return {
    '@version': ADMISSION_CURRENTNESS_VERSION,
    observed_at: NOW,
    qualification_status_authority_id: snapshot.qualification_status.authority_id,
    qualification_status_sequence: snapshot.qualification_status.sequence,
    qualification_status_head_digest: snapshot.qualification_status.head_payload_digest,
    qualification_status_expires_at: snapshot.qualification_status.expires_at,
    trust_epoch: snapshot.trust_epoch,
    trust_configuration_digest: snapshot.trust_configuration_digest,
    configuration_epoch: snapshot.configuration_epoch,
    configuration_digest: snapshot.configuration_digest,
    runtime_measurement_digest: snapshot.runtime_measurement_digest,
    candidate_match: 'EXACT_MATCH',
    external_leases: [],
  };
}

function createSyntheticStore(executionProgramVerificationPolicy) {
  let ownerIndex = 1;
  let invocationIndex = 1;
  return createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => (
      `admission-owner:v2:${Buffer.alloc(32, ownerIndex++).toString('base64url')}`
    ),
    invocationTokenFactory: () => (
      `admission-invocation:v2:${Buffer.alloc(32, invocationIndex++).toString('base64url')}`
    ),
    currentnessOracle: {
      read: async (snapshot) => currentness(snapshot.body),
    },
    executionProgramStatusOracle: {
      read: async (reference) => ({
        '@version': EXECUTION_PROGRAM_STATUS_VERSION,
        ...reference,
        status: 'ACTIVE',
        sequence: 0,
        observed_at: NOW,
        expires_at: '2026-07-30T20:00:00.000Z',
      }),
    },
    executionProgramVerificationPolicy,
  });
}

function accepted(result, label) {
  assert.equal(result.ok, true, `${label} refused: ${result.reason ?? 'unknown'}`);
  return result;
}

function refused(result, reason, label) {
  assert.deepEqual(result, { ok: false, reason }, `${label} did not fail closed`);
  return result;
}

function budgets(state) {
  return state.budgets
    .map((budget) => `${budget.budget_id}=${budget.consumed}/${budget.limit}`)
    .join(', ');
}

function line(stage, message) {
  console.log(`${stage.padEnd(13)} ${message}`);
}

async function runCommittedNode(store, programDigest, nodeId, sequence, remedyFor = null) {
  const input = admissionInput(nodeId, sequence, remedyFor);
  const reserved = accepted(await store.reserveExecutionProgramAdmission({
    program_digest: programDigest,
    node_id: nodeId,
    occurrence_id: `occurrence:${nodeId}:01`,
    admission: input,
  }), `${nodeId} reservation`);
  const begun = accepted(await store.beginExecutionProgramInvocation({
    tenant_id: TENANT_ID,
    admission_id: input.admission_id,
    expected_revision: reserved.record.revision,
    owner_token: reserved.owner_token,
  }), `${nodeId} provider entry`);
  const committed = accepted(await store.recordProviderOutcome({
    tenant_id: TENANT_ID,
    admission_id: input.admission_id,
    expected_revision: begun.record.revision,
    owner_token: reserved.owner_token,
    invocation_token: begun.invocation_token,
    value: 'COMMITTED',
    evidence_digest: digest(`synthetic-provider-committed:${nodeId}:${sequence}`),
    observed_at: NOW,
  }), `${nodeId} provider outcome`);
  const related = accepted(await store.recordEffectRelation({
    tenant_id: TENANT_ID,
    admission_id: input.admission_id,
    expected_revision: committed.record.revision,
    owner_token: reserved.owner_token,
    invocation_token: begun.invocation_token,
    value: 'OBSERVED_AS_REQUESTED',
    evidence_digest: digest(`synthetic-effect-observation:${nodeId}:${sequence}`),
    observed_at: NOW,
  }), `${nodeId} effect relation`);
  return { input, reserved, begun, committed, related };
}

async function syntheticProviderTimeout() {
  const providerNeverReplies = new Promise(() => {});
  const timeout = new Promise((resolve) => setTimeout(() => resolve('TIMEOUT'), 5));
  return Promise.race([providerNeverReplies, timeout]);
}

export async function runDemo() {
  const keys = keyMaterial();
  const store = createSyntheticStore(keys.policy);
  assert.equal(store.testOnly, true);
  assert.equal(store.durable, false);

  const artifactV1 = signBoundedExecutionProgram(program(), keys.signer);
  const verifiedV1 = verifyBoundedExecutionProgram(artifactV1, keys.verification(1));
  assert.equal(verifiedV1.accepted, true);
  assert.equal(artifactV1['@version'], BOUNDED_EXECUTION_PROGRAM_VERSION);
  line('SIGN', `${artifactV1['@version']} signature accepted`);

  const registered = accepted(
    await store.registerExecutionProgram(artifactV1, keys.context(1)),
    'program registration',
  );
  const programDigest = registered.program.program_digest;
  line('REGISTER', `v1 ACTIVE (${programDigest.slice(0, 20)}...)`);

  const inspect = await runCommittedNode(store, programDigest, 'inspect', 1);
  const inspectOccurrence = await store.readExecutionProgramOccurrence({
    tenant_id: TENANT_ID,
    program_digest: programDigest,
    occurrence_id: 'occurrence:inspect:01',
  });
  assert.equal(inspectOccurrence?.state, 'COMMITTED');
  line('INSPECT', 'synthetic outcome COMMITTED; remediate unlocked');

  const remedyFor = {
    tenant_id: TENANT_ID,
    admission_id: inspect.input.admission_id,
    operation_id: inspect.input.operation_id,
    snapshot_digest: inspect.reserved.snapshot.snapshot_digest,
  };
  const remediateInput = admissionInput('remediate', 2, remedyFor);
  const remediateReserved = accepted(await store.reserveExecutionProgramAdmission({
    program_digest: programDigest,
    node_id: 'remediate',
    occurrence_id: 'occurrence:remediate:01',
    admission: remediateInput,
  }), 'remediate reservation');
  const remediateBegun = accepted(await store.beginExecutionProgramInvocation({
    tenant_id: TENANT_ID,
    admission_id: remediateInput.admission_id,
    expected_revision: remediateReserved.record.revision,
    owner_token: remediateReserved.owner_token,
  }), 'remediate provider entry');

  assert.equal(await syntheticProviderTimeout(), 'TIMEOUT');
  const indeterminate = accepted(await store.recoverIndeterminate({
    tenant_id: TENANT_ID,
    admission_id: remediateInput.admission_id,
    owner_token: remediateReserved.owner_token,
  }), 'timeout recovery');
  const indeterminateOccurrence = await store.readExecutionProgramOccurrence({
    tenant_id: TENANT_ID,
    program_digest: programDigest,
    occurrence_id: 'occurrence:remediate:01',
  });
  assert.equal(indeterminate.record.state, 'INDETERMINATE');
  assert.equal(indeterminateOccurrence?.state, 'INDETERMINATE');
  line('REMEDIATE', 'synthetic provider timeout -> INDETERMINATE');

  const verifyInput = admissionInput('verify', 3);
  const lockedVerify = await store.reserveExecutionProgramAdmission({
    program_digest: programDigest,
    node_id: 'verify',
    occurrence_id: 'occurrence:verify:01',
    admission: verifyInput,
  });
  refused(lockedVerify, 'program_node_unreachable', 'dependent verify reservation');
  line('NO UNLOCK', 'verify refused: program_node_unreachable');

  const reconciled = accepted(await store.recordProviderOutcome({
    tenant_id: TENANT_ID,
    admission_id: remediateInput.admission_id,
    expected_revision: indeterminate.record.revision,
    owner_token: remediateReserved.owner_token,
    invocation_token: indeterminate.reconciliation_token,
    value: 'COMMITTED',
    evidence_digest: digest('synthetic-reconciliation:remediate:committed'),
    observed_at: NOW,
  }), 'remediate reconciliation');
  const reconciledEffect = accepted(await store.recordEffectRelation({
    tenant_id: TENANT_ID,
    admission_id: remediateInput.admission_id,
    expected_revision: reconciled.record.revision,
    owner_token: remediateReserved.owner_token,
    invocation_token: indeterminate.reconciliation_token,
    value: 'OBSERVED_AS_REQUESTED',
    evidence_digest: digest('synthetic-reconciliation:remediate:effect'),
    observed_at: NOW,
  }), 'remediate effect reconciliation');
  assert.equal(reconciledEffect.record.state, 'COMMITTED');
  line('RECONCILE', 'synthetic evidence -> COMMITTED; verify unlocked');

  const verifyReserved = accepted(await store.reserveExecutionProgramAdmission({
    program_digest: programDigest,
    node_id: 'verify',
    occurrence_id: 'occurrence:verify:01',
    admission: verifyInput,
  }), 'verify reservation after reconciliation');
  const verifyBegun = accepted(await store.beginExecutionProgramInvocation({
    tenant_id: TENANT_ID,
    admission_id: verifyInput.admission_id,
    expected_revision: verifyReserved.record.revision,
    owner_token: verifyReserved.owner_token,
  }), 'verify provider entry');
  const verifyCommitted = accepted(await store.recordProviderOutcome({
    tenant_id: TENANT_ID,
    admission_id: verifyInput.admission_id,
    expected_revision: verifyBegun.record.revision,
    owner_token: verifyReserved.owner_token,
    invocation_token: verifyBegun.invocation_token,
    value: 'COMMITTED',
    evidence_digest: digest('synthetic-provider-committed:verify:3'),
    observed_at: NOW,
  }), 'verify provider outcome');
  accepted(await store.recordEffectRelation({
    tenant_id: TENANT_ID,
    admission_id: verifyInput.admission_id,
    expected_revision: verifyCommitted.record.revision,
    owner_token: verifyReserved.owner_token,
    invocation_token: verifyBegun.invocation_token,
    value: 'OBSERVED_AS_REQUESTED',
    evidence_digest: digest('synthetic-effect-observation:verify:3'),
    observed_at: NOW,
  }), 'verify effect relation');
  line('VERIFY', 'synthetic post-remediation check COMMITTED');

  const depleted = await store.readExecutionProgram({
    tenant_id: TENANT_ID,
    program_digest: programDigest,
  });
  assert.ok(depleted);
  assert.deepEqual(depleted.budgets, [
    { budget_id: 'attempts', unit: 'attempt', limit: 3, reserved: 0, consumed: 3 },
    { budget_id: 'change-risk', unit: 'risk-point', limit: 4, reserved: 0, consumed: 4 },
  ]);
  const overBudget = await store.reserveExecutionProgramAdmission({
    program_digest: programDigest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:inspect:02',
    admission: admissionInput('inspect', 4),
  });
  refused(overBudget, 'program_budget_exhausted', 'post-depletion reservation');
  line('BUDGET', `${budgets(depleted)}; refused: program_budget_exhausted`);

  const reportSnapshot = await store.readExecutionProgramReportSnapshot({
    tenant_id: TENANT_ID,
    program_digest: programDigest,
  });
  assert.ok(reportSnapshot);
  assert.equal(reportSnapshot.runtime_state.total_occurrences, 3);
  assert.equal(reportSnapshot.occurrences.length, 3);
  const report = signBoundedExecutionReport({
    report_id: 'report:synthetic-remediation:point-in-time:01',
    relying_party_id: AUTHORIZER_ID,
    report_interval: { start: NOW, end: REPORT_END },
    generated_at: REPORT_GENERATED_AT,
    verified_program: verifiedV1,
    report_snapshot: reportSnapshot,
  }, {
    relying_party_id: AUTHORIZER_ID,
    key_id: keys.signer.key_id,
    private_key: keys.signer.private_key,
  });
  const reportVerification = verifyBoundedExecutionReport(report, {
    trusted_keys: keys.verification(1).trusted_keys,
    expected_report_id: report.report_id,
    expected_relying_party_id: AUTHORIZER_ID,
    expected_tenant_id: TENANT_ID,
    expected_program_id: PROGRAM_ID,
    expected_program_version: 1,
    expected_program_digest: programDigest,
    expected_subject_id: SUBJECT_ID,
    expected_audience: AUDIENCE,
    expected_report_interval: { start: NOW, end: REPORT_END },
    expected_runtime_state_digest:
      boundedExecutionRuntimeStateDigest(reportSnapshot.runtime_state),
    expected_occurrence_inventory_digest:
      boundedExecutionOccurrenceInventoryDigest(reportSnapshot.occurrences),
    expected_report_snapshot_marker: reportSnapshot.snapshot_marker,
    now: REPORT_GENERATED_AT,
    max_report_age_ms: 60_000,
  });
  assert.equal(reportVerification.accepted, true);
  line('REPORT', 'signed point-in-time program-to-date Gate snapshot accepted');

  const artifactV2 = signBoundedExecutionProgram(program(2, programDigest), keys.signer);
  const verifiedV2 = verifyBoundedExecutionProgram(artifactV2, keys.verification(2));
  assert.equal(verifiedV2.accepted, true);
  assert.equal(verifiedV2.program?.supersedes_program_digest, programDigest);
  const superseded = accepted(
    await store.supersedeExecutionProgram(artifactV2, keys.context(2)),
    'signed program supersession',
  );
  const oldProgram = await store.readExecutionProgram({
    tenant_id: TENANT_ID,
    program_digest: programDigest,
  });
  assert.equal(oldProgram?.status, 'SUPERSEDED');
  assert.equal(oldProgram?.superseded_by_program_digest, superseded.program.program_digest);
  assert.equal(superseded.program.status, 'ACTIVE');
  refused(await store.reserveExecutionProgramAdmission({
    program_digest: programDigest,
    node_id: 'inspect',
    occurrence_id: 'occurrence:old-program:01',
    admission: admissionInput('inspect', 5),
  }), 'program_superseded', 'old program reservation');
  line('SUPERSEDE', 'signed v2 ACTIVE; v1 closed to new reservations');

  assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
  line('RESULT', 'PASS — synthetic in-memory demonstration only');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runDemo().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
