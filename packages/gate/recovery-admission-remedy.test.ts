// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import test from 'node:test';

import {
  ADMISSION_CURRENTNESS_VERSION,
  EXECUTION_PROGRAM_STATUS_VERSION,
  createMemoryAdmissionStore,
  type AdmissionCurrentnessObservation,
  type AdmissionSnapshotInput,
  type ExecutionProgramAdmissionStore,
} from './admission-store.js';
import { signBoundedExecutionProgram } from './bounded-execution-program.js';
import { canonicalize } from './execution-binding.js';
import {
  createRecoveryAdmissionRemedyBridge,
  type RecoveryAdmissionRemedyInput,
} from './recovery-admission-remedy.js';
import {
  issueRemedyProgramReceipt,
  remedyProgramReceiptSigningBytes,
} from './remedy-program-receipt.js';
import {
  createRemedyMemoryStore,
  createRemedyProgramKernel,
  type RemedyProgramStore,
} from './remedy-program.js';

const NOW = '2026-07-21T18:30:00.000Z';
const EXPIRES = '2026-07-21T19:00:00.000Z';
const INPUT_EXPIRES = '2026-07-21T19:15:00.000Z';
const TENANT = 'tenant-1';
const INSTANCE = 'remedy-1';
const ORIGINAL_OPERATION = 'payment-op-1';
const REMEDY_OPERATION = 'refund-op-1';
const ORIGINAL_CAID = 'caid:1:payments.capture.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const REMEDY_CAID = 'caid:1:payments.refund.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

function d(label: string): `sha256:${string}` {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

const ORIGINAL_ACTION = d('original-action');
const REMEDY_ACTION = d('remedy-action');
const OWNER_DIGEST = d('remedy-owner');
const ISSUER = Object.freeze({
  issuer: 'emilia-gate-operator',
  tenant: TENANT,
  environment: 'production',
  audience: 'remedy-auditor',
  key_id: 'remedy-key-1',
});

function currentness(snapshot: Readonly<{ body: AdmissionSnapshotInput }>): AdmissionCurrentnessObservation {
  return {
    '@version': ADMISSION_CURRENTNESS_VERSION,
    observed_at: NOW,
    qualification_status_authority_id: snapshot.body.qualification_status.authority_id,
    qualification_status_sequence: snapshot.body.qualification_status.sequence,
    qualification_status_head_digest: snapshot.body.qualification_status.head_payload_digest,
    qualification_status_expires_at: snapshot.body.qualification_status.expires_at,
    trust_epoch: snapshot.body.trust_epoch,
    trust_configuration_digest: snapshot.body.trust_configuration_digest,
    configuration_epoch: snapshot.body.configuration_epoch,
    configuration_digest: snapshot.body.configuration_digest,
    runtime_measurement_digest: snapshot.body.runtime_measurement_digest,
    candidate_match: 'EXACT_MATCH',
    external_leases: [],
  };
}

function admission(
  kind: 'original' | 'remedy',
  authorizationDigest: `sha256:${string}`,
  relation: AdmissionSnapshotInput['remedy_for'] = null,
): AdmissionSnapshotInput {
  const operationId = kind === 'original' ? ORIGINAL_OPERATION : REMEDY_OPERATION;
  const actionDigest = kind === 'original' ? ORIGINAL_ACTION : REMEDY_ACTION;
  const actionCaid = kind === 'original' ? ORIGINAL_CAID : REMEDY_CAID;
  const sequence = kind === 'original' ? 1 : 2;
  const inputs: AdmissionSnapshotInput['inputs'] = [
    'candidate_manifest', 'runtime_measurement', 'test_result',
    'agent_evaluation_evidence', 'qualification_statement',
    'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
  ].map((role) => ({
    role: role as AdmissionSnapshotInput['inputs'][number]['role'],
    artifact_type: `artifact.${role}`,
    subject: role === 'candidate_manifest' || role === 'aeb'
      ? 'agent:remedy-worker' : `subject:${role}`,
    payload_digest: role === 'authorization'
      ? authorizationDigest : d(`${kind}:${role}`),
    profile_digest: d(`profile:${role}`),
    verifier_id: `verifier:${role}`,
    trust_configuration_digest: d(`input-trust:${role}`),
    valid_until: INPUT_EXPIRES,
  }));
  return {
    tenant_id: TENANT,
    admission_id: `admission:${kind}:1`,
    operation_id: operationId,
    candidate_manifest_digest: d(`${kind}:candidate`),
    runtime_measurement_digest: d(`${kind}:runtime`),
    candidate_custody: {
      request_construction: 'GATE',
      mutation_credential_custody: 'GATE',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: d(`${kind}:custody`),
    },
    assignment_digest: d(`${kind}:assignment`),
    qualification_policy_digest: d(`${kind}:qualification-policy`),
    test_result_payload_digests: [d(`${kind}:test_result`)],
    agent_evaluation_evidence_payload_digests: [d(`${kind}:agent_evaluation_evidence`)],
    qualification_statement_payload_digest: d(`${kind}:qualification_statement`),
    qualification_status: {
      authority_id: 'qualification-authority:primary',
      sequence,
      head_payload_digest: d(`${kind}:status`),
      observed_at: NOW,
      expires_at: INPUT_EXPIRES,
    },
    caid: actionCaid,
    action_digest: actionDigest,
    effect_request_digest: d(`${kind}:effect`),
    provider: {
      provider_id: 'provider:payments',
      account_id: 'account:production',
      environment: 'production',
    },
    executor_adapter_digest: d('executor-adapter'),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: d('remedy-trust-program'),
    trust_epoch: 1,
    trust_configuration_digest: d('trust-configuration'),
    configuration_epoch: 1,
    configuration_digest: d('configuration'),
    inputs,
    resource_reservations: [
      {
        kind: 'replay', resource_id: `receipt:${kind}:1`,
        reservation_id: `replay:admission:${kind}:1`, digest: d(`${kind}:replay`),
        expires_at: INPUT_EXPIRES,
      },
      {
        kind: 'provider_operation', resource_id: operationId,
        reservation_id: `provider:admission:${kind}:1`, digest: d(`${kind}:provider`),
        expires_at: INPUT_EXPIRES,
      },
    ],
    admitted_at: NOW,
    expires_at: EXPIRES,
    supersedes_admission_id: null,
    remedy_for: relation,
  };
}

function verifiedOriginal(input: any) {
  return { ok: true, ...input.original, evidence_digest: input.original.terminal_evidence_digest };
}

function verifiedDispute(input: any) {
  return {
    ok: true,
    ...input.dispute,
    original_operation_id: input.expected.original.operation_id,
    original_action_digest: input.expected.original.action_digest,
  };
}

function verifiedAuthorization(input: any) {
  return {
    ok: true,
    ...input.authorization,
    dispute_id: input.expected.dispute.dispute_id,
    original_operation_id: input.expected.original.operation_id,
    destination_binding_digest: input.expected.destination_binding_digest,
    unit: input.expected.unit,
  };
}

async function claimedRemedy(remedyStore: RemedyProgramStore, claim = true) {
  const subject = createRemedyProgramKernel({
    store: remedyStore,
    verifyOriginalEffect: verifiedOriginal,
    verifyRevocation: () => ({ ok: false }),
    verifyDispute: verifiedDispute,
    verifyRemedyAuthorization: verifiedAuthorization,
    verifyRemedyOutcome: () => ({ ok: false }),
    verifyOriginalReconciliation: () => ({ ok: false }),
    now: () => Date.parse(NOW),
    allowEphemeralState: true,
  });
  assert.equal((await subject.create({
    instanceId: INSTANCE,
    tenantId: TENANT,
    environment: ISSUER.environment,
    audience: ISSUER.audience,
    original: {
      caid: ORIGINAL_CAID,
      action_digest: ORIGINAL_ACTION,
      operation_id: ORIGINAL_OPERATION,
      consequence_mode: 'receipt-program',
      consequence_digest: d('original-consequence'),
      terminal_evidence_digest: d('original-terminal-evidence'),
      outcome: 'executed',
      occurred_at: '2026-07-21T18:00:00.000Z',
    },
    remedyProfileDigest: d('remedy-profile'),
    destinationBindingDigest: d('destination'),
    maxRemedyUnits: 10_000,
    unit: 'USD-cent',
    evidence: { kind: 'receipt-program-certificate' },
  })).ok, true);
  assert.equal((await subject.openDispute({
    tenantId: TENANT,
    instanceId: INSTANCE,
    dispute: {
      dispute_id: 'dispute-1',
      evidence_id: 'dispute-evidence-1',
      evidence_digest: d('dispute-evidence'),
      challenger_id: 'buyer-1',
      requested_units: 4_000,
      opened_at: '2026-07-21T18:20:00.000Z',
    },
  })).ok, true);
  const authorized = await subject.authorizeRemedy({
    tenantId: TENANT,
    instanceId: INSTANCE,
    authorization: {
      evidence_id: 'authorization-1',
      evidence_digest: d('authorization-evidence'),
      remedy_operation_id: REMEDY_OPERATION,
      remedy_caid: REMEDY_CAID,
      remedy_action_digest: REMEDY_ACTION,
      consequence_mode: 'receipt-program',
      capability_template_digest: OWNER_DIGEST,
      escrow_profile_digest: null,
      units: 4_000,
      authorized_at: '2026-07-21T18:25:00.000Z',
    },
  });
  assert.equal(authorized.ok, true, authorized.reason);
  if (!claim) return authorized.state!;
  const claimed = await subject.claimRemedy({
    tenantId: TENANT,
    instanceId: INSTANCE,
    remedyOperationId: REMEDY_OPERATION,
    claimToken: 'worker-A',
  });
  assert.equal(claimed.ok, true, claimed.reason);
  return claimed.state!;
}

function receiptContentDigest(receipt: any): `sha256:${string}` {
  return `sha256:${crypto.createHash('sha256').update(canonicalize({
    version: receipt.version,
    issuer: receipt.issuer,
    payload: receipt.payload,
  })).digest('hex')}`;
}

function resign(receipt: any, privateKey: any) {
  const changed = structuredClone(receipt);
  changed.content_digest = receiptContentDigest(changed);
  changed.signature = {
    algorithm: 'Ed25519',
    value: cryptoSign(null, remedyProgramReceiptSigningBytes(changed), privateKey)
      .toString('base64url'),
  };
  return changed;
}

async function fixture(options: { claim?: boolean } = {}) {
  const pair = generateKeyPairSync('ed25519');
  const remedyStore = createRemedyMemoryStore();
  const state = await claimedRemedy(remedyStore, options.claim ?? true);
  const receipt = await issueRemedyProgramReceipt({
    state,
    remedyOperationId: REMEDY_OPERATION,
  }, {
    context: ISSUER,
    privateKey: pair.privateKey,
    allowEphemeralState: true,
  });
  const admissionStore = createMemoryAdmissionStore({
    now: NOW,
    currentnessOracle: { read: async (snapshot) => currentness(snapshot as any) },
  });
  const original = admission('original', d('original-authorization'));
  const originalReserved = await admissionStore.reserve(original);
  assert.equal(originalReserved.ok, true);
  if (!originalReserved.ok) throw new Error('original admission reservation failed');
  const originalBegun = await admissionStore.beginInvocation({
    tenant_id: TENANT,
    admission_id: original.admission_id,
    expected_revision: 0,
    owner_token: originalReserved.owner_token,
  });
  assert.equal(originalBegun.ok, true);
  if (!originalBegun.ok) throw new Error('original admission invocation failed');
  const originalCommitted = await admissionStore.recordProviderOutcome({
    tenant_id: TENANT,
    admission_id: original.admission_id,
    expected_revision: 1,
    owner_token: originalReserved.owner_token,
    invocation_token: originalBegun.invocation_token,
    value: 'COMMITTED',
    evidence_digest: d('original-terminal-evidence'),
    observed_at: NOW,
  });
  assert.equal(originalCommitted.ok, true);
  const relation = {
    tenant_id: TENANT,
    admission_id: original.admission_id,
    operation_id: original.operation_id,
    snapshot_digest: originalReserved.snapshot.snapshot_digest,
    caid: original.caid,
    action_digest: original.action_digest,
  };
  const remedy = admission('remedy', receipt.content_digest, relation);
  const bridge = createRecoveryAdmissionRemedyBridge({
    remedyProgramStore: remedyStore,
    admissionStore,
    trustedReceiptKeys: {
      [ISSUER.key_id]: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
    expectedReceiptIssuer: ISSUER,
    allowedRemedyOwners: [{ owner_mode: 'receipt-program', owner_digest: OWNER_DIGEST }],
  });
  const input: RecoveryAdmissionRemedyInput = {
    tenant_id: TENANT,
    remedy_case_instance_id: INSTANCE,
    original_admission_id: original.admission_id,
    receipt,
    admission: remedy,
  };
  return {
    pair, remedyStore, admissionStore, state, receipt, original, relation, remedy, bridge, input,
  };
}

test('reserves one fresh claimed remedy as a separate ordinary admission', async () => {
  const f = await fixture();
  const result = await f.bridge.reserve(f.input);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.receipt_content_digest, f.receipt.content_digest);
  assert.equal(result.reservation.record.state, 'RESERVED');
  assert.equal(result.reservation.snapshot.body.operation_id, REMEDY_OPERATION);
  assert.deepEqual(result.reservation.snapshot.body.remedy_for, f.relation);
  assert.equal(result.reservation.snapshot.body.supersedes_admission_id, null);
  assert.equal((await f.admissionStore.read({
    tenant_id: TENANT,
    admission_id: f.original.admission_id,
  }))?.state, 'COMMITTED');
});

test('fails closed for every signed receipt binding mutation', async (t) => {
  const mutations: Array<[string, (receipt: any) => void]> = [
    ['case instance', (r) => { r.payload.case.instance_id = 'other-case'; }],
    ['case revision', (r) => { r.payload.case.revision += 1; }],
    ['case status', (r) => { r.payload.case.status = 'remedy_authorized'; }],
    ['state digest', (r) => { r.payload.case.state_snapshot_digest = d('other-state'); }],
    ['original operation', (r) => { r.payload.original_effect.operation_id = 'other-original'; }],
    ['original CAID', (r) => { r.payload.original_effect.caid = REMEDY_CAID; }],
    ['original action', (r) => { r.payload.original_effect.action_digest = d('other-original'); }],
    ['original terminal evidence', (r) => { r.payload.original_effect.terminal_evidence_digest = d('other-terminal'); }],
    ['remedy operation', (r) => { r.payload.remedy.operation_id = 'other-remedy'; }],
    ['remedy CAID', (r) => { r.payload.remedy.caid = ORIGINAL_CAID; }],
    ['remedy action', (r) => { r.payload.remedy.action_digest = d('other-remedy'); }],
    ['destination', (r) => { r.payload.remedy.destination_binding_digest = d('other-destination'); }],
    ['units', (r) => { r.payload.remedy.units += 1; }],
    ['unit', (r) => { r.payload.remedy.unit = 'EUR-cent'; }],
    ['owner mode', (r) => {
      r.payload.remedy.owner_mode = 'action-escrow';
      r.payload.remedy.owner_digest = d('other-owner');
    }],
    ['owner digest', (r) => { r.payload.remedy.owner_digest = d('other-owner'); }],
    ['remedy status', (r) => { r.payload.remedy.status = 'authorized'; }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, async () => {
      const f = await fixture();
      const hostile = structuredClone(f.receipt);
      mutate(hostile);
      const result = await f.bridge.reserve({ ...f.input, receipt: resign(hostile, f.pair.privateKey) });
      assert.equal(result.ok, false);
      if (!result.ok) assert.match(result.reason, /^remedy_receipt_/);
    });
  }
});

test('rejects wrong tenant, original relation, and fresh remedy admission bindings', async (t) => {
  const mutations: Array<[string, (f: Awaited<ReturnType<typeof fixture>>) => RecoveryAdmissionRemedyInput]> = [
    ['tenant', (f) => ({ ...f.input, tenant_id: 'tenant-other' })],
    ['original id', (f) => ({ ...f.input, original_admission_id: 'admission:missing' })],
    ['original operation', (f) => ({ ...f.input, admission: {
      ...f.remedy, remedy_for: { ...f.relation, operation_id: 'operation:other' },
    } })],
    ['original CAID', (f) => ({ ...f.input, admission: {
      ...f.remedy, remedy_for: { ...f.relation, caid: REMEDY_CAID },
    } })],
    ['original action', (f) => ({ ...f.input, admission: {
      ...f.remedy, remedy_for: { ...f.relation, action_digest: d('other-original') },
    } })],
    ['remedy operation', (f) => ({ ...f.input, admission: {
      ...f.remedy, operation_id: 'refund-op-other', idempotency_key: 'idempotency:refund-op-other',
    } })],
    ['remedy CAID', (f) => ({ ...f.input, admission: { ...f.remedy, caid: ORIGINAL_CAID } })],
    ['remedy action', (f) => ({ ...f.input, admission: {
      ...f.remedy, action_digest: d('other-remedy'),
    } })],
    ['supersedes', (f) => ({ ...f.input, admission: {
      ...f.remedy, supersedes_admission_id: f.original.admission_id,
    } })],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, async () => {
      const f = await fixture();
      const result = await f.bridge.reserve(mutate(f));
      assert.equal(result.ok, false);
    });
  }
});

test('requires exactly one authorization input bound to the verified receipt digest', async () => {
  const wrong = await fixture();
  const wrongInputs = wrong.remedy.inputs.map((entry) => entry.role === 'authorization'
    ? { ...entry, payload_digest: d('caller-selected-authorization') }
    : entry);
  const wrongResult = await wrong.bridge.reserve({
    ...wrong.input,
    admission: { ...wrong.remedy, inputs: wrongInputs },
  });
  assert.deepEqual(wrongResult, { ok: false, reason: 'authorization_evidence_mismatch' });

  const duplicate = await fixture();
  const authorization = duplicate.remedy.inputs.find((entry) => entry.role === 'authorization')!;
  const duplicateResult = await duplicate.bridge.reserve({
    ...duplicate.input,
    admission: { ...duplicate.remedy, inputs: [...duplicate.remedy.inputs, authorization] },
  });
  assert.deepEqual(duplicateResult, { ok: false, reason: 'authorization_evidence_mismatch' });
});

test('requires a current claimed remedy and a server-pinned owner pair', async () => {
  const unclaimed = await fixture({ claim: false });
  assert.deepEqual(await unclaimed.bridge.reserve(unclaimed.input), {
    ok: false,
    reason: 'remedy_not_currently_claimed',
  });

  const wrongOwner = await fixture();
  const bridge = createRecoveryAdmissionRemedyBridge({
    remedyProgramStore: wrongOwner.remedyStore,
    admissionStore: wrongOwner.admissionStore,
    trustedReceiptKeys: {
      [ISSUER.key_id]: wrongOwner.pair.publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
    expectedReceiptIssuer: ISSUER,
    allowedRemedyOwners: [{ owner_mode: 'receipt-program', owner_digest: d('not-pinned') }],
  });
  assert.deepEqual(await bridge.reserve(wrongOwner.input), {
    ok: false,
    reason: 'remedy_owner_not_allowed',
  });
});

test('duplicate concurrent reservations linearize in AdmissionStore', async () => {
  const f = await fixture();
  const [left, right] = await Promise.all([
    f.bridge.reserve(f.input),
    f.bridge.reserve(f.input),
  ]);
  assert.equal([left, right].filter((result) => result.ok).length, 1);
  assert.deepEqual(
    [left, right].find((result) => !result.ok),
    { ok: false, reason: 'admission_exists' },
  );
});

test('the bridge cannot invoke, retry, or enter a provider', async () => {
  const f = await fixture();
  let providerEntries = 0;
  const admissionStore = new Proxy(f.admissionStore, {
    get(target, property, receiver) {
      if (typeof property === 'string'
          && /begin.*invocation|provider|recover|retry/i.test(property)) {
        return () => {
          providerEntries += 1;
          throw new Error('provider entry forbidden from remedy admission bridge');
        };
      }
      return Reflect.get(target, property, receiver);
    },
  }) as ExecutionProgramAdmissionStore;
  const bridge = createRecoveryAdmissionRemedyBridge({
    remedyProgramStore: f.remedyStore,
    admissionStore,
    trustedReceiptKeys: {
      [ISSUER.key_id]: f.pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
    expectedReceiptIssuer: ISSUER,
    allowedRemedyOwners: [{ owner_mode: 'receipt-program', owner_digest: OWNER_DIGEST }],
  });
  assert.equal((await bridge.reserve(f.input)).ok, true);
  assert.equal(providerEntries, 0);
  assert.deepEqual(Object.keys(bridge), ['reserve']);
});

function boundedProgram(authorizationDigest: string) {
  return {
    program_id: 'program:remedy:01',
    tenant_id: TENANT,
    version: 1,
    subject_id: 'agent:remedy-worker',
    audience: 'gate:production:01',
    objective_digest: d('bounded-objective'),
    authorization_digest: authorizationDigest,
    presentation_digest: d('bounded-presentation'),
    supersedes_program_digest: null,
    issued_at: '2026-07-21T18:25:00.000Z',
    valid_from: NOW,
    expires_at: EXPIRES,
    max_total_occurrences: 1,
    max_concurrent_effects: 1,
    budgets: [{ budget_id: 'refund-units', unit: 'USD-cent', limit: 4_000 }],
    nodes: [{
      node_id: 'refund',
      action: { mode: 'exact' as const, caid: REMEDY_CAID, action_digest: REMEDY_ACTION },
      trust_program_digest: d('remedy-trust-program'),
      depends_on: [],
      max_occurrences: 1,
      charges: [{ budget_id: 'refund-units', amount: 4_000 }],
    }],
  };
}

test('bounded-program reservation preserves occurrence and budget limits', async () => {
  const f = await fixture();
  const programKeys = generateKeyPairSync('ed25519');
  const signer = {
    issuer_id: 'customer:security',
    key_id: 'key:program-authorizer',
    private_key: programKeys.privateKey,
  };
  const artifact = signBoundedExecutionProgram(boundedProgram(f.receipt.content_digest), signer);
  const policyStore = createMemoryAdmissionStore({
    now: NOW,
    currentnessOracle: { read: async (snapshot) => currentness(snapshot as any) },
    executionProgramVerificationPolicy: {
      trusted_keys: {
        [signer.key_id]: {
          issuer_id: signer.issuer_id,
          public_key: programKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
          role: 'program_authorizer',
          status: 'ACTIVE',
        },
      },
    },
    executionProgramStatusOracle: {
      read: async (reference) => ({
        '@version': EXECUTION_PROGRAM_STATUS_VERSION,
        ...reference,
        status: 'ACTIVE',
        sequence: 0,
        observed_at: NOW,
        expires_at: EXPIRES,
      }),
    },
  });
  const original = admission('original', d('bounded-original-authorization'));
  const originalReserved = await policyStore.reserve(original);
  assert.equal(originalReserved.ok, true);
  if (!originalReserved.ok) return;
  const begun = await policyStore.beginInvocation({
    tenant_id: TENANT, admission_id: original.admission_id,
    expected_revision: 0, owner_token: originalReserved.owner_token,
  });
  assert.equal(begun.ok, true);
  const relation = {
    tenant_id: TENANT,
    admission_id: original.admission_id,
    operation_id: original.operation_id,
    snapshot_digest: originalReserved.snapshot.snapshot_digest,
    caid: original.caid,
    action_digest: original.action_digest,
  };
  const remedy = admission('remedy', f.receipt.content_digest, relation);
  const registered = await policyStore.registerExecutionProgram(artifact, {
    expected_program_id: 'program:remedy:01',
    expected_tenant_id: TENANT,
    expected_authorization_digest: f.receipt.content_digest,
    expected_audience: 'gate:production:01',
  });
  assert.equal(registered.ok, true, registered.ok ? undefined : registered.reason);
  if (!registered.ok) return;
  const bridge = createRecoveryAdmissionRemedyBridge({
    remedyProgramStore: f.remedyStore,
    admissionStore: policyStore,
    trustedReceiptKeys: {
      [ISSUER.key_id]: f.pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
    expectedReceiptIssuer: ISSUER,
    allowedRemedyOwners: [{ owner_mode: 'receipt-program', owner_digest: OWNER_DIGEST }],
  });
  const input: RecoveryAdmissionRemedyInput = {
    ...f.input,
    original_admission_id: original.admission_id,
    admission: remedy,
    execution_program: {
      program_digest: registered.program.program_digest,
      node_id: 'refund',
      occurrence_id: 'occurrence:refund:1',
    },
  };
  const reserved = await bridge.reserve(input);
  assert.equal(reserved.ok, true);
  const runtime = await policyStore.readExecutionProgram({
    tenant_id: TENANT,
    program_digest: registered.program.program_digest,
  });
  assert.deepEqual(runtime?.budgets, [
    { budget_id: 'refund-units', unit: 'USD-cent', limit: 4_000, reserved: 4_000, consumed: 0 },
  ]);
  const duplicateAdmission = {
    ...remedy,
    admission_id: 'admission:remedy:2',
    idempotency_key: 'idempotency:refund-op-2',
    operation_id: 'refund-op-2',
    resource_reservations: remedy.resource_reservations.map((resource) => ({
      ...resource,
      resource_id: `${resource.resource_id}:2`,
      reservation_id: `${resource.reservation_id}:2`,
    })),
  };
  const limited = await bridge.reserve({
    ...input,
    admission: duplicateAdmission,
    execution_program: { ...input.execution_program!, occurrence_id: 'occurrence:refund:2' },
  });
  assert.equal(limited.ok, false);
  assert.notEqual(limited.reason, null);
  assert.deepEqual((await policyStore.readExecutionProgram({
    tenant_id: TENANT,
    program_digest: registered.program.program_digest,
  }))?.budgets, runtime?.budgets);
});
