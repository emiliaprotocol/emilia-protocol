#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import crypto, {
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

import {
  createEg1Harness,
  createGate,
  MemoryConsumptionStore,
} from '../../packages/gate/index.js';
import { manifestFromPack } from '../../packages/gate/adapters/_kit.js';
import {
  fieldOriginProfileDigest,
  signFieldOriginEvidence,
} from '../../packages/gate/field-origin-evidence.js';
import { signBoundedExecutionProgram } from '../../packages/gate/bounded-execution-program.js';
import {
  allowanceDigest,
  issueGateAllowance,
} from '../../packages/gate/allowance.js';
import {
  capabilityBaseReceiptDigest,
  createMemoryCapabilityStore,
} from '../../packages/gate/capability-receipt.js';
import {
  createStripeAllowanceConnector,
  guardStripeAllowanceMutation,
} from '../../packages/gate/adapters/stripe.js';
import { canonicalize } from '../../packages/gate/execution-binding.js';
import { createProtectionPlan } from '../../packages/gate/protection-plan.js';
import {
  ADMISSION_CURRENTNESS_VERSION,
  createMemoryAdmissionStore,
} from '../../packages/gate/admission-store.js';

export const FINANCE_LOSS_BOUNDARY_VERSION = 'EP-FINANCE-LOSS-BOUNDARY-v1';
export const FINANCE_LOSS_BOUNDARY_CLAIM =
  'synthetic_local_reference_showing_pre_entry_refusal_single_admitted_provider_attempt_and_separate_provider_effect_evidence_not_source_truth_not_invoice_validity_not_settlement_not_payment_loss_prevention';

const NOW = '2026-08-20T18:00:00.000Z';
const NOW_MS = Date.parse(NOW);
const INPUT_EXPIRES = '2026-08-20T18:15:00.000Z';
const ADMISSION_EXPIRES = '2026-08-20T18:10:00.000Z';

/** @returns {`sha256:${string}`} */
function digest(label) {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function publicKey(key) {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function caid(label) {
  return `caid:1:payment.release.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`;
}

function ownerToken(byte) {
  return `admission-owner:v2:${Buffer.alloc(32, byte).toString('base64url')}`;
}

function immutableSnapshot() {
  return { kind: 'immutable', observed_at: null, source_version: null };
}

function fieldRule(path, role, required, allowedOrigins) {
  return {
    path,
    role,
    required,
    allowed_origins: allowedOrigins,
    snapshot_policy: 'immutable',
    max_snapshot_age_sec: null,
    allowed_transform_ids: [],
  };
}

const BANK_ACTION = Object.freeze({
  action_type: 'finops.vendor.bank_detail_change',
  vendor_id: 'V-88012',
  erp: 'netsuite.prod.example',
  change_ticket: 'CHG-2026-4471',
  new_account_digest: digest('approved-bank-account'),
});

const FIELD_ORIGIN_PROFILE = Object.freeze({
  profile_id: 'profile:finance-loss-boundary:field-origin:01',
  relying_party_id: 'rp:finance-loss-boundary',
  action_type: BANK_ACTION.action_type,
  fields: [
    fieldRule('/action_type', 'control', true, ['operator_pinned']),
    fieldRule('/vendor_id', 'control', true, ['operator_pinned', 'approver_supplied']),
    fieldRule('/erp', 'control', true, ['operator_pinned']),
    fieldRule('/change_ticket', 'control', true, ['operator_pinned', 'approver_supplied']),
    fieldRule('/new_account_digest', 'control', true, ['approver_supplied']),
    fieldRule('/memo', 'bounded_data', false, ['operator_pinned', 'approver_supplied', 'untrusted_bounded']),
  ],
  transforms: [],
});

const BANK_ACTION_PACK = Object.freeze([Object.freeze({
  id: BANK_ACTION.action_type,
  label: 'Vendor bank-detail change',
  action_type: BANK_ACTION.action_type,
  risk: 'critical',
  receipt_required: true,
  assurance_class: 'quorum',
  match: { protocol: 'finops', tool: 'vendor_bank_detail_change' },
  execution_binding: { required_fields: Object.keys(BANK_ACTION) },
})]);

function fieldAnnotations(action, overrides = {}) {
  return Object.keys(action).sort().map((key) => ({
    path: `/${key}`,
    origin_class: key === 'action_type' || key === 'vendor_id' || key === 'erp'
      ? 'operator_pinned'
      : (key === 'memo' ? 'untrusted_bounded' : 'approver_supplied'),
    snapshot: immutableSnapshot(),
    transform: null,
    ...(overrides[`/${key}`] ?? {}),
  }));
}

function fieldOriginHarness() {
  const evidenceKeys = generateKeyPairSync('ed25519');
  const evidenceKeyId = 'key:finance-field-origin';
  const evidenceSigner = {
    issuer_id: FIELD_ORIGIN_PROFILE.relying_party_id,
    key_id: evidenceKeyId,
    private_key: evidenceKeys.privateKey,
  };
  const trustedEvidenceKeys = {
    [evidenceKeyId]: {
      issuer_id: FIELD_ORIGIN_PROFILE.relying_party_id,
      public_key: publicKey(evidenceKeys.publicKey),
    },
  };

  const programKeys = generateKeyPairSync('ed25519');
  const programKeyId = 'key:finance-operating-mandate';
  const programIssuer = 'customer:finance-operations';
  const program = signBoundedExecutionProgram({
    program_id: 'program:finance-loss-boundary:01',
    tenant_id: 'tenant:finance-design-partner',
    version: 1,
    subject_id: 'agent:finance-operations:01',
    audience: 'gate:finance-operations:01',
    objective_digest: digest('finance-loss-boundary-objective'),
    authorization_digest: digest('finance-loss-boundary-authorization'),
    presentation_digest: digest('finance-loss-boundary-presentation'),
    supersedes_program_digest: null,
    issued_at: '2026-08-20T17:50:00.000Z',
    valid_from: '2026-08-20T17:55:00.000Z',
    expires_at: '2026-08-20T19:00:00.000Z',
    max_total_occurrences: 2,
    max_concurrent_effects: 1,
    budgets: [{ budget_id: 'vendor-change-attempts', unit: 'attempt', limit: 2 }],
    nodes: [{
      node_id: 'vendor-bank-detail-change',
      action: {
        mode: 'profile',
        profile_id: FIELD_ORIGIN_PROFILE.profile_id,
        profile_digest: fieldOriginProfileDigest(FIELD_ORIGIN_PROFILE),
      },
      trust_program_digest: digest('finance-loss-boundary-trust-program'),
      depends_on: [],
      max_occurrences: 2,
      charges: [{ budget_id: 'vendor-change-attempts', amount: 1 }],
    }],
  }, {
    issuer_id: programIssuer,
    key_id: programKeyId,
    private_key: programKeys.privateKey,
  });
  const executionProgram = {
    artifact: program,
    verification_options: {
      trusted_keys: {
        [programKeyId]: {
          issuer_id: programIssuer,
          public_key: publicKey(programKeys.publicKey),
        },
      },
      now: NOW,
      expected_program_id: 'program:finance-loss-boundary:01',
      expected_tenant_id: 'tenant:finance-design-partner',
      expected_authorizer_id: programIssuer,
      expected_authorization_digest: digest('finance-loss-boundary-authorization'),
      expected_audience: 'gate:finance-operations:01',
    },
    node_id: 'vendor-bank-detail-change',
  };

  return { evidenceSigner, trustedEvidenceKeys, executionProgram };
}

async function runVendorChangeCases() {
  const field = fieldOriginHarness();
  const receipt = createEg1Harness({
    action: BANK_ACTION,
    now: () => NOW_MS,
    idPrefix: 'finance-loss-boundary',
  });
  const gate = createGate({
    manifest: manifestFromPack([...BANK_ACTION_PACK]),
    trustedKeys: [receipt.publicKey],
    approverKeys: receipt.approverKeys,
    rpId: receipt.rpId,
    allowedOrigins: receipt.allowedOrigins,
    quorumPolicy: receipt.quorumPolicy,
    store: new MemoryConsumptionStore(),
    allowEphemeralStore: true,
    now: () => NOW_MS,
    requiredFieldOriginProfile: FIELD_ORIGIN_PROFILE,
    fieldOriginTrustedKeys: field.trustedEvidenceKeys,
    fieldOriginExecutionProgram: field.executionProgram,
  });

  async function run(action, annotations) {
    let effects = 0;
    const result = await gate.run({
      selector: { protocol: 'finops', tool: 'vendor_bank_detail_change' },
      receipt: receipt.mint({ outcome: 'allow_with_signoff', quorum: { threshold: 2 } }),
      observedAction: action,
      fieldOriginEvidence: signFieldOriginEvidence({
        evidence_id: `evidence:finance-field-origin:${crypto.randomUUID()}`,
        profile: FIELD_ORIGIN_PROFILE,
        observed_action: action,
        observed_at: NOW,
        annotations,
      }, field.evidenceSigner),
    }, async () => {
      effects += 1;
      return { changed: true };
    });
    return {
      admitted: result.ok === true,
      reason: result.ok === true ? null : result.authorization.reason,
      effects,
    };
  }

  const injectedEmail = await run(BANK_ACTION, fieldAnnotations(BANK_ACTION, {
    '/new_account_digest': { origin_class: 'untrusted_bounded' },
  }));
  const positive = { ...BANK_ACTION, memo: 'Invoice memo supplied by email' };
  const boundedMemo = await run(positive, fieldAnnotations(positive));
  return { injected_email: injectedEmail, bounded_memo: boundedMemo };
}

function authorizationReceipt(keys) {
  const payload = {
    receipt_id: 'receipt:finance-loss-boundary:allowance',
    created_at: '2026-08-20T17:59:00.000Z',
    subject: 'finance-owner@example.test',
    claim: {
      action_type: 'gate.allowance.issue',
      outcome: 'allow',
      capability_only: true,
    },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(null, Buffer.from(canonicalize(payload)), keys.privateKey).toString('base64url'),
    },
    public_key: publicKey(keys.publicKey),
  };
}

function verifyAuthorizationReceipt(receipt, expectedPublicKey) {
  if (receipt?.['@version'] !== 'EP-RECEIPT-v1'
      || receipt?.signature?.algorithm !== 'Ed25519'
      || receipt?.public_key !== expectedPublicKey
      || receipt?.payload?.claim?.capability_only !== true) {
    return { ok: false, reason: 'authorization_receipt_rejected' };
  }
  const key = createPublicKey({
    key: Buffer.from(receipt.public_key, 'base64url'),
    type: 'spki',
    format: 'der',
  });
  return verify(
    null,
    Buffer.from(canonicalize(receipt.payload)),
    key,
    Buffer.from(receipt.signature.value, 'base64url'),
  ) ? { ok: true } : { ok: false, reason: 'authorization_signature_invalid' };
}

async function runPayoutCases() {
  const tenantId = 'tenant:finance-design-partner';
  const allowanceId = 'allowance:finance-loss-boundary:01';
  const connectorId = 'stripe:acct_finance_demo';
  const allowanceProfileId = `${tenantId}/${allowanceId}`;
  const controlDomainId = 'control-domain:finance-loss-boundary';
  const customerKeys = generateKeyPairSync('ed25519');
  const capabilityKeys = generateKeyPairSync('ed25519');
  const customerKeyId = 'key:finance-loss-boundary-customer';
  const customerIssuer = 'customer:finance-operations';
  const receipt = authorizationReceipt(customerKeys);
  const allowance = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: {
      allowance_id: allowanceId,
      tenant_id: tenantId,
      subject_id: 'agent:finance-operations:01',
      audience: 'gate:finance-operations:01',
      connector_id: connectorId,
      action_type: 'stripe.payout.create',
      revision: 1,
      supersedes_allowance_digest: null,
      authorization_receipt_digest: capabilityBaseReceiptDigest(receipt),
      presentation_digest: digest('finance-loss-boundary-allowance-presentation'),
      issued_at: '2026-08-20T17:59:00.000Z',
      valid_from: NOW,
      expires_at: '2026-08-21T18:00:00.000Z',
      constraints: {
        currency: 'USD',
        aggregate_amount: 10_000,
        max_amount_per_action: 5_000,
        material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
        operation_id_field: 'operation_id',
        amount_field: 'amount',
        currency_field: 'currency',
        target_field: 'destination',
        allowed_targets: ['acct_known_vendor'],
        allowed_values: {},
      },
    },
    signer: {
      issuer_id: customerIssuer,
      key_id: customerKeyId,
      private_key: customerKeys.privateKey,
    },
    capabilityIssuerPrivateKey: capabilityKeys.privateKey,
    capabilityRevocationMode: 'direct',
  });
  const controlAuthorityDigest = digest('finance-loss-boundary-control-authority');
  const store = createMemoryCapabilityStore({
    verifyControlTransition: (input) => {
      const authorization = input.authorization;
      if (!authorization || typeof authorization !== 'object' || Array.isArray(authorization)) {
        return { authenticated: false, authorized: false };
      }
      const claim = /** @type {{
        authenticated?: unknown;
        currently_authorized?: unknown;
        authority_instance_digest?: string;
        action_digest?: string;
      }} */ (authorization);
      return {
        authenticated: claim.authenticated === true,
        authorized: claim.currently_authorized === true,
        authority_instance_digest: claim.authority_instance_digest,
        action_digest: claim.action_digest,
      };
    },
  });
  if (!store.registerCapability(allowance.capabilityReceipt)) {
    throw new Error('finance_loss_capability_registration_failed');
  }
  const registered = await store.registerControlDomain({ controlDomainId, now: NOW_MS });
  if (!registered.ok) throw new Error('finance_loss_control_domain_registration_failed');
  const allowanceArtifactDigest = allowanceDigest(allowance.allowance);
  /** @type {Parameters<ReturnType<typeof createMemoryCapabilityStore>['advanceAllowanceStatus']>[0]} */
  const status = {
    allowance_profile_id: allowanceProfileId,
    allowance_digest: allowanceArtifactDigest,
    revision: 1,
    expected_status_epoch: null,
    expected_status_head_digest: null,
    status_epoch: 1,
    status_head_digest: digest('finance-loss-boundary-status-head:1'),
    status: 'active',
  };
  const advanced = await store.advanceAllowanceStatus(status);
  if (!advanced.ok) throw new Error('finance_loss_allowance_status_failed');

  /** @type {Array<{params: Record<string, unknown>, options: Record<string, unknown>}>} */
  const stripeCalls = [];
  const localStripe = {
    calls: stripeCalls,
    accounts: { retrieve: async () => ({ id: 'acct_finance_demo' }) },
    payouts: {
      create: async (params, options) => {
        localStripe.calls.push({ params: structuredClone(params), options: structuredClone(options) });
        return { id: `po_finance_${localStripe.calls.length}`, ...params };
      },
    },
  };
  const connector = await createStripeAllowanceConnector({ stripe: localStripe });
  const expected = {
    allowance_id: allowanceId,
    tenant_id: tenantId,
    subject_id: 'agent:finance-operations:01',
    audience: 'gate:finance-operations:01',
    connector_id: connectorId,
    authorizer_id: customerIssuer,
  };
  const options = {
    allowance: allowance.allowance,
    capabilityReceipt: allowance.capabilityReceipt,
    secret: allowance.secret,
    store,
    verifyAuthorizationReceipt: (candidate) => verifyAuthorizationReceipt(candidate, publicKey(customerKeys.publicKey)),
    verifyAllowanceStatus: (_candidate, context) => ({
      ok: context.allowance_digest === allowanceArtifactDigest,
      reason: 'allowance_superseded',
      status_epoch: status.status_epoch,
      status_head_digest: status.status_head_digest,
    }),
    trustedAllowanceKeys: {
      [customerKeyId]: {
        issuer_id: customerIssuer,
        public_key: publicKey(customerKeys.publicKey),
      },
    },
    trustedCapabilityIssuerKeys: [publicKey(capabilityKeys.publicKey)],
    expected,
    controlDomainId,
    now: NOW_MS,
  };

  const first = await guardStripeAllowanceMutation({
    connector,
    params: { amount: 2_500, currency: 'USD', destination: 'acct_known_vendor' },
    operationId: 'payout:finance-loss:01',
    ...options,
  });
  const allowed = { admitted: first.ok === true, provider_calls: localStripe.calls.length };
  const repeated = await guardStripeAllowanceMutation({
    connector,
    params: { amount: 2_500, currency: 'USD', destination: 'acct_known_vendor' },
    operationId: 'payout:finance-loss:01',
    ...options,
  });
  const replay = {
    admitted: repeated.ok === true,
    reason: repeated.reason,
    provider_calls: localStripe.calls.length,
  };

  const freezeActionDigest = digest('finance-loss-boundary-freeze');
  const frozen = await store.freezeControlDomain({
    controlDomainId,
    operationId: 'control:finance-loss:freeze:01',
    actionDigest: freezeActionDigest,
    authorization: {
      authenticated: true,
      currently_authorized: true,
      authority_instance_digest: controlAuthorityDigest,
      action_digest: freezeActionDigest,
    },
    now: NOW_MS + 1,
  });
  if (!frozen.ok) throw new Error('finance_loss_control_domain_freeze_failed');
  const frozenAttempt = await guardStripeAllowanceMutation({
    connector,
    params: { amount: 1_000, currency: 'USD', destination: 'acct_known_vendor' },
    operationId: 'payout:finance-loss:frozen',
    ...options,
  });
  return {
    allowed,
    replay,
    frozen: {
      admitted: frozenAttempt.ok === true,
      reason: frozenAttempt.reason,
      provider_calls: localStripe.calls.length,
    },
  };
}

function admissionInput(role, suffix) {
  return {
    role,
    artifact_type: `artifact.${role}`,
    subject: `subject:${suffix}:${role}`,
    payload_digest: digest(`payload:${suffix}:${role}`),
    profile_digest: digest(`profile:${suffix}:${role}`),
    verifier_id: `verifier:${role}`,
    trust_configuration_digest: digest(`trust:${suffix}:${role}`),
    valid_until: INPUT_EXPIRES,
  };
}

/**
 * @param {string} suffix
 * @returns {import('../../packages/gate/admission-store.js').AdmissionSnapshotInput}
 */
function admissionSnapshot(suffix) {
  const operationId = `operation:${suffix}`;
  const admissionId = `admission:${suffix}`;
  /** @type {Array<[import('../../packages/gate/admission-store.js').AdmissionResourceKind, string]>} */
  const resourceReservations = [
    ['replay', `receipt:${suffix}`],
    ['budget', `budget:${suffix}`],
    ['provider_operation', operationId],
    ['external_lease', `lease:${suffix}`],
  ];
  return {
    tenant_id: `tenant:${suffix}`,
    admission_id: admissionId,
    operation_id: operationId,
    candidate_manifest_digest: digest(`candidate:${suffix}`),
    runtime_measurement_digest: digest(`runtime:${suffix}`),
    candidate_custody: {
      request_construction: 'EXECUTOR_ADAPTER',
      mutation_credential_custody: 'EXECUTOR_ADAPTER',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: digest(`custody:${suffix}`),
    },
    assignment_digest: digest(`assignment:${suffix}`),
    qualification_policy_digest: digest(`qualification-policy:${suffix}`),
    test_result_payload_digests: [digest(`test-result:${suffix}`)],
    agent_evaluation_evidence_payload_digests: [digest(`agent-evidence:${suffix}`)],
    qualification_statement_payload_digest: digest(`qualification-statement:${suffix}`),
    qualification_status: {
      authority_id: 'qualification-authority:finance',
      sequence: 7,
      head_payload_digest: digest(`status-head:${suffix}`),
      observed_at: NOW,
      expires_at: INPUT_EXPIRES,
    },
    caid: caid(suffix),
    action_digest: digest(`action:${suffix}`),
    effect_request_digest: digest(`effect-request:${suffix}`),
    provider: {
      provider_id: 'provider:payment-rail',
      account_id: 'account:merchant',
      environment: 'sandbox',
    },
    executor_adapter_digest: digest(`adapter:${suffix}`),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: digest(`authorization-policy:${suffix}`),
    trust_epoch: 4,
    trust_configuration_digest: digest(`trust-configuration:${suffix}`),
    configuration_epoch: 9,
    configuration_digest: digest(`configuration:${suffix}`),
    inputs: [
      'authorization', 'test_result', 'aeb', 'candidate_manifest', 'local_policy',
      'qualification_statement', 'runtime_measurement', 'qualification_status',
      'agent_evaluation_evidence', 'aec',
    ].map((role) => admissionInput(role, suffix)),
    resource_reservations: resourceReservations.map(([kind, resourceId]) => ({
      kind,
      resource_id: resourceId,
      reservation_id: `${kind}:${admissionId}`,
      digest: digest(`${kind}:${suffix}`),
      expires_at: INPUT_EXPIRES,
    })),
    admitted_at: NOW,
    expires_at: ADMISSION_EXPIRES,
    supersedes_admission_id: null,
    remedy_for: null,
  };
}

/**
 * @param {import('../../packages/gate/admission-store.js').AdmissionSnapshotInput} value
 * @returns {import('../../packages/gate/admission-store.js').AdmissionCurrentnessObservation}
 */
function currentness(value) {
  return {
    '@version': ADMISSION_CURRENTNESS_VERSION,
    observed_at: NOW,
    qualification_status_authority_id: value.qualification_status.authority_id,
    qualification_status_sequence: value.qualification_status.sequence,
    qualification_status_head_digest: value.qualification_status.head_payload_digest,
    qualification_status_expires_at: value.qualification_status.expires_at,
    trust_epoch: value.trust_epoch,
    trust_configuration_digest: value.trust_configuration_digest,
    configuration_epoch: value.configuration_epoch,
    configuration_digest: value.configuration_digest,
    runtime_measurement_digest: value.runtime_measurement_digest,
    candidate_match: 'EXACT_MATCH',
    external_leases: value.resource_reservations
      .filter((resource) => resource.kind === 'external_lease')
      .map((resource) => ({
        resource_id: resource.resource_id,
        digest: resource.digest,
        expires_at: resource.expires_at,
      })),
  };
}

/**
 * @param {ReturnType<typeof createMemoryAdmissionStore>} store
 * @param {import('../../packages/gate/admission-store.js').AdmissionSnapshotInput} value
 */
async function beginAdmission(store, value) {
  const reserved = await store.reserve(value);
  if (!reserved.ok) throw new Error(`finance_loss_reserve_failed:${reserved.reason}`);
  const begun = await store.beginInvocation({
    tenant_id: value.tenant_id,
    admission_id: value.admission_id,
    expected_revision: 0,
    owner_token: reserved.owner_token,
  });
  if (!begun.ok) throw new Error(`finance_loss_begin_failed:${begun.reason}`);
  return { reserved, begun };
}

async function runOutcomeCases() {
  const invocationToken = `admission-invocation:v2:${Buffer.alloc(32, 4).toString('base64url')}`;
  const divergedInput = admissionSnapshot('finance-diverged');
  const divergedStore = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => ownerToken(1),
    invocationTokenFactory: () => invocationToken,
    currentnessOracle: { read: async (snapshot) => currentness(snapshot.body) },
  });
  const divergedStart = await beginAdmission(divergedStore, divergedInput);
  const provider = await divergedStore.recordProviderOutcome({
    tenant_id: divergedInput.tenant_id,
    admission_id: divergedInput.admission_id,
    expected_revision: 1,
    owner_token: divergedStart.reserved.owner_token,
    invocation_token: invocationToken,
    value: 'COMMITTED',
    evidence_digest: digest('provider-commitment-evidence'),
    observed_at: NOW,
  });
  if (!provider.ok) throw new Error(`finance_loss_provider_outcome_failed:${provider.reason}`);
  const effect = await divergedStore.recordEffectRelation({
    tenant_id: divergedInput.tenant_id,
    admission_id: divergedInput.admission_id,
    expected_revision: 2,
    owner_token: divergedStart.reserved.owner_token,
    invocation_token: invocationToken,
    value: 'DIVERGED',
    evidence_digest: digest('independent-effect-evidence'),
    observed_at: NOW,
  });
  if (!effect.ok) throw new Error(`finance_loss_effect_relation_failed:${effect.reason}`);

  const unknownInput = admissionSnapshot('finance-unknown');
  const unknownStore = createMemoryAdmissionStore({
    now: NOW,
    ownerTokenFactory: () => ownerToken(2),
    currentnessOracle: { read: async (snapshot) => currentness(snapshot.body) },
  });
  const unknownStart = await beginAdmission(unknownStore, unknownInput);
  const unknown = await unknownStore.recoverIndeterminate({
    tenant_id: unknownInput.tenant_id,
    admission_id: unknownInput.admission_id,
    owner_token: unknownStart.reserved.owner_token,
  });
  if (!unknown.ok) throw new Error(`finance_loss_indeterminate_failed:${unknown.reason}`);
  const retry = await unknownStore.beginInvocation({
    tenant_id: unknownInput.tenant_id,
    admission_id: unknownInput.admission_id,
    expected_revision: 2,
    owner_token: unknownStart.reserved.owner_token,
  });
  if (retry.ok) throw new Error('finance_loss_blind_retry_unexpectedly_admitted');

  return {
    diverged: {
      provider_outcome: effect.record.provider_outcome,
      effect_relation: effect.record.effect_relation,
      execution_right: effect.record.execution_right,
    },
    unknown: {
      state: unknown.record.state,
      execution_right: unknown.record.execution_right,
      blind_retry: retry.reason,
    },
  };
}

export async function runFinanceLossBoundaryScenario() {
  const protectionPlan = createProtectionPlan({
    planId: 'finance-loss-boundary',
    ownerLabel: 'Finance design partner',
    createdAt: NOW,
    selections: [{ presetId: 'spend-money' }],
  });
  const [vendorChange, payout, outcomes] = await Promise.all([
    runVendorChangeCases(),
    runPayoutCases(),
    runOutcomeCases(),
  ]);
  return Object.freeze({
    '@version': FINANCE_LOSS_BOUNDARY_VERSION,
    claim_boundary: FINANCE_LOSS_BOUNDARY_CLAIM,
    network_requests: 0,
    money_moved: false,
    protection_plan: Object.freeze({
      version: protectionPlan['@version'],
      selection: protectionPlan.selections[0].preset_id,
      authority: protectionPlan.authority.status,
      activation: protectionPlan.activation.status,
    }),
    vendor_change: Object.freeze(vendorChange),
    payout: Object.freeze(payout),
    outcomes: Object.freeze(outcomes),
  });
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  console.log(JSON.stringify(await runFinanceLossBoundaryScenario(), null, 2));
}
