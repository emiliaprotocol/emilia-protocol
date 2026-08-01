// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  ADMISSION_CURRENTNESS_VERSION,
  createAdmissionSnapshot,
  createMemoryAdmissionStore,
  type AdmissionCurrentnessObservation,
  type AdmissionDigest,
  type AdmissionInput,
  type AdmissionSnapshot,
  type AdmissionSnapshotInput,
} from './admission-store.js';
import {
  composeQualificationDecisionV2,
  type GateQualificationBundleV2,
} from './gate-qualification-v2.js';
import {
  createFidoAp2AdmissionInput,
  createFidoAp2QualificationBundle,
  digestFidoAp2EffectRequest,
  type FidoAp2AuthenticatedStatus,
  type FidoAp2ProviderRequestVerifier,
  type FidoAp2TrustedAdmissionControls,
} from './fido-ap2-bridge.js';
// @ts-expect-error -- the CAID reference implementation intentionally has no TS surface.
import { computeCaid } from '../verify/vendor/caid.mjs';
import {
  AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
  adapterPinDigest,
  canonicalizeAeb,
  createAebNativeVerificationAttestationAdapter,
  digestAeb,
  evaluateAebEvidence,
  registryEntryDigest,
  signAebNativeVerificationAttestation,
  unifiedRegistryDigest,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  createFidoAp2AebAdapter,
  createFidoAp2NativeSourceBinding,
  createFidoAp2PinnedProfile,
  FIDO_AP2_ACTION_TYPE,
  FIDO_AP2_AEB_CONFIG_VERSION,
  FIDO_AP2_AEB_TRUST_ROOT_VERSION,
  FIDO_AP2_CAID_ACTION_DEFINITIONS,
  FIDO_AP2_CAID_MAPPER_ID,
  FIDO_AP2_CAID_PROFILE_ID,
  FIDO_AP2_NATIVE_PROTOCOL_ID,
  FIDO_AP2_SOURCE_REVISION,
  projectFidoAp2PaymentAction,
} from '@emilia-protocol/verify/fido-ap2-bridge';

type Obj = Record<string, any>;

const NOW = '2026-07-31T18:00:00.000Z';
const ADMISSION_EXPIRES = '2026-07-31T18:03:00.000Z';
const SOURCE_EXPIRES = '2026-07-31T18:04:00.000Z';
const INPUT_EXPIRES = '2026-07-31T18:05:00.000Z';
const SOURCE_IAT = Math.floor(Date.parse('2026-07-31T17:59:00.000Z') / 1_000);
const CHECKOUT_EXP = Math.floor(Date.parse('2026-07-31T18:05:00.000Z') / 1_000);
const PAYMENT_EXP = Math.floor(Date.parse(SOURCE_EXPIRES) / 1_000);
const TENANT_ID = 'tenant:merchant-alpha';
const RELYING_PARTY_ID = 'rp:payments-production';
const AUDIENCE = 'urn:emilia:gate:payments';
const OPERATION_ID = 'operation:payment-001';
const ADMISSION_ID = 'admission:payment-001';
const INITIATOR_ID = 'workload:checkout-agent';
const EXECUTOR_ID = 'executor:payments-v1';
const APPROVER_ID = 'human:approver-7';
const PROVIDER = Object.freeze({
  provider_id: 'provider:stripe',
  account_id: 'account:merchant-alpha',
  environment: 'production',
});
const RP_ID = 'payments.example.test';
const ORIGIN = 'https://payments.example.test';
const CREDENTIAL_ID = 'credential:approver-7:p256';
const NONCE = 'fido-ap2-20260731-0001';
const NATIVE_PROTOCOL = FIDO_AP2_NATIVE_PROTOCOL_ID;
const NATIVE_ADAPTER_ID = 'bridge:ap2-native-verifier';
const NATIVE_KEY_ID = 'native-verifier:ap2:test';
const EVALUATOR_KEY_ID = 'evaluator:fido-ap2:test';
const HUMAN_ARTIFACT_REF = 'artifact:fido-human:001';
const NATIVE_ARTIFACT_REF = 'artifact:ap2-native:001';
const EXECUTOR_ADAPTER_DIGEST = d('provider-adapter:fido-ap2:v1');

const webauthnSigner = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const nativeVerifierSigner = crypto.generateKeyPairSync('ed25519');
const evaluatorSigner = crypto.generateKeyPairSync('ed25519');

function d(label: string): AdmissionDigest {
  return `sha256:${crypto.createHash('sha256').update(label, 'utf8').digest('hex')}`;
}

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function compactJwt(label: string, payload: unknown): string {
  return [
    base64urlJson({ alg: 'ES256', kid: `key:${label}`, typ: 'JWT' }),
    base64urlJson(payload),
    Buffer.from(`deterministic-signature:${label}`, 'utf8').toString('base64url'),
  ].join('.');
}

function canonicalSdJwt(label: string, payload: unknown): string {
  return `${compactJwt(label, payload)}~`;
}

function sha256Base64url(value: string): string {
  return crypto.createHash('sha256').update(value, 'ascii').digest('base64url');
}

function hashBase64url(
  algorithm: 'sha-256' | 'sha-384' | 'sha-512',
  value: string,
): string {
  return crypto.createHash(algorithm.replace('-', ''))
    .update(value, 'ascii').digest('base64url');
}

interface RawAp2Options {
  seed?: string;
  checkoutTokenIssue?: string;
  checkoutExp?: number;
  paymentExp?: number;
  checkoutHashAlgorithm?: 'sha-256' | 'sha-384' | 'sha-512';
}

function rawAp2(options: RawAp2Options = {}) {
  const seed = options.seed ?? '001';
  const checkoutPayloadJwt = compactJwt(`checkout-payload:${seed}`, {
    cart_id: `cart-${seed}`,
    line_items: [{
      description: 'Industrial sensor',
      quantity: 1,
      amount_minor: 12_550,
    }],
    total: { amount: 12_550, currency: 'USD' },
  });
  const checkoutHashAlgorithm = options.checkoutHashAlgorithm ?? 'sha-256';
  const checkoutHash = hashBase64url(checkoutHashAlgorithm, checkoutPayloadJwt);
  const checkoutMandate = {
    vct: 'mandate.checkout.1',
    checkout_jwt: checkoutPayloadJwt,
    checkout_hash: checkoutHash,
    iat: SOURCE_IAT,
    exp: options.checkoutExp ?? CHECKOUT_EXP,
  };
  const paymentMandate: Obj = {
    vct: 'mandate.payment.1',
    transaction_id: checkoutHash,
    payee: { id: 'merchant:acme', name: 'Acme Industrial' },
    payment_amount: { amount: 12_550, currency: 'USD' },
    payment_instrument: {
      id: 'instrument:visa-4242',
      type: 'CARD',
    },
    iat: SOURCE_IAT,
    exp: options.paymentExp ?? PAYMENT_EXP,
  };
  const checkoutMandateToken = canonicalSdJwt(
    `checkout-mandate:${options.checkoutTokenIssue ?? seed}`,
    checkoutHashAlgorithm === 'sha-256'
      ? checkoutMandate
      : { ...checkoutMandate, _sd_alg: checkoutHashAlgorithm },
  );
  const paymentMandateToken = canonicalSdJwt(
    `payment-mandate:${seed}`,
    paymentMandate,
  );
  const sourceBinding = createFidoAp2NativeSourceBinding({
    checkout_mandate_token: checkoutMandateToken,
    payment_mandate_token: paymentMandateToken,
    checkout_mandate_payload: checkoutMandate,
    payment_mandate_payload: paymentMandate,
  });
  return {
    checkout_mandate: checkoutMandate,
    payment_mandate: paymentMandate,
    checkout_mandate_token: checkoutMandateToken,
    payment_mandate_token: paymentMandateToken,
    source_binding: sourceBinding,
  };
}

function projectionInput(raw: ReturnType<typeof rawAp2>): Obj {
  return {
    checkout_mandate: raw.checkout_mandate,
    payment_mandate: raw.payment_mandate,
    source_binding: raw.source_binding,
  };
}

function disclosureFor(action: Obj): Obj {
  return {
    checkout_commitment: action.checkout_mandate_digest,
    payment_commitment: action.payment_mandate_digest,
    checkout_payload_jwt_commitment: action.checkout_payload_jwt_digest,
    transaction_id: action.transaction_id,
    amount_minor: action.amount_minor,
    currency: action.currency,
    payee_id: action.payee_id,
    payee_name: action.payee_name,
    payment_instrument_id: action.payment_instrument_id,
    payment_instrument_type: action.payment_instrument_type,
    execution: action.execution,
    source_expires_at: action.source_expires_at,
  };
}

function caid(action: Obj): string {
  const result = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: FIDO_AP2_CAID_ACTION_DEFINITIONS,
  });
  assert.equal(typeof result.caid, 'string');
  return result.caid;
}

function evidenceInput(
  role: AdmissionInput['role'],
  payloadDigest: AdmissionDigest,
): AdmissionInput {
  return {
    role,
    artifact_type: `artifact.${role}`,
    subject: `subject:${role}`,
    payload_digest: payloadDigest,
    profile_digest: d(`profile:${role}`),
    verifier_id: `verifier:${role}`,
    trust_configuration_digest: d(`trust:${role}`),
    valid_until: INPUT_EXPIRES,
  };
}

function registryEntry(
  id: string,
  kind: string,
  version: string,
  definition: Obj,
): Obj {
  const entry: Obj = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(id, entry as any);
  return entry;
}

function webauthnAssertion(context: Obj): Obj {
  const challenge = crypto.createHash('sha256')
    .update(canonicalizeAeb(context), 'utf8')
    .digest('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin: ORIGIN,
  }), 'utf8');
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(42);
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([0x05]),
    counter,
  ]);
  const signedData = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientData).digest(),
  ]);
  return {
    credential_id: CREDENTIAL_ID,
    authenticator_data: authenticatorData.toString('base64url'),
    client_data_json: clientData.toString('base64url'),
    signature: crypto.sign(
      'sha256',
      signedData,
      webauthnSigner.privateKey,
    ).toString('base64url'),
  };
}

function providerRequestBytes(
  paymentMandateToken: string,
  provider: Readonly<typeof PROVIDER> = PROVIDER,
): Uint8Array {
  return Buffer.from(JSON.stringify({
    operation_id: OPERATION_ID,
    provider,
    payment_mandate_token: paymentMandateToken,
  }), 'utf8');
}

function exactProviderRequestVerifier(
  expectedBytes: Uint8Array,
  expectedPaymentToken: string,
  expectedPaymentDigest: AdmissionDigest,
  expectedProvider: Readonly<typeof PROVIDER> = PROVIDER,
  onVerify?: (input: Parameters<FidoAp2ProviderRequestVerifier['verify']>[0]) => void,
): FidoAp2ProviderRequestVerifier {
  const bytes = Buffer.from(expectedBytes);
  return {
    id: 'provider-request-verifier:fido-ap2:v1',
    version: '1',
    implementation_digest: EXECUTOR_ADAPTER_DIGEST,
    verify(input) {
      onVerify?.(input);
      return Buffer.from(input.effect_request_bytes).equals(bytes)
        && input.payment_mandate_token === expectedPaymentToken
        && input.payment_mandate_token_digest === expectedPaymentDigest
        && input.provider.provider_id === expectedProvider.provider_id
        && input.provider.account_id === expectedProvider.account_id
        && input.provider.environment === expectedProvider.environment;
    },
  };
}

function authenticatedStatuses(
  evaluation: Obj,
  status: Obj,
): [FidoAp2AuthenticatedStatus, FidoAp2AuthenticatedStatus] {
  const byRole = new Map<string, Obj>(
    evaluation.legs.map((leg: Obj) => [leg.evidence_role, leg]),
  );
  const native = byRole.get('ap2-native-authorization');
  const human = byRole.get('human_authorization');
  assert.ok(native);
  assert.ok(human);
  return [native, human].map((leg, index) => ({
    artifact_ref: leg.artifact_ref,
    evidence_digest: leg.evidence_digest,
    replay_unit: leg.replay_unit,
    authority_id: index === 0
      ? 'status-authority:ap2-native'
      : 'status-authority:webauthn',
    sequence: 11 + index,
    head_digest: d(`status-head:${leg.artifact_ref}:sequence:${11 + index}`),
    status: structuredClone(status),
  })) as [FidoAp2AuthenticatedStatus, FidoAp2AuthenticatedStatus];
}

interface FixtureOptions extends RawAp2Options {
  seed?: string;
  /**
   * Overrides applied AFTER projection, so the artifact, its disclosure, the
   * signed context and the native attestation are all rebuilt consistently
   * around an action that disagrees with the mandates the Gate holds. That is
   * the one shape a self-comparison cannot detect.
   */
  actionOverrides?: Record<string, unknown>;
}

function fixture(options: FixtureOptions = {}) {
  const ap2 = rawAp2(options);
  const action = { ...projectFidoAp2PaymentAction(projectionInput(ap2)), ...options.actionOverrides };
  const actionCaid = caid(action);
  const profile = createFidoAp2PinnedProfile();
  const effectBytes = providerRequestBytes(ap2.payment_mandate_token);
  const effectRequestDigest = digestFidoAp2EffectRequest(effectBytes);
  const nativeAttestation = signAebNativeVerificationAttestation({
    '@version': AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
    protocol_id: NATIVE_PROTOCOL,
    audience: AUDIENCE,
    native_artifact_ref: NATIVE_ARTIFACT_REF,
    native_artifact_digest: ap2.source_binding.native_artifact_digest,
    evidence_role: 'ap2-native-authorization',
    subject: { id: 'verifier:ap2-native-1', kind: 'system' },
    verified_at: '2026-07-31T17:59:30.000Z',
    expires_at: SOURCE_EXPIRES,
    mapping: {
      profile_digest: profile.profile_digest,
      mapper_id: profile.mapper_id,
      resolver_digest: profile.resolver.implementation_digest,
      caid: actionCaid,
      normalized_action_digest: digestAeb(action),
    },
  }, {
    key_id: NATIVE_KEY_ID,
    private_key: nativeVerifierSigner.privateKey,
  });
  const sourceCommitments = {
    checkout_mandate_token_digest:
      ap2.source_binding.checkout_mandate_token_digest,
    payment_mandate_token_digest:
      ap2.source_binding.payment_mandate_token_digest,
    native_verification_attestation_digest: digestAeb(nativeAttestation),
  };
  const disclosure = disclosureFor(action);
  const context = {
    source_revision: FIDO_AP2_SOURCE_REVISION,
    tenant_id: TENANT_ID,
    relying_party_id: RELYING_PARTY_ID,
    audience: AUDIENCE,
    operation_id: OPERATION_ID,
    effect_request_digest: effectRequestDigest,
    provider: { ...PROVIDER },
    source_commitments: structuredClone(sourceCommitments),
    normalized_action_digest: digestAeb(action),
    caid: actionCaid,
    disclosure_digest: digestAeb(disclosure),
    approver_id: APPROVER_ID,
    nonce: NONCE,
    expires_at: SOURCE_EXPIRES,
  };
  const humanArtifact = {
    '@version': 'EP-FIDO-AP2-EVIDENCE-v1',
    source_revision: FIDO_AP2_SOURCE_REVISION,
    tenant_id: TENANT_ID,
    relying_party_id: RELYING_PARTY_ID,
    audience: AUDIENCE,
    operation_id: OPERATION_ID,
    effect_request_digest: effectRequestDigest,
    provider: { ...PROVIDER },
    source_commitments: sourceCommitments,
    normalized_action: action,
    disclosure,
    signoff: {
      context,
      webauthn: webauthnAssertion(context),
    },
  };
  const humanAdapter = createFidoAp2AebAdapter();
  const nativeAdapter = createAebNativeVerificationAttestationAdapter({
    id: NATIVE_ADAPTER_ID,
    version: '1',
  });
  const entries: Obj = {
    [profile.registry_entry_ref]: registryEntry(
      profile.registry_entry_ref,
      'mapping-profile',
      profile.version,
      { profile_digest: profile.profile_digest },
    ),
    'role:ap2-native-authorization': registryEntry(
      'role:ap2-native-authorization',
      'evidence-role',
      '1',
      { role: 'ap2-native-authorization', subject_kinds: ['system'] },
    ),
    'role:human_authorization': registryEntry(
      'role:human_authorization',
      'evidence-role',
      '1',
      { role: 'human_authorization', subject_kinds: ['human'] },
    ),
  };
  const registry: Obj = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:fido-ap2:gate-test',
    epoch: 1,
    entries,
  };
  registry.registry_digest = unifiedRegistryDigest(registry as any);
  const humanConfig = {
    '@version': FIDO_AP2_AEB_CONFIG_VERSION,
    source_revision: FIDO_AP2_SOURCE_REVISION,
    evidence_role: 'human_authorization',
    subject: { id: APPROVER_ID, kind: 'human', native_id: CREDENTIAL_ID },
    tenant_id: TENANT_ID,
    relying_party_id: RELYING_PARTY_ID,
    audience: AUDIENCE,
    action_type: FIDO_AP2_ACTION_TYPE,
    rp_id: RP_ID,
    allowed_origins: [ORIGIN],
    expected_nonce: NONCE,
    max_status_age_seconds: 120,
    sign_count_policy: 'above-enrollment-and-one-time',
    allow_backup_eligible: false,
    allow_backup_state: false,
  };
  const humanRoot = {
    '@version': FIDO_AP2_AEB_TRUST_ROOT_VERSION,
    source_revision: FIDO_AP2_SOURCE_REVISION,
    approver_id: APPROVER_ID,
    credential_id: CREDENTIAL_ID,
    public_key_spki: webauthnSigner.publicKey.export({
      type: 'spki',
      format: 'der',
    }).toString('base64url'),
    rp_id: RP_ID,
    key_class: 'A',
    status: 'active',
    sign_count: 41,
  };
  const humanPin: Obj = {
    version: humanAdapter.version,
    trust_roots: [humanRoot],
    config: humanConfig,
    max_status_age_sec: 120,
  };
  humanPin.config_digest = adapterPinDigest(humanAdapter.id, humanPin as any);
  const nativePin: Obj = {
    version: nativeAdapter.version,
    trust_roots: [{
      key_id: NATIVE_KEY_ID,
      public_key: nativeVerifierSigner.publicKey.export({
        type: 'spki',
        format: 'der',
      }).toString('base64url'),
    }],
    config: { audience: AUDIENCE, accepted_protocols: [NATIVE_PROTOCOL] },
    max_status_age_sec: 120,
  };
  nativePin.config_digest = adapterPinDigest(nativeAdapter.id, nativePin as any);
  const pinnedConfig: Obj = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: RELYING_PARTY_ID,
    evaluator_keys: {
      [EVALUATOR_KEY_ID]: {
        public_key: evaluatorSigner.publicKey.export({
          type: 'spki',
          format: 'der',
        }).toString('base64url'),
      },
    },
    registry,
    accepted_mappers: [FIDO_AP2_CAID_MAPPER_ID],
    adapters: {
      [humanAdapter.id]: humanPin,
      [nativeAdapter.id]: nativePin,
    },
    profiles: { [FIDO_AP2_CAID_PROFILE_ID]: profile },
    requirements: {
      'requirement:fido-ap2:two-leg': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['ap2-native-authorization', 'human_authorization'],
        terms: [
          { type: 'initiator-exclusion', roles: ['human_authorization'] },
          { type: 'executor-exclusion', roles: ['human_authorization'] },
          { type: 'one-time-consumption' },
        ],
      },
    },
  };
  const status = {
    checked_at: '2026-07-31T17:59:45.000Z',
    expires_at: SOURCE_EXPIRES,
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  const evaluated = evaluateAebEvidence({
    config: pinnedConfig as any,
    adapters: {
      [humanAdapter.id]: humanAdapter,
      [nativeAdapter.id]: nativeAdapter,
    },
    operation_id: OPERATION_ID,
    consumption_nonce: NONCE,
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    requirement_ref: 'requirement:fido-ap2:two-leg',
    caid: actionCaid,
    expected_action: action,
    legs: [{
      adapter_id: nativeAdapter.id,
      profile_id: FIDO_AP2_CAID_PROFILE_ID,
      artifact_ref: NATIVE_ARTIFACT_REF,
      artifact: nativeAttestation,
      status,
    }, {
      adapter_id: humanAdapter.id,
      profile_id: FIDO_AP2_CAID_PROFILE_ID,
      artifact_ref: HUMAN_ARTIFACT_REF,
      artifact: humanArtifact,
      status,
    }],
    evaluated_at: NOW,
    signer: {
      key_id: EVALUATOR_KEY_ID,
      private_key: evaluatorSigner.privateKey,
    },
  });
  assert.equal(evaluated.valid, true, JSON.stringify(evaluated.reasons));

  const candidateManifest = d('candidate-manifest');
  const runtimeMeasurement = d('runtime-measurement');
  const testResult = d('test-result');
  const agentEvidence = d('agent-evaluation-evidence');
  const qualificationStatement = d('qualification-statement');
  const qualificationStatus = d('qualification-status-head');
  const aecEvidence = d('aec-evidence');
  const localPolicyEvidence = d('local-policy-evidence');
  const authorizationEvidence = d('authorization-evidence');
  const raw = {
    evaluation: evaluated.record,
    humanArtifact,
    nativeAttestation,
    bindings: {
      tenant_id: TENANT_ID,
      relying_party_id: RELYING_PARTY_ID,
      audience: AUDIENCE,
      admission_id: ADMISSION_ID,
      operation_id: OPERATION_ID,
      caid: evaluated.record.caid,
      action_digest: digestAeb(action),
      effect_request_digest: effectRequestDigest,
      provider: { ...PROVIDER },
      candidate_manifest_digest: candidateManifest,
      runtime_measurement_digest: runtimeMeasurement,
      candidate_custody: {
        request_construction: 'EXECUTOR_ADAPTER',
        mutation_credential_custody: 'EXECUTOR_ADAPTER',
        enforcement_placement: 'ACTUATOR',
        evidence_digest: d('candidate-custody'),
      },
      assignment_digest: d('assignment'),
      qualification_policy_digest: d('qualification-policy'),
      test_result_payload_digests: [testResult],
      agent_evaluation_evidence_payload_digests: [agentEvidence],
      qualification_statement_payload_digest: qualificationStatement,
      qualification_status: {
        authority_id: 'qualification-authority:primary',
        sequence: 7,
        head_payload_digest: qualificationStatus,
        observed_at: NOW,
        expires_at: INPUT_EXPIRES,
      },
      executor_adapter_digest: EXECUTOR_ADAPTER_DIGEST,
      idempotency_key: 'idempotency:payment-001',
      authorization_policy_digest: d('authorization-policy'),
      trust_epoch: 4,
      trust_configuration_digest: evaluated.record.evaluator.pinned_config_digest,
      configuration_epoch: 9,
      configuration_digest: d('configuration'),
      inputs: [
        evidenceInput('candidate_manifest', candidateManifest),
        evidenceInput('runtime_measurement', runtimeMeasurement),
        evidenceInput('test_result', testResult),
        evidenceInput('agent_evaluation_evidence', agentEvidence),
        evidenceInput('qualification_statement', qualificationStatement),
        evidenceInput('qualification_status', qualificationStatus),
        evidenceInput('aec', aecEvidence),
        evidenceInput('local_policy', localPolicyEvidence),
        evidenceInput('authorization', authorizationEvidence),
      ],
      expires_at: ADMISSION_EXPIRES,
    },
  };
  const statuses = authenticatedStatuses(evaluated.record, status);
  const controls: FidoAp2TrustedAdmissionControls = {
    now: () => NOW,
    pinned_config: pinnedConfig as any,
    resolve_current_statuses: () => structuredClone(statuses),
    tenant_id: TENANT_ID,
    relying_party_id: RELYING_PARTY_ID,
    audience: AUDIENCE,
    operation_id: OPERATION_ID,
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    provider: PROVIDER,
    gate_trust_configuration_digest:
      evaluated.record.evaluator.pinned_config_digest,
    executor_adapter_digest: EXECUTOR_ADAPTER_DIGEST,
    webauthn_counter_head: 41,
    ap2_source: {
      checkout_mandate_token: ap2.checkout_mandate_token,
      payment_mandate_token: ap2.payment_mandate_token,
      checkout_mandate_payload: ap2.checkout_mandate,
      payment_mandate_payload: ap2.payment_mandate,
    },
    effect_request_bytes: effectBytes,
    provider_request_verifier: exactProviderRequestVerifier(
      effectBytes,
      ap2.payment_mandate_token,
      ap2.source_binding.payment_mandate_token_digest,
    ),
  };
  return {
    ap2,
    action,
    raw,
    pinnedConfig,
    statuses,
    controls,
    effectBytes,
  };
}

describe('FIDO/AP2 expected action is derived, not echoed', () => {
  it('re-derives the economic fields from the mandates the Gate holds', () => {
    const { controls } = fixture();
    const derived = projectFidoAp2PaymentAction({
      checkout_mandate: controls.ap2_source.checkout_mandate_payload,
      payment_mandate: controls.ap2_source.payment_mandate_payload,
      source_binding: createFidoAp2NativeSourceBinding(controls.ap2_source),
    }) as Record<string, unknown>;

    // Every field a tampered normalized_action could have lied about comes back
    // from the mandate itself rather than from the artifact under check.
    const payment = controls.ap2_source.payment_mandate_payload as any;
    assert.equal(derived.amount_minor, payment.payment_amount.amount);
    assert.equal(derived.currency, payment.payment_amount.currency);
    assert.equal(derived.payee_id, payment.payee.id);
    assert.equal(derived.payment_instrument_id, payment.payment_instrument.id);
    assert.equal(derived.transaction_id, payment.transaction_id);
  });

  it('refuses admission when the attested action disagrees with the held mandates', () => {
    // The full attack, built consistently. Everything the artifact carries
    // agrees with itself: the disclosure the human saw, the signed context, the
    // CAID, and an attestation from the pinned native verifier all name an
    // action reading 9,999,999 minor units. Only the AP2 mandates the Gate is
    // holding say otherwise. While the Gate echoed the artifact's own action
    // back as its expectation, that comparison was a value against itself and
    // every chain closed. Deriving the expectation from the mandates is what
    // makes the disagreement visible.
    const honest = fixture();
    const attack = fixture({ actionOverrides: { amount_minor: 9_999_999 } });

    // The artifact is internally consistent: it is only the mandates that disagree.
    assert.equal(
      (attack.action as Record<string, unknown>).amount_minor,
      9_999_999,
    );
    assert.equal(
      (attack.controls.ap2_source.payment_mandate_payload as any).payment_amount.amount,
      (honest.action as Record<string, unknown>).amount_minor,
    );

    // Refused. Several layers object to an artifact whose action disagrees with
    // the mandates (evaluation re-derivation and the verdict check both fire
    // here), which is why the reported exploit needed inputs constructed past
    // the public entry point. The Gate deriving its own expectation removes the
    // last path where the disagreement would have gone unremarked.
    assert.throws(() => createFidoAp2AdmissionInput(attack.raw, attack.controls));
  });

  it('refuses a payload spliced onto a different authenticated token', () => {
    const { controls } = fixture();
    const binding = createFidoAp2NativeSourceBinding(controls.ap2_source);
    // Keep the authenticated token digests; change the amount underneath them.
    // This is the splice docs/protocol/fido-ap2-consequence-bridge-v1.md says
    // is refused, and the reason the Gate must run the projection itself.
    const tampered = structuredClone(controls.ap2_source.payment_mandate_payload) as any;
    tampered.payment_amount.amount = 9_999_999;

    assert.throws(
      () => projectFidoAp2PaymentAction({
        checkout_mandate: controls.ap2_source.checkout_mandate_payload,
        payment_mandate: tampered,
        source_binding: binding,
      }),
      /payload binding mismatch/,
    );
  });
});

const REQUIRED_QUALIFICATION_CHECKS = [
  'schemas',
  'payload_signatures',
  'trust_accepted',
  'campaign_lineage',
  'terminal_outcomes_complete',
  'hidden_challenge_commitments',
  'qualification_statement_binding',
  'status_chain',
  'status_current_as_observed',
  'runtime_candidate_exact_match',
  'assignment_in_scope',
  'protected_request_bound',
] as const;

function payloadFor(
  snapshot: Readonly<AdmissionSnapshot>,
  role: 'aeb' | 'aec' | 'local_policy',
): AdmissionDigest {
  const value = snapshot.body.inputs.find((entry) => entry.role === role)
    ?.payload_digest;
  assert.ok(value);
  return value;
}

function qualificationParts(admissionInput: AdmissionSnapshotInput) {
  const snapshot = createAdmissionSnapshot(admissionInput);
  return {
    snapshot,
    qualification: {
      decision: 'QUALIFIED',
      reason: 'qualified',
      verification: 'VERIFIED',
      acceptance: 'ACCEPTED',
      candidate_match: 'EXACT_MATCH',
      assignment_scope: 'IN_SCOPE',
      currentness: 'CURRENT_AS_OBSERVED',
      campaign_graph: 'COMPLETE',
      remeasure_at_begin_invocation: true,
      checks: Object.fromEntries(
        REQUIRED_QUALIFICATION_CHECKS.map((check) => [check, true]),
      ),
      payload_digests: {
        candidate_manifest: snapshot.body.candidate_manifest_digest,
        campaign_head: d('campaign-head'),
        qualification_graph: d('qualification-graph'),
        qualification_statement:
          snapshot.body.qualification_statement_payload_digest,
        qualification_status_head:
          snapshot.body.qualification_status.head_payload_digest,
        runtime_measurement: snapshot.body.runtime_measurement_digest,
        protected_request_digest: snapshot.body.effect_request_digest,
      },
    },
    aec: {
      decision: 'allow',
      requirementId: 'aec:execution-continuity-v1',
      evidenceDigest: payloadFor(snapshot, 'aec'),
      caid: snapshot.body.caid,
      actionDigest: snapshot.body.action_digest,
    },
    localPolicy: {
      decision: 'allow',
      policyId: 'policy:payments-production-v1',
      policyDigest: snapshot.body.authorization_policy_digest,
      evidenceDigest: payloadFor(snapshot, 'local_policy'),
      caid: snapshot.body.caid,
      actionDigest: snapshot.body.action_digest,
    },
  };
}

function matchingObservation(
  snapshot: Readonly<AdmissionSnapshot>,
): AdmissionCurrentnessObservation {
  return {
    '@version': ADMISSION_CURRENTNESS_VERSION,
    observed_at: NOW,
    qualification_status_authority_id:
      snapshot.body.qualification_status.authority_id,
    qualification_status_sequence: snapshot.body.qualification_status.sequence,
    qualification_status_head_digest:
      snapshot.body.qualification_status.head_payload_digest,
    qualification_status_expires_at:
      snapshot.body.qualification_status.expires_at,
    trust_epoch: snapshot.body.trust_epoch,
    trust_configuration_digest: snapshot.body.trust_configuration_digest,
    configuration_epoch: snapshot.body.configuration_epoch,
    configuration_digest: snapshot.body.configuration_digest,
    runtime_measurement_digest: snapshot.body.runtime_measurement_digest,
    candidate_match: 'EXACT_MATCH',
    external_leases: snapshot.body.resource_reservations
      .filter((resource) => resource.kind === 'external_lease')
      .map((resource) => ({
        resource_id: resource.resource_id,
        digest: resource.digest,
        expires_at: resource.expires_at,
      })),
  };
}

function enrolledCounterHeads(snapshot: Readonly<AdmissionSnapshot>) {
  return snapshot.body.resource_reservations
    .filter((resource) => resource.kind === 'monotonic_counter')
    .map((resource) => ({
      tenant_id: snapshot.body.tenant_id,
      resource_id: resource.resource_id,
      current_value: resource.expected_value!,
    }));
}

describe('FIDO/AP2 Gate bridge v1 over official AP2 v0.2', () => {
  it('builds the canonical admission from current mandates, exact source tokens, and trusted controls', () => {
    const f = fixture();
    const admission = createFidoAp2AdmissionInput(f.raw, f.controls);
    const snapshot = createAdmissionSnapshot(admission);

    assert.equal(FIDO_AP2_SOURCE_REVISION,
      'google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43');
    assert.deepEqual(Object.keys(f.ap2.checkout_mandate).sort(), [
      'checkout_hash', 'checkout_jwt', 'exp', 'iat', 'vct',
    ]);
    assert.deepEqual(Object.keys(f.ap2.payment_mandate).sort(), [
      'exp', 'iat', 'payee', 'payment_amount', 'payment_instrument',
      'transaction_id', 'vct',
    ]);
    assert.match(f.ap2.checkout_mandate_token,
      /^[^.]+\.[^.]+\.[A-Za-z0-9_-]+~$/);
    assert.match(f.ap2.payment_mandate_token,
      /^[^.]+\.[^.]+\.[A-Za-z0-9_-]+~$/);
    assert.deepEqual(f.action,
      projectFidoAp2PaymentAction(projectionInput(f.ap2)));
    assert.equal(f.raw.nativeAttestation.protocol_id, NATIVE_PROTOCOL);
    assert.equal(snapshot.body.admitted_at, NOW);
    assert.equal(snapshot.body.effect_request_digest,
      digestFidoAp2EffectRequest(f.effectBytes));
    assert.deepEqual(snapshot.body.provider, PROVIDER);

    const replay = snapshot.body.resource_reservations.filter(
      (resource) => resource.kind === 'replay',
    );
    assert.equal(replay.length, 3);
    assert.deepEqual(replay.map((resource) => resource.resource_id.split(':')[0]), [
      'ap2-checkout-mandate-token',
      'ap2-payment-mandate-token',
      'webauthn-assertion',
    ]);
    const providerOperations = snapshot.body.resource_reservations.filter(
      (resource) => resource.kind === 'provider_operation',
    );
    assert.equal(providerOperations.length, 1);
    assert.equal(providerOperations[0].resource_id, OPERATION_ID);

    const leases = snapshot.body.resource_reservations.filter(
      (resource) => resource.kind === 'external_lease',
    );
    assert.equal(leases.length, 2);
    const counters = snapshot.body.resource_reservations.filter(
      (resource) => resource.kind === 'monotonic_counter',
    );
    assert.equal(counters.length, 1);
    assert.equal(counters[0].expected_value, 41);
    assert.equal(counters[0].next_value, 42);
    assert.deepEqual(
      leases.map((lease) => lease.digest).sort(),
      f.statuses.map((status) => status.head_digest).sort(),
    );
  });

  it('keeps the payment replay identity stable when only the CheckoutMandate token is reissued', () => {
    const first = fixture();
    const reissuedCheckout = fixture({ checkoutTokenIssue: 'reissued-001' });

    assert.deepEqual(reissuedCheckout.ap2.checkout_mandate, first.ap2.checkout_mandate);
    assert.deepEqual(reissuedCheckout.ap2.payment_mandate, first.ap2.payment_mandate);
    assert.notEqual(
      reissuedCheckout.ap2.checkout_mandate_token,
      first.ap2.checkout_mandate_token,
    );
    assert.equal(
      reissuedCheckout.ap2.payment_mandate_token,
      first.ap2.payment_mandate_token,
    );

    const replayIds = (value: ReturnType<typeof fixture>) => new Map(
      createAdmissionSnapshot(createFidoAp2AdmissionInput(value.raw, value.controls))
        .body.resource_reservations
        .filter((resource) => resource.kind === 'replay')
        .map((resource) => [resource.resource_id.split(':')[0], resource.resource_id]),
    );
    const firstReplayIds = replayIds(first);
    const reissuedReplayIds = replayIds(reissuedCheckout);

    assert.notEqual(
      reissuedReplayIds.get('ap2-checkout-mandate-token'),
      firstReplayIds.get('ap2-checkout-mandate-token'),
    );
    assert.equal(
      reissuedReplayIds.get('ap2-payment-mandate-token'),
      firstReplayIds.get('ap2-payment-mandate-token'),
    );
  });

  it('retains the digest of the complete signed evaluation record and composes the derived AEB leg', () => {
    const f = fixture();
    const admission = createFidoAp2AdmissionInput(f.raw, f.controls);
    const parts = qualificationParts(admission);
    const fullRecordDigest = digestAeb(f.raw.evaluation);
    const aebInput = parts.snapshot.body.inputs.find(
      (entry) => entry.role === 'aeb',
    );
    assert.ok(aebInput);
    assert.equal(aebInput.payload_digest, fullRecordDigest);
    assert.notEqual(aebInput.payload_digest, f.raw.evaluation.evidence_digest);

    const bundle = createFidoAp2QualificationBundle({
      bridgeInput: f.raw,
      qualification: parts.qualification,
      aec: parts.aec,
      localPolicy: parts.localPolicy,
    }, f.controls) as GateQualificationBundleV2;
    assert.deepEqual(bundle.aeb, {
      decision: 'allow',
      requirementId: f.raw.evaluation.requirement_ref,
      caid: f.raw.evaluation.caid,
      actionDigest: digestAeb(f.action),
      evidenceDigest: fullRecordDigest,
    });
    const decision = composeQualificationDecisionV2({
      snapshot: parts.snapshot,
      qualification: bundle,
    });
    assert.equal(decision.allow, true);
    assert.deepEqual(decision.reasons, []);
  });

  it('refuses request-side clock, trust configuration, status, and verifier injection', () => {
    for (const [key, value] of [
      ['now', NOW],
      ['pinnedConfig', {}],
      ['currentStatuses', {}],
      ['resolve_current_statuses', 'presenter:resolver'],
      ['provider_request_verifier', { id: 'presenter:verifier' }],
    ] as const) {
      const f = fixture();
      (f.raw as Obj)[key] = value;
      assert.throws(
        () => createFidoAp2AdmissionInput(f.raw, f.controls),
        /is not allowed/,
      );
    }
  });

  it('refuses a forged signed evaluation and trusted actor mismatch', () => {
    const forged = fixture();
    const signature = Buffer.from(
      forged.raw.evaluation.signature.value,
      'base64url',
    );
    signature[signature.length - 1] ^= 0x01;
    forged.raw.evaluation.signature.value = signature.toString('base64url');
    assert.throws(
      () => createFidoAp2AdmissionInput(forged.raw, forged.controls),
      /signed AEB evaluation is not execution-authorizing/,
    );

    for (const actor of ['initiator_id', 'executor_id'] as const) {
      const f = fixture();
      const controls = {
        ...f.controls,
        [actor]: `${actor}:attacker`,
      };
      assert.throws(
        () => createFidoAp2AdmissionInput(f.raw, controls),
        new RegExp(`server-owned ${actor.replace('_id', '')} binding`),
      );
    }
  });

  it('binds exact effect bytes, payment token, provider identity, and provider adapter', () => {
    const f = fixture();
    let verified: Parameters<FidoAp2ProviderRequestVerifier['verify']>[0] | null = null;
    const controls = {
      ...f.controls,
      provider_request_verifier: exactProviderRequestVerifier(
        f.effectBytes,
        f.ap2.payment_mandate_token,
        f.ap2.source_binding.payment_mandate_token_digest,
        PROVIDER,
        (input) => { verified = input; },
      ),
    };
    createFidoAp2AdmissionInput(f.raw, controls);
    assert.ok(verified);
    assert.deepEqual(Buffer.from(verified.effect_request_bytes),
      Buffer.from(f.effectBytes));
    assert.equal(verified.payment_mandate_token,
      f.ap2.payment_mandate_token);
    assert.equal(verified.payment_mandate_token_digest,
      f.ap2.source_binding.payment_mandate_token_digest);
    assert.deepEqual(verified.provider, PROVIDER);

    const wrongBytes = fixture();
    const changedBytes = Buffer.from(wrongBytes.effectBytes);
    changedBytes[changedBytes.length - 1] ^= 0x01;
    assert.throws(() => createFidoAp2AdmissionInput(wrongBytes.raw, {
      ...wrongBytes.controls,
      effect_request_bytes: changedBytes,
      provider_request_verifier: exactProviderRequestVerifier(
        changedBytes,
        wrongBytes.ap2.payment_mandate_token,
        wrongBytes.ap2.source_binding.payment_mandate_token_digest,
      ),
    }), /server-owned provider-request digest binding/);

    const wrongToken = fixture();
    const alternate = rawAp2({ seed: 'alternate' });
    assert.throws(() => createFidoAp2AdmissionInput(wrongToken.raw, {
      ...wrongToken.controls,
      ap2_source: {
        checkout_mandate_token: wrongToken.ap2.checkout_mandate_token,
        payment_mandate_token: alternate.payment_mandate_token,
      },
      provider_request_verifier: {
        ...wrongToken.controls.provider_request_verifier,
        verify: () => true,
      },
    }), /trusted AP2 source tokens are invalid|nativeAttestation source commitment binding|trusted payment token binding/);

    const wrongAdapter = fixture();
    assert.throws(() => createFidoAp2AdmissionInput(wrongAdapter.raw, {
      ...wrongAdapter.controls,
      provider_request_verifier: {
        ...wrongAdapter.controls.provider_request_verifier,
        implementation_digest: d('provider-adapter:attacker'),
      },
    }), /provider-request verifier implementation binding/);

    const unboundToken = fixture();
    assert.throws(() => createFidoAp2AdmissionInput(unboundToken.raw, {
      ...unboundToken.controls,
      provider_request_verifier: {
        ...unboundToken.controls.provider_request_verifier,
        verify: () => false,
      },
    }), /exact AP2 payment token is not bound/);
  });

  it('refuses authenticated-status identity mismatch and expired source authority', () => {
    const wrongIdentity = fixture();
    const statuses = structuredClone(wrongIdentity.statuses);
    statuses[0].artifact_ref = 'artifact:attacker';
    assert.throws(() => createFidoAp2AdmissionInput(wrongIdentity.raw, {
      ...wrongIdentity.controls,
      resolve_current_statuses: () => statuses,
    }), /authenticated status identity mismatch/);

    const wrongEvidence = fixture();
    const evidenceStatuses = structuredClone(wrongEvidence.statuses);
    evidenceStatuses[1].evidence_digest = d('attacker-evidence');
    assert.throws(() => createFidoAp2AdmissionInput(wrongEvidence.raw, {
      ...wrongEvidence.controls,
      resolve_current_statuses: () => evidenceStatuses,
    }), /authenticated status evidence digest/);

    const expired = fixture();
    assert.throws(() => createFidoAp2AdmissionInput(expired.raw, {
      ...expired.controls,
      now: () => SOURCE_EXPIRES,
    }), /freshness|expired|expiration/);

    const outlivesSource = fixture();
    outlivesSource.raw.bindings.expires_at = '2026-07-31T18:04:00.001Z';
    assert.throws(
      () => createFidoAp2AdmissionInput(outlivesSource.raw, outlivesSource.controls),
      /closed source freshness does not cover admission/,
    );
  });

  it('requires the WebAuthn signature counter to advance from the server-owned head', () => {
    const stale = fixture();
    assert.throws(() => createFidoAp2AdmissionInput(stale.raw, {
      ...stale.controls,
      webauthn_counter_head: 42,
    }), /WebAuthn counter is not above the server-owned current head/);
  });

  it('atomically advances WebAuthn counters across distinct admissions', async () => {
    const f = fixture();
    const firstInput = createFidoAp2AdmissionInput(f.raw, f.controls);
    const first = createAdmissionSnapshot(firstInput);
    const observation = matchingObservation(first);
    const store = createMemoryAdmissionStore({
      now: NOW,
      initialMonotonicCounterHeads: enrolledCounterHeads(first),
      currentnessOracle: { read: async () => structuredClone(observation) },
    });
    const firstReservation = await store.reserve(first);
    assert.equal(firstReservation.ok, true);
    if (!firstReservation.ok) assert.fail(firstReservation.reason);

    const fork = (
      suffix: string,
      expectedValue: number,
      nextValue: number,
    ): AdmissionSnapshotInput => {
      const input = structuredClone(firstInput);
      input.admission_id = `admission:fido-ap2:${suffix}`;
      input.operation_id = `operation:fido-ap2:${suffix}`;
      input.idempotency_key = `idempotency:fido-ap2:${suffix}`;
      input.resource_reservations = input.resource_reservations.map((resource, index) => {
        if (resource.kind === 'monotonic_counter') {
          return {
            ...resource,
            expected_value: expectedValue,
            next_value: nextValue,
            reservation_id: `counter-reservation:${suffix}`,
            digest: d(`counter:${suffix}:${expectedValue}:${nextValue}`),
          };
        }
        return {
          ...resource,
          resource_id: resource.kind === 'provider_operation'
            ? input.operation_id
            : `${resource.kind}:${suffix}:${index}`,
          reservation_id: `reservation:${suffix}:${index}`,
          digest: d(`resource:${suffix}:${index}`),
        };
      });
      return input;
    };

    const clonedCount = await store.reserve(createAdmissionSnapshot(fork('clone', 41, 42)));
    assert.deepEqual(clonedCount, { ok: false, reason: 'resource_conflict' });

    const advanced = await store.reserve(createAdmissionSnapshot(fork('next', 42, 43)));
    assert.equal(advanced.ok, true);
    if (!advanced.ok) assert.fail(advanced.reason);

    const begun = await store.beginInvocation({
      tenant_id: TENANT_ID,
      admission_id: ADMISSION_ID,
      expected_revision: firstReservation.record.revision,
      owner_token: firstReservation.owner_token,
    });
    assert.equal(begun.ok, true);
  });

  it('reaches AdmissionStore reserve and beginInvocation with authenticated external leases', async () => {
    const f = fixture();
    const admission = createFidoAp2AdmissionInput(f.raw, f.controls);
    const snapshot = createAdmissionSnapshot(admission);
    const expectedObservation = matchingObservation(snapshot);
    assert.equal(expectedObservation.external_leases.length, 2);

    const store = createMemoryAdmissionStore({
      now: NOW,
      initialMonotonicCounterHeads: enrolledCounterHeads(snapshot),
      currentnessOracle: {
        read: async () => structuredClone(expectedObservation),
      },
    });
    const reserved = await store.reserve(snapshot);
    assert.equal(reserved.ok, true);
    if (!reserved.ok) assert.fail(reserved.reason);
    assert.equal(reserved.record.state, 'RESERVED');
    assert.equal(reserved.record.resources.filter(
      (resource) => resource.kind === 'external_lease',
    ).length, 2);

    const begun = await store.beginInvocation({
      tenant_id: TENANT_ID,
      admission_id: ADMISSION_ID,
      expected_revision: reserved.record.revision,
      owner_token: reserved.owner_token,
    });
    assert.equal(begun.ok, true);
    if (!begun.ok) assert.fail(begun.reason);
    assert.equal(begun.record.state, 'INVOKING');
    assert.equal(begun.record.execution_right, 'CONSUMED');
    assert.equal(begun.record.provider_attempt, 'INVOKING');
    assert.equal(begun.record.resources.every(
      (resource) => resource.state === 'CONSUMED',
    ), true);
  });

  it('refuses beginInvocation when an authenticated status head no longer matches', async () => {
    const f = fixture();
    const snapshot = createAdmissionSnapshot(
      createFidoAp2AdmissionInput(f.raw, f.controls),
    );
    const changedHead = matchingObservation(snapshot);
    changedHead.external_leases[0].digest = d('changed-authenticated-status-head');
    const store = createMemoryAdmissionStore({
      now: NOW,
      initialMonotonicCounterHeads: enrolledCounterHeads(snapshot),
      currentnessOracle: { read: async () => changedHead },
    });
    const reserved = await store.reserve(snapshot);
    assert.equal(reserved.ok, true);
    if (!reserved.ok) assert.fail(reserved.reason);
    const begun = await store.beginInvocation({
      tenant_id: TENANT_ID,
      admission_id: ADMISSION_ID,
      expected_revision: reserved.record.revision,
      owner_token: reserved.owner_token,
    });
    assert.deepEqual(begun, { ok: false, reason: 'currentness_refused' });
    const record = await store.read({
      tenant_id: TENANT_ID,
      admission_id: ADMISSION_ID,
    });
    assert.equal(record?.state, 'RELEASED');
    assert.equal(record?.provider_attempt, 'NOT_ENTERED');
  });

  it('remains synchronous, pure, and deterministic for identical trusted inputs', () => {
    const f = fixture();
    const before = structuredClone(f.raw);
    const first = createFidoAp2AdmissionInput(f.raw, f.controls);
    const second = createFidoAp2AdmissionInput(f.raw, f.controls);
    assert.deepEqual(f.raw, before);
    assert.deepEqual(first, second);
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(first.inputs), true);
    assert.equal(Object.isFrozen(first.inputs[0]), true);
    assert.throws(() => {
      (first.inputs[0] as Obj).subject = 'attacker:mutated';
    }, TypeError);
    assert.equal(first instanceof Promise, false);
    for (const forbidden of [
      'reserve', 'beginInvocation', 'invoke', 'reconcile',
      'recordProviderOutcome', 'recordEffectRelation',
    ]) assert.equal(forbidden in (first as Obj), false);
  });

  it('conformance corpus counts and executable test references cannot drift', () => {
    const corpus = JSON.parse(readFileSync(
      new URL('../../conformance/vectors/fido-ap2-bridge.v1.json', import.meta.url),
      'utf8',
    )) as Obj;
    assert.equal(corpus.determinism.vector_count, corpus.vectors.length);

    const vectorIds = corpus.vectors.map((vector: Obj) => vector.id);
    assert.equal(new Set(vectorIds).size, vectorIds.length);
    assert.deepEqual(
      vectorIds.map((id: string) => Number(id.slice(0, 2))),
      Array.from({ length: vectorIds.length }, (_, index) => index + 1),
    );

    const catalogIds = corpus.test_catalog.map((entry: Obj) => entry.id);
    assert.deepEqual(
      catalogIds,
      Array.from(
        { length: catalogIds.length },
        (_, index) => `T${String(index + 1).padStart(2, '0')}`,
      ),
    );
    const catalog = new Map(corpus.test_catalog.map(
      (entry: Obj) => [entry.id, entry] as const,
    ));
    for (const observation of corpus.coverage_observations as Obj[]) {
      for (const testId of observation.test_ids as string[]) {
        assert.equal(
          catalog.has(testId),
          true,
          `${observation.requirement}: unknown test_catalog ID ${testId}`,
        );
      }
    }
    for (const vector of corpus.vectors as Obj[]) {
      assert.equal(catalog.has(vector.coverage.test_id), true, vector.id);
      assert.deepEqual(
        vector.reason_codes,
        [...new Set(vector.reason_codes as string[])].sort(),
        vector.id,
      );
    }

    for (const entry of corpus.test_catalog as Obj[]) {
      const source = readFileSync(
        new URL(`../../${entry.file}`, import.meta.url),
        'utf8',
      );
      assert.equal(source.includes(`'${entry.title}'`), true, entry.id);
    }
  });
});
