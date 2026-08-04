// SPDX-License-Identifier: Apache-2.0
/**
 * Relying-party-pinned recovery classification at the admission boundary.
 *
 * The signed artifact binds one exact action/provider/adapter tuple. Mutable
 * status and reservation evidence never comes from that presenter: the
 * evaluator obtains it from relying-party-injected callbacks immediately
 * before admission and treats every unavailable or malformed answer as a
 * refusal.
 */
import {
  RISK_CAID,
  RISK_DIGEST,
  riskClone,
  riskDigest,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';
import type { AdmissionSnapshotBody } from './admission-store.js';

export const RECOVERY_CAPABILITY_VERSION = 'EP-RECOVERY-CAPABILITY-v1';
export const RECOVERY_CAPABILITY_STATUS_VERSION = 'EP-RECOVERY-CAPABILITY-STATUS-v1';
export const RECOVERY_RESERVATION_STATUS_VERSION = 'EP-RECOVERY-RESERVATION-STATUS-v1';
export const RECOVERY_ADMISSION_BINDINGS_VERSION = 'EP-RECOVERY-ADMISSION-BINDINGS-v1';
export const RECOVERY_CAPABILITY_CLAIM_BOUNDARY =
  'signed_policy_bound_recovery_classification_and_current_reserved_capacity_only_local_atomic_intra_transaction_only_compensation_requires_fresh_separate_admission_not_guaranteed_reversal_not_retry_authority_not_external_effect_truth_not_complete_mediation';

export type RecoveryMode = 'LOCAL_ATOMIC' | 'RESERVED_COMPENSATION' | 'IRREVERSIBLE';
export type RecoveryAdmissionRoute =
  | 'LOCAL_ATOMIC'
  | 'RESERVED_COMPENSATION'
  | 'AUTHORITY_REQUIRED'
  | 'REFUSED';

export interface LocalAtomicRecovery {
  scope: 'INTRA_TRANSACTION_ONLY';
  state_domain_digest: string;
  adapter_id: string;
  adapter_digest: string;
  max_transaction_ms: number;
}

export interface ReservedCompensationRecovery {
  scope: 'RESERVED_CAPACITY_ONLY';
  compensation_admission: 'FRESH_SEPARATE_ACTION_REQUIRED';
  remedy_caid: string;
  remedy_action_digest: string;
  destination_digest: string;
  authority_digest: string;
  reservation_digest: string;
  units: number;
  unit: string;
  available_until: string;
}

interface RecoveryCapabilityCommonInput {
  capability_id: string;
  admission_id: string;
  admission_snapshot_digest: string;
  tenant_id: string;
  audience: string;
  action_caid: string;
  action_digest: string;
  action_capability_expires_at: string;
  provider_id: string;
  account_digest: string;
  environment_digest: string;
  operation_id: string;
  issuer_digest: string;
  trust_epoch_digest: string;
  config_epoch_digest: string;
  adapter_id: string;
  adapter_digest: string;
  resource_set_digest: string;
  issued_at: string;
  valid_from: string;
  expires_at: string;
}

export type RecoveryCapabilityInput = RecoveryCapabilityCommonInput & (
  | { mode: 'LOCAL_ATOMIC'; recovery: LocalAtomicRecovery }
  | { mode: 'RESERVED_COMPENSATION'; recovery: ReservedCompensationRecovery }
  | { mode: 'IRREVERSIBLE'; recovery: null }
);

export type VerifiedRecoveryCapability = Readonly<RecoveryCapabilityInput & {
  '@version': typeof RECOVERY_CAPABILITY_VERSION;
  retry_permitted: false;
  claim_boundary: typeof RECOVERY_CAPABILITY_CLAIM_BOUNDARY;
}>;

interface RecoveryExpectedPolicyCommonSnapshot {
  capability_id: string;
  admission_id: string;
  admission_snapshot_digest: string;
  tenant_id: string;
  audience: string;
  action_caid: string;
  action_digest: string;
  action_capability_expires_at: string;
  provider_id: string;
  account_digest: string;
  environment_digest: string;
  operation_id: string;
  issuer_id: string;
  issuer_digest: string;
  trust_epoch_digest: string;
  config_epoch_digest: string;
  adapter_id: string;
  adapter_digest: string;
  resource_set_digest: string;
}

export type RecoveryExpectedPolicySnapshot = RecoveryExpectedPolicyCommonSnapshot & (
  | { mode: 'LOCAL_ATOMIC'; recovery: LocalAtomicRecovery }
  | { mode: 'RESERVED_COMPENSATION'; recovery: ReservedCompensationRecovery }
  | { mode: 'IRREVERSIBLE'; recovery: null }
);

export interface RecoveryCapabilityVerificationContext {
  trusted_keys: TrustedRiskKeys;
  expected_policy: RecoveryExpectedPolicySnapshot;
  now: string;
}

export interface RecoveryAdmissionSnapshotBindings {
  provider_id: string;
  account_digest: string;
  environment_digest: string;
  adapter_digest: string;
  trust_epoch_digest: string;
  config_epoch_digest: string;
  resource_set_digest: string;
}

export interface RecoveryCapabilityVerification {
  accepted: boolean;
  verified: boolean;
  reason: string | null;
  capability_digest: string | null;
  capability: VerifiedRecoveryCapability | null;
  issuer_id: string | null;
  claim_boundary: typeof RECOVERY_CAPABILITY_CLAIM_BOUNDARY;
}

export interface RecoveryStatusResolverInput {
  capability: VerifiedRecoveryCapability;
  capability_digest: string;
  issuer_id: string;
  admission_at: string;
  action_capability_expires_at: string;
}

export type RecoveryCurrentStatusResolver = (
  input: Readonly<RecoveryStatusResolverInput>,
) => unknown | Promise<unknown>;

export type RecoveryReservationVerifier = (
  input: Readonly<RecoveryStatusResolverInput>,
) => unknown | Promise<unknown>;

export interface RecoveryAdmissionDependencies {
  current_status_resolver: RecoveryCurrentStatusResolver;
  reservation_verifier?: RecoveryReservationVerifier;
}

export interface RecoveryAdmissionDecision {
  recovery_route_accepted: boolean;
  route: RecoveryAdmissionRoute;
  reason: string | null;
  scope: 'INTRA_TRANSACTION_ONLY' | 'RESERVED_CAPACITY_ONLY'
    | 'FRESH_AUTHORITY_REQUIRED' | 'NONE';
  retry_permitted: false;
  fresh_action_admission_required: boolean;
  capability_digest: string | null;
  capability: VerifiedRecoveryCapability | null;
  status: Readonly<RiskRecord> | null;
  reservation: Readonly<RiskRecord> | null;
  claim_boundary: typeof RECOVERY_CAPABILITY_CLAIM_BOUNDARY;
}

const INPUT_KEYS = [
  'capability_id', 'admission_id', 'admission_snapshot_digest', 'tenant_id',
  'audience', 'action_caid', 'action_digest', 'action_capability_expires_at',
  'provider_id', 'account_digest', 'environment_digest', 'operation_id',
  'issuer_digest', 'trust_epoch_digest', 'config_epoch_digest', 'adapter_id',
  'adapter_digest', 'resource_set_digest', 'issued_at', 'valid_from',
  'expires_at', 'mode', 'recovery',
] as const;
const BODY_KEYS = [
  '@version', ...INPUT_KEYS, 'retry_permitted', 'claim_boundary', 'issuer',
] as const;
const ISSUER_KEYS = ['id', 'key_id'] as const;
const SIGNER_KEYS = ['issuer_id', 'key_id', 'private_key'] as const;
const LOCAL_RECOVERY_KEYS = [
  'scope', 'state_domain_digest', 'adapter_id', 'adapter_digest', 'max_transaction_ms',
] as const;
const RESERVED_RECOVERY_KEYS = [
  'scope', 'compensation_admission', 'remedy_caid', 'remedy_action_digest',
  'destination_digest', 'authority_digest', 'reservation_digest', 'units',
  'unit', 'available_until',
] as const;
const CONTEXT_KEYS = ['trusted_keys', 'expected_policy', 'now'] as const;
const EXPECTED_POLICY_KEYS = [
  'capability_id', 'admission_id', 'admission_snapshot_digest', 'mode',
  'recovery', 'tenant_id', 'audience', 'action_caid', 'action_digest',
  'action_capability_expires_at', 'provider_id', 'account_digest',
  'environment_digest', 'operation_id', 'issuer_id', 'issuer_digest',
  'trust_epoch_digest', 'config_epoch_digest', 'adapter_id', 'adapter_digest',
  'resource_set_digest',
] as const;
const TRUSTED_KEY_KEYS = ['issuer_id', 'public_key'] as const;
const CURRENT_STATUS_KEYS = [
  '@version', 'capability_id', 'capability_digest', 'tenant_id', 'audience',
  'action_caid', 'action_digest', 'provider_id', 'adapter_id', 'issuer_id',
  'status', 'observed_at', 'valid_from', 'valid_until',
] as const;
const RESERVATION_STATUS_KEYS = [
  '@version', 'capability_id', 'capability_digest', 'tenant_id', 'audience',
  'action_caid', 'action_digest', 'provider_id', 'adapter_id',
  'reservation_digest', 'remedy_caid', 'remedy_action_digest',
  'destination_digest', 'authority_digest', 'units', 'unit', 'status',
  'observed_at', 'valid_from', 'available_until',
] as const;

export class RecoveryCapabilityValidationError extends TypeError {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'RecoveryCapabilityValidationError';
    this.code = code;
  }
}

function invalid(code: string, message: string): never {
  throw new RecoveryCapabilityValidationError(code, message);
}

function strictSnapshot(value: unknown, label: string): any {
  try {
    return riskClone(value);
  } catch {
    invalid('non_json_value', `${label} is outside strict JSON data model`);
  }
}

function identifier(value: unknown, label: string): string {
  if (!riskIdentifier(value)) invalid('identifier_invalid', `${label} is invalid`);
  return value;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !RISK_DIGEST.test(value)) {
    invalid('digest_invalid', `${label} is invalid`);
  }
  return value;
}

function caid(value: unknown, label: string): string {
  if (typeof value !== 'string' || !RISK_CAID.test(value)) {
    invalid('caid_invalid', `${label} is invalid`);
  }
  return value;
}

function canonicalInstant(value: unknown, label: string): string {
  if (typeof value !== 'string') invalid('instant_invalid', `${label} is invalid`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid('instant_invalid', `${label} must be a canonical RFC 3339 instant`);
  }
  return value;
}

function positiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

/**
 * Derive the privacy-preserving execution-context bindings carried by a
 * recovery capability from the exact ordinary admission snapshot. Issuers and
 * executors use this same derivation so a valid recovery signature cannot be
 * replayed onto a different provider account, environment, trust/configuration
 * epoch, adapter, or reserved resource set.
 */
export function deriveRecoveryAdmissionSnapshotBindings(
  snapshot: Readonly<AdmissionSnapshotBody>,
): Readonly<RecoveryAdmissionSnapshotBindings> {
  const value = strictSnapshot(snapshot, 'admission snapshot body');
  if (!riskRecord(value)
      || !riskRecord(value.provider)
      || !riskIdentifier(value.provider.provider_id)
      || !riskIdentifier(value.provider.account_id)
      || !riskIdentifier(value.provider.environment)
      || typeof value.executor_adapter_digest !== 'string'
      || !RISK_DIGEST.test(value.executor_adapter_digest)
      || !Number.isSafeInteger(value.trust_epoch) || value.trust_epoch < 1
      || typeof value.trust_configuration_digest !== 'string'
      || !RISK_DIGEST.test(value.trust_configuration_digest)
      || !Number.isSafeInteger(value.configuration_epoch) || value.configuration_epoch < 1
      || typeof value.configuration_digest !== 'string'
      || !RISK_DIGEST.test(value.configuration_digest)
      || !Array.isArray(value.resource_reservations)) {
    invalid('admission_snapshot_binding_invalid', 'admission snapshot bindings are invalid');
  }
  const domain = RECOVERY_ADMISSION_BINDINGS_VERSION;
  return riskFreeze({
    provider_id: value.provider.provider_id,
    account_digest: riskDigest({
      '@version': domain,
      field: 'provider_account',
      provider_id: value.provider.provider_id,
      account_id: value.provider.account_id,
    }),
    environment_digest: riskDigest({
      '@version': domain,
      field: 'provider_environment',
      provider_id: value.provider.provider_id,
      environment: value.provider.environment,
    }),
    adapter_digest: value.executor_adapter_digest,
    trust_epoch_digest: riskDigest({
      '@version': domain,
      field: 'trust_epoch',
      trust_epoch: value.trust_epoch,
      trust_configuration_digest: value.trust_configuration_digest,
    }),
    config_epoch_digest: riskDigest({
      '@version': domain,
      field: 'configuration_epoch',
      configuration_epoch: value.configuration_epoch,
      configuration_digest: value.configuration_digest,
    }),
    resource_set_digest: riskDigest({
      '@version': domain,
      field: 'resource_reservations',
      resource_reservations: value.resource_reservations,
    }),
  });
}

function normalizeLocalRecovery(
  value: unknown,
  adapterId: string,
  adapterDigest: string,
): LocalAtomicRecovery {
  if (!riskExact(value, LOCAL_RECOVERY_KEYS)) {
    invalid('local_recovery_invalid', 'local recovery shape is invalid');
  }
  const recovery = {
    scope: value.scope,
    state_domain_digest: digest(value.state_domain_digest, 'state_domain_digest'),
    adapter_id: identifier(value.adapter_id, 'recovery.adapter_id'),
    adapter_digest: digest(value.adapter_digest, 'adapter_digest'),
    max_transaction_ms: value.max_transaction_ms,
  };
  if (recovery.scope !== 'INTRA_TRANSACTION_ONLY') {
    invalid('local_recovery_invalid', 'local recovery must be intra-transaction only');
  }
  if (!positiveSafeInteger(recovery.max_transaction_ms)) {
    invalid('local_recovery_invalid', 'local recovery max transaction is invalid');
  }
  if (recovery.adapter_id !== adapterId || recovery.adapter_digest !== adapterDigest) {
    invalid(
      'local_recovery_adapter_mismatch',
      'local recovery adapter must match the provider adapter binding',
    );
  }
  return recovery;
}

function normalizeReservedRecovery(
  value: unknown,
  actionCapabilityExpiresAt: string,
): ReservedCompensationRecovery {
  if (!riskExact(value, RESERVED_RECOVERY_KEYS)) {
    invalid('reserved_recovery_invalid', 'reserved recovery shape is invalid');
  }
  const recovery = {
    scope: value.scope,
    compensation_admission: value.compensation_admission,
    remedy_caid: caid(value.remedy_caid, 'remedy_caid'),
    remedy_action_digest: digest(value.remedy_action_digest, 'remedy_action_digest'),
    destination_digest: digest(value.destination_digest, 'destination_digest'),
    authority_digest: digest(value.authority_digest, 'authority_digest'),
    reservation_digest: digest(value.reservation_digest, 'reservation_digest'),
    units: value.units,
    unit: identifier(value.unit, 'reservation.unit'),
    available_until: canonicalInstant(value.available_until, 'available_until'),
  };
  if (recovery.scope !== 'RESERVED_CAPACITY_ONLY'
      || recovery.compensation_admission !== 'FRESH_SEPARATE_ACTION_REQUIRED') {
    invalid(
      'reserved_recovery_invalid',
      'reserved compensation is capacity only and requires fresh separate action admission',
    );
  }
  if (!positiveSafeInteger(recovery.units)) {
    invalid('reserved_recovery_invalid', 'reservation units are invalid');
  }
  if (Date.parse(recovery.available_until) < Date.parse(actionCapabilityExpiresAt)) {
    invalid(
      'reserved_recovery_coverage_invalid',
      'reservation must cover the action capability expiry',
    );
  }
  return recovery;
}

function normalizeInput(rawInput: unknown): RecoveryCapabilityInput {
  const input = strictSnapshot(rawInput, 'capability input');
  if (!riskExact(input, INPUT_KEYS)) {
    invalid('capability_input_invalid', 'capability input must be a closed JSON object');
  }
  if (!['LOCAL_ATOMIC', 'RESERVED_COMPENSATION', 'IRREVERSIBLE'].includes(input.mode)) {
    invalid('recovery_mode_invalid', 'recovery mode is invalid');
  }
  const capabilityId = identifier(input.capability_id, 'capability_id');
  const admissionId = identifier(input.admission_id, 'admission_id');
  const admissionSnapshotDigest = digest(
    input.admission_snapshot_digest,
    'admission_snapshot_digest',
  );
  const tenantId = identifier(input.tenant_id, 'tenant_id');
  const audience = identifier(input.audience, 'audience');
  const actionCaid = caid(input.action_caid, 'action_caid');
  const actionDigest = digest(input.action_digest, 'action_digest');
  const actionCapabilityExpiresAt = canonicalInstant(
    input.action_capability_expires_at,
    'action_capability_expires_at',
  );
  const providerId = identifier(input.provider_id, 'provider_id');
  const accountDigest = digest(input.account_digest, 'account_digest');
  const environmentDigest = digest(input.environment_digest, 'environment_digest');
  const operationId = identifier(input.operation_id, 'operation_id');
  const issuerDigest = digest(input.issuer_digest, 'issuer_digest');
  const trustEpochDigest = digest(input.trust_epoch_digest, 'trust_epoch_digest');
  const configEpochDigest = digest(input.config_epoch_digest, 'config_epoch_digest');
  const adapterId = identifier(input.adapter_id, 'adapter_id');
  const adapterDigest = digest(input.adapter_digest, 'adapter_digest');
  const resourceSetDigest = digest(input.resource_set_digest, 'resource_set_digest');
  const issuedAt = canonicalInstant(input.issued_at, 'issued_at');
  const validFrom = canonicalInstant(input.valid_from, 'valid_from');
  const expiresAt = canonicalInstant(input.expires_at, 'expires_at');
  if (Date.parse(issuedAt) > Date.parse(validFrom)
      || Date.parse(validFrom) >= Date.parse(actionCapabilityExpiresAt)
      || Date.parse(actionCapabilityExpiresAt) > Date.parse(expiresAt)) {
    invalid('capability_time_invalid', 'capability validity interval is invalid');
  }

  const common = {
    capability_id: capabilityId,
    admission_id: admissionId,
    admission_snapshot_digest: admissionSnapshotDigest,
    tenant_id: tenantId,
    audience,
    action_caid: actionCaid,
    action_digest: actionDigest,
    action_capability_expires_at: actionCapabilityExpiresAt,
    provider_id: providerId,
    account_digest: accountDigest,
    environment_digest: environmentDigest,
    operation_id: operationId,
    issuer_digest: issuerDigest,
    trust_epoch_digest: trustEpochDigest,
    config_epoch_digest: configEpochDigest,
    adapter_id: adapterId,
    adapter_digest: adapterDigest,
    resource_set_digest: resourceSetDigest,
    issued_at: issuedAt,
    valid_from: validFrom,
    expires_at: expiresAt,
  };
  if (input.mode === 'LOCAL_ATOMIC') {
    return {
      ...common,
      mode: 'LOCAL_ATOMIC',
      recovery: normalizeLocalRecovery(input.recovery, adapterId, adapterDigest),
    };
  }
  if (input.mode === 'RESERVED_COMPENSATION') {
    return {
      ...common,
      mode: 'RESERVED_COMPENSATION',
      recovery: normalizeReservedRecovery(input.recovery, actionCapabilityExpiresAt),
    };
  }
  if (input.recovery !== null) {
    invalid('irreversible_recovery_invalid', 'irreversible recovery must be null');
  }
  return { ...common, mode: 'IRREVERSIBLE', recovery: null };
}

function validateBody(value: unknown): {
  capability: VerifiedRecoveryCapability;
  issuer: Readonly<{ id: string; key_id: string }>;
} {
  if (!riskExact(value, BODY_KEYS)
      || value['@version'] !== RECOVERY_CAPABILITY_VERSION
      || value.retry_permitted !== false
      || value.claim_boundary !== RECOVERY_CAPABILITY_CLAIM_BOUNDARY
      || !riskExact(value.issuer, ISSUER_KEYS)) {
    invalid('capability_schema_invalid', 'capability body is invalid');
  }
  const issuer = {
    id: identifier(value.issuer.id, 'issuer.id'),
    key_id: identifier(value.issuer.key_id, 'issuer.key_id'),
  };
  const input = normalizeInput(Object.fromEntries(
    INPUT_KEYS.map((key) => [key, value[key]]),
  ));
  const expected = {
    '@version': RECOVERY_CAPABILITY_VERSION,
    ...input,
    retry_permitted: false,
    claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
    issuer,
  };
  if (riskDigest(expected) !== riskDigest(value)) {
    invalid('capability_schema_invalid', 'capability body is invalid');
  }
  const capability = riskFreeze(riskClone({
    '@version': RECOVERY_CAPABILITY_VERSION,
    ...input,
    retry_permitted: false,
    claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
  })) as VerifiedRecoveryCapability;
  return { capability, issuer: riskFreeze(issuer) };
}

function normalizeExpectedPolicy(value: unknown): Readonly<RecoveryExpectedPolicySnapshot> | null {
  if (!riskExact(value, EXPECTED_POLICY_KEYS)
      || !riskIdentifier(value.capability_id)
      || !riskIdentifier(value.admission_id)
      || typeof value.admission_snapshot_digest !== 'string'
      || !RISK_DIGEST.test(value.admission_snapshot_digest)
      || !['LOCAL_ATOMIC', 'RESERVED_COMPENSATION', 'IRREVERSIBLE'].includes(value.mode)
      || !riskIdentifier(value.tenant_id)
      || !riskIdentifier(value.audience)
      || typeof value.action_caid !== 'string' || !RISK_CAID.test(value.action_caid)
      || typeof value.action_digest !== 'string' || !RISK_DIGEST.test(value.action_digest)
      || !riskIdentifier(value.provider_id)
      || typeof value.account_digest !== 'string' || !RISK_DIGEST.test(value.account_digest)
      || typeof value.environment_digest !== 'string' || !RISK_DIGEST.test(value.environment_digest)
      || !riskIdentifier(value.operation_id)
      || !riskIdentifier(value.issuer_id)
      || typeof value.issuer_digest !== 'string' || !RISK_DIGEST.test(value.issuer_digest)
      || typeof value.trust_epoch_digest !== 'string' || !RISK_DIGEST.test(value.trust_epoch_digest)
      || typeof value.config_epoch_digest !== 'string' || !RISK_DIGEST.test(value.config_epoch_digest)
      || !riskIdentifier(value.adapter_id)
      || typeof value.adapter_digest !== 'string' || !RISK_DIGEST.test(value.adapter_digest)
      || typeof value.resource_set_digest !== 'string'
      || !RISK_DIGEST.test(value.resource_set_digest)) return null;
  try {
    const actionCapabilityExpiresAt = canonicalInstant(
      value.action_capability_expires_at,
      'expected action capability expiry',
    );
    if (value.mode === 'LOCAL_ATOMIC') {
      return riskFreeze({
        ...value,
        mode: 'LOCAL_ATOMIC',
        recovery: normalizeLocalRecovery(
          value.recovery,
          value.adapter_id,
          value.adapter_digest,
        ),
      } as RecoveryExpectedPolicySnapshot);
    }
    if (value.mode === 'RESERVED_COMPENSATION') {
      return riskFreeze({
        ...value,
        mode: 'RESERVED_COMPENSATION',
        recovery: normalizeReservedRecovery(value.recovery, actionCapabilityExpiresAt),
      } as RecoveryExpectedPolicySnapshot);
    }
    if (value.recovery !== null) return null;
    return riskFreeze({
      ...value,
      mode: 'IRREVERSIBLE',
      recovery: null,
    } as RecoveryExpectedPolicySnapshot);
  } catch {
    return null;
  }
}

function normalizeContext(
  rawContext: unknown,
): Readonly<RecoveryCapabilityVerificationContext> | null {
  let context: unknown;
  try {
    context = riskClone(rawContext);
  } catch {
    return null;
  }
  if (!riskExact(context, CONTEXT_KEYS)
      || !riskRecord(context.trusted_keys)
      || Object.keys(context.trusted_keys).length < 1
      || !Object.entries(context.trusted_keys).every(([keyId, pin]) => (
        riskIdentifier(keyId)
        && riskExact(pin, TRUSTED_KEY_KEYS)
        && riskIdentifier(pin.issuer_id)
        && typeof pin.public_key === 'string'
        && /^[A-Za-z0-9_-]+$/.test(pin.public_key)
      ))) return null;
  const expectedPolicy = normalizeExpectedPolicy(context.expected_policy);
  if (!expectedPolicy) return null;
  try {
    canonicalInstant(context.now, 'verification now');
  } catch {
    return null;
  }
  return riskFreeze({
    trusted_keys: context.trusted_keys,
    expected_policy: expectedPolicy,
    now: context.now,
  } as RecoveryCapabilityVerificationContext);
}

function verificationRefusal(
  reason: string,
  verified = false,
  capabilityDigest: string | null = null,
): RecoveryCapabilityVerification {
  return riskFreeze({
    accepted: false,
    verified,
    reason,
    capability_digest: capabilityDigest,
    capability: null,
    issuer_id: null,
    claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
  });
}

/** Sign the closed v1 body with Ed25519 over reliance-risk-crypto JCS bytes. */
export function signRecoveryCapability(
  rawInput: RecoveryCapabilityInput | RiskRecord,
  rawSigner: { issuer_id: string; key_id: string; private_key: any },
): RiskRecord {
  if (!riskExact(rawSigner, SIGNER_KEYS)
      || !riskIdentifier(rawSigner.issuer_id)
      || !riskIdentifier(rawSigner.key_id)) {
    invalid('signer_invalid', 'recovery capability signer is invalid');
  }
  const input = normalizeInput(rawInput);
  const body = {
    '@version': RECOVERY_CAPABILITY_VERSION,
    ...input,
    retry_permitted: false,
    claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
  };
  validateBody({
    ...body,
    issuer: { id: rawSigner.issuer_id, key_id: rawSigner.key_id },
  });
  try {
    return signRiskBody(RECOVERY_CAPABILITY_VERSION, body, rawSigner);
  } catch {
    invalid('signer_invalid', 'recovery capability signing key must be Ed25519');
  }
}

/** Digest of the complete signed artifact, including its Ed25519 proof. */
export function recoveryCapabilityDigest(artifact: unknown): string {
  const snapshot = strictSnapshot(artifact, 'recovery capability artifact');
  if (!riskRecord(snapshot) || !riskRecord(snapshot.proof)) {
    invalid('capability_artifact_invalid', 'capability artifact is invalid');
  }
  return riskDigest(snapshot);
}

/** Verify signature, closed schema, complete expected tuple, and active time. */
export function verifyRecoveryCapability(
  artifact: unknown,
  rawContext?: RecoveryCapabilityVerificationContext,
): RecoveryCapabilityVerification {
  const context = normalizeContext(rawContext);
  if (!context) return verificationRefusal('verification_context_required');

  let snapshot: unknown;
  try {
    snapshot = riskClone(artifact);
  } catch {
    return verificationRefusal('artifact_invalid');
  }
  const signed = verifyRiskBody(
    snapshot,
    RECOVERY_CAPABILITY_VERSION,
    context.trusted_keys,
  );
  if (!signed.valid || !signed.body || !signed.artifact_digest) {
    return verificationRefusal(
      signed.reason === 'issuer_untrusted' ? 'issuer_untrusted' : 'signature_invalid',
    );
  }

  let body: ReturnType<typeof validateBody>;
  try {
    body = validateBody(signed.body);
  } catch {
    return verificationRefusal('capability_schema_invalid', true, signed.artifact_digest);
  }
  const capability = body.capability;
  const policy = context.expected_policy;
  const checks: Array<[boolean, string]> = [
    [capability.capability_id !== policy.capability_id, 'capability_id_mismatch'],
    [capability.admission_id !== policy.admission_id, 'admission_id_mismatch'],
    [capability.admission_snapshot_digest !== policy.admission_snapshot_digest,
      'admission_snapshot_digest_mismatch'],
    [capability.mode !== policy.mode, 'mode_mismatch'],
    [capability.tenant_id !== policy.tenant_id, 'tenant_mismatch'],
    [capability.audience !== policy.audience, 'audience_mismatch'],
    [capability.action_caid !== policy.action_caid, 'action_caid_mismatch'],
    [capability.action_digest !== policy.action_digest, 'action_digest_mismatch'],
    [capability.action_capability_expires_at !== policy.action_capability_expires_at,
      'action_capability_expiry_mismatch'],
    [capability.provider_id !== policy.provider_id, 'provider_mismatch'],
    [capability.account_digest !== policy.account_digest, 'account_mismatch'],
    [capability.environment_digest !== policy.environment_digest, 'environment_mismatch'],
    [capability.operation_id !== policy.operation_id, 'operation_mismatch'],
    [body.issuer.id !== policy.issuer_id, 'issuer_mismatch'],
    [capability.issuer_digest !== policy.issuer_digest, 'issuer_digest_mismatch'],
    [capability.trust_epoch_digest !== policy.trust_epoch_digest, 'trust_epoch_mismatch'],
    [capability.config_epoch_digest !== policy.config_epoch_digest, 'config_epoch_mismatch'],
    [capability.adapter_id !== policy.adapter_id, 'adapter_mismatch'],
    [capability.adapter_digest !== policy.adapter_digest, 'adapter_digest_mismatch'],
    [capability.resource_set_digest !== policy.resource_set_digest, 'resource_set_mismatch'],
    [riskDigest(capability.recovery) !== riskDigest(policy.recovery), 'recovery_mismatch'],
  ];
  for (const [mismatched, reason] of checks) {
    if (mismatched) return verificationRefusal(reason, true, signed.artifact_digest);
  }
  const now = Date.parse(context.now);
  if (now < Date.parse(capability.valid_from)) {
    return verificationRefusal('capability_not_yet_valid', true, signed.artifact_digest);
  }
  if (now >= Date.parse(capability.expires_at)) {
    return verificationRefusal('capability_expired', true, signed.artifact_digest);
  }
  if (now >= Date.parse(capability.action_capability_expires_at)) {
    return verificationRefusal('action_capability_expired', true, signed.artifact_digest);
  }
  return riskFreeze({
    accepted: true,
    verified: true,
    reason: null,
    capability_digest: signed.artifact_digest,
    capability,
    issuer_id: body.issuer.id,
    claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
  });
}

function normalizeCurrentStatus(value: unknown): RiskRecord | null {
  let status: unknown;
  try {
    status = riskClone(value);
  } catch {
    return null;
  }
  if (!riskExact(status, CURRENT_STATUS_KEYS)
      || status['@version'] !== RECOVERY_CAPABILITY_STATUS_VERSION
      || !riskIdentifier(status.capability_id)
      || typeof status.capability_digest !== 'string' || !RISK_DIGEST.test(status.capability_digest)
      || !riskIdentifier(status.tenant_id)
      || !riskIdentifier(status.audience)
      || typeof status.action_caid !== 'string' || !RISK_CAID.test(status.action_caid)
      || typeof status.action_digest !== 'string' || !RISK_DIGEST.test(status.action_digest)
      || !riskIdentifier(status.provider_id)
      || !riskIdentifier(status.adapter_id)
      || !riskIdentifier(status.issuer_id)
      || !['CURRENT', 'REVOKED'].includes(status.status)) return null;
  try {
    canonicalInstant(status.observed_at, 'status.observed_at');
    canonicalInstant(status.valid_from, 'status.valid_from');
    canonicalInstant(status.valid_until, 'status.valid_until');
  } catch {
    return null;
  }
  return riskFreeze(status);
}

function normalizeReservationStatus(value: unknown): RiskRecord | null {
  let reservation: unknown;
  try {
    reservation = riskClone(value);
  } catch {
    return null;
  }
  if (!riskExact(reservation, RESERVATION_STATUS_KEYS)
      || reservation['@version'] !== RECOVERY_RESERVATION_STATUS_VERSION
      || !riskIdentifier(reservation.capability_id)
      || typeof reservation.capability_digest !== 'string'
      || !RISK_DIGEST.test(reservation.capability_digest)
      || !riskIdentifier(reservation.tenant_id)
      || !riskIdentifier(reservation.audience)
      || typeof reservation.action_caid !== 'string'
      || !RISK_CAID.test(reservation.action_caid)
      || typeof reservation.action_digest !== 'string'
      || !RISK_DIGEST.test(reservation.action_digest)
      || !riskIdentifier(reservation.provider_id)
      || !riskIdentifier(reservation.adapter_id)
      || typeof reservation.reservation_digest !== 'string'
      || !RISK_DIGEST.test(reservation.reservation_digest)
      || typeof reservation.remedy_caid !== 'string'
      || !RISK_CAID.test(reservation.remedy_caid)
      || typeof reservation.remedy_action_digest !== 'string'
      || !RISK_DIGEST.test(reservation.remedy_action_digest)
      || typeof reservation.destination_digest !== 'string'
      || !RISK_DIGEST.test(reservation.destination_digest)
      || typeof reservation.authority_digest !== 'string'
      || !RISK_DIGEST.test(reservation.authority_digest)
      || !positiveSafeInteger(reservation.units)
      || !riskIdentifier(reservation.unit)
      || !['RESERVED', 'RELEASED', 'REVOKED', 'CONSUMED'].includes(reservation.status)) return null;
  try {
    canonicalInstant(reservation.observed_at, 'reservation.observed_at');
    canonicalInstant(reservation.valid_from, 'reservation.valid_from');
    canonicalInstant(reservation.available_until, 'reservation.available_until');
  } catch {
    return null;
  }
  return riskFreeze(reservation);
}

function decision(
  route: RecoveryAdmissionRoute,
  reason: string | null,
  verification: RecoveryCapabilityVerification,
  status: Readonly<RiskRecord> | null = null,
  reservation: Readonly<RiskRecord> | null = null,
): RecoveryAdmissionDecision {
  const scope = route === 'LOCAL_ATOMIC' ? 'INTRA_TRANSACTION_ONLY'
    : route === 'RESERVED_COMPENSATION' ? 'RESERVED_CAPACITY_ONLY'
      : route === 'AUTHORITY_REQUIRED' ? 'FRESH_AUTHORITY_REQUIRED' : 'NONE';
  return riskFreeze({
    recovery_route_accepted: route === 'LOCAL_ATOMIC' || route === 'RESERVED_COMPENSATION',
    route,
    reason,
    scope,
    retry_permitted: false,
    fresh_action_admission_required:
      route === 'RESERVED_COMPENSATION' || route === 'AUTHORITY_REQUIRED',
    capability_digest: verification.capability_digest,
    capability: verification.capability,
    status,
    reservation,
    claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
  });
}

function currentStatusReason(
  status: RiskRecord,
  input: RecoveryStatusResolverInput,
): string | null {
  const capability = input.capability;
  if (status.capability_id !== capability.capability_id
      || status.capability_digest !== input.capability_digest
      || status.tenant_id !== capability.tenant_id
      || status.audience !== capability.audience
      || status.action_caid !== capability.action_caid
      || status.action_digest !== capability.action_digest
      || status.provider_id !== capability.provider_id
      || status.adapter_id !== capability.adapter_id
      || status.issuer_id !== input.issuer_id) return 'current_status_binding_mismatch';
  if (status.status === 'REVOKED') return 'current_status_revoked';
  const admission = Date.parse(input.admission_at);
  const observed = Date.parse(status.observed_at);
  const validFrom = Date.parse(status.valid_from);
  const validUntil = Date.parse(status.valid_until);
  const actionExpiry = Date.parse(input.action_capability_expires_at);
  if (validFrom > admission) return 'current_status_not_yet_valid';
  if (observed > admission || observed < validFrom) return 'current_status_invalid';
  if (validUntil <= admission || observed >= validUntil) return 'current_status_stale';
  if (validUntil < actionExpiry) return 'current_status_insufficient_coverage';
  return null;
}

function reservationReason(
  reservation: RiskRecord,
  input: RecoveryStatusResolverInput,
): string | null {
  const capability = input.capability;
  if (capability.mode !== 'RESERVED_COMPENSATION') return 'reservation_invalid';
  const recovery = capability.recovery;
  if (reservation.capability_id !== capability.capability_id
      || reservation.capability_digest !== input.capability_digest
      || reservation.tenant_id !== capability.tenant_id
      || reservation.audience !== capability.audience
      || reservation.action_caid !== capability.action_caid
      || reservation.action_digest !== capability.action_digest
      || reservation.provider_id !== capability.provider_id
      || reservation.adapter_id !== capability.adapter_id
      || reservation.reservation_digest !== recovery.reservation_digest
      || reservation.remedy_caid !== recovery.remedy_caid
      || reservation.remedy_action_digest !== recovery.remedy_action_digest
      || reservation.destination_digest !== recovery.destination_digest
      || reservation.authority_digest !== recovery.authority_digest
      || reservation.units !== recovery.units
      || reservation.unit !== recovery.unit) return 'reservation_binding_mismatch';
  if (reservation.status !== 'RESERVED') return 'reservation_not_current';
  const admission = Date.parse(input.admission_at);
  const observed = Date.parse(reservation.observed_at);
  const validFrom = Date.parse(reservation.valid_from);
  const availableUntil = Date.parse(reservation.available_until);
  const actionExpiry = Date.parse(input.action_capability_expires_at);
  if (validFrom > admission) return 'reservation_not_yet_valid';
  if (observed > admission || observed < validFrom) return 'reservation_invalid';
  if (availableUntil <= admission || observed >= availableUntil) return 'reservation_expired';
  if (availableUntil < actionExpiry) return 'reservation_insufficient_coverage';
  if (reservation.available_until !== recovery.available_until) {
    return 'reservation_binding_mismatch';
  }
  return null;
}

function dependencyReason(
  dependencies: unknown,
  mode: RecoveryMode,
): string | null {
  if (!riskRecord(dependencies)
      || !Object.hasOwn(dependencies, 'current_status_resolver')
      || typeof dependencies.current_status_resolver !== 'function') {
    return 'current_status_resolver_required';
  }
  const keys = Reflect.ownKeys(dependencies);
  if (mode === 'RESERVED_COMPENSATION') {
    if (!Object.hasOwn(dependencies, 'reservation_verifier')
        || typeof dependencies.reservation_verifier !== 'function') {
      return 'reservation_verifier_required';
    }
    if (keys.length !== 2
        || !keys.includes('current_status_resolver')
        || !keys.includes('reservation_verifier')) return 'evaluator_configuration_invalid';
  } else if (keys.length !== 1 || !keys.includes('current_status_resolver')) {
    return 'evaluator_configuration_invalid';
  }
  return null;
}

/**
 * Resolve current status from relying-party code and return the only four v1
 * routes. Presenter-supplied mutable state is outside this API by design.
 */
export async function evaluateRecoveryAdmission(
  artifact: unknown,
  rawContext: RecoveryCapabilityVerificationContext,
  dependencies: RecoveryAdmissionDependencies,
): Promise<RecoveryAdmissionDecision> {
  const context = normalizeContext(rawContext);
  if (!context) {
    return decision('REFUSED', 'verification_context_required', verificationRefusal(
      'verification_context_required',
    ));
  }
  const verification = verifyRecoveryCapability(artifact, context);
  if (!verification.accepted || !verification.capability
      || !verification.capability_digest || !verification.issuer_id) {
    return decision('REFUSED', verification.reason, verification);
  }
  const configurationFailure = dependencyReason(dependencies, verification.capability.mode);
  if (configurationFailure) return decision('REFUSED', configurationFailure, verification);

  const callbackInput = riskFreeze({
    capability: verification.capability,
    capability_digest: verification.capability_digest,
    issuer_id: verification.issuer_id,
    admission_at: context.now,
    action_capability_expires_at: verification.capability.action_capability_expires_at,
  }) as Readonly<RecoveryStatusResolverInput>;

  let rawStatus: unknown;
  try {
    rawStatus = await dependencies.current_status_resolver(callbackInput);
  } catch {
    return decision('REFUSED', 'current_status_resolver_exception', verification);
  }
  const status = normalizeCurrentStatus(rawStatus);
  if (!status) return decision('REFUSED', 'current_status_invalid', verification);
  const statusFailure = currentStatusReason(status, callbackInput);
  if (statusFailure) return decision('REFUSED', statusFailure, verification, status);

  if (verification.capability.mode === 'IRREVERSIBLE') {
    return decision(
      'AUTHORITY_REQUIRED',
      'irreversible_authority_required',
      verification,
      status,
    );
  }
  if (verification.capability.mode === 'LOCAL_ATOMIC') {
    return decision('LOCAL_ATOMIC', null, verification, status);
  }

  let rawReservation: unknown;
  try {
    rawReservation = await dependencies.reservation_verifier!(callbackInput);
  } catch {
    return decision(
      'REFUSED',
      'reservation_verifier_exception',
      verification,
      status,
    );
  }
  const reservation = normalizeReservationStatus(rawReservation);
  if (!reservation) return decision('REFUSED', 'reservation_invalid', verification, status);
  const reservationFailure = reservationReason(reservation, callbackInput);
  if (reservationFailure) {
    return decision('REFUSED', reservationFailure, verification, status, reservation);
  }
  return decision('RESERVED_COMPENSATION', null, verification, status, reservation);
}

export default {
  RECOVERY_CAPABILITY_VERSION,
  RECOVERY_CAPABILITY_STATUS_VERSION,
  RECOVERY_RESERVATION_STATUS_VERSION,
  RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
  signRecoveryCapability,
  recoveryCapabilityDigest,
  verifyRecoveryCapability,
  evaluateRecoveryAdmission,
};
