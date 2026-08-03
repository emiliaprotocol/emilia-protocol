// SPDX-License-Identifier: Apache-2.0

/**
 * Gate Allowance v1.
 *
 * A Gate allowance is a customer-signed, time-bounded authorization envelope
 * for one typed connector action. It does not hold provider credentials and it
 * does not authorize arbitrary tools. The capability store remains the atomic
 * budget, replay, and post-entry uncertainty boundary.
 */

import {
  createHash,
  createPublicKey,
  randomUUID,
  type KeyLike,
  type KeyObject,
} from 'node:crypto';
import {
  CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
  capabilityActionDigest,
  capabilityBaseReceiptDigest,
  executeWithCapability,
  mintCapabilityReceipt,
} from './capability-receipt.js';
import {
  RISK_DIGEST,
  riskClone,
  riskDigest,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskInstant,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';

export const GATE_ALLOWANCE_VERSION = 'EP-GATE-ALLOWANCE-v1';
export const GATE_ALLOWANCE_CLAIM_BOUNDARY =
  'one_bounded_period_and_typed_connector_not_recurring_schedule_generic_tool_safety_or_complete_mediation';

const ALLOWANCE_BODY_KEYS = [
  '@version',
  'action_type',
  'allowance_id',
  'audience',
  'authorization_receipt_digest',
  'capability_id',
  'capability_issuer_key_digest',
  'claim_boundary',
  'connector_id',
  'constraints',
  'expires_at',
  'issued_at',
  'issuer',
  'presentation_digest',
  'revision',
  'subject_id',
  'supersedes_allowance_digest',
  'tenant_id',
  'valid_from',
] as const;

const ALLOWANCE_INPUT_KEYS = ALLOWANCE_BODY_KEYS.filter((key) =>
  !['@version', 'claim_boundary', 'issuer'].includes(key),
);

const CONSTRAINT_KEYS = [
  'aggregate_amount',
  'allowed_values',
  'allowed_targets',
  'amount_field',
  'currency',
  'currency_field',
  'material_fields',
  'max_amount_per_action',
  'operation_id_field',
  'target_field',
] as const;

const FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const CURRENCY = /^[A-Z][A-Z0-9]{2,11}$/;
const MAX_FIELDS = 32;
const MAX_TARGETS = 512;

type AllowanceSigner = {
  issuer_id: string;
  key_id: string;
  private_key: KeyLike;
};

type CapabilityKeyMaterial = KeyObject | string | Buffer;

type ExpectedAllowanceContext = {
  allowance_id: string;
  tenant_id: string;
  subject_id: string;
  audience: string;
  connector_id: string;
  authorizer_id: string;
};

function capabilityIssuerKeyDigest(key: CapabilityKeyMaterial): string {
  const publicKey =
    typeof key === 'object' && !Buffer.isBuffer(key) && key.type === 'public'
      ? key
      : createPublicKey(key as any);
  const encoded = publicKey
    .export({ type: 'spki', format: 'der' });
  return `sha256:${createHash('sha256').update(encoded).digest('hex')}`;
}

function validPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function uniqueBoundedStrings(
  value: unknown,
  label: string,
  max: number,
  predicate: (entry: string) => boolean,
): string[] {
  if (!Array.isArray(value)
      || value.length < 1
      || value.length > max
      || value.some((entry) => typeof entry !== 'string' || !predicate(entry))
      || new Set(value).size !== value.length) {
    throw new TypeError(`${label} must be a bounded, non-empty set of canonical strings`);
  }
  return [...value].sort();
}

function normalizeConstraints(value: unknown): RiskRecord {
  if (!riskExact(value, CONSTRAINT_KEYS)) throw new TypeError('allowance constraints are not closed');
  const materialFields = uniqueBoundedStrings(
    value.material_fields,
    'allowance constraints.material_fields',
    MAX_FIELDS,
    (entry) => FIELD_NAME.test(entry),
  );
  const allowedTargets = uniqueBoundedStrings(
    value.allowed_targets,
    'allowance constraints.allowed_targets',
    MAX_TARGETS,
    (entry) => riskIdentifier(entry),
  );
  if (!riskRecord(value.allowed_values) || Object.keys(value.allowed_values).length > MAX_FIELDS) {
    throw new TypeError('allowance constraints.allowed_values must be a bounded closed object');
  }
  const allowedValues: RiskRecord = {};
  for (const field of Object.keys(value.allowed_values).sort()) {
    if (!FIELD_NAME.test(field) || !materialFields.includes(field)) {
      throw new TypeError('allowance allowed_values must name material fields');
    }
    allowedValues[field] = uniqueBoundedStrings(
      value.allowed_values[field],
      `allowance constraints.allowed_values.${field}`,
      MAX_TARGETS,
      (entry) => riskIdentifier(entry),
    );
  }
  const fieldNames = [
    value.operation_id_field,
    value.amount_field,
    value.currency_field,
    value.target_field,
  ];
  if (fieldNames.some((entry) => typeof entry !== 'string' || !FIELD_NAME.test(entry))) {
    throw new TypeError('allowance constraint field selectors are invalid');
  }
  if (new Set(fieldNames).size !== fieldNames.length
      || fieldNames.some((entry) => !materialFields.includes(entry))) {
    throw new TypeError('allowance constraint selectors must name distinct material fields');
  }
  if (!materialFields.includes('action_type')) {
    throw new TypeError('allowance constraints must bind action_type');
  }
  if (typeof value.currency !== 'string' || !CURRENCY.test(value.currency)) {
    throw new TypeError('allowance currency must be canonical uppercase currency text');
  }
  if (!validPositiveSafeInteger(value.aggregate_amount)
      || !validPositiveSafeInteger(value.max_amount_per_action)
      || value.max_amount_per_action > value.aggregate_amount) {
    throw new TypeError('allowance monetary limits must be positive safe integers within the aggregate');
  }
  return {
    currency: value.currency,
    aggregate_amount: value.aggregate_amount,
    max_amount_per_action: value.max_amount_per_action,
    material_fields: materialFields,
    operation_id_field: value.operation_id_field,
    amount_field: value.amount_field,
    currency_field: value.currency_field,
    target_field: value.target_field,
    allowed_targets: allowedTargets,
    allowed_values: allowedValues,
  };
}

function normalizeAllowanceInput(value: unknown): RiskRecord {
  if (!riskExact(value, ALLOWANCE_INPUT_KEYS)) throw new TypeError('allowance input is not closed');
  for (const key of [
    'allowance_id',
    'tenant_id',
    'subject_id',
    'audience',
    'connector_id',
    'action_type',
    'capability_id',
  ]) {
    if (!riskIdentifier(value[key])) throw new TypeError(`allowance ${key} is invalid`);
  }
  if (typeof value.authorization_receipt_digest !== 'string'
      || !RISK_DIGEST.test(value.authorization_receipt_digest)) {
    throw new TypeError('allowance authorization_receipt_digest is invalid');
  }
  if (typeof value.presentation_digest !== 'string' || !RISK_DIGEST.test(value.presentation_digest)) {
    throw new TypeError('allowance presentation_digest is invalid');
  }
  if (typeof value.capability_issuer_key_digest !== 'string'
      || !RISK_DIGEST.test(value.capability_issuer_key_digest)) {
    throw new TypeError('allowance capability_issuer_key_digest is invalid');
  }
  if (!Number.isSafeInteger(value.revision) || value.revision < 1) {
    throw new TypeError('allowance revision must be a positive safe integer');
  }
  if ((value.revision === 1 && value.supersedes_allowance_digest !== null)
      || (value.revision > 1
        && (typeof value.supersedes_allowance_digest !== 'string'
          || !RISK_DIGEST.test(value.supersedes_allowance_digest)))) {
    throw new TypeError('allowance supersession link is invalid');
  }
  const issuedAt = riskInstant(value.issued_at);
  const validFrom = riskInstant(value.valid_from);
  const expiresAt = riskInstant(value.expires_at);
  if (![issuedAt, validFrom, expiresAt].every(Number.isFinite)
      || issuedAt > validFrom
      || validFrom >= expiresAt) {
    throw new TypeError('allowance validity window is invalid');
  }
  return {
    allowance_id: value.allowance_id,
    tenant_id: value.tenant_id,
    subject_id: value.subject_id,
    audience: value.audience,
    connector_id: value.connector_id,
    action_type: value.action_type,
    capability_id: value.capability_id,
    capability_issuer_key_digest: value.capability_issuer_key_digest,
    revision: value.revision,
    supersedes_allowance_digest: value.supersedes_allowance_digest,
    authorization_receipt_digest: value.authorization_receipt_digest,
    presentation_digest: value.presentation_digest,
    issued_at: value.issued_at,
    valid_from: value.valid_from,
    expires_at: value.expires_at,
    constraints: normalizeConstraints(value.constraints),
  };
}

function nowMilliseconds(now: number | (() => number)): number {
  const value = typeof now === 'function' ? now() : now;
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('allowance clock is invalid');
  return value;
}

function withoutProof(artifact: unknown): RiskRecord {
  if (!riskRecord(artifact)) throw new TypeError('allowance artifact is invalid');
  const { proof: _proof, ...body } = artifact;
  return body;
}

/** Sign a closed Gate allowance with a customer-controlled Ed25519 key. */
export function signGateAllowance(input: unknown, signer: AllowanceSigner): RiskRecord {
  const allowance = normalizeAllowanceInput(input);
  return signRiskBody(GATE_ALLOWANCE_VERSION, {
    '@version': GATE_ALLOWANCE_VERSION,
    ...allowance,
    claim_boundary: GATE_ALLOWANCE_CLAIM_BOUNDARY,
  }, signer);
}

/** Digest the signed allowance, including its proof. */
export function allowanceDigest(artifact: unknown): string {
  return riskDigest(artifact);
}

/** Verify signature, closed shape, validity, and relying-party context. */
export function verifyGateAllowance(
  artifact: unknown,
  {
    trusted_keys,
    now = Date.now,
    expected_allowance_id,
    expected_tenant_id,
    expected_subject_id,
    expected_audience,
    expected_connector_id,
    expected_authorizer_id,
  }: {
    trusted_keys?: TrustedRiskKeys;
    now?: number | (() => number);
    expected_allowance_id?: string;
    expected_tenant_id?: string;
    expected_subject_id?: string;
    expected_audience?: string;
    expected_connector_id?: string;
    expected_authorizer_id?: string;
  } = {},
): RiskRecord {
  const verified = verifyRiskBody(artifact, GATE_ALLOWANCE_VERSION, trusted_keys);
  if (!verified.valid || !verified.body) {
    return {
      accepted: false,
      reason: verified.reason === 'issuer_untrusted'
        ? 'allowance_issuer_untrusted'
        : 'allowance_signature_invalid',
    };
  }
  const body = verified.body;
  try {
    if (!riskExact(body, ALLOWANCE_BODY_KEYS)
        || body.claim_boundary !== GATE_ALLOWANCE_CLAIM_BOUNDARY) {
      return { accepted: false, reason: 'allowance_shape_invalid' };
    }
    const normalized = normalizeAllowanceInput(
      Object.fromEntries(ALLOWANCE_INPUT_KEYS.map((key) => [key, body[key]])),
    );
    const instant = nowMilliseconds(now);
    if (instant < riskInstant(normalized.valid_from)) return { accepted: false, reason: 'allowance_not_yet_valid' };
    if (instant >= riskInstant(normalized.expires_at)) return { accepted: false, reason: 'allowance_expired' };
    const comparisons = [
      ['allowance_id', expected_allowance_id, body.allowance_id],
      ['tenant', expected_tenant_id, body.tenant_id],
      ['subject', expected_subject_id, body.subject_id],
      ['audience', expected_audience, body.audience],
      ['connector', expected_connector_id, body.connector_id],
      ['authorizer', expected_authorizer_id, body.issuer.id],
    ];
    for (const [label, expected, actual] of comparisons) {
      if (typeof expected !== 'string' || expected.length === 0) {
        return { accepted: false, reason: `expected_${label}_required` };
      }
      if (actual !== expected) return { accepted: false, reason: `${label}_mismatch` };
    }
    return {
      accepted: true,
      reason: null,
      allowance: riskFreeze(riskClone(artifact)),
      allowance_digest: allowanceDigest(artifact),
      authorization_receipt_digest: body.authorization_receipt_digest,
    };
  } catch {
    return { accepted: false, reason: 'allowance_shape_invalid' };
  }
}

/**
 * Issue the signed allowance and its atomic monetary capability.
 *
 * The caller still owns verification of the authorizing receipt. This function
 * binds the exact receipt bytes to both artifacts; it does not claim that the
 * receipt is trustworthy merely because it exists.
 */
export function issueGateAllowance({
  authorizationReceipt,
  allowance,
  predecessorAllowance,
  signer,
  capabilityIssuerPrivateKey,
  capabilityId,
  secret,
}: {
  authorizationReceipt?: RiskRecord;
  allowance?: RiskRecord;
  predecessorAllowance?: RiskRecord;
  signer?: AllowanceSigner;
  capabilityIssuerPrivateKey?: CapabilityKeyMaterial;
  capabilityId?: string;
  secret?: Buffer | string;
} = {}): RiskRecord {
  if (!riskRecord(authorizationReceipt)) throw new TypeError('authorizationReceipt is required');
  if (!riskRecord(allowance)) throw new TypeError('allowance is required');
  if (!signer) throw new TypeError('allowance signer is required');
  if (!capabilityIssuerPrivateKey) throw new TypeError('capability issuer key is required');
  if (allowance.revision === 1 && predecessorAllowance !== undefined) {
    throw new TypeError('revision 1 allowance must not have a predecessor');
  }
  if (Number(allowance.revision) > 1) {
    if (!riskRecord(predecessorAllowance)) {
      throw new TypeError('successor allowance requires the complete signed predecessor');
    }
    const predecessorBody = withoutProof(predecessorAllowance);
    if (!riskExact(predecessorBody, ALLOWANCE_BODY_KEYS)
        || predecessorBody.claim_boundary !== GATE_ALLOWANCE_CLAIM_BOUNDARY) {
      throw new TypeError('successor predecessor allowance is invalid');
    }
    const normalizedPredecessor = normalizeAllowanceInput(
      Object.fromEntries(ALLOWANCE_INPUT_KEYS.map((key) => [key, predecessorBody[key]])),
    );
    const stableLineageFields = [
      'allowance_id',
      'tenant_id',
      'subject_id',
      'audience',
      'connector_id',
      'action_type',
    ];
    if (allowance.revision !== normalizedPredecessor.revision + 1
        || allowance.supersedes_allowance_digest !== allowanceDigest(predecessorAllowance)
        || stableLineageFields.some((field) => allowance[field] !== normalizedPredecessor[field])) {
      throw new TypeError('successor allowance does not continue the predecessor lineage');
    }
  }
  const boundCapabilityId =
    capabilityId ??
    (typeof allowance.capability_id === 'string' ? allowance.capability_id : randomUUID());
  const boundIssuerKeyDigest = capabilityIssuerKeyDigest(capabilityIssuerPrivateKey);
  if (allowance.capability_id !== undefined && allowance.capability_id !== boundCapabilityId) {
    throw new TypeError('allowance capability_id does not match requested capability');
  }
  if (allowance.capability_issuer_key_digest !== undefined
      && allowance.capability_issuer_key_digest !== boundIssuerKeyDigest) {
    throw new TypeError('allowance capability issuer key does not match requested capability');
  }
  const receiptDigest = capabilityBaseReceiptDigest(authorizationReceipt);
  if (allowance.authorization_receipt_digest !== undefined
      && allowance.authorization_receipt_digest !== receiptDigest) {
    throw new TypeError('allowance authorization receipt digest does not match supplied receipt');
  }
  const signedAllowance = signGateAllowance({
    ...riskClone(allowance),
    authorization_receipt_digest: receiptDigest,
    capability_id: boundCapabilityId,
    capability_issuer_key_digest: boundIssuerKeyDigest,
  }, signer);
  const signedBody = withoutProof(signedAllowance);
  const minted = mintCapabilityReceipt(authorizationReceipt, {
    issuerPrivateKey: capabilityIssuerPrivateKey,
    budget: {
      amount: signedBody.constraints.aggregate_amount,
      currency: signedBody.constraints.currency,
    },
    expiry: signedBody.expires_at,
    scope: {
      profile: CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
      profile_id: `${signedBody.tenant_id}/${signedBody.allowance_id}`,
      profile_digest: allowanceDigest(signedAllowance),
      operation_id_field: signedBody.constraints.operation_id_field,
    },
    capabilityId: boundCapabilityId,
    ...(secret ? { secret } : {}),
  });
  // The secret is a Buffer and must remain opaque binary material. Freeze the
  // container only; recursively freezing typed-array elements is unsupported
  // by Node and would also pretend to add security that belongs in key custody.
  return Object.freeze({
    allowance: signedAllowance,
    capabilityReceipt: minted.capabilityReceipt,
    secret: minted.secret,
    shares: minted.shares,
  });
}

function validateActionAgainstAllowance(
  action: unknown,
  operationId: string,
  body: RiskRecord,
): { ok: true; amount: number; currency: string } | { ok: false; reason: string } {
  if (!riskRecord(action)) return { ok: false, reason: 'allowance_action_shape_invalid' };
  const constraints = body.constraints;
  const actualFields = Object.keys(action).sort();
  if (actualFields.length !== constraints.material_fields.length
      || actualFields.some((field, index) => field !== constraints.material_fields[index])) {
    return { ok: false, reason: 'allowance_action_shape_invalid' };
  }
  if (action.action_type !== body.action_type) return { ok: false, reason: 'allowance_action_type_mismatch' };
  if (action[constraints.operation_id_field] !== operationId) {
    return { ok: false, reason: 'allowance_operation_binding_failed' };
  }
  const amount = action[constraints.amount_field];
  if (!validPositiveSafeInteger(amount)) return { ok: false, reason: 'allowance_amount_invalid' };
  if (amount > constraints.max_amount_per_action) {
    return { ok: false, reason: 'allowance_per_action_limit_exceeded' };
  }
  const currency = action[constraints.currency_field];
  if (currency !== constraints.currency) return { ok: false, reason: 'allowance_currency_mismatch' };
  const target = action[constraints.target_field];
  if (typeof target !== 'string' || !constraints.allowed_targets.includes(target)) {
    return { ok: false, reason: 'allowance_target_not_allowed' };
  }
  for (const [field, permitted] of Object.entries(
    constraints.allowed_values as Record<string, string[]>,
  )) {
    if (!permitted.includes(action[field])) {
      return { ok: false, reason: 'allowance_field_value_not_allowed' };
    }
  }
  return { ok: true, amount, currency };
}

function allowanceActionFenceDigest(action: RiskRecord, operationIdField: string): string {
  // operationIdField identifies the request wrapper, not the material action.
  // Every other field is closed and profile-validated above, so the resulting
  // digest remains stable when a caller retries one action under a new wrapper.
  const materialAction: RiskRecord = {};
  for (const field of Object.keys(action).sort()) {
    if (field !== operationIdField) materialAction[field] = action[field];
  }
  return capabilityActionDigest(materialAction);
}

/**
 * Execute one typed, in-envelope action through the existing capability ledger.
 */
export async function executeWithGateAllowance({
  allowance,
  capabilityReceipt,
  secret,
  action,
  operationId,
  store,
  executeAction,
  verifyAuthorizationReceipt,
  verifyAllowanceStatus,
  trustedAllowanceKeys,
  trustedCapabilityIssuerKeys = [],
  expected,
  now = Date.now,
}: {
  allowance?: RiskRecord;
  capabilityReceipt?: RiskRecord;
  secret?: Buffer | string;
  action?: RiskRecord;
  operationId?: string;
  store?: RiskRecord;
  executeAction?: (...args: any[]) => any;
  verifyAuthorizationReceipt?: ((receipt: RiskRecord, allowance: RiskRecord) => any) | null;
  verifyAllowanceStatus?: ((allowance: RiskRecord, context: {
    allowance_digest: string;
    revision: number;
    supersedes_allowance_digest: string | null;
  }) => {
    ok: boolean;
    reason?: string;
    status_epoch?: number;
    status_head_digest?: string;
  } | Promise<{
    ok: boolean;
    reason?: string;
    status_epoch?: number;
    status_head_digest?: string;
  }>) | null;
  trustedAllowanceKeys?: TrustedRiskKeys;
  trustedCapabilityIssuerKeys?: string[];
  expected?: ExpectedAllowanceContext;
  now?: number | (() => number);
} = {}): Promise<RiskRecord> {
  if (!expected) return { ok: false, reason: 'allowance_expected_context_required' };
  const verifiedAllowance = verifyGateAllowance(allowance, {
    trusted_keys: trustedAllowanceKeys,
    now,
    expected_allowance_id: expected.allowance_id,
    expected_tenant_id: expected.tenant_id,
    expected_subject_id: expected.subject_id,
    expected_audience: expected.audience,
    expected_connector_id: expected.connector_id,
    expected_authorizer_id: expected.authorizer_id,
  });
  if (!verifiedAllowance.accepted) return { ok: false, reason: verifiedAllowance.reason };
  const verifiedArtifact = verifiedAllowance.allowance as RiskRecord;
  const body = withoutProof(verifiedArtifact);
  const receipt = capabilityReceipt?.receipt;
  if (!riskRecord(receipt)
      || capabilityBaseReceiptDigest(receipt) !== body.authorization_receipt_digest) {
    return { ok: false, reason: 'allowance_authorization_receipt_mismatch' };
  }
  if (typeof verifyAuthorizationReceipt !== 'function') {
    return { ok: false, reason: 'allowance_authorization_receipt_verifier_required' };
  }
  let receiptVerification;
  try {
    receiptVerification = await verifyAuthorizationReceipt(
      riskClone(receipt),
      riskClone(verifiedArtifact),
    );
  } catch {
    return { ok: false, reason: 'allowance_authorization_receipt_verification_failed' };
  }
  if (receiptVerification !== true && receiptVerification?.ok !== true) {
    return { ok: false, reason: receiptVerification?.reason || 'allowance_authorization_receipt_rejected' };
  }
  if (typeof verifyAllowanceStatus !== 'function') {
    return { ok: false, reason: 'allowance_status_verifier_required' };
  }
  if (!store || store.allowanceCurrentnessCapable !== true) {
    return { ok: false, reason: 'allowance_status_store_required' };
  }
  let statusVerification;
  try {
    statusVerification = await verifyAllowanceStatus(
      riskClone(verifiedArtifact),
      {
        allowance_digest: allowanceDigest(verifiedArtifact),
        revision: body.revision,
        supersedes_allowance_digest: body.supersedes_allowance_digest,
      },
    );
  } catch {
    return { ok: false, reason: 'allowance_status_verification_failed' };
  }
  if (!statusVerification || statusVerification.ok !== true) {
    return { ok: false, reason: statusVerification?.reason || 'allowance_not_current' };
  }
  if (!Number.isSafeInteger(statusVerification.status_epoch)
      || Number(statusVerification.status_epoch) < 1
      || typeof statusVerification.status_head_digest !== 'string'
      || !RISK_DIGEST.test(statusVerification.status_head_digest)) {
    return { ok: false, reason: 'allowance_status_verification_invalid' };
  }
  const capability = capabilityReceipt?.capability;
  const scope = capability?.scope;
  const signature = capabilityReceipt?.capability_signature;
  if (!riskRecord(capability)
      || !riskRecord(scope)
      || !riskRecord(signature)
      || scope.profile !== CAPABILITY_ALLOWANCE_SCOPE_PROFILE
      || scope.profile_id !== `${body.tenant_id}/${body.allowance_id}`
      || scope.profile_digest !== allowanceDigest(verifiedArtifact)
      || scope.operation_id_field !== body.constraints.operation_id_field
      || capability.id !== body.capability_id
      || capabilityIssuerKeyDigest(
        createPublicKey({
          key: Buffer.from(signature.public_key, 'base64url'),
          type: 'spki',
          format: 'der',
        }),
      ) !== body.capability_issuer_key_digest
      || !Array.isArray(capability.delegation_chain)
      || capability.delegation_chain.length !== 0
      || capability.budget?.amount !== body.constraints.aggregate_amount
      || capability.budget?.currency !== body.constraints.currency
      || capability.expiry !== body.expires_at) {
    return { ok: false, reason: 'allowance_capability_binding_mismatch' };
  }
  if (typeof operationId !== 'string' || operationId.length === 0) {
    return { ok: false, reason: 'allowance_operation_id_required' };
  }
  const actionCheck = validateActionAgainstAllowance(action, operationId, body);
  if (!actionCheck.ok) return { ok: false, reason: actionCheck.reason };
  return executeWithCapability({
    capabilityReceipt,
    secret,
    action: {
      amount: actionCheck.amount,
      currency: actionCheck.currency,
    },
    observedAction: action,
    operationId,
    store,
    executeAction,
    verifyBaseReceipt: () => true,
    verifyActionProfile: (candidate, profile) => {
      const ok = profile.profile_id === `${body.tenant_id}/${body.allowance_id}`
        && profile.profile_digest === allowanceDigest(verifiedArtifact);
      return ok
        ? {
          ok: true,
          action_fence_digest: allowanceActionFenceDigest(
            candidate,
            body.constraints.operation_id_field,
          ),
        }
        : { ok: false, reason: 'allowance_profile_binding_mismatch' };
    },
    allowanceStatus: {
      allowance_profile_id: `${body.tenant_id}/${body.allowance_id}`,
      allowance_digest: allowanceDigest(verifiedArtifact),
      revision: body.revision,
      status_epoch: statusVerification.status_epoch,
      status_head_digest: statusVerification.status_head_digest,
    },
    trustedIssuerKeys: trustedCapabilityIssuerKeys,
    now,
  });
}

export default {
  GATE_ALLOWANCE_VERSION,
  GATE_ALLOWANCE_CLAIM_BOUNDARY,
  allowanceDigest,
  signGateAllowance,
  verifyGateAllowance,
  issueGateAllowance,
  executeWithGateAllowance,
};
