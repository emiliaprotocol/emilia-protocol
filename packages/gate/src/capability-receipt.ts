// SPDX-License-Identifier: Apache-2.0

/**
 * EP Capability Receipt v1.
 *
 * A capability receipt is an issuer-signed envelope around an ordinary EP
 * receipt.  The ordinary receipt remains the policy/assurance proof; the
 * capability envelope adds a secret preimage, an immutable budget, an expiry,
 * and (optionally) Shamir shares.  Spend state is never trusted from the
 * envelope.  Every spend must pass through an atomic capability store.
 *
 * The executor deliberately follows the same indeterminate-outcome rule as
 * Gate: once the external effect is entered, a storage failure cannot reopen
 * the budget.  The reservation remains blocked until reconciliation.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from 'node:crypto';
import { canonicalize } from './execution-binding.js';
import {
  evaluateProviderEntryGuard,
  providerEntryContext,
  requiredProviderEntryControlDomain,
  type ProviderEntryGuard,
} from './provider-entry.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgilityOptions,
  type AgileSigningKey,
} from '@emilia-protocol/verify/pq-signature-agility';

export const CAPABILITY_RECEIPT_VERSION = 'EP-CAPABILITY-RECEIPT-v1';
export const CAPABILITY_STATE_VERSION = 'EP-CAPABILITY-STATE-v1';
export const CAPABILITY_SHARE_VERSION = 'EP-CAPABILITY-SHARE-v1';
export const CAPABILITY_HASH_ALGORITHM = 'sha256';
export const CAPABILITY_SCOPE_PROFILE = 'urn:emilia:scope:action-digest-set-v1';
export const CAPABILITY_CAID_SCOPE_PROFILE = 'urn:emilia:scope:caid-set-v1';
export const CAPABILITY_ALLOWANCE_SCOPE_PROFILE = 'EP-CAPABILITY-ALLOWANCE-SCOPE-v1';
export const CAPABILITY_ACTION_FENCE_PROFILE = 'EP-CAPABILITY-ACTION-FENCE-v1';
export const CAPABILITY_REVOCATION_MODES = Object.freeze(['direct', 'cascade'] as const);

// 2^521 - 1 is a prime and is comfortably larger than a 256-bit secret.
const FIELD = (2n ** 521n) - 1n;
const SHARE_BYTES = 66;
const HASH_BYTES = 32;
const MAX_CURRENCY_BYTES = 32;
const MAX_OPERATION_ID_BYTES = 128;
const MAX_EVIDENCE_PROFILE_BYTES = 512;
const DEFAULT_PROVIDER_ENTRY_TIMEOUT_MS = 30_000;
const MAX_DELEGATES = 64;
const MAX_SCOPE_ACTIONS = 256;
const ACTION_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ACTION_FENCE_CONSTRAINT = 'ep_capability_operations_live_action_uniq';

type KeyMaterial = KeyObject | string | Buffer;
type CapabilityBudget = { amount: number; currency: string };
type CapabilityRevocationMode = typeof CAPABILITY_REVOCATION_MODES[number];
type AllowanceStatusAssertion = {
  allowance_profile_id: string;
  allowance_digest: string;
  revision: number;
  status_epoch: number;
  status_head_digest: string;
};
type AdvanceAllowanceStatusOptions = AllowanceStatusAssertion & {
  expected_status_epoch: number | null;
  expected_status_head_digest: string | null;
  status: 'active' | 'suspended' | 'revoked';
};
// reserveSpend needs every field to build the reservation row and to run the
// unguarded budget arithmetic below, so these are required rather than
// optional; every call site in this file already supplies all of them.
type ReserveSpendOptions = {
  capabilityId: string;
  capabilityFingerprint: string;
  operationNamespace?: string;
  operationId: string;
  actionDigest: string;
  actionFenceDigest?: string;
  amount: number;
  currency: string;
  controlDomainId?: string;
  allowanceStatus?: AllowanceStatusAssertion;
  now?: number | (() => number);
};
type CommitSpendOptions = {
  capabilityId?: string;
  operationNamespace?: string;
  operationId?: string;
  reservationToken?: string;
  outcome?: string;
  now?: number | (() => number);
};
type BeginProviderEntryOptions = {
  capabilityId?: string;
  operationNamespace?: string;
  operationId?: string;
  reservationToken?: string;
  controlDomainId?: string;
  now?: number | (() => number);
};
type ControlTransitionVerification = {
  authenticated: boolean;
  authorized: boolean;
  authority_instance_digest?: string;
  action_digest?: string;
};
type ControlTransitionOptions = {
  controlDomainId?: string;
  operationId?: string;
  actionDigest?: string;
  authorization?: unknown;
  now?: number | (() => number);
};
type VerifyControlTransition = (
  input: Readonly<{
    event_type: 'freeze' | 'restore';
    control_domain_id: string;
    operation_id: string;
    action_digest: string;
    authorization: unknown;
  }>,
) => ControlTransitionVerification | Promise<ControlTransitionVerification>;
type RecoverPreEntrySpendOptions = {
  capabilityId?: string;
  operationNamespace?: string;
  operationId?: string;
  actionDigest?: string;
  reservationToken?: string;
  disposition?: 'release' | 'burn';
  now?: number | (() => number);
};
type ReconcileSpendOptions = {
  capabilityId?: string;
  operationNamespace?: string;
  operationId?: string;
  actionDigest?: string;
  evidenceDigest?: string;
  evidenceProfile?: string;
  evidenceFinal?: boolean;
  evidenceObservedAt?: string;
  outcome?: string;
  now?: number | (() => number);
};
type RevokeCapabilityOptions = {
  capabilityId?: string;
  capabilityFingerprint?: string;
  now?: number | (() => number);
};
type CapabilityExecutionDomain = {
  executor_id: string;
  expected_state_domain_digest?: string | null;
  single_executor_id?: string | null;
  require_aggregate?: boolean;
};
type HumanAuthorizationVerificationContext = {
  action: Readonly<Record<string, any>>;
  action_digest: string;
  pins: Readonly<Record<string, any>>;
};
type ExecuteWithCapabilityOptions = {
  capabilityReceipt?: Record<string, any>;
  secret?: Buffer | string;
  action?: Record<string, any>;
  store?: Record<string, any>;
  executeAction?: (...args: any[]) => any;
  gate?: Record<string, any> | null;
  selector?: Record<string, any>;
  observedAction?: Record<string, any> | null;
  trustedIssuerKeys?: string[];
  verifyBaseReceipt?: ((...args: any[]) => any) | null;
  resolveCaid?: ((action: any) => any) | null;
  verifyActionProfile?: ((action: any, profile: { profile_id: string; profile_digest: string }) => any) | null;
  executionDomain?: CapabilityExecutionDomain | null;
  requireHumanAuthorization?: boolean;
  humanAuthorization?: unknown;
  humanAuthorizationPins?: Record<string, any> | null;
  verifyHumanAuthorization?: ((artifact: unknown, context: HumanAuthorizationVerificationContext) => any) | null;
  allowanceStatus?: AllowanceStatusAssertion;
  controlDomainId?: string;
  operationId?: string | null;
  now?: number | (() => number);
  thresholdSecretVerified?: boolean;
  providerEntryGuard?: ProviderEntryGuard | null;
};
type ExecuteWithCapabilityResult = {
  ok: boolean;
  reason?: string;
  status?: number;
  result?: any;
  scope?: any;
  authorization?: any;
  human_authorization?: any;
  budget_guarantee?: any;
  operation_id?: string | null;
  action_digest?: string;
  action_fence_digest?: string;
  holding_operation_id?: string | null;
  caid?: string;
  remaining?: any;
  provider_entry_evidence?: Readonly<Record<string, any>> | null;
};

function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object') return value;
  const stack = [value];
  const seen = new WeakSet();
  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== 'object' || seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) stack.push(child);
    Object.freeze(current);
  }
  return value;
}

function nowMs(now) {
  const value = typeof now === 'function' ? now() : now;
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('capability clock must return a non-negative safe integer');
  return value;
}

function boundedIdentifier(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && Buffer.byteLength(value, 'utf8') <= 512
    && /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/.test(value);
}

function base64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function withoutBase64Padding(value) {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x3d) end -= 1;
  return value.slice(0, end);
}

function decodeBase64u(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${label} must be base64url`);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || base64u(bytes) !== withoutBase64Padding(value)) throw new TypeError(`${label} is not canonical base64url`);
  return bytes;
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
  return sha256(value).toString('hex');
}

function digestSecret(secret) {
  const bytes = Buffer.isBuffer(secret) ? Buffer.from(secret) : decodeBase64u(secret, 'secret');
  if (bytes.length !== HASH_BYTES) throw new TypeError('capability secret must be exactly 32 bytes');
  return { bytes, hash: `sha256:${sha256Hex(bytes)}` };
}

function equalHash(expected, actual) {
  if (typeof expected !== 'string' || typeof actual !== 'string') return false;
  if (!/^sha256:[0-9a-f]{64}$/.test(expected) || !/^sha256:[0-9a-f]{64}$/.test(actual)) return false;
  return timingSafeEqual(Buffer.from(expected.slice(7), 'hex'), Buffer.from(actual.slice(7), 'hex'));
}

function keyBytes(value, label) {
  if (value?.type === 'private' || value?.type === 'public') return value;
  if (typeof value !== 'string' && !Buffer.isBuffer(value)) throw new TypeError(`${label} must be a Node KeyObject or encoded key`);
  return value;
}

function publicKeyB64u(privateKey) {
  return createPublicKey(keyBytes(privateKey, 'issuerPrivateKey'))
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
}

function validateCurrency(currency) {
  if (typeof currency !== 'string' || currency.length === 0 || Buffer.byteLength(currency, 'utf8') > MAX_CURRENCY_BYTES) {
    throw new TypeError('capability currency must be a short non-empty string');
  }
  return currency;
}

function validateAmount(amount, label = 'amount') {
  if (!Number.isSafeInteger(amount) || amount < 0) throw new TypeError(`capability ${label} must be a non-negative safe integer`);
  return amount;
}

function validateSpendAmount(amount) {
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw new TypeError('capability amount must be a positive safe integer');
  }
  return amount;
}

function validateOperationId(operationId) {
  if (typeof operationId !== 'string' || operationId.length === 0 || Buffer.byteLength(operationId, 'utf8') > MAX_OPERATION_ID_BYTES) {
    throw new TypeError('operation_id must be a short non-empty string');
  }
  return operationId;
}

function validateOperationNamespace(operationNamespace) {
  if (typeof operationNamespace !== 'string'
      || operationNamespace.length === 0
      || Buffer.byteLength(operationNamespace, 'utf8') > 512) {
    throw new TypeError('operation_namespace must be a bounded non-empty string');
  }
  return operationNamespace;
}

function validateControlDomainId(controlDomainId) {
  if (!boundedIdentifier(controlDomainId)) {
    throw new TypeError('control_domain_id must be a bounded non-empty identifier');
  }
  return controlDomainId;
}

async function verifyControlTransitionRequest(
  verifier: VerifyControlTransition | undefined,
  eventType: 'freeze' | 'restore',
  request: ControlTransitionOptions,
) {
  if (typeof verifier !== 'function') {
    return { authenticated: false, authorized: false };
  }
  try {
    const result = await verifier(Object.freeze({
      event_type: eventType,
      control_domain_id: request.controlDomainId as string,
      operation_id: request.operationId as string,
      action_digest: request.actionDigest as string,
      authorization: request.authorization,
    }));
    if (!isRecord(result) || result.authenticated !== true) {
      return { authenticated: false, authorized: false };
    }
    if (typeof result.authority_instance_digest !== 'string'
        || !ACTION_DIGEST_RE.test(result.authority_instance_digest)
        || result.action_digest !== request.actionDigest) {
      return { authenticated: false, authorized: false };
    }
    return {
      authenticated: true,
      authorized: result.authorized === true,
      authority_instance_digest: result.authority_instance_digest,
      action_digest: result.action_digest,
    };
  } catch {
    return { authenticated: false, authorized: false };
  }
}

function validateProviderEntryTimeoutMs(value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError('providerEntryTimeoutMs must be a positive safe integer');
  }
  return value;
}

function entryDeadline(at, capabilityExpiry, timeoutMs) {
  const timeoutDeadline = at > Number.MAX_SAFE_INTEGER - timeoutMs
    ? Number.MAX_SAFE_INTEGER
    : at + timeoutMs;
  return Math.min(capabilityExpiry, timeoutDeadline);
}

function validateActionDigest(actionDigest) {
  if (typeof actionDigest !== 'string' || !ACTION_DIGEST_RE.test(actionDigest)) {
    throw new TypeError('action_digest must be SHA-256');
  }
  return actionDigest;
}

function capabilityStateDomainDigest(): string {
  return `sha256:${sha256Hex(Buffer.concat([
    Buffer.from('EP-CAPABILITY-STATE-DOMAIN-v1\0', 'utf8'),
    randomBytes(32),
  ]))}`;
}

function normalizeOptionalStateDomainDigest(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  return validateActionDigest(value);
}

function capabilityBudgetGuarantee(store: Record<string, any>, binding: CapabilityExecutionDomain | null | undefined) {
  if (binding === undefined || binding === null) {
    return {
      ok: true,
      guarantee: Object.freeze({
        mode: 'local_store_only',
        executor_id: null,
        state_domain_digest: null,
      }),
    };
  }
  if (!isRecord(binding)) return { ok: false, reason: 'capability_execution_domain_invalid' };
  const allowed = new Set([
    'executor_id',
    'expected_state_domain_digest',
    'single_executor_id',
    'require_aggregate',
  ]);
  if (Object.keys(binding).some((key) => !allowed.has(key))
      || !boundedIdentifier(binding.executor_id)
      || (binding.require_aggregate !== undefined && typeof binding.require_aggregate !== 'boolean')
      || (binding.single_executor_id !== undefined
        && binding.single_executor_id !== null
        && !boundedIdentifier(binding.single_executor_id))) {
    return { ok: false, reason: 'capability_execution_domain_invalid' };
  }
  let expectedStateDomainDigest: string | null;
  try {
    expectedStateDomainDigest = normalizeOptionalStateDomainDigest(
      binding.expected_state_domain_digest,
    );
  } catch {
    return { ok: false, reason: 'capability_execution_domain_invalid' };
  }
  const singleExecutorId = binding.single_executor_id ?? null;
  const singleExecutorMatches = singleExecutorId !== null
    && singleExecutorId === binding.executor_id;

  if (expectedStateDomainDigest !== null
      && store.atomicStateDomainCapable === true
      && store.stateDomainDigest === expectedStateDomainDigest) {
    return {
      ok: true,
      guarantee: Object.freeze({
        mode: 'aggregate_atomic_domain',
        executor_id: binding.executor_id,
        state_domain_digest: expectedStateDomainDigest,
      }),
    };
  }
  if (singleExecutorMatches && binding.require_aggregate !== true) {
    return {
      ok: true,
      guarantee: Object.freeze({
        mode: 'single_executor',
        executor_id: binding.executor_id,
        state_domain_digest: null,
      }),
    };
  }
  if (singleExecutorId !== null && !singleExecutorMatches) {
    return { ok: false, reason: 'capability_executor_mismatch' };
  }
  if (expectedStateDomainDigest === null) {
    return {
      ok: false,
      reason: binding.require_aggregate === true
        ? 'capability_state_domain_required'
        : 'capability_execution_domain_required',
    };
  }
  return { ok: false, reason: 'capability_state_domain_mismatch' };
}

async function verifyPerActionHumanAuthorization({
  required,
  artifact,
  pins,
  verifier,
  action,
  actionDigest,
}: {
  required: boolean;
  artifact: unknown;
  pins: Record<string, any> | null | undefined;
  verifier: ((artifact: unknown, context: HumanAuthorizationVerificationContext) => any) | null | undefined;
  action: Readonly<Record<string, any>>;
  actionDigest: string;
}) {
  const enabled = required
    || artifact !== undefined
    || pins !== undefined
    || verifier !== undefined;
  if (!enabled) return { ok: true, result: null };
  if (artifact === undefined || artifact === null) {
    return { ok: false, reason: 'capability_human_authorization_required' };
  }
  if (!isRecord(pins) || Object.keys(pins).length === 0) {
    return { ok: false, reason: 'capability_human_authorization_pins_required' };
  }
  if (typeof verifier !== 'function') {
    return { ok: false, reason: 'capability_human_authorization_verifier_required' };
  }
  const frozenPins = deepFreeze(structuredClone(pins));
  let result;
  try {
    result = await verifier(structuredClone(artifact), Object.freeze({
      action,
      action_digest: actionDigest,
      pins: frozenPins,
    }));
  } catch {
    return { ok: false, reason: 'capability_human_authorization_unavailable' };
  }
  if (!isRecord(result)
      || Object.keys(result).length !== 5
      || result.native_verification !== 'VERIFIED'
      || result.acceptance !== 'ACCEPTED'
      || result.evidence_type !== 'human_authorization'
      || typeof result.action_digest !== 'string'
      || typeof result.evidence_digest !== 'string'
      || !ACTION_DIGEST_RE.test(result.action_digest)
      || !ACTION_DIGEST_RE.test(result.evidence_digest)) {
    return { ok: false, reason: 'capability_human_authorization_invalid' };
  }
  if (result.action_digest !== actionDigest) {
    return { ok: false, reason: 'capability_human_authorization_action_mismatch' };
  }
  return {
    ok: true,
    result: deepFreeze({
      native_verification: result.native_verification,
      acceptance: result.acceptance,
      evidence_type: result.evidence_type,
      action_digest: result.action_digest,
      evidence_digest: result.evidence_digest,
    }),
  };
}

function validateEvidenceProfile(evidenceProfile) {
  if (typeof evidenceProfile !== 'string'
      || evidenceProfile.length === 0
      || Buffer.byteLength(evidenceProfile, 'utf8') > MAX_EVIDENCE_PROFILE_BYTES) {
    throw new TypeError('evidence_profile must be a bounded non-empty string');
  }
  return evidenceProfile;
}

function evidenceObservedAtMs(value) {
  if (typeof value !== 'string') throw new TypeError('evidence observed_at must be an ISO-8601 timestamp');
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError('evidence observed_at must be an ISO-8601 timestamp');
  return parsed;
}

function existingOperationReason(status) {
  if (status === 'reserved' || status === 'provider_entered') return 'operation_in_flight';
  if (status === 'committed') return 'operation_already_committed';
  return 'operation_already_finalized';
}

/**
 * Statuses in which an operation still holds the action: it is either about to
 * happen, happening, or has happened. 'released' is absent on purpose. A
 * released operation carries outcome 'not_entered', meaning the provider
 * provably never received it, so re-authorizing that same action is a genuine
 * retry rather than a duplicate.
 */
const ACTION_HOLDING_STATUSES = Object.freeze(['reserved', 'provider_entered', 'committed']);

/**
 * Why a DIFFERENT operation already holds this action digest.
 *
 * Deliberately distinct from existingOperationReason. That one answers "this
 * operation id was already used". This one answers "some other operation id is
 * already authorized for this exact action", which is a different diagnosis and
 * a different fix for the caller.
 */
function actionHeldReason(status) {
  return status === 'committed' ? 'action_already_committed' : 'action_in_flight';
}

/** Postgres unique_violation on the live-action partial index, and only that one. */
const LIVE_ACTION_UNIQUE_INDEX = 'ep_capability_operations_live_action_uniq';
function isLiveActionUniqueViolation(error: unknown): boolean {
  return isRecord(error)
    && error.code === '23505'
    && error.constraint === LIVE_ACTION_UNIQUE_INDEX;
}

function isActionFenceConflict(error: unknown): boolean {
  return isRecord(error)
    && error.code === '23505'
    && error.constraint === ACTION_FENCE_CONSTRAINT;
}

function normalizeAllowanceStatusAssertion(value: unknown): AllowanceStatusAssertion {
  if (!isRecord(value)
      || Object.keys(value).length !== 5
      || !Object.hasOwn(value, 'allowance_profile_id')
      || !Object.hasOwn(value, 'allowance_digest')
      || !Object.hasOwn(value, 'revision')
      || !Object.hasOwn(value, 'status_epoch')
      || !Object.hasOwn(value, 'status_head_digest')) {
    throw new TypeError('allowance status assertion must be a closed object');
  }
  const allowanceProfileId = validateOperationNamespace(value.allowance_profile_id);
  if (typeof value.allowance_digest !== 'string' || !ACTION_DIGEST_RE.test(value.allowance_digest)
      || typeof value.status_head_digest !== 'string' || !ACTION_DIGEST_RE.test(value.status_head_digest)) {
    throw new TypeError('allowance status digests must be SHA-256');
  }
  if (!Number.isSafeInteger(value.revision) || value.revision < 1
      || !Number.isSafeInteger(value.status_epoch) || value.status_epoch < 1) {
    throw new TypeError('allowance status revision and epoch must be positive safe integers');
  }
  return {
    allowance_profile_id: allowanceProfileId,
    allowance_digest: value.allowance_digest,
    revision: value.revision,
    status_epoch: value.status_epoch,
    status_head_digest: value.status_head_digest,
  };
}

function normalizeAllowanceStatusAdvance(value: unknown): AdvanceAllowanceStatusOptions {
  if (!isRecord(value)
      || Object.keys(value).length !== 8
      || !Object.hasOwn(value, 'expected_status_epoch')
      || !Object.hasOwn(value, 'expected_status_head_digest')
      || !Object.hasOwn(value, 'status')) {
    throw new TypeError('allowance status advance must be a closed object');
  }
  const assertion = normalizeAllowanceStatusAssertion(Object.fromEntries(
    ['allowance_profile_id', 'allowance_digest', 'revision', 'status_epoch', 'status_head_digest']
      .map((key) => [key, value[key]]),
  ));
  const expectedEpoch = value.expected_status_epoch;
  const expectedHead = value.expected_status_head_digest;
  if ((expectedEpoch === null) !== (expectedHead === null)
      || (expectedEpoch !== null
        && (!Number.isSafeInteger(expectedEpoch) || expectedEpoch < 1
          || typeof expectedHead !== 'string' || !ACTION_DIGEST_RE.test(expectedHead)))) {
    throw new TypeError('allowance status expected head is invalid');
  }
  if (!['active', 'suspended', 'revoked'].includes(value.status)) {
    throw new TypeError('allowance status is invalid');
  }
  return {
    ...assertion,
    expected_status_epoch: expectedEpoch,
    expected_status_head_digest: expectedHead,
    status: value.status as AdvanceAllowanceStatusOptions['status'],
  };
}

function allowanceStatusRefusal(current, asserted: AllowanceStatusAssertion) {
  if (current.status !== 'active') return `allowance_${current.status}`;
  if (current.allowance_digest !== asserted.allowance_digest
      || Number(current.revision) > asserted.revision) {
    return 'allowance_superseded';
  }
  if (current.allowance_profile_id !== asserted.allowance_profile_id
      || Number(current.revision) !== asserted.revision
      || Number(current.status_epoch) !== asserted.status_epoch
      || current.status_head_digest !== asserted.status_head_digest) {
    return 'allowance_not_current';
  }
  return null;
}

/**
 * Reconstruct the exact allowance-status assertion captured when an operation
 * was reserved. Provider entry replays this assertion against the current
 * status head so a later suspension, revocation, or superseding revision takes
 * effect before credentials cross the provider boundary.
 */
function reservedAllowanceStatusAssertion(state, operation): AllowanceStatusAssertion | null {
  if (typeof state?.allowance_profile_id !== 'string'
      || operation?.operation_namespace !== state.allowance_profile_id) {
    return null;
  }
  try {
    return normalizeAllowanceStatusAssertion({
      allowance_profile_id: state.allowance_profile_id,
      allowance_digest: state.allowance_digest,
      revision: Number(operation.allowance_revision),
      status_epoch: Number(operation.allowance_status_epoch),
      status_head_digest: operation.allowance_status_head_digest,
    });
  } catch {
    return null;
  }
}

function exactAllowanceStatus(current, next: AdvanceAllowanceStatusOptions) {
  return current.allowance_profile_id === next.allowance_profile_id
    && current.allowance_digest === next.allowance_digest
    && Number(current.revision) === next.revision
    && Number(current.status_epoch) === next.status_epoch
    && current.status_head_digest === next.status_head_digest
    && current.status === next.status;
}

function allowanceStatusAdvanceConflict(current, next: AdvanceAllowanceStatusOptions) {
  return Number(current.status_epoch) !== next.expected_status_epoch
    || current.status_head_digest !== next.expected_status_head_digest
    || next.status_epoch <= Number(current.status_epoch)
    || next.status_head_digest === current.status_head_digest
    || next.revision < Number(current.revision)
    || next.revision > Number(current.revision) + 1
    || (next.revision === Number(current.revision)
      && next.allowance_digest !== current.allowance_digest)
    || (next.revision > Number(current.revision)
      && next.allowance_digest === current.allowance_digest);
}

/** Digest the exact immutable action snapshot exercised under a capability. */
export function capabilityActionDigest(action) {
  return `sha256:${sha256Hex(Buffer.from(canonicalize(action), 'utf8'))}`;
}

/**
 * Derive the namespace-level duplicate-action fence for a resolved CAID.
 * This domain is intentionally separate from the exact v1 action digest: CAID
 * scope may join wrapper-distinct exact actions without changing what either
 * action was or what capabilityActionDigest means.
 */
function capabilityCaidActionFenceDigest(caid: string) {
  return `sha256:${sha256Hex(Buffer.from(canonicalize({
    profile: CAPABILITY_ACTION_FENCE_PROFILE,
    kind: 'caid',
    caid,
  }), 'utf8'))}`;
}

function normalizeCapabilityScope(scope): any {
  if (!isRecord(scope) || ![
    CAPABILITY_SCOPE_PROFILE,
    CAPABILITY_CAID_SCOPE_PROFILE,
    CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
  ].includes(scope.profile)) {
    throw new TypeError(`capability scope.profile must be ${CAPABILITY_SCOPE_PROFILE}, ${CAPABILITY_CAID_SCOPE_PROFILE}, or ${CAPABILITY_ALLOWANCE_SCOPE_PROFILE}`);
  }
  if (scope.profile === CAPABILITY_ALLOWANCE_SCOPE_PROFILE) {
    const expected = ['operation_id_field', 'profile', 'profile_digest', 'profile_id'];
    const actual = Object.keys(scope).sort();
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
      throw new TypeError('capability allowance scope is not closed');
    }
    if (typeof scope.profile_id !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/.test(scope.profile_id)) {
      throw new TypeError('capability scope.profile_id must be a bounded identifier');
    }
    if (typeof scope.profile_digest !== 'string' || !ACTION_DIGEST_RE.test(scope.profile_digest)) {
      throw new TypeError('capability scope.profile_digest must be a sha256 digest');
    }
    if (typeof scope.operation_id_field !== 'string'
        || !/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(scope.operation_id_field)) {
      throw new TypeError('capability scope.operation_id_field must name a closed action field');
    }
    return {
      profile: scope.profile,
      profile_id: scope.profile_id,
      profile_digest: scope.profile_digest,
      operation_id_field: scope.operation_id_field,
    };
  }
  const memberField = scope.profile === CAPABILITY_CAID_SCOPE_PROFILE ? 'caids' : 'action_digests';
  const expected = [memberField, 'operation_id_field', 'profile'].sort();
  const actual = Object.keys(scope).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError('capability scope is not closed');
  }
  const members = scope[memberField];
  const memberPattern = scope.profile === CAPABILITY_CAID_SCOPE_PROFILE ? CAID_RE : ACTION_DIGEST_RE;
  if (!Array.isArray(members)
      || members.length < 1
      || members.length > MAX_SCOPE_ACTIONS
      || members.some((member) => typeof member !== 'string' || !memberPattern.test(member))) {
    throw new TypeError(`capability scope.${memberField} must be a bounded non-empty array of canonical identifiers`);
  }
  if (new Set(members).size !== members.length) {
    throw new TypeError(`capability scope.${memberField} must not contain duplicates`);
  }
  if (typeof scope.operation_id_field !== 'string'
      || !/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(scope.operation_id_field)) {
    throw new TypeError('capability scope.operation_id_field must name a closed action field');
  }
  return {
    profile: scope.profile,
    [memberField]: [...members].sort(),
    operation_id_field: scope.operation_id_field,
  };
}

function valueAtPath(action, path) {
  let value = action;
  for (const segment of path.split('.')) {
    if (!isRecord(value) || !Object.hasOwn(value, segment)) return undefined;
    value = value[segment];
  }
  return value;
}

/**
 * @param {object} capability
 * @param {object} action
 * @param {string} operationId
 * @param {object} [options]
 * @param {Function|null} [options.resolveCaid]
 * @param {Function|null} [options.verifyActionProfile]
 */
export function verifyCapabilityScope(capability, action, operationId, {
  resolveCaid = null,
  verifyActionProfile = null,
}: {
  resolveCaid?: ((action: any) => any) | null;
  verifyActionProfile?: ((action: any, profile: { profile_id: string; profile_digest: string }) => any) | null;
} = {}) {
  try {
    const scope = normalizeCapabilityScope(capability?.scope);
    const actionDigest = capabilityActionDigest(action);
    let actionFenceDigest = actionDigest;
    let caid: string | null = null;
    if (scope.profile === CAPABILITY_ALLOWANCE_SCOPE_PROFILE) {
      if (typeof verifyActionProfile !== 'function') {
        return {
          ok: false,
          reason: 'capability_action_profile_verifier_required',
          action_digest: actionDigest,
        };
      }
      const profile = {
        profile_id: scope.profile_id,
        profile_digest: scope.profile_digest,
      };
      const result = verifyActionProfile(structuredClone(action), profile);
      if (result !== true && result?.ok !== true) {
        return {
          ok: false,
          reason: result?.reason || 'capability_action_profile_rejected',
          action_digest: actionDigest,
        };
      }
      if (!isRecord(result) || !Object.hasOwn(result, 'action_fence_digest')) {
        return {
          ok: false,
          reason: 'capability_action_fence_digest_required',
          action_digest: actionDigest,
        };
      }
      try {
        actionFenceDigest = validateActionDigest(result.action_fence_digest);
      } catch {
        return {
          ok: false,
          reason: 'capability_action_fence_digest_invalid',
          action_digest: actionDigest,
        };
      }
    } else if (scope.profile === CAPABILITY_CAID_SCOPE_PROFILE) {
      if (typeof resolveCaid !== 'function') {
        return { ok: false, reason: 'capability_caid_resolver_required', action_digest: actionDigest };
      }
      const resolved = resolveCaid(structuredClone(action));
      // Object-shaped resolvers carry an explicit decision. Never recover a
      // CAID from a failed decision merely because the object also contains a
      // syntactically valid `caid` field.
      caid = typeof resolved === 'string'
        ? resolved
        : isRecord(resolved) && resolved.ok === true
          ? resolved.caid
          : null;
      if (typeof caid !== 'string' || !CAID_RE.test(caid)) {
        return { ok: false, reason: 'capability_caid_resolution_failed', action_digest: actionDigest };
      }
      if (!scope.caids.includes(caid)) {
        return { ok: false, reason: 'capability_action_out_of_scope', action_digest: actionDigest, caid };
      }
      actionFenceDigest = capabilityCaidActionFenceDigest(caid);
    } else if (!scope.action_digests.includes(actionDigest)) {
      return { ok: false, reason: 'capability_action_out_of_scope', action_digest: actionDigest };
    }
    if (valueAtPath(action, scope.operation_id_field) !== operationId) {
      return {
        ok: false,
        reason: 'capability_operation_binding_failed',
        action_digest: actionDigest,
        operation_id_field: scope.operation_id_field,
      };
    }
    return {
      ok: true,
      action_digest: actionDigest,
      action_fence_digest: actionFenceDigest,
      ...(caid ? { caid } : {}),
      ...(scope.profile === CAPABILITY_ALLOWANCE_SCOPE_PROFILE
        ? { operation_namespace: scope.profile_id }
        : {}),
      operation_id_field: scope.operation_id_field,
    };
  } catch (error) {
    return { ok: false, reason: 'capability_scope_invalid', detail: (error as Error)?.message || 'invalid capability scope' };
  }
}

function validateCapabilityId(capabilityId) {
  if (typeof capabilityId !== 'string' || capabilityId.length === 0 || Buffer.byteLength(capabilityId, 'utf8') > MAX_OPERATION_ID_BYTES) {
    throw new TypeError('capability id must be a short non-empty string');
  }
  return capabilityId;
}

function validateExpiry(expiry) {
  const value = typeof expiry === 'number' ? new Date(expiry).toISOString() : expiry;
  const parsed = Date.parse(value);
  if (typeof value !== 'string' || !Number.isFinite(parsed)) throw new TypeError('capability expiry must be an ISO-8601 timestamp');
  return new Date(parsed).toISOString();
}

function normalizeRevocationMode(value: unknown): CapabilityRevocationMode {
  if (value !== 'direct' && value !== 'cascade') {
    throw new TypeError('capability revocation_mode must be direct or cascade');
  }
  return value;
}

function validateThreshold(threshold = { m: 1, n: 1 }) {
  if (!isRecord(threshold)
      || !Number.isSafeInteger(threshold.m) || !Number.isSafeInteger(threshold.n)
      || threshold.m < 1 || threshold.n < threshold.m || threshold.n > 255) {
    throw new TypeError('capability threshold must satisfy 1 <= m <= n <= 255');
  }
  return { m: threshold.m, n: threshold.n };
}

function validateBaseReceipt(baseReceipt) {
  if (!isRecord(baseReceipt) || baseReceipt['@version'] !== 'EP-RECEIPT-v1' || !isRecord(baseReceipt.payload)) {
    throw new TypeError('capability base receipt must be an EP-RECEIPT-v1 document');
  }
  if (typeof baseReceipt.payload.receipt_id !== 'string' || baseReceipt.payload.receipt_id.length === 0) {
    throw new TypeError('capability base receipt must carry receipt_id');
  }
  if (!isRecord(baseReceipt.payload.claim) || baseReceipt.payload.claim.capability_only !== true) {
    throw new TypeError('capability base receipt must be signed as capability_only');
  }
  return structuredClone(baseReceipt);
}

export function capabilityBaseReceiptDigest(receipt) {
  return `sha256:${sha256Hex(Buffer.from(canonicalize(receipt), 'utf8'))}`;
}

function capabilityUnsignedBody(receipt, capability) {
  return {
    '@version': CAPABILITY_RECEIPT_VERSION,
    base_receipt_id: receipt.payload.receipt_id,
    base_receipt_digest: capabilityBaseReceiptDigest(receipt),
    capability,
  };
}

function capabilitySignature(capabilityReceipt) {
  const signature = capabilityReceipt?.capability_signature;
  return signature && signature.algorithm === 'Ed25519' && typeof signature.value === 'string' && typeof signature.public_key === 'string'
    ? signature
    : null;
}

function capabilityEnvelopeFingerprint(capabilityReceipt) {
  const signature = capabilitySignature(capabilityReceipt);
  if (!signature) throw new TypeError('capability signature is required for fingerprinting');
  return `sha256:${sha256Hex(Buffer.from(canonicalize({
    '@version': CAPABILITY_RECEIPT_VERSION,
    base_receipt_id: capabilityReceipt.receipt.payload.receipt_id,
    base_receipt_digest: capabilityBaseReceiptDigest(capabilityReceipt.receipt),
    capability: capabilityReceipt.capability,
    issuer_public_key: signature.public_key,
  }), 'utf8'))}`;
}

/**
 * Validate a delegation chain at ingest time.
 *
 * Shape and bounded length are not sufficient: a hand-crafted envelope can
 * carry a cyclic or authority-inflating chain and still be internally
 * consistent. This validator enforces three structural invariants that every
 * chain produced by {@link delegateCapabilityReceipt} satisfies and that no
 * cyclic or forged chain can:
 *
 *   1. Acyclicity. Each delegation is a distinct parent spend, so a
 *      delegation_id never recurs; a capability delegates at most once as a
 *      parent, so a parent_capability_id never recurs. Either repeat is a cycle
 *      in the delegation graph and is rejected. The leaf capability id (when
 *      supplied) may never appear as one of its own ancestors' parents.
 *   2. Monotonic authority. No hop may grant more than the hop that delegated
 *      to it: amounts are non-increasing from root to leaf. This holds
 *      standalone here, independent of the runtime parent reserve guard.
 *
 * Fail-closed: any violation throws and the caller treats the envelope as
 * malformed. Signature and per-entry shape checks are unchanged.
 */
function assertDelegationChain(chain, capabilityId?: string) {
  if (chain === undefined) return [];
  if (!Array.isArray(chain) || chain.length > MAX_DELEGATES) throw new TypeError('delegation_chain must be a bounded array');
  const seenDelegationIds = new Set();
  const seenParentIds = new Set();
  let previousAmount = null;
  return chain.map((entry) => {
    if (!isRecord(entry)
        || typeof entry.delegation_id !== 'string'
        || typeof entry.parent_capability_id !== 'string'
        || typeof entry.delegate_id !== 'string'
        || !Number.isSafeInteger(entry.amount)
        || entry.amount < 0
        || typeof entry.currency !== 'string'
        || typeof entry.issued_at !== 'string') {
      throw new TypeError('delegation_chain contains an invalid signed entry');
    }
    if (seenDelegationIds.has(entry.delegation_id)) throw new TypeError('delegation_chain repeats a delegation_id (cyclic or forged chain)');
    if (seenParentIds.has(entry.parent_capability_id)) throw new TypeError('delegation_chain repeats a parent_capability_id (cyclic delegation)');
    if (capabilityId !== undefined && entry.parent_capability_id === capabilityId) throw new TypeError('delegation_chain references the leaf capability as a parent (broken delegation link)');
    if (previousAmount !== null && entry.amount > previousAmount) throw new TypeError('delegation_chain grants increasing authority (non-monotonic amount)');
    seenDelegationIds.add(entry.delegation_id);
    seenParentIds.add(entry.parent_capability_id);
    previousAmount = entry.amount;
    return structuredClone(entry);
  });
}

function assertCapabilityShape(capability) {
  if (!isRecord(capability) || capability.version !== CAPABILITY_STATE_VERSION) throw new TypeError('invalid capability state version');
  validateCapabilityId(capability.id);
  if (typeof capability.secret_hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(capability.secret_hash)) throw new TypeError('capability secret_hash is invalid');
  if (!isRecord(capability.budget)) throw new TypeError('capability budget is required');
  validateAmount(capability.budget.amount, 'budget.amount');
  validateCurrency(capability.budget.currency);
  validateExpiry(capability.expiry);
  validateThreshold(capability.threshold);
  normalizeRevocationMode(capability.revocation_mode);
  normalizeCapabilityScope(capability.scope);
  assertDelegationChain(capability.delegation_chain, capability.id);
  if (capability.consumed !== 0) throw new TypeError('capability consumed is issuer-initialized and must be zero');
  return true;
}

function verifyTrustedIssuer(publicKey, trustedIssuerKeys) {
  return Array.isArray(trustedIssuerKeys)
    && trustedIssuerKeys.length > 0
    && trustedIssuerKeys.includes(publicKey);
}

/**
 * Mint a signed capability envelope. The issuer must sign the capability
 * metadata; a holder cannot enlarge the budget by editing a bearer object.
 * For m-of-n > 1, the raw secret is not returned; distribute the returned
 * shares instead.
 *
 * @param {object} baseReceipt EP-RECEIPT-v1 document
 * @param {object} [options]
 * @param {KeyMaterial} [options.issuerPrivateKey]
 * @param {CapabilityBudget} [options.budget]
 * @param {string|number} [options.expiry]
 * @param {{m:number,n:number}} [options.threshold]
 * @param {'direct'|'cascade'} [options.revocationMode]
 * @param {object} [options.scope]
 * @param {any[]} [options.delegationChain]
 * @param {string} [options.capabilityId]
 * @param {string} [options.operationNamespace]
 * @param {Buffer|string} [options.secret]
 */
export function mintCapabilityReceipt(baseReceipt, {
  issuerPrivateKey,
  budget,
  expiry,
  threshold = { m: 1, n: 1 },
  revocationMode,
  scope,
  delegationChain = [],
  capabilityId = randomUUID(),
  secret = randomBytes(HASH_BYTES),
}: {
  issuerPrivateKey?: KeyMaterial;
  budget?: CapabilityBudget;
  expiry?: string | number;
  threshold?: { m: number; n: number };
  revocationMode?: CapabilityRevocationMode;
  scope?: Record<string, any>;
  delegationChain?: any[];
  capabilityId?: string;
  secret?: Buffer | string;
} = {}) {
  const receipt = validateBaseReceipt(baseReceipt);
  if (!issuerPrivateKey) throw new TypeError('mintCapabilityReceipt requires issuerPrivateKey');
  if (!isRecord(budget)) throw new TypeError('capability budget is required');
  const normalizedThreshold = validateThreshold(threshold);
  const normalizedSecret = digestSecret(secret);
  const publicKey = publicKeyB64u(issuerPrivateKey);
  const capability = {
    version: CAPABILITY_STATE_VERSION,
    id: validateCapabilityId(String(capabilityId)),
    secret_hash: normalizedSecret.hash,
    budget: { amount: validateAmount(budget.amount, 'budget.amount'), currency: validateCurrency(budget.currency) },
    consumed: 0,
    threshold: normalizedThreshold,
    revocation_mode: normalizeRevocationMode(revocationMode),
    scope: normalizeCapabilityScope(scope),
    delegation_chain: assertDelegationChain(delegationChain),
    expiry: validateExpiry(expiry),
  };
  assertCapabilityShape(capability);
  const value = sign(null, Buffer.from(canonicalize(capabilityUnsignedBody(receipt, capability)), 'utf8'), keyBytes(issuerPrivateKey, 'issuerPrivateKey')).toString('base64url');
  const capabilityReceipt = {
    '@version': CAPABILITY_RECEIPT_VERSION,
    receipt,
    capability,
    capability_signature: { algorithm: 'Ed25519', public_key: publicKey, value },
  };
  const shares = normalizedThreshold.m === 1 && normalizedThreshold.n === 1
    ? null
    : splitCapabilitySecret(normalizedSecret.bytes, normalizedThreshold);
  return Object.freeze({
    capabilityReceipt: Object.freeze(capabilityReceipt),
    secret: shares ? null : Buffer.from(normalizedSecret.bytes),
    shares,
  });
}

/**
 * Verify the issuer signature and immutable capability metadata.
 * @param {object} capabilityReceipt
 * @param {object} [options]
 * @param {string[]} [options.trustedIssuerKeys]
 * @param {boolean} [options.allowUntrustedIssuer] Deprecated and ignored. A
 * caller must pin at least one issuer key; self-signed authority is refused.
 */
export function verifyCapabilityReceipt(capabilityReceipt, {
  trustedIssuerKeys = [],
  allowUntrustedIssuer: _allowUntrustedIssuer = false,
}: { trustedIssuerKeys?: string[]; allowUntrustedIssuer?: boolean } = {}) {
  try {
    if (!isRecord(capabilityReceipt) || capabilityReceipt['@version'] !== CAPABILITY_RECEIPT_VERSION) return { ok: false, reason: 'malformed_capability_receipt' };
    const receipt = validateBaseReceipt(capabilityReceipt.receipt);
    assertCapabilityShape(capabilityReceipt.capability);
    const signature = capabilitySignature(capabilityReceipt);
    if (!signature || !verifyTrustedIssuer(signature.public_key, trustedIssuerKeys)) {
      return { ok: false, reason: 'capability_issuer_not_trusted' };
    }
    const ok = verify(
      null,
      Buffer.from(canonicalize(capabilityUnsignedBody(receipt, capabilityReceipt.capability)), 'utf8'),
      createPublicKey({ key: Buffer.from(signature.public_key, 'base64url'), format: 'der', type: 'spki' }),
      Buffer.from(signature.value, 'base64url'),
    );
    return ok ? { ok: true, receipt, capability: capabilityReceipt.capability, issuer_public_key: signature.public_key } : { ok: false, reason: 'capability_signature_invalid' };
  } catch (error) {
    return { ok: false, reason: 'capability_malformed', detail: (error as Error)?.message || 'invalid capability' };
  }
}

/**
 * Internal integrity-only check used while a store registers an envelope that
 * has already crossed the caller's trust boundary. Deriving this temporary pin
 * from the envelope proves only self-consistency. It must never be exported or
 * treated as issuer authority.
 */
function verifyCapabilityReceiptIntegrity(capabilityReceipt) {
  const signature = capabilitySignature(capabilityReceipt);
  if (!signature) return { ok: false, reason: 'malformed_capability_receipt' };
  return verifyCapabilityReceipt(capabilityReceipt, {
    trustedIssuerKeys: [signature.public_key],
  });
}

function fieldToBytes(value) {
  const bytes = Buffer.alloc(SHARE_BYTES);
  let remaining = BigInt(value);
  for (let i = SHARE_BYTES - 1; i >= 0; i -= 1) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function bytesToField(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value % FIELD;
}

function mod(value) {
  const result = value % FIELD;
  return result < 0n ? result + FIELD : result;
}

function modInverse(value) {
  let a = mod(value);
  let b = FIELD;
  let x = 1n;
  let y = 0n;
  while (b !== 0n) {
    const quotient = a / b;
    [a, b] = [b, a - quotient * b];
    [x, y] = [y, x - quotient * y];
  }
  if (a !== 1n) throw new Error('capability field inverse does not exist');
  return mod(x);
}

function randomField(randomBytesFn) {
  while (true) {
    const bytes = Buffer.from(randomBytesFn(SHARE_BYTES));
    if (bytes.length !== SHARE_BYTES) throw new TypeError('randomBytesFn returned the wrong length');
    // 66 bytes carry 528 bits; clear the seven unused high bits so the
    // candidate is sampled directly from the 521-bit field instead of using
    // a biased modulo reduction.
    bytes[0] &= 0x01;
    const value = bytesToField(bytes);
    if (value !== 0n && value < FIELD) return value;
  }
}

/** Split the 32-byte capability secret using Shamir's polynomial scheme. */
export function splitCapabilitySecret(secret, threshold, { randomBytesFn = randomBytes } = {}) {
  const normalized = digestSecret(secret);
  const { m, n } = validateThreshold(threshold);
  const coefficients = [bytesToField(normalized.bytes)];
  for (let i = 1; i < m; i += 1) coefficients.push(randomField(randomBytesFn));
  const shares: string[] = [];
  for (let x = 1; x <= n; x += 1) {
    let y = 0n;
    let power = 1n;
    for (const coefficient of coefficients) {
      y = mod(y + coefficient * power);
      power = mod(power * BigInt(x));
    }
    shares.push(`ep-share-v1.${x}.${base64u(fieldToBytes(y))}`);
  }
  return shares;
}

function parseShare(share) {
  if (typeof share !== 'string') throw new TypeError('capability share must be a string');
  const parts = share.split('.');
  if (parts.length !== 3 || parts[0] !== 'ep-share-v1') throw new TypeError('invalid capability share version');
  const x = Number(parts[1]);
  if (!Number.isSafeInteger(x) || x < 1 || x > 255) throw new TypeError('capability share index is invalid');
  const y = decodeBase64u(parts[2], 'capability share');
  if (y.length !== SHARE_BYTES) throw new TypeError('capability share scalar has the wrong length');
  return { x, y: bytesToField(y) };
}

/** Reconstruct a capability secret from at least m unique shares. */
export function reconstructCapabilitySecret(shares, threshold) {
  const { m, n } = validateThreshold(threshold);
  if (!Array.isArray(shares) || shares.length < m || shares.length > n) throw new TypeError('insufficient capability shares');
  const parsed = shares.map(parseShare);
  if (new Set(parsed.map((share) => share.x)).size !== parsed.length) throw new TypeError('duplicate capability share index');
  let secret = 0n;
  for (const current of parsed) {
    let numerator = 1n;
    let denominator = 1n;
    for (const other of parsed) {
      if (current.x === other.x) continue;
      numerator = mod(numerator * BigInt(-other.x));
      denominator = mod(denominator * BigInt(current.x - other.x));
    }
    secret = mod(secret + current.y * numerator * modInverse(denominator));
  }
  return fieldToBytes(secret).subarray(SHARE_BYTES - HASH_BYTES);
}

function capabilityStateFromEnvelope(capabilityReceipt) {
  const c = capabilityReceipt.capability;
  const allowanceScope = c.scope?.profile === CAPABILITY_ALLOWANCE_SCOPE_PROFILE
    ? c.scope
    : null;
  return {
    capability_id: c.id,
    capability_fingerprint: capabilityEnvelopeFingerprint(capabilityReceipt),
    budget_amount: c.budget.amount,
    currency: c.budget.currency,
    expires_at: Date.parse(c.expiry),
    revocation_mode: normalizeRevocationMode(c.revocation_mode),
    parent_capability_id: c.delegation_chain.length > 0
      ? c.delegation_chain.at(-1).parent_capability_id
      : null,
    allowance_profile_id: allowanceScope?.profile_id ?? null,
    allowance_digest: allowanceScope?.profile_digest ?? null,
  };
}

function capabilityLineageRefusal(
  states: Map<string, Record<string, any>>,
  capabilityId: string,
) {
  const seen = new Set<string>();
  let currentId: string | null = capabilityId;
  let depth = 0;
  while (currentId !== null) {
    if (seen.has(currentId) || depth > MAX_DELEGATES) {
      return 'capability_ancestor_status_unavailable';
    }
    seen.add(currentId);
    const state = states.get(currentId);
    if (!state) return 'capability_ancestor_status_unavailable';
    if (Object.hasOwn(state, 'revocation_state_ready')
        && state.revocation_state_ready !== true) {
      return 'capability_ancestor_status_unavailable';
    }
    try {
      normalizeRevocationMode(state.revocation_mode);
    } catch {
      return 'capability_revocation_mode_invalid';
    }
    if (state.revoked_at !== null && state.revoked_at !== undefined) {
      if (currentId === capabilityId) return 'capability_revoked';
      if (state.revocation_mode === 'cascade') return 'capability_ancestor_revoked';
    }
    currentId = state.parent_capability_id ?? null;
    depth += 1;
  }
  return null;
}

async function postgresCapabilityLineageRefusal(
  query: Function,
  leafState: Record<string, any>,
) {
  const states = new Map<string, Record<string, any>>();
  states.set(leafState.capability_id, leafState);
  const seen = new Set([leafState.capability_id]);
  let parentId = leafState.parent_capability_id ?? null;
  let depth = 0;
  while (parentId !== null) {
    if (seen.has(parentId) || depth >= MAX_DELEGATES) {
      return 'capability_ancestor_status_unavailable';
    }
    seen.add(parentId);
    const result = await query(CAPABILITY_SQL.readState, [parentId]);
    const parent = result?.rows?.[0];
    if (!parent) return 'capability_ancestor_status_unavailable';
    states.set(parentId, parent);
    parentId = parent.parent_capability_id ?? null;
    depth += 1;
  }
  return capabilityLineageRefusal(states, leafState.capability_id);
}

/**
 * Production capability-store contract. Methods alone are insufficient: an
 * adapter must explicitly assert durable custody and reconciliation support.
 */
export function isSecureCapabilityStore(store) {
  if (!store || typeof store !== 'object') return false;
  return store.durable === true
    && store.reconciliationCapable === true
    && typeof store.registerCapability === 'function'
    && typeof store.reserveSpend === 'function'
    && typeof store.beginProviderEntry === 'function'
    && typeof store.recoverPreEntrySpend === 'function'
    && typeof store.commitSpend === 'function'
    && typeof store.reconcileSpend === 'function'
    && typeof store.revokeCapability === 'function'
    && store.revocationInheritanceCapable === true;
}

/**
 * An in-memory atomic reference store. It is intentionally marked non-durable
 * and is suitable only for tests; production callers must use an implementation
 * backed by a transactional database or equivalent linearizable store.
 */
export function createMemoryCapabilityStore({
  providerEntryTimeoutMs = DEFAULT_PROVIDER_ENTRY_TIMEOUT_MS,
  verifyControlTransition,
}: {
  providerEntryTimeoutMs?: number;
  verifyControlTransition?: VerifyControlTransition;
} = {}) {
  const entryTimeoutMs = validateProviderEntryTimeoutMs(providerEntryTimeoutMs);
  const stateDomainDigest = capabilityStateDomainDigest();
  const states = new Map();
  const operations = new Map();
  const allowanceStatuses = new Map();
  const controlDomains = new Map<string, Record<string, any>>();
  const controlDomainEvents = new Map<string, Record<string, any>>();
  const operationKey = (operationNamespace, operationId) =>
    JSON.stringify([operationNamespace, operationId]);
  const actionKey = (operationNamespace, actionFenceDigest) =>
    JSON.stringify([operationNamespace, actionFenceDigest]);
  // actionKey -> operationKey. A HINT, never the source of truth. Every read
  // revalidates the operation it points at, so a holder that has since been
  // released simply fails the status test and the entry is overwritten. That is
  // why nothing here has to be deleted on release: a stale hint self-heals, and
  // an index maintained at every transition would not.
  const actionHolders = new Map();
  async function transitionMemoryControlDomain(
    eventType: 'freeze' | 'restore',
    options: ControlTransitionOptions,
  ) {
    try {
      validateControlDomainId(options.controlDomainId);
      validateOperationId(options.operationId);
      validateActionDigest(options.actionDigest);
    } catch {
      return { ok: false, reason: 'control_transition_refused' };
    }
    const controlDomainId = options.controlDomainId as string;
    const operationId = options.operationId as string;
    const actionDigest = options.actionDigest as string;
    const verified = await verifyControlTransitionRequest(
      verifyControlTransition,
      eventType,
      options,
    );
    if (!verified.authenticated) {
      return { ok: false, reason: 'control_transition_refused' };
    }
    const existing = controlDomainEvents.get(operationId);
    if (existing) {
      const matches = existing.event_type === eventType
        && existing.control_domain_id === controlDomainId
        && existing.action_digest === actionDigest
        && existing.authority_instance_digest === verified.authority_instance_digest;
      return matches
        ? { ...existing.result, idempotent: true }
        : { ok: false, reason: 'control_transition_refused' };
    }
    if (!verified.authorized) {
      return { ok: false, reason: 'control_transition_refused' };
    }
    const domain = controlDomains.get(controlDomainId);
    if (!domain) return { ok: false, reason: 'control_transition_refused' };
    const at = nowMs(options.now ?? Date.now);
    if (eventType === 'freeze' && domain.status === 'frozen') {
      const result = {
        ok: true,
        idempotent: false,
        status: 'already_frozen',
        control_domain_id: domain.control_domain_id,
        epoch: domain.epoch,
      };
      controlDomainEvents.set(operationId, {
        operation_id: operationId,
        control_domain_id: controlDomainId,
        event_type: eventType,
        epoch_at_event: domain.epoch,
        action_digest: options.actionDigest,
        authority_instance_digest: verified.authority_instance_digest,
        committed_at: at,
        result,
      });
      return result;
    }
    if (eventType === 'restore' && domain.status !== 'frozen') {
      return { ok: false, reason: 'control_transition_refused' };
    }
    domain.status = eventType === 'freeze' ? 'frozen' : 'active';
    domain.epoch += 1;
    domain.frozen_at = eventType === 'freeze' ? at : null;
    domain.frozen_by_digest = eventType === 'freeze'
      ? verified.authority_instance_digest
      : null;
    domain.updated_at = at;
    const result = {
      ok: true,
      idempotent: false,
      status: domain.status,
      control_domain_id: domain.control_domain_id,
      epoch: domain.epoch,
    };
    controlDomainEvents.set(operationId, {
      operation_id: operationId,
      control_domain_id: controlDomainId,
      event_type: eventType,
      epoch_at_event: domain.epoch,
      action_digest: options.actionDigest,
      authority_instance_digest: verified.authority_instance_digest,
      committed_at: at,
      result,
    });
    return result;
  }
  return {
    durable: false,
    atomicStateDomainCapable: true,
    stateDomainDigest,
    reconciliationCapable: true,
    revocationInheritanceCapable: true,
    allowanceCurrentnessCapable: true,
    providerEntryDispositionCapable: true,
    controlDomainCapable: true,
    async registerControlDomain({
      controlDomainId,
      now = Date.now,
    }: { controlDomainId?: string; now?: number | (() => number) } = {}) {
      validateControlDomainId(controlDomainId);
      const validatedControlDomainId = controlDomainId as string;
      const existing = controlDomains.get(validatedControlDomainId);
      if (existing) {
        return {
          ok: true,
          idempotent: true,
          control_domain_id: validatedControlDomainId,
          status: existing.status,
          epoch: existing.epoch,
        };
      }
      controlDomains.set(validatedControlDomainId, {
        control_domain_id: validatedControlDomainId,
        status: 'active',
        epoch: 1,
        frozen_at: null,
        frozen_by_digest: null,
        updated_at: nowMs(now),
      });
      return {
        ok: true,
        idempotent: false,
        control_domain_id: validatedControlDomainId,
        status: 'active',
        epoch: 1,
      };
    },
    async freezeControlDomain(options: ControlTransitionOptions = {}) {
      return transitionMemoryControlDomain('freeze', options);
    },
    async restoreControlDomain(options: ControlTransitionOptions = {}) {
      return transitionMemoryControlDomain('restore', options);
    },
    registerCapability(capabilityReceipt) {
      const verified = verifyCapabilityReceiptIntegrity(capabilityReceipt);
      if (!verified.ok) return false;
      const state = capabilityStateFromEnvelope(capabilityReceipt);
      const existing = states.get(state.capability_id);
      if (existing) {
        return existing.capability_fingerprint === state.capability_fingerprint
          && existing.budget_amount === state.budget_amount
          && existing.currency === state.currency
          && existing.expires_at === state.expires_at
          && existing.revocation_mode === state.revocation_mode
          && existing.parent_capability_id === state.parent_capability_id
          && existing.allowance_profile_id === state.allowance_profile_id
          && existing.allowance_digest === state.allowance_digest;
      }
      if (state.parent_capability_id !== null) {
        const parentRefusal = capabilityLineageRefusal(states, state.parent_capability_id);
        if (parentRefusal) return false;
      }
      states.set(state.capability_id, {
        ...state,
        consumed_amount: 0,
        reserved_amount: 0,
        revoked_at: null,
      });
      return true;
    },
    async revokeCapability({ capabilityId, capabilityFingerprint, now = Date.now }: RevokeCapabilityOptions = {}) {
      try {
        validateCapabilityId(capabilityId);
      } catch {
        return { ok: false, reason: 'capability_revocation_target_invalid' };
      }
      const state = states.get(capabilityId);
      if (!state) return { ok: false, reason: 'capability_not_registered' };
      if (state.capability_fingerprint !== capabilityFingerprint) {
        return { ok: false, reason: 'capability_envelope_mismatch' };
      }
      try {
        normalizeRevocationMode(state.revocation_mode);
      } catch {
        return { ok: false, reason: 'capability_revocation_mode_invalid' };
      }
      if (state.revoked_at !== null) {
        return {
          ok: true,
          idempotent: true,
          capability_id: capabilityId,
          revocation_mode: state.revocation_mode,
          revoked_at: state.revoked_at,
        };
      }
      state.revoked_at = nowMs(now);
      return {
        ok: true,
        idempotent: false,
        capability_id: capabilityId,
        revocation_mode: state.revocation_mode,
        revoked_at: state.revoked_at,
      };
    },
    advanceAllowanceStatus(options: AdvanceAllowanceStatusOptions) {
      const next = normalizeAllowanceStatusAdvance(options);
      const current = allowanceStatuses.get(next.allowance_profile_id);
      if (current && exactAllowanceStatus(current, next)) {
        return { ok: true, idempotent: true };
      }
      if (!current) {
        if (next.expected_status_epoch !== null || next.expected_status_head_digest !== null) {
          return { ok: false, reason: 'allowance_status_head_conflict' };
        }
      } else if (allowanceStatusAdvanceConflict(current, next)) {
        return { ok: false, reason: 'allowance_status_head_conflict' };
      }
      allowanceStatuses.set(next.allowance_profile_id, {
        allowance_profile_id: next.allowance_profile_id,
        allowance_digest: next.allowance_digest,
        revision: next.revision,
        status_epoch: next.status_epoch,
        status_head_digest: next.status_head_digest,
        status: next.status,
      });
      return { ok: true, idempotent: false };
    },
    async reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace = capabilityId, operationId, actionDigest, actionFenceDigest = actionDigest, amount, currency, controlDomainId, allowanceStatus, now = Date.now }: ReserveSpendOptions) {
      validateOperationId(operationId);
      validateOperationNamespace(operationNamespace);
      validateActionDigest(actionDigest);
      validateActionDigest(actionFenceDigest);
      validateSpendAmount(amount);
      validateCurrency(currency);
      let controlDomain: Record<string, any> | null = null;
      if (controlDomainId !== undefined) {
        validateControlDomainId(controlDomainId);
        controlDomain = controlDomains.get(controlDomainId) ?? null;
        if (!controlDomain) return { ok: false, reason: 'capability_control_domain_not_found' };
        if (controlDomain.status !== 'active') {
          return { ok: false, reason: 'capability_control_domain_frozen' };
        }
      }
      const state = states.get(capabilityId);
      if (!state) return { ok: false, reason: 'capability_not_registered' };
      if (state.capability_fingerprint !== capabilityFingerprint) return { ok: false, reason: 'capability_envelope_mismatch' };
      const lineageRefusal = capabilityLineageRefusal(states, capabilityId);
      if (lineageRefusal) return { ok: false, reason: lineageRefusal };
      if (state.allowance_profile_id !== null && operationNamespace === state.allowance_profile_id) {
        let asserted;
        try {
          asserted = normalizeAllowanceStatusAssertion(allowanceStatus);
        } catch {
          return { ok: false, reason: 'allowance_status_assertion_required' };
        }
        if (asserted.allowance_profile_id !== state.allowance_profile_id
            || asserted.allowance_digest !== state.allowance_digest) {
          return { ok: false, reason: 'allowance_status_binding_mismatch' };
        }
      const current = allowanceStatuses.get(asserted.allowance_profile_id);
      if (!current) return { ok: false, reason: 'allowance_status_not_initialized' };
      const refusal = allowanceStatusRefusal(current, asserted);
        if (refusal) return { ok: false, reason: refusal };
      } else if (allowanceStatus !== undefined) {
        return { ok: false, reason: 'allowance_status_not_applicable' };
      }
      const key = operationKey(operationNamespace, operationId);
      const existing = operations.get(key);
      if (existing) {
        return {
          ok: false,
          reason: existingOperationReason(existing.status),
          action_digest: actionDigest,
          action_fence_digest: actionFenceDigest,
          holding_operation_id: existing.operation_id,
        };
      }
      // Fence on the ACTION, not only on the token. A caller that retries
      // request-for-approval gets a fresh operation id, and both requests carry
      // the same material-action fence. Keying only on the id let both reserve,
      // so the same merge, payout, or delete could be authorized twice under
      // two ids.
      // Budget is not material-action identity: two wrappers can both reserve
      // positive occurrence units while still referring to one merge, payout,
      // or delete. The separate fence closes that replay class.
      const held = actionHolders.get(actionKey(operationNamespace, actionFenceDigest));
      const holder = held === undefined ? undefined : operations.get(held);
      if (holder && ACTION_HOLDING_STATUSES.includes(holder.status)) {
        return {
          ok: false,
          reason: actionHeldReason(holder.status),
          action_digest: actionDigest,
          action_fence_digest: actionFenceDigest,
          holding_operation_id: holder.operation_id,
        };
      }
      const at = nowMs(now);
      if (at >= state.expires_at) return { ok: false, reason: 'capability_expired' };
      if (currency !== state.currency) return { ok: false, reason: 'currency_mismatch' };
      if (state.consumed_amount + state.reserved_amount + amount > state.budget_amount) return { ok: false, reason: 'budget_exceeded' };
      const reservationToken = randomUUID();
      const entryDeadlineAt = entryDeadline(at, state.expires_at, entryTimeoutMs);
      operations.set(key, {
        operation_namespace: operationNamespace,
        operation_id: operationId,
        capability_id: capabilityId,
        action_digest: actionDigest,
        action_fence_digest: actionFenceDigest,
        amount,
        currency,
        status: 'reserved',
        reservation_token: reservationToken,
        reserved_at: at,
        entry_deadline_at: entryDeadlineAt,
        provider_entry_at: null,
        allowance_revision: allowanceStatus?.revision ?? null,
        allowance_status_epoch: allowanceStatus?.status_epoch ?? null,
        allowance_status_head_digest: allowanceStatus?.status_head_digest ?? null,
        control_domain_id: controlDomain?.control_domain_id ?? null,
        reserved_control_epoch: controlDomain?.epoch ?? null,
      });
      state.reserved_amount += amount;
      actionHolders.set(actionKey(operationNamespace, actionFenceDigest), key);
      return {
        ok: true,
        operation_id: operationId,
        action_digest: actionDigest,
        action_fence_digest: actionFenceDigest,
        reservation_token: reservationToken,
        entry_deadline_at: entryDeadlineAt,
        control_domain_id: controlDomain?.control_domain_id ?? null,
        reserved_control_epoch: controlDomain?.epoch ?? null,
        remaining: state.budget_amount - state.consumed_amount - state.reserved_amount,
      };
    },
    async beginProviderEntry({ capabilityId, operationNamespace = capabilityId, operationId, reservationToken, controlDomainId, now = Date.now }: BeginProviderEntryOptions = {}) {
      validateOperationId(operationId);
      validateOperationNamespace(operationNamespace);
      if (typeof reservationToken !== 'string' || reservationToken.length < 16) {
        return { ok: false, reason: 'capability_reservation_token_invalid' };
      }
      const operation = operations.get(operationKey(operationNamespace, operationId));
      const state = states.get(capabilityId);
      if (!operation || !state) return { ok: false, reason: 'capability_operation_not_found' };
      if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
      if (operation.status !== 'reserved') {
        return {
          ok: false,
          reason: operation.status === 'provider_entered'
            ? 'capability_provider_entry_already_recorded'
            : 'capability_operation_already_finalized',
        };
      }
      if (operation.reservation_token !== reservationToken) return { ok: false, reason: 'capability_reservation_owner_mismatch' };
      if (operation.control_domain_id !== null) {
        if (controlDomainId === undefined) {
          return { ok: false, reason: 'capability_control_domain_required' };
        }
        if (controlDomainId !== operation.control_domain_id) {
          return { ok: false, reason: 'capability_control_domain_binding_mismatch' };
        }
        const controlDomain = controlDomains.get(operation.control_domain_id);
        if (!controlDomain) {
          return { ok: false, reason: 'capability_control_domain_unavailable' };
        }
        if (controlDomain.status !== 'active'
            || controlDomain.epoch !== operation.reserved_control_epoch) {
          operation.status = 'released';
          operation.outcome = 'not_entered';
          operation.release_reason = controlDomain.status === 'frozen'
            ? 'control_domain_frozen'
            : 'control_domain_epoch_mismatch';
          operation.released_at = nowMs(now);
          state.reserved_amount -= operation.amount;
          return {
            ok: false,
            reason: controlDomain.status === 'frozen'
              ? 'capability_control_domain_frozen'
              : 'capability_control_domain_epoch_mismatch',
            outcome: 'not_entered',
            reservation: 'released',
          };
        }
      } else if (controlDomainId !== undefined) {
        return { ok: false, reason: 'capability_control_domain_binding_mismatch' };
      }
      const reservedAllowanceStatus = reservedAllowanceStatusAssertion(state, operation);
      if (typeof state.allowance_profile_id === 'string'
          && operationNamespace === state.allowance_profile_id) {
        if (!reservedAllowanceStatus) return { ok: false, reason: 'allowance_status_assertion_required' };
        const currentAllowanceStatus = allowanceStatuses.get(state.allowance_profile_id);
        if (!currentAllowanceStatus) return { ok: false, reason: 'allowance_status_not_initialized' };
        const refusal = allowanceStatusRefusal(currentAllowanceStatus, reservedAllowanceStatus);
        if (refusal) return { ok: false, reason: refusal };
      }
      const at = nowMs(now);
      if (at >= operation.entry_deadline_at) return { ok: false, reason: 'capability_reservation_expired' };
      operation.status = 'provider_entered';
      operation.provider_entry_at = at;
      state.reserved_amount -= operation.amount;
      state.consumed_amount += operation.amount;
      return {
        ok: true,
        operation_id: operationId,
        provider_entry_at: at,
        consumed: state.consumed_amount,
        remaining: state.budget_amount - state.consumed_amount - state.reserved_amount,
      };
    },
    async recoverPreEntrySpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, reservationToken, disposition, now = Date.now }: RecoverPreEntrySpendOptions = {}) {
      validateOperationId(operationId);
      validateOperationNamespace(operationNamespace);
      validateActionDigest(actionDigest);
      const operation = operations.get(operationKey(operationNamespace, operationId));
      const state = states.get(capabilityId);
      if (!operation || !state) return { ok: false, reason: 'capability_operation_not_found' };
      if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
      if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
      if (disposition !== undefined) {
        if (disposition !== 'release' && disposition !== 'burn') {
          return { ok: false, reason: 'capability_provider_entry_disposition_invalid' };
        }
        if (typeof reservationToken !== 'string' || reservationToken.length < 16) {
          return { ok: false, reason: 'capability_reservation_token_invalid' };
        }
        if (operation.reservation_token !== reservationToken) {
          return { ok: false, reason: 'capability_reservation_owner_mismatch' };
        }
        if (disposition === 'release'
            && operation.status === 'released'
            && operation.outcome === 'not_entered'
            && operation.release_reason === 'provider_entry_guard_release') {
          return { ok: true, idempotent: true, outcome: 'not_entered', released: operation.amount };
        }
        if (disposition === 'burn'
            && operation.status === 'committed'
            && operation.outcome === 'refused') {
          return { ok: true, idempotent: true, outcome: 'refused', consumed: operation.amount };
        }
        if (operation.status !== 'reserved') {
          return { ok: false, reason: 'capability_provider_entry_recorded' };
        }
        const at = nowMs(now);
        state.reserved_amount -= operation.amount;
        if (disposition === 'burn') {
          operation.status = 'committed';
          operation.outcome = 'refused';
          operation.committed_at = at;
          state.consumed_amount += operation.amount;
          return {
            ok: true,
            outcome: 'refused',
            consumed: operation.amount,
            remaining: state.budget_amount - state.consumed_amount - state.reserved_amount,
          };
        }
        operation.status = 'released';
        operation.outcome = 'not_entered';
        operation.release_reason = 'provider_entry_guard_release';
        operation.released_at = at;
        return {
          ok: true,
          outcome: 'not_entered',
          released: operation.amount,
          remaining: state.budget_amount - state.consumed_amount - state.reserved_amount,
        };
      }
      if (operation.status === 'released' && operation.outcome === 'not_entered'
          && operation.release_reason === 'pre_entry_deadline_elapsed') {
        return {
          ok: true,
          idempotent: true,
          outcome: 'not_entered',
          released: operation.amount,
          remaining: state.budget_amount - state.consumed_amount - state.reserved_amount,
        };
      }
      if (operation.status !== 'reserved') {
        return { ok: false, reason: 'capability_provider_entry_recorded' };
      }
      const at = nowMs(now);
      if (!Number.isSafeInteger(operation.entry_deadline_at)) {
        return { ok: false, reason: 'capability_recovery_deadline_unavailable' };
      }
      if (at < operation.entry_deadline_at) return { ok: false, reason: 'capability_recovery_deadline_active' };
      operation.status = 'released';
      operation.outcome = 'not_entered';
      operation.release_reason = 'pre_entry_deadline_elapsed';
      operation.released_at = at;
      state.reserved_amount -= operation.amount;
      return {
        ok: true,
        outcome: 'not_entered',
        released: operation.amount,
        remaining: state.budget_amount - state.consumed_amount - state.reserved_amount,
      };
    },
    async commitSpend({ capabilityId, operationNamespace = capabilityId, operationId, reservationToken, outcome = 'executed', now = Date.now }: CommitSpendOptions = {}) {
      validateOperationId(operationId);
      validateOperationNamespace(operationNamespace);
      const operation = operations.get(operationKey(operationNamespace, operationId));
      const state = states.get(capabilityId);
      if (!operation || !state) return { ok: false, reason: 'capability_operation_not_found' };
      if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
      if (!['executed', 'indeterminate', 'delegated'].includes(outcome)) return { ok: false, reason: 'capability_outcome_invalid' };
      const expectedStatus = outcome === 'delegated' ? 'reserved' : 'provider_entered';
      if (operation.status !== expectedStatus) {
        return {
          ok: false,
          reason: operation.status === 'reserved'
            ? 'capability_provider_entry_not_recorded'
            : 'capability_operation_already_finalized',
        };
      }
      if (operation.reservation_token !== reservationToken) return { ok: false, reason: 'capability_reservation_owner_mismatch' };
      const at = nowMs(now);
      if (outcome === 'delegated' && at >= operation.entry_deadline_at) {
        return { ok: false, reason: 'capability_reservation_expired' };
      }
      operation.status = 'committed';
      operation.outcome = outcome;
      operation.committed_at = at;
      if (outcome === 'delegated') {
        state.reserved_amount -= operation.amount;
        state.consumed_amount += operation.amount;
      }
      return { ok: true, outcome, consumed: state.consumed_amount, remaining: state.budget_amount - state.consumed_amount - state.reserved_amount };
    },
    async reconcileSpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, evidenceDigest, evidenceProfile, evidenceFinal, evidenceObservedAt, outcome = 'executed', now = Date.now }: ReconcileSpendOptions = {}) {
      validateOperationId(operationId);
      validateOperationNamespace(operationNamespace);
      const operation = operations.get(operationKey(operationNamespace, operationId));
      if (!operation) return { ok: false, reason: 'capability_operation_not_found' };
      if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
      if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
      if (!['executed', 'not_entered'].includes(outcome)
          || typeof evidenceDigest !== 'string' || !ACTION_DIGEST_RE.test(evidenceDigest)) {
        return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
      }
      const at = nowMs(now);
      if (outcome === 'not_entered') {
        let observedAt;
        try {
          validateEvidenceProfile(evidenceProfile);
          if (evidenceFinal !== true) throw new TypeError('negative evidence must be final');
          observedAt = evidenceObservedAtMs(evidenceObservedAt);
        } catch {
          return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
        }
        if (observedAt > at) return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
        const state = states.get(operation.capability_id);
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        if (operation.status === 'released') {
          return operation.outcome === 'not_entered'
              && operation.release_evidence_digest === evidenceDigest
              && operation.release_evidence_profile === evidenceProfile
            ? { ok: true, idempotent: true, outcome }
            : { ok: false, reason: 'capability_reconciliation_conflict' };
        }
        if (!Number.isSafeInteger(operation.entry_deadline_at)) {
          return { ok: false, reason: 'capability_recovery_deadline_unavailable' };
        }
        if (at < operation.entry_deadline_at) return { ok: false, reason: 'capability_recovery_deadline_active' };
        if (observedAt < operation.entry_deadline_at) {
          return { ok: false, reason: 'capability_reconciliation_evidence_stale' };
        }
        if (operation.status === 'reserved') {
          operation.status = 'released';
          operation.outcome = 'not_entered';
          operation.release_reason = 'authenticated_final_provider_non_entry';
          operation.release_evidence_profile = evidenceProfile;
          operation.release_evidence_digest = evidenceDigest;
          operation.released_at = at;
          state.reserved_amount -= operation.amount;
          return { ok: true, idempotent: false, outcome };
        }
        if (operation.reconciliation_outcome) {
          return operation.reconciliation_outcome === outcome
              && operation.reconciliation_evidence_digest === evidenceDigest
            ? { ok: true, idempotent: true, outcome }
            : { ok: false, reason: 'capability_reconciliation_conflict' };
        }
        if (operation.status === 'provider_entered') {
          operation.status = 'committed';
          operation.outcome = 'indeterminate';
          operation.committed_at = at;
        } else if (operation.status !== 'committed' || operation.outcome !== 'indeterminate') {
          return { ok: false, reason: 'capability_operation_not_indeterminate' };
        }
        operation.reconciliation_outcome = outcome;
        operation.reconciliation_evidence_digest = evidenceDigest;
        operation.reconciled_at = at;
        return { ok: true, idempotent: false, outcome };
      }
      if (operation.reconciliation_outcome) {
        return operation.reconciliation_outcome === outcome && operation.reconciliation_evidence_digest === evidenceDigest
          ? { ok: true, idempotent: true, outcome }
          : { ok: false, reason: 'capability_reconciliation_conflict' };
      }
      if (operation.status === 'reserved') {
        const state = states.get(operation.capability_id);
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        operation.status = 'committed';
        operation.outcome = 'indeterminate';
        operation.committed_at = at;
        state.reserved_amount -= operation.amount;
        state.consumed_amount += operation.amount;
      } else if (operation.status === 'provider_entered') {
        operation.status = 'committed';
        operation.outcome = 'indeterminate';
        operation.committed_at = at;
      } else if (operation.status !== 'committed' || operation.outcome !== 'indeterminate') {
        return { ok: false, reason: 'capability_operation_not_indeterminate' };
      }
      operation.reconciliation_outcome = outcome;
      operation.reconciliation_evidence_digest = evidenceDigest;
      operation.reconciled_at = at;
      return { ok: true, idempotent: false, outcome };
    },
    getState(capabilityId) {
      const state = states.get(capabilityId);
      return state ? Object.freeze({ ...state }) : null;
    },
    getAllowanceStatus(allowanceProfileId) {
      const status = allowanceStatuses.get(allowanceProfileId);
      return status ? Object.freeze({ ...status }) : null;
    },
    getControlDomain(controlDomainId) {
      const domain = controlDomains.get(controlDomainId);
      return domain ? Object.freeze({ ...domain }) : null;
    },
    getControlDomainEvent(operationId) {
      const event = controlDomainEvents.get(operationId);
      return event ? Object.freeze({ ...event, result: Object.freeze({ ...event.result }) }) : null;
    },
    getOperation(operationId, capabilityId = null, operationNamespace = capabilityId) {
      let operation = capabilityId === null
        ? null
        : operations.get(operationKey(operationNamespace, operationId));
      if (capabilityId === null) {
        for (const candidate of operations.values()) {
          if (candidate.operation_id !== operationId) continue;
          if (operation) return null;
          operation = candidate;
        }
      }
      return operation ? Object.freeze({ ...operation }) : null;
    },
  };
}

export const CAPABILITY_STATE_TABLE = 'ep_capability_state';
export const CAPABILITY_OPERATION_TABLE = 'ep_capability_operations';
export const CAPABILITY_ALLOWANCE_STATUS_TABLE = 'ep_gate_allowance_status';
export const CAPABILITY_CONTROL_DOMAIN_TABLE = 'ep_gate_control_domains';
export const CAPABILITY_CONTROL_DOMAIN_EVENT_TABLE = 'ep_gate_control_domain_events';
export const CAPABILITY_STATE_DDL = `CREATE TABLE IF NOT EXISTS ${CAPABILITY_STATE_TABLE} (
  capability_id TEXT PRIMARY KEY,
  capability_fingerprint TEXT NOT NULL CHECK (capability_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  budget_amount BIGINT NOT NULL CHECK (budget_amount >= 0),
  currency TEXT NOT NULL,
  consumed_amount BIGINT NOT NULL DEFAULT 0 CHECK (consumed_amount >= 0),
  reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),
  expires_at TIMESTAMPTZ NOT NULL,
  revocation_mode TEXT NOT NULL CHECK (revocation_mode IN ('direct', 'cascade')),
  parent_capability_id TEXT REFERENCES ${CAPABILITY_STATE_TABLE}(capability_id),
  revoked_at TIMESTAMPTZ,
  revocation_state_ready BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  allowance_profile_id TEXT,
  allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),
  semantic_fence_ready BOOLEAN NOT NULL DEFAULT TRUE,
  CHECK ((allowance_profile_id IS NULL) = (allowance_digest IS NULL))
);
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS capability_fingerprint TEXT;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS allowance_profile_id TEXT;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS semantic_fence_ready BOOLEAN;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS revocation_mode TEXT;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS parent_capability_id TEXT;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS revocation_state_ready BOOLEAN;
ALTER TABLE ${CAPABILITY_STATE_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_STATE_TABLE}_revocation_mode_check;
ALTER TABLE ${CAPABILITY_STATE_TABLE}
  ADD CONSTRAINT ${CAPABILITY_STATE_TABLE}_revocation_mode_check
  CHECK (revocation_mode IS NULL OR revocation_mode IN ('direct', 'cascade'));
ALTER TABLE ${CAPABILITY_STATE_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_STATE_TABLE}_parent_capability_id_fkey;
ALTER TABLE ${CAPABILITY_STATE_TABLE}
  ADD CONSTRAINT ${CAPABILITY_STATE_TABLE}_parent_capability_id_fkey
  FOREIGN KEY (parent_capability_id) REFERENCES ${CAPABILITY_STATE_TABLE}(capability_id);
UPDATE ${CAPABILITY_STATE_TABLE}
  SET revocation_state_ready = (revocation_mode IN ('direct', 'cascade'))
  WHERE revocation_state_ready IS NULL
     OR (revocation_state_ready IS TRUE AND revocation_mode NOT IN ('direct', 'cascade'));
ALTER TABLE ${CAPABILITY_STATE_TABLE}
  ALTER COLUMN revocation_state_ready SET DEFAULT TRUE,
  ALTER COLUMN revocation_state_ready SET NOT NULL;
CREATE OR REPLACE FUNCTION ep_require_capability_revocation_metadata()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $capability_revocation_metadata_function$
BEGIN
  IF NEW.revocation_state_ready IS TRUE
     AND (
       NEW.revocation_mode IS NULL
       OR NEW.revocation_mode NOT IN ('direct', 'cascade')
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'capability revocation metadata is not ready',
      DETAIL = format('capability_id=%s', NEW.capability_id),
      HINT = 'Reissue the capability with an explicitly signed direct or cascade revocation mode.';
  END IF;
  RETURN NEW;
END
$capability_revocation_metadata_function$;
DROP TRIGGER IF EXISTS ep_capability_state_revocation_metadata_guard
  ON ${CAPABILITY_STATE_TABLE};
CREATE TRIGGER ep_capability_state_revocation_metadata_guard
  BEFORE INSERT OR UPDATE OF revocation_mode, revocation_state_ready
  ON ${CAPABILITY_STATE_TABLE}
  FOR EACH ROW
  EXECUTE FUNCTION ep_require_capability_revocation_metadata();
CREATE TABLE IF NOT EXISTS ${CAPABILITY_ALLOWANCE_STATUS_TABLE} (
  allowance_profile_id TEXT PRIMARY KEY,
  allowance_digest TEXT NOT NULL CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),
  revision BIGINT NOT NULL CHECK (revision > 0),
  status_epoch BIGINT NOT NULL CHECK (status_epoch > 0),
  status_head_digest TEXT NOT NULL CHECK (status_head_digest ~ '^sha256:[0-9a-f]{64}$'),
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ${CAPABILITY_CONTROL_DOMAIN_TABLE} (
  control_domain_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('active', 'frozen')),
  epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),
  frozen_at TIMESTAMPTZ,
  frozen_by_digest TEXT CHECK (frozen_by_digest ~ '^sha256:[0-9a-f]{64}$'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (
    (status = 'active' AND frozen_at IS NULL AND frozen_by_digest IS NULL)
    OR
    (status = 'frozen' AND frozen_at IS NOT NULL AND frozen_by_digest IS NOT NULL)
  )
);
CREATE TABLE IF NOT EXISTS ${CAPABILITY_CONTROL_DOMAIN_EVENT_TABLE} (
  operation_id TEXT NOT NULL,
  control_domain_id TEXT NOT NULL REFERENCES ${CAPABILITY_CONTROL_DOMAIN_TABLE}(control_domain_id),
  event_type TEXT NOT NULL CHECK (event_type IN ('freeze', 'restore')),
  epoch_at_event BIGINT NOT NULL CHECK (epoch_at_event > 0),
  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  authority_instance_digest TEXT NOT NULL CHECK (authority_instance_digest ~ '^sha256:[0-9a-f]{64}$'),
  result JSONB NOT NULL,
  committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (operation_id)
);
CREATE TABLE IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE} (
  operation_namespace TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  capability_id TEXT NOT NULL REFERENCES ${CAPABILITY_STATE_TABLE}(capability_id),
  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  action_fence_digest TEXT NOT NULL CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$'),
  amount BIGINT NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_status_check CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released')),
  reservation_token TEXT NOT NULL,
  outcome TEXT,
  reconciliation_outcome TEXT CHECK (reconciliation_outcome IN ('executed', 'not_entered')),
  reconciliation_evidence_digest TEXT CHECK (reconciliation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  allowance_revision BIGINT CHECK (allowance_revision > 0),
  allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0),
  allowance_status_head_digest TEXT CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$'),
  reserved_at TIMESTAMPTZ NOT NULL,
  entry_deadline_at TIMESTAMPTZ,
  provider_entry_at TIMESTAMPTZ,
  committed_at TIMESTAMPTZ,
  reconciled_at TIMESTAMPTZ,
  released_at TIMESTAMPTZ,
  release_reason TEXT,
  release_evidence_profile TEXT,
  release_evidence_digest TEXT CHECK (release_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  control_domain_id TEXT REFERENCES ${CAPABILITY_CONTROL_DOMAIN_TABLE}(control_domain_id),
  reserved_control_epoch BIGINT CHECK (reserved_control_epoch > 0),
  CHECK (
    (reconciliation_outcome IS NULL AND reconciliation_evidence_digest IS NULL AND reconciled_at IS NULL)
    OR
    (reconciliation_outcome IS NOT NULL AND reconciliation_evidence_digest IS NOT NULL AND reconciled_at IS NOT NULL)
  ),
  CHECK (
    (allowance_revision IS NULL AND allowance_status_epoch IS NULL AND allowance_status_head_digest IS NULL)
    OR
    (allowance_revision IS NOT NULL AND allowance_status_epoch IS NOT NULL AND allowance_status_head_digest IS NOT NULL)
  ),
  CHECK ((control_domain_id IS NULL) = (reserved_control_epoch IS NULL)),
  PRIMARY KEY (operation_namespace, operation_id)
);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS operation_namespace TEXT;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS entry_deadline_at TIMESTAMPTZ;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS provider_entry_at TIMESTAMPTZ;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS release_reason TEXT;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS release_evidence_profile TEXT;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS release_evidence_digest TEXT CHECK (release_evidence_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS control_domain_id TEXT REFERENCES ${CAPABILITY_CONTROL_DOMAIN_TABLE}(control_domain_id);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS reserved_control_epoch BIGINT CHECK (reserved_control_epoch > 0);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_OPERATION_TABLE}_control_domain_binding_check;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_control_domain_binding_check
  CHECK ((control_domain_id IS NULL) = (reserved_control_epoch IS NULL));
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_OPERATION_TABLE}_action_digest_check;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_action_digest_check
  CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_OPERATION_TABLE}_release_evidence_digest_check;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_release_evidence_digest_check
  CHECK (release_evidence_digest IS NULL OR release_evidence_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_OPERATION_TABLE}_status_check;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_status_check
  CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released'));
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_OPERATION_TABLE}_reconciliation_outcome_check;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_reconciliation_outcome_check
  CHECK (reconciliation_outcome IS NULL OR reconciliation_outcome IN ('executed', 'not_entered'));
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS allowance_revision BIGINT CHECK (allowance_revision > 0);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS allowance_status_head_digest TEXT CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS action_fence_digest TEXT CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_OPERATION_TABLE}_action_fence_digest_check;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_action_fence_digest_check
  CHECK (action_fence_digest IS NULL OR action_fence_digest ~ '^sha256:[0-9a-f]{64}$');
-- Capture legacy capability ids before compatibility backfills erase the only
-- reliable signal that their historical rows never carried a semantic fence.
-- This also closes an incomplete-bootstrap case where the state flag was
-- already added with its TRUE default but operation bindings remain legacy.
DROP TABLE IF EXISTS pg_temp.ep_capability_action_fence_legacy_ids;
CREATE TEMP TABLE ep_capability_action_fence_legacy_ids
ON COMMIT DROP
AS
SELECT DISTINCT capability_id
FROM ${CAPABILITY_OPERATION_TABLE}
WHERE operation_namespace IS NULL
   OR action_fence_digest IS NULL;
UPDATE ${CAPABILITY_OPERATION_TABLE}
  SET operation_namespace = capability_id
  WHERE operation_namespace IS NULL;
UPDATE ${CAPABILITY_OPERATION_TABLE}
  SET action_fence_digest = action_digest
  WHERE action_fence_digest IS NULL;
DO $capability_legacy_reservation_preflight$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ${CAPABILITY_OPERATION_TABLE}
      WHERE status = 'reserved' AND entry_deadline_at IS NULL
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'legacy reserved capability operations require operator reconciliation before action-fence migration';
  END IF;
END
$capability_legacy_reservation_preflight$;
UPDATE ${CAPABILITY_STATE_TABLE} AS capability_state
  SET semantic_fence_ready = FALSE
  FROM pg_temp.ep_capability_action_fence_legacy_ids AS legacy_capability
  WHERE legacy_capability.capability_id = capability_state.capability_id;
UPDATE ${CAPABILITY_STATE_TABLE} AS capability_state
  SET semantic_fence_ready = NOT EXISTS (
    SELECT 1 FROM ${CAPABILITY_OPERATION_TABLE} AS operation
      WHERE operation.capability_id = capability_state.capability_id
  )
  WHERE capability_state.semantic_fence_ready IS NULL;
ALTER TABLE ${CAPABILITY_STATE_TABLE}
  ALTER COLUMN semantic_fence_ready SET DEFAULT TRUE,
  ALTER COLUMN semantic_fence_ready SET NOT NULL;
CREATE OR REPLACE FUNCTION ep_require_semantic_capability_fence()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $semantic_capability_fence_function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM ${CAPABILITY_STATE_TABLE} AS capability_state
      WHERE capability_state.capability_id = NEW.capability_id
        AND capability_state.semantic_fence_ready IS TRUE
        AND capability_state.revocation_state_ready IS TRUE
        AND capability_state.revocation_mode IN ('direct', 'cascade')
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'capability semantic action fence is not ready',
      DETAIL = format('capability_id=%s', NEW.capability_id),
      HINT = 'Reissue a fresh capability with a new capability ID; do not infer semantic equivalence from historical exact digests.';
  END IF;
  RETURN NEW;
END
$semantic_capability_fence_function$;
DROP TRIGGER IF EXISTS ep_capability_operations_semantic_fence_guard
  ON ${CAPABILITY_OPERATION_TABLE};
CREATE TRIGGER ep_capability_operations_semantic_fence_guard
  BEFORE INSERT ON ${CAPABILITY_OPERATION_TABLE}
  FOR EACH ROW
  EXECUTE FUNCTION ep_require_semantic_capability_fence();
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ALTER COLUMN operation_namespace SET NOT NULL;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ALTER COLUMN action_fence_digest SET NOT NULL;
DO $capability_operation_primary_key$
DECLARE
  current_primary_key_name TEXT;
  current_primary_key_definition TEXT;
BEGIN
  SELECT conname, pg_get_constraintdef(oid)
    INTO current_primary_key_name, current_primary_key_definition
    FROM pg_constraint
    WHERE conrelid = '${CAPABILITY_OPERATION_TABLE}'::regclass
      AND contype = 'p';
  IF current_primary_key_definition IS DISTINCT FROM 'PRIMARY KEY (operation_namespace, operation_id)' THEN
    IF current_primary_key_name IS NOT NULL THEN
      EXECUTE format(
        'ALTER TABLE %I DROP CONSTRAINT %I',
        '${CAPABILITY_OPERATION_TABLE}',
        current_primary_key_name
      );
    END IF;
    ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
      ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_pkey
      PRIMARY KEY (operation_namespace, operation_id);
  END IF;
END
$capability_operation_primary_key$;
CREATE INDEX IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE}_capability_idx ON ${CAPABILITY_OPERATION_TABLE}(capability_id);
CREATE INDEX IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE}_recovery_idx ON ${CAPABILITY_OPERATION_TABLE}(status, entry_deadline_at);
DO $capability_live_action_preflight$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM ${CAPABILITY_OPERATION_TABLE}
      WHERE status IN ('reserved', 'provider_entered', 'committed')
      GROUP BY operation_namespace, action_fence_digest
      HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '23505',
      MESSAGE = 'duplicate live capability actions require operator reconciliation before installing the action fence';
  END IF;
END
$capability_live_action_preflight$;
CREATE UNIQUE INDEX IF NOT EXISTS ${ACTION_FENCE_CONSTRAINT}
  ON ${CAPABILITY_OPERATION_TABLE}(operation_namespace, action_fence_digest)
  WHERE status IN ('reserved', 'provider_entered', 'committed');
DO $capability_action_fence_index_contract$
DECLARE
  index_is_unique BOOLEAN;
  index_is_valid BOOLEAN;
  index_is_ready BOOLEAN;
  index_is_immediate BOOLEAN;
  index_is_exclusion BOOLEAN;
  index_nulls_not_distinct BOOLEAN;
  index_access_method TEXT;
  index_table OID;
  index_key_count INTEGER;
  index_attribute_count INTEGER;
  index_key_columns TEXT[];
  index_key_collations OID[];
  expected_key_collations OID[];
  index_key_opclasses OID[];
  expected_key_opclasses OID[];
  index_key_options SMALLINT[];
  index_predicate TEXT;
  normalized_predicate TEXT;
BEGIN
  SELECT
      i.indisunique,
      i.indisvalid,
      i.indisready,
      i.indimmediate,
      i.indisexclusion,
      i.indnullsnotdistinct,
      access_method.amname,
      i.indrelid,
      i.indnkeyatts,
      i.indnatts,
      ARRAY(
        SELECT a.attname
          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)
          JOIN pg_attribute AS a
            ON a.attrelid = i.indrelid
           AND a.attnum = key.attnum
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      ARRAY(
        SELECT key.collation_oid
          FROM unnest(i.indcollation::OID[]) WITH ORDINALITY AS key(collation_oid, ordinal)
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      ARRAY(
        SELECT attribute.attcollation
          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)
          JOIN pg_attribute AS attribute
            ON attribute.attrelid = i.indrelid
           AND attribute.attnum = key.attnum
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      ARRAY(
        SELECT key.opclass_oid
          FROM unnest(i.indclass::OID[]) WITH ORDINALITY AS key(opclass_oid, ordinal)
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      ARRAY(
        SELECT default_opclass.oid
          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)
          JOIN pg_attribute AS attribute
            ON attribute.attrelid = i.indrelid
           AND attribute.attnum = key.attnum
          JOIN LATERAL (
            SELECT opclass.oid
              FROM pg_opclass AS opclass
              WHERE opclass.opcmethod = index_relation.relam
                AND opclass.opcdefault
                AND opclass.opcintype = attribute.atttypid
              ORDER BY opclass.oid
              LIMIT 1
          ) AS default_opclass ON TRUE
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      ARRAY(
        SELECT key.option_bits
          FROM unnest(i.indoption::SMALLINT[]) WITH ORDINALITY AS key(option_bits, ordinal)
          WHERE key.ordinal <= i.indnkeyatts
          ORDER BY key.ordinal
      ),
      pg_get_expr(i.indpred, i.indrelid)
    INTO
      index_is_unique,
      index_is_valid,
      index_is_ready,
      index_is_immediate,
      index_is_exclusion,
      index_nulls_not_distinct,
      index_access_method,
      index_table,
      index_key_count,
      index_attribute_count,
      index_key_columns,
      index_key_collations,
      expected_key_collations,
      index_key_opclasses,
      expected_key_opclasses,
      index_key_options,
      index_predicate
    FROM pg_index AS i
    JOIN pg_class AS index_relation
      ON index_relation.oid = i.indexrelid
    JOIN pg_am AS access_method
      ON access_method.oid = index_relation.relam
    WHERE i.indexrelid = to_regclass('${ACTION_FENCE_CONSTRAINT}')
      AND i.indrelid = '${CAPABILITY_OPERATION_TABLE}'::regclass;

  normalized_predicate := replace(
    regexp_replace(coalesce(index_predicate, ''), '\\s+', '', 'g'),
    '::text',
    ''
  );

  IF index_is_unique IS DISTINCT FROM TRUE
     OR index_is_valid IS DISTINCT FROM TRUE
     OR index_is_ready IS DISTINCT FROM TRUE
     OR index_is_immediate IS DISTINCT FROM TRUE
     OR index_is_exclusion IS DISTINCT FROM FALSE
     OR index_nulls_not_distinct IS DISTINCT FROM FALSE
     OR index_access_method IS DISTINCT FROM 'btree'
     OR index_table IS DISTINCT FROM '${CAPABILITY_OPERATION_TABLE}'::regclass::OID
     OR index_key_count IS DISTINCT FROM 2
     OR index_attribute_count IS DISTINCT FROM 2
     OR index_key_columns IS DISTINCT FROM ARRAY['operation_namespace', 'action_fence_digest']::TEXT[]
     OR index_key_collations IS DISTINCT FROM expected_key_collations
     OR index_key_opclasses IS DISTINCT FROM expected_key_opclasses
     OR index_key_options IS DISTINCT FROM ARRAY[0, 0]::SMALLINT[]
     OR normalized_predicate IS DISTINCT FROM
       '(status=ANY(ARRAY[''reserved'',''provider_entered'',''committed'']))' THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'EMILIA capability action-fence index does not match its required contract',
      DETAIL = format(
        'unique=%s valid=%s ready=%s immediate=%s exclusion=%s nulls_not_distinct=%s method=%s table_oid=%s key_count=%s attribute_count=%s columns=%s collations=%s expected_collations=%s opclasses=%s expected_opclasses=%s options=%s predicate=%s',
        coalesce(index_is_unique::TEXT, '<missing>'),
        coalesce(index_is_valid::TEXT, '<missing>'),
        coalesce(index_is_ready::TEXT, '<missing>'),
        coalesce(index_is_immediate::TEXT, '<missing>'),
        coalesce(index_is_exclusion::TEXT, '<missing>'),
        coalesce(index_nulls_not_distinct::TEXT, '<missing>'),
        coalesce(index_access_method, '<missing>'),
        coalesce(index_table::TEXT, '<missing>'),
        coalesce(index_key_count::TEXT, '<missing>'),
        coalesce(index_attribute_count::TEXT, '<missing>'),
        coalesce(array_to_string(index_key_columns, ','), '<missing>'),
        coalesce(array_to_string(index_key_collations, ','), '<missing>'),
        coalesce(array_to_string(expected_key_collations, ','), '<missing>'),
        coalesce(array_to_string(index_key_opclasses, ','), '<missing>'),
        coalesce(array_to_string(expected_key_opclasses, ','), '<missing>'),
        coalesce(array_to_string(index_key_options, ','), '<missing>'),
        coalesce(index_predicate, '<missing>')
      ),
      HINT = 'Do not continue. Remove or repair the conflicting index only through a reviewed migration after preserving all operation history.';
  END IF;
END
$capability_action_fence_index_contract$;`;

export const CAPABILITY_SQL = Object.freeze({
  register: `INSERT INTO ${CAPABILITY_STATE_TABLE} (capability_id, budget_amount, currency, expires_at, capability_fingerprint, allowance_profile_id, allowance_digest, revocation_mode, parent_capability_id, revocation_state_ready) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE) ON CONFLICT (capability_id) DO NOTHING`,
  readState: `SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at, allowance_profile_id, allowance_digest, semantic_fence_ready, revocation_mode, parent_capability_id, revoked_at, revocation_state_ready FROM ${CAPABILITY_STATE_TABLE} WHERE capability_id = $1 FOR UPDATE`,
  revokeState: `UPDATE ${CAPABILITY_STATE_TABLE} SET revoked_at = $3 WHERE capability_id = $1 AND capability_fingerprint = $2 AND revoked_at IS NULL AND revocation_state_ready IS TRUE AND revocation_mode IN ('direct', 'cascade')`,
  readAllowanceStatus: `SELECT allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status FROM ${CAPABILITY_ALLOWANCE_STATUS_TABLE} WHERE allowance_profile_id = $1 FOR UPDATE`,
  insertAllowanceStatus: `INSERT INTO ${CAPABILITY_ALLOWANCE_STATUS_TABLE} (allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (allowance_profile_id) DO NOTHING`,
  updateAllowanceStatus: `UPDATE ${CAPABILITY_ALLOWANCE_STATUS_TABLE} SET allowance_digest = $4, revision = $5, status_epoch = $6, status_head_digest = $7, status = $8, updated_at = $9 WHERE allowance_profile_id = $1 AND status_epoch = $2 AND status_head_digest = $3`,
  insertControlDomain: `INSERT INTO ${CAPABILITY_CONTROL_DOMAIN_TABLE} (control_domain_id, status, epoch, updated_at) VALUES ($1, 'active', 1, $2) ON CONFLICT (control_domain_id) DO NOTHING RETURNING control_domain_id, status, epoch`,
  readControlDomain: `SELECT control_domain_id, status, epoch, frozen_at, frozen_by_digest, updated_at FROM ${CAPABILITY_CONTROL_DOMAIN_TABLE} WHERE control_domain_id = $1 FOR UPDATE`,
  readControlDomainEvent: `SELECT operation_id, control_domain_id, event_type, epoch_at_event, action_digest, authority_instance_digest, result, committed_at FROM ${CAPABILITY_CONTROL_DOMAIN_EVENT_TABLE} WHERE operation_id = $1`,
  freezeControlDomain: `UPDATE ${CAPABILITY_CONTROL_DOMAIN_TABLE} SET status = 'frozen', epoch = epoch + 1, frozen_at = $2, frozen_by_digest = $3, updated_at = $2 WHERE control_domain_id = $1 AND status = 'active' RETURNING control_domain_id, status, epoch`,
  restoreControlDomain: `UPDATE ${CAPABILITY_CONTROL_DOMAIN_TABLE} SET status = 'active', epoch = epoch + 1, frozen_at = NULL, frozen_by_digest = NULL, updated_at = $2 WHERE control_domain_id = $1 AND status = 'frozen' RETURNING control_domain_id, status, epoch`,
  insertControlDomainEvent: `INSERT INTO ${CAPABILITY_CONTROL_DOMAIN_EVENT_TABLE} (operation_id, control_domain_id, event_type, epoch_at_event, action_digest, authority_instance_digest, result, committed_at) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`,
  readOperation: `SELECT operation_namespace, operation_id, capability_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, allowance_revision, allowance_status_epoch, allowance_status_head_digest, reconciled_at, reserved_at, entry_deadline_at, provider_entry_at, released_at, release_reason, release_evidence_profile, release_evidence_digest, control_domain_id, reserved_control_epoch FROM ${CAPABILITY_OPERATION_TABLE} WHERE operation_namespace = $1 AND operation_id = $2 FOR UPDATE`,
  // Is this material-action fence already held by SOME operation, whatever its
  // id? An existing holder is row-locked here. Same-capability reservations also
  // serialize on readState. For custom namespaces spanning capability rows, the
  // partial unique index shipped in CAPABILITY_STATE_DDL (and mirrored by the
  // repository migration) is the authoritative race backstop because
  // PostgreSQL cannot lock a row that does not exist yet.
  readActionHolder: `SELECT operation_id, status, action_digest, action_fence_digest FROM ${CAPABILITY_OPERATION_TABLE} WHERE operation_namespace = $1 AND action_fence_digest = $2 AND status IN ('reserved', 'provider_entered', 'committed') LIMIT 1 FOR UPDATE`,
  insertOperation: `INSERT INTO ${CAPABILITY_OPERATION_TABLE} (operation_namespace, capability_id, operation_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, reserved_at, entry_deadline_at, allowance_revision, allowance_status_epoch, allowance_status_head_digest, control_domain_id, reserved_control_epoch) VALUES ($1, $2, $3, $4, $5, $6, $7, 'reserved', $8, $9, $10, $11, $12, $13, $14, $15)`,
  reserveState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND semantic_fence_ready IS TRUE AND revocation_state_ready IS TRUE AND revocation_mode IN ('direct', 'cascade') AND revoked_at IS NULL AND budget_amount - consumed_amount - reserved_amount >= $2`,
  beginProviderEntry: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'provider_entered', provider_entry_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'reserved' AND reservation_token = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at > $5`,
  commitOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'committed', outcome = $4, committed_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = $7 AND reservation_token = $6`,
  reconcileOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET reconciliation_outcome = $4, reconciliation_evidence_digest = $5, reconciled_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL`,
  recoverPreEntryOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'released', outcome = 'not_entered', release_reason = 'pre_entry_deadline_elapsed', released_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND status = 'reserved' AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $5`,
  releaseGuardRefusedOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'released', outcome = 'not_entered', release_reason = 'provider_entry_guard_release', released_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND reservation_token = $5 AND status = 'reserved'`,
  releaseControlBlockedOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'released', outcome = 'not_entered', release_reason = $6, released_at = $7 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND reservation_token = $4 AND status = 'reserved' AND control_domain_id = $5`,
  releaseReservedOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'released', outcome = 'not_entered', release_reason = 'authenticated_final_provider_non_entry', release_evidence_profile = $5, release_evidence_digest = $6, released_at = $8 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $7 AND $7 <= $8 AND status = 'reserved'`,
  commitState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2`,
  releaseReservedState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount - $2 WHERE capability_id = $1 AND reserved_amount >= $2`,
});

/**
 * Production adapter. `transaction` MUST run the callback on one database
 * connection with BEGIN/COMMIT/ROLLBACK. The state row is locked before the
 * operation row is inserted, making budget reservation linearizable per
 * capability and refusing all ambiguous database outcomes.
 *
 * @param {object} [options]
 * @param {(callback: (query: Function) => any) => any} [options.transaction]
 */
export function createPostgresCapabilityStore({
  transaction,
  providerEntryTimeoutMs = DEFAULT_PROVIDER_ENTRY_TIMEOUT_MS,
  stateDomainDigest = null,
  verifyControlTransition,
}: {
  transaction?: (callback: (query: Function) => any) => any;
  providerEntryTimeoutMs?: number;
  stateDomainDigest?: string | null;
  verifyControlTransition?: VerifyControlTransition;
} = {}) {
  if (typeof transaction !== 'function') throw new TypeError('createPostgresCapabilityStore requires a transaction(callback) function');
  const entryTimeoutMs = validateProviderEntryTimeoutMs(providerEntryTimeoutMs);
  const configuredStateDomainDigest = normalizeOptionalStateDomainDigest(stateDomainDigest);
  async function transitionPostgresControlDomain(
    eventType: 'freeze' | 'restore',
    options: ControlTransitionOptions,
  ) {
    try {
      validateControlDomainId(options.controlDomainId);
      validateOperationId(options.operationId);
      validateActionDigest(options.actionDigest);
    } catch {
      return { ok: false, reason: 'control_transition_refused' };
    }
    const verified = await verifyControlTransitionRequest(
      verifyControlTransition,
      eventType,
      options,
    );
    if (!verified.authenticated) {
      return { ok: false, reason: 'control_transition_refused' };
    }
    const controlDomainId = options.controlDomainId as string;
    const operationId = options.operationId as string;
    const actionDigest = options.actionDigest as string;
    try {
      return await transaction!(async (query) => {
        // The control-domain row is the first durable lock for every covered
        // transition. It serializes freeze, restore, reserve, and provider entry.
        const domainResult = await query(CAPABILITY_SQL.readControlDomain, [controlDomainId]);
        const domain = domainResult?.rows?.[0];
        if (!domain) return { ok: false, reason: 'control_transition_refused' };
        const existingResult = await query(CAPABILITY_SQL.readControlDomainEvent, [operationId]);
        const existing = existingResult?.rows?.[0];
        if (existing) {
          const matches = existing.event_type === eventType
            && existing.control_domain_id === controlDomainId
            && existing.action_digest === actionDigest
            && existing.authority_instance_digest === verified.authority_instance_digest;
          if (!matches) return { ok: false, reason: 'control_transition_refused' };
          const stored = typeof existing.result === 'string'
            ? JSON.parse(existing.result)
            : existing.result;
          return { ...stored, idempotent: true };
        }
        if (!verified.authorized) {
          return { ok: false, reason: 'control_transition_refused' };
        }
        const at = nowMs(options.now ?? Date.now);
        if (eventType === 'freeze' && domain.status === 'frozen') {
          const result = {
            ok: true,
            idempotent: false,
            status: 'already_frozen',
            control_domain_id: controlDomainId,
            epoch: Number(domain.epoch),
          };
          await query(CAPABILITY_SQL.insertControlDomainEvent, [
            operationId,
            controlDomainId,
            eventType,
            domain.epoch,
            actionDigest,
            verified.authority_instance_digest,
            JSON.stringify(result),
            new Date(at).toISOString(),
          ]);
          return result;
        }
        if (eventType === 'restore' && domain.status !== 'frozen') {
          return { ok: false, reason: 'control_transition_refused' };
        }
        const transitionSql = eventType === 'freeze'
          ? CAPABILITY_SQL.freezeControlDomain
          : CAPABILITY_SQL.restoreControlDomain;
        const transitionedResult = await query(
          transitionSql,
          eventType === 'freeze'
            ? [controlDomainId, new Date(at).toISOString(), verified.authority_instance_digest]
            : [controlDomainId, new Date(at).toISOString()],
        );
        const transitioned = transitionedResult?.rows?.[0];
        if (!transitioned) {
          throw new Error('control-domain transition lost serialization ownership');
        }
        const result = {
          ok: true,
          idempotent: false,
          status: transitioned.status,
          control_domain_id: transitioned.control_domain_id,
          epoch: Number(transitioned.epoch),
        };
        await query(CAPABILITY_SQL.insertControlDomainEvent, [
          operationId,
          controlDomainId,
          eventType,
          transitioned.epoch,
          actionDigest,
          verified.authority_instance_digest,
          JSON.stringify(result),
          new Date(at).toISOString(),
        ]);
        return result;
      });
    } catch {
      return { ok: false, reason: 'control_transition_refused' };
    }
  }
  return {
    durable: true,
    atomicStateDomainCapable: true,
    stateDomainDigest: configuredStateDomainDigest,
    reconciliationCapable: true,
    revocationInheritanceCapable: true,
    allowanceCurrentnessCapable: true,
    providerEntryDispositionCapable: true,
    controlDomainCapable: true,
    async registerControlDomain({
      controlDomainId,
      now = Date.now,
    }: { controlDomainId?: string; now?: number | (() => number) } = {}) {
      validateControlDomainId(controlDomainId);
      const validatedControlDomainId = controlDomainId as string;
      const at = nowMs(now);
      return transaction(async (query) => {
        const inserted = await query(CAPABILITY_SQL.insertControlDomain, [
          validatedControlDomainId,
          new Date(at).toISOString(),
        ]);
        const result = inserted?.rows?.[0]
          ? inserted
          : await query(CAPABILITY_SQL.readControlDomain, [validatedControlDomainId]);
        const domain = result?.rows?.[0];
        if (!domain) throw new Error('control-domain registration unavailable');
        return {
          ok: true,
          idempotent: inserted?.rowCount !== 1,
          control_domain_id: domain.control_domain_id,
          status: domain.status,
          epoch: Number(domain.epoch),
        };
      });
    },
    async freezeControlDomain(options: ControlTransitionOptions = {}) {
      return transitionPostgresControlDomain('freeze', options);
    },
    async restoreControlDomain(options: ControlTransitionOptions = {}) {
      return transitionPostgresControlDomain('restore', options);
    },
    async registerCapability(capabilityReceipt) {
      const verified = verifyCapabilityReceiptIntegrity(capabilityReceipt);
      if (!verified.ok) return false;
      const state = capabilityStateFromEnvelope(capabilityReceipt);
      return transaction(async (query) => {
        const existingResult = await query(CAPABILITY_SQL.readState, [state.capability_id]);
        const existing = existingResult?.rows?.[0];
        if (existing) {
          return existing.capability_fingerprint === state.capability_fingerprint
            && Number(existing.budget_amount) === state.budget_amount
            && existing.currency === state.currency
            && Date.parse(existing.expires_at) === state.expires_at
            && (existing.allowance_profile_id ?? null) === state.allowance_profile_id
            && (existing.allowance_digest ?? null) === state.allowance_digest
            && existing.revocation_mode === state.revocation_mode
            && (existing.parent_capability_id ?? null) === state.parent_capability_id
            && existing.revocation_state_ready === true
            && existing.semantic_fence_ready === true;
        }
        if (state.parent_capability_id !== null) {
          const parentResult = await query(CAPABILITY_SQL.readState, [state.parent_capability_id]);
          const parent = parentResult?.rows?.[0];
          if (!parent) return false;
          const parentRefusal = await postgresCapabilityLineageRefusal(query, parent);
          if (parentRefusal) return false;
        }
        await query(CAPABILITY_SQL.register, [
          state.capability_id,
          state.budget_amount,
          capabilityReceipt.capability.budget.currency,
          new Date(state.expires_at).toISOString(),
          state.capability_fingerprint,
          state.allowance_profile_id,
          state.allowance_digest,
          state.revocation_mode,
          state.parent_capability_id,
        ]);
        const result = await query(CAPABILITY_SQL.readState, [state.capability_id]);
        const row = result?.rows?.[0];
        return Boolean(row)
          && row.capability_fingerprint === state.capability_fingerprint
          && Number(row.budget_amount) === state.budget_amount
          && row.currency === state.currency
          && Date.parse(row.expires_at) === state.expires_at
          && (row.allowance_profile_id ?? null) === state.allowance_profile_id
          && (row.allowance_digest ?? null) === state.allowance_digest
          && row.revocation_mode === state.revocation_mode
          && (row.parent_capability_id ?? null) === state.parent_capability_id
          && row.revocation_state_ready === true
          && row.semantic_fence_ready === true;
      });
    },
    async revokeCapability({ capabilityId, capabilityFingerprint, now = Date.now }: RevokeCapabilityOptions = {}) {
      try {
        validateCapabilityId(capabilityId);
      } catch {
        return { ok: false, reason: 'capability_revocation_target_invalid' };
      }
      const at = nowMs(now);
      return transaction(async (query) => {
        const result = await query(CAPABILITY_SQL.readState, [capabilityId]);
        const state = result?.rows?.[0];
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        if (state.capability_fingerprint !== capabilityFingerprint) {
          return { ok: false, reason: 'capability_envelope_mismatch' };
        }
        if (state.revocation_state_ready !== true) {
          return { ok: false, reason: 'capability_ancestor_status_unavailable' };
        }
        try {
          normalizeRevocationMode(state.revocation_mode);
        } catch {
          return { ok: false, reason: 'capability_revocation_mode_invalid' };
        }
        if (state.revoked_at !== null && state.revoked_at !== undefined) {
          return {
            ok: true,
            idempotent: true,
            capability_id: capabilityId,
            revocation_mode: state.revocation_mode,
            revoked_at: Date.parse(state.revoked_at),
          };
        }
        const revoked = await query(CAPABILITY_SQL.revokeState, [
          capabilityId,
          capabilityFingerprint,
          new Date(at).toISOString(),
        ]);
        if (revoked?.rowCount !== 1) {
          throw new Error('capability revocation transition conflicted; transaction must roll back');
        }
        return {
          ok: true,
          idempotent: false,
          capability_id: capabilityId,
          revocation_mode: state.revocation_mode,
          revoked_at: at,
        };
      });
    },
    async advanceAllowanceStatus(options: AdvanceAllowanceStatusOptions) {
      const next = normalizeAllowanceStatusAdvance(options);
      const updatedAt = new Date().toISOString();
      return transaction(async (query) => {
        let result = await query(CAPABILITY_SQL.readAllowanceStatus, [next.allowance_profile_id]);
        let current = result?.rows?.[0];
        if (current && exactAllowanceStatus(current, next)) {
          return { ok: true, idempotent: true };
        }
        if (!current) {
          if (next.expected_status_epoch !== null || next.expected_status_head_digest !== null) {
            return { ok: false, reason: 'allowance_status_head_conflict' };
          }
          await query(CAPABILITY_SQL.insertAllowanceStatus, [
            next.allowance_profile_id,
            next.allowance_digest,
            next.revision,
            next.status_epoch,
            next.status_head_digest,
            next.status,
            updatedAt,
          ]);
          result = await query(CAPABILITY_SQL.readAllowanceStatus, [next.allowance_profile_id]);
          current = result?.rows?.[0];
          return current && exactAllowanceStatus(current, next)
            ? { ok: true, idempotent: false }
            : { ok: false, reason: 'allowance_status_head_conflict' };
        }
        if (allowanceStatusAdvanceConflict(current, next)) {
          return { ok: false, reason: 'allowance_status_head_conflict' };
        }
        const advanced = await query(CAPABILITY_SQL.updateAllowanceStatus, [
          next.allowance_profile_id,
          next.expected_status_epoch,
          next.expected_status_head_digest,
          next.allowance_digest,
          next.revision,
          next.status_epoch,
          next.status_head_digest,
          next.status,
          updatedAt,
        ]);
        if (advanced?.rowCount !== 1) {
          return { ok: false, reason: 'allowance_status_head_conflict' };
        }
        return { ok: true, idempotent: false };
      });
    },
    async reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace = capabilityId, operationId, actionDigest, actionFenceDigest = actionDigest, amount, currency, controlDomainId, allowanceStatus, now = Date.now }: ReserveSpendOptions) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace); validateSpendAmount(amount); validateCurrency(currency);
      validateActionDigest(actionDigest);
      validateActionDigest(actionFenceDigest);
      const at = nowMs(now);
      try {
        return await transaction(async (query) => {
        let controlDomain: Record<string, any> | null = null;
        if (controlDomainId !== undefined) {
          validateControlDomainId(controlDomainId);
          const domainResult = await query(CAPABILITY_SQL.readControlDomain, [controlDomainId]);
          controlDomain = domainResult?.rows?.[0] ?? null;
          if (!controlDomain) return { ok: false, reason: 'capability_control_domain_not_found' };
          if (controlDomain.status !== 'active') {
            return { ok: false, reason: 'capability_control_domain_frozen' };
          }
        }
        const stateResult = await query(CAPABILITY_SQL.readState, [capabilityId]);
        const state = stateResult?.rows?.[0];
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        if (state.capability_fingerprint !== capabilityFingerprint) return { ok: false, reason: 'capability_envelope_mismatch' };
        if (state.semantic_fence_ready !== true) {
          return { ok: false, reason: 'capability_semantic_fence_migration_required' };
        }
        if (state.revocation_state_ready !== true) {
          return { ok: false, reason: 'capability_ancestor_status_unavailable' };
        }
        const lineageRefusal = await postgresCapabilityLineageRefusal(query, state);
        if (lineageRefusal) return { ok: false, reason: lineageRefusal };
        let assertedAllowanceStatus: AllowanceStatusAssertion | null = null;
        if (typeof state.allowance_profile_id === 'string'
            && operationNamespace === state.allowance_profile_id) {
          try {
            assertedAllowanceStatus = normalizeAllowanceStatusAssertion(allowanceStatus);
          } catch {
            return { ok: false, reason: 'allowance_status_assertion_required' };
          }
          if (assertedAllowanceStatus.allowance_profile_id !== state.allowance_profile_id
              || assertedAllowanceStatus.allowance_digest !== state.allowance_digest) {
            return { ok: false, reason: 'allowance_status_binding_mismatch' };
          }
          let statusResult = await query(CAPABILITY_SQL.readAllowanceStatus, [
            assertedAllowanceStatus.allowance_profile_id,
          ]);
          let currentStatus = statusResult?.rows?.[0];
          if (!currentStatus) return { ok: false, reason: 'allowance_status_not_initialized' };
          const refusal = allowanceStatusRefusal(currentStatus, assertedAllowanceStatus);
          if (refusal) return { ok: false, reason: refusal };
        } else if (allowanceStatus !== undefined) {
          return { ok: false, reason: 'allowance_status_not_applicable' };
        }
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationNamespace, operationId]);
        if (operationResult?.rows?.[0]) {
          return {
            ok: false,
            reason: existingOperationReason(operationResult.rows[0].status),
            action_digest: actionDigest,
            action_fence_digest: actionFenceDigest,
            holding_operation_id: operationResult.rows[0].operation_id,
          };
        }
        // Same fence as the memory store: a second operation id carrying an
        // material-action fence that is already reserved, entered, or committed
        // is a duplicate authorization of one action, not a new one.
        const holderResult = await query(CAPABILITY_SQL.readActionHolder, [operationNamespace, actionFenceDigest]);
        const holder = holderResult?.rows?.[0];
        if (holder) {
          return {
            ok: false,
            reason: actionHeldReason(holder.status),
            action_digest: actionDigest,
            action_fence_digest: actionFenceDigest,
            holding_operation_id: holder.operation_id,
          };
        }
        const capabilityExpiry = Date.parse(state.expires_at);
        if (at >= capabilityExpiry) return { ok: false, reason: 'capability_expired' };
        if (currency !== state.currency) return { ok: false, reason: 'currency_mismatch' };
        const available = Number(state.budget_amount) - Number(state.consumed_amount) - Number(state.reserved_amount);
        if (!Number.isSafeInteger(available) || available < amount) return { ok: false, reason: 'budget_exceeded' };
        const token = randomUUID();
        const reserved = await query(CAPABILITY_SQL.reserveState, [capabilityId, amount]);
        if (reserved?.rowCount !== 1) return { ok: false, reason: 'budget_reservation_conflict' };
        const entryDeadlineAt = entryDeadline(at, capabilityExpiry, entryTimeoutMs);
        await query(CAPABILITY_SQL.insertOperation, [
          operationNamespace,
          capabilityId,
          operationId,
          actionDigest,
          actionFenceDigest,
          amount,
          currency,
          token,
          new Date(at).toISOString(),
          new Date(entryDeadlineAt).toISOString(),
          assertedAllowanceStatus?.revision ?? null,
          assertedAllowanceStatus?.status_epoch ?? null,
          assertedAllowanceStatus?.status_head_digest ?? null,
          controlDomain?.control_domain_id ?? null,
          controlDomain?.epoch ?? null,
        ]);
        return {
          ok: true,
          operation_id: operationId,
          action_digest: actionDigest,
          action_fence_digest: actionFenceDigest,
          reservation_token: token,
          entry_deadline_at: entryDeadlineAt,
          control_domain_id: controlDomain?.control_domain_id ?? null,
          reserved_control_epoch: controlDomain === null ? null : Number(controlDomain.epoch),
          remaining: available - amount,
        };
        });
      } catch (error) {
        // Two transactions can both observe an empty custom namespace before
        // either inserts. The database constraint decides the winner. Translate
        // that expected race into the same closed result as the preflight read;
        // the transaction contract must roll back the budget reservation first.
        if (isActionFenceConflict(error) || isLiveActionUniqueViolation(error)) {
          let holder: Record<string, any> | null = null;
          try {
            const holderResult = await transaction((query) => query(
              CAPABILITY_SQL.readActionHolder,
              [operationNamespace, actionFenceDigest],
            ));
            holder = holderResult?.rows?.[0] ?? null;
          } catch {
            // Preserve the closed conflict even if the diagnostic lookup fails.
          }
          return {
            ok: false,
            reason: holder ? actionHeldReason(holder.status) : 'action_in_flight',
            action_digest: actionDigest,
            action_fence_digest: actionFenceDigest,
            holding_operation_id: holder?.operation_id ?? null,
          };
        }
        throw error;
      }
    },
    async beginProviderEntry({ capabilityId, operationNamespace = capabilityId, operationId, reservationToken, controlDomainId, now = Date.now }: BeginProviderEntryOptions = {}) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace);
      if (typeof reservationToken !== 'string' || reservationToken.length < 16) return { ok: false, reason: 'capability_reservation_token_invalid' };
      const at = nowMs(now);
      return transaction(async (query) => {
        // Covered paths lock control domain first, then capability, allowance,
        // and operation. A supplied domain is only a lock locator; the locked
        // operation binding is rechecked below before any release or entry.
        let controlDomain: Record<string, any> | null = null;
        if (controlDomainId !== undefined) {
          validateControlDomainId(controlDomainId);
          const domainResult = await query(CAPABILITY_SQL.readControlDomain, [controlDomainId]);
          controlDomain = domainResult?.rows?.[0] ?? null;
        }
        const stateResult = await query(CAPABILITY_SQL.readState, [capabilityId]);
        const state = stateResult?.rows?.[0];
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        let currentAllowanceStatus = null;
        if (typeof state.allowance_profile_id === 'string'
            && operationNamespace === state.allowance_profile_id) {
          const statusResult = await query(CAPABILITY_SQL.readAllowanceStatus, [state.allowance_profile_id]);
          currentAllowanceStatus = statusResult?.rows?.[0] ?? null;
        }
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationNamespace, operationId]);
        const operation = operationResult?.rows?.[0];
        if (!operation) return { ok: false, reason: 'capability_operation_not_found' };
        if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
        if (operation.status !== 'reserved') {
          return {
            ok: false,
            reason: operation.status === 'provider_entered'
              ? 'capability_provider_entry_already_recorded'
              : 'capability_operation_already_finalized',
          };
        }
        if (operation.reservation_token !== reservationToken) return { ok: false, reason: 'capability_reservation_owner_mismatch' };
        if (operation.control_domain_id !== null
            && operation.control_domain_id !== undefined) {
          if (controlDomainId === undefined) {
            return { ok: false, reason: 'capability_control_domain_required' };
          }
          if (operation.control_domain_id !== controlDomainId) {
            return { ok: false, reason: 'capability_control_domain_binding_mismatch' };
          }
          if (!controlDomain) {
            return { ok: false, reason: 'capability_control_domain_unavailable' };
          }
          if (controlDomain.status !== 'active'
              || Number(controlDomain.epoch) !== Number(operation.reserved_control_epoch)) {
            const releaseReason = controlDomain.status === 'frozen'
              ? 'control_domain_frozen'
              : 'control_domain_epoch_mismatch';
            const released = await query(CAPABILITY_SQL.releaseControlBlockedOperation, [
              operationNamespace,
              operationId,
              capabilityId,
              reservationToken,
              controlDomainId,
              releaseReason,
              new Date(at).toISOString(),
            ]);
            if (released?.rowCount !== 1) {
              throw new Error('control-domain release lost operation ownership; transaction must roll back');
            }
            const restored = await query(CAPABILITY_SQL.releaseReservedState, [capabilityId, operation.amount]);
            if (restored?.rowCount !== 1) {
              throw new Error('control-domain release lost budget ownership; transaction must roll back');
            }
            return {
              ok: false,
              reason: controlDomain.status === 'frozen'
                ? 'capability_control_domain_frozen'
                : 'capability_control_domain_epoch_mismatch',
              outcome: 'not_entered',
              reservation: 'released',
            };
          }
        } else if (controlDomainId !== undefined) {
          return { ok: false, reason: 'capability_control_domain_binding_mismatch' };
        }
        if (typeof state.allowance_profile_id === 'string'
            && operationNamespace === state.allowance_profile_id) {
          const reservedAllowanceStatus = reservedAllowanceStatusAssertion(state, operation);
          if (!reservedAllowanceStatus) return { ok: false, reason: 'allowance_status_assertion_required' };
          if (!currentAllowanceStatus) return { ok: false, reason: 'allowance_status_not_initialized' };
          const refusal = allowanceStatusRefusal(currentAllowanceStatus, reservedAllowanceStatus);
          if (refusal) return { ok: false, reason: refusal };
        }
        const deadline = Date.parse(operation.entry_deadline_at);
        if (!Number.isFinite(deadline)) return { ok: false, reason: 'capability_recovery_deadline_unavailable' };
        if (at >= deadline) return { ok: false, reason: 'capability_reservation_expired' };
        const entered = await query(CAPABILITY_SQL.beginProviderEntry, [
          operationNamespace,
          operationId,
          capabilityId,
          reservationToken,
          new Date(at).toISOString(),
        ]);
        if (entered?.rowCount !== 1) throw new Error('capability provider-entry transition lost ownership; transaction must roll back');
        const consumed = await query(CAPABILITY_SQL.commitState, [capabilityId, operation.amount]);
        if (consumed?.rowCount !== 1) throw new Error('capability provider-entry budget transition conflicted; transaction must roll back');
        return { ok: true, operation_id: operationId, provider_entry_at: at, consumed: null, remaining: null };
      });
    },
    async recoverPreEntrySpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, reservationToken, disposition, now = Date.now }: RecoverPreEntrySpendOptions = {}) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace); validateActionDigest(actionDigest);
      const at = nowMs(now);
      return transaction(async (query) => {
        // Match reserveSpend and beginProviderEntry: capability state is the
        // first lock whenever a transition can move reserved budget. Locking
        // the operation first here would invert the provider-entry order.
        const stateResult = await query(CAPABILITY_SQL.readState, [capabilityId]);
        const state = stateResult?.rows?.[0];
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationNamespace, operationId]);
        const operation = operationResult?.rows?.[0];
        if (!operation) return { ok: false, reason: 'capability_operation_not_found' };
        if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
        if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
        if (disposition !== undefined) {
          if (disposition !== 'release' && disposition !== 'burn') {
            return { ok: false, reason: 'capability_provider_entry_disposition_invalid' };
          }
          if (typeof reservationToken !== 'string' || reservationToken.length < 16) {
            return { ok: false, reason: 'capability_reservation_token_invalid' };
          }
          if (operation.reservation_token !== reservationToken) {
            return { ok: false, reason: 'capability_reservation_owner_mismatch' };
          }
          if (disposition === 'release'
              && operation.status === 'released'
              && operation.outcome === 'not_entered'
              && operation.release_reason === 'provider_entry_guard_release') {
            return { ok: true, idempotent: true, outcome: 'not_entered', released: Number(operation.amount), remaining: null };
          }
          if (disposition === 'burn'
              && operation.status === 'committed'
              && operation.outcome === 'refused') {
            return { ok: true, idempotent: true, outcome: 'refused', consumed: Number(operation.amount), remaining: null };
          }
          if (operation.status !== 'reserved') return { ok: false, reason: 'capability_provider_entry_recorded' };
          if (disposition === 'burn') {
            const committed = await query(CAPABILITY_SQL.commitOperation, [
              operationNamespace,
              operationId,
              capabilityId,
              'refused',
              new Date(at).toISOString(),
              reservationToken,
              'reserved',
            ]);
            if (committed?.rowCount !== 1) throw new Error('capability provider-entry burn lost ownership; transaction must roll back');
            const consumed = await query(CAPABILITY_SQL.commitState, [capabilityId, operation.amount]);
            if (consumed?.rowCount !== 1) throw new Error('capability provider-entry burn budget transition conflicted; transaction must roll back');
            return { ok: true, outcome: 'refused', consumed: Number(operation.amount), remaining: null };
          }
          const released = await query(CAPABILITY_SQL.releaseGuardRefusedOperation, [
            operationNamespace,
            operationId,
            capabilityId,
            actionDigest,
            reservationToken,
            new Date(at).toISOString(),
          ]);
          if (released?.rowCount !== 1) throw new Error('capability provider-entry release lost ownership; transaction must roll back');
          const restored = await query(CAPABILITY_SQL.releaseReservedState, [capabilityId, operation.amount]);
          if (restored?.rowCount !== 1) throw new Error('capability provider-entry release budget transition conflicted; transaction must roll back');
          return { ok: true, outcome: 'not_entered', released: Number(operation.amount), remaining: null };
        }
        if (operation.status === 'released' && operation.outcome === 'not_entered'
            && operation.release_reason === 'pre_entry_deadline_elapsed') {
          return { ok: true, idempotent: true, outcome: 'not_entered', released: Number(operation.amount), remaining: null };
        }
        if (operation.status !== 'reserved') return { ok: false, reason: 'capability_provider_entry_recorded' };
        const deadline = Date.parse(operation.entry_deadline_at);
        if (!Number.isFinite(deadline)) return { ok: false, reason: 'capability_recovery_deadline_unavailable' };
        if (at < deadline) return { ok: false, reason: 'capability_recovery_deadline_active' };
        const released = await query(CAPABILITY_SQL.recoverPreEntryOperation, [
          operationNamespace,
          operationId,
          capabilityId,
          actionDigest,
          new Date(at).toISOString(),
        ]);
        if (released?.rowCount !== 1) throw new Error('capability pre-entry recovery lost ownership; transaction must roll back');
        const restored = await query(CAPABILITY_SQL.releaseReservedState, [capabilityId, operation.amount]);
        if (restored?.rowCount !== 1) throw new Error('capability pre-entry budget recovery conflicted; transaction must roll back');
        return { ok: true, outcome: 'not_entered', released: Number(operation.amount), remaining: null };
      });
    },
    async commitSpend({ capabilityId, operationNamespace = capabilityId, operationId, reservationToken, outcome = 'executed', now = Date.now }: CommitSpendOptions = {}) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace);
      if (typeof reservationToken !== 'string' || reservationToken.length < 16) return { ok: false, reason: 'capability_reservation_token_invalid' };
      if (!['executed', 'indeterminate', 'delegated'].includes(outcome)) return { ok: false, reason: 'capability_outcome_invalid' };
      const at = nowMs(now);
      return transaction(async (query) => {
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationNamespace, operationId]);
        const operation = operationResult?.rows?.[0];
        if (!operation) return { ok: false, reason: 'capability_operation_not_found' };
        if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
        const expectedStatus = outcome === 'delegated' ? 'reserved' : 'provider_entered';
        if (operation.status !== expectedStatus) {
          return {
            ok: false,
            reason: operation.status === 'reserved'
              ? 'capability_provider_entry_not_recorded'
              : 'capability_operation_already_finalized',
          };
        }
        if (operation.reservation_token !== reservationToken) return { ok: false, reason: 'capability_reservation_owner_mismatch' };
        if (outcome === 'delegated') {
          const deadline = Date.parse(operation.entry_deadline_at);
          if (!Number.isFinite(deadline)) return { ok: false, reason: 'capability_recovery_deadline_unavailable' };
          if (at >= deadline) return { ok: false, reason: 'capability_reservation_expired' };
        }
        const committed = await query(CAPABILITY_SQL.commitOperation, [operationNamespace, operationId, capabilityId, outcome, new Date(at).toISOString(), reservationToken, expectedStatus]);
        if (committed?.rowCount !== 1) throw new Error('capability operation transition lost ownership; transaction must roll back');
        if (outcome === 'delegated') {
          const updated = await query(CAPABILITY_SQL.commitState, [capabilityId, operation.amount]);
          if (updated?.rowCount !== 1) throw new Error('capability state transition conflicted; transaction must roll back');
        }
        return { ok: true, outcome, consumed: null, remaining: null };
      });
    },
    async reconcileSpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, evidenceDigest, evidenceProfile, evidenceFinal, evidenceObservedAt, outcome = 'executed', now = Date.now }: ReconcileSpendOptions = {}) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace);
      if (typeof actionDigest !== 'string' || !ACTION_DIGEST_RE.test(actionDigest)
          || typeof evidenceDigest !== 'string' || !ACTION_DIGEST_RE.test(evidenceDigest)
          || !['executed', 'not_entered'].includes(outcome)) {
        return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
      }
      if (outcome === 'not_entered') {
        try {
          validateEvidenceProfile(evidenceProfile);
          if (evidenceFinal !== true) throw new TypeError('negative evidence must be final');
          evidenceObservedAtMs(evidenceObservedAt);
        } catch {
          return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
        }
      }
      const at = nowMs(now);
      return transaction(async (query) => {
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationNamespace, operationId]);
        const operation = operationResult?.rows?.[0];
        if (!operation) return { ok: false, reason: 'capability_operation_not_found' };
        if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
        if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
        if (outcome === 'not_entered') {
          const observedAt = evidenceObservedAtMs(evidenceObservedAt);
          if (observedAt > at) return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
          if (operation.status === 'released') {
            return operation.outcome === 'not_entered'
                && operation.release_evidence_digest === evidenceDigest
                && operation.release_evidence_profile === evidenceProfile
              ? { ok: true, idempotent: true, outcome }
              : { ok: false, reason: 'capability_reconciliation_conflict' };
          }
          const deadline = Date.parse(operation.entry_deadline_at);
          if (!Number.isFinite(deadline)) return { ok: false, reason: 'capability_recovery_deadline_unavailable' };
          if (at < deadline) return { ok: false, reason: 'capability_recovery_deadline_active' };
          if (observedAt < deadline) return { ok: false, reason: 'capability_reconciliation_evidence_stale' };
          if (operation.status === 'reserved') {
            const released = await query(CAPABILITY_SQL.releaseReservedOperation, [
              operationNamespace,
              operationId,
              capabilityId,
              actionDigest,
              evidenceProfile,
              evidenceDigest,
              new Date(observedAt).toISOString(),
              new Date(at).toISOString(),
            ]);
            if (released?.rowCount !== 1) throw new Error('capability authenticated pre-entry release conflicted; transaction must roll back');
            const restored = await query(CAPABILITY_SQL.releaseReservedState, [capabilityId, operation.amount]);
            if (restored?.rowCount !== 1) throw new Error('capability authenticated pre-entry budget recovery conflicted; transaction must roll back');
            return { ok: true, idempotent: false, outcome };
          }
          if (operation.reconciliation_outcome) {
            return operation.reconciliation_outcome === outcome
                && operation.reconciliation_evidence_digest === evidenceDigest
              ? { ok: true, idempotent: true, outcome }
              : { ok: false, reason: 'capability_reconciliation_conflict' };
          }
          if (operation.status === 'provider_entered') {
            const committed = await query(CAPABILITY_SQL.commitOperation, [
              operationNamespace,
              operationId,
              capabilityId,
              'indeterminate',
              new Date(at).toISOString(),
              operation.reservation_token,
              'provider_entered',
            ]);
            if (committed?.rowCount !== 1) throw new Error('capability post-entry negative reconciliation lost ownership; transaction must roll back');
          } else if (operation.status !== 'committed' || operation.outcome !== 'indeterminate') {
            return { ok: false, reason: 'capability_operation_not_indeterminate' };
          }
          const reconciled = await query(CAPABILITY_SQL.reconcileOperation, [
            operationNamespace,
            operationId,
            capabilityId,
            outcome,
            evidenceDigest,
            new Date(at).toISOString(),
          ]);
          if (reconciled?.rowCount !== 1) throw new Error('capability post-entry negative reconciliation conflicted; transaction must roll back');
          return { ok: true, idempotent: false, outcome };
        }
        if (operation.reconciliation_outcome) {
          return operation.reconciliation_outcome === outcome
              && operation.reconciliation_evidence_digest === evidenceDigest
            ? { ok: true, idempotent: true, outcome }
            : { ok: false, reason: 'capability_reconciliation_conflict' };
        }
        if (operation.status === 'reserved' || operation.status === 'provider_entered') {
          const committed = await query(CAPABILITY_SQL.commitOperation, [
            operationNamespace,
            operationId,
            capabilityId,
            'indeterminate',
            new Date(at).toISOString(),
            operation.reservation_token,
            operation.status,
          ]);
          if (committed?.rowCount !== 1) throw new Error('capability indeterminate recovery lost ownership; transaction must roll back');
          if (operation.status === 'reserved') {
            const consumed = await query(CAPABILITY_SQL.commitState, [capabilityId, operation.amount]);
            if (consumed?.rowCount !== 1) throw new Error('capability indeterminate budget recovery conflicted; transaction must roll back');
          }
        } else if (operation.status !== 'committed' || operation.outcome !== 'indeterminate') {
          return { ok: false, reason: 'capability_operation_not_indeterminate' };
        }
        const updated = await query(CAPABILITY_SQL.reconcileOperation, [
          operationNamespace,
          operationId,
          capabilityId,
          outcome,
          evidenceDigest,
          new Date(at).toISOString(),
        ]);
        if (updated?.rowCount !== 1) throw new Error('capability reconciliation transition conflicted; transaction must roll back');
        return { ok: true, idempotent: false, outcome };
      });
    },
    async getControlDomain(controlDomainId) {
      validateControlDomainId(controlDomainId);
      return transaction(async (query) => {
        const result = await query(CAPABILITY_SQL.readControlDomain, [controlDomainId]);
        const domain = result?.rows?.[0];
        return domain ? Object.freeze({ ...domain, epoch: Number(domain.epoch) }) : null;
      });
    },
    async getControlDomainEvent(operationId) {
      validateOperationId(operationId);
      return transaction(async (query) => {
        const result = await query(CAPABILITY_SQL.readControlDomainEvent, [operationId]);
        const event = result?.rows?.[0];
        return event ? Object.freeze({ ...event, epoch_at_event: Number(event.epoch_at_event) }) : null;
      });
    },
  };
}

function verifySecret(capability, secret) {
  const normalized = digestSecret(secret);
  return equalHash(capability.secret_hash, normalized.hash);
}

function capabilityAmount(action, capability, verifiedAction = action) {
  const amount = validateAmount(action?.amount, 'action.amount');
  const currency = validateCurrency(action?.currency);
  if (currency !== capability.budget.currency) throw new TypeError('capability action currency does not match the budget');
  const verifiedAmount = Number.isSafeInteger(verifiedAction?.amount)
    ? verifiedAction.amount
    : verifiedAction?.amount_usd;
  if (verifiedAmount !== amount || verifiedAction?.currency !== currency) {
    throw new TypeError('capability budget projection does not match the verified action');
  }
  if (amount <= 0) throw new TypeError('capability action amount must be greater than zero');
  return { amount, currency };
}

/**
 * Execute one spend under a capability. The base EP receipt is checked on
 * every spend with consumptionMode=none; the capability store is the replay
 * and budget authority. The external function is entered only after the
 * atomic reservation and durable provider-entry transition succeed. `action` is the budget projection; the
 * external function receives only a clone of the exact verified
 * `observedAction ?? action`. Any exception after entry permanently commits
 * the reserved amount as indeterminate.
 *
 * @param {object} [options]
 * @param {object} [options.capabilityReceipt]
 * @param {Buffer|string} [options.secret]
 * @param {{amount:number,currency:string}} [options.action]
 * @param {any} [options.store]
 * @param {Function} [options.executeAction]
 * @param {any} [options.gate]
 * @param {object} [options.selector]
 * @param {object|null} [options.observedAction]
 * @param {string[]} [options.trustedIssuerKeys]
 * @param {Function|null} [options.verifyBaseReceipt]
 * @param {Function|null} [options.resolveCaid]
 * @param {Function|null} [options.verifyActionProfile]
 * @param {object|null} [options.executionDomain] relying-party executor and
 *   atomic state-domain binding. Aggregate accounting is claimed only when
 *   the pinned digest matches an atomic-capable store; otherwise an explicit
 *   single-executor binding is required for fallback.
 * @param {boolean} [options.requireHumanAuthorization]
 * @param {unknown} [options.humanAuthorization] native per-action artifact
 * @param {object|null} [options.humanAuthorizationPins] relying-party trust inputs
 * @param {Function|null} [options.verifyHumanAuthorization] native verifier
 * @param {Function|null} [options.providerEntryGuard] final relying-party check
 *   after the atomic budget reservation and immediately before provider entry.
 *   A refusal atomically releases, burns, or holds the pre-entry reservation
 *   according to the guard's closed disposition; it never invokes the provider.
 * @param {string} [options.controlDomainId] optional Gate execution-control
 *   domain. A guard-owned requirement is derived automatically; an explicit
 *   different domain is refused.
 * @param {string|null} [options.operationId]
 * @param {number|(() => number)} [options.now]
 * @param {boolean} [options.thresholdSecretVerified]
 */
export async function executeWithCapability({
  capabilityReceipt,
  secret,
  action,
  store,
  executeAction,
  gate = null,
  selector = {},
  observedAction = null,
  trustedIssuerKeys = [],
  verifyBaseReceipt = null,
  resolveCaid = null,
  verifyActionProfile = null,
  executionDomain = null,
  requireHumanAuthorization = false,
  humanAuthorization = undefined,
  humanAuthorizationPins = undefined,
  verifyHumanAuthorization = undefined,
  providerEntryGuard = null,
  allowanceStatus,
  controlDomainId,
  operationId = null,
  now = Date.now,
  thresholdSecretVerified = false,
}: ExecuteWithCapabilityOptions = {}): Promise<ExecuteWithCapabilityResult> {
  const verified = verifyCapabilityReceipt(capabilityReceipt, { trustedIssuerKeys });
  if (!verified.ok) return { ok: false, reason: verified.reason };
  if ((verified.capability.threshold.m !== 1 || verified.capability.threshold.n !== 1) && thresholdSecretVerified !== true) return { ok: false, reason: 'threshold_shares_required' };
  if (!verifySecret(verified.capability, secret)) return { ok: false, reason: 'invalid_secret' };
  if (!store
      || typeof store.reserveSpend !== 'function'
      || typeof store.beginProviderEntry !== 'function'
      || typeof store.commitSpend !== 'function') {
    return { ok: false, reason: 'capability_store_required' };
  }
  if (typeof executeAction !== 'function') throw new TypeError('executeWithCapability requires executeAction');
  if (providerEntryGuard !== null && typeof providerEntryGuard !== 'function') {
    throw new TypeError('providerEntryGuard must be a function when configured');
  }
  const requiredControlDomainId = requiredProviderEntryControlDomain(providerEntryGuard);
  if (requiredControlDomainId !== null
      && controlDomainId !== undefined
      && controlDomainId !== requiredControlDomainId) {
    return { ok: false, reason: 'capability_provider_entry_control_domain_mismatch' };
  }
  const effectiveControlDomainId = requiredControlDomainId ?? controlDomainId;
  if (requiredControlDomainId !== null && store?.controlDomainCapable !== true) {
    return { ok: false, reason: 'capability_control_domain_store_required' };
  }
  if (typeof requireHumanAuthorization !== 'boolean') {
    return { ok: false, reason: 'capability_human_authorization_configuration_invalid' };
  }
  if (providerEntryGuard !== null
      && (store.providerEntryDispositionCapable !== true
        || typeof store.recoverPreEntrySpend !== 'function')) {
    return { ok: false, reason: 'capability_store_disposition_required' };
  }
  try {
    validateOperationId(operationId);
  } catch {
    return { ok: false, reason: 'capability_operation_id_required' };
  }
  let immutableAction;
  let scope;
  try {
    immutableAction = deepFreeze(structuredClone(observedAction ?? action));
    scope = verifyCapabilityScope(verified.capability, immutableAction, operationId as string, {
      resolveCaid,
      verifyActionProfile,
    });
  } catch {
    return { ok: false, reason: 'capability_action_invalid' };
  }
  if (!scope.ok) return { ok: false, reason: scope.reason, scope };
  const domain = capabilityBudgetGuarantee(store, executionDomain);
  if (!domain.ok) return { ok: false, reason: domain.reason };
  const budgetGuarantee = domain.guarantee;
  const human = await verifyPerActionHumanAuthorization({
    required: requireHumanAuthorization,
    artifact: humanAuthorization,
    pins: humanAuthorizationPins,
    verifier: verifyHumanAuthorization,
    action: immutableAction,
    actionDigest: scope.action_digest,
  });
  if (!human.ok) {
    return {
      ok: false,
      reason: human.reason,
      budget_guarantee: budgetGuarantee,
      action_digest: scope.action_digest,
    };
  }
  const humanAuthorizationResult = human.result;
  const composition = {
    budget_guarantee: budgetGuarantee,
    ...(humanAuthorizationResult
      ? { human_authorization: humanAuthorizationResult }
      : {}),
  };
  let authorization: Record<string, any> | null = null;
  if (gate && typeof gate.check === 'function') {
    authorization = await gate.check({
      selector,
      receipt: verified.receipt,
      observedAction: immutableAction,
      consumptionMode: 'none',
      capability: { capabilityReceipt, action: immutableAction, operationId },
    });
    if (!authorization?.allow) return {
      ok: false,
      reason: 'base_receipt_rejected',
      authorization,
      ...composition,
    };
  } else if (typeof verifyBaseReceipt === 'function') {
    const result = await verifyBaseReceipt(verified.receipt, {
      action: immutableAction,
      selector,
      observedAction: immutableAction,
      scope,
    });
    if (result !== true && result?.ok !== true) return {
      ok: false,
      reason: 'base_receipt_rejected',
      authorization: result,
      ...composition,
    };
  } else {
    return { ok: false, reason: 'base_receipt_verifier_required', ...composition };
  }
  let spend;
  try {
    // `action` is the budget projection used by Gate integrations; it must
    // match the verified action and can never reach the effect.
    spend = capabilityAmount(action, verified.capability, immutableAction);
  } catch (error) {
    return {
      ok: false,
      reason: (error as Error)?.message || 'capability_action_invalid',
      authorization,
      ...composition,
    };
  }
  const reserved = await store.reserveSpend({
    capabilityId: verified.capability.id,
    capabilityFingerprint: capabilityEnvelopeFingerprint(capabilityReceipt),
    operationNamespace: scope.operation_namespace ?? verified.capability.id,
    operationId,
    actionDigest: scope.action_digest,
    actionFenceDigest: scope.action_fence_digest,
    amount: spend.amount,
    currency: spend.currency,
    ...(allowanceStatus ? { allowanceStatus } : {}),
    ...(effectiveControlDomainId !== undefined
      ? { controlDomainId: effectiveControlDomainId }
      : {}),
    now,
  });
  if (!reserved?.ok) {
    return {
      ok: false,
      reason: reserved?.reason || 'capability_reservation_refused',
      authorization,
      ...composition,
      operation_id: operationId,
      action_digest: reserved?.action_digest ?? scope.action_digest,
      action_fence_digest: reserved?.action_fence_digest ?? scope.action_fence_digest,
      ...(Object.hasOwn(reserved ?? {}, 'holding_operation_id')
        ? { holding_operation_id: reserved.holding_operation_id }
        : {}),
      ...(scope.caid ? { caid: scope.caid } : {}),
    };
  }
  // `undefined` means no provider-entry guard was configured. Preserve that
  // distinction so enabling this evidence channel does not change the return
  // shape or canonical bytes of existing no-guard integrations. A configured
  // guard that returns no evidence is represented explicitly as `null`.
  let providerEntryEvidence: Readonly<Record<string, any>> | null | undefined = undefined;
  if (providerEntryGuard) {
    const baseEntryContext = providerEntryContext({
      authorization,
      selector,
      observedAction: immutableAction,
      capability: {
        id: verified.capability.id,
        operation_id: operationId,
        action_digest: scope.action_digest,
        action_fence_digest: scope.action_fence_digest,
      },
      now,
    });
    const entryVerdict = await evaluateProviderEntryGuard(
      providerEntryGuard,
      Object.freeze({
        ...baseEntryContext,
        human_authorization: humanAuthorizationResult
          ? structuredClone(humanAuthorizationResult)
          : null,
        budget_guarantee: structuredClone(budgetGuarantee),
      }),
    );
    if (!entryVerdict || entryVerdict.ok !== true) {
      if (entryVerdict?.reason === 'provider_entry_guard_disposition_invalid') {
        return {
          ok: false,
          reason: 'capability_provider_entry_disposition_invalid',
          status: entryVerdict?.status ?? 409,
          authorization,
          ...composition,
          provider_entry_evidence: entryVerdict?.evidence ?? null,
          operation_id: operationId,
          action_digest: scope.action_digest,
          action_fence_digest: scope.action_fence_digest,
          ...(scope.caid ? { caid: scope.caid } : {}),
        };
      }
      const suppliedDisposition = entryVerdict?.reservation;
      // Absence is uncertainty, not proof that provider entry did not happen.
      // Authority is restored only when a guard explicitly returns `release`.
      const disposition = suppliedDisposition === undefined ? 'hold' : suppliedDisposition;
      if (!['release', 'burn', 'hold'].includes(disposition)) {
        return {
          ok: false,
          reason: 'capability_provider_entry_disposition_invalid',
          status: entryVerdict?.status ?? 409,
          authorization,
          ...composition,
          provider_entry_evidence: entryVerdict?.evidence ?? null,
          operation_id: operationId,
          action_digest: scope.action_digest,
          action_fence_digest: scope.action_fence_digest,
          ...(scope.caid ? { caid: scope.caid } : {}),
        };
      }
      if (disposition !== 'hold') {
        const transition = await store.recoverPreEntrySpend({
          capabilityId: verified.capability.id,
          operationNamespace: scope.operation_namespace ?? verified.capability.id,
          operationId,
          actionDigest: scope.action_digest,
          reservationToken: reserved.reservation_token,
          disposition,
          now,
        }).catch(() => ({ ok: false }));
        if (!transition?.ok) {
          return {
            ok: false,
            reason: 'capability_provider_entry_reservation_transition_indeterminate',
            status: 503,
            authorization,
            ...composition,
            provider_entry_evidence: entryVerdict?.evidence ?? null,
            operation_id: operationId,
            action_digest: scope.action_digest,
            action_fence_digest: scope.action_fence_digest,
            ...(scope.caid ? { caid: scope.caid } : {}),
          };
        }
      }
      return {
        ok: false,
        reason: typeof entryVerdict?.reason === 'string'
          ? entryVerdict.reason
          : 'provider_entry_guard_refused',
        status: entryVerdict?.status ?? 409,
        authorization,
        ...composition,
        provider_entry_evidence: entryVerdict?.evidence ?? null,
        operation_id: operationId,
        action_digest: scope.action_digest,
        action_fence_digest: scope.action_fence_digest,
        ...(scope.caid ? { caid: scope.caid } : {}),
      };
    }
    providerEntryEvidence = entryVerdict.evidence ?? null;
  }
  const providerEntry = await store.beginProviderEntry({
    capabilityId: verified.capability.id,
    operationNamespace: scope.operation_namespace ?? verified.capability.id,
    operationId,
    reservationToken: reserved.reservation_token,
    ...(effectiveControlDomainId !== undefined
      ? { controlDomainId: effectiveControlDomainId }
      : {}),
    now,
  }).catch(() => ({ ok: false, reason: 'capability_provider_entry_indeterminate' }));
  if (!providerEntry?.ok) {
    return {
      ok: false,
      reason: providerEntry?.reason || 'capability_provider_entry_indeterminate',
      authorization,
      ...composition,
      ...(providerEntryEvidence !== undefined
        ? { provider_entry_evidence: providerEntryEvidence }
        : {}),
      operation_id: operationId,
      action_digest: scope.action_digest,
      action_fence_digest: scope.action_fence_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
    };
  }
  try {
    const result = await executeAction(structuredClone(immutableAction), {
      capabilityReceipt,
      authorization,
      human_authorization: humanAuthorizationResult,
      budget_guarantee: budgetGuarantee,
      operation_id: operationId,
      action_digest: scope.action_digest,
      action_fence_digest: scope.action_fence_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
      observed_action: immutableAction,
      ...(providerEntryEvidence !== undefined
        ? { provider_entry_evidence: providerEntryEvidence }
        : {}),
      reservation: reserved,
      provider_entry: providerEntry,
    });
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationNamespace: scope.operation_namespace ?? verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'executed', now });
    if (!committed?.ok) {
      return {
        ok: false,
        reason: 'capability_commit_indeterminate',
        authorization,
        ...composition,
        ...(providerEntryEvidence !== undefined
          ? { provider_entry_evidence: providerEntryEvidence }
          : {}),
        result,
        operation_id: operationId,
        action_digest: scope.action_digest,
        action_fence_digest: scope.action_fence_digest,
        ...(scope.caid ? { caid: scope.caid } : {}),
      };
    }
    return {
      ok: true,
      result,
      authorization,
      ...composition,
      ...(providerEntryEvidence !== undefined
        ? { provider_entry_evidence: providerEntryEvidence }
        : {}),
      operation_id: operationId,
      action_digest: scope.action_digest,
      action_fence_digest: scope.action_fence_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
      remaining: committed.remaining,
    };
  } catch (error) {
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationNamespace: scope.operation_namespace ?? verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'indeterminate', now }).catch(() => ({ ok: false }));
    return {
      ok: false,
      reason: committed.ok ? 'effect_indeterminate' : 'capability_commit_indeterminate',
      authorization,
      ...composition,
      ...(providerEntryEvidence !== undefined
        ? { provider_entry_evidence: providerEntryEvidence }
        : {}),
      operation_id: operationId,
      action_digest: scope.action_digest,
      action_fence_digest: scope.action_fence_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
    };
  }
}

/**
 * Execute a capability requiring m-of-n Shamir shares.
 * @param {Record<string, any>} [args] capabilityReceipt, shares, and executeWithCapability passthrough options
 */
export async function executeWithThreshold({ capabilityReceipt, shares, ...options }: ExecuteWithCapabilityOptions & { shares?: string[] } = {}) {
  const verified = verifyCapabilityReceipt(capabilityReceipt, { trustedIssuerKeys: options.trustedIssuerKeys || [] });
  if (!verified.ok) return { ok: false, reason: verified.reason };
  try {
    const secret = reconstructCapabilitySecret(shares, verified.capability.threshold);
    return executeWithCapability({ ...options, capabilityReceipt, secret, thresholdSecretVerified: true });
  } catch (error) {
    return { ok: false, reason: (error as Error)?.message === 'insufficient capability shares' ? 'insufficient_shares' : 'invalid_shares' };
  }
}

/**
 * Authentically reconcile a capability operation. Positive evidence records an
 * executed outcome without restoring budget. Final authenticated negative
 * evidence may release only a still-reserved operation after its durable
 * provider-entry deadline. Once provider entry consumes authority, negative
 * evidence records the reconciled outcome but never restores authority.
 *
 * @param {object} [options]
 * @param {any} [options.store]
 * @param {string} [options.capabilityId]
 * @param {string} [options.operationId]
 * @param {object} [options.action]
 * @param {object} [options.evidence]
 * @param {Function} [options.verifyEvidence]
 * @param {number|(() => number)} [options.now]
 */
export async function reconcileCapabilityOperation({
  store,
  capabilityId,
  operationNamespace = capabilityId,
  operationId,
  action,
  evidence,
  verifyEvidence,
  now = Date.now,
}: {
  store?: Record<string, any>;
  capabilityId?: string;
  operationNamespace?: string;
  operationId?: string;
  action?: Record<string, any>;
  evidence?: Record<string, any>;
  verifyEvidence?: (...args: any[]) => any;
  now?: number | (() => number);
} = {}) {
  if (!store || typeof store.reconcileSpend !== 'function') return { ok: false, reason: 'capability_reconciliation_store_required' };
  try {
    validateCapabilityId(capabilityId);
    validateOperationId(operationId);
    validateOperationNamespace(operationNamespace);
  } catch {
    return { ok: false, reason: 'capability_reconciliation_operation_invalid' };
  }
  if (typeof verifyEvidence !== 'function') return { ok: false, reason: 'capability_reconciliation_verifier_required' };
  let actionDigest;
  let verified;
  try {
    const immutableAction = structuredClone(action);
    actionDigest = capabilityActionDigest(immutableAction);
    verified = await verifyEvidence(structuredClone(evidence), {
      capability_id: capabilityId,
      operation_namespace: operationNamespace,
      operation_id: operationId,
      action: immutableAction,
      action_digest: actionDigest,
    });
  } catch {
    return { ok: false, reason: 'capability_reconciliation_evidence_rejected' };
  }
  const negative = isRecord(verified) && verified.outcome === 'not_entered';
  if (!isRecord(verified) || verified.valid !== true
      || !['executed', 'not_entered'].includes(verified.outcome)
      || verified.action_digest !== actionDigest
      || typeof verified.evidence_digest !== 'string'
      || !ACTION_DIGEST_RE.test(verified.evidence_digest)) {
    return { ok: false, reason: 'capability_reconciliation_evidence_rejected' };
  }
  if (negative && (verified.authenticated !== true
      || verified.final !== true
      || verified.capability_id !== capabilityId
      || verified.operation_namespace !== operationNamespace
      || verified.operation_id !== operationId
      || typeof verified.observed_at !== 'string')) {
    return { ok: false, reason: 'capability_reconciliation_evidence_rejected' };
  }
  if (negative) {
    try {
      validateEvidenceProfile(verified.evidence_profile);
      evidenceObservedAtMs(verified.observed_at);
    } catch {
      return { ok: false, reason: 'capability_reconciliation_evidence_rejected' };
    }
  }
  const result = await store.reconcileSpend({
    capabilityId,
    operationNamespace,
    operationId,
    actionDigest,
    evidenceDigest: verified.evidence_digest,
    ...(negative ? {
      evidenceProfile: verified.evidence_profile,
      evidenceFinal: true,
      evidenceObservedAt: verified.observed_at,
    } : {}),
    outcome: verified.outcome,
    now,
  });
  return result?.ok
    ? {
      ok: true,
      outcome: verified.outcome,
      action_digest: actionDigest,
      evidence_digest: verified.evidence_digest,
      ...(negative ? { evidence_profile: verified.evidence_profile } : {}),
      idempotent: result.idempotent === true,
    }
    : { ok: false, reason: result?.reason || 'capability_reconciliation_refused' };
}

/**
 * Issue a bounded child capability from a parent capability.
 *
 * Delegation is issuer-authorized metadata plus an atomic parent spend. The
 * parent budget is committed as `delegated` before the child is registered;
 * if child registration fails, the safe result is an orphaned child issuance
 * that must be reconciled, never a child with unbacked budget.
 *
 * @param {object} [options]
 * @param {object} [options.parentCapabilityReceipt]
 * @param {Buffer|string} [options.parentSecret]
 * @param {KeyMaterial} [options.issuerPrivateKey]
 * @param {CapabilityBudget} [options.budget]
 * @param {string|number} [options.expiry]
 * @param {{m:number,n:number}} [options.threshold]
 * @param {'direct'|'cascade'} [options.revocationMode]
 * @param {object|null} [options.scope]
 * @param {string} [options.delegateId]
 * @param {string} [options.capabilityId]
 * @param {Buffer|string} [options.secret]
 * @param {any} [options.store]
 * @param {string[]} [options.trustedIssuerKeys]
 * @param {string|null} [options.operationId]
 * @param {number|(() => number)} [options.now]
 */
export async function delegateCapabilityReceipt({
  parentCapabilityReceipt,
  parentSecret,
  issuerPrivateKey,
  budget,
  expiry,
  threshold = { m: 1, n: 1 },
  revocationMode,
  scope = null,
  delegateId,
  capabilityId = randomUUID(),
  secret = randomBytes(HASH_BYTES),
  store,
  trustedIssuerKeys = [],
  operationId = null,
  now = Date.now,
}: {
  parentCapabilityReceipt?: Record<string, any>;
  parentSecret?: Buffer | string;
  issuerPrivateKey?: KeyMaterial;
  budget?: CapabilityBudget;
  expiry?: string | number;
  threshold?: { m: number; n: number };
  revocationMode?: CapabilityRevocationMode;
  scope?: Record<string, any> | null;
  delegateId?: string;
  capabilityId?: string;
  secret?: Buffer | string;
  store?: Record<string, any>;
  trustedIssuerKeys?: string[];
  operationId?: string | null;
  now?: number | (() => number);
} = {}) {
  const verified = verifyCapabilityReceipt(parentCapabilityReceipt, { trustedIssuerKeys });
  if (!verified.ok) return { ok: false, reason: verified.reason };
  if (!verifySecret(verified.capability, parentSecret)) return { ok: false, reason: 'invalid_parent_secret' };
  if (!store || typeof store.reserveSpend !== 'function' || typeof store.commitSpend !== 'function' || typeof store.registerCapability !== 'function') {
    return { ok: false, reason: 'capability_store_required' };
  }
  if (typeof delegateId !== 'string' || delegateId.length === 0) return { ok: false, reason: 'delegate_id_required' };
  try {
    const childId = validateCapabilityId(String(capabilityId));
    if (!isRecord(budget)) throw new TypeError('capability budget is required');
    const childAmount = validateAmount(budget.amount, 'budget.amount');
    const currency = validateCurrency(budget.currency);
    if (childAmount <= 0) throw new TypeError('delegated capability budget must be greater than zero');
    if (currency !== verified.capability.budget.currency) throw new TypeError('delegated capability currency does not match the parent budget');
    const childExpiry = validateExpiry(expiry);
    const parentExpiry = validateExpiry(verified.capability.expiry);
    if (Date.parse(childExpiry) > Date.parse(parentExpiry)) return { ok: false, reason: 'delegated_capability_expiry_exceeds_parent' };
    const parentScope = normalizeCapabilityScope(verified.capability.scope);
    const childScope = normalizeCapabilityScope(scope ?? parentScope);
    const scopeBroadened = childScope.profile !== parentScope.profile
      || childScope.operation_id_field !== parentScope.operation_id_field
      || (parentScope.profile === CAPABILITY_ALLOWANCE_SCOPE_PROFILE
        ? childScope.profile_id !== parentScope.profile_id
          || childScope.profile_digest !== parentScope.profile_digest
        : (() => {
          const parentMembers = parentScope.profile === CAPABILITY_CAID_SCOPE_PROFILE
            ? parentScope.caids : parentScope.action_digests;
          const childMembers = childScope.profile === CAPABILITY_CAID_SCOPE_PROFILE
            ? childScope.caids : childScope.action_digests;
          return childMembers.some((member) => !parentMembers.includes(member));
        })());
    if (scopeBroadened) {
      return { ok: false, reason: 'delegated_capability_scope_broadened' };
    }
    const parentOperationId = validateOperationId(operationId || `delegation:${childId}`);
    const child = mintCapabilityReceipt(verified.receipt, {
      issuerPrivateKey,
      budget: { amount: childAmount, currency },
      expiry: childExpiry,
      threshold,
      revocationMode,
      scope: childScope,
      capabilityId: childId,
      secret,
      delegationChain: [
        ...verified.capability.delegation_chain,
        {
          delegation_id: parentOperationId,
          parent_capability_id: verified.capability.id,
          delegate_id: delegateId,
          amount: childAmount,
          currency,
          issued_at: new Date(nowMs(now)).toISOString(),
        },
      ],
    });
    const reserved = await store.reserveSpend({
      capabilityId: verified.capability.id,
      capabilityFingerprint: capabilityEnvelopeFingerprint(parentCapabilityReceipt),
      operationId: parentOperationId,
      actionDigest: capabilityActionDigest({
        action_type: 'capability.delegate',
        operation_id: parentOperationId,
        parent_capability_id: verified.capability.id,
        child_capability_id: childId,
        child_capability_fingerprint: capabilityEnvelopeFingerprint(child.capabilityReceipt),
      }),
      amount: childAmount,
      currency,
      now,
    });
    if (!reserved?.ok) return { ok: false, reason: reserved?.reason || 'parent_delegation_refused' };
    const committed = await store.commitSpend({
      capabilityId: verified.capability.id,
      operationId: parentOperationId,
      reservationToken: reserved.reservation_token,
      outcome: 'delegated',
      now,
    });
    if (!committed?.ok) return { ok: false, reason: 'parent_delegation_commit_indeterminate', operation_id: parentOperationId };
    const registered = await store.registerCapability(child.capabilityReceipt);
    if (!registered) return { ok: false, reason: 'child_registration_failed', operation_id: parentOperationId };
    return {
      ok: true,
      capabilityReceipt: child.capabilityReceipt,
      secret: child.secret,
      shares: child.shares,
      operation_id: parentOperationId,
      remaining: committed.remaining,
    };
  } catch (error) {
    return { ok: false, reason: (error as Error)?.message || 'delegation_invalid' };
  }
}

// ===========================================================================
// EP-CAPABILITY-RECEIPT-v2 -- the hybrid (Ed25519 + ML-DSA-65) capability envelope.
// ===========================================================================
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference hybrid
 * migration in docs/protocol/pq-hybrid-program.md, section "PATTERN: the
 * reference hybrid migration" (EP-REVOCATION-v2, packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `capability_signature`, a wire-format change, so the artifact takes a new
 *    `@version` (EP-CAPABILITY-RECEIPT-v2). verifyCapabilityReceipt (v1) is
 *    untouched and refuses a v2 envelope on the version marker
 *    ('malformed_capability_receipt') before inspecting any signature; it never
 *    throws on caller input.
 * 2. SET SHAPE. `capability_signature` carries `required_algorithms` plus a
 *    `signatures` array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one per algorithm in the registered order. Ed25519
 *    keeps its base64url SPKI DER public key; ML-DSA-65 carries raw base64url
 *    public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (capabilityV2SignedPayload below), over the SAME canonical
 *    unsigned body v1 signs plus `required_algorithms`. Drop the ML-DSA leg and
 *    narrow `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies. The verifier rebuilds the bytes from the REGISTERED set.
 * 4. V1 COMPATIBILITY. v1 envelopes keep verifying through the unchanged
 *    synchronous verifyCapabilityReceipt; v2 verification is ASYNC (ML-DSA is
 *    async), so it is a SEPARATE entry point, with verifyCapabilityReceiptAny()
 *    routing on @version. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure returns a named reason; nothing throws on
 *    caller input. An absent ML-DSA backend is 'capability_pq_backend_unavailable'
 *    surfaced through the agility result, never a skipped check and never a pass on
 *    the classical leg.
 *
 * HONEST BOUNDARIES carry over from v1: the envelope authenticates issuer-signed
 * capability metadata; spend state is never trusted from the envelope, and every
 * spend must still pass through the atomic capability store. The ML-DSA backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently audited
 * and not a FIPS validated module. v2 does NOT retroactively protect v1 envelopes.
 */

export const CAPABILITY_RECEIPT_V2_VERSION = 'EP-CAPABILITY-RECEIPT-v2';

/** The registered required algorithm set, in canonical order. */
export const CAPABILITY_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const CAPABILITY_SIGNATURE_V2_KEYS = new Set([
  'profile', 'required_algorithms', 'public_key', 'key_id',
  'pq_public_key', 'pq_key_id', 'signatures',
]);

export interface CapabilityV2IssuerPin {
  /** Ed25519 base64url SPKI DER. */
  public_key: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key: string;
}

function capabilityV2AlgorithmSetRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === CAPABILITY_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === CAPABILITY_V2_REQUIRED_ALGORITHMS[i]);
}

/** ML-DSA-65 public-key identifier: SHA-256 of the raw public key bytes. */
function capabilityPqKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:capability-issuer-key:ml-dsa-65:sha256:${sha256Hex(raw)}`;
  } catch {
    return '';
  }
}

/** Ed25519 curve-pinned public-key identifier: SHA-256 of the SPKI DER. */
function capabilityEdKeyId(publicKeyB64u: unknown): string {
  try {
    if (typeof publicKeyB64u !== 'string' || publicKeyB64u.length === 0) return '';
    const der = Buffer.from(publicKeyB64u, 'base64url');
    if (der.length === 0 || der.toString('base64url') !== publicKeyB64u) return '';
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return '';
    return `ep:capability-issuer-key:sha256:${sha256Hex(der)}`;
  } catch {
    return '';
  }
}

function capabilityV2AgilityPassthrough(opts: any): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts?.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts?.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

function capabilityUnsignedBodyV2(receipt, capability, requiredAlgorithms: readonly string[]) {
  return {
    '@version': CAPABILITY_RECEIPT_V2_VERSION,
    base_receipt_id: receipt.payload.receipt_id,
    base_receipt_digest: capabilityBaseReceiptDigest(receipt),
    capability,
    required_algorithms: [...requiredAlgorithms],
  };
}

/**
 * The bytes BOTH legs sign: the SAME canonical unsigned body v1 signs, under the
 * v2 marker, plus the committed `required_algorithms` set. Recomputed
 * independently by the verifier from the PRESENTED receipt/capability and the
 * REGISTERED set. See PATTERN move 3.
 */
export function capabilityV2SignedPayload(
  receipt,
  capability,
  requiredAlgorithms: readonly string[] = CAPABILITY_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!capabilityV2AlgorithmSetRegistered(requiredAlgorithms)) {
    throw new TypeError('capabilityV2SignedPayload: algorithm set is not the registered EP-CAPABILITY-RECEIPT-v2 set');
  }
  return Buffer.from(canonicalize(capabilityUnsignedBodyV2(receipt, capability, requiredAlgorithms)), 'utf8');
}

/**
 * Mint a signed HYBRID capability envelope. Reuses mintCapabilityReceipt for the
 * entire receipt/capability construction and validation, then re-signs the same
 * canonical body under both algorithms. For m-of-n > 1 the raw secret is not
 * returned; distribute the returned shares instead. Issuance throws on invalid
 * local input; verification below never throws.
 */
export async function mintCapabilityReceiptV2(baseReceipt, options: {
  issuerPrivateKey?: KeyMaterial;
  pqPublicKey?: string;
  pqPrivateKey?: string | Uint8Array;
  budget?: CapabilityBudget;
  expiry?: string | number;
  threshold?: { m: number; n: number };
  revocationMode?: CapabilityRevocationMode;
  scope?: Record<string, any>;
  delegationChain?: any[];
  capabilityId?: string;
  secret?: Buffer | string;
} = {}) {
  const { pqPublicKey, pqPrivateKey, ...v1Options } = options;
  const issuerPrivateKey = options.issuerPrivateKey;
  if (!issuerPrivateKey) throw new TypeError('mintCapabilityReceiptV2 requires issuerPrivateKey');
  if (typeof pqPublicKey !== 'string' || capabilityPqKeyId(pqPublicKey) === '') {
    throw new TypeError('mintCapabilityReceiptV2 requires a valid ML-DSA-65 pqPublicKey');
  }
  if (pqPrivateKey === undefined) throw new TypeError('mintCapabilityReceiptV2 requires pqPrivateKey');
  const minted = mintCapabilityReceipt(baseReceipt, v1Options);
  const receipt = minted.capabilityReceipt.receipt;
  const capability = minted.capabilityReceipt.capability;
  const edPubB64u = publicKeyB64u(issuerPrivateKey);
  const edId = capabilityEdKeyId(edPubB64u);
  const pqId = capabilityPqKeyId(pqPublicKey);
  if (!edId) throw new TypeError('mintCapabilityReceiptV2 issuerPrivateKey is not Ed25519');
  const bytes = capabilityV2SignedPayload(receipt, capability, CAPABILITY_V2_REQUIRED_ALGORITHMS);
  const keys: AgileSigningKey[] = [
    { alg: 'Ed25519', private_key: createPrivateKeyObject(issuerPrivateKey), key_id: edId },
    { alg: 'ML-DSA-65', private_key: pqPrivateKey, key_id: pqId },
  ];
  const signatures = await signAgileSet(new Uint8Array(bytes), keys);
  const capabilityReceipt = {
    '@version': CAPABILITY_RECEIPT_V2_VERSION,
    receipt,
    capability,
    capability_signature: {
      profile: CAPABILITY_RECEIPT_V2_VERSION,
      required_algorithms: [...CAPABILITY_V2_REQUIRED_ALGORITHMS],
      public_key: edPubB64u,
      key_id: edId,
      pq_public_key: pqPublicKey,
      pq_key_id: pqId,
      signatures,
    },
  };
  return Object.freeze({
    capabilityReceipt: Object.freeze(capabilityReceipt),
    secret: minted.secret,
    shares: minted.shares,
  });
}

function createPrivateKeyObject(material: KeyMaterial): KeyObject {
  if (material && typeof material === 'object' && (material as KeyObject).type === 'private') {
    return material as KeyObject;
  }
  return createPrivateKey(material as Parameters<typeof createPrivateKey>[0]);
}

function capabilitySignatureV2(capabilityReceipt): any | null {
  const signature = capabilityReceipt?.capability_signature;
  if (!isRecord(signature)
      || Object.keys(signature).length !== CAPABILITY_SIGNATURE_V2_KEYS.size
      || !Object.keys(signature).every((key) => CAPABILITY_SIGNATURE_V2_KEYS.has(key))
      || signature.profile !== CAPABILITY_RECEIPT_V2_VERSION
      || typeof signature.public_key !== 'string'
      || typeof signature.pq_public_key !== 'string') {
    return null;
  }
  return signature;
}

/**
 * FAIL-CLOSED hybrid verifier for one EP-CAPABILITY-RECEIPT-v2 envelope. Never
 * throws on caller input; a v2 envelope NEVER verifies on one leg alone. Trust
 * follows the same model as v1: a pinned issuer PAIR is required. The legacy
 * allowUntrustedIssuer option is ignored so a self-signed envelope can never
 * become authority through this public verifier.
 */
export async function verifyCapabilityReceiptV2(capabilityReceipt, {
  trustedIssuerKeys = [],
  allowUntrustedIssuer: _allowUntrustedIssuer = false,
  mldsaBackend,
  mldsaBackendLoader,
}: {
  trustedIssuerKeys?: CapabilityV2IssuerPin[];
  allowUntrustedIssuer?: boolean;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
} = {}) {
  try {
    if (!isRecord(capabilityReceipt) || capabilityReceipt['@version'] !== CAPABILITY_RECEIPT_V2_VERSION) {
      return { ok: false, reason: 'malformed_capability_receipt' };
    }
    const receipt = validateBaseReceipt(capabilityReceipt.receipt);
    assertCapabilityShape(capabilityReceipt.capability);
    const signature = capabilitySignatureV2(capabilityReceipt);
    if (!signature) return { ok: false, reason: 'capability_signature_envelope_invalid' };

    const presentedEdKey = signature.public_key;
    const presentedPqKey = signature.pq_public_key;
    const pinnedPair = Array.isArray(trustedIssuerKeys)
      ? trustedIssuerKeys.some((pin) => isRecord(pin)
        && pin.public_key === presentedEdKey && pin.pq_public_key === presentedPqKey)
      : false;
    if (!pinnedPair) return { ok: false, reason: 'capability_issuer_not_trusted' };

    const derivedEdKeyId = capabilityEdKeyId(presentedEdKey);
    const derivedPqKeyId = capabilityPqKeyId(presentedPqKey);
    if (!derivedEdKeyId || signature.key_id !== derivedEdKeyId
        || !derivedPqKeyId || signature.pq_key_id !== derivedPqKeyId) {
      return { ok: false, reason: 'capability_issuer_key_unbound' };
    }

    if (!capabilityV2AlgorithmSetRegistered(signature.required_algorithms)) {
      return { ok: false, reason: 'capability_algorithm_set_invalid' };
    }

    const signatures = Array.isArray(signature.signatures) ? signature.signatures : null;
    if (!signatures || signatures.length === 0) return { ok: false, reason: 'capability_signature_legs_missing' };
    const presented = new Set<string>();
    for (const s of signatures) {
      if (!isRecord(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        return { ok: false, reason: 'capability_signature_leg_malformed' };
      }
      if (presented.has(s.alg)) return { ok: false, reason: 'capability_signature_leg_duplicate' };
      presented.add(s.alg);
    }
    for (const alg of presented) {
      if (!(CAPABILITY_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
        return { ok: false, reason: 'capability_signature_leg_unexpected' };
      }
    }
    for (const alg of CAPABILITY_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) return { ok: false, reason: 'capability_signature_leg_stripped' };
    }

    const bytes = capabilityV2SignedPayload(receipt, capabilityReceipt.capability, CAPABILITY_V2_REQUIRED_ALGORITHMS);
    const verificationKeys = [
      { alg: 'Ed25519', public_key: presentedEdKey, key_id: derivedEdKeyId },
      { alg: 'ML-DSA-65', public_key: presentedPqKey, key_id: derivedPqKeyId },
    ];
    let setResult: any = null;
    try {
      setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), signatures, verificationKeys, {
        ...capabilityV2AgilityPassthrough({ mldsaBackend, mldsaBackendLoader }),
        policy: 'hybrid_all',
        requiredAlgorithms: [...CAPABILITY_V2_REQUIRED_ALGORITHMS],
      });
    } catch {
      setResult = null;
    }
    if (setResult?.verified !== true) {
      const reason = String(setResult?.reason ?? 'signature_set_unverified');
      return { ok: false, reason: `capability_signature_invalid (${reason})` };
    }

    return {
      ok: true,
      receipt,
      capability: capabilityReceipt.capability,
      issuer_public_key: presentedEdKey,
      issuer_pq_public_key: presentedPqKey,
      issuer_trusted: true,
    };
  } catch (error) {
    return { ok: false, reason: 'capability_malformed', detail: (error as Error)?.message || 'invalid capability' };
  }
}

/**
 * Route an envelope of EITHER version to its verifier. v1 envelopes keep the exact
 * v1 verdict; v2 envelopes get the hybrid check. An envelope whose @version is
 * neither refuses through the v1 verifier, which is fail-closed.
 */
export async function verifyCapabilityReceiptAny(capabilityReceipt, options: any = {}) {
  if (isRecord(capabilityReceipt) && capabilityReceipt['@version'] === CAPABILITY_RECEIPT_V2_VERSION) {
    return verifyCapabilityReceiptV2(capabilityReceipt, options);
  }
  return verifyCapabilityReceipt(capabilityReceipt, options);
}

export default {
  CAPABILITY_RECEIPT_VERSION,
  CAPABILITY_RECEIPT_V2_VERSION,
  CAPABILITY_V2_REQUIRED_ALGORITHMS,
  CAPABILITY_STATE_VERSION,
  CAPABILITY_SHARE_VERSION,
  CAPABILITY_SCOPE_PROFILE,
  CAPABILITY_CAID_SCOPE_PROFILE,
  CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
  CAPABILITY_ACTION_FENCE_PROFILE,
  CAPABILITY_REVOCATION_MODES,
  CAPABILITY_ALLOWANCE_STATUS_TABLE,
  CAPABILITY_STATE_DDL,
  CAPABILITY_SQL,
  capabilityBaseReceiptDigest,
  capabilityActionDigest,
  verifyCapabilityScope,
  mintCapabilityReceipt,
  verifyCapabilityReceipt,
  splitCapabilitySecret,
  reconstructCapabilitySecret,
  createMemoryCapabilityStore,
  createPostgresCapabilityStore,
  isSecureCapabilityStore,
  executeWithCapability,
  executeWithThreshold,
  reconcileCapabilityOperation,
  delegateCapabilityReceipt,
};
