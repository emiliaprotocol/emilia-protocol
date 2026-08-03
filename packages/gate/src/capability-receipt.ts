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
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from 'node:crypto';
import { canonicalize } from './execution-binding.js';

export const CAPABILITY_RECEIPT_VERSION = 'EP-CAPABILITY-RECEIPT-v1';
export const CAPABILITY_STATE_VERSION = 'EP-CAPABILITY-STATE-v1';
export const CAPABILITY_SHARE_VERSION = 'EP-CAPABILITY-SHARE-v1';
export const CAPABILITY_HASH_ALGORITHM = 'sha256';
export const CAPABILITY_SCOPE_PROFILE = 'urn:emilia:scope:action-digest-set-v1';
export const CAPABILITY_CAID_SCOPE_PROFILE = 'urn:emilia:scope:caid-set-v1';
export const CAPABILITY_ALLOWANCE_SCOPE_PROFILE = 'EP-CAPABILITY-ALLOWANCE-SCOPE-v1';

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
  amount: number;
  currency: string;
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
  now?: number | (() => number);
};
type RecoverPreEntrySpendOptions = {
  capabilityId?: string;
  operationNamespace?: string;
  operationId?: string;
  actionDigest?: string;
  now?: number | (() => number);
};
type ReconcileSpendOptions = {
  capabilityId?: string;
  operationNamespace?: string;
  operationId?: string;
  actionDigest?: string;
  evidenceDigest?: string;
  evidenceProfile?: string;
  outcome?: string;
  now?: number | (() => number);
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
  allowanceStatus?: AllowanceStatusAssertion;
  operationId?: string | null;
  now?: number | (() => number);
  thresholdSecretVerified?: boolean;
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

function validateEvidenceProfile(evidenceProfile) {
  if (typeof evidenceProfile !== 'string'
      || evidenceProfile.length === 0
      || Buffer.byteLength(evidenceProfile, 'utf8') > MAX_EVIDENCE_PROFILE_BYTES) {
    throw new TypeError('evidence_profile must be a bounded non-empty string');
  }
  return evidenceProfile;
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
    let caid = null;
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
    } else if (scope.profile === CAPABILITY_CAID_SCOPE_PROFILE) {
      if (typeof resolveCaid !== 'function') {
        return { ok: false, reason: 'capability_caid_resolver_required', action_digest: actionDigest };
      }
      const resolved = resolveCaid(structuredClone(action));
      caid = typeof resolved === 'string' ? resolved : resolved?.caid;
      if (typeof caid !== 'string' || !CAID_RE.test(caid)) {
        return { ok: false, reason: 'capability_caid_resolution_failed', action_digest: actionDigest };
      }
      if (!scope.caids.includes(caid)) {
        return { ok: false, reason: 'capability_action_out_of_scope', action_digest: actionDigest, caid };
      }
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
  normalizeCapabilityScope(capability.scope);
  assertDelegationChain(capability.delegation_chain, capability.id);
  if (capability.consumed !== 0) throw new TypeError('capability consumed is issuer-initialized and must be zero');
  return true;
}

function verifyTrustedIssuer(publicKey, trustedIssuerKeys, allowUntrustedIssuer) {
  if (!Array.isArray(trustedIssuerKeys) || trustedIssuerKeys.length === 0) {
    return allowUntrustedIssuer === true;
  }
  return trustedIssuerKeys.includes(publicKey);
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
  scope,
  delegationChain = [],
  capabilityId = randomUUID(),
  secret = randomBytes(HASH_BYTES),
}: {
  issuerPrivateKey?: KeyMaterial;
  budget?: CapabilityBudget;
  expiry?: string | number;
  threshold?: { m: number; n: number };
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
 * @param {boolean} [options.allowUntrustedIssuer]
 */
export function verifyCapabilityReceipt(capabilityReceipt, {
  trustedIssuerKeys = [],
  allowUntrustedIssuer = false,
}: { trustedIssuerKeys?: string[]; allowUntrustedIssuer?: boolean } = {}) {
  try {
    if (!isRecord(capabilityReceipt) || capabilityReceipt['@version'] !== CAPABILITY_RECEIPT_VERSION) return { ok: false, reason: 'malformed_capability_receipt' };
    const receipt = validateBaseReceipt(capabilityReceipt.receipt);
    assertCapabilityShape(capabilityReceipt.capability);
    const signature = capabilitySignature(capabilityReceipt);
    if (!signature || !verifyTrustedIssuer(signature.public_key, trustedIssuerKeys, allowUntrustedIssuer)) {
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
    allowance_profile_id: allowanceScope?.profile_id ?? null,
    allowance_digest: allowanceScope?.profile_digest ?? null,
  };
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
    && typeof store.reconcileSpend === 'function';
}

/**
 * An in-memory atomic reference store. It is intentionally marked non-durable
 * and is suitable only for tests; production callers must use an implementation
 * backed by a transactional database or equivalent linearizable store.
 */
export function createMemoryCapabilityStore({
  providerEntryTimeoutMs = DEFAULT_PROVIDER_ENTRY_TIMEOUT_MS,
}: { providerEntryTimeoutMs?: number } = {}) {
  const entryTimeoutMs = validateProviderEntryTimeoutMs(providerEntryTimeoutMs);
  const states = new Map();
  const operations = new Map();
  const allowanceStatuses = new Map();
  const operationKey = (operationNamespace, operationId) =>
    JSON.stringify([operationNamespace, operationId]);
  const actionKey = (operationNamespace, actionDigest) =>
    JSON.stringify([operationNamespace, actionDigest]);
  // actionKey -> operationKey. A HINT, never the source of truth. Every read
  // revalidates the operation it points at, so a holder that has since been
  // released simply fails the status test and the entry is overwritten. That is
  // why nothing here has to be deleted on release: a stale hint self-heals, and
  // an index maintained at every transition would not.
  const actionHolders = new Map();
  return {
    durable: false,
    reconciliationCapable: true,
    allowanceCurrentnessCapable: true,
    registerCapability(capabilityReceipt) {
      const verified = verifyCapabilityReceipt(capabilityReceipt, { allowUntrustedIssuer: true });
      if (!verified.ok) return false;
      const state = capabilityStateFromEnvelope(capabilityReceipt);
      const existing = states.get(state.capability_id);
      if (existing) {
        return existing.capability_fingerprint === state.capability_fingerprint
          && existing.budget_amount === state.budget_amount
          && existing.currency === state.currency
          && existing.expires_at === state.expires_at
          && existing.allowance_profile_id === state.allowance_profile_id
          && existing.allowance_digest === state.allowance_digest;
      }
      states.set(state.capability_id, { ...state, consumed_amount: 0, reserved_amount: 0 });
      return true;
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
    async reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace = capabilityId, operationId, actionDigest, amount, currency, allowanceStatus, now = Date.now }: ReserveSpendOptions) {
      validateOperationId(operationId);
      validateOperationNamespace(operationNamespace);
      validateActionDigest(actionDigest);
      validateAmount(amount);
      validateCurrency(currency);
      const state = states.get(capabilityId);
      if (!state) return { ok: false, reason: 'capability_not_registered' };
      if (state.capability_fingerprint !== capabilityFingerprint) return { ok: false, reason: 'capability_envelope_mismatch' };
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
      if (existing) return { ok: false, reason: existingOperationReason(existing.status) };
      // Fence on the ACTION, not only on the token. A caller that retries
      // request-for-approval gets a fresh operation id, and both requests carry
      // the same action digest. Keying only on the id let both reserve, so the
      // same merge, payout, or delete could be authorized twice under two ids.
      // The budget hid this whenever an amount was attached; it hid nothing for
      // a zero-amount irreversible action.
      const held = actionHolders.get(actionKey(operationNamespace, actionDigest));
      const holder = held === undefined ? undefined : operations.get(held);
      if (holder && ACTION_HOLDING_STATUSES.includes(holder.status)) {
        return {
          ok: false,
          reason: actionHeldReason(holder.status),
          action_digest: actionDigest,
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
      });
      state.reserved_amount += amount;
      actionHolders.set(actionKey(operationNamespace, actionDigest), key);
      return {
        ok: true,
        operation_id: operationId,
        reservation_token: reservationToken,
        entry_deadline_at: entryDeadlineAt,
        remaining: state.budget_amount - state.consumed_amount - state.reserved_amount,
      };
    },
    async beginProviderEntry({ capabilityId, operationNamespace = capabilityId, operationId, reservationToken, now = Date.now }: BeginProviderEntryOptions = {}) {
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
    async recoverPreEntrySpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, now = Date.now }: RecoverPreEntrySpendOptions = {}) {
      validateOperationId(operationId);
      validateOperationNamespace(operationNamespace);
      validateActionDigest(actionDigest);
      const operation = operations.get(operationKey(operationNamespace, operationId));
      const state = states.get(capabilityId);
      if (!operation || !state) return { ok: false, reason: 'capability_operation_not_found' };
      if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
      if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
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
    async reconcileSpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, evidenceDigest, evidenceProfile, outcome = 'executed', now = Date.now }: ReconcileSpendOptions = {}) {
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
        try {
          validateEvidenceProfile(evidenceProfile);
        } catch {
          return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
        }
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
        if (operation.status !== 'provider_entered'
            && !(operation.status === 'committed' && operation.outcome === 'indeterminate')) {
          return { ok: false, reason: operation.status === 'reserved'
            ? 'capability_provider_entry_not_recorded'
            : 'capability_operation_not_indeterminate' };
        }
        operation.status = 'released';
        operation.outcome = 'not_entered';
        operation.release_reason = 'authenticated_provider_non_entry';
        operation.release_evidence_profile = evidenceProfile;
        operation.release_evidence_digest = evidenceDigest;
        operation.released_at = at;
        state.consumed_amount -= operation.amount;
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
export const CAPABILITY_STATE_DDL = `CREATE TABLE IF NOT EXISTS ${CAPABILITY_STATE_TABLE} (
  capability_id TEXT PRIMARY KEY,
  capability_fingerprint TEXT NOT NULL CHECK (capability_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  budget_amount BIGINT NOT NULL CHECK (budget_amount >= 0),
  currency TEXT NOT NULL,
  consumed_amount BIGINT NOT NULL DEFAULT 0 CHECK (consumed_amount >= 0),
  reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  allowance_profile_id TEXT,
  allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),
  CHECK ((allowance_profile_id IS NULL) = (allowance_digest IS NULL))
);
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS capability_fingerprint TEXT;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS allowance_profile_id TEXT;
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$');
CREATE TABLE IF NOT EXISTS ${CAPABILITY_ALLOWANCE_STATUS_TABLE} (
  allowance_profile_id TEXT PRIMARY KEY,
  allowance_digest TEXT NOT NULL CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),
  revision BIGINT NOT NULL CHECK (revision > 0),
  status_epoch BIGINT NOT NULL CHECK (status_epoch > 0),
  status_head_digest TEXT NOT NULL CHECK (status_head_digest ~ '^sha256:[0-9a-f]{64}$'),
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE} (
  operation_namespace TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  capability_id TEXT NOT NULL REFERENCES ${CAPABILITY_STATE_TABLE}(capability_id),
  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  amount BIGINT NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_status_check CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released')),
  reservation_token TEXT NOT NULL,
  outcome TEXT,
  reconciliation_outcome TEXT CHECK (reconciliation_outcome IN ('executed')),
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
  PRIMARY KEY (operation_namespace, operation_id)
);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS operation_namespace TEXT;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS entry_deadline_at TIMESTAMPTZ;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS provider_entry_at TIMESTAMPTZ;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS release_reason TEXT;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS release_evidence_profile TEXT;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS release_evidence_digest TEXT CHECK (release_evidence_digest ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} DROP CONSTRAINT IF EXISTS ${CAPABILITY_OPERATION_TABLE}_status_check;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ADD CONSTRAINT ${CAPABILITY_OPERATION_TABLE}_status_check
  CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released'));
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS allowance_revision BIGINT CHECK (allowance_revision > 0);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0);
ALTER TABLE ${CAPABILITY_OPERATION_TABLE} ADD COLUMN IF NOT EXISTS allowance_status_head_digest TEXT CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$');
UPDATE ${CAPABILITY_OPERATION_TABLE}
  SET operation_namespace = capability_id
  WHERE operation_namespace IS NULL;
ALTER TABLE ${CAPABILITY_OPERATION_TABLE}
  ALTER COLUMN operation_namespace SET NOT NULL;
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
CREATE INDEX IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE}_recovery_idx ON ${CAPABILITY_OPERATION_TABLE}(status, entry_deadline_at);`;

export const CAPABILITY_SQL = Object.freeze({
  register: `INSERT INTO ${CAPABILITY_STATE_TABLE} (capability_id, budget_amount, currency, expires_at, capability_fingerprint, allowance_profile_id, allowance_digest) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(${CAPABILITY_STATE_TABLE}.capability_fingerprint, EXCLUDED.capability_fingerprint), allowance_profile_id = COALESCE(${CAPABILITY_STATE_TABLE}.allowance_profile_id, EXCLUDED.allowance_profile_id), allowance_digest = COALESCE(${CAPABILITY_STATE_TABLE}.allowance_digest, EXCLUDED.allowance_digest) WHERE ${CAPABILITY_STATE_TABLE}.budget_amount = EXCLUDED.budget_amount AND ${CAPABILITY_STATE_TABLE}.currency = EXCLUDED.currency AND ${CAPABILITY_STATE_TABLE}.expires_at = EXCLUDED.expires_at AND (${CAPABILITY_STATE_TABLE}.allowance_profile_id IS NULL OR ${CAPABILITY_STATE_TABLE}.allowance_profile_id IS NOT DISTINCT FROM EXCLUDED.allowance_profile_id) AND (${CAPABILITY_STATE_TABLE}.allowance_digest IS NULL OR ${CAPABILITY_STATE_TABLE}.allowance_digest IS NOT DISTINCT FROM EXCLUDED.allowance_digest)`,
  readState: `SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at, allowance_profile_id, allowance_digest FROM ${CAPABILITY_STATE_TABLE} WHERE capability_id = $1 FOR UPDATE`,
  readAllowanceStatus: `SELECT allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status FROM ${CAPABILITY_ALLOWANCE_STATUS_TABLE} WHERE allowance_profile_id = $1 FOR UPDATE`,
  insertAllowanceStatus: `INSERT INTO ${CAPABILITY_ALLOWANCE_STATUS_TABLE} (allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (allowance_profile_id) DO NOTHING`,
  updateAllowanceStatus: `UPDATE ${CAPABILITY_ALLOWANCE_STATUS_TABLE} SET allowance_digest = $4, revision = $5, status_epoch = $6, status_head_digest = $7, status = $8, updated_at = $9 WHERE allowance_profile_id = $1 AND status_epoch = $2 AND status_head_digest = $3`,
  readOperation: `SELECT operation_namespace, operation_id, capability_id, action_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, allowance_revision, allowance_status_epoch, allowance_status_head_digest, reconciled_at, reserved_at, entry_deadline_at, provider_entry_at, released_at, release_reason, release_evidence_profile, release_evidence_digest FROM ${CAPABILITY_OPERATION_TABLE} WHERE operation_namespace = $1 AND operation_id = $2 FOR UPDATE`,
  // Is this exact action already held by SOME operation, whatever its id? The
  // An existing holder is row-locked here. Same-capability reservations also
  // serialize on readState. For custom namespaces spanning capability rows, the
  // partial unique index in migration 20260803010000 is the authoritative race
  // backstop because PostgreSQL cannot lock a row that does not exist yet.
  readActionHolder: `SELECT operation_id, status FROM ${CAPABILITY_OPERATION_TABLE} WHERE operation_namespace = $1 AND action_digest = $2 AND status IN ('reserved', 'provider_entered', 'committed') LIMIT 1 FOR UPDATE`,
  insertOperation: `INSERT INTO ${CAPABILITY_OPERATION_TABLE} (operation_namespace, capability_id, operation_id, action_digest, amount, currency, status, reservation_token, reserved_at, entry_deadline_at, allowance_revision, allowance_status_epoch, allowance_status_head_digest) VALUES ($1, $2, $3, $4, $5, $6, 'reserved', $7, $8, $9, $10, $11, $12)`,
  reserveState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND budget_amount - consumed_amount - reserved_amount >= $2`,
  beginProviderEntry: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'provider_entered', provider_entry_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'reserved' AND reservation_token = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at > $5`,
  commitOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'committed', outcome = $4, committed_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = $7 AND reservation_token = $6`,
  reconcileOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET reconciliation_outcome = $4, reconciliation_evidence_digest = $5, reconciled_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL`,
  recoverPreEntryOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'released', outcome = 'not_entered', release_reason = 'pre_entry_deadline_elapsed', released_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND status = 'reserved' AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $5`,
  releaseEnteredOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'released', outcome = 'not_entered', release_reason = 'authenticated_provider_non_entry', release_evidence_profile = $5, release_evidence_digest = $6, released_at = $7 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $7 AND (status = 'provider_entered' OR (status = 'committed' AND outcome = 'indeterminate'))`,
  commitState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2`,
  releaseReservedState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount - $2 WHERE capability_id = $1 AND reserved_amount >= $2`,
  releaseConsumedState: `UPDATE ${CAPABILITY_STATE_TABLE} SET consumed_amount = consumed_amount - $2 WHERE capability_id = $1 AND consumed_amount >= $2`,
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
}: {
  transaction?: (callback: (query: Function) => any) => any;
  providerEntryTimeoutMs?: number;
} = {}) {
  if (typeof transaction !== 'function') throw new TypeError('createPostgresCapabilityStore requires a transaction(callback) function');
  const entryTimeoutMs = validateProviderEntryTimeoutMs(providerEntryTimeoutMs);
  return {
    durable: true,
    reconciliationCapable: true,
    allowanceCurrentnessCapable: true,
    async registerCapability(capabilityReceipt) {
      const verified = verifyCapabilityReceipt(capabilityReceipt, { allowUntrustedIssuer: true });
      if (!verified.ok) return false;
      const state = capabilityStateFromEnvelope(capabilityReceipt);
      return transaction(async (query) => {
        await query(CAPABILITY_SQL.register, [
          state.capability_id,
          state.budget_amount,
          capabilityReceipt.capability.budget.currency,
          new Date(state.expires_at).toISOString(),
          state.capability_fingerprint,
          state.allowance_profile_id,
          state.allowance_digest,
        ]);
        const result = await query(CAPABILITY_SQL.readState, [state.capability_id]);
        const row = result?.rows?.[0];
        return Boolean(row)
          && row.capability_fingerprint === state.capability_fingerprint
          && Number(row.budget_amount) === state.budget_amount
          && row.currency === state.currency
          && Date.parse(row.expires_at) === state.expires_at
          && (row.allowance_profile_id ?? null) === state.allowance_profile_id
          && (row.allowance_digest ?? null) === state.allowance_digest;
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
    async reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace = capabilityId, operationId, actionDigest, amount, currency, allowanceStatus, now = Date.now }: ReserveSpendOptions) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace); validateAmount(amount); validateCurrency(currency);
      validateActionDigest(actionDigest);
      const at = nowMs(now);
      try {
        return await transaction(async (query) => {
        const stateResult = await query(CAPABILITY_SQL.readState, [capabilityId]);
        const state = stateResult?.rows?.[0];
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        if (state.capability_fingerprint !== capabilityFingerprint) return { ok: false, reason: 'capability_envelope_mismatch' };
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
        if (operationResult?.rows?.[0]) return { ok: false, reason: existingOperationReason(operationResult.rows[0].status) };
        // Same fence as the memory store: a second operation id carrying an
        // action digest that is already reserved, entered, or committed is a
        // duplicate authorization of one action, not a new one.
        const holderResult = await query(CAPABILITY_SQL.readActionHolder, [operationNamespace, actionDigest]);
        const holder = holderResult?.rows?.[0];
        if (holder) {
          return {
            ok: false,
            reason: actionHeldReason(holder.status),
            action_digest: actionDigest,
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
        try {
          await query(CAPABILITY_SQL.insertOperation, [
            operationNamespace,
            capabilityId,
            operationId,
            actionDigest,
            amount,
            currency,
            token,
            new Date(at).toISOString(),
            new Date(entryDeadlineAt).toISOString(),
            assertedAllowanceStatus?.revision ?? null,
            assertedAllowanceStatus?.status_epoch ?? null,
            assertedAllowanceStatus?.status_head_digest ?? null,
          ]);
        } catch (error) {
          // The readActionHolder above takes FOR UPDATE, so two reservations in
          // the same transaction serialize there. A caller reaching this table
          // on another connection can still lose the race, and then the partial
          // unique index rejects the insert. Losing a race is a refusal with a
          // reason, not an exception: a thrown 23505 would escape reserveSpend's
          // result contract and reach the caller as a crash, which is the
          // opposite of the property this index exists to provide.
          if (isLiveActionUniqueViolation(error)) {
            return { ok: false, reason: 'action_in_flight', action_digest: actionDigest };
          }
          throw error;
        }
        return {
          ok: true,
          operation_id: operationId,
          reservation_token: token,
          entry_deadline_at: entryDeadlineAt,
          remaining: available - amount,
        };
        });
      } catch (error) {
        // Two transactions can both observe an empty custom namespace before
        // either inserts. The database constraint decides the winner. Translate
        // that expected race into the same closed result as the preflight read;
        // the transaction contract must roll back the budget reservation first.
        if (isActionFenceConflict(error)) {
          return {
            ok: false,
            reason: 'action_in_flight',
            action_digest: actionDigest,
          };
        }
        throw error;
      }
    },
    async beginProviderEntry({ capabilityId, operationNamespace = capabilityId, operationId, reservationToken, now = Date.now }: BeginProviderEntryOptions = {}) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace);
      if (typeof reservationToken !== 'string' || reservationToken.length < 16) return { ok: false, reason: 'capability_reservation_token_invalid' };
      const at = nowMs(now);
      return transaction(async (query) => {
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
    async recoverPreEntrySpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, now = Date.now }: RecoverPreEntrySpendOptions = {}) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace); validateActionDigest(actionDigest);
      const at = nowMs(now);
      return transaction(async (query) => {
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationNamespace, operationId]);
        const operation = operationResult?.rows?.[0];
        if (!operation) return { ok: false, reason: 'capability_operation_not_found' };
        if (operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_owner_mismatch' };
        if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
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
    async reconcileSpend({ capabilityId, operationNamespace = capabilityId, operationId, actionDigest, evidenceDigest, evidenceProfile, outcome = 'executed', now = Date.now }: ReconcileSpendOptions = {}) {
      validateOperationId(operationId); validateOperationNamespace(operationNamespace);
      if (typeof actionDigest !== 'string' || !ACTION_DIGEST_RE.test(actionDigest)
          || typeof evidenceDigest !== 'string' || !ACTION_DIGEST_RE.test(evidenceDigest)
          || !['executed', 'not_entered'].includes(outcome)) {
        return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
      }
      if (outcome === 'not_entered') {
        try {
          validateEvidenceProfile(evidenceProfile);
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
          if (operation.status !== 'provider_entered'
              && !(operation.status === 'committed' && operation.outcome === 'indeterminate')) {
            return { ok: false, reason: operation.status === 'reserved'
              ? 'capability_provider_entry_not_recorded'
              : 'capability_operation_not_indeterminate' };
          }
          const released = await query(CAPABILITY_SQL.releaseEnteredOperation, [
            operationNamespace,
            operationId,
            capabilityId,
            actionDigest,
            evidenceProfile,
            evidenceDigest,
            new Date(at).toISOString(),
          ]);
          if (released?.rowCount !== 1) throw new Error('capability authenticated non-entry transition conflicted; transaction must roll back');
          const restored = await query(CAPABILITY_SQL.releaseConsumedState, [capabilityId, operation.amount]);
          if (restored?.rowCount !== 1) throw new Error('capability authenticated non-entry budget recovery conflicted; transaction must roll back');
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
  allowanceStatus,
  operationId = null,
  now = Date.now,
  thresholdSecretVerified = false,
}: ExecuteWithCapabilityOptions = {}) {
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
  let authorization: Record<string, any> | null = null;
  if (gate && typeof gate.check === 'function') {
    authorization = await gate.check({
      selector,
      receipt: verified.receipt,
      observedAction: immutableAction,
      consumptionMode: 'none',
      capability: { capabilityReceipt, action: immutableAction, operationId },
    });
    if (!authorization?.allow) return { ok: false, reason: 'base_receipt_rejected', authorization };
  } else if (typeof verifyBaseReceipt === 'function') {
    const result = await verifyBaseReceipt(verified.receipt, {
      action: immutableAction,
      selector,
      observedAction: immutableAction,
      scope,
    });
    if (result !== true && result?.ok !== true) return { ok: false, reason: 'base_receipt_rejected', authorization: result };
  } else {
    return { ok: false, reason: 'base_receipt_verifier_required' };
  }
  let spend;
  try {
    // `action` is the budget projection used by Gate integrations; it must
    // match the verified action and can never reach the effect.
    spend = capabilityAmount(action, verified.capability, immutableAction);
  } catch (error) {
    return { ok: false, reason: (error as Error)?.message || 'capability_action_invalid', authorization };
  }
  const reserved = await store.reserveSpend({
    capabilityId: verified.capability.id,
    capabilityFingerprint: capabilityEnvelopeFingerprint(capabilityReceipt),
    operationNamespace: scope.operation_namespace ?? verified.capability.id,
    operationId,
    actionDigest: scope.action_digest,
    amount: spend.amount,
    currency: spend.currency,
    ...(allowanceStatus ? { allowanceStatus } : {}),
    now,
  });
  if (!reserved?.ok) return { ok: false, reason: reserved?.reason || 'capability_reservation_refused', authorization };
  const providerEntry = await store.beginProviderEntry({
    capabilityId: verified.capability.id,
    operationNamespace: scope.operation_namespace ?? verified.capability.id,
    operationId,
    reservationToken: reserved.reservation_token,
    now,
  }).catch(() => ({ ok: false, reason: 'capability_provider_entry_indeterminate' }));
  if (!providerEntry?.ok) {
    return {
      ok: false,
      reason: providerEntry?.reason || 'capability_provider_entry_indeterminate',
      authorization,
      operation_id: operationId,
      action_digest: scope.action_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
    };
  }
  try {
    const result = await executeAction(structuredClone(immutableAction), {
      capabilityReceipt,
      authorization,
      operation_id: operationId,
      action_digest: scope.action_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
      observed_action: immutableAction,
      reservation: reserved,
      provider_entry: providerEntry,
    });
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationNamespace: scope.operation_namespace ?? verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'executed', now });
    if (!committed?.ok) return { ok: false, reason: 'capability_commit_indeterminate', authorization, result, operation_id: operationId };
    return {
      ok: true,
      result,
      authorization,
      operation_id: operationId,
      action_digest: scope.action_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
      remaining: committed.remaining,
    };
  } catch (error) {
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationNamespace: scope.operation_namespace ?? verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'indeterminate', now }).catch(() => ({ ok: false }));
    return {
      ok: false,
      reason: committed.ok ? 'effect_indeterminate' : 'capability_commit_indeterminate',
      authorization,
      operation_id: operationId,
      action_digest: scope.action_digest,
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
 * executed outcome without restoring budget. A post-entry release additionally
 * requires an authenticated, action-specific negative-evidence profile and is
 * still gated by the reservation's durable provider-entry deadline.
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
      || verified.capability_id !== capabilityId
      || verified.operation_namespace !== operationNamespace
      || verified.operation_id !== operationId)) {
    return { ok: false, reason: 'capability_reconciliation_evidence_rejected' };
  }
  if (negative) {
    try {
      validateEvidenceProfile(verified.evidence_profile);
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
    ...(negative ? { evidenceProfile: verified.evidence_profile } : {}),
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

export default {
  CAPABILITY_RECEIPT_VERSION,
  CAPABILITY_STATE_VERSION,
  CAPABILITY_SHARE_VERSION,
  CAPABILITY_SCOPE_PROFILE,
  CAPABILITY_CAID_SCOPE_PROFILE,
  CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
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
