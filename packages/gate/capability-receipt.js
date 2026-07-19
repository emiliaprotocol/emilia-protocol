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
} from 'node:crypto';
import { canonicalize } from './execution-binding.js';

export const CAPABILITY_RECEIPT_VERSION = 'EP-CAPABILITY-RECEIPT-v1';
export const CAPABILITY_STATE_VERSION = 'EP-CAPABILITY-STATE-v1';
export const CAPABILITY_SHARE_VERSION = 'EP-CAPABILITY-SHARE-v1';
export const CAPABILITY_HASH_ALGORITHM = 'sha256';
export const CAPABILITY_SCOPE_PROFILE = 'urn:emilia:scope:action-digest-set-v1';
export const CAPABILITY_CAID_SCOPE_PROFILE = 'urn:emilia:scope:caid-set-v1';

// 2^521 - 1 is a prime and is comfortably larger than a 256-bit secret.
const FIELD = (2n ** 521n) - 1n;
const SHARE_BYTES = 66;
const HASH_BYTES = 32;
const MAX_CURRENCY_BYTES = 32;
const MAX_OPERATION_ID_BYTES = 128;
const MAX_DELEGATES = 64;
const MAX_SCOPE_ACTIONS = 256;
const ACTION_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
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

/** Digest the exact immutable action snapshot exercised under a capability. */
export function capabilityActionDigest(action) {
  return `sha256:${sha256Hex(Buffer.from(canonicalize(action), 'utf8'))}`;
}

function normalizeCapabilityScope(scope) {
  if (!isRecord(scope) || ![CAPABILITY_SCOPE_PROFILE, CAPABILITY_CAID_SCOPE_PROFILE].includes(scope.profile)) {
    throw new TypeError(`capability scope.profile must be ${CAPABILITY_SCOPE_PROFILE} or ${CAPABILITY_CAID_SCOPE_PROFILE}`);
  }
  const memberField = scope.profile === CAPABILITY_CAID_SCOPE_PROFILE ? 'caids' : 'action_digests';
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

export function verifyCapabilityScope(capability, action, operationId, { resolveCaid = null } = {}) {
  try {
    const scope = normalizeCapabilityScope(capability?.scope);
    const actionDigest = capabilityActionDigest(action);
    let caid = null;
    if (scope.profile === CAPABILITY_CAID_SCOPE_PROFILE) {
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
      operation_id_field: scope.operation_id_field,
    };
  } catch (error) {
    return { ok: false, reason: 'capability_scope_invalid', detail: error?.message || 'invalid capability scope' };
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
function assertDelegationChain(chain, capabilityId) {
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

/** Verify the issuer signature and immutable capability metadata. */
export function verifyCapabilityReceipt(capabilityReceipt, {
  trustedIssuerKeys = [],
  allowUntrustedIssuer = false,
} = {}) {
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
    return { ok: false, reason: 'capability_malformed', detail: error?.message || 'invalid capability' };
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
  const shares = [];
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
  return {
    capability_id: c.id,
    capability_fingerprint: capabilityEnvelopeFingerprint(capabilityReceipt),
    budget_amount: c.budget.amount,
    currency: c.budget.currency,
    expires_at: Date.parse(c.expiry),
  };
}

/**
 * An in-memory atomic reference store. It is intentionally marked non-durable
 * and is suitable only for tests; production callers must use an implementation
 * backed by a transactional database or equivalent linearizable store.
 */
export function createMemoryCapabilityStore() {
  const states = new Map();
  const operations = new Map();
  return {
    durable: false,
    registerCapability(capabilityReceipt) {
      const verified = verifyCapabilityReceipt(capabilityReceipt, { allowUntrustedIssuer: true });
      if (!verified.ok) return false;
      const state = capabilityStateFromEnvelope(capabilityReceipt);
      const existing = states.get(state.capability_id);
      if (existing) {
        return existing.capability_fingerprint === state.capability_fingerprint
          && existing.budget_amount === state.budget_amount
          && existing.currency === state.currency
          && existing.expires_at === state.expires_at;
      }
      states.set(state.capability_id, { ...state, consumed_amount: 0, reserved_amount: 0 });
      return true;
    },
    async reserveSpend({ capabilityId, capabilityFingerprint, operationId, actionDigest, amount, currency, now = Date.now } = {}) {
      validateOperationId(operationId);
      if (typeof actionDigest !== 'string' || !ACTION_DIGEST_RE.test(actionDigest)) throw new TypeError('action_digest must be SHA-256');
      validateAmount(amount);
      validateCurrency(currency);
      const state = states.get(capabilityId);
      if (!state) return { ok: false, reason: 'capability_not_registered' };
      if (state.capability_fingerprint !== capabilityFingerprint) return { ok: false, reason: 'capability_envelope_mismatch' };
      const existing = operations.get(operationId);
      if (existing) return { ok: false, reason: existing.status === 'reserved' ? 'operation_in_flight' : 'operation_already_committed' };
      const at = nowMs(now);
      if (at >= state.expires_at) return { ok: false, reason: 'capability_expired' };
      if (currency !== state.currency) return { ok: false, reason: 'currency_mismatch' };
      if (state.consumed_amount + state.reserved_amount + amount > state.budget_amount) return { ok: false, reason: 'budget_exceeded' };
      const reservationToken = randomUUID();
      operations.set(operationId, { capability_id: capabilityId, action_digest: actionDigest, amount, currency, status: 'reserved', reservation_token: reservationToken, reserved_at: at });
      state.reserved_amount += amount;
      return { ok: true, operation_id: operationId, reservation_token: reservationToken, remaining: state.budget_amount - state.consumed_amount - state.reserved_amount };
    },
    async commitSpend({ capabilityId, operationId, reservationToken, outcome = 'executed', now = Date.now } = {}) {
      const operation = operations.get(operationId);
      const state = states.get(capabilityId);
      if (!operation || !state || operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_not_found' };
      if (operation.status !== 'reserved') return { ok: false, reason: 'capability_operation_already_finalized' };
      if (operation.reservation_token !== reservationToken) return { ok: false, reason: 'capability_reservation_owner_mismatch' };
      operation.status = 'committed';
      operation.outcome = outcome;
      operation.committed_at = nowMs(now);
      state.reserved_amount -= operation.amount;
      state.consumed_amount += operation.amount;
      return { ok: true, outcome, consumed: state.consumed_amount, remaining: state.budget_amount - state.consumed_amount - state.reserved_amount };
    },
    async reconcileSpend({ capabilityId, operationId, actionDigest, evidenceDigest, outcome = 'executed', now = Date.now } = {}) {
      const operation = operations.get(operationId);
      if (!operation || operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_not_found' };
      if (operation.status !== 'committed' || operation.outcome !== 'indeterminate') return { ok: false, reason: 'capability_operation_not_indeterminate' };
      if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
      if (outcome !== 'executed' || typeof evidenceDigest !== 'string' || !ACTION_DIGEST_RE.test(evidenceDigest)) {
        return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
      }
      if (operation.reconciliation_outcome) {
        return operation.reconciliation_outcome === outcome && operation.reconciliation_evidence_digest === evidenceDigest
          ? { ok: true, idempotent: true, outcome }
          : { ok: false, reason: 'capability_reconciliation_conflict' };
      }
      operation.reconciliation_outcome = outcome;
      operation.reconciliation_evidence_digest = evidenceDigest;
      operation.reconciled_at = nowMs(now);
      return { ok: true, idempotent: false, outcome };
    },
    getState(capabilityId) {
      const state = states.get(capabilityId);
      return state ? Object.freeze({ ...state }) : null;
    },
    getOperation(operationId) {
      const operation = operations.get(operationId);
      return operation ? Object.freeze({ ...operation }) : null;
    },
  };
}

export const CAPABILITY_STATE_TABLE = 'ep_capability_state';
export const CAPABILITY_OPERATION_TABLE = 'ep_capability_operations';
export const CAPABILITY_STATE_DDL = `CREATE TABLE IF NOT EXISTS ${CAPABILITY_STATE_TABLE} (
  capability_id TEXT PRIMARY KEY,
  capability_fingerprint TEXT NOT NULL CHECK (capability_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  budget_amount BIGINT NOT NULL CHECK (budget_amount >= 0),
  currency TEXT NOT NULL,
  consumed_amount BIGINT NOT NULL DEFAULT 0 CHECK (consumed_amount >= 0),
  reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE ${CAPABILITY_STATE_TABLE} ADD COLUMN IF NOT EXISTS capability_fingerprint TEXT;
CREATE TABLE IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE} (
  operation_id TEXT PRIMARY KEY,
  capability_id TEXT NOT NULL REFERENCES ${CAPABILITY_STATE_TABLE}(capability_id),
  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  amount BIGINT NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('reserved', 'committed')),
  reservation_token TEXT NOT NULL,
  outcome TEXT,
  reconciliation_outcome TEXT CHECK (reconciliation_outcome IN ('executed')),
  reconciliation_evidence_digest TEXT CHECK (reconciliation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  reserved_at TIMESTAMPTZ NOT NULL,
  committed_at TIMESTAMPTZ,
  reconciled_at TIMESTAMPTZ,
  CHECK (
    (reconciliation_outcome IS NULL AND reconciliation_evidence_digest IS NULL AND reconciled_at IS NULL)
    OR
    (reconciliation_outcome IS NOT NULL AND reconciliation_evidence_digest IS NOT NULL AND reconciled_at IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE}_capability_idx ON ${CAPABILITY_OPERATION_TABLE}(capability_id);`;

export const CAPABILITY_SQL = Object.freeze({
  register: `INSERT INTO ${CAPABILITY_STATE_TABLE} (capability_id, budget_amount, currency, expires_at, capability_fingerprint) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(${CAPABILITY_STATE_TABLE}.capability_fingerprint, EXCLUDED.capability_fingerprint) WHERE ${CAPABILITY_STATE_TABLE}.budget_amount = EXCLUDED.budget_amount AND ${CAPABILITY_STATE_TABLE}.currency = EXCLUDED.currency AND ${CAPABILITY_STATE_TABLE}.expires_at = EXCLUDED.expires_at`,
  readState: `SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at FROM ${CAPABILITY_STATE_TABLE} WHERE capability_id = $1 FOR UPDATE`,
  readOperation: `SELECT operation_id, capability_id, action_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, reconciled_at FROM ${CAPABILITY_OPERATION_TABLE} WHERE operation_id = $1 FOR UPDATE`,
  insertOperation: `INSERT INTO ${CAPABILITY_OPERATION_TABLE} (operation_id, capability_id, action_digest, amount, currency, status, reservation_token, reserved_at) VALUES ($1, $2, $3, $4, $5, 'reserved', $6, $7)`,
  reserveState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND budget_amount - consumed_amount - reserved_amount >= $2`,
  commitOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'committed', outcome = $3, committed_at = $4 WHERE operation_id = $1 AND capability_id = $2 AND status = 'reserved' AND reservation_token = $5`,
  reconcileOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET reconciliation_outcome = $3, reconciliation_evidence_digest = $4, reconciled_at = $5 WHERE operation_id = $1 AND capability_id = $2 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL`,
  commitState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2`,
});

/**
 * Production adapter. `transaction` MUST run the callback on one database
 * connection with BEGIN/COMMIT/ROLLBACK. The state row is locked before the
 * operation row is inserted, making budget reservation linearizable per
 * capability and refusing all ambiguous database outcomes.
 */
export function createPostgresCapabilityStore({ transaction } = {}) {
  if (typeof transaction !== 'function') throw new TypeError('createPostgresCapabilityStore requires a transaction(callback) function');
  return {
    durable: true,
    async registerCapability(capabilityReceipt) {
      const verified = verifyCapabilityReceipt(capabilityReceipt, { allowUntrustedIssuer: true });
      if (!verified.ok) return false;
      const state = capabilityStateFromEnvelope(capabilityReceipt);
      return transaction(async (query) => {
        await query(CAPABILITY_SQL.register, [state.capability_id, state.budget_amount, capabilityReceipt.capability.budget.currency, new Date(state.expires_at).toISOString(), state.capability_fingerprint]);
        const result = await query(CAPABILITY_SQL.readState, [state.capability_id]);
        const row = result?.rows?.[0];
        return Boolean(row)
          && row.capability_fingerprint === state.capability_fingerprint
          && Number(row.budget_amount) === state.budget_amount
          && row.currency === state.currency
          && Date.parse(row.expires_at) === state.expires_at;
      });
    },
    async reserveSpend({ capabilityId, capabilityFingerprint, operationId, actionDigest, amount, currency, now = Date.now } = {}) {
      validateOperationId(operationId); validateAmount(amount); validateCurrency(currency);
      if (typeof actionDigest !== 'string' || !ACTION_DIGEST_RE.test(actionDigest)) throw new TypeError('action_digest must be SHA-256');
      const at = nowMs(now);
      return transaction(async (query) => {
        const stateResult = await query(CAPABILITY_SQL.readState, [capabilityId]);
        const state = stateResult?.rows?.[0];
        if (!state) return { ok: false, reason: 'capability_not_registered' };
        if (state.capability_fingerprint !== capabilityFingerprint) return { ok: false, reason: 'capability_envelope_mismatch' };
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationId]);
        if (operationResult?.rows?.[0]) return { ok: false, reason: operationResult.rows[0].status === 'reserved' ? 'operation_in_flight' : 'operation_already_committed' };
        if (at >= Date.parse(state.expires_at)) return { ok: false, reason: 'capability_expired' };
        if (currency !== state.currency) return { ok: false, reason: 'currency_mismatch' };
        const available = Number(state.budget_amount) - Number(state.consumed_amount) - Number(state.reserved_amount);
        if (!Number.isSafeInteger(available) || available < amount) return { ok: false, reason: 'budget_exceeded' };
        const token = randomUUID();
        const reserved = await query(CAPABILITY_SQL.reserveState, [capabilityId, amount]);
        if (reserved?.rowCount !== 1) return { ok: false, reason: 'budget_reservation_conflict' };
        await query(CAPABILITY_SQL.insertOperation, [operationId, capabilityId, actionDigest, amount, currency, token, new Date(at).toISOString()]);
        return { ok: true, operation_id: operationId, reservation_token: token, remaining: available - amount };
      });
    },
    async commitSpend({ capabilityId, operationId, reservationToken, outcome = 'executed', now = Date.now } = {}) {
      validateOperationId(operationId);
      if (typeof reservationToken !== 'string' || reservationToken.length < 16) return { ok: false, reason: 'capability_reservation_token_invalid' };
      const at = nowMs(now);
      return transaction(async (query) => {
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationId]);
        const operation = operationResult?.rows?.[0];
        if (!operation || operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_not_found' };
        if (operation.status !== 'reserved') return { ok: false, reason: 'capability_operation_already_finalized' };
        if (operation.reservation_token !== reservationToken) return { ok: false, reason: 'capability_reservation_owner_mismatch' };
        const committed = await query(CAPABILITY_SQL.commitOperation, [operationId, capabilityId, outcome, new Date(at).toISOString(), reservationToken]);
        if (committed?.rowCount !== 1) throw new Error('capability operation transition lost ownership; transaction must roll back');
        const updated = await query(CAPABILITY_SQL.commitState, [capabilityId, operation.amount]);
        if (updated?.rowCount !== 1) throw new Error('capability state transition conflicted; transaction must roll back');
        return { ok: true, outcome, consumed: null, remaining: null };
      });
    },
    async reconcileSpend({ capabilityId, operationId, actionDigest, evidenceDigest, outcome = 'executed', now = Date.now } = {}) {
      validateOperationId(operationId);
      if (typeof actionDigest !== 'string' || !ACTION_DIGEST_RE.test(actionDigest)
          || typeof evidenceDigest !== 'string' || !ACTION_DIGEST_RE.test(evidenceDigest)
          || outcome !== 'executed') {
        return { ok: false, reason: 'capability_reconciliation_evidence_invalid' };
      }
      const at = nowMs(now);
      return transaction(async (query) => {
        const operationResult = await query(CAPABILITY_SQL.readOperation, [operationId]);
        const operation = operationResult?.rows?.[0];
        if (!operation || operation.capability_id !== capabilityId) return { ok: false, reason: 'capability_operation_not_found' };
        if (operation.status !== 'committed' || operation.outcome !== 'indeterminate') return { ok: false, reason: 'capability_operation_not_indeterminate' };
        if (operation.action_digest !== actionDigest) return { ok: false, reason: 'capability_reconciliation_action_mismatch' };
        if (operation.reconciliation_outcome) {
          return operation.reconciliation_outcome === outcome
              && operation.reconciliation_evidence_digest === evidenceDigest
            ? { ok: true, idempotent: true, outcome }
            : { ok: false, reason: 'capability_reconciliation_conflict' };
        }
        const updated = await query(CAPABILITY_SQL.reconcileOperation, [
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

function capabilityAmount(action, capability) {
  const amount = validateAmount(action?.amount, 'action.amount');
  const currency = validateCurrency(action?.currency);
  if (currency !== capability.budget.currency) throw new TypeError('capability action currency does not match the budget');
  if (amount <= 0) throw new TypeError('capability action amount must be greater than zero');
  return { amount, currency };
}

/**
 * Execute one spend under a capability. The base EP receipt is checked on
 * every spend with consumptionMode=none; the capability store is the replay
 * and budget authority. The external function is entered only after the
 * atomic reservation succeeds. Any exception after entry permanently commits
 * the reserved amount as indeterminate.
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
  operationId = null,
  now = Date.now,
  thresholdSecretVerified = false,
} = {}) {
  const verified = verifyCapabilityReceipt(capabilityReceipt, { trustedIssuerKeys });
  if (!verified.ok) return { ok: false, reason: verified.reason };
  if ((verified.capability.threshold.m !== 1 || verified.capability.threshold.n !== 1) && thresholdSecretVerified !== true) return { ok: false, reason: 'threshold_shares_required' };
  if (!verifySecret(verified.capability, secret)) return { ok: false, reason: 'invalid_secret' };
  if (!store || typeof store.reserveSpend !== 'function' || typeof store.commitSpend !== 'function') return { ok: false, reason: 'capability_store_required' };
  if (typeof executeAction !== 'function') throw new TypeError('executeWithCapability requires executeAction');
  try {
    validateOperationId(operationId);
  } catch {
    return { ok: false, reason: 'capability_operation_id_required' };
  }
  let immutableAction;
  let scope;
  try {
    immutableAction = structuredClone(observedAction ?? action);
    scope = verifyCapabilityScope(verified.capability, immutableAction, operationId, { resolveCaid });
  } catch {
    return { ok: false, reason: 'capability_action_invalid' };
  }
  if (!scope.ok) return { ok: false, reason: scope.reason, scope };
  let spend;
  try {
    spend = capabilityAmount(action, verified.capability);
  } catch (error) {
    return { ok: false, reason: error?.message || 'capability_action_invalid' };
  }
  let authorization = null;
  if (gate && typeof gate.check === 'function') {
    authorization = await gate.check({
      selector,
      receipt: verified.receipt,
      observedAction: immutableAction,
      consumptionMode: 'none',
      capability: { capabilityReceipt, action, operationId },
    });
    if (!authorization?.allow) return { ok: false, reason: 'base_receipt_rejected', authorization };
  } else if (typeof verifyBaseReceipt === 'function') {
    const result = await verifyBaseReceipt(verified.receipt, { action, selector, observedAction: immutableAction, scope });
    if (result !== true && result?.ok !== true) return { ok: false, reason: 'base_receipt_rejected', authorization: result };
  } else {
    return { ok: false, reason: 'base_receipt_verifier_required' };
  }
  const reserved = await store.reserveSpend({
    capabilityId: verified.capability.id,
    capabilityFingerprint: capabilityEnvelopeFingerprint(capabilityReceipt),
    operationId,
    actionDigest: scope.action_digest,
    amount: spend.amount,
    currency: spend.currency,
    now,
  });
  if (!reserved?.ok) return { ok: false, reason: reserved?.reason || 'capability_reservation_refused', authorization };
  try {
    const result = await executeAction(structuredClone(action), {
      capabilityReceipt,
      authorization,
      operation_id: operationId,
      action_digest: scope.action_digest,
      ...(scope.caid ? { caid: scope.caid } : {}),
      observed_action: immutableAction,
      reservation: reserved,
    });
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'executed', now });
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
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'indeterminate', now }).catch(() => ({ ok: false }));
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

/** Execute a capability requiring m-of-n Shamir shares. */
export async function executeWithThreshold({ capabilityReceipt, shares, ...options } = {}) {
  const verified = verifyCapabilityReceipt(capabilityReceipt, { trustedIssuerKeys: options.trustedIssuerKeys || [] });
  if (!verified.ok) return { ok: false, reason: verified.reason };
  try {
    const secret = reconstructCapabilitySecret(shares, verified.capability.threshold);
    return executeWithCapability({ ...options, capabilityReceipt, secret, thresholdSecretVerified: true });
  } catch (error) {
    return { ok: false, reason: error?.message === 'insufficient capability shares' ? 'insufficient_shares' : 'invalid_shares' };
  }
}

/**
 * Authentically reconcile a committed indeterminate capability operation.
 * The generic path records only a proven `executed` outcome and never restores
 * budget. A deployment that wants to prove the effect boundary was not crossed
 * needs a separate, action-specific negative-evidence profile.
 */
export async function reconcileCapabilityOperation({
  store,
  capabilityId,
  operationId,
  action,
  evidence,
  verifyEvidence,
  now = Date.now,
} = {}) {
  if (!store || typeof store.reconcileSpend !== 'function') return { ok: false, reason: 'capability_reconciliation_store_required' };
  try {
    validateCapabilityId(capabilityId);
    validateOperationId(operationId);
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
      operation_id: operationId,
      action: immutableAction,
      action_digest: actionDigest,
    });
  } catch {
    return { ok: false, reason: 'capability_reconciliation_evidence_rejected' };
  }
  if (!isRecord(verified) || verified.valid !== true
      || verified.outcome !== 'executed'
      || verified.action_digest !== actionDigest
      || typeof verified.evidence_digest !== 'string'
      || !ACTION_DIGEST_RE.test(verified.evidence_digest)) {
    return { ok: false, reason: 'capability_reconciliation_evidence_rejected' };
  }
  const result = await store.reconcileSpend({
    capabilityId,
    operationId,
    actionDigest,
    evidenceDigest: verified.evidence_digest,
    outcome: 'executed',
    now,
  });
  return result?.ok
    ? { ok: true, outcome: 'executed', action_digest: actionDigest, evidence_digest: verified.evidence_digest, idempotent: result.idempotent === true }
    : { ok: false, reason: result?.reason || 'capability_reconciliation_refused' };
}

/**
 * Issue a bounded child capability from a parent capability.
 *
 * Delegation is issuer-authorized metadata plus an atomic parent spend. The
 * parent budget is committed as `delegated` before the child is registered;
 * if child registration fails, the safe result is an orphaned child issuance
 * that must be reconciled, never a child with unbacked budget.
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
    const parentMembers = parentScope.profile === CAPABILITY_CAID_SCOPE_PROFILE ? parentScope.caids : parentScope.action_digests;
    const childMembers = childScope.profile === CAPABILITY_CAID_SCOPE_PROFILE ? childScope.caids : childScope.action_digests;
    if (childScope.profile !== parentScope.profile
        || childScope.operation_id_field !== parentScope.operation_id_field
        || childMembers.some((member) => !parentMembers.includes(member))) {
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
    return { ok: false, reason: error?.message || 'delegation_invalid' };
  }
}

export default {
  CAPABILITY_RECEIPT_VERSION,
  CAPABILITY_STATE_VERSION,
  CAPABILITY_SHARE_VERSION,
  CAPABILITY_SCOPE_PROFILE,
  CAPABILITY_CAID_SCOPE_PROFILE,
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
  executeWithCapability,
  executeWithThreshold,
  reconcileCapabilityOperation,
  delegateCapabilityReceipt,
};
