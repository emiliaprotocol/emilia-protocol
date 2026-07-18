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

// 2^521 - 1 is a prime and is comfortably larger than a 256-bit secret.
const FIELD = (2n ** 521n) - 1n;
const SHARE_BYTES = 66;
const HASH_BYTES = 32;
const MAX_CURRENCY_BYTES = 32;
const MAX_OPERATION_ID_BYTES = 128;
const MAX_DELEGATES = 64;

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

function capabilityUnsignedBody(receipt, capability) {
  return {
    '@version': CAPABILITY_RECEIPT_VERSION,
    base_receipt_id: receipt.payload.receipt_id,
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
    capability: capabilityReceipt.capability,
    issuer_public_key: signature.public_key,
  }), 'utf8'))}`;
}

function assertDelegationChain(chain) {
  if (chain === undefined) return [];
  if (!Array.isArray(chain) || chain.length > MAX_DELEGATES) throw new TypeError('delegation_chain must be a bounded array');
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
  assertDelegationChain(capability.delegation_chain);
  if (capability.consumed !== 0) throw new TypeError('capability consumed is issuer-initialized and must be zero');
  return true;
}

function verifyTrustedIssuer(publicKey, trustedIssuerKeys) {
  if (!Array.isArray(trustedIssuerKeys) || trustedIssuerKeys.length === 0) return true;
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
  if (receipt.public_key && receipt.public_key !== publicKey) throw new TypeError('issuerPrivateKey does not match base receipt public_key');
  const capability = {
    version: CAPABILITY_STATE_VERSION,
    id: validateCapabilityId(String(capabilityId)),
    secret_hash: normalizedSecret.hash,
    budget: { amount: validateAmount(budget.amount, 'budget.amount'), currency: validateCurrency(budget.currency) },
    consumed: 0,
    threshold: normalizedThreshold,
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
export function verifyCapabilityReceipt(capabilityReceipt, { trustedIssuerKeys = [] } = {}) {
  try {
    if (!isRecord(capabilityReceipt) || capabilityReceipt['@version'] !== CAPABILITY_RECEIPT_VERSION) return { ok: false, reason: 'malformed_capability_receipt' };
    const receipt = validateBaseReceipt(capabilityReceipt.receipt);
    assertCapabilityShape(capabilityReceipt.capability);
    const signature = capabilitySignature(capabilityReceipt);
    if (!signature || !verifyTrustedIssuer(signature.public_key, trustedIssuerKeys)) return { ok: false, reason: 'capability_issuer_not_trusted' };
    if (receipt.public_key && receipt.public_key !== signature.public_key) return { ok: false, reason: 'capability_issuer_mismatch' };
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
      const verified = verifyCapabilityReceipt(capabilityReceipt);
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
    async reserveSpend({ capabilityId, capabilityFingerprint, operationId, amount, currency, now = Date.now } = {}) {
      validateOperationId(operationId);
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
      operations.set(operationId, { capability_id: capabilityId, amount, currency, status: 'reserved', reservation_token: reservationToken, reserved_at: at });
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
  amount BIGINT NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('reserved', 'committed')),
  reservation_token TEXT NOT NULL,
  outcome TEXT,
  reserved_at TIMESTAMPTZ NOT NULL,
  committed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ${CAPABILITY_OPERATION_TABLE}_capability_idx ON ${CAPABILITY_OPERATION_TABLE}(capability_id);`;

export const CAPABILITY_SQL = Object.freeze({
  register: `INSERT INTO ${CAPABILITY_STATE_TABLE} (capability_id, budget_amount, currency, expires_at, capability_fingerprint) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(${CAPABILITY_STATE_TABLE}.capability_fingerprint, EXCLUDED.capability_fingerprint) WHERE ${CAPABILITY_STATE_TABLE}.budget_amount = EXCLUDED.budget_amount AND ${CAPABILITY_STATE_TABLE}.currency = EXCLUDED.currency AND ${CAPABILITY_STATE_TABLE}.expires_at = EXCLUDED.expires_at`,
  readState: `SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at FROM ${CAPABILITY_STATE_TABLE} WHERE capability_id = $1 FOR UPDATE`,
  readOperation: `SELECT operation_id, capability_id, amount, currency, status, reservation_token FROM ${CAPABILITY_OPERATION_TABLE} WHERE operation_id = $1 FOR UPDATE`,
  insertOperation: `INSERT INTO ${CAPABILITY_OPERATION_TABLE} (operation_id, capability_id, amount, currency, status, reservation_token, reserved_at) VALUES ($1, $2, $3, $4, 'reserved', $5, $6)`,
  reserveState: `UPDATE ${CAPABILITY_STATE_TABLE} SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND budget_amount - consumed_amount - reserved_amount >= $2`,
  commitOperation: `UPDATE ${CAPABILITY_OPERATION_TABLE} SET status = 'committed', outcome = $3, committed_at = $4 WHERE operation_id = $1 AND capability_id = $2 AND status = 'reserved' AND reservation_token = $5`,
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
      const verified = verifyCapabilityReceipt(capabilityReceipt);
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
    async reserveSpend({ capabilityId, capabilityFingerprint, operationId, amount, currency, now = Date.now } = {}) {
      validateOperationId(operationId); validateAmount(amount); validateCurrency(currency);
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
        await query(CAPABILITY_SQL.insertOperation, [operationId, capabilityId, amount, currency, token, new Date(at).toISOString()]);
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
  operationId = randomUUID(),
  now = Date.now,
  thresholdSecretVerified = false,
} = {}) {
  const verified = verifyCapabilityReceipt(capabilityReceipt, { trustedIssuerKeys });
  if (!verified.ok) return { ok: false, reason: verified.reason };
  if ((verified.capability.threshold.m !== 1 || verified.capability.threshold.n !== 1) && thresholdSecretVerified !== true) return { ok: false, reason: 'threshold_shares_required' };
  if (!verifySecret(verified.capability, secret)) return { ok: false, reason: 'invalid_secret' };
  if (!store || typeof store.reserveSpend !== 'function' || typeof store.commitSpend !== 'function') return { ok: false, reason: 'capability_store_required' };
  if (typeof executeAction !== 'function') throw new TypeError('executeWithCapability requires executeAction');
  let spend;
  try {
    spend = capabilityAmount(action, verified.capability);
  } catch (error) {
    return { ok: false, reason: error?.message || 'capability_action_invalid' };
  }
  let authorization = null;
  if (gate && typeof gate.check === 'function') {
    authorization = await gate.check({ selector, receipt: verified.receipt, observedAction, consumptionMode: 'none' });
    if (!authorization?.allow) return { ok: false, reason: 'base_receipt_rejected', authorization };
  } else if (typeof verifyBaseReceipt === 'function') {
    const result = await verifyBaseReceipt(verified.receipt, { action, selector, observedAction });
    if (result !== true && result?.ok !== true) return { ok: false, reason: 'base_receipt_rejected', authorization: result };
  } else {
    return { ok: false, reason: 'base_receipt_verifier_required' };
  }
  const reserved = await store.reserveSpend({ capabilityId: verified.capability.id, capabilityFingerprint: capabilityEnvelopeFingerprint(capabilityReceipt), operationId, amount: spend.amount, currency: spend.currency, now });
  if (!reserved?.ok) return { ok: false, reason: reserved?.reason || 'capability_reservation_refused', authorization };
  try {
    const result = await executeAction(action, { capabilityReceipt, authorization, operation_id: operationId, reservation: reserved });
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'executed', now });
    if (!committed?.ok) return { ok: false, reason: 'capability_commit_indeterminate', authorization, result, operation_id: operationId };
    return { ok: true, result, authorization, operation_id: operationId, remaining: committed.remaining };
  } catch (error) {
    const committed = await store.commitSpend({ capabilityId: verified.capability.id, operationId, reservationToken: reserved.reservation_token, outcome: 'indeterminate', now }).catch(() => ({ ok: false }));
    return { ok: false, reason: committed.ok ? 'effect_indeterminate' : 'capability_commit_indeterminate', authorization, operation_id: operationId };
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
    const parentOperationId = validateOperationId(operationId || `delegation:${childId}`);
    const child = mintCapabilityReceipt(verified.receipt, {
      issuerPrivateKey,
      budget: { amount: childAmount, currency },
      expiry: childExpiry,
      threshold,
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
  CAPABILITY_STATE_DDL,
  CAPABILITY_SQL,
  mintCapabilityReceipt,
  verifyCapabilityReceipt,
  splitCapabilitySecret,
  reconstructCapabilitySecret,
  createMemoryCapabilityStore,
  createPostgresCapabilityStore,
  executeWithCapability,
  executeWithThreshold,
  delegateCapabilityReceipt,
};
