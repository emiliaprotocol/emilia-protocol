/**
 * EMILIA Protocol — EP Commit (Signed Pre-Action Authorization)
 *
 * An EP Commit is a signed authorization token proving that a machine action
 * was evaluated under policy BEFORE the action proceeded. It is the pre-action
 * counterpart to a receipt (post-action record).
 *
 * Decision vocabulary: allow / review / deny (canonical EP vocabulary)
 * Action types: install / connect / delegate / transact
 * Signature algorithm: Ed25519 (fast, small, no patents)
 *
 * EP does not enforce, hold, or settle monetary value.
 * EP proves evaluation happened, not money movement.
 *
 * State machine:
 *   active → fulfilled   (action completed successfully)
 *   active → revoked     (policy change, abuse discovered, manual revocation)
 *   active → expired     (automatic when current_time > expires_at)
 *   fulfilled/revoked/expired → no further transitions (terminal)
 *
 * A fulfilled commit's RECEIPT can be disputed, but the commit status itself
 * stays fulfilled.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { verifyDelegation } from '@/lib/delegation';

// ── Constants ────────────────────────────────────────────────────────────────

const COMMIT_PREFIX = 'epc_';
const VALID_ACTIONS = new Set(['install', 'connect', 'delegate', 'transact']);
const VALID_DECISIONS = new Set(['allow', 'review', 'deny']);
const TERMINAL_STATUSES = new Set(['fulfilled', 'revoked', 'expired']);

/** Default expiry: 10 minutes (configurable via options) */
const DEFAULT_EXPIRY_MS = 10 * 60 * 1000;

// ── Nonce replay protection (in-memory supplement to DB UNIQUE constraint) ──
const _usedNonces = new Set();

// ── Ed25519 Key Management ──────────────────────────────────────────────────

/**
 * DER prefix for Ed25519 PKCS#8 private key (RFC 8410).
 */
const ED25519_PKCS8_DER_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex'
);

/**
 * DER prefix for Ed25519 SPKI public key.
 */
const ED25519_SPKI_DER_PREFIX = Buffer.from(
  '302a300506032b6570032100',
  'hex'
);

/**
 * Get or generate the Ed25519 signing keypair.
 * Uses EP_COMMIT_SIGNING_KEY env var (base64-encoded 32-byte seed) if set,
 * otherwise generates an ephemeral keypair (suitable for dev/test).
 *
 * @returns {{ privateKey: crypto.KeyObject, publicKey: crypto.KeyObject, publicKeyBase64: string }}
 */
function getSigningKeypair() {
  const envKey = process.env.EP_COMMIT_SIGNING_KEY;

  if (envKey) {
    const seed = Buffer.from(envKey, 'base64');
    if (seed.length !== 32) {
      throw new Error('EP_COMMIT_SIGNING_KEY must be a base64-encoded 32-byte Ed25519 seed');
    }
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]);
    const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey(privateKey);
    const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12); // strip SPKI header
    return { privateKey, publicKey, publicKeyBase64: pubRaw.toString('base64') };
  }

  // Ephemeral keypair for dev/test
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
  return { privateKey, publicKey, publicKeyBase64: pubRaw.toString('base64') };
}

// Cache the keypair for the process lifetime
let _cachedKeypair = null;
function ensureKeypair() {
  if (!_cachedKeypair) {
    _cachedKeypair = getSigningKeypair();
  }
  return _cachedKeypair;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function newCommitId() {
  return `${COMMIT_PREFIX}${crypto.randomUUID().replace(/-/g, '')}`;
}

function newNonce() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Build the canonical JSON payload for signing.
 * Fields are sorted alphabetically for deterministic serialization.
 */
function buildCanonicalPayload(fields) {
  const sorted = {};
  for (const key of Object.keys(fields).sort()) {
    if (fields[key] !== undefined) {
      sorted[key] = fields[key];
    }
  }
  return JSON.stringify(sorted);
}

/**
 * Sign a payload with Ed25519.
 * @returns {{ signature: string, publicKeyBase64: string }}
 */
function signPayload(payload) {
  const { privateKey, publicKeyBase64 } = ensureKeypair();
  const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey);
  return { signature: sig.toString('base64'), publicKeyBase64 };
}

/**
 * Verify an Ed25519 signature.
 * @param {string} payload - The canonical JSON string
 * @param {string} signatureBase64 - Base64-encoded signature
 * @param {string} publicKeyBase64 - Base64-encoded 32-byte public key
 * @returns {boolean}
 */
function verifySignature(payload, signatureBase64, publicKeyBase64) {
  try {
    const pubRaw = Buffer.from(publicKeyBase64, 'base64');
    if (pubRaw.length !== 32) return false;
    const spkiDer = Buffer.concat([ED25519_SPKI_DER_PREFIX, pubRaw]);
    const keyObject = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    const sigBuffer = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, Buffer.from(payload, 'utf8'), keyObject, sigBuffer);
  } catch {
    return false;
  }
}

/**
 * Get a Supabase service client, returning null if env is not configured.
 * Used for graceful degradation when the commits table doesn't exist yet.
 */
function tryGetServiceClient() {
  try {
    return getServiceClient();
  } catch {
    return null;
  }
}

// ── Lightweight error class ─────────────────────────────────────────────────

export class CommitError extends Error {
  constructor(message, status = 500, code = 'COMMIT_ERROR') {
    super(message);
    this.name = 'CommitError';
    this.status = status;
    this.code = code;
  }
}

// ── Core API ────────────────────────────────────────────────────────────────

/**
 * Issue a new EP Commit: evaluate policy, sign, and store.
 *
 * @param {Object} params
 * @param {string} params.entity_id - Entity being evaluated
 * @param {string} [params.principal_id] - Human/org principal
 * @param {string} [params.counterparty_entity_id] - Other side of interaction
 * @param {string} [params.delegation_id] - If acting under delegation
 * @param {string} params.action_type - install | connect | delegate | transact
 * @param {Object} [params.scope] - Action scope details
 * @param {number} [params.max_value_usd] - Advisory only. This field informs policy evaluation.
 *   EP does not enforce, hold, or settle monetary value.
 * @param {Object} [params.context] - Context for trust evaluation
 * @param {string|Object} [params.policy] - Policy name or custom policy object
 * @param {number} [params.expiry_ms] - Custom expiry in milliseconds (default: 10 min)
 * @returns {Promise<Object>} The signed commit object
 */
export async function issueCommit({
  entity_id,
  principal_id = null,
  counterparty_entity_id = null,
  delegation_id = null,
  action_type,
  scope = null,
  max_value_usd = null,
  context = null,
  policy = null,
  expiry_ms = DEFAULT_EXPIRY_MS,
}) {
  // ── Validate inputs ──
  if (!entity_id) {
    throw new CommitError('entity_id is required', 400, 'VALIDATION_ERROR');
  }
  if (!action_type || !VALID_ACTIONS.has(action_type)) {
    throw new CommitError(
      `action_type must be one of: ${[...VALID_ACTIONS].join(', ')}`,
      400, 'VALIDATION_ERROR'
    );
  }

  // Clamp expiry to 5-15 minute range
  const clampedExpiry = Math.max(5 * 60_000, Math.min(15 * 60_000, expiry_ms));

  // ── Delegation verification (if provided) ──
  if (delegation_id) {
    const delegationResult = await verifyDelegation(delegation_id, action_type);
    if (!delegationResult.valid) {
      throw new CommitError(
        `Delegation invalid: ${delegationResult.reason}`,
        403, 'DELEGATION_INVALID'
      );
    }
    if (delegationResult.action_permitted === false) {
      throw new CommitError(
        `Action "${action_type}" not permitted by delegation: ${delegationResult.reason}`,
        403, 'DELEGATION_SCOPE_DENIED'
      );
    }
  }

  // ── Policy evaluation via canonical evaluator ──
  const evaluation = await canonicalEvaluate(entity_id, {
    context,
    policy,
    includeDisputes: true,
    includeEstablishment: false,
  });

  if (evaluation.error) {
    throw new CommitError(
      `Entity evaluation failed: ${evaluation.error}`,
      evaluation.status || 400, 'EVALUATION_FAILED'
    );
  }

  // ── Determine trust decision ──
  let decision;
  if (evaluation.policyResult) {
    decision = evaluation.policyResult.pass ? 'allow' : 'deny';
    // If deny but has only warnings (no hard failures), downgrade to review
    if (!evaluation.policyResult.pass
        && evaluation.policyResult.failures?.length === 0
        && evaluation.policyResult.warnings?.length > 0) {
      decision = 'review';
    }
  } else {
    // Trust-critical commits require explicit policy evaluation.
    // No raw score fallback — scores may be on different scales (0-1 vs 0-100)
    // and bypassing policy review is a security risk. Default to 'review'.
    decision = 'review';
  }

  // ── Build commit ──
  const commit_id = newCommitId();
  const nonce = newNonce();
  const now = new Date();
  const expires_at = new Date(now.getTime() + clampedExpiry);

  const kid = 'ep-signing-key-1';

  const canonicalFields = {
    commit_id,
    entity_id,
    kid,
    principal_id,
    counterparty_entity_id,
    delegation_id,
    action_type,
    decision,
    scope,
    max_value_usd,
    context,
    nonce,
    expires_at: expires_at.toISOString(),
    created_at: now.toISOString(),
  };

  const canonicalPayload = buildCanonicalPayload(canonicalFields);
  const { signature, publicKeyBase64 } = signPayload(canonicalPayload);

  const commitRecord = {
    commit_id,
    entity_id,
    kid,
    principal_id,
    counterparty_entity_id,
    delegation_id,
    action_type,
    decision,
    scope,
    max_value_usd,
    context,
    policy_snapshot: evaluation.policyResult || null,
    nonce,
    signature,
    public_key: publicKeyBase64,
    expires_at: expires_at.toISOString(),
    status: 'active',
    evaluation_result: {
      score: evaluation.score,
      confidence: evaluation.confidence,
      profile: evaluation.profile,
      anomaly: evaluation.anomaly,
    },
    created_at: now.toISOString(),
  };

  // ── Store in DB (graceful degradation) ──
  const supabase = tryGetServiceClient();
  if (supabase) {
    const { error } = await supabase
      .from('commits')
      .insert(commitRecord);

    if (error) {
      // 42P01 = table doesn't exist yet
      if (error.code === '42P01') {
        console.warn('[EP Commit] commits table not yet created — returning in-memory commit');
      } else {
        throw new CommitError(`Failed to store commit: ${error.message}`, 500, 'DB_ERROR');
      }
    }
  }

  // Track nonce in memory for replay protection
  _usedNonces.add(nonce);

  return commitRecord;
}

/**
 * Verify an EP Commit: check signature, status, expiry, and replay.
 *
 * @param {string} commit_id_or_token - Commit ID to verify
 * @returns {Promise<{ valid: boolean, status: string, decision?: string, expires_at?: string, reasons: string[] }>}
 */
export async function verifyCommit(commit_id_or_token) {
  const reasons = [];

  // ── Fetch commit from DB ──
  const supabase = tryGetServiceClient();
  let commit = null;

  if (supabase) {
    const { data, error } = await supabase
      .from('commits')
      .select('*')
      .eq('commit_id', commit_id_or_token)
      .maybeSingle();

    if (error?.code === '42P01') {
      return { valid: false, status: 'unknown', reasons: ['not_found'] };
    }
    commit = data;
  }

  if (!commit) {
    return { valid: false, status: 'not_found', reasons: ['not_found'] };
  }

  // ── Check expiry (auto-expire if past) ──
  const now = new Date();
  if (commit.status === 'active' && new Date(commit.expires_at) < now) {
    // Auto-expire
    if (supabase) {
      await supabase
        .from('commits')
        .update({ status: 'expired' })
        .eq('commit_id', commit.commit_id)
        .eq('status', 'active');
    }
    commit.status = 'expired';
  }

  // ── Check status ──
  if (commit.status !== 'active') {
    reasons.push(commit.status);
    return {
      valid: false,
      status: commit.status,
      decision: commit.decision,
      expires_at: commit.expires_at,
      reasons,
    };
  }

  // ── Check nonce replay (does this nonce appear on a *different* commit?) ──
  if (commit.nonce) {
    const { data: dupeRows, error: dupeError } = await supabase
      .from('commits')
      .select('commit_id')
      .eq('nonce', commit.nonce)
      .neq('commit_id', commit.commit_id)
      .limit(1);

    if (!dupeError && dupeRows && dupeRows.length > 0) {
      reasons.push('nonce_reuse');
      return {
        valid: false,
        status: commit.status,
        decision: commit.decision,
        expires_at: commit.expires_at,
        reasons,
      };
    }
  }

  // ── Verify signature ──
  // TODO(trust-root): Currently verifies against the public_key embedded in the
  // commit record itself. This proves self-consistency but NOT that the commit was
  // signed by a trusted authority. Future: fetch the key set from /api/commit/keys
  // (or the .well-known/ep-trust.json discovery_endpoint), look up the key by
  // commit.kid, and verify against the discovered key instead of commit.public_key.
  const canonicalFields = {
    commit_id: commit.commit_id,
    entity_id: commit.entity_id,
    kid: commit.kid || 'ep-signing-key-1',
    principal_id: commit.principal_id,
    counterparty_entity_id: commit.counterparty_entity_id,
    delegation_id: commit.delegation_id,
    action_type: commit.action_type,
    decision: commit.decision,
    scope: commit.scope,
    max_value_usd: commit.max_value_usd != null ? Number(commit.max_value_usd) : null,
    context: commit.context,
    nonce: commit.nonce,
    expires_at: commit.expires_at,
    created_at: commit.created_at,
  };

  const canonicalPayload = buildCanonicalPayload(canonicalFields);
  const signatureValid = verifySignature(canonicalPayload, commit.signature, commit.public_key);

  if (!signatureValid) {
    reasons.push('invalid_signature');
    return {
      valid: false,
      status: commit.status,
      decision: commit.decision,
      expires_at: commit.expires_at,
      reasons,
    };
  }

  return {
    valid: true,
    status: 'active',
    decision: commit.decision,
    expires_at: commit.expires_at,
    reasons: [],
  };
}

/**
 * Revoke an active commit.
 *
 * @param {string} commit_id - Commit to revoke
 * @param {string} reason - Why the commit is being revoked
 * @returns {Promise<{ success: boolean, commit_id: string, reason?: string }>}
 */
export async function revokeCommit(commit_id, reason) {
  if (!commit_id) {
    throw new CommitError('commit_id is required', 400, 'VALIDATION_ERROR');
  }
  if (!reason) {
    throw new CommitError('reason is required for revocation', 400, 'VALIDATION_ERROR');
  }

  const supabase = tryGetServiceClient();
  if (!supabase) {
    return { success: false, commit_id, reason: 'Database not available' };
  }

  // Fetch current state
  const { data: commit, error: fetchError } = await supabase
    .from('commits')
    .select('status')
    .eq('commit_id', commit_id)
    .maybeSingle();

  if (fetchError?.code === '42P01') {
    return { success: false, commit_id, reason: 'commits table not yet created' };
  }
  if (!commit) {
    throw new CommitError('Commit not found', 404, 'NOT_FOUND');
  }

  // Only active commits can be revoked — terminal states are immutable
  if (commit.status !== 'active') {
    throw new CommitError(
      `Cannot revoke commit in '${commit.status}' state — terminal states are immutable`,
      409, 'INVALID_STATE_TRANSITION'
    );
  }

  const now = new Date().toISOString();
  const { error: updateError } = await supabase
    .from('commits')
    .update({ status: 'revoked', revoked_reason: reason, revoked_at: now })
    .eq('commit_id', commit_id)
    .eq('status', 'active'); // Optimistic concurrency: only update if still active

  if (updateError) {
    throw new CommitError(`Failed to revoke commit: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return { success: true, commit_id };
}

/**
 * Fulfill an active commit (action completed successfully).
 *
 * @param {string} commit_id - Commit to fulfill
 * @returns {Promise<Object>} The updated commit record
 */
export async function fulfillCommit(commit_id) {
  if (!commit_id) {
    throw new CommitError('commit_id is required', 400, 'VALIDATION_ERROR');
  }

  const supabase = tryGetServiceClient();
  if (!supabase) {
    throw new CommitError('Database not available', 503, 'DB_UNAVAILABLE');
  }

  // Fetch current state
  const { data: commit, error: fetchError } = await supabase
    .from('commits')
    .select('*')
    .eq('commit_id', commit_id)
    .maybeSingle();

  if (fetchError?.code === '42P01') {
    throw new CommitError('commits table not yet created', 503, 'TABLE_MISSING');
  }
  if (!commit) {
    throw new CommitError('Commit not found', 404, 'NOT_FOUND');
  }

  // Auto-expire check
  if (commit.status === 'active' && new Date(commit.expires_at) < new Date()) {
    await supabase
      .from('commits')
      .update({ status: 'expired' })
      .eq('commit_id', commit_id)
      .eq('status', 'active');
    throw new CommitError('Commit has expired', 409, 'COMMIT_EXPIRED');
  }

  // Only active commits can be fulfilled — terminal states are immutable
  if (commit.status !== 'active') {
    throw new CommitError(
      `Cannot fulfill commit in '${commit.status}' state — terminal states are immutable`,
      409, 'INVALID_STATE_TRANSITION'
    );
  }

  const now = new Date().toISOString();
  const { data: updated, error: updateError } = await supabase
    .from('commits')
    .update({ status: 'fulfilled', fulfilled_at: now })
    .eq('commit_id', commit_id)
    .eq('status', 'active')
    .select()
    .single();

  if (updateError) {
    throw new CommitError(`Failed to fulfill commit: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return updated;
}

/**
 * Get current commit status and metadata. Auto-expires if past expires_at.
 *
 * @param {string} commit_id
 * @returns {Promise<Object|null>} Commit record or null if not found
 */
export async function getCommitStatus(commit_id) {
  if (!commit_id) {
    throw new CommitError('commit_id is required', 400, 'VALIDATION_ERROR');
  }

  const supabase = tryGetServiceClient();
  if (!supabase) {
    return null;
  }

  const { data: commit, error } = await supabase
    .from('commits')
    .select('*')
    .eq('commit_id', commit_id)
    .maybeSingle();

  if (error?.code === '42P01') {
    return null;
  }
  if (!commit) {
    return null;
  }

  // Auto-expire if past expiry
  if (commit.status === 'active' && new Date(commit.expires_at) < new Date()) {
    await supabase
      .from('commits')
      .update({ status: 'expired' })
      .eq('commit_id', commit_id)
      .eq('status', 'active');
    commit.status = 'expired';
  }

  return commit;
}

/**
 * Bind a receipt to a fulfilled (or active) commit for post-action accountability.
 * This links the pre-action authorization (commit) to the post-action record (receipt).
 *
 * @param {string} commit_id
 * @param {string} receipt_id
 * @returns {Promise<{ success: boolean, commit_id: string, receipt_id: string }>}
 */
export async function bindReceiptToCommit(commit_id, receipt_id) {
  if (!commit_id || !receipt_id) {
    throw new CommitError('commit_id and receipt_id are required', 400, 'VALIDATION_ERROR');
  }

  const supabase = tryGetServiceClient();
  if (!supabase) {
    throw new CommitError('Database not available', 503, 'DB_UNAVAILABLE');
  }

  const { data: commit, error: fetchError } = await supabase
    .from('commits')
    .select('status')
    .eq('commit_id', commit_id)
    .maybeSingle();

  if (fetchError?.code === '42P01') {
    throw new CommitError('commits table not yet created', 503, 'TABLE_MISSING');
  }
  if (!commit) {
    throw new CommitError('Commit not found', 404, 'NOT_FOUND');
  }

  // Receipts can be bound to active or fulfilled commits
  if (commit.status !== 'active' && commit.status !== 'fulfilled') {
    throw new CommitError(
      `Cannot bind receipt to commit in '${commit.status}' state`,
      409, 'INVALID_STATE_FOR_RECEIPT'
    );
  }

  const { error: updateError } = await supabase
    .from('commits')
    .update({ receipt_id })
    .eq('commit_id', commit_id);

  if (updateError) {
    throw new CommitError(`Failed to bind receipt: ${updateError.message}`, 500, 'DB_ERROR');
  }

  return { success: true, commit_id, receipt_id };
}

// ── Testing utilities ───────────────────────────────────────────────────────

/**
 * Reset cached keypair and nonce set. For testing only.
 * @private
 */
export function _resetForTesting() {
  _cachedKeypair = null;
  _usedNonces.clear();
}

/**
 * Expose internal helpers for unit testing.
 * @private
 */
export const _internals = {
  buildCanonicalPayload,
  signPayload,
  verifySignature,
  newCommitId,
  newNonce,
  getPublicKeyBase64: () => ensureKeypair().publicKeyBase64,
  VALID_ACTIONS,
  VALID_DECISIONS,
  TERMINAL_STATUSES,
  DEFAULT_EXPIRY_MS,
};
