/**
 * EMILIA Protocol — EP Commit: Signed Pre-Action Authorization
 *
 * An EP Commit is a signed authorization token proving that a trust evaluation
 * occurred before an action was taken. It records the decision (allow/review/deny),
 * the scope, and the entity involved — without holding, escrowing, or settling
 * any monetary value.
 *
 * State machine: active → fulfilled | revoked | expired (all terminal)
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from './supabase.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_DECISIONS = ['allow', 'review', 'deny'];

const VALID_ACTION_TYPES = [
  'purchase',
  'delegation',
  'tool_invocation',
  'api_call',
  'data_access',
  'transfer',
  'registration',
];

const TERMINAL_STATES = ['fulfilled', 'revoked', 'expired'];

const DEFAULT_EXPIRY_MINUTES = 10;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateNonce() {
  return crypto.randomBytes(32).toString('hex'); // 64 hex chars = 32 bytes
}

function generateCommitId() {
  return `epc_${crypto.randomUUID().replace(/-/g, '')}`;
}

function signCommit(commitPayload) {
  // Canonical JSON serialization for signing
  const canonical = JSON.stringify(commitPayload, Object.keys(commitPayload).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

// ---------------------------------------------------------------------------
// Core API
// ---------------------------------------------------------------------------

/**
 * Issue a new EP Commit — a signed pre-action authorization token.
 *
 * @param {Object} params
 * @param {string} params.entity_id - The entity being evaluated
 * @param {string} params.action_type - One of the valid action types
 * @param {string} params.decision - allow | review | deny
 * @param {Object} [params.scope] - Contextual scope of the commit
 * @param {number} [params.max_value_usd] - Advisory value cap (does not affect decision logic)
 * @param {number} [params.expiry_minutes] - Minutes until expiry (default: 10)
 * @param {Object} [params.db] - Optional Supabase client override
 * @returns {Promise<Object>} The issued commit record
 */
export async function issueCommit({
  entity_id,
  action_type,
  decision,
  scope = {},
  max_value_usd = null,
  expiry_minutes = DEFAULT_EXPIRY_MINUTES,
  db = null,
}) {
  // Validation
  if (!entity_id || typeof entity_id !== 'string') {
    throw new Error('entity_id is required and must be a non-empty string');
  }

  if (!VALID_ACTION_TYPES.includes(action_type)) {
    throw new Error(
      `Invalid action_type: "${action_type}". Must be one of: ${VALID_ACTION_TYPES.join(', ')}`
    );
  }

  if (!VALID_DECISIONS.includes(decision)) {
    throw new Error(
      `Invalid decision: "${decision}". Must be one of: ${VALID_DECISIONS.join(', ')}`
    );
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiry_minutes * 60 * 1000);

  const commit = {
    commit_id: generateCommitId(),
    version: '1.0',
    decision,
    action_type,
    entity_id,
    scope,
    nonce: generateNonce(),
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    status: 'active',
    max_value_usd,
    signature: null, // placeholder, computed below
  };

  // Sign the commit (signature covers all fields except signature itself)
  const { signature: _, ...payloadToSign } = commit;
  commit.signature = signCommit(payloadToSign);

  // Persist if DB is available
  const client = db || _tryGetClient();
  if (client) {
    await client.from('ep_commits').insert(commit);
  }

  return commit;
}

/**
 * Verify an EP Commit's current validity.
 *
 * Returns { valid: true } for active, non-expired commits.
 * Returns { valid: false, status } for expired, revoked, or unknown commits.
 * Does NOT expose the full commit payload (minimum disclosure).
 *
 * @param {string} commitId
 * @param {Object} [db] - Optional Supabase client override
 * @returns {Promise<Object>}
 */
export async function verifyCommit(commitId, db = null) {
  const client = db || _tryGetClient();
  if (!client) {
    return { valid: false, reason: 'no_storage' };
  }

  const { data, error } = await client
    .from('ep_commits')
    .select('commit_id, status, expires_at, decision')
    .eq('commit_id', commitId)
    .maybeSingle();

  if (error || !data) {
    return { valid: false };
  }

  // Check expiry
  if (new Date(data.expires_at) < new Date()) {
    // Auto-transition to expired if still active
    if (data.status === 'active') {
      await client
        .from('ep_commits')
        .update({ status: 'expired' })
        .eq('commit_id', commitId);
    }
    return { valid: false, status: 'expired' };
  }

  if (data.status !== 'active') {
    return { valid: false, status: data.status };
  }

  return { valid: true };
}

/**
 * Revoke an active EP Commit.
 *
 * @param {string} commitId
 * @param {Object} [db] - Optional Supabase client override
 * @returns {Promise<Object>}
 */
export async function revokeCommit(commitId, db = null) {
  const client = db || _tryGetClient();
  if (!client) {
    throw new Error('Storage client required for revocation');
  }

  const { data, error } = await client
    .from('ep_commits')
    .select('commit_id, status, expires_at')
    .eq('commit_id', commitId)
    .maybeSingle();

  if (error || !data) {
    throw new Error(`Commit not found: ${commitId}`);
  }

  // Check for terminal states
  if (data.status === 'revoked') {
    throw new Error('Commit is already revoked');
  }

  if (TERMINAL_STATES.includes(data.status)) {
    throw new Error(`Cannot revoke commit in terminal state: ${data.status}`);
  }

  // Check if expired (time-based terminal)
  if (new Date(data.expires_at) < new Date()) {
    await client
      .from('ep_commits')
      .update({ status: 'expired' })
      .eq('commit_id', commitId);
    throw new Error('Cannot revoke commit in terminal state: expired');
  }

  await client
    .from('ep_commits')
    .update({ status: 'revoked' })
    .eq('commit_id', commitId);

  return { commit_id: commitId, status: 'revoked' };
}

/**
 * Fulfill an active EP Commit (mark the authorized action as completed).
 *
 * @param {string} commitId
 * @param {Object} [db] - Optional Supabase client override
 * @returns {Promise<Object>}
 */
export async function fulfillCommit(commitId, db = null) {
  const client = db || _tryGetClient();
  if (!client) {
    throw new Error('Storage client required for fulfillment');
  }

  const { data, error } = await client
    .from('ep_commits')
    .select('commit_id, status, expires_at')
    .eq('commit_id', commitId)
    .maybeSingle();

  if (error || !data) {
    throw new Error(`Commit not found: ${commitId}`);
  }

  // Already fulfilled — idempotent
  if (data.status === 'fulfilled') {
    return { commit_id: commitId, status: 'fulfilled' };
  }

  // Cannot transition from other terminal states
  if (TERMINAL_STATES.includes(data.status)) {
    throw new Error(`Cannot fulfill commit in terminal state: ${data.status}`);
  }

  // Check if expired
  if (new Date(data.expires_at) < new Date()) {
    await client
      .from('ep_commits')
      .update({ status: 'expired' })
      .eq('commit_id', commitId);
    throw new Error('Cannot fulfill commit in terminal state: expired');
  }

  await client
    .from('ep_commits')
    .update({ status: 'fulfilled' })
    .eq('commit_id', commitId);

  return { commit_id: commitId, status: 'fulfilled' };
}

/**
 * Bind a receipt ID to a commit, linking the authorization to its outcome.
 *
 * @param {string} commitId
 * @param {string} receiptId
 * @param {Object} [db] - Optional Supabase client override
 * @returns {Promise<Object>}
 */
export async function bindReceiptToCommit(commitId, receiptId, db = null) {
  const client = db || _tryGetClient();
  if (!client) {
    throw new Error('Storage client required for binding');
  }

  const { data, error } = await client
    .from('ep_commits')
    .select('commit_id, status')
    .eq('commit_id', commitId)
    .maybeSingle();

  if (error || !data) {
    throw new Error(`Commit not found: ${commitId}`);
  }

  if (data.status !== 'active' && data.status !== 'fulfilled') {
    throw new Error(`Cannot bind receipt to commit in state: ${data.status}`);
  }

  await client
    .from('ep_commits')
    .update({ receipt_id: receiptId })
    .eq('commit_id', commitId);

  return { commit_id: commitId, receipt_id: receiptId, bound: true };
}

// ---------------------------------------------------------------------------
// Exports for testing
// ---------------------------------------------------------------------------

export const _internals = {
  VALID_DECISIONS,
  VALID_ACTION_TYPES,
  TERMINAL_STATES,
  DEFAULT_EXPIRY_MINUTES,
  generateNonce,
  generateCommitId,
  signCommit,
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _tryGetClient() {
  try {
    return getServiceClient();
  } catch {
    return null;
  }
}
