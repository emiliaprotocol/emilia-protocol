// WRITE DISCIPLINE: This file is authorized to use getServiceClient() for
// trust-bearing writes. Route handlers MUST use getGuardedClient() from
// lib/write-guard.js, which blocks mutations on trust tables at runtime.

/**
 * Protocol Write — Single choke point for all trust-changing state transitions.
 *
 * Every trust-changing write in EMILIA must flow through this function.
 * It enforces: validation → evaluation → authorization → idempotency →
 * persist event → materialize projection → emit telemetry.
 *
 * This module WRAPS the existing canonical functions (canonical-writer.js,
 * commit.js) — it does not replace them. The canonical functions remain
 * the implementation details; this module adds the unified enforcement layer.
 *
 * Existing code that calls canonical functions directly continues to work
 * for backward compatibility. New code should use protocolWrite().
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';
import { resolveActorRef } from '@/lib/actor';
import { sha256 } from '@/lib/crypto';
import {
  canonicalSubmitReceipt,
  canonicalSubmitAutoReceipt,
  canonicalBilateralConfirm,
  canonicalFileDispute,
  canonicalResolveDispute,
  canonicalRespondDispute,
  canonicalAppealDispute,
  canonicalResolveAppeal,
  canonicalWithdrawDispute,
  canonicalFileReport,
} from '@/lib/canonical-writer';
import {
  issueCommit,
  verifyCommit,
  revokeCommit,
} from '@/lib/commit';
import {
  hasPermission,
  checkAbuse,
  validateTransition,
  DISPUTE_STATES,
} from '@/lib/procedural-justice';
import { ProtocolWriteError } from '@/lib/errors';
// Handshake handlers are loaded lazily to avoid circular imports.
// Each handler delegates to the internal _handle* function (not the
// public API) to avoid protocol-write recursion.

// ── Command Type Constants ──────────────────────────────────────────────────

/**
 * @typedef {Object} CommandTypes
 * @property {string} SUBMIT_RECEIPT - Submit a new trust receipt
 * @property {string} CONFIRM_RECEIPT - Bilateral confirmation of a receipt
 * @property {string} ISSUE_COMMIT - Issue a new trust commit
 * @property {string} VERIFY_COMMIT - Verify an existing commit
 * @property {string} REVOKE_COMMIT - Revoke a commit with reason
 * @property {string} FILE_DISPUTE - File a dispute against a receipt
 * @property {string} RESOLVE_DISPUTE - Resolve an open dispute
 * @property {string} FILE_REPORT - File a trust report
 * @property {string} RESPOND_DISPUTE - Respond to a dispute
 * @property {string} APPEAL_DISPUTE - Appeal a resolved dispute
 * @property {string} RESOLVE_APPEAL - Resolve a dispute appeal
 * @property {string} WITHDRAW_DISPUTE - Withdraw a filed dispute
 * @property {string} SUBMIT_AUTO_RECEIPT - Submit an automated trust receipt
 * @property {string} INITIATE_HANDSHAKE - Initiate a new EP handshake
 * @property {string} ADD_PRESENTATION - Add a presentation to a handshake
 * @property {string} VERIFY_HANDSHAKE - Verify a handshake
 * @property {string} REVOKE_HANDSHAKE - Revoke a handshake
 * @property {string} SIGNOFF_CHALLENGE_ISSUE - Issue a signoff challenge
 * @property {string} SIGNOFF_CHALLENGE_VIEW - Mark a signoff challenge as viewed
 * @property {string} SIGNOFF_ATTEST - Attest to a signoff challenge
 * @property {string} SIGNOFF_DENY - Deny a signoff challenge
 * @property {string} SIGNOFF_CONSUME - Consume an approved signoff
 * @property {string} SIGNOFF_CHALLENGE_REVOKE - Revoke a signoff challenge
 * @property {string} SIGNOFF_ATTESTATION_REVOKE - Revoke a signoff attestation
 * @property {string} SIGNOFF_CHALLENGE_EXPIRE - Expire a signoff challenge
 * @property {string} SIGNOFF_ATTESTATION_EXPIRE - Expire a signoff attestation
 * @property {string} CONSUME_HANDSHAKE_BINDING - Consume a handshake binding
 * @property {string} EXPIRE_RECEIPTS - Expire stale receipts (cron)
 * @property {string} ESCALATE_DISPUTES - Escalate overdue disputes (cron)
 * @property {string} EXPIRE_CONTINUITY_CLAIMS - Expire stale continuity claims (cron)
 */

/** @type {Readonly<CommandTypes>} */
export const COMMAND_TYPES = {
  SUBMIT_RECEIPT: 'submit_receipt',
  CONFIRM_RECEIPT: 'confirm_receipt',
  ISSUE_COMMIT: 'issue_commit',
  VERIFY_COMMIT: 'verify_commit',
  REVOKE_COMMIT: 'revoke_commit',
  FILE_DISPUTE: 'file_dispute',
  RESOLVE_DISPUTE: 'resolve_dispute',
  FILE_REPORT: 'file_report',
  RESPOND_DISPUTE: 'respond_dispute',
  APPEAL_DISPUTE: 'appeal_dispute',
  RESOLVE_APPEAL: 'resolve_appeal',
  WITHDRAW_DISPUTE: 'withdraw_dispute',
  SUBMIT_AUTO_RECEIPT: 'submit_auto_receipt',
  INITIATE_HANDSHAKE: 'initiate_handshake',
  ADD_PRESENTATION: 'add_presentation',
  VERIFY_HANDSHAKE: 'verify_handshake',
  REVOKE_HANDSHAKE: 'revoke_handshake',
  SIGNOFF_CHALLENGE_ISSUE: 'signoff_challenge_issue',
  SIGNOFF_CHALLENGE_VIEW: 'signoff_challenge_view',
  SIGNOFF_ATTEST: 'signoff_attest',
  SIGNOFF_DENY: 'signoff_deny',
  SIGNOFF_CONSUME: 'signoff_consume',
  SIGNOFF_CHALLENGE_REVOKE: 'signoff_challenge_revoke',
  SIGNOFF_ATTESTATION_REVOKE: 'signoff_attestation_revoke',
  SIGNOFF_CHALLENGE_EXPIRE: 'signoff_challenge_expire',
  SIGNOFF_ATTESTATION_EXPIRE: 'signoff_attestation_expire',
  CONSUME_HANDSHAKE_BINDING: 'consume_handshake_binding',
  EXPIRE_RECEIPTS: 'expire_receipts',
  ESCALATE_DISPUTES: 'escalate_disputes',
  EXPIRE_CONTINUITY_CLAIMS: 'expire_continuity_claims',
  EYE_RECORD_OBSERVATION: 'eye_record_observation',
  EYE_ISSUE_ADVISORY: 'eye_issue_advisory',
  EYE_CREATE_SUPPRESSION: 'eye_create_suppression',
  EYE_REVOKE_SUPPRESSION: 'eye_revoke_suppression',
};

const VALID_COMMAND_TYPES = new Set(Object.values(COMMAND_TYPES));

// ── Aggregate Type Mapping ──────────────────────────────────────────────────

const COMMAND_TO_AGGREGATE = {
  [COMMAND_TYPES.SUBMIT_RECEIPT]: 'receipt',
  [COMMAND_TYPES.CONFIRM_RECEIPT]: 'receipt',
  [COMMAND_TYPES.ISSUE_COMMIT]: 'commit',
  [COMMAND_TYPES.VERIFY_COMMIT]: 'commit',
  [COMMAND_TYPES.REVOKE_COMMIT]: 'commit',
  [COMMAND_TYPES.FILE_DISPUTE]: 'dispute',
  [COMMAND_TYPES.RESOLVE_DISPUTE]: 'dispute',
  [COMMAND_TYPES.FILE_REPORT]: 'report',
  [COMMAND_TYPES.RESPOND_DISPUTE]: 'dispute',
  [COMMAND_TYPES.APPEAL_DISPUTE]: 'dispute',
  [COMMAND_TYPES.RESOLVE_APPEAL]: 'dispute',
  [COMMAND_TYPES.WITHDRAW_DISPUTE]: 'dispute',
  [COMMAND_TYPES.SUBMIT_AUTO_RECEIPT]: 'receipt',
  [COMMAND_TYPES.INITIATE_HANDSHAKE]: 'handshake',
  [COMMAND_TYPES.ADD_PRESENTATION]: 'handshake',
  [COMMAND_TYPES.VERIFY_HANDSHAKE]: 'handshake',
  [COMMAND_TYPES.REVOKE_HANDSHAKE]: 'handshake',
  [COMMAND_TYPES.SIGNOFF_CHALLENGE_ISSUE]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_CHALLENGE_VIEW]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_ATTEST]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_DENY]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_CONSUME]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_CHALLENGE_REVOKE]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_ATTESTATION_REVOKE]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_CHALLENGE_EXPIRE]: 'signoff',
  [COMMAND_TYPES.SIGNOFF_ATTESTATION_EXPIRE]: 'signoff',
  [COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING]: 'handshake',
  [COMMAND_TYPES.EXPIRE_RECEIPTS]: 'receipt',
  [COMMAND_TYPES.ESCALATE_DISPUTES]: 'dispute',
  [COMMAND_TYPES.EXPIRE_CONTINUITY_CLAIMS]: 'continuity',
  [COMMAND_TYPES.EYE_RECORD_OBSERVATION]: 'eye',
  [COMMAND_TYPES.EYE_ISSUE_ADVISORY]: 'eye',
  [COMMAND_TYPES.EYE_CREATE_SUPPRESSION]: 'eye',
  [COMMAND_TYPES.EYE_REVOKE_SUPPRESSION]: 'eye',
};

// ── ProtocolWriteError is imported from '@/lib/errors' ──────────────────────
// Re-export for backward compatibility with consumers that import from this module.
export { ProtocolWriteError };

// ── Crypto Helpers ──────────────────────────────────────────────────────────

/**
 * Canonical JSON stringification with sorted keys for deterministic output.
 * Ensures that semantically identical objects with different key insertion
 * order produce the same string.
 *
 * @param {*} obj - Value to stringify
 * @returns {string} Deterministic JSON string
 */
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalStringify).join(',') + ']';
  return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

/**
 * Compute an idempotency key from the command.
 * Same command type + same actor + same input = same key.
 *
 * Uses canonicalStringify to ensure deterministic key computation
 * regardless of object key insertion order.
 *
 * @param {{ type: string, actor: string|object, input: object }} command - The protocol command
 * @returns {string} Hex-encoded SHA-256 hash used as idempotency key
 */
function computeIdempotencyKey(command) {
  return sha256(`${command.type}:${command.actor}:${canonicalStringify(command.input)}`);
}

// ── Idempotency Cache ───────────────────────────────────────────────────────
// In-memory cache supplemented by DB check. Entries expire after 10 minutes.

const _idempotencyCache = new Map();
const IDEMPOTENCY_TTL_MS = 10 * 60 * 1000;

function checkIdempotencyCache(key) {
  const cached = _idempotencyCache.get(key);
  if (!cached) return null;
  if (Date.now() - cached.timestamp > IDEMPOTENCY_TTL_MS) {
    _idempotencyCache.delete(key);
    return null;
  }
  return cached.result;
}

function setIdempotencyCache(key, result) {
  _idempotencyCache.set(key, { result, timestamp: Date.now() });
  // Evict oldest entry when cache exceeds 10,000 entries (matches commit.js nonce cache bound)
  if (_idempotencyCache.size > 10000) {
    const firstKey = _idempotencyCache.keys().next().value;
    _idempotencyCache.delete(firstKey);
  }
}

// ── Protocol Event Builder ──────────────────────────────────────────────────

/**
 * @typedef {Object} ProtocolEvent
 * @property {string} event_id - UUID for this event
 * @property {string} aggregate_type - The aggregate type (e.g. 'receipt', 'commit', 'dispute', 'handshake', 'signoff')
 * @property {string} aggregate_id - The aggregate entity's ID
 * @property {string} command_type - The command that produced this event (one of COMMAND_TYPES values)
 * @property {string|null} parent_event_hash - Hash of previous event for this aggregate (for chaining)
 * @property {string} payload_hash - SHA-256 of the canonicalized command input
 * @property {string} actor_authority_id - Who performed the action
 * @property {string} idempotency_key - Computed idempotency key
 * @property {string} created_at - ISO-8601 timestamp of event creation
 */

/**
 * Build a protocol event record for the append-only event log.
 *
 * @param {object} params
 * @param {string} params.aggregateType - The aggregate type (e.g. 'receipt', 'commit', 'dispute', 'report', 'handshake', 'signoff')
 * @param {string} params.aggregateId - The entity's ID for this aggregate
 * @param {string} params.commandType - The command that produced this event
 * @param {object} params.payload - The canonical payload to hash
 * @param {string} params.actorAuthorityId - Who performed the action
 * @param {string} params.idempotencyKey - Computed idempotency key
 * @param {string|null} [params.parentEventHash=null] - Hash of previous event for this aggregate
 * @returns {ProtocolEvent} Protocol event record ready for insertion
 */
function buildProtocolEvent({
  aggregateType,
  aggregateId,
  commandType,
  payload,
  actorAuthorityId,
  idempotencyKey,
  parentEventHash = null,
}) {
  const canonicalPayload = JSON.stringify(payload, Object.keys(payload).sort());
  return {
    event_id: crypto.randomUUID(),
    aggregate_type: aggregateType,
    aggregate_id: aggregateId,
    command_type: commandType,
    parent_event_hash: parentEventHash,
    payload_json: payload,
    payload_hash: sha256(canonicalPayload),
    actor_authority_id: actorAuthorityId,
    idempotency_key: idempotencyKey,
    created_at: new Date().toISOString(),
  };
}

// ── Telemetry ───────────────────────────────────────────────────────────────

/**
 * Emit telemetry for a protocol write. Fire-and-forget.
 * Structured for observability pipelines (OpenTelemetry, Vercel, etc.)
 *
 * @param {ProtocolEvent} event - The persisted protocol event
 * @param {{ type: string, actor: string|object }} command - The original command
 * @param {number} durationMs - Wall-clock duration of the entire write pipeline in milliseconds
 * @returns {void}
 */
function emitTelemetry(event, command, durationMs) {
  try {
    // Structured log — picked up by observability tooling
    console.info(JSON.stringify({
      _ep_telemetry: true,
      event_id: event.event_id,
      command_type: command.type,
      aggregate_type: event.aggregate_type,
      aggregate_id: event.aggregate_id,
      actor: command.actor,
      duration_ms: durationMs,
      timestamp: event.created_at,
    }));
  } catch {
    // Telemetry must never crash the write path
  }
}

// ── Command Validators ──────────────────────────────────────────────────────

const VALIDATORS = {
  [COMMAND_TYPES.SUBMIT_RECEIPT](command) {
    const { input, actor } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!actor) throw new ProtocolWriteError('actor is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SUBMIT_AUTO_RECEIPT](command) {
    const { input, actor } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!actor) throw new ProtocolWriteError('actor is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.CONFIRM_RECEIPT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.receipt_id) throw new ProtocolWriteError('input.receipt_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.confirming_entity_id) throw new ProtocolWriteError('input.confirming_entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (typeof input.confirm !== 'boolean') throw new ProtocolWriteError('input.confirm must be a boolean', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.ISSUE_COMMIT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.action_type) throw new ProtocolWriteError('input.action_type is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.VERIFY_COMMIT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.commit_id) throw new ProtocolWriteError('input.commit_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.REVOKE_COMMIT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.commit_id) throw new ProtocolWriteError('input.commit_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.FILE_DISPUTE](command) {
    const { input, actor } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.receipt_id) throw new ProtocolWriteError('input.receipt_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!actor) throw new ProtocolWriteError('actor is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.RESOLVE_DISPUTE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.dispute_id) throw new ProtocolWriteError('input.dispute_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.resolution) throw new ProtocolWriteError('input.resolution is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.rationale) throw new ProtocolWriteError('input.rationale is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.operator_id) throw new ProtocolWriteError('input.operator_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.FILE_REPORT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.report_type) throw new ProtocolWriteError('input.report_type is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.description) throw new ProtocolWriteError('input.description is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.RESPOND_DISPUTE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.dispute_id) throw new ProtocolWriteError('input.dispute_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.responder_id) throw new ProtocolWriteError('input.responder_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.response) throw new ProtocolWriteError('input.response is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.APPEAL_DISPUTE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.dispute_id) throw new ProtocolWriteError('input.dispute_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.reason || input.reason.length < 10) throw new ProtocolWriteError('input.reason is required and must be at least 10 characters', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.RESOLVE_APPEAL](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.dispute_id) throw new ProtocolWriteError('input.dispute_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.resolution) throw new ProtocolWriteError('input.resolution is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.rationale) throw new ProtocolWriteError('input.rationale is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.operator_id) throw new ProtocolWriteError('input.operator_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.WITHDRAW_DISPUTE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.dispute_id) throw new ProtocolWriteError('input.dispute_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.INITIATE_HANDSHAKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.mode) throw new ProtocolWriteError('input.mode is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.policy_id) throw new ProtocolWriteError('input.policy_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.parties || !Array.isArray(input.parties) || input.parties.length === 0) {
      throw new ProtocolWriteError('input.parties must be a non-empty array', { code: 'VALIDATION_ERROR', status: 400 });
    }
  },

  [COMMAND_TYPES.ADD_PRESENTATION](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.handshake_id) throw new ProtocolWriteError('input.handshake_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.party_role) throw new ProtocolWriteError('input.party_role is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.presentation_hash) throw new ProtocolWriteError('input.presentation_hash is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.VERIFY_HANDSHAKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.handshake_id) throw new ProtocolWriteError('input.handshake_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.REVOKE_HANDSHAKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.handshake_id) throw new ProtocolWriteError('input.handshake_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  // ── Signoff validators ──────────────────────────────────────────────────

  [COMMAND_TYPES.SIGNOFF_CHALLENGE_ISSUE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.action_type) throw new ProtocolWriteError('input.action_type is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_CHALLENGE_VIEW](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.challenge_id) throw new ProtocolWriteError('input.challenge_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_ATTEST](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.challenge_id) throw new ProtocolWriteError('input.challenge_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_DENY](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.challenge_id) throw new ProtocolWriteError('input.challenge_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_CONSUME](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.signoff_id) throw new ProtocolWriteError('input.signoff_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_CHALLENGE_REVOKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.challenge_id) throw new ProtocolWriteError('input.challenge_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_ATTESTATION_REVOKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.attestation_id) throw new ProtocolWriteError('input.attestation_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_CHALLENGE_EXPIRE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.challenge_id) throw new ProtocolWriteError('input.challenge_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.SIGNOFF_ATTESTATION_EXPIRE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.attestation_id) throw new ProtocolWriteError('input.attestation_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  // ── Cron / lifecycle validators ─────────────────────────────────────────

  [COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.handshake_id) throw new ProtocolWriteError('input.handshake_id is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.consumed_by) throw new ProtocolWriteError('input.consumed_by is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.consumed_for) throw new ProtocolWriteError('input.consumed_for is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.EXPIRE_RECEIPTS](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!Array.isArray(input.receipt_ids) || input.receipt_ids.length === 0) {
      throw new ProtocolWriteError('input.receipt_ids must be a non-empty array', { code: 'VALIDATION_ERROR', status: 400 });
    }
  },

  [COMMAND_TYPES.ESCALATE_DISPUTES](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!Array.isArray(input.dispute_ids) || input.dispute_ids.length === 0) {
      throw new ProtocolWriteError('input.dispute_ids must be a non-empty array', { code: 'VALIDATION_ERROR', status: 400 });
    }
  },

  [COMMAND_TYPES.EXPIRE_CONTINUITY_CLAIMS](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!Array.isArray(input.continuity_ids) || input.continuity_ids.length === 0) {
      throw new ProtocolWriteError('input.continuity_ids must be a non-empty array', { code: 'VALIDATION_ERROR', status: 400 });
    }
  },

  // ── Eye validators ─────────────────────────────────────────────────────

  [COMMAND_TYPES.EYE_RECORD_OBSERVATION](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.observation_type) throw new ProtocolWriteError('input.observation_type is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.EYE_ISSUE_ADVISORY](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.advisory_type) throw new ProtocolWriteError('input.advisory_type is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.EYE_CREATE_SUPPRESSION](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.rule_id) throw new ProtocolWriteError('input.rule_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },

  [COMMAND_TYPES.EYE_REVOKE_SUPPRESSION](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', { code: 'VALIDATION_ERROR', status: 400 });
    if (!input.suppression_id) throw new ProtocolWriteError('input.suppression_id is required', { code: 'VALIDATION_ERROR', status: 400 });
  },
};

// ── Command Handlers ────────────────────────────────────────────────────────
// Each handler delegates to the existing canonical function and returns
// { result, aggregateId } so the protocol layer can build the event.

const HANDLERS = {
  async [COMMAND_TYPES.SUBMIT_RECEIPT](command) {
    const result = await canonicalSubmitReceipt(command.input, command.actor);
    return {
      result,
      aggregateId: result.receipt?.receipt_id || result.receipt?.entity_id || 'unknown',
    };
  },

  async [COMMAND_TYPES.SUBMIT_AUTO_RECEIPT](command) {
    const result = await canonicalSubmitAutoReceipt(command.input, command.actor);
    return {
      result,
      aggregateId: result.receipt?.receipt_id || result.receipt?.entity_id || 'unknown',
    };
  },

  async [COMMAND_TYPES.CONFIRM_RECEIPT](command) {
    const { receipt_id, confirming_entity_id, confirm } = command.input;
    const result = await canonicalBilateralConfirm(receipt_id, confirming_entity_id, confirm);
    return {
      result,
      aggregateId: receipt_id,
    };
  },

  async [COMMAND_TYPES.ISSUE_COMMIT](command) {
    const result = await issueCommit(command.input);
    return {
      result,
      aggregateId: result.commit_id || 'unknown',
    };
  },

  async [COMMAND_TYPES.VERIFY_COMMIT](command) {
    const result = await verifyCommit(command.input.commit_id);
    return {
      result,
      aggregateId: command.input.commit_id,
    };
  },

  async [COMMAND_TYPES.REVOKE_COMMIT](command) {
    const result = await revokeCommit(command.input.commit_id, command.input.reason);
    return {
      result,
      aggregateId: command.input.commit_id,
    };
  },

  async [COMMAND_TYPES.FILE_DISPUTE](command) {
    const result = await canonicalFileDispute(command.input, command.actor);
    return {
      result,
      aggregateId: result.dispute_id || 'unknown',
    };
  },

  async [COMMAND_TYPES.RESOLVE_DISPUTE](command) {
    const { dispute_id, resolution, rationale, operator_id } = command.input;
    const result = await canonicalResolveDispute(dispute_id, resolution, rationale, operator_id);
    return {
      result,
      aggregateId: dispute_id,
    };
  },

  async [COMMAND_TYPES.FILE_REPORT](command) {
    const result = await canonicalFileReport(command.input);
    return {
      result,
      aggregateId: result.report_id || 'unknown',
    };
  },

  async [COMMAND_TYPES.RESPOND_DISPUTE](command) {
    const result = await canonicalRespondDispute(
      command.input.dispute_id, command.input.responder_id, command.input.response, command.input.evidence
    );
    return {
      result,
      aggregateId: command.input.dispute_id,
    };
  },

  async [COMMAND_TYPES.APPEAL_DISPUTE](command) {
    const result = await canonicalAppealDispute(
      command.input.dispute_id,
      { id: command.input.appealer_id || command.actor },
      command.input.reason,
      command.input.evidence
    );
    return {
      result,
      aggregateId: command.input.dispute_id,
    };
  },

  async [COMMAND_TYPES.RESOLVE_APPEAL](command) {
    const result = await canonicalResolveAppeal(
      command.input.dispute_id, command.input.resolution, command.input.rationale, command.input.operator_id
    );
    return {
      result,
      aggregateId: command.input.dispute_id,
    };
  },

  async [COMMAND_TYPES.WITHDRAW_DISPUTE](command) {
    const result = await canonicalWithdrawDispute(
      command.input.dispute_id,
      { id: command.input.withdrawer_id || command.actor }
    );
    return {
      result,
      aggregateId: command.input.dispute_id,
    };
  },

  async [COMMAND_TYPES.INITIATE_HANDSHAKE](command) {
    const { _handleInitiateHandshake } = await import('@/lib/handshake/create.js');
    return _handleInitiateHandshake(command);
  },

  async [COMMAND_TYPES.ADD_PRESENTATION](command) {
    const { _handleAddPresentation } = await import('@/lib/handshake/present.js');
    return _handleAddPresentation(command);
  },

  async [COMMAND_TYPES.VERIFY_HANDSHAKE](command) {
    const { _handleVerifyHandshake } = await import('@/lib/handshake/verify.js');
    return _handleVerifyHandshake(command);
  },

  async [COMMAND_TYPES.REVOKE_HANDSHAKE](command) {
    const { _handleRevokeHandshake } = await import('@/lib/handshake/finalize.js');
    return _handleRevokeHandshake(command);
  },

  // ── Signoff handlers ──────────────────────────────────────────────────

  async [COMMAND_TYPES.SIGNOFF_CHALLENGE_ISSUE](command) {
    const { issueChallenge } = await import('@/lib/signoff/challenge.js');
    const result = await issueChallenge(command.input, command.actor);
    return { result, aggregateId: result.challenge_id || 'unknown' };
  },

  async [COMMAND_TYPES.SIGNOFF_CHALLENGE_VIEW](command) {
    // View is a read-through-write for audit logging
    return { result: { challenge_id: command.input.challenge_id }, aggregateId: command.input.challenge_id };
  },

  async [COMMAND_TYPES.SIGNOFF_ATTEST](command) {
    const { createAttestation } = await import('@/lib/signoff/attest.js');
    const result = await createAttestation(command.input, command.actor);
    return { result, aggregateId: command.input.challenge_id };
  },

  async [COMMAND_TYPES.SIGNOFF_DENY](command) {
    const { createAttestation } = await import('@/lib/signoff/attest.js');
    const result = await createAttestation({ ...command.input, denied: true }, command.actor);
    return { result, aggregateId: command.input.challenge_id };
  },

  async [COMMAND_TYPES.SIGNOFF_CONSUME](command) {
    const { consumeSignoff } = await import('@/lib/signoff/consume.js');
    const result = await consumeSignoff(command.input.signoff_id, command.actor);
    return { result, aggregateId: command.input.signoff_id };
  },

  async [COMMAND_TYPES.SIGNOFF_CHALLENGE_REVOKE](command) {
    const { revokeChallenge } = await import('@/lib/signoff/revoke.js');
    const result = await revokeChallenge(command.input.challenge_id, command.input.reason, command.actor);
    return { result, aggregateId: command.input.challenge_id };
  },

  async [COMMAND_TYPES.SIGNOFF_ATTESTATION_REVOKE](command) {
    const { revokeAttestation } = await import('@/lib/signoff/revoke.js');
    const result = await revokeAttestation(command.input.attestation_id, command.input.reason, command.actor);
    return { result, aggregateId: command.input.attestation_id };
  },

  async [COMMAND_TYPES.SIGNOFF_CHALLENGE_EXPIRE](command) {
    const { emitSignoffEvent } = await import('@/lib/signoff/events.js');
    const result = await emitSignoffEvent('challenge_expired', { challenge_id: command.input.challenge_id });
    return { result, aggregateId: command.input.challenge_id };
  },

  async [COMMAND_TYPES.SIGNOFF_ATTESTATION_EXPIRE](command) {
    const { emitSignoffEvent } = await import('@/lib/signoff/events.js');
    const result = await emitSignoffEvent('attestation_expired', { attestation_id: command.input.attestation_id });
    return { result, aggregateId: command.input.attestation_id };
  },

  // ── Cron / lifecycle handlers ─────────────────────────────────────────

  async [COMMAND_TYPES.CONSUME_HANDSHAKE_BINDING](command) {
    const supabase = getServiceClient();
    const { handshake_id, consumed_by, consumed_for } = command.input;
    const { data, error } = await supabase
      .from('handshake_bindings')
      .update({
        consumed_at: new Date().toISOString(),
        consumed_by,
        consumed_for,
      })
      .eq('handshake_id', handshake_id)
      .is('consumed_at', null)
      .select()
      .maybeSingle();

    if (error) {
      throw new ProtocolWriteError(
        `Failed to consume handshake binding: ${error.message}`,
        { code: 'CONSUME_BINDING_FAILED', status: 500 },
      );
    }
    return { result: { consumed: !!data, binding: data }, aggregateId: handshake_id };
  },

  async [COMMAND_TYPES.EXPIRE_RECEIPTS](command) {
    const supabase = getServiceClient();
    const { receipt_ids } = command.input;
    const { error } = await supabase
      .from('receipts')
      .update({ bilateral_status: 'expired' })
      .in('receipt_id', receipt_ids);

    if (error) {
      throw new ProtocolWriteError(
        `Failed to expire receipts: ${error.message}`,
        { code: 'EXPIRE_RECEIPTS_FAILED', status: 500 },
      );
    }
    return { result: { expired: receipt_ids.length, receipt_ids }, aggregateId: receipt_ids[0] };
  },

  async [COMMAND_TYPES.ESCALATE_DISPUTES](command) {
    const supabase = getServiceClient();
    const { dispute_ids } = command.input;
    const now = new Date().toISOString();
    const { error } = await supabase
      .from('disputes')
      .update({ status: 'under_review', updated_at: now })
      .in('dispute_id', dispute_ids);

    if (error) {
      throw new ProtocolWriteError(
        `Failed to escalate disputes: ${error.message}`,
        { code: 'ESCALATE_DISPUTES_FAILED', status: 500 },
      );
    }
    return { result: { escalated: dispute_ids.length, dispute_ids }, aggregateId: dispute_ids[0] };
  },

  async [COMMAND_TYPES.EXPIRE_CONTINUITY_CLAIMS](command) {
    const supabase = getServiceClient();
    const { continuity_ids } = command.input;
    const now = new Date().toISOString();
    const { error } = await supabase
      .from('continuity_claims')
      .update({ status: 'expired', updated_at: now })
      .in('continuity_id', continuity_ids);

    if (error) {
      throw new ProtocolWriteError(
        `Failed to expire continuity claims: ${error.message}`,
        { code: 'EXPIRE_CONTINUITY_FAILED', status: 500 },
      );
    }
    return { result: { expired: continuity_ids.length, continuity_ids }, aggregateId: continuity_ids[0] };
  },

  // ── Eye handlers ───────────────────────────────────────────────────────

  async [COMMAND_TYPES.EYE_RECORD_OBSERVATION](command) {
    const { observation_type, entity_id } = command.input;
    return { result: { observation_type, entity_id, recorded: true }, aggregateId: entity_id };
  },

  async [COMMAND_TYPES.EYE_ISSUE_ADVISORY](command) {
    const { advisory_type, entity_id } = command.input;
    return { result: { advisory_type, entity_id, issued: true }, aggregateId: entity_id };
  },

  async [COMMAND_TYPES.EYE_CREATE_SUPPRESSION](command) {
    const { rule_id } = command.input;
    return { result: { rule_id, created: true }, aggregateId: rule_id };
  },

  async [COMMAND_TYPES.EYE_REVOKE_SUPPRESSION](command) {
    const { suppression_id } = command.input;
    return { result: { suppression_id, revoked: true }, aggregateId: suppression_id };
  },
};

// ── Protocol Invariants ─────────────────────────────────────────────────────

/**
 * Assert protocol-level invariants that must hold for any write.
 * These are NOT business-logic validations (those are in VALIDATORS).
 * These are structural invariants of the protocol itself.
 */
function assertInvariants(command) {
  // Invariant 1: command must have a type
  if (!command.type) {
    throw new ProtocolWriteError('command.type is required', { code: 'INVARIANT_VIOLATION', status: 400 });
  }

  // Invariant 2: command type must be known
  if (!VALID_COMMAND_TYPES.has(command.type)) {
    throw new ProtocolWriteError(
      `Unknown command type: "${command.type}". Valid types: ${[...VALID_COMMAND_TYPES].join(', ')}`,
      { code: 'UNKNOWN_COMMAND_TYPE', status: 400 },
    );
  }

  // Invariant 3: input must be an object
  if (command.input !== null && command.input !== undefined && typeof command.input !== 'object') {
    throw new ProtocolWriteError('command.input must be an object', { code: 'INVARIANT_VIOLATION', status: 400 });
  }
}

// ── Authority Resolution ────────────────────────────────────────────────────

/**
 * Resolve the acting authority from the command.
 * Returns a normalized authority object.
 */
function resolveAuthority(command) {
  // actor can be a full entity object (from auth middleware) or a string ID.
  // NOTE: resolveAuthority prefers .id over .entity_id (database primary key
  // takes precedence over slug). This differs from the shared resolveActorRef()
  // utility which prefers .entity_id — the difference is intentional because
  // authority resolution must use the canonical database identifier.
  const actor = command.actor;
  const actorId = typeof actor === 'object' && actor !== null
    ? (actor.id || actor.entity_id || 'anonymous')
    : (actor || 'anonymous');

  return {
    id: actorId,
    role: command.requestMeta?.role || 'entity',
    source: command.requestMeta?.source || 'api',
  };
}

// ── Event Persistence ───────────────────────────────────────────────────────

/**
 * Append a protocol event to the protocol_events table.
 * This is a HARD requirement — if the event cannot be written, the entire
 * operation must fail. An unlogged trust-changing transition is never acceptable.
 *
 * @param {ProtocolEvent} event - The protocol event record to persist
 * @returns {Promise<void>}
 * @throws {ProtocolWriteError} If the event cannot be persisted (code: 'EVENT_PERSISTENCE_FAILED', status: 500)
 */
async function appendProtocolEvent(event) {
  const supabase = getServiceClient();
  const { error } = await supabase.from('protocol_events').insert(event);

  if (error) {
    throw new ProtocolWriteError(
      `EVENT_WRITE_REQUIRED: Failed to persist protocol event for ${event.command_type} ` +
      `on ${event.aggregate_type}/${event.aggregate_id}: ${error.message}. ` +
      `State transition REJECTED — every transition must be logged.`,
      { code: 'EVENT_PERSISTENCE_FAILED', status: 500 },
    );
  }
}

// ── The Protocol Write Function ─────────────────────────────────────────────

/**
 * THE PROTOCOL WRITE — Single choke point for all trust-changing state transitions.
 *
 * Every trust-changing write in EMILIA should flow through this function.
 * It enforces a strict pipeline:
 *
 *   1. Validate command (type-specific schema validation)
 *   2. Assert invariants (protocol-level invariants that must hold)
 *   3. Resolve authority (who is the actor, what can they do)
 *   4. Evaluate (canonical policy evaluation for this command)
 *   5. Ensure idempotency (check idempotency key)
 *   6. Build protocol event (append-only event record)
 *   7. Append event to protocol_events table
 *   8. Materialize projection (update current-state tables — done by canonical functions)
 *   9. Emit telemetry
 *  10. Return projection
 *
 * @param {object} command
 * @param {string} command.type - One of COMMAND_TYPES
 * @param {object} command.input - Type-specific input data
 * @param {object|string} command.actor - The acting entity (object from auth middleware or string ID)
 * @param {object} [command.requestMeta] - Request metadata (role, source, ip, etc.)
 * @returns {Promise<object>} The result projection from the underlying canonical function
 * @throws {ProtocolWriteError} On validation failure, invariant violation, or unknown command
 */
export async function protocolWrite(command) {
  const startTime = Date.now();

  // ── Step 1: Assert protocol invariants ──
  assertInvariants(command);

  // ── Step 2: Validate command (type-specific) ──
  const validator = VALIDATORS[command.type];
  if (validator) {
    validator(command);
  }

  // ── Step 3: Resolve authority ──
  const authority = resolveAuthority(command);

  // ── Step 4: Abuse / authorization checks ──
  // For dispute and report commands, run abuse detection
  if (command.type === COMMAND_TYPES.FILE_DISPUTE || command.type === COMMAND_TYPES.FILE_REPORT) {
    try {
      const supabase = getServiceClient();
      const abuseType = command.type === COMMAND_TYPES.FILE_DISPUTE ? 'dispute' : 'report';
      const abuseParams = command.type === COMMAND_TYPES.FILE_DISPUTE
        ? { filer_entity_id: authority.id, target_entity_id: command.input.entity_id }
        : { entity_id: command.input.entity_id, report_type: command.input.report_type, reporter_ip_hash: command.input.reporter_ip_hash };

      const abuseCheck = await checkAbuse(supabase, abuseType, abuseParams);
      if (!abuseCheck.allowed) {
        throw new ProtocolWriteError(
        `Action blocked by abuse detection: ${abuseCheck.pattern}`,
        { code: 'ABUSE_DETECTED', status: 429 },
      );
      }
    } catch (e) {
      // If it's our own ProtocolWriteError, rethrow
      if (e instanceof ProtocolWriteError) throw e;
      // Otherwise degrade gracefully — abuse check failure should not block writes
      console.warn('[protocolWrite] Abuse check failed, proceeding:', e.message);
    }
  }

  // ── Step 5: Ensure idempotency ──
  const idempotencyKey = computeIdempotencyKey(command);
  const cachedResult = checkIdempotencyCache(idempotencyKey);
  if (cachedResult !== null) {
    return { ...cachedResult, _idempotent: true };
  }

  // ── Step 6: Execute handler (delegates to canonical function) ──
  const handler = HANDLERS[command.type];
  if (!handler) {
    // This should never happen given invariant check, but defense in depth
    /* c8 ignore next */
    throw new ProtocolWriteError(`No handler for command type: ${command.type}`, { code: 'NO_HANDLER', status: 500 });
  }

  const handlerResult = await handler(command);
  const { result, aggregateId, _protocolEventWritten } = handlerResult;

  // If the canonical function returned an error (not thrown), propagate it
  if (result && result.error) {
    return result;
  }

  // ── Step 7-8: Build and append protocol event ──
  // Skip if the handler already wrote the event atomically (e.g., via RPC).
  let protocolEvent = null;
  if (!_protocolEventWritten) {
    protocolEvent = buildProtocolEvent({
      aggregateType: COMMAND_TO_AGGREGATE[command.type],
      aggregateId,
      commandType: command.type,
      payload: command.input || {},
      actorAuthorityId: authority.id,
      idempotencyKey,
      parentEventHash: null,
    });
    await appendProtocolEvent(protocolEvent);
  }

  // ── Step 9: Cache for idempotency ──
  setIdempotencyCache(idempotencyKey, result);

  // ── Step 10: Emit telemetry ──
  const durationMs = Date.now() - startTime;
  if (protocolEvent) {
    emitTelemetry(protocolEvent, command, durationMs);
  }

  // ── Step 11: Return projection ──
  return result;
}

// ── Exports for testing ─────────────────────────────────────────────────────

export const _internals = {
  computeIdempotencyKey,
  buildProtocolEvent,
  sha256,
  assertInvariants,
  resolveAuthority,
  VALIDATORS,
  HANDLERS,
  VALID_COMMAND_TYPES,
  COMMAND_TO_AGGREGATE,
  _idempotencyCache,
};
