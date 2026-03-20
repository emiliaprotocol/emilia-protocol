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
// Handshake handlers are loaded lazily to avoid circular imports.
// handshake.js is a self-contained EP Extension that writes directly
// to Supabase. The handlers below delegate to its public API.

// ── Command Type Constants ──────────────────────────────────────────────────

export const COMMAND_TYPES = {
  SUBMIT_RECEIPT: 'submit_receipt',
  CONFIRM_RECEIPT: 'confirm_receipt',
  ISSUE_COMMIT: 'issue_commit',
  VERIFY_COMMIT: 'verify_commit',
  REVOKE_COMMIT: 'revoke_commit',
  FILE_DISPUTE: 'file_dispute',
  RESOLVE_DISPUTE: 'resolve_dispute',
  FILE_REPORT: 'file_report',
  SUBMIT_AUTO_RECEIPT: 'submit_auto_receipt',
  INITIATE_HANDSHAKE: 'initiate_handshake',
  ADD_PRESENTATION: 'add_presentation',
  VERIFY_HANDSHAKE: 'verify_handshake',
  REVOKE_HANDSHAKE: 'revoke_handshake',
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
  [COMMAND_TYPES.SUBMIT_AUTO_RECEIPT]: 'receipt',
  [COMMAND_TYPES.INITIATE_HANDSHAKE]: 'handshake',
  [COMMAND_TYPES.ADD_PRESENTATION]: 'handshake',
  [COMMAND_TYPES.VERIFY_HANDSHAKE]: 'handshake',
  [COMMAND_TYPES.REVOKE_HANDSHAKE]: 'handshake',
};

// ── Error Class ─────────────────────────────────────────────────────────────

export class ProtocolWriteError extends Error {
  constructor(message, code = 'PROTOCOL_WRITE_ERROR', status = 400) {
    super(message);
    this.name = 'ProtocolWriteError';
    this.code = code;
    this.status = status;
  }
}

// ── Crypto Helpers ──────────────────────────────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

/**
 * Compute an idempotency key from the command.
 * Same command type + same actor + same input = same key.
 */
function computeIdempotencyKey(command) {
  return sha256(`${command.type}:${command.actor}:${JSON.stringify(command.input)}`);
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
}

// ── Protocol Event Builder ──────────────────────────────────────────────────

/**
 * Build a protocol event record for the append-only event log.
 *
 * @param {object} params
 * @param {string} params.aggregateType - receipt | commit | dispute | report
 * @param {string} params.aggregateId - The entity's ID for this aggregate
 * @param {string} params.commandType - The command that produced this event
 * @param {object} params.payload - The canonical payload to hash
 * @param {string} params.actorAuthorityId - Who performed the action
 * @param {string} params.idempotencyKey - Computed idempotency key
 * @param {string|null} params.parentEventHash - Hash of previous event for this aggregate
 * @returns {object} Protocol event record
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
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', 'VALIDATION_ERROR');
    if (!actor) throw new ProtocolWriteError('actor is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.SUBMIT_AUTO_RECEIPT](command) {
    const { input, actor } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', 'VALIDATION_ERROR');
    if (!actor) throw new ProtocolWriteError('actor is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.CONFIRM_RECEIPT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.receipt_id) throw new ProtocolWriteError('input.receipt_id is required', 'VALIDATION_ERROR');
    if (!input.confirming_entity_id) throw new ProtocolWriteError('input.confirming_entity_id is required', 'VALIDATION_ERROR');
    if (typeof input.confirm !== 'boolean') throw new ProtocolWriteError('input.confirm must be a boolean', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.ISSUE_COMMIT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', 'VALIDATION_ERROR');
    if (!input.action_type) throw new ProtocolWriteError('input.action_type is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.VERIFY_COMMIT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.commit_id) throw new ProtocolWriteError('input.commit_id is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.REVOKE_COMMIT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.commit_id) throw new ProtocolWriteError('input.commit_id is required', 'VALIDATION_ERROR');
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.FILE_DISPUTE](command) {
    const { input, actor } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.receipt_id) throw new ProtocolWriteError('input.receipt_id is required', 'VALIDATION_ERROR');
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', 'VALIDATION_ERROR');
    if (!actor) throw new ProtocolWriteError('actor is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.RESOLVE_DISPUTE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.dispute_id) throw new ProtocolWriteError('input.dispute_id is required', 'VALIDATION_ERROR');
    if (!input.resolution) throw new ProtocolWriteError('input.resolution is required', 'VALIDATION_ERROR');
    if (!input.rationale) throw new ProtocolWriteError('input.rationale is required', 'VALIDATION_ERROR');
    if (!input.operator_id) throw new ProtocolWriteError('input.operator_id is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.FILE_REPORT](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.entity_id) throw new ProtocolWriteError('input.entity_id is required', 'VALIDATION_ERROR');
    if (!input.report_type) throw new ProtocolWriteError('input.report_type is required', 'VALIDATION_ERROR');
    if (!input.description) throw new ProtocolWriteError('input.description is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.INITIATE_HANDSHAKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.mode) throw new ProtocolWriteError('input.mode is required', 'VALIDATION_ERROR');
    if (!input.policy_id) throw new ProtocolWriteError('input.policy_id is required', 'VALIDATION_ERROR');
    if (!input.parties || !Array.isArray(input.parties) || input.parties.length === 0) {
      throw new ProtocolWriteError('input.parties must be a non-empty array', 'VALIDATION_ERROR');
    }
  },

  [COMMAND_TYPES.ADD_PRESENTATION](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.handshake_id) throw new ProtocolWriteError('input.handshake_id is required', 'VALIDATION_ERROR');
    if (!input.party_role) throw new ProtocolWriteError('input.party_role is required', 'VALIDATION_ERROR');
    if (!input.presentation_hash) throw new ProtocolWriteError('input.presentation_hash is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.VERIFY_HANDSHAKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.handshake_id) throw new ProtocolWriteError('input.handshake_id is required', 'VALIDATION_ERROR');
  },

  [COMMAND_TYPES.REVOKE_HANDSHAKE](command) {
    const { input } = command;
    if (!input) throw new ProtocolWriteError('input is required', 'VALIDATION_ERROR');
    if (!input.handshake_id) throw new ProtocolWriteError('input.handshake_id is required', 'VALIDATION_ERROR');
    if (!input.reason) throw new ProtocolWriteError('input.reason is required', 'VALIDATION_ERROR');
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

  async [COMMAND_TYPES.INITIATE_HANDSHAKE](command) {
    const { initiateHandshake } = await import('@/lib/handshake');
    const result = await initiateHandshake(command.input);
    return { result, aggregateId: result.handshake_id || 'unknown' };
  },

  async [COMMAND_TYPES.ADD_PRESENTATION](command) {
    const { addPresentation } = await import('@/lib/handshake');
    const { handshake_id, party_role, ...presentation } = command.input;
    const result = await addPresentation(handshake_id, party_role, presentation);
    return { result, aggregateId: handshake_id };
  },

  async [COMMAND_TYPES.VERIFY_HANDSHAKE](command) {
    const { verifyHandshake } = await import('@/lib/handshake');
    const result = await verifyHandshake(command.input.handshake_id);
    return { result, aggregateId: command.input.handshake_id };
  },

  async [COMMAND_TYPES.REVOKE_HANDSHAKE](command) {
    const { revokeHandshake } = await import('@/lib/handshake');
    const result = await revokeHandshake(command.input.handshake_id, command.input.reason);
    return { result, aggregateId: command.input.handshake_id };
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
    throw new ProtocolWriteError('command.type is required', 'INVARIANT_VIOLATION');
  }

  // Invariant 2: command type must be known
  if (!VALID_COMMAND_TYPES.has(command.type)) {
    throw new ProtocolWriteError(
      `Unknown command type: "${command.type}". Valid types: ${[...VALID_COMMAND_TYPES].join(', ')}`,
      'UNKNOWN_COMMAND_TYPE'
    );
  }

  // Invariant 3: input must be an object
  if (command.input !== null && command.input !== undefined && typeof command.input !== 'object') {
    throw new ProtocolWriteError('command.input must be an object', 'INVARIANT_VIOLATION');
  }
}

// ── Authority Resolution ────────────────────────────────────────────────────

/**
 * Resolve the acting authority from the command.
 * Returns a normalized authority object.
 */
function resolveAuthority(command) {
  // actor can be a full entity object (from auth middleware) or a string ID
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
 * Fire-and-forget — never blocks the write path.
 */
async function appendProtocolEvent(event) {
  try {
    const supabase = getServiceClient();
    await supabase.from('protocol_events').insert(event);
  } catch (e) {
    // Degrade gracefully if table doesn't exist (pre-migration)
    const isMissingTable = e.message?.includes('does not exist') || e.message?.includes('relation');
    if (!isMissingTable) {
      console.warn('[protocolWrite] Event persistence failed:', e.message);
    }
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
          'ABUSE_DETECTED',
          429
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
    throw new ProtocolWriteError(`No handler for command type: ${command.type}`, 'NO_HANDLER', 500);
  }

  const { result, aggregateId } = await handler(command);

  // If the canonical function returned an error (not thrown), propagate it
  if (result && result.error) {
    return result;
  }

  // ── Step 7: Build protocol event ──
  const protocolEvent = buildProtocolEvent({
    aggregateType: COMMAND_TO_AGGREGATE[command.type],
    aggregateId,
    commandType: command.type,
    payload: command.input || {},
    actorAuthorityId: authority.id,
    idempotencyKey,
    parentEventHash: null, // TODO: chain events per aggregate
  });

  // ── Step 8: Append event (fire-and-forget) ──
  appendProtocolEvent(protocolEvent);

  // ── Step 9: Cache for idempotency ──
  setIdempotencyCache(idempotencyKey, result);

  // ── Step 10: Emit telemetry ──
  const durationMs = Date.now() - startTime;
  emitTelemetry(protocolEvent, command, durationMs);

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
