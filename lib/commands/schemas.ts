/**
 * EP Command Schemas — Shared validation for all mutating commands.
 *
 * Every mutating route must validate against these schemas before
 * calling protocolWrite(). This ensures no route-specific validation drift.
 *
 * @license Apache-2.0
 */

import { ProtocolWriteError } from '@/lib/protocol-write';

function requireField(obj: any, field: string, label?: string): void {
  if (!obj[field] && obj[field] !== 0 && obj[field] !== false) {
    throw new ProtocolWriteError(`${label || field} is required`, { code: 'VALIDATION_ERROR', status: 400 });
  }
}

function requireString(obj: any, field: string, label?: string): void {
  requireField(obj, field, label);
  if (typeof obj[field] !== 'string') {
    throw new ProtocolWriteError(`${label || field} must be a string`, { code: 'VALIDATION_ERROR', status: 400 });
  }
}

function requireArray(obj: any, field: string, label?: string): void {
  if (!Array.isArray(obj[field]) || obj[field].length === 0) {
    throw new ProtocolWriteError(`${label || field} must be a non-empty array`, { code: 'VALIDATION_ERROR', status: 400 });
  }
}

// ── Receipt Commands ─────────────────────────────────────────────────────

export function validateSubmitReceipt(input: any): void {
  requireString(input, 'entity_id');
}

export function validateSubmitAutoReceipt(input: any): void {
  requireString(input, 'entity_id');
}

export function validateConfirmReceipt(input: any): void {
  requireString(input, 'receipt_id');
  requireString(input, 'confirming_entity_id');
  if (typeof input.confirm !== 'boolean') {
    throw new ProtocolWriteError('confirm must be a boolean', { code: 'VALIDATION_ERROR', status: 400 });
  }
}

// ── Commit Commands ─────────────────────────────────────────────────────

export function validateIssueCommit(input: any): void {
  requireString(input, 'entity_id');
  requireString(input, 'action_type');
}

export function validateVerifyCommit(input: any): void {
  requireString(input, 'commit_id');
}

export function validateRevokeCommit(input: any): void {
  requireString(input, 'commit_id');
  requireString(input, 'reason');
}

// ── Dispute Commands ─────────────────────────────────────────────────────

export function validateFileDispute(input: any): void {
  requireString(input, 'receipt_id');
  requireString(input, 'reason');
}

export function validateRespondDispute(input: any): void {
  requireString(input, 'dispute_id');
  requireString(input, 'responder_id');
  requireString(input, 'response');
}

export function validateResolveDispute(input: any): void {
  requireString(input, 'dispute_id');
  requireString(input, 'resolution');
  requireString(input, 'rationale');
  requireString(input, 'operator_id');
}

export function validateAppealDispute(input: any): void {
  requireString(input, 'dispute_id');
  requireString(input, 'reason');
  if (input.reason && input.reason.trim().length < 10) {
    throw new ProtocolWriteError('Appeal reason must be at least 10 characters', { code: 'VALIDATION_ERROR', status: 400 });
  }
}

export function validateResolveAppeal(input: any): void {
  requireString(input, 'dispute_id');
  requireString(input, 'resolution');
  requireString(input, 'rationale');
  requireString(input, 'operator_id');
}

export function validateWithdrawDispute(input: any): void {
  requireString(input, 'dispute_id');
}

export function validateFileReport(input: any): void {
  requireString(input, 'entity_id');
  requireString(input, 'report_type');
  requireString(input, 'description');
}

// ── Handshake Commands ───────────────────────────────────────────────────

export function validateInitiateHandshake(input: any): void {
  requireString(input, 'mode');
  requireString(input, 'policy_id');
  requireArray(input, 'parties');
}

export function validateAddPresentation(input: any): void {
  requireString(input, 'handshake_id');
  requireString(input, 'party_role');
  requireString(input, 'presentation_hash');
}

export function validateVerifyHandshake(input: any): void {
  requireString(input, 'handshake_id');
}

export function validateRevokeHandshake(input: any): void {
  requireString(input, 'handshake_id');
  requireString(input, 'reason');
}

// ── Schema Map (command_type → validator) ────────────────────────────────

export const COMMAND_SCHEMAS: Record<string, Function> = {
  submit_receipt: validateSubmitReceipt,
  submit_auto_receipt: validateSubmitAutoReceipt,
  confirm_receipt: validateConfirmReceipt,
  issue_commit: validateIssueCommit,
  verify_commit: validateVerifyCommit,
  revoke_commit: validateRevokeCommit,
  file_dispute: validateFileDispute,
  respond_dispute: validateRespondDispute,
  resolve_dispute: validateResolveDispute,
  appeal_dispute: validateAppealDispute,
  resolve_appeal: validateResolveAppeal,
  withdraw_dispute: validateWithdrawDispute,
  file_report: validateFileReport,
  initiate_handshake: validateInitiateHandshake,
  add_presentation: validateAddPresentation,
  verify_handshake: validateVerifyHandshake,
  revoke_handshake: validateRevokeHandshake,
};
