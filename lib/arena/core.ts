// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Arena's synthetic allowance profile.
 *
 * This is a product demonstration profile, not a bank account, stored-value
 * instrument, production credential, or authorization receipt. The public
 * Arena uses it to make Gate's bounded-action/refusal behavior legible before
 * a buyer connects a real workflow.
 */
import { createHash } from 'node:crypto';

import { canonicalize, hashCanonical } from '@/packages/gate/execution-binding.js';
import { ACTION_REFUSAL_CLAIM_BOUNDARY } from '@/packages/gate/action-refusal-statement.js';

export const ARENA_ALLOWANCE_VERSION = 'EP-ARENA-ALLOWANCE-v1';
export const ARENA_ACTION_TYPE = 'arena.resource.allocate.1';
export const ARENA_CURRENCY = 'CREDITS';
export const ARENA_CLAIM_BOUNDARY =
  'synthetic_challenge_not_money_custody_settlement_identity_certification_or_production_authorization';

const PROFILE_KEYS = [
  '@version', 'session_id', 'agent_name', 'currency', 'total_amount',
  'max_amount_per_action', 'allowed_targets', 'issued_at', 'expires_at',
  'claim_boundary',
] as const;
const ACTION_KEYS = [
  'operation_id', 'action_type', 'target', 'amount', 'currency', 'purpose',
] as const;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/;
const ACTION_TYPE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;

export type ArenaAllowance = Readonly<{
  '@version': typeof ARENA_ALLOWANCE_VERSION;
  session_id: string;
  agent_name: string;
  currency: typeof ARENA_CURRENCY;
  total_amount: number;
  max_amount_per_action: number;
  allowed_targets: readonly string[];
  issued_at: string;
  expires_at: string;
  claim_boundary: typeof ARENA_CLAIM_BOUNDARY;
}>;

export type ArenaAction = Readonly<{
  operation_id: string;
  action_type: typeof ARENA_ACTION_TYPE;
  target: string;
  amount: number;
  currency: typeof ARENA_CURRENCY;
  purpose: string;
}>;

export type ArenaActionBinding = Readonly<{
  caid: string;
  action_digest: string;
}>;

export type ArenaDecision = Readonly<{
  decision: 'allow' | 'refuse';
  reason: string | null;
  remaining_amount: number;
}>;

function isPlainDataRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return isPlainDataRecord(value)
    && Reflect.ownKeys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function validInstant(value: unknown): value is string {
  return typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

export function createArenaAllowance(input: {
  sessionId: string;
  agentName: string;
  totalAmount: number;
  maxAmountPerAction: number;
  allowedTargets: string[];
  issuedAt: string;
  expiresAt: string;
}): ArenaAllowance {
  if (!IDENTIFIER.test(input.sessionId)) throw new TypeError('arena session id is invalid');
  const agentName = input.agentName.trim();
  if (agentName.length < 1 || agentName.length > 64) throw new TypeError('arena agent name is invalid');
  if (!Number.isSafeInteger(input.totalAmount) || input.totalAmount < 1
      || !Number.isSafeInteger(input.maxAmountPerAction) || input.maxAmountPerAction < 1
      || input.maxAmountPerAction > input.totalAmount) {
    throw new TypeError('arena allowance amounts are invalid');
  }
  if (!Array.isArray(input.allowedTargets) || input.allowedTargets.length < 1
      || input.allowedTargets.length > 32
      || input.allowedTargets.some((target) => typeof target !== 'string' || !IDENTIFIER.test(target))
      || new Set(input.allowedTargets).size !== input.allowedTargets.length) {
    throw new TypeError('arena allowance targets are invalid');
  }
  if (!validInstant(input.issuedAt) || !validInstant(input.expiresAt)
      || Date.parse(input.issuedAt) >= Date.parse(input.expiresAt)) {
    throw new TypeError('arena allowance time window is invalid');
  }
  return deepFreeze({
    '@version': ARENA_ALLOWANCE_VERSION,
    session_id: input.sessionId,
    agent_name: agentName,
    currency: ARENA_CURRENCY,
    total_amount: input.totalAmount,
    max_amount_per_action: input.maxAmountPerAction,
    allowed_targets: [...input.allowedTargets].sort(),
    issued_at: new Date(input.issuedAt).toISOString(),
    expires_at: new Date(input.expiresAt).toISOString(),
    claim_boundary: ARENA_CLAIM_BOUNDARY,
  });
}

function validateAllowance(value: unknown): value is ArenaAllowance {
  return hasExactKeys(value, PROFILE_KEYS)
    && value['@version'] === ARENA_ALLOWANCE_VERSION
    && value.currency === ARENA_CURRENCY
    && value.claim_boundary === ARENA_CLAIM_BOUNDARY
    && typeof value.session_id === 'string' && IDENTIFIER.test(value.session_id)
    && typeof value.agent_name === 'string' && value.agent_name.length > 0
    && Number.isSafeInteger(value.total_amount) && Number(value.total_amount) > 0
    && Number.isSafeInteger(value.max_amount_per_action)
    && Number(value.max_amount_per_action) > 0
    && Number(value.max_amount_per_action) <= Number(value.total_amount)
    && Array.isArray(value.allowed_targets)
    && value.allowed_targets.length > 0
    && value.allowed_targets.every((target) => typeof target === 'string' && IDENTIFIER.test(target))
    && new Set(value.allowed_targets).size === value.allowed_targets.length
    && validInstant(value.issued_at) && validInstant(value.expires_at)
    && Date.parse(value.issued_at) < Date.parse(value.expires_at);
}

function validateAction(value: unknown): value is ArenaAction {
  return hasExactKeys(value, ACTION_KEYS)
    && typeof value.operation_id === 'string' && IDENTIFIER.test(value.operation_id)
    && value.action_type === ARENA_ACTION_TYPE && ACTION_TYPE.test(value.action_type)
    && typeof value.target === 'string' && IDENTIFIER.test(value.target)
    && Number.isSafeInteger(value.amount) && Number(value.amount) > 0
    && typeof value.currency === 'string' && /^[A-Z][A-Z0-9]{2,11}$/.test(value.currency)
    && typeof value.purpose === 'string' && IDENTIFIER.test(value.purpose);
}

export function evaluateArenaAttempt({
  allowance,
  action,
  remainingAmount,
  operationSeen,
  now,
}: {
  allowance: unknown;
  action: unknown;
  remainingAmount: number;
  operationSeen: boolean;
  now: number;
}): ArenaDecision {
  const refuse = (reason: string): ArenaDecision => Object.freeze({
    decision: 'refuse', reason, remaining_amount: remainingAmount,
  });
  if (!validateAllowance(allowance)) return refuse('allowance_profile_invalid');
  if (!Number.isSafeInteger(now) || now < 0
      || !Number.isSafeInteger(remainingAmount) || remainingAmount < 0
      || remainingAmount > allowance.total_amount
      || typeof operationSeen !== 'boolean') return refuse('allowance_state_invalid');
  if (now < Date.parse(allowance.issued_at)) return refuse('allowance_not_yet_valid');
  if (now >= Date.parse(allowance.expires_at)) return refuse('allowance_expired');
  if (!validateAction(action)) return refuse('allowance_action_shape_invalid');
  if (operationSeen) return refuse('allowance_operation_replay');
  if (action.currency !== allowance.currency) return refuse('allowance_currency_mismatch');
  if (!allowance.allowed_targets.includes(action.target)) return refuse('allowance_target_not_allowed');
  if (action.amount > allowance.max_amount_per_action) {
    return refuse('allowance_per_action_limit_exceeded');
  }
  if (action.amount > remainingAmount) return refuse('allowance_aggregate_limit_exceeded');
  return Object.freeze({
    decision: 'allow', reason: null, remaining_amount: remainingAmount - action.amount,
  });
}

export function deriveArenaActionBinding(action: unknown): ArenaActionBinding {
  if (!validateAction(action)) throw new TypeError('arena action is invalid');
  const canonical = canonicalize(action);
  const digest = createHash('sha256').update(canonical, 'utf8').digest();
  return Object.freeze({
    caid: `caid:1:${action.action_type}:jcs-sha256:${digest.toString('base64url')}`,
    action_digest: `sha256:${digest.toString('hex')}`,
  });
}

const REQUIREMENT_BY_REASON: Readonly<Record<string, string>> = Object.freeze({
  allowance_profile_invalid: 'allowance-profile-valid',
  allowance_state_invalid: 'allowance-state-valid',
  allowance_not_yet_valid: 'allowance-current',
  allowance_expired: 'allowance-current',
  allowance_action_shape_invalid: 'allowance-exact-action',
  allowance_operation_replay: 'allowance-single-use-operation',
  allowance_currency_mismatch: 'allowance-currency',
  allowance_target_not_allowed: 'allowance-target',
  allowance_per_action_limit_exceeded: 'allowance-per-action-limit',
  allowance_aggregate_limit_exceeded: 'allowance-aggregate-limit',
});

export function arenaRequirementForReason(reason: unknown): string | null {
  return typeof reason === 'string' ? REQUIREMENT_BY_REASON[reason] || null : null;
}

export function buildArenaRefusalInput({
  allowance,
  action,
  binding,
  reason,
  refusalId,
  relyingPartyId,
  nonce,
  refusedAt,
  expiresAt,
}: {
  allowance: ArenaAllowance;
  action: ArenaAction;
  binding: ArenaActionBinding;
  reason: string;
  refusalId: string;
  relyingPartyId: string;
  nonce: string;
  refusedAt: string;
  expiresAt: string;
}): Record<string, unknown> {
  if (!validateAllowance(allowance) || !validateAction(action)
      || !IDENTIFIER.test(refusalId) || !IDENTIFIER.test(relyingPartyId)
      || !IDENTIFIER.test(nonce) || !validInstant(refusedAt) || !validInstant(expiresAt)
      || Date.parse(refusedAt) >= Date.parse(expiresAt)
      || REQUIREMENT_BY_REASON[reason] === undefined) {
    throw new TypeError('arena refusal context is invalid');
  }
  const expectedBinding = deriveArenaActionBinding(action);
  if (binding.caid !== expectedBinding.caid || binding.action_digest !== expectedBinding.action_digest) {
    throw new TypeError('arena refusal action binding mismatch');
  }
  const profileDigest = `sha256:${hashCanonical(allowance)}`;
  return {
    refusal_id: refusalId,
    relying_party_id: relyingPartyId,
    caid: binding.caid,
    action_digest: binding.action_digest,
    program: {
      program_id: 'emilia.arena.allowance.1',
      version: 1,
      source_digest: profileDigest,
      program_digest: profileDigest,
    },
    failed_requirement_ids: [REQUIREMENT_BY_REASON[reason]],
    evidence_digests: [],
    challenge_digests: [binding.action_digest],
    nonce,
    refused_at: refusedAt,
    expires_at: expiresAt,
    refusal_class: 'authorization_refused',
    semantics: {
      verification: 'VERIFIED',
      match: 'MATCH',
      satisfaction: 'NOT_SATISFIED',
      authorization: 'NOT_AUTHORIZED',
    },
    delivery: null,
    custody: null,
    transparency_anchor: null,
    claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
  };
}
