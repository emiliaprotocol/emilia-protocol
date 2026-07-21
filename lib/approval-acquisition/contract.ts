// SPDX-License-Identifier: Apache-2.0
//
// Closed EP-APPROVAL-v1 request contract. Acquisition profiles are selected
// exclusively by the challenged action type. Callers cannot supply policy,
// display text, renderers, or an endpoint adapter. The reference registry is
// deliberately limited to ceremonies that are fully implemented end to end.

import crypto from 'node:crypto';
import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { computeCaid } from '@/caid/impl/js/caid.mjs';
import caidActionTypeRegistry from '@/caid/registry/action-types.json';

type JsonObject = Record<string, any>;

export const APPROVAL_FLOW = 'EP-APPROVAL-v1';
export const APPROVAL_ACTION_TYPE = 'payment.release';
export const APPROVAL_CAID_ACTION_TYPE = 'payment.release.1';
export const APPROVAL_REQUIRED_FIELDS = Object.freeze([
  'action_type',
  'amount_usd',
  'currency',
  'payment_instruction_id',
  'beneficiary_account_hash',
]);
export const APPROVAL_PROFILES = Object.freeze({
  [APPROVAL_ACTION_TYPE]: Object.freeze({
    actionType: APPROVAL_ACTION_TYPE,
    caidActionType: APPROVAL_CAID_ACTION_TYPE,
    requiredFields: APPROVAL_REQUIRED_FIELDS,
    ceremony: 'cloud-payment-release-class-a',
  }),
});
export const SUPPORTED_APPROVAL_ACTION_TYPES = Object.freeze(Object.keys(APPROVAL_PROFILES));

const TOP_LEVEL_KEYS = Object.freeze(['action', 'approver_id', 'challenge', 'flow', 'idempotency_key']);
const CHALLENGE_REQUIRED_KEYS = Object.freeze(['action', 'action_hash', 'required_fields']);
const CHALLENGE_OPTIONAL_KEYS = Object.freeze(['caid_selector']);
const ACTION_KEYS = Object.freeze([
  'action_caid',
  'action_type',
  'amount_usd',
  'beneficiary_account_hash',
  'counterparty_name',
  'currency',
  'payment_instruction_id',
]);
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const APPROVER = /^[A-Za-z0-9:_.@-]{3,128}$/;
const PAYMENT_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9:._/-]{2,199}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

const paymentDefinition = caidActionTypeRegistry.types.find(
  (definition) => definition.action_type === APPROVAL_CAID_ACTION_TYPE
    && definition.status === 'active',
);

export type ApprovalCreateValue = {
  normalizedBody: JsonObject;
  action: JsonObject;
  actionHash: string;
  actionCaid: string;
  challengeHash: string;
  requestDigest: string;
  idempotencyDigest: string;
  approverId: string;
  idempotencyKey: string;
  cloudApprovalBody: {
    payment_reference: string;
    amount: number;
    currency: string;
    counterparty_name: string;
    payment_destination_hash: string;
    approver_id: string;
  };
};

export type ApprovalParseResult =
  | { ok: true; value: ApprovalCreateValue }
  | { ok: false; status: number; code: string; detail: string };

function isPlainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: JsonObject, required: readonly string[], optional: readonly string[] = []): boolean {
  const requiredSet = new Set(required);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key))
    && Object.keys(value).filter((key) => requiredSet.has(key)).length === required.length;
}

function closedJson(value: unknown, depth = 0): boolean {
  if (depth > 32) return false;
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.length <= 64 && value.every((entry) => closedJson(entry, depth + 1));
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  return keys.length <= 64
    && keys.every((key) => !FORBIDDEN_KEYS.has(key) && closedJson(value[key], depth + 1));
}

function canonicalize(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(',')}}`;
}

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}

function error(code: string, detail: string, status = 400): ApprovalParseResult {
  return { ok: false, status, code, detail };
}

function amountString(value: number): string | null {
  if (!Number.isFinite(value) || value <= 0 || value > 1_000_000_000_000) return null;
  const cents = value * 100;
  if (!Number.isSafeInteger(cents)) return null;
  return value.toFixed(2).replace(/\.00$/, '').replace(/(\.\d)0$/, '$1');
}

export function buildPaymentReleaseActionIdentity(material: JsonObject):
  | { ok: true; actionCaid: string; caidDigest: string; caidAction: JsonObject }
  | { ok: false; detail: string } {
  const amount = amountString(material.amount_usd);
  if (!amount) return { ok: false, detail: 'amount_usd must be positive, finite, bounded, and have at most two decimals' };
  const caidAction = {
    action_type: APPROVAL_CAID_ACTION_TYPE,
    amount,
    currency: material.currency,
    beneficiary_account: material.beneficiary_account_hash,
    payment_instruction_id: material.payment_instruction_id,
    ...(typeof material.counterparty_name === 'string' && material.counterparty_name.trim()
      ? { memo: material.counterparty_name.trim() }
      : {}),
  };
  const result = computeCaid(caidAction, {
    suite: 'jcs-sha256',
    definitions: [paymentDefinition],
  });
  if (!result?.caid || !result?.digest) {
    return { ok: false, detail: `payment material cannot form a CAID (${(result?.refusals || []).join(', ')})` };
  }
  return {
    ok: true,
    actionCaid: result.caid,
    caidDigest: result.digest,
    caidAction,
  };
}

export function parseApprovalCreateRequest(input: unknown): ApprovalParseResult {
  if (!isPlainObject(input) || !closedJson(input) || !hasExactKeys(input, TOP_LEVEL_KEYS)) {
    return error('invalid_approval_request', 'request must be a closed EP-APPROVAL-v1 JSON object');
  }
  if (input.flow !== APPROVAL_FLOW) {
    return error('unsupported_approval_flow', `flow must be ${APPROVAL_FLOW}`);
  }
  if (!APPROVER.test(input.approver_id || '')) {
    return error('invalid_approver_id', 'approver_id is outside the fixed profile');
  }
  if (!IDEMPOTENCY.test(input.idempotency_key || '')) {
    return error('invalid_idempotency_key', 'idempotency_key must be 16-128 safe characters');
  }

  const challenge = input.challenge;
  if (!isPlainObject(challenge)
      || !hasExactKeys(challenge, CHALLENGE_REQUIRED_KEYS, CHALLENGE_OPTIONAL_KEYS)) {
    return error('invalid_challenge', 'challenge must use the closed payment-release challenge schema');
  }
  const profile = APPROVAL_PROFILES[challenge.action as keyof typeof APPROVAL_PROFILES];
  if (!profile || !SHA256.test(challenge.action_hash || '')) {
    return error('invalid_challenge_binding', 'challenge action or action_hash is invalid');
  }
  if (!Array.isArray(challenge.required_fields)
      || challenge.required_fields.length !== profile.requiredFields.length
      || new Set(challenge.required_fields).size !== profile.requiredFields.length
      || profile.requiredFields.some((field) => !challenge.required_fields.includes(field))) {
    return error('required_fields_mismatch', 'challenge must require every payment-release material field');
  }
  if (challenge.caid_selector !== undefined
      && (!isPlainObject(challenge.caid_selector)
        || !hasExactKeys(challenge.caid_selector, ['field'])
        || challenge.caid_selector.field !== 'action_caid')) {
    return error('caid_selector_mismatch', 'caid_selector must select action_caid');
  }

  const action = input.action;
  if (!isPlainObject(action) || !hasExactKeys(action, ACTION_KEYS)) {
    return error('invalid_action', 'action must use the closed payment-release action schema');
  }
  if (action.action_type !== APPROVAL_ACTION_TYPE
      || amountString(action.amount_usd) === null
      || typeof action.currency !== 'string'
      || !/^[A-Z]{3}$/.test(action.currency)
      || !PAYMENT_REFERENCE.test(action.payment_instruction_id || '')
      || String(action.payment_instruction_id).includes('..')
      || !SHA256.test(action.beneficiary_account_hash || '')
      || typeof action.counterparty_name !== 'string'
      || !action.counterparty_name.trim()
      || action.counterparty_name.length > 160
      || CONTROL_CHARACTERS.test(action.counterparty_name)) {
    return error('invalid_action_material', 'payment-release action material is invalid');
  }

  const identity = buildPaymentReleaseActionIdentity(action);
  if (!identity.ok) return error('invalid_action_caid', identity.detail);
  if (action.action_caid !== identity.actionCaid) {
    return error('action_caid_mismatch', 'action_caid does not identify the exact payment material');
  }
  const actionHash = approvalActionHash(action);
  if (challenge.action_hash !== actionHash) {
    return error('action_hash_mismatch', 'challenge action_hash does not bind the exact action');
  }

  const normalizedAction = JSON.parse(JSON.stringify(action));
  const normalizedChallenge = {
    action: APPROVAL_ACTION_TYPE,
    action_hash: actionHash,
    required_fields: [...profile.requiredFields],
    ...(challenge.caid_selector ? { caid_selector: { field: 'action_caid' } } : {}),
  };
  const normalizedBody = {
    flow: APPROVAL_FLOW,
    challenge: normalizedChallenge,
    action: normalizedAction,
    approver_id: input.approver_id,
  };

  return {
    ok: true,
    value: {
      normalizedBody,
      action: normalizedAction,
      actionHash,
      actionCaid: identity.actionCaid,
      challengeHash: digest(normalizedChallenge),
      requestDigest: digest(normalizedBody),
      idempotencyDigest: digest(input.idempotency_key),
      approverId: input.approver_id,
      idempotencyKey: input.idempotency_key,
      cloudApprovalBody: {
        payment_reference: action.payment_instruction_id,
        amount: action.amount_usd,
        currency: action.currency,
        counterparty_name: action.counterparty_name.trim(),
        payment_destination_hash: action.beneficiary_account_hash,
        approver_id: input.approver_id,
      },
    },
  };
}

export const _internals = { canonicalize, digest, amountString };
