// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { canonicalize } from './canonical-json.js';

export const GATE_COMMIT_BINDING_VERSION = 'EP-GATE-COMMIT-BINDING-v1';

const GATE_POLICIES = new Set(['strict', 'standard', 'permissive']);
const RESERVED_CONTEXT_FIELDS = new Set([
  'gate_ref',
  'handshake_id',
  'resource_ref',
  'intent_ref',
]);
const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_DEPTH = 64;
const MAX_NODES = 20_000;
const MAX_IDENTIFIER_LENGTH = 4_096;

export class GateCommitBindingError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GateCommitBindingError';
  }
}

function normalizeJson(value, path, state = { nodes: 0 }, depth = 0) {
  state.nodes += 1;
  if (state.nodes > MAX_NODES) {
    throw new GateCommitBindingError(`${path} exceeds the canonical binding size limit`);
  }
  if (depth > MAX_DEPTH) {
    throw new GateCommitBindingError(`${path} exceeds the canonical binding depth limit`);
  }

  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new GateCommitBindingError(`${path} contains an unsafe number`);
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    const result: any[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        throw new GateCommitBindingError(`${path} contains a sparse array`);
      }
      result.push(normalizeJson(value[index], `${path}[${index}]`, state, depth + 1));
    }
    return result;
  }
  if (typeof value !== 'object' || value === undefined) {
    throw new GateCommitBindingError(`${path} must contain JSON values only`);
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new GateCommitBindingError(`${path} must be a plain JSON object`);
  }

  const result = Object.create(null);
  for (const key of Object.keys(value).sort()) {
    if (FORBIDDEN_OBJECT_KEYS.has(key)) {
      throw new GateCommitBindingError(`${path} contains forbidden key "${key}"`);
    }
    result[key] = normalizeJson(value[key], `${path}.${key}`, state, depth + 1);
  }
  return result;
}

function normalizeObject(value, path) {
  if (value == null) return null;
  const result = normalizeJson(value, path);
  if (Array.isArray(result) || typeof result !== 'object') {
    throw new GateCommitBindingError(`${path} must be a JSON object`);
  }
  return Object.keys(result).length === 0 ? null : result;
}

function requiredString(value, path) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_IDENTIFIER_LENGTH) {
    throw new GateCommitBindingError(`${path} must be a non-empty string`);
  }
  return value;
}

function optionalString(value, path) {
  if (value == null) return null;
  return requiredString(value, path);
}

function normalizePolicy(value) {
  const policy = value == null || value === '' ? 'standard' : value;
  if (typeof policy !== 'string' || !GATE_POLICIES.has(policy)) {
    throw new GateCommitBindingError('policy must be strict, standard, or permissive');
  }
  return policy;
}

function normalizeAmount(value, path) {
  if (value == null) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new GateCommitBindingError(`${path} must be a finite non-negative number`);
  }
  return Object.is(value, -0) ? 0 : value;
}

function splitContext(rawContext, topLevelGateRef = null) {
  const normalized = normalizeObject(rawContext, 'context');
  if (!normalized) return { context: null, refs: Object.create(null) };

  if (normalized.gate_ref != null) {
    if (topLevelGateRef == null || normalized.gate_ref !== topLevelGateRef) {
      throw new GateCommitBindingError('context.gate_ref must match the top-level gate_ref');
    }
  }

  const refs = Object.create(null);
  const context = Object.create(null);
  for (const [key, value] of Object.entries(normalized)) {
    if (RESERVED_CONTEXT_FIELDS.has(key)) {
      if (key !== 'gate_ref') refs[key] = value;
    } else {
      context[key] = value;
    }
  }

  return {
    context: Object.keys(context).length === 0 ? null : context,
    refs,
  };
}

function resolveReference(directValue, contextValue, path) {
  const direct = optionalString(directValue, path);
  const nested = optionalString(contextValue, `context.${path}`);
  if (direct != null && nested != null && direct !== nested) {
    throw new GateCommitBindingError(`${path} conflicts with context.${path}`);
  }
  return direct ?? nested;
}

function buildBinding({
  entityId,
  actionType,
  principalId,
  counterpartyEntityId,
  delegationId,
  scope,
  amount,
  context,
  policy,
  handshakeId,
  resourceRef,
  intentRef,
  gateRef = null,
}) {
  const split = splitContext(context, gateRef);

  return {
    '@version': GATE_COMMIT_BINDING_VERSION,
    action_type: requiredString(actionType, 'action_type'),
    context: split.context,
    counterparty_entity_id: optionalString(counterpartyEntityId, 'counterparty_entity_id'),
    delegation_id: optionalString(delegationId, 'delegation_id'),
    entity_id: requiredString(entityId, 'entity_id'),
    handshake_id: resolveReference(handshakeId, split.refs.handshake_id, 'handshake_id'),
    intent_ref: resolveReference(intentRef, split.refs.intent_ref, 'intent_ref'),
    max_value_usd: normalizeAmount(amount, 'max_value_usd'),
    policy: normalizePolicy(policy),
    principal_id: optionalString(principalId, 'principal_id'),
    resource_ref: resolveReference(resourceRef, split.refs.resource_ref, 'resource_ref'),
    scope: normalizeObject(scope, 'scope'),
  };
}

export function buildGateCommitBindingFromGateRequest(body) {
  return buildBinding({
    entityId: body?.entity_id,
    actionType: body?.action,
    principalId: body?.principal_id,
    counterpartyEntityId: body?.counterparty_entity_id,
    delegationId: body?.delegation_id,
    scope: body?.scope,
    amount: body?.value_usd,
    context: body?.context,
    policy: body?.policy,
    handshakeId: body?.handshake_id,
    resourceRef: body?.resource_ref,
    intentRef: body?.intent_ref,
  });
}

export function buildGateCommitBindingFromIssueRequest(body) {
  return buildBinding({
    entityId: body?.entity_id,
    actionType: body?.action_type,
    principalId: body?.principal_id,
    counterpartyEntityId: body?.counterparty_entity_id,
    delegationId: body?.delegation_id,
    scope: body?.scope,
    amount: body?.max_value_usd,
    context: body?.context,
    policy: body?.policy,
    handshakeId: body?.handshake_id,
    resourceRef: body?.resource_ref,
    intentRef: body?.intent_ref,
    gateRef: body?.gate_ref,
  });
}

export function hashGateCommitBinding(binding) {
  if (binding?.['@version'] !== GATE_COMMIT_BINDING_VERSION) {
    throw new GateCommitBindingError('unsupported gate commit binding version');
  }
  return `sha256:${createHash('sha256').update(canonicalize(binding), 'utf8').digest('hex')}`;
}
