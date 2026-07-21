// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  buildGateCommitBindingFromGateRequest,
  buildGateCommitBindingFromIssueRequest,
  GATE_COMMIT_BINDING_VERSION,
  GateCommitBindingError,
  hashGateCommitBinding,
} from '../lib/gate-commit-binding.js';

const gateRequest = {
  entity_id: 'agent-1',
  action: 'transact',
  principal_id: 'human-1',
  counterparty_entity_id: 'merchant-1',
  delegation_id: 'delegation-1',
  scope: { currency: 'USD', purpose: 'invoice', limits: { daily: 1000 } },
  value_usd: 250,
  context: { region: 'us', resource_ref: 'invoice-42' },
  policy: 'strict',
  handshake_id: 'handshake-1',
  intent_ref: 'intent-1',
};

const issueRequest = {
  entity_id: 'agent-1',
  action_type: 'transact',
  principal_id: 'human-1',
  counterparty_entity_id: 'merchant-1',
  delegation_id: 'delegation-1',
  scope: { limits: { daily: 1000 }, purpose: 'invoice', currency: 'USD' },
  max_value_usd: 250,
  context: {
    intent_ref: 'intent-1',
    gate_ref: 'epc_gate',
    region: 'us',
    resource_ref: 'invoice-42',
    handshake_id: 'handshake-1',
  },
  policy: 'strict',
  gate_ref: 'epc_gate',
};

describe('gate commit exact-action binding', () => {
  it('joins equivalent gate and issue requests despite key order and ref placement', () => {
    const gateBinding = buildGateCommitBindingFromGateRequest(gateRequest);
    const issueBinding = buildGateCommitBindingFromIssueRequest(issueRequest);

    expect(issueBinding).toEqual(gateBinding);
    expect(hashGateCommitBinding(issueBinding)).toBe(hashGateCommitBinding(gateBinding));
  });

  it.each([
    ['principal_id', 'human-2'],
    ['counterparty_entity_id', 'attacker-merchant'],
    ['delegation_id', 'delegation-2'],
    ['max_value_usd', 251],
    ['scope', { currency: 'EUR', purpose: 'invoice', limits: { daily: 1000 } }],
    ['policy', 'permissive'],
  ])('changes the binding when %s changes', (field, value) => {
    const mutated = { ...issueRequest, [field]: value };
    expect(hashGateCommitBinding(buildGateCommitBindingFromIssueRequest(mutated)))
      .not.toBe(hashGateCommitBinding(buildGateCommitBindingFromGateRequest(gateRequest)));
  });

  it('changes the binding when nested context changes', () => {
    const mutated = {
      ...issueRequest,
      context: { ...issueRequest.context, region: 'eu' },
    };
    expect(hashGateCommitBinding(buildGateCommitBindingFromIssueRequest(mutated)))
      .not.toBe(hashGateCommitBinding(buildGateCommitBindingFromGateRequest(gateRequest)));
  });

  it('refuses conflicting top-level and context references', () => {
    expect(() => buildGateCommitBindingFromIssueRequest({
      ...issueRequest,
      resource_ref: 'invoice-99',
    })).toThrow(GateCommitBindingError);
  });

  it.each([
    [{ ...gateRequest, policy: 'made-up' }, /policy/i],
    [{ ...gateRequest, value_usd: '250' }, /number/i],
    [{ ...gateRequest, scope: [] }, /object/i],
    [{ ...gateRequest, context: { constructor: 'pollute' } }, /forbidden/i],
  ])('refuses non-canonical or unsafe input', (input, pattern) => {
    expect(() => buildGateCommitBindingFromGateRequest(input)).toThrow(pattern);
  });

  it.each([
    [{ ...gateRequest, entity_id: '' }, /entity_id/i],
    [{ ...gateRequest, action: null }, /action_type/i],
    [{ ...gateRequest, principal_id: 'x'.repeat(4097) }, /principal_id/i],
    [{ ...gateRequest, value_usd: -1 }, /non-negative/i],
    [{ ...gateRequest, value_usd: Number.POSITIVE_INFINITY }, /non-negative/i],
    [{ ...gateRequest, value_usd: Number.MAX_SAFE_INTEGER + 1 }, /non-negative/i],
    [{ ...gateRequest, context: { unsafe: Number.NaN } }, /unsafe number/i],
    [{ ...gateRequest, context: { unsupported: undefined } }, /JSON values only/i],
    [{ ...gateRequest, context: new Date() }, /plain JSON object/i],
  ])('fails closed on malformed material fields %#', (input, pattern) => {
    expect(() => buildGateCommitBindingFromGateRequest(input)).toThrow(pattern);
  });

  it('rejects sparse arrays rather than canonicalizing around omitted entries', () => {
    const sparse = [];
    sparse.length = 2;
    sparse[1] = 'present';
    expect(() => buildGateCommitBindingFromGateRequest({
      ...gateRequest,
      scope: { approvals: sparse },
    })).toThrow(/sparse array/i);
  });

  it('enforces depth and node-count limits before hashing', () => {
    let deep = { leaf: true };
    for (let index = 0; index < 65; index += 1) deep = { next: deep };
    expect(() => buildGateCommitBindingFromGateRequest({ ...gateRequest, scope: deep }))
      .toThrow(/depth limit/i);

    expect(() => buildGateCommitBindingFromGateRequest({
      ...gateRequest,
      scope: { nodes: Array.from({ length: 20_001 }, () => null) },
    })).toThrow(/size limit/i);
  });

  it('normalizes empty objects, null-prototype objects, defaults, and negative zero', () => {
    const nullPrototype = Object.create(null);
    nullPrototype.region = 'us';
    const binding = buildGateCommitBindingFromGateRequest({
      entity_id: 'agent-1',
      action: 'transact',
      value_usd: -0,
      scope: {},
      context: nullPrototype,
      policy: '',
    });

    expect(binding).toMatchObject({
      '@version': GATE_COMMIT_BINDING_VERSION,
      context: { region: 'us' },
      max_value_usd: 0,
      policy: 'standard',
      scope: null,
    });
    expect(Object.is(binding.max_value_usd, -0)).toBe(false);
  });

  it('refuses a context gate reference that is absent or different at top level', () => {
    expect(() => buildGateCommitBindingFromIssueRequest({
      ...issueRequest,
      gate_ref: null,
    })).toThrow(/context\.gate_ref/i);
    expect(() => buildGateCommitBindingFromIssueRequest({
      ...issueRequest,
      gate_ref: 'epc_other',
    })).toThrow(/context\.gate_ref/i);
  });

  it('refuses hashing an object outside the registered binding version', () => {
    expect(() => hashGateCommitBinding({ '@version': 'EP-GATE-COMMIT-BINDING-v2' }))
      .toThrow(/unsupported gate commit binding version/i);
  });
});
