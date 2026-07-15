// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  buildGateCommitBindingFromGateRequest,
  buildGateCommitBindingFromIssueRequest,
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
});
