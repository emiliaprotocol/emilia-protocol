// SPDX-License-Identifier: Apache-2.0
// STRIX-11 regression: independent selector identities must converge on one
// manifest entry. A caller cannot use an unguarded action_type to override a
// protected transport selector.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findActionRequirement, resolveActionRequirement } from './index.js';

const MANIFEST = {
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: [
    {
      id: 'read',
      action_type: 'read.balance',
      receipt_required: false,
      match: { protocol: 'mcp', tool: 'read_balance' },
    },
    {
      id: 'release',
      action_type: 'payment.release',
      receipt_required: true,
      risk: 'critical',
      assurance_class: 'class_a',
      match: { protocol: 'mcp', tool: 'release_payment' },
    },
  ],
};

test('STRIX-11: contradictory action and transport selector identities do not first-match pass-through', () => {
  const selector = {
    action_type: 'read.balance',
    protocol: 'mcp',
    tool: 'release_payment',
  };
  const requirement = findActionRequirement(MANIFEST, selector);

  assert.equal(requirement, null);
  assert.deepEqual(resolveActionRequirement(MANIFEST, selector), {
    status: 'conflict',
    action: null,
    action_ids: ['read', 'release'],
  });
});

test('redundant selector identities resolve when they all name the same action', () => {
  const requirement = findActionRequirement(MANIFEST, {
    id: 'release',
    action_type: 'payment.release',
    protocol: 'mcp',
    tool: 'release_payment',
  });

  assert.equal(requirement?.id, 'release');
});

test('a conflicting transport qualifier cannot ride on a valid action id', () => {
  const requirement = findActionRequirement(MANIFEST, {
    id: 'release',
    protocol: 'http',
  });

  assert.equal(requirement, null);
});

test('an unknown standalone selector remains an ordinary no-match', () => {
  assert.deepEqual(resolveActionRequirement(MANIFEST, { tool: 'unknown_tool' }), {
    status: 'none',
    action: null,
  });
});
