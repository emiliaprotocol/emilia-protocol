// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyAction } from './index.js';

test('leading read verbs survive camelCase, kebab-case, and snake_case tokenization', () => {
  for (const name of ['getAccountBalance', 'fetch-account-status', 'list_customers']) {
    const classification = classifyAction({ name });
    assert.equal(classification.decision, 'pass_through', name);
    assert.equal(classification.receipt_required, false, name);
    assert.match(classification.reason, /leading read-only verb/i, name);
  }
});

test('read words cannot launder mutation or ambiguous hybrid semantics', () => {
  const hostileActions = [
    { name: 'rotateApiKey', expectedSignal: 'rotate' },
    { name: 'archiveCustomer', expectedSignal: 'archive' },
    { name: 'readThenRotate', expectedSignal: 'rotate' },
    {
      name: 'rotateApiKey',
      description: 'Fetch the current API key and rotate it',
      expectedSignal: 'rotate',
    },
    {
      name: 'archiveCustomer',
      description: 'List the customer and archive the record',
      expectedSignal: 'archive',
    },
    {
      name: 'fetchAndRotateApiKey',
      description: 'Fetch the API key before replacing it',
      expectedSignal: 'rotate',
    },
    {
      name: 'listThenFrobnicateCustomer',
      description: 'List a customer, then perform a second undocumented operation',
      expectedSignal: 'then',
    },
  ];

  for (const { expectedSignal, ...action } of hostileActions) {
    const classification = classifyAction(action);
    assert.equal(classification.decision, 'review_fail_closed', action.name);
    assert.equal(classification.receipt_required, true, action.name);
    assert.match(classification.reason, new RegExp(expectedSignal, 'i'), action.name);
  }
});

test('inflected mutation verbs fail closed instead of hiding behind a read-shaped name', () => {
  for (const [description, expectedSignal] of [
    ['Rotates the active API credential', 'rotate'],
    ['Archives the record', 'archive'],
    ['Updates account metadata', 'update'],
    ['Revoked the current authorization', 'revoke'],
  ]) {
    const classification = classifyAction({ name: 'getCustomer', description });
    assert.equal(classification.decision, 'review_fail_closed', description);
    assert.equal(classification.receipt_required, true, description);
    assert.match(classification.reason, new RegExp(expectedSignal, 'i'), description);
  }
});
