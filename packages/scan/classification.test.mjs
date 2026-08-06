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

test('newly admitted read verbs classify plain reads as pass-through', () => {
  for (const name of [
    'retrieve_balance',
    'findCustomerByEmail',
    'showInvoice',
    'inspectContainer',
    'browseCatalog',
  ]) {
    const classification = classifyAction({ name, description: 'Returns existing data.' });
    assert.equal(classification.decision, 'pass_through', name);
    assert.equal(classification.receipt_required, false, name);
  }
});

test('a leading read verb never launders a higher-precedence risk signal', () => {
  // Every case below leads with a read verb admitted above. Each must still be
  // caught, because risk category, destructive annotation, state change, and
  // hybrid-operation markers all outrank the read verb.
  const mustNotPassThrough = [
    { name: 'retrieveAndDeleteCustomer', description: 'Read the record, then delete it' },
    { name: 'findAndRefundCharge', description: 'Locate the charge and refund it' },
    { name: 'showThenGrantAdminRole', description: 'Display the user, then grant admin' },
    { name: 'inspectAndTerminateInstance', description: 'Inspect the host before terminating it' },
    { name: 'browseAndExportCustomerPII', description: 'Browse records and export them in bulk' },
    { name: 'retrieveInvoice', description: 'Retrieve the invoice, then send the wire' },
    { name: 'findUser', description: 'Finds the user and updates their bank details' },
    { name: 'showRecord', annotations: { destructiveHint: true }, description: 'Displays a record' },
  ];

  for (const action of mustNotPassThrough) {
    const classification = classifyAction(action);
    assert.notEqual(classification.decision, 'pass_through', action.name);
    assert.equal(classification.receipt_required, true, action.name);
  }
});
