// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyAction, scanActions, KNOWN_CATEGORIES, HIGH_RISK_ACTION_PACKS } from './index.js';

test('STRUCTURAL: every category maps to a real risk pack (no guessed ids)', () => {
  const realIds = new Set(HIGH_RISK_ACTION_PACKS.map((p) => p.id));
  for (const cat of KNOWN_CATEGORIES) {
    assert.ok(realIds.has(cat), `category "${cat}" does not match any risk-pack id — it would lose its tier and required_fields`);
  }
});

test('tiers are correct, not defaulted (quorum stays quorum)', () => {
  assert.equal(classifyAction({ name: 'grantAdminRole', description: 'give admin privileges' }).assurance_class, 'quorum');
  assert.equal(classifyAction({ name: 'overrideRegulatedDecision', description: 'override a benefits decision' }).assurance_class, 'quorum');
  const del = classifyAction({ name: 'deleteCustomer', description: 'permanently remove a record' });
  assert.equal(del.category, 'records.delete');
  assert.ok(del.required_fields.includes('before_state_hash'), 'record delete must bind the pre-state, not fall back to just action_type');
});
import { HIGH_RISK_ACTION_PACKS as VENDORED } from './risk-packs.js';
// Monorepo-only: gate is a sibling here, never shipped with this package. This
// guards the vendored risk packs against drifting from the authoritative Gate copy.
import { HIGH_RISK_ACTION_PACKS as GATE } from '../gate/action-packs.js';

test('DRIFT GUARD: vendored risk-packs match the authoritative Gate action packs', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(VENDORED)), JSON.parse(JSON.stringify(GATE)),
    'packages/scan/risk-packs.js drifted from packages/gate/action-packs.js — re-sync it');
});

test('recognized high-risk actions are gated at the right tier', () => {
  const wire = classifyAction({ name: 'sendWire', description: 'outgoing wire to a beneficiary' });
  assert.equal(wire.decision, 'gate');
  assert.equal(wire.receipt_required, true);
  assert.equal(wire.assurance_class, 'class_a');

  const deploy = classifyAction({ name: 'deployToProduction', description: 'ship build to prod' });
  assert.equal(deploy.decision, 'gate');
  assert.equal(deploy.assurance_class, 'quorum');

  const bank = classifyAction({ name: 'updateBeneficiaryBankDetails', description: 'change destination account for a payee' });
  assert.equal(bank.decision, 'gate');
  assert.equal(bank.category, 'money_movement.bank_details_change', 'payee/beneficiary must land in bank-detail-change, not generic release');
});

test('read-only actions pass through', () => {
  assert.equal(classifyAction({ name: 'getAccountBalance' }).decision, 'pass_through');
  assert.equal(classifyAction({ name: 'searchTransactions' }).decision, 'pass_through');
  assert.equal(classifyAction({ name: 'summarizeTicket', annotations: { readOnlyHint: true } }).decision, 'pass_through');
});

test('THE HONEST CORE: a mutating action of unrecognized category fails closed, never waved through', () => {
  const c = classifyAction({ name: 'reconcileLedger', description: 'reconcile ledger and post adjustments' });
  assert.equal(c.decision, 'review_fail_closed');
  assert.equal(c.receipt_required, true, 'an unrecognized mutator MUST default to requiring a receipt');
});

test('MCP destructiveHint annotation is honored', () => {
  const c = classifyAction({ name: 'rotateApiKey', annotations: { destructiveHint: true } });
  assert.equal(c.decision, 'gate');
  assert.equal(c.receipt_required, true);
});

test('the emitted manifest fails closed on every discovered action', () => {
  const rep = scanActions([
    { name: 'getBalance' },
    { name: 'sendWire', description: 'wire funds' },
    { name: 'reconcileLedger', description: 'post adjustments' },
  ]);
  const discovered = rep.manifest.actions.filter((a) => String(a.id).startsWith('discovered.'));
  assert.ok(discovered.length >= 2, 'both mutating actions should be in the manifest');
  assert.ok(discovered.every((a) => a.receipt_required === true), 'no discovered action may be receipt_required:false');
});
