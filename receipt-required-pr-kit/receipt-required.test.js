// SPDX-License-Identifier: Apache-2.0
//
// RR-1 conformance: proves the four checks on every push, so the claim can't go
// stale. Run: `npm test` (node --test).
//
//   1. missing receipt  -> 428 Receipt Required
//   2. valid receipt    -> the action runs (200)
//   3. replayed receipt -> refused (one-time consumption)
//   4. forged receipt   -> refused (signature / action-binding fails)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { receiptRequiredConformance } from '@emilia-protocol/require-receipt';
import { dispatch } from './example-dangerous-action.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, 'agent-actions.json'), 'utf8'));

// These conformance checks are self-contained: each receipt is minted with a
// fresh key, so we run the gate in explicit NON-PRODUCTION inline mode. In
// production you pin EMILIA_TRUSTED_KEYS instead (see the fail-closed test below,
// which proves the secure default refuses a destructive action with no trusted
// key configured).
process.env.EMILIA_ALLOW_INLINE_KEY = '1';

// Byte-identical to @emilia-protocol/verify's EP-RECEIPT-v1 canonicalization.
const canonicalize = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
      : JSON.stringify(v));

// Mint a FRESH valid EP-RECEIPT-v1 bound to `action`, signed by a named human's
// device key. (In production this is a real Face ID / passkey signoff; here it's
// node:crypto so the test is self-contained and needs no EMILIA backend.)
function issueReceipt(action) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'jane.doe@yourco.example' },
  };
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
}

test('RR-1: missing -> 428, valid -> runs, replay -> refused, forged -> refused', async () => {
  const result = await receiptRequiredConformance({
    dispatch,
    tool: 'delete_all_records',
    args: { table: 'customers' },
    // The receipt is bound to the SPECIFIC target the dispatcher acts on, not
    // just the action type (see example-dangerous-action.js): <action>:<table>.
    action: 'db.records.delete_all:customers',
    issueReceipt,
    manifest: MANIFEST,
  });

  assert.equal(result.checks.challenge_on_missing, true, 'missing receipt should return 428');
  assert.equal(result.checks.runs_on_valid, true, 'valid receipt should run the action');
  assert.equal(result.checks.replay_refused, true, 'replayed receipt should be refused');
  assert.equal(result.checks.forged_refused, true, 'forged receipt should be refused');
  assert.equal(result.level, 'RR-1', `expected RR-1, got ${result.level} (${JSON.stringify(result.detail)})`);
});

test('cross-target binding: a receipt for one table cannot wipe another', async () => {
  // Mint a receipt that authorizes wiping the "customers" table only.
  const receiptForCustomers = issueReceipt('db.records.delete_all:customers');

  // Sanity: it works on its own target.
  const onTarget = await dispatch('delete_all_records', { table: 'customers' }, receiptForCustomers);
  assert.equal(onTarget.status, 200, 'receipt should run against its bound table');

  // Same action type, DIFFERENT table -> must be refused (action_mismatch), and
  // the rejection must be sanitized to just a reason code.
  const offTarget = await dispatch('delete_all_records', { table: 'orders' }, issueReceipt('db.records.delete_all:customers'));
  assert.notEqual(offTarget.status, 200, 'a customers receipt must not wipe orders');
  assert.equal(offTarget.body.rejected.reason, 'action_mismatch', 'cross-target refusal should be action_mismatch');
  assert.deepEqual(Object.keys(offTarget.body.rejected), ['reason'], 'rejection must be sanitized to { reason } only');
});

test('consume-after-success: a failed action leaves the receipt retryable', async () => {
  const receipt = issueReceipt('db.records.delete_all:inventory');
  // First call succeeds and consumes the receipt.
  const first = await dispatch('delete_all_records', { table: 'inventory' }, receipt);
  assert.equal(first.status, 200);
  // Replaying the now-consumed receipt is refused.
  const replay = await dispatch('delete_all_records', { table: 'inventory' }, receipt);
  assert.notEqual(replay.status, 200, 'consumed receipt should be refused on replay');
  assert.equal(replay.body.rejected.reason, 'replay_refused');
});

test('secure default: enforcement on with NO trusted key fails closed (does not run)', async () => {
  // Simulate production posture: no inline opt-in, no pinned issuer keys.
  const prevInline = process.env.EMILIA_ALLOW_INLINE_KEY;
  const prevKeys = process.env.EMILIA_TRUSTED_KEYS;
  delete process.env.EMILIA_ALLOW_INLINE_KEY;
  delete process.env.EMILIA_TRUSTED_KEYS;
  try {
    // Even a well-formed receipt must NOT run the destructive action when no
    // issuer key is trusted — accepting a self-signed receipt here would be the
    // exact unsafe default we refuse to ship.
    const res = await dispatch('delete_all_records', { table: 'customers' }, issueReceipt('db.records.delete_all:customers'));
    assert.notEqual(res.status, 200, 'destructive action must not run without a trusted key');
    assert.equal(res.body.rejected.reason, 'receipt_enforcement_misconfigured');
    assert.notEqual(res.body.ran, true, 'the action must not have executed');
  } finally {
    if (prevInline === undefined) delete process.env.EMILIA_ALLOW_INLINE_KEY; else process.env.EMILIA_ALLOW_INLINE_KEY = prevInline;
    if (prevKeys === undefined) delete process.env.EMILIA_TRUSTED_KEYS; else process.env.EMILIA_TRUSTED_KEYS = prevKeys;
  }
});
