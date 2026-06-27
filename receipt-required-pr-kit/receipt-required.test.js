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
    action: 'db.records.delete_all',
    issueReceipt,
    manifest: MANIFEST,
  });

  assert.equal(result.checks.challenge_on_missing, true, 'missing receipt should return 428');
  assert.equal(result.checks.runs_on_valid, true, 'valid receipt should run the action');
  assert.equal(result.checks.replay_refused, true, 'replayed receipt should be refused');
  assert.equal(result.checks.forged_refused, true, 'forged receipt should be refused');
  assert.equal(result.level, 'RR-1', `expected RR-1, got ${result.level} (${JSON.stringify(result.detail)})`);
});
