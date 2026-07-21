// SPDX-License-Identifier: Apache-2.0
// verifyEmiliaReceipt() core tests — freshness fail-closed regression.
//
// Regression for the LOW fail-closed finding: when maxAgeSec is enforced, a
// receipt with a MISSING or UNPARSEABLE created_at must be treated as EXPIRED
// (fail closed), never silently accepted by skipping the age gate. This mirrors
// what /api/v1/guarded enforces on the demand side.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyEmiliaReceipt } from './index.js';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

// Mint a validly SIGNED EP-RECEIPT-v1. `createdAt` may be a valid ISO string or
// an unparseable string; pass `omitCreatedAt: true` to leave the field off the
// payload entirely. The value is signed over so the signature stays valid.
function mint(/** @type {{actionType?: string, createdAt?: string, omitCreatedAt?: boolean, expiresAt?: string}} */ {
  actionType = 'db.records.delete',
  createdAt = new Date().toISOString(),
  omitCreatedAt = false,
  expiresAt = undefined,
} = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  /** @type {any} */
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    claim: { action_type: actionType, outcome: 'allow_with_signoff', approver: 'jane@yourco.example' },
  };
  if (!omitCreatedAt) payload.created_at = createdAt;
  if (expiresAt !== undefined) payload.expires_at = expiresAt;
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { doc: { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub }, pub };
}

test('fresh receipt with a valid created_at verifies', () => {
  const { doc, pub } = mint({ createdAt: new Date().toISOString() });
  const v = verifyEmiliaReceipt(doc, { trustedKeys: [pub], maxAgeSec: 900 });
  assert.equal(v.ok, true, `expected ok, got ${JSON.stringify(v)}`);
});

test('receipt older than maxAgeSec is rejected as expired', () => {
  const stale = new Date(Date.now() - 3600 * 1000).toISOString(); // 1h ago
  const { doc, pub } = mint({ createdAt: stale });
  const v = verifyEmiliaReceipt(doc, { trustedKeys: [pub], maxAgeSec: 900 });
  assert.equal(v.ok, false);
  assert.equal(v.reason, 'receipt_expired');
});

test('receipt beyond the allowed future clock skew is rejected', () => {
  const nowMs = Date.parse('2026-07-21T19:00:00.000Z');
  const { doc, pub } = mint({ createdAt: new Date(nowMs + 61_000).toISOString() });
  const v = verifyEmiliaReceipt(doc, { trustedKeys: [pub], maxAgeSec: 900, now: () => nowMs });
  assert.equal(v.ok, false);
  assert.equal(v.reason, 'receipt_not_yet_valid');
});

test('signed expires_at is enforced independently of max age', () => {
  const nowMs = Date.parse('2026-07-21T19:00:00.000Z');
  const { doc, pub } = mint({
    createdAt: new Date(nowMs - 1_000).toISOString(),
    expiresAt: new Date(nowMs).toISOString(),
  });
  const v = verifyEmiliaReceipt(doc, { trustedKeys: [pub], maxAgeSec: 0, now: () => nowMs });
  assert.equal(v.ok, false);
  assert.equal(v.reason, 'receipt_expired');
});

test('freshness uses the caller-supplied trusted clock', () => {
  const nowMs = Date.parse('2026-07-19T04:00:00.000Z');
  const { doc, pub } = mint({
    createdAt: new Date(nowMs - 1_000).toISOString(),
  });
  const v = verifyEmiliaReceipt(doc, {
    trustedKeys: [pub],
    maxAgeSec: 900,
    now: () => nowMs,
  });
  assert.equal(v.ok, true, `expected deterministic freshness, got ${JSON.stringify(v)}`);
});

test('FAIL-CLOSED: missing created_at is rejected as expired when maxAgeSec set', () => {
  const { doc, pub } = mint({ omitCreatedAt: true });
  assert.equal(doc.payload.created_at, undefined, 'fixture must omit created_at');
  const v = verifyEmiliaReceipt(doc, { trustedKeys: [pub], maxAgeSec: 900 });
  assert.equal(v.ok, false, 'an undated receipt must NOT slip past the age gate');
  assert.equal(v.reason, 'receipt_expired');
});

test('FAIL-CLOSED: unparseable created_at is rejected as expired when maxAgeSec set', () => {
  const { doc, pub } = mint({ createdAt: 'not-a-date' });
  const v = verifyEmiliaReceipt(doc, { trustedKeys: [pub], maxAgeSec: 900 });
  assert.equal(v.ok, false, 'a garbage created_at must NOT slip past the age gate');
  assert.equal(v.reason, 'receipt_expired');
});

test('missing created_at is allowed only when age enforcement is disabled', () => {
  const { doc, pub } = mint({ omitCreatedAt: true });
  // maxAgeSec:0 (falsy) disables the age gate entirely — undated is fine then.
  const v = verifyEmiliaReceipt(doc, { trustedKeys: [pub], maxAgeSec: 0 });
  assert.equal(v.ok, true, `with age enforcement off, undated verifies; got ${JSON.stringify(v)}`);
});
