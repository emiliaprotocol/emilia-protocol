// SPDX-License-Identifier: Apache-2.0
//
// Self-test for the WIMSE PEP obligation. Asserts the four decisions the demo
// prints, plus the fail-closed misconfiguration cases. Exits non-zero on any
// mismatch. Everything runs in memory; no key material touches disk.
//
//   node examples/wimse-pep/self-test.mjs

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { enforceHumanAuthorizationObligation } from './pep-obligation.mjs';

const canon = (v) => (v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

function mintReceipt({ issuerKey, action, createdAtMs, receiptId }) {
  const payload = {
    receipt_id: receiptId,
    subject: 'spiffe://example.org/ns/finance/sa/payments-agent',
    issuer: 'ep:org:wimse-pep-demo',
    created_at: new Date(createdAtMs).toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'ep:approver:duty-officer' },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), issuerKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}
const pubB64u = (kp) => kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

const ACTION = 'payment.release';
const NOW = Date.now();
const trustedIssuer = crypto.generateKeyPairSync('ed25519');
const rogueIssuer = crypto.generateKeyPairSync('ed25519');
const pinnedIssuerKeys = [pubB64u(trustedIssuer)];
const call = (presentedReceipt, extra = {}) => enforceHumanAuthorizationObligation({ action: ACTION, presentedReceipt, pinnedIssuerKeys, now: NOW, ...extra });

let passed = 0;
const ok = (name) => { passed++; process.stdout.write(`  ok ${passed}: ${name}\n`); };

// (a) valid workload identity + valid receipt -> ALLOW
const a = call(mintReceipt({ issuerKey: trustedIssuer.privateKey, action: ACTION, createdAtMs: NOW, receiptId: 'r_a' }));
assert.equal(a.allow, true);
assert.equal(a.reason, 'authorized');
assert.equal(a.receipt_id, 'r_a');
ok('(a) valid workload identity WITH a valid human-authorization receipt -> ALLOW');

// (b) no receipt -> DENY missing_receipt (delegation alone is not sufficient)
const b = call(null);
assert.equal(b.allow, false);
assert.equal(b.reason, 'missing_receipt');
ok('(b) valid workload identity, NO receipt -> DENY (missing_receipt)');

// (c) receipt for a different action -> DENY action_mismatch
const c = call(mintReceipt({ issuerKey: trustedIssuer.privateKey, action: 'config.update', createdAtMs: NOW, receiptId: 'r_c' }));
assert.equal(c.allow, false);
assert.equal(c.reason, 'action_mismatch');
ok('(c) receipt bound to a DIFFERENT action -> DENY (action_mismatch)');

// (d1) receipt signed by an unpinned key -> DENY wrong_issuer_key
const d1 = call(mintReceipt({ issuerKey: rogueIssuer.privateKey, action: ACTION, createdAtMs: NOW, receiptId: 'r_d1' }));
assert.equal(d1.allow, false);
assert.equal(d1.reason, 'wrong_issuer_key');
ok('(d1) receipt signed by an UNPINNED issuer key -> DENY (wrong_issuer_key)');

// (d2) expired receipt from the pinned issuer -> DENY expired
const d2 = call(mintReceipt({ issuerKey: trustedIssuer.privateKey, action: ACTION, createdAtMs: NOW - 2 * 60 * 60 * 1000, receiptId: 'r_d2' }));
assert.equal(d2.allow, false);
assert.equal(d2.reason, 'expired');
ok('(d2) expired receipt from the pinned issuer -> DENY (expired)');

// Fail-closed: a tampered receipt (claim mutated after signing) -> DENY, not ALLOW.
const tampered = mintReceipt({ issuerKey: trustedIssuer.privateKey, action: ACTION, createdAtMs: NOW, receiptId: 'r_t' });
(tampered.payload.claim as any).amount_usd = 9_999_999; // breaks the Ed25519 signature over canon(payload)
const t = call(tampered);
assert.equal(t.allow, false);
assert.equal(t.reason, 'wrong_issuer_key'); // no pinned key verifies the mutated payload
ok('tampered receipt (payload mutated after signing) -> DENY');

// Fail-closed misconfiguration: no pinned issuer keys -> DENY.
const noKeys = enforceHumanAuthorizationObligation({ action: ACTION, presentedReceipt: null, pinnedIssuerKeys: [], now: NOW });
assert.equal(noKeys.allow, false);
assert.equal(noKeys.reason, 'no_pinned_issuer_keys');
ok('no pinned issuer keys -> DENY (no_pinned_issuer_keys)');

// Fail-closed misconfiguration: no action to bind -> DENY.
const noAction = enforceHumanAuthorizationObligation({ action: '', presentedReceipt: null, pinnedIssuerKeys, now: NOW });
assert.equal(noAction.allow, false);
assert.equal(noAction.reason, 'no_action_specified');
ok('no action specified -> DENY (no_action_specified)');

process.stdout.write(`\nself-test PASS (${passed} checks)\n`);
