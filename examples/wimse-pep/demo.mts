// SPDX-License-Identifier: Apache-2.0
//
// End-to-end WIMSE PEP scenario.
//
//   node examples/wimse-pep/demo.mjs
//
// A mock workload that WIMSE has ALREADY authenticated (it carries a valid
// workload identity) attempts a high-consequence action. The PEP applies one
// extra obligation via enforceHumanAuthorizationObligation: a per-action human
// authorization receipt. We mint the demo receipt inline with the REAL EP
// signing/canonicalization path (Ed25519 over JCS-canonical JSON, byte-identical
// to @emilia-protocol/require-receipt's verifier), using a throwaway key held
// only in memory. Nothing is written to disk.
//
// Four requests, same authenticated workload identity every time:
//   (a) valid workload identity + valid human-authorization receipt  -> ALLOW
//   (b) valid workload identity, NO receipt                          -> DENY (delegation alone is not sufficient)
//   (c) receipt bound to a DIFFERENT action                          -> DENY (action_mismatch)
//   (d) receipt signed by an UNPINNED key, and an EXPIRED receipt     -> DENY

import crypto from 'node:crypto';
import { enforceHumanAuthorizationObligation } from './pep-obligation.mjs';

// EP JCS canonicalization: the exact recursive sorted-key form the receipt
// signature is computed over (identical to packages/require-receipt/index.js and
// packages/verify/index.js). Signer and verifier MUST agree byte-for-byte.
const canon = (v) => (v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

// Mint a genuine EP-RECEIPT-v1: Ed25519 signature over canon(payload). This is
// the real issuance path, not a toy. `issuerKey` is a Node KeyObject.
function mintReceipt({ issuerKey, action, subject, createdAtMs, receiptId }) {
  const payload = {
    receipt_id: receiptId,
    subject,
    issuer: 'ep:org:wimse-pep-demo',
    created_at: new Date(createdAtMs).toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'ep:approver:duty-officer' },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), issuerKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}

const pubB64u = (kp) => kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

// The consequential action this WIMSE-authenticated workload wants to perform.
const ACTION = 'payment.release';
const SUBJECT = 'spiffe://example.org/ns/finance/sa/payments-agent'; // the workload identity WIMSE authenticated
const NOW = Date.now();

// The issuer the PEP pins, plus an UNPINNED rogue issuer for case (d).
const trustedIssuer = crypto.generateKeyPairSync('ed25519');
const rogueIssuer = crypto.generateKeyPairSync('ed25519');
const pinnedIssuerKeys = [pubB64u(trustedIssuer)];

function decide(label, presentedReceipt) {
  const out = enforceHumanAuthorizationObligation({ action: ACTION, presentedReceipt, pinnedIssuerKeys, now: NOW });
  const verdict = out.allow ? 'ALLOW' : 'DENY ';
  console.log(`  ${verdict}  ${label}`);
  console.log(`         reason: ${out.reason}${out.receipt_id ? `  receipt_id: ${out.receipt_id}` : ''}`);
  return out;
}

console.log('WIMSE PEP + EP per-action human-authorization obligation');
console.log(`  workload identity (authenticated upstream by WIMSE): ${SUBJECT}`);
console.log(`  guarded action: ${ACTION}`);
console.log('');

// (a) valid workload identity + valid, action-bound, in-window receipt -> ALLOW
decide('(a) valid workload identity WITH a valid human-authorization receipt', mintReceipt({
  issuerKey: trustedIssuer.privateKey, action: ACTION, subject: SUBJECT, createdAtMs: NOW, receiptId: 'rcpt_demo_a',
}));

// (b) same authenticated workload identity, NO receipt -> DENY
decide('(b) same valid workload identity but NO receipt (delegation alone)', null);

// (c) a receipt for a DIFFERENT action -> DENY (action_mismatch)
decide('(c) receipt bound to a DIFFERENT action (config.update, not payment.release)', mintReceipt({
  issuerKey: trustedIssuer.privateKey, action: 'config.update', subject: SUBJECT, createdAtMs: NOW, receiptId: 'rcpt_demo_c',
}));

// (d) a receipt signed by an UNPINNED issuer key -> DENY (wrong_issuer_key)
decide('(d1) receipt signed by an UNPINNED issuer key', mintReceipt({
  issuerKey: rogueIssuer.privateKey, action: ACTION, subject: SUBJECT, createdAtMs: NOW, receiptId: 'rcpt_demo_d1',
}));

// (d) an EXPIRED receipt from the pinned issuer -> DENY (expired)
decide('(d2) receipt from the pinned issuer but EXPIRED (created 2h ago, maxAge 15m)', mintReceipt({
  issuerKey: trustedIssuer.privateKey, action: ACTION, subject: SUBJECT, createdAtMs: NOW - 2 * 60 * 60 * 1000, receiptId: 'rcpt_demo_d2',
}));

console.log('');
console.log('Delegation says the agent may act. The receipt says a named human authorized THIS action.');
