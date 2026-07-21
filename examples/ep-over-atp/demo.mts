#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EP-receipt-over-ATP — composition demo for the IETF 126 hackathon.
 *
 * Two layers, two independent signatures, no single point of trust:
 *
 *   ATP (draft-li-atp)  — proves WHICH agent/domain sent a signed message.
 *                         The domain signs the message envelope with its ATK
 *                         key (Ed25519, published in DNS). The payload is
 *                         OPAQUE to ATP by design.
 *   EMILIA Protocol     — proves WHICH human authorized the exact action. The
 *   (EP-RECEIPT-v1)       approver signs the canonical action on their own key.
 *                         This receipt is carried AS the ATP payload.
 *
 * Both sides already share primitives: Ed25519 + RFC 8785 (JCS) canonical JSON,
 * so the bytes are interoperable. This file is self-contained (node:crypto only)
 * so either team can run it: `node demo.mjs`.
 */
import crypto from 'node:crypto';

// ── RFC 8785 (JCS) canonical JSON — the shared canonicalization both specs use ──
function jcs(v: any): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`;
}
const ed25519 = (): any => crypto.generateKeyPairSync('ed25519');
const sign = (priv: any, obj: any): string => crypto.sign(null, Buffer.from(jcs(obj), 'utf8'), priv).toString('base64url');
const verify = (pub: any, obj: any, sigB64u: string): boolean => crypto.verify(null, Buffer.from(jcs(obj), 'utf8'), pub, Buffer.from(sigB64u, 'base64url'));

// ── Keys: a human approver (EP) and a sending domain (ATP ATK, in DNS) ──────────
const approver = ed25519();       // CFO's device-bound key (EP human signoff)
const atkDomain = ed25519();      // acme.example's ATK key (ATP domain identity)

// ── 1. EP: a named human authorizes the exact irreversible action ───────────────
const action = {
  action_type: 'payment.release',
  amount_usd: 40000,
  currency: 'USD',
  payment_instruction_id: 'pi_42',
  beneficiary_account_hash: 'sha256:7c9e...beef',
};
const epPayload = {
  receipt_id: 'rcpt_demo_1',
  subject: 'agent:treasury-bot',
  issuer: 'ep:org:acme',
  approver: 'ep:approver:cfo',
  created_at: '2026-06-29T12:00:00Z',
  claim: { ...action, outcome: 'allow_with_signoff' },
};
const epReceipt = {
  '@version': 'EP-RECEIPT-v1',
  payload: epPayload,
  signature: { algorithm: 'Ed25519', value: sign(approver.privateKey, epPayload) },
};

// ── 2. ATP: the sending domain wraps the EP receipt as an OPAQUE payload ─────────
const atpMessage = {
  atp_version: 'ATP/0.2',
  from: 'treasury-bot@acme.example',
  to: 'ledger@bank.example',
  sent_at: '2026-06-29T12:00:01Z',
  content_type: 'application/ep-receipt+json',
  payload: epReceipt, // opaque to ATP — it just transports it
};
const atpEnvelopeSig = sign(atkDomain.privateKey, atpMessage); // domain signs the envelope

// ── 3. Receiver verifies BOTH halves INDEPENDENTLY ──────────────────────────────
const atpOk = verify(atkDomain.publicKey, atpMessage, atpEnvelopeSig);
const epOk = verify(approver.publicKey, atpMessage.payload.payload, atpMessage.payload.signature.value);
// The join: the action the executor is about to run must equal the authorized claim.
const executing = { ...action, outcome: 'allow_with_signoff' };
const boundOk = jcs(executing) === jcs(atpMessage.payload.payload.claim);

const G = (s) => `\x1b[32m${s}\x1b[0m`;
const R = (s) => `\x1b[31m${s}\x1b[0m`;
const line = (s = '') => console.log(s);
line('='.repeat(70));
line('  EP-receipt-over-ATP — composition demo');
line('='.repeat(70));
line(`  ATP envelope signature (which agent/domain sent it)   -> ${atpOk ? G('VALID') : R('INVALID')}`);
line(`  EP receipt signature   (which human authorized it)    -> ${epOk ? G('VALID') : R('INVALID')}`);
line(`  action binding         (executed == authorized)       -> ${boundOk ? G('MATCH') : R('DRIFT')}`);
line('  ' + '-'.repeat(66));
line(`  Result: ${atpOk && epOk && boundOk ? G('ACCEPT — agent identity + human authorization both proven') : R('REJECT')}`);

// ── 4. Tamper checks: each layer fails closed independently ─────────────────────
const tamperedPayload = JSON.parse(JSON.stringify(atpMessage));
tamperedPayload.payload.payload.claim.amount_usd = 9_999_999; // attacker inflates the amount post-signing
const epAfterTamper = verify(approver.publicKey, tamperedPayload.payload.payload, tamperedPayload.payload.signature.value);

const reroute = JSON.parse(JSON.stringify(atpMessage));
reroute.to = 'attacker@evil.example'; // attacker reroutes the message envelope
const atpAfterReroute = verify(atkDomain.publicKey, reroute, atpEnvelopeSig);

line('');
line(`  tamper: inflate amount inside the EP receipt  -> EP verify ${epAfterTamper ? R('PASS (bad!)') : G('FAILS (correct)')}`);
line(`  tamper: reroute the ATP envelope              -> ATP verify ${atpAfterReroute ? R('PASS (bad!)') : G('FAILS (correct)')}`);
line('  ' + '-'.repeat(66));
line('  Neither layer trusts the other; both bind their own bytes. That is the join.');
line('='.repeat(70));

process.exit(atpOk && epOk && boundOk && !epAfterTamper && !atpAfterReroute ? 0 : 1);
