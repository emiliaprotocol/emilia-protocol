#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EP-receipt-over-AGTP — composition demo (draft-hood-independent-agtp-09 × EP receipts).
 *
 * draft-hood-agtp-composition-01 defines three profile families; the
 * "external IdP" family is the human-authorization layer. This demo shows
 * EMILIA Protocol (EP) as one concrete realization of that profile:
 *
 *   AGTP (draft-hood-independent-agtp-09)
 *     — proves WHICH agent sent the message, bound to its Owner-ID and
 *       AGTP-CERT (the SSL/TLS CA analogy for agent identity). The payload
 *       is opaque to the transport layer.
 *
 *   EMILIA Protocol (EP-RECEIPT-v1)
 *     — proves WHICH human authorized the exact irreversible action.
 *       Carried as the EP-Receipt claim inside the AGTP external-IdP slot.
 *
 * Both specs share Ed25519 + RFC 8785 (JCS) canonical JSON, so the
 * bytes are interoperable with no glue. Run with: node demo.mjs
 */
import crypto from 'node:crypto';

// ── RFC 8785 (JCS) canonical JSON ────────────────────────────────────────────
function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`;
}
const ed25519 = () => crypto.generateKeyPairSync('ed25519');
const sign = (priv, obj) => crypto.sign(null, Buffer.from(jcs(obj), 'utf8'), priv).toString('base64url');
const verify = (pub, obj, sigB64u) =>
  crypto.verify(null, Buffer.from(jcs(obj), 'utf8'), pub, Buffer.from(sigB64u, 'base64url'));

// ── Keys ─────────────────────────────────────────────────────────────────────
// AGTP: agent identity key (backed by AGTP-CERT from an Agent CA, e.g. DigiCert/Let's Encrypt analog)
const agentIdentityKey = ed25519();   // treasury-agent's AGTP-CERT key
// EP: human approver key (device-bound; the "external IdP" credential)
const approverKey = ed25519();        // CFO's device-bound key (EP human signoff)

// ── 1. EP: human authorizes the exact irreversible action ────────────────────
const action = {
  action_type: 'payment.release',
  amount_usd: 40000,
  currency: 'USD',
  payment_instruction_id: 'pi_42',
  beneficiary_account_hash: 'sha256:7c9e...beef',
};
const epPayload = {
  receipt_id: 'rcpt_demo_agtp_1',
  subject: 'agtp:treasury-agent@acme.example',   // AGTP Owner-ID of the acting agent
  issuer: 'ep:org:acme',
  approver: 'ep:approver:cfo',
  created_at: '2026-06-29T16:00:00Z',
  claim: { ...action, outcome: 'allow_with_signoff' },
};
const epReceipt = {
  '@version': 'EP-RECEIPT-v1',
  payload: epPayload,
  signature: { algorithm: 'Ed25519', value: sign(approverKey.privateKey, epPayload) },
};

// ── 2. AGTP: agent wraps EP receipt as the external-IdP authorization claim ──
// agtp-composition-01 §external-IdP profile: the EP receipt is the
// human-authorization credential; AGTP transports it opaquely.
const agtpMessage = {
  agtp_version: '0.9',
  from: 'agtp:treasury-agent@acme.example',   // Owner-ID (v09 rename from Principal-ID)
  to: 'agtp:ledger@bank.example',
  sent_at: '2026-06-29T16:00:01Z',
  content_type: 'application/ep-receipt+json',
  // external-IdP slot (agtp-composition-01): human-authorization credential
  authorization: {
    profile: 'ep-receipt-v1',
    credential: epReceipt,               // opaque to AGTP transport layer
  },
};
// Agent signs the full message with its AGTP-CERT key (structural enforcement)
const agtpSig = sign(agentIdentityKey.privateKey, agtpMessage);

// ── 3. Receiver verifies BOTH layers independently ───────────────────────────
const agtpOk = verify(agentIdentityKey.publicKey, agtpMessage, agtpSig);
const epOk = verify(
  approverKey.publicKey,
  agtpMessage.authorization.credential.payload,
  agtpMessage.authorization.credential.signature.value,
);
// The join: the action the executor is about to run must equal the authorized claim.
const executing = { ...action, outcome: 'allow_with_signoff' };
const boundOk = jcs(executing) === jcs(agtpMessage.authorization.credential.payload.claim);

const G = (s) => `\x1b[32m${s}\x1b[0m`;
const R = (s) => `\x1b[31m${s}\x1b[0m`;
const line = (s = '') => console.log(s);
line('='.repeat(70));
line('  EP-receipt-over-AGTP — composition demo (agtp-09 × EP receipts)');
line('='.repeat(70));
line(`  AGTP message signature  (which agent/Owner-ID sent it)      -> ${agtpOk ? G('VALID') : R('INVALID')}`);
line(`  EP receipt signature    (which human authorized it)          -> ${epOk ? G('VALID') : R('INVALID')}`);
line(`  action binding          (executed == authorized claim)        -> ${boundOk ? G('MATCH') : R('DRIFT')}`);
line('  ' + '-'.repeat(66));
line(`  Result: ${agtpOk && epOk && boundOk ? G('ACCEPT — agent identity + human authorization both proven') : R('REJECT')}`);

// ── 4. Tamper checks: each layer fails closed independently ──────────────────
// Attacker inflates payment amount inside the EP receipt post-signing
const tamperedAuth = JSON.parse(JSON.stringify(agtpMessage));
tamperedAuth.authorization.credential.payload.claim.amount_usd = 9_999_999;
const epAfterTamper = verify(
  approverKey.publicKey,
  tamperedAuth.authorization.credential.payload,
  tamperedAuth.authorization.credential.signature.value,
);

// Attacker reroutes the AGTP envelope to a different destination
const rerouted = JSON.parse(JSON.stringify(agtpMessage));
rerouted.to = 'agtp:attacker@evil.example';
const agtpAfterReroute = verify(agentIdentityKey.publicKey, rerouted, agtpSig);

line('');
line(`  tamper: inflate amount in EP receipt    -> EP verify ${epAfterTamper ? R('PASS (bad!)') : G('FAILS (correct)')}`);
line(`  tamper: reroute AGTP envelope           -> AGTP verify ${agtpAfterReroute ? R('PASS (bad!)') : G('FAILS (correct)')}`);
line('  ' + '-'.repeat(66));
line('  AGTP proves which agent; EP proves which human. The join binds both to the action.');
line('='.repeat(70));

process.exit(agtpOk && epOk && boundOk && !epAfterTamper && !agtpAfterReroute ? 0 : 1);
