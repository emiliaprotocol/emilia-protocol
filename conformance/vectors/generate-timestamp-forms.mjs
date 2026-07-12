// SPDX-License-Identifier: Apache-2.0
// Generator for the cross-language timestamp-profile + required_approvals-type
// conformance vectors. Mints REAL §6.2 Trust Receipts (Class-A WebAuthn signoff +
// Ed25519 log checkpoint + Merkle inclusion) so JS, Python, and Go verify the SAME
// bytes and MUST return identical verdicts on every vector.
//
// Locks two cross-language agreement rules:
//   A) Canonical timestamp profile = RFC 3339 WITH an explicit UTC offset ("Z" or
//      ±hh:mm). No-timezone ("2026-07-01T12:00:00") and date-only ("2026-07-01")
//      forms MUST be rejected identically (fail-closed) on all three ports.
//   B) required_approvals MUST be an integer-typed JSON number. A string ("2")
//      is malformed and MUST be rejected — a single signoff must never satisfy a
//      threshold of 2 because the type was silently coerced away (SoD bypass).
//
// Run: node generate-timestamp-forms.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import {
  buildContexts, collectSignoffs, assembleAuthorizationReceipt,
  policyHash as computePolicyHash, generateEd25519KeyPair,
} from '../../packages/issue/index.js';

const FLAG_UP = 0x01; const FLAG_UV = 0x04;
function newP256() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function classASigner({ approverKeyId, privateKey, signedAt }) {
  return {
    approverKeyId, keyClass: 'A', signedAt,
    signWebAuthn: (digest) => {
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: Buffer.from(digest).toString('base64url'), origin: 'https://test.emilia', crossOrigin: false }), 'utf8');
      const ad = Buffer.concat([crypto.createHash('sha256').update('rp').digest(), Buffer.from([FLAG_UP | FLAG_UV]), Buffer.from([0, 0, 0, 1])]);
      const signed = Buffer.concat([ad, crypto.createHash('sha256').update(cd).digest()]);
      return { authenticator_data: ad.toString('base64url'), client_data_json: cd.toString('base64url'), signature: crypto.sign('sha256', signed, privateKey).toString('base64url') };
    },
  };
}

// Mint a real receipt where issued_at/expires_at (inside the SIGNED context),
// signed_at, committed_at and the key window all carry the given timestamp forms,
// with the given required_approvals value inside the signed context.
async function mint({ issuedAt, expiresAt, committedAt, keyFrom, keyTo, requiredApprovals = 1 }) {
  const action = { action_type: 'payment.release', policy_id: 'pol:test', initiator: 'ep:agent:1', params: { amount: 82000, currency: 'USD' } };
  const kp = newP256(); const logKp = generateEd25519KeyPair();
  const contexts = buildContexts({ action, policyHash: computePolicyHash({ policy_id: action.policy_id }), approvers: ['ep:approver:dir'], requiredApprovals, issuedAt, expiresAt });
  const signoffs = await collectSignoffs(contexts, [classASigner({ approverKeyId: 'ep:key:dir#1', signedAt: issuedAt, privateKey: kp.privateKey })]);
  const receipt = assembleAuthorizationReceipt({ receiptId: `ep:receipt:${crypto.randomBytes(8).toString('base64url')}`, action, contexts, signoffs, committedAt, log: { privateKey: logKp.privateKey, logKeyId: 'ep:log:test#1' } });
  const verification = { approver_keys: { 'ep:key:dir#1': { approver_id: 'ep:approver:dir', public_key: kp.publicKeyB64u, key_class: 'A', valid_from: keyFrom, valid_to: keyTo } }, log_public_key: logKp.publicKeyB64u };
  return { receipt, verification };
}

const V = [];
const add = (id, expectValid, reason, tr, verification) => V.push({ id, expect: { valid: expectValid }, reason, trust_receipt: tr, verification });

// ── A: timestamp profile ──────────────────────────────────────────────────────
// A0 canonical "Z" — MUST accept (the profile all three parse identically).
{
  const m = await mint({ issuedAt: '2026-06-13T11:00:00.000Z', expiresAt: '2026-06-13T18:00:00.000Z', committedAt: '2026-06-13T11:30:00.000Z', keyFrom: '2026-01-01T00:00:00Z', keyTo: '2036-01-01T00:00:00Z' });
  add('accept_canonical_z', true, 'RFC3339 with Z offset — the canonical profile; accepted on all three ports', m.receipt, m.verification);
}
// A1 explicit +hh:mm offset — MUST accept (RFC3339 with a numeric offset).
{
  const m = await mint({ issuedAt: '2026-06-13T13:00:00.000+02:00', expiresAt: '2026-06-13T20:00:00.000+02:00', committedAt: '2026-06-13T13:30:00.000+02:00', keyFrom: '2026-01-01T00:00:00Z', keyTo: '2036-01-01T00:00:00Z' });
  add('accept_numeric_offset', true, 'RFC3339 with +02:00 offset — accepted on all three ports', m.receipt, m.verification);
}
// A2 NO timezone — MUST reject on all three (ambiguous UTC-vs-local; fail-closed).
{
  const m = await mint({ issuedAt: '2026-07-01T12:00:00', expiresAt: '2026-07-01T20:00:00', committedAt: '2026-07-01T12:30:00', keyFrom: '2026-01-01T00:00:00', keyTo: '2036-01-01T00:00:00' });
  add('reject_no_timezone', false, 'no-timezone form "2026-07-01T12:00:00" is ambiguous; rejected identically (fail-closed)', m.receipt, m.verification);
}
// A3 date-only — MUST reject on all three.
{
  const m = await mint({ issuedAt: '2026-07-01', expiresAt: '2026-07-02', committedAt: '2026-07-01', keyFrom: '2026-01-01', keyTo: '2036-01-01' });
  add('reject_date_only', false, 'date-only form "2026-07-01" carries no time/zone; rejected identically (fail-closed)', m.receipt, m.verification);
}
// A4 syntactically shaped but impossible calendar date — MUST reject. Native
// JavaScript Date.parse normalizes February 30 into March, so this vector pins
// the calendar-validity check rather than accepting a different instant.
{
  const m = await mint({ issuedAt: '2026-02-30T11:00:00.000Z', expiresAt: '2026-03-03T18:00:00.000Z', committedAt: '2026-02-30T11:30:00.000Z', keyFrom: '2026-01-01T00:00:00Z', keyTo: '2036-01-01T00:00:00Z' });
  add('reject_impossible_calendar_date', false, 'February 30 is not an RFC3339 instant and must not be normalized to March', m.receipt, m.verification);
}

// ── B: required_approvals type ──────────────────────────────────────────────────
// B1 string "2" with a single signoff — MUST reject on all three (SoD bypass guard).
{
  const m = await mint({ issuedAt: '2026-06-13T11:00:00.000Z', expiresAt: '2026-06-13T18:00:00.000Z', committedAt: '2026-06-13T11:30:00.000Z', keyFrom: '2026-01-01T00:00:00Z', keyTo: '2036-01-01T00:00:00Z', requiredApprovals: '2' });
  add('reject_required_approvals_string', false, 'required_approvals:"2" (string) with 1 signoff — malformed threshold; must NOT be silently coerced (SoD bypass)', m.receipt, m.verification);
}
// B2 integer 1 with a single signoff — MUST accept (canonical typed threshold met).
{
  const m = await mint({ issuedAt: '2026-06-13T11:00:00.000Z', expiresAt: '2026-06-13T18:00:00.000Z', committedAt: '2026-06-13T11:30:00.000Z', keyFrom: '2026-01-01T00:00:00Z', keyTo: '2036-01-01T00:00:00Z', requiredApprovals: 1 });
  add('accept_required_approvals_int', true, 'required_approvals:1 (integer) satisfied by 1 signoff — canonical typed threshold', m.receipt, m.verification);
}

const suite = {
  suite: 'EP-TRUST-RECEIPT-v1 timestamp profile + required_approvals type (§6.2/§6.3)',
  profile: 'Cross-language agreement lock: canonical timestamp = RFC3339 with explicit offset (Z or ±hh:mm); required_approvals MUST be an integer-typed number. JS, Python, and Go verifiers MUST return expect.valid on every vector (fail-closed on non-conforming forms).',
  vectors_version: '1.0.0',
  count: V.length,
  vectors: V,
};
// v1 is frozen by the externally attested 16-suite/164-vector clean-room
// bundle. New cases go to v2 so advancing the live corpus never rewrites the
// bytes an external implementation actually evaluated.
writeFileSync(new URL('./trust-receipt.timestamp-forms.v2.json', import.meta.url), JSON.stringify(suite, null, 2) + '\n');
console.log(`wrote trust-receipt.timestamp-forms.v2.json — ${V.length} vectors`);
