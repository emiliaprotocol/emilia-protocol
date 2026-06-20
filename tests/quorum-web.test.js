// SPDX-License-Identifier: Apache-2.0
//
// Tests for lib/quorum-web.js — the in-browser (Web Crypto) EP-QUORUM-v1
// verifier used by /try/multi-party. Mints real ECDSA P-256 assertions with
// Web Crypto (available in the Node/vitest runtime) and asserts the same
// fail-closed behavior as packages/verify/quorum.js: a happy ordered quorum
// authorizes; each adversarial mutation drives the whole quorum invalid.
import { describe, it, expect } from 'vitest';
import { verifyQuorum } from '../lib/quorum-web.js';

const HOST = 'emiliaprotocol.ai';
const utf8 = (s) => new TextEncoder().encode(s);
const b64u = (b) => Buffer.from(b).toString('base64url');
const canon = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
function rawToDer(raw) {
  const enc = (v) => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; let b = v.subarray(i); if (b[0] & 0x80) { const t = new Uint8Array(b.length + 1); t.set(b, 1); b = t; } return b; };
  const rb = enc(raw.subarray(0, 32)); const sb = enc(raw.subarray(32, 64));
  const L = 2 + rb.length + 2 + sb.length; const o = new Uint8Array(2 + L); let p = 0;
  o[p++] = 0x30; o[p++] = L; o[p++] = 0x02; o[p++] = rb.length; o.set(rb, p); p += rb.length;
  o[p++] = 0x02; o[p++] = sb.length; o.set(sb, p); return o;
}
async function signSim(context, { wrongKey = false } = {}) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const verKey = wrongKey ? (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey : pair.publicKey;
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', verKey));
  const ch = b64u(await sha(utf8(canon(context))));
  const cd = utf8(JSON.stringify({ type: 'webauthn.get', challenge: ch, origin: `https://${HOST}`, crossOrigin: false }));
  const ad = new Uint8Array(37); ad.set(await sha(utf8(HOST)), 0); ad[32] = 0x05;
  const signed = new Uint8Array(ad.length + 32); signed.set(ad, 0); signed.set(await sha(cd), ad.length);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed));
  return { approver_public_key: b64u(spki), signoff: { '@type': 'ep.signoff', context, webauthn: { authenticator_data: b64u(ad), client_data_json: b64u(cd), signature: b64u(rawToDer(sig)) } } };
}

const ROSTER = [
  { role: 'program_officer', approver: 'ep:po' },
  { role: 'authorizing_official', approver: 'ep:ao' },
  { role: 'inspector_general', approver: 'ep:ig' },
];
let ACTION;
const ctx = (slot, i, appr, ah) => ({ action_hash: ah ?? ACTION, policy: 'p', role: slot.role, approver: appr ?? slot.approver, nonce: b64u(crypto.getRandomValues(new Uint8Array(16))), issued_at: new Date(Date.UTC(2026, 5, 11, 0, i) ).toISOString() });
const ordered = () => ({ mode: 'ordered', required: 3, approvers: ROSTER.map((r) => ({ role: r.role, approver: r.approver })), distinct_humans: true, window_sec: 900 });
const quorum = (members, policy) => ({ '@type': 'ep.quorum', action_hash: ACTION, policy: policy ?? ordered(), members });
const member = async (i, opts, appr, ah) => ({ ...await signSim(ctx(ROSTER[i], i, appr, ah), opts), role: ROSTER[i].role });

describe('lib/quorum-web.js — EP-QUORUM-v1 (Web Crypto)', () => {
  it('authorizes a genuine ordered 3-of-3 quorum (every check passes)', async () => {
    ACTION = Array.from(await sha(utf8(canon({ a: 'release', amt: 40000000 }))), (x) => x.toString(16).padStart(2, '0')).join('');
    const m = [await member(0), await member(1), await member(2)];
    const r = await verifyQuorum(quorum(m), { rpId: HOST });
    expect(r.valid).toBe(true);
    for (const v of Object.values(r.checks)) expect(v).toBe(true);
  });

  it('authorizes a threshold 2-of-3 quorum', async () => {
    const pol = { mode: 'threshold', required: 2, approvers: ROSTER.map((r) => ({ role: r.role, approver: r.approver })), distinct_humans: true, window_sec: 900 };
    const m = [await member(0), await member(2)];
    expect((await verifyQuorum(quorum(m, pol), { rpId: HOST })).valid).toBe(true);
  });

  it('rejects: under threshold', async () => {
    const r = await verifyQuorum(quorum([await member(0), await member(1)]), { rpId: HOST });
    expect(r.valid).toBe(false); expect(r.checks.threshold_met).toBe(false);
  });

  it('rejects: same human in two slots (separation of duties)', async () => {
    const m = [await member(0), await member(1), await member(2, {}, 'ep:po')];
    const r = await verifyQuorum(quorum(m), { rpId: HOST });
    expect(r.valid).toBe(false); expect(r.checks.distinct_humans).toBe(false);
  });

  it('rejects: a member signed a different action', async () => {
    const m = [await member(0), await member(1), await member(2, {}, undefined, 'f'.repeat(64))];
    const r = await verifyQuorum(quorum(m), { rpId: HOST });
    expect(r.valid).toBe(false); expect(r.checks.action_binding).toBe(false);
  });

  it('rejects: one bad signature', async () => {
    const m = [await member(0), await member(1, { wrongKey: true }), await member(2)];
    const r = await verifyQuorum(quorum(m), { rpId: HOST });
    expect(r.valid).toBe(false); expect(r.checks.all_signatures_valid).toBe(false);
  });

  it('rejects: an ineligible role/approver', async () => {
    const pol = { mode: 'threshold', required: 2, approvers: ROSTER.map((r) => ({ role: r.role, approver: r.approver })), distinct_humans: true, window_sec: 900 };
    const intruder = { ...await signSim(ctx({ role: 'intern' }, 1, 'ep:nobody')), role: 'intern' };
    const r = await verifyQuorum(quorum([await member(0), intruder], pol), { rpId: HOST });
    expect(r.valid).toBe(false); expect(r.checks.roles_admitted).toBe(false);
  });

  it('fails closed on malformed input without throwing', async () => {
    for (const bad of [null, {}, { policy: {}, members: [] }]) {
      expect((await verifyQuorum(bad, { rpId: HOST })).valid).toBe(false);
    }
  });
});
