// SPDX-License-Identifier: Apache-2.0
//
// Tests for lib/signoff/quorum-session.js — the multi-party signoff
// orchestration brain. Mints real ECDSA P-256 attestations (Web Crypto) and
// asserts incremental enforcement: canAccept() admits a valid next signer and
// rejects each adversarial case (wrong action, ineligible role, duplicate
// human, out-of-order, window, bad signature); evaluateTrail() satisfies a
// genuine ordered trail and never satisfies a tampered one.
import { describe, it, expect } from 'vitest';
import { canAccept, quorumGate, evaluateTrail } from '../lib/signoff/quorum-session.js';

const HOST = 'emiliaprotocol.ai';
const utf8 = (s) => new TextEncoder().encode(s);
const b64u = (b) => Buffer.from(b).toString('base64url');
const canon = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
function rawToDer(raw) {
  const e = (v) => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; let b = v.subarray(i); if (b[0] & 0x80) { const t = new Uint8Array(b.length + 1); t.set(b, 1); b = t; } return b; };
  const r = e(raw.subarray(0, 32)); const s = e(raw.subarray(32, 64)); const L = 2 + r.length + 2 + s.length;
  const o = new Uint8Array(2 + L); let p = 0; o[p++] = 0x30; o[p++] = L; o[p++] = 2; o[p++] = r.length; o.set(r, p); p += r.length; o[p++] = 2; o[p++] = s.length; o.set(s, p); return o;
}
async function mkMember(role, approver, i, { actionHash, wrongKey } = {}) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const ver = wrongKey ? (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey : pair.publicKey;
  const ctx = { action_hash: actionHash ?? ACTION, policy: 'p', role, approver, initiator: 'ent_agent_7', nonce: b64u(crypto.getRandomValues(new Uint8Array(16))), issued_at: new Date(Date.UTC(2026, 5, 11, 0, i)).toISOString() };
  const ch = b64u(await sha(utf8(canon(ctx))));
  const cd = utf8(JSON.stringify({ type: 'webauthn.get', challenge: ch, origin: `https://${HOST}`, crossOrigin: false }));
  const ad = new Uint8Array(37); ad.set(await sha(utf8(HOST)), 0); ad[32] = 0x05;
  const signed = new Uint8Array(ad.length + 32); signed.set(ad, 0); signed.set(await sha(cd), ad.length);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed));
  return { role, approver_public_key: b64u(new Uint8Array(await crypto.subtle.exportKey('spki', ver))), signoff: { '@type': 'ep.signoff', context: ctx, webauthn: { authenticator_data: b64u(ad), client_data_json: b64u(cd), signature: b64u(rawToDer(sig)) } } };
}

const PO = ['program_officer', 'ep:po'], AO = ['authorizing_official', 'ep:ao'], IG = ['inspector_general', 'ep:ig'];
const POLICY = { mode: 'ordered', required: 3, approvers: [PO, AO, IG].map(([role, approver]) => ({ role, approver })), distinct_humans: true, window_sec: 900 };
let ACTION;
const OPTS = { rpId: HOST, allowedOrigins: [`https://${HOST}`] };

describe('lib/signoff/quorum-session.js — trail-of-signatories enforcement', () => {
  it('accepts a valid ordered trail and gates satisfied', async () => {
    ACTION = Array.from(await sha(utf8(canon({ a: 'release' }))), (x) => x.toString(16).padStart(2, '0')).join('');
    const m0 = await mkMember(...PO, 1), m1 = await mkMember(...AO, 2), m2 = await mkMember(...IG, 3);
    expect(canAccept(POLICY, ACTION, [], m0, OPTS).ok).toBe(true);
    expect(canAccept(POLICY, ACTION, [m0], m1, OPTS).ok).toBe(true);
    expect(canAccept(POLICY, ACTION, [m0, m1], m2, OPTS).ok).toBe(true);
    expect(quorumGate(POLICY, ACTION, [m0, m1, m2], OPTS).satisfied).toBe(true);
  });

  // Threshold roster (any M-of-N) — where the same valid human resubmitting is
  // the duplicate-human case (in an ordered 1:1 roster that's caught earlier as
  // ineligible_role, since a human is only ever eligible for their own slot).
  const TPOL = { mode: 'threshold', required: 2, approvers: [PO, AO, IG].map(([role, approver]) => ({ role, approver })), distinct_humans: true, window_sec: 900 };

  it('rejects a duplicate human at attest time (threshold)', async () => {
    const m0 = await mkMember(...PO, 1);
    const again = await mkMember(...PO, 2); // same valid approver, second time
    expect(canAccept(TPOL, ACTION, [m0], again, OPTS)).toMatchObject({ ok: false, reason: 'duplicate_human' });
  });

  it('rejects a same-human-wrong-slot as ineligible (ordered 1:1 roster)', async () => {
    const m0 = await mkMember(...PO, 1);
    const wrong = await mkMember('inspector_general', 'ep:po', 2); // PO claiming IG slot
    expect(canAccept(POLICY, ACTION, [m0], wrong, OPTS)).toMatchObject({ ok: false, reason: 'ineligible_role' });
  });

  it('rejects an out-of-order signer (ordered mode)', async () => {
    const m0 = await mkMember(...PO, 1);
    const ig = await mkMember(...IG, 2); // IG before AO
    expect(canAccept(POLICY, ACTION, [m0], ig, OPTS)).toMatchObject({ ok: false, reason: 'out_of_order' });
  });

  it('rejects an ineligible role', async () => {
    const x = await mkMember('intern', 'ep:nobody', 1);
    expect(canAccept(POLICY, ACTION, [], x, OPTS)).toMatchObject({ ok: false, reason: 'ineligible_role' });
  });

  it('rejects a different action', async () => {
    const x = await mkMember(...PO, 1, { actionHash: 'f'.repeat(64) });
    expect(canAccept(POLICY, ACTION, [], x, OPTS)).toMatchObject({ ok: false, reason: 'action_mismatch' });
  });

  it('rejects a stale signature outside the window', async () => {
    const m0 = await mkMember(...PO, 0);
    const late = await mkMember(...AO, 30); // 30 min later, window 900s
    expect(canAccept(POLICY, ACTION, [m0], late, OPTS)).toMatchObject({ ok: false, reason: 'window_exceeded' });
  });

  it('rejects a bad signature', async () => {
    const bad = await mkMember(...PO, 1, { wrongKey: true });
    expect(canAccept(POLICY, ACTION, [], bad, OPTS)).toMatchObject({ ok: false, reason: 'invalid_signature' });
  });

  it('evaluateTrail folds candidates: keeps valid, rejects bad, gates satisfied', async () => {
    const m0 = await mkMember(...PO, 1), m1 = await mkMember(...AO, 2), m2 = await mkMember(...IG, 3);
    const dup = await mkMember(...PO, 4); // same valid approver again → duplicate_human (threshold)
    const r = evaluateTrail(TPOL, ACTION, [m0, m1, dup, m2], OPTS);
    expect(r.accepted.length).toBe(3);
    expect(r.rejected).toEqual([{ approver: 'ep:po', role: 'program_officer', reason: 'duplicate_human' }]);
    expect(r.satisfied).toBe(true);
  });

  it('fails closed on malformed input', () => {
    expect(canAccept(null, ACTION, [], {}, OPTS).ok).toBe(false);
    expect(quorumGate(POLICY, ACTION, [], OPTS).satisfied).toBe(false);
  });
});
