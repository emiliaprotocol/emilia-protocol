// SPDX-License-Identifier: Apache-2.0
//
// Tests for lib/signoff/attestation-members.js — the bridge that reconstitutes
// EP-QUORUM-v1 members from stored Class-A signoff evidence. Proves the bridge
// is faithful by round-tripping: mint a real ECDSA P-256 signoff, reduce it to
// the shape the approve route stores (context + assertion + approver key), map
// it back via attestationsToMembers, and confirm quorumGate ACCEPTS the result
// — i.e. the gate verifies exactly what was stored, through the real verifier.
import { describe, it, expect } from 'vitest';
import { attestationsToMembers, decisionToMember, decisionsToMembers } from '../lib/signoff/attestation-members.js';
import { quorumGate } from '../lib/signoff/quorum-session.js';

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
// Mint a stored-decision record exactly as the approve route persists it.
async function mkDecision(role, approver, i, action) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const context = { action_hash: action, policy: 'p', role, approver, nonce: b64u(crypto.getRandomValues(new Uint8Array(16))), issued_at: new Date(Date.UTC(2026, 5, 11, 0, i)).toISOString() };
  const ch = b64u(await sha(utf8(canon(context))));
  const cd = utf8(JSON.stringify({ type: 'webauthn.get', challenge: ch, origin: `https://${HOST}`, crossOrigin: false }));
  const ad = new Uint8Array(37); ad.set(await sha(utf8(HOST)), 0); ad[32] = 0x05;
  const signed = new Uint8Array(ad.length + 32); signed.set(ad, 0); signed.set(await sha(cd), ad.length);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed));
  return {
    role,
    approver_public_key: b64u(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))),
    context,                                          // as stored in audit_events.after_state.context
    webauthn: {                                       // as stored in after_state.webauthn
      credential_id: 'cred-' + i,
      authenticator_data: b64u(ad),
      client_data_json: b64u(cd),
      signature: b64u(rawToDer(sig)),
    },
  };
}

const PO = ['program_officer', 'ep:po'], AO = ['authorizing_official', 'ep:ao'], IG = ['inspector_general', 'ep:ig'];
const POLICY = { mode: 'ordered', required: 3, approvers: [PO, AO, IG].map(([role, approver]) => ({ role, approver })), distinct_humans: true, window_sec: 900 };
const OPTS = { rpId: HOST };

describe('lib/signoff/attestation-members.js — stored evidence → verifiable members', () => {
  it('round-trips: stored Class-A decisions map to members quorumGate accepts', async () => {
    const action = Array.from(await sha(utf8(canon({ a: 'release' }))), (x) => x.toString(16).padStart(2, '0')).join('');
    const decisions = [await mkDecision(...PO, 1, action), await mkDecision(...AO, 2, action), await mkDecision(...IG, 3, action)];
    const members = attestationsToMembers(decisions);
    expect(members).toHaveLength(3);
    expect(members[0]).toMatchObject({ role: 'program_officer', signoff: { '@type': 'ep.signoff' } });
    expect(quorumGate(POLICY, action, members, OPTS).satisfied).toBe(true);
  });

  it('drops incomplete records (missing context or assertion) — fail-safe', async () => {
    const action = 'a'.repeat(64);
    const good = await mkDecision(...PO, 1, action);
    const members = attestationsToMembers([good, { role: 'x' }, null, { context: {}, webauthn: null, approver_public_key: 'k' }]);
    expect(members).toHaveLength(1);
  });

  it('decisionToMember carries only the three assertion fields', async () => {
    const d = await mkDecision(...AO, 5, 'b'.repeat(64));
    const m = decisionToMember(d);
    expect(Object.keys(m.signoff.webauthn).sort()).toEqual(['authenticator_data', 'client_data_json', 'signature']);
  });

  // decisionsToMembers joins raw guard.signoff.approved payloads (which carry
  // approver_id + credential_id but NOT role/key) with the policy roster and the
  // approver_credentials key map — the exact join the consume gate performs.
  it('decisionsToMembers joins audit-event payloads + creds → members quorumGate accepts', async () => {
    const action = Array.from(await sha(utf8(canon({ a: 'wire' }))), (x) => x.toString(16).padStart(2, '0')).join('');
    const raw = [await mkDecision(...PO, 1, action), await mkDecision(...AO, 2, action), await mkDecision(...IG, 3, action)];
    // Reshape into the audit-event after_state shape: approver_id + credential_id, key lives in creds.
    const credsByCredentialId = {};
    const decisions = raw.map((d) => {
      credsByCredentialId[d.webauthn.credential_id] = { public_key_spki: d.approver_public_key };
      return { context: d.context, approver_id: d.context.approver, webauthn: d.webauthn };
    });
    const members = decisionsToMembers(POLICY, decisions, credsByCredentialId);
    expect(members).toHaveLength(3);
    expect(quorumGate(POLICY, action, members, OPTS).satisfied).toBe(true);
  });

  it('decisionsToMembers drops a decision whose approver is not on the roster', async () => {
    const action = 'c'.repeat(64);
    const d = await mkDecision('program_officer', 'ep:stranger', 1, action); // not in POLICY roster
    const decisions = [{ context: d.context, approver_id: 'ep:stranger', webauthn: d.webauthn }];
    expect(decisionsToMembers(POLICY, decisions, { [d.webauthn.credential_id]: { public_key_spki: d.approver_public_key } })).toHaveLength(0);
  });
});
