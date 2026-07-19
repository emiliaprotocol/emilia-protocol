'use client';
/**
 * /try/multi-party — the two-person rule, shown not told.
 * @license Apache-2.0
 *
 * A high-consequence action ($40M program release) requires an ORDERED quorum of
 * three named humans — Program Officer -> Authorizing Official -> Inspector
 * General. Each "signs" on a simulated secure element (ephemeral Web Crypto
 * P-256, the same path as /try) bound to the EXACT action. The EP-QUORUM-v1
 * verifier runs entirely in your browser (lib/quorum-web.js) — nothing uploaded.
 * A "let one person sign twice" button shows the separation-of-duties rejection.
 */
import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, font, styles } from '@/lib/tokens';
import { verifyQuorum } from '@/lib/quorum-web.js';

// ── minimal crypto helpers (mirror /try) ──────────────────────────────────────
const utf8 = (s) => new TextEncoder().encode(s);
const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
}
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
function rawP256ToDer(raw) {
  const enc = (v) => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; let b = v.subarray(i); if (b[0] & 0x80) { const t = new Uint8Array(b.length + 1); t.set(b, 1); b = t; } return b; };
  const rb = enc(raw.subarray(0, 32)); const sb = enc(raw.subarray(32, 64));
  const seqLen = 2 + rb.length + 2 + sb.length; const out = new Uint8Array(2 + seqLen); let o = 0;
  out[o++] = 0x30; out[o++] = seqLen; out[o++] = 0x02; out[o++] = rb.length; out.set(rb, o); o += rb.length;
  out[o++] = 0x02; out[o++] = sb.length; out.set(sb, o); return out;
}
const HOST = 'emiliaprotocol.ai';
async function signSim(context) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const challengeB64u = b64u(await sha256(utf8(canonicalize(context))));
  const clientDataBytes = utf8(JSON.stringify({ type: 'webauthn.get', challenge: challengeB64u, origin: `https://${HOST}`, crossOrigin: false }));
  const authData = new Uint8Array(37);
  authData.set(await sha256(utf8(HOST)), 0); authData[32] = 0x05; // UP | UV
  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0); signedData.set(await sha256(clientDataBytes), authData.length);
  const rawSig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signedData));
  return {
    approver_public_key: b64u(spki),
    signoff: { '@type': 'ep.signoff', context, webauthn: { authenticator_data: b64u(authData), client_data_json: b64u(clientDataBytes), signature: b64u(rawP256ToDer(rawSig)) } },
  };
}

// ── the scenario ──────────────────────────────────────────────────────────────
const ROSTER = [
  { role: 'program_officer', approver: 'ep:approver:po_rivera', label: 'Program Officer', who: 'M. Rivera' },
  { role: 'authorizing_official', approver: 'ep:approver:ao_chen', label: 'Authorizing Official', who: 'J. Chen' },
  { role: 'inspector_general', approver: 'ep:approver:ig_okafor', label: 'Inspector General', who: 'A. Okafor' },
];
const ACTION_FIELDS = { action: 'program_funds.release', amount: '40000000.00', currency: 'USD', program: 'program/aegis-1', memo: 'FY26 milestone disbursement' };

export default function MultiPartyDemo() {
  const [actionHash, setActionHash] = useState(null);
  const [members, setMembers] = useState([]); // signed, in order
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [cheated, setCheated] = useState(false);

  async function ensureHash() {
    if (actionHash) return actionHash;
    const h = Array.from(await sha256(utf8(canonicalize(ACTION_FIELDS))), (x) => x.toString(16).padStart(2, '0')).join('');
    setActionHash(h); return h;
  }
  const mkContext = (slot, h, idx) => ({
    action_hash: h, policy: 'policy_aegis_quorum', role: slot.role, approver: slot.approver,
    initiator: 'agent:program-ops/v2', nonce: b64u(crypto.getRandomValues(new Uint8Array(16))),
    issued_at: new Date(Date.now() + idx * 60000).toISOString(),
  });
  const buildQuorum = (mem, h) => ({
    '@type': 'ep.quorum', action_hash: h,
    policy: { mode: 'ordered', required: 3, approvers: ROSTER.map((r) => ({ role: r.role, approver: r.approver })), distinct_humans: true, window_sec: 900 },
    members: mem,
  });

  async function signNext() {
    setBusy(true);
    try {
      const h = await ensureHash();
      const idx = members.length;
      const slot = ROSTER[idx];
      const m = await signSim(mkContext(slot, h, idx));
      const next = [...members, { ...m, role: slot.role }];
      setMembers(next); setResult(null); setCheated(false);
      if (next.length === ROSTER.length) {
        setResult(await verifyQuorum(buildQuorum(next, h), {
          rpId: HOST,
          allowedOrigins: [`https://${HOST}`],
        }));
      }
    } finally { setBusy(false); }
  }

  // The cheat: the Program Officer (already signed) also signs the IG slot.
  async function cheatDuplicate() {
    setBusy(true);
    try {
      const h = await ensureHash();
      const po = ROSTER[0];
      const m0 = await signSim(mkContext(po, h, 0));
      const m1 = await signSim(mkContext(ROSTER[1], h, 1));
      // IG slot signed by the SAME human as the Program Officer:
      const m2 = await signSim({ ...mkContext(ROSTER[2], h, 2), approver: po.approver });
      const mem = [{ ...m0, role: po.role }, { ...m1, role: ROSTER[1].role }, { ...m2, role: ROSTER[2].role }];
      setMembers(mem); setCheated(true);
      setResult(await verifyQuorum(buildQuorum(mem, h), {
        rpId: HOST,
        allowedOrigins: [`https://${HOST}`],
      }));
    } finally { setBusy(false); }
  }

  function reset() { setMembers([]); setResult(null); setCheated(false); }

  const allSigned = members.length === ROSTER.length;
  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ maxWidth: 880, margin: '0 auto', padding: '56px 24px 96px' }}>
        <div style={styles.eyebrow}>EP-QUORUM-v1 · the two-person rule</div>
        <h1 style={{ ...styles.h1, maxWidth: 760 }}>Some actions need more than one human.</h1>
        <p style={{ ...styles.body, maxWidth: 720 }}>
          A <strong>$40,000,000</strong> program release. Policy requires an <strong>ordered quorum</strong> — Program Officer, then Authorizing Official, then Inspector General — each approving the <em>exact</em> action on their own device, all within the window. No quorum, no release. Everything below runs in your browser; nothing is uploaded.
        </p>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', margin: '28px 0' }}>
          {ROSTER.map((r, i) => {
            const signed = i < members.length && !cheated;
            const isNext = i === members.length && !allSigned && !cheated;
            return (
              <div key={r.role} style={{
                flex: '1 1 240px', border: `1px solid ${signed ? color.green : isNext ? color.blue : color.border}`,
                borderRadius: 10, padding: '16px 18px', background: color.card,
              }}>
                <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1.5, textTransform: 'uppercase', color: signed ? color.green : color.t3 }}>
                  {i + 1} · {signed ? 'signed ✓' : isNext ? 'next' : 'waiting'}
                </div>
                <div style={{ fontSize: 17, fontWeight: 600, color: color.t1, marginTop: 6 }}>{r.label}</div>
                <div style={{ fontSize: 13, color: color.t2 }}>{r.who}</div>
              </div>
            );
          })}
        </div>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          {!allSigned && !cheated && (
            <button onClick={signNext} disabled={busy} style={btn(color.blue)}>
              {busy ? 'Signing…' : `Sign as ${ROSTER[members.length].label} (Face ID)`}
            </button>
          )}
          <button onClick={cheatDuplicate} disabled={busy} style={btn(color.t2, true)}>Try to cheat: one person signs twice</button>
          {(members.length > 0) && <button onClick={reset} disabled={busy} style={btn(color.t3, true)}>Reset</button>}
        </div>

        {result && (
          <div style={{
            marginTop: 30, border: `1px solid ${result.valid ? color.green : color.red}`,
            borderRadius: 12, padding: '22px 24px', background: color.card,
          }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: result.valid ? color.green : color.red }}>
              {result.valid ? '✓ QUORUM INTERNALLY CONSISTENT' : '✕ QUORUM REJECTED'}
            </div>
            {cheated && !result.valid && (
              <p style={{ ...styles.body, marginTop: 8 }}>The same human filled two slots. <strong>Separation of duties</strong> fails the quorum — exactly as the two-person rule requires.</p>
            )}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 24px', marginTop: 16 }}>
              {Object.entries(result.checks).map(([k, v]) => (
                <div key={k} style={{ fontFamily: font.mono, fontSize: 13, color: v ? color.green : color.red }}>
                  {v ? '✓' : '✕'} {k}
                </div>
              ))}
            </div>
            <p style={{ fontSize: 13, color: color.t3, marginTop: 16, lineHeight: 1.6 }}>
              Verified in-browser by the EP-QUORUM-v1 verifier, using the same logic as <span style={{ fontFamily: font.mono }}>@emilia-protocol/verify</span>. Each signature is a real ECDSA P-256 assertion bound to the exact action; tamper any field, duplicate a signer, break the order, or miss the window and the quorum fails. This local simulation proves internal consistency, not enrollment or organizational authority; a relying party must pin the roster, policy, and member keys separately.
            </p>
          </div>
        )}

        <p style={{ fontSize: 13, color: color.t3, marginTop: 36, lineHeight: 1.7, maxWidth: 720 }}>
          Roles are illustrative chain-of-command, not real individuals. This is a simulated secure element for demonstration; in production each approver signs on their own enrolled device (Face ID · Touch ID · passkey).
        </p>
      </main>
      <SiteFooter />
    </div>
  );
}

function btn(c, ghost) {
  return {
    fontFamily: font.mono, fontSize: 13, letterSpacing: 1, textTransform: 'uppercase',
    padding: '12px 20px', borderRadius: 8, cursor: 'pointer',
    background: ghost ? 'transparent' : c, color: ghost ? c : '#fff',
    border: `1px solid ${c}`, fontWeight: 600,
  };
}
