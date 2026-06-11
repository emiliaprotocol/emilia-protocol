'use client';

/**
 * /try — Be the human in the loop. A self-serve Class-A signoff, live.
 * @license Apache-2.0
 *
 * The visceral version of the whole protocol: an AI agent tries to wire
 * $82,000, EMILIA holds it, and YOU approve it on your own device with
 * Face ID / Touch ID. The approval is then verified — every check — entirely
 * in this browser tab with the shipped @emilia-protocol/verify code. Then we
 * tamper one digit of the action and watch the same signature collapse.
 *
 * Design constraints that make this robust enough to demo on a stranger's phone:
 *   - No backend, no account, no database. A real WebAuthn ceremony
 *     (navigator.credentials.create/get) produces a real EP signoff object,
 *     verified by the real verifier. Nothing is uploaded.
 *   - If the device has no platform authenticator (or declines), it falls back
 *     to a "simulated secure element" (an ephemeral Web Crypto P-256 key) that
 *     runs the identical verification path — so the demo never dead-ends, and
 *     it is exercisable in headless CI.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, font, radius } from '@/lib/tokens';
import { verifyWebAuthnSignoff } from '@/lib/verify-web';

// ── primitives (local copies; byte-identical to @emilia-protocol/verify) ──────
const ENC = new TextEncoder();
const utf8 = (s) => ENC.encode(s);

function bytesToB64u(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Recursive canonical JSON — MUST match the verifier's canonicalize() exactly,
// because the challenge the device signs is SHA-256 over these bytes.
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

async function sha256Bytes(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function randHex(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

// Web Crypto signs ECDSA as raw r‖s; a WebAuthn assertion is ASN.1 DER. For the
// simulated path we encode raw → DER so it travels the identical verifier branch
// (which then converts DER → raw again). P-256 components fit in short-form DER.
function rawP256ToDer(raw) {
  const enc = (v) => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    let b = v.subarray(i);
    if (b[0] & 0x80) {
      const t = new Uint8Array(b.length + 1);
      t.set(b, 1);
      b = t;
    }
    return b;
  };
  const rb = enc(raw.subarray(0, 32));
  const sb = enc(raw.subarray(32, 64));
  const seqLen = 2 + rb.length + 2 + sb.length;
  const out = new Uint8Array(2 + seqLen);
  let o = 0;
  out[o++] = 0x30; out[o++] = seqLen;
  out[o++] = 0x02; out[o++] = rb.length; out.set(rb, o); o += rb.length;
  out[o++] = 0x02; out[o++] = sb.length; out.set(sb, o); o += sb.length;
  return out;
}

// ── the action under approval ─────────────────────────────────────────────────
function buildContext(approver, host) {
  return {
    action: 'wire_transfer.execute',
    amount: '82000.00',
    currency: 'USD',
    beneficiary: 'Northwind Logistics LLC',
    beneficiary_account_last4: '4021',
    memo: 'Q3 vendor onboarding — net-30 settlement',
    initiated_by: 'agent:ap-automation/v4',
    approver,
    rp_id: host,
    nonce: randHex(16),
    proposed_at: new Date().toISOString(),
  };
}

function fmtUSD(s) {
  const n = Number(s);
  return n.toLocaleString('en-US', { style: 'currency', currency: 'USD' });
}

// ── enrollment ────────────────────────────────────────────────────────────────
async function enrollReal(approver, host) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'EMILIA Protocol — Try It', id: host },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: `${approver || 'you'}@try.emiliaprotocol.ai`,
        displayName: approver || 'You',
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256 / P-256
      authenticatorSelection: {
        userVerification: 'required',
        authenticatorAttachment: 'platform', // Face ID / Touch ID / Windows Hello
        requireResidentKey: false,
      },
      timeout: 60000,
      attestation: 'none',
    },
  });
  if (cred.response.getPublicKeyAlgorithm?.() !== -7) {
    throw new Error('This device did not offer an ES256 passkey.');
  }
  const spki = cred.response.getPublicKey?.();
  if (!spki) throw new Error('This browser does not expose the public key (getPublicKey).');
  return { kind: 'real', spkiB64u: bytesToB64u(new Uint8Array(spki)), rawId: cred.rawId };
}

async function enrollSim() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
  );
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  return { kind: 'sim', spkiB64u: bytesToB64u(new Uint8Array(spki)), privateKey: pair.privateKey };
}

// ── signing → assemble a real EP signoff object ───────────────────────────────
async function signReal(context, cred, host) {
  const challenge = await sha256Bytes(utf8(canonicalize(context)));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ type: 'public-key', id: cred.rawId }],
      userVerification: 'required',
      rpId: host,
      timeout: 60000,
    },
  });
  const r = assertion.response;
  return {
    context,
    webauthn: {
      authenticator_data: bytesToB64u(new Uint8Array(r.authenticatorData)),
      client_data_json: bytesToB64u(new Uint8Array(r.clientDataJSON)),
      signature: bytesToB64u(new Uint8Array(r.signature)), // DER
    },
  };
}

async function signSim(context, cred, host) {
  const challengeB64u = bytesToB64u(await sha256Bytes(utf8(canonicalize(context))));
  const clientData = JSON.stringify({
    type: 'webauthn.get',
    challenge: challengeB64u,
    origin: window.location.origin,
    crossOrigin: false,
  });
  const clientDataBytes = utf8(clientData);

  const rpIdHash = await sha256Bytes(utf8(host));
  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = 0x05; // UP | UV

  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0);
  signedData.set(await sha256Bytes(clientDataBytes), authData.length);

  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cred.privateKey, signedData),
  );
  return {
    context,
    webauthn: {
      authenticator_data: bytesToB64u(authData),
      client_data_json: bytesToB64u(clientDataBytes),
      signature: bytesToB64u(rawP256ToDer(rawSig)),
    },
  };
}

// ── check display ─────────────────────────────────────────────────────────────
const CHECK_ORDER = [
  ['challenge_binding', 'Approval is bound to this exact action — change one field and it breaks'],
  ['user_verified', 'Verified with biometric / PIN (Face ID · Touch ID · passkey)'],
  ['user_present', 'A human was physically present at the device'],
  ['signature', "Signed by the approver's enrolled device key (ECDSA P-256)"],
  ['client_data_type', 'A genuine authenticator assertion, not a replayed registration'],
  ['rp_id_hash', 'Scoped to this exact site (relying party)'],
];

export default function TryPage() {
  const [approver, setApprover] = useState('');
  const [phase, setPhase] = useState('intro'); // intro · ready · signed · forged
  const [mode, setMode] = useState(null); // 'real' | 'sim'
  const [platformAvail, setPlatformAvail] = useState(false);
  const [cred, setCred] = useState(null);
  const [context, setContext] = useState(null);
  const [signoff, setSignoff] = useState(null);
  const [result, setResult] = useState(null); // valid signoff verify
  const [forged, setForged] = useState(null); // { signoff, result }
  const [busy, setBusy] = useState(false);
  const [signMs, setSignMs] = useState(null);
  const [error, setError] = useState(null);
  const host = useRef('').current;

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (window.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable) {
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then((ok) => setPlatformAvail(Boolean(ok)))
        .catch(() => setPlatformAvail(false));
    }
  }, []);

  const getHost = () => (typeof window === 'undefined' ? 'localhost' : window.location.hostname);

  const begin = useCallback(async (useSim) => {
    setBusy(true);
    setError(null);
    try {
      const h = getHost();
      const c = useSim ? await enrollSim() : await enrollReal(approver, h);
      setCred(c);
      setMode(c.kind);
      setContext(buildContext(approver.trim() || 'You', h));
      setPhase('ready');
    } catch (e) {
      const name = e?.name || '';
      if (name === 'NotAllowedError') {
        setError('The device declined or timed out. You can try again, or use the simulated secure element below.');
      } else {
        setError(`${e.message || e}. You can use the simulated secure element below instead.`);
      }
    }
    setBusy(false);
  }, [approver]);

  const approve = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const h = getHost();
      const t0 = performance.now();
      const so = mode === 'sim'
        ? await signSim(context, cred, h)
        : await signReal(context, cred, h);
      setSignMs(Math.round(performance.now() - t0));
      const res = await verifyWebAuthnSignoff(so, cred.spkiB64u, { rpId: h });
      setSignoff(so);
      setResult(res);
      setPhase('signed');
    } catch (e) {
      const name = e?.name || '';
      setError(name === 'NotAllowedError'
        ? 'Approval was cancelled or timed out. Click “Approve” to try again.'
        : `${e.message || e}`);
    }
    setBusy(false);
  }, [mode, context, cred]);

  const forge = useCallback(async () => {
    setBusy(true);
    try {
      const h = getHost();
      // An attacker who intercepts the signed approval tries to inflate the amount,
      // reusing the exact same device signature. The challenge no longer matches.
      const tampered = { ...signoff, context: { ...signoff.context, amount: '820000.00' } };
      const res = await verifyWebAuthnSignoff(tampered, cred.spkiB64u, { rpId: h });
      setForged({ signoff: tampered, result: res });
      setPhase('forged');
    } catch (e) {
      setError(`${e.message || e}`);
    }
    setBusy(false);
  }, [signoff, cred]);

  const reset = () => {
    setPhase('intro'); setMode(null); setCred(null); setContext(null);
    setSignoff(null); setResult(null); setForged(null); setError(null); setSignMs(null);
  };

  const downloadSignoff = () => {
    const packet = { ...signoff, approver_public_key: cred.spkiB64u, rp_id: getHost() };
    const blob = new Blob([JSON.stringify(packet, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'emilia-signoff.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const page = { minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans };
  const wrap = { maxWidth: 720, margin: '0 auto', padding: '52px 24px 96px' };
  const uvLabel = platformAvail ? 'Face ID / Touch ID' : 'your device';

  return (
    <div style={page}>
      <SiteNav />
      <main style={wrap}>
        <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 18 }}>
          Be the human in the loop
        </div>
        <h1 style={{ fontWeight: 700, fontSize: 'clamp(32px, 5vw, 50px)', letterSpacing: -1.5, lineHeight: 1.04, margin: '0 0 18px' }}>
          An AI agent is about to wire $82,000.
        </h1>
        <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.7, maxWidth: 600, margin: '0 0 36px' }}>
          In most systems it just&nbsp;happens. In EMILIA it can&rsquo;t — not until a named human
          approves it on their own device. <strong style={{ color: color.t1 }}>Be that human.</strong>{' '}
          You&rsquo;ll approve with {uvLabel}, then watch the approval verify — every check — right here in
          your browser, with nothing uploaded.
        </p>

        {/* STEP 1 — enroll */}
        {phase === 'intro' && (
          <div style={card}>
            <Step n="1" label="Enroll as the approver" />
            <label htmlFor="ep-try-name" style={lbl}>Your name (optional)</label>
            <input
              id="ep-try-name"
              value={approver}
              onChange={(e) => setApprover(e.target.value)}
              placeholder="e.g. Jordan Chen, Controller"
              style={input}
            />
            <button onClick={() => begin(false)} disabled={busy} style={primaryBtn(busy)}>
              {busy ? 'Waiting for your device…' : `Enroll with ${uvLabel} →`}
            </button>
            <button onClick={() => begin(true)} disabled={busy} style={ghostBtn}>
              No passkey on this device? Use a simulated secure element
            </button>
            {error && <ErrorNote text={error} />}
          </div>
        )}

        {/* STEP 2 — agent proposes, you approve */}
        {phase === 'ready' && context && (
          <div style={card}>
            <Step n="2" label="The agent requests approval" />
            <ActionCard context={context} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '14px 0 18px', fontSize: 13, color: color.t3 }}>
              <span style={{ width: 7, height: 7, borderRadius: 7, background: color.gold, display: 'inline-block' }} />
              Held by EMILIA — waiting for {mode === 'sim' ? 'a simulated approval' : `${uvLabel}`}.
            </div>
            <button onClick={approve} disabled={busy} style={primaryBtn(busy)}>
              {busy ? 'Waiting for your device…' : (mode === 'sim' ? 'Approve (simulated) →' : `Approve with ${uvLabel} →`)}
            </button>
            {error && <ErrorNote text={error} />}
          </div>
        )}

        {/* STEP 3 — verified */}
        {(phase === 'signed' || phase === 'forged') && result && (
          <div style={{ marginBottom: 20 }}>
            <VerifyPanel ok={result.valid} checks={result.checks} title="Class-A Device Signoff"
              meaning={`A named human approved this exact action on their own device${signMs ? ` in ${(signMs / 1000).toFixed(1)}s` : ''}. Neither a compromised agent nor the operator could have produced this signature.`} />
            {phase === 'signed' && (
              <div style={card}>
                <Step n="3" label="Now try to forge it" />
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, margin: '0 0 16px' }}>
                  Imagine an attacker intercepts your approved approval and inflates the amount —
                  reusing your real device signature. Change <strong>$82,000 → $820,000</strong> and re-verify:
                </p>
                <button onClick={forge} disabled={busy} style={primaryBtn(busy)}>
                  Tamper the amount &amp; re-verify →
                </button>
              </div>
            )}
          </div>
        )}

        {/* STEP 4 — forgery collapses */}
        {phase === 'forged' && forged && (
          <div style={{ marginBottom: 20 }}>
            <VerifyPanel ok={forged.result.valid} checks={forged.result.checks} title="Tampered Signoff ($820,000)"
              meaning="" forged />
            <div style={{ ...card, background: '#FFFBEB', border: `1px solid ${color.gold}` }}>
              <p style={{ fontSize: 15, color: color.t1, lineHeight: 1.65, margin: 0, fontWeight: 600 }}>
                The signature was bound to the exact action. Change one digit and it collapses.
              </p>
              <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: '10px 0 0' }}>
                No agent, no operator, and no server — not even EMILIA — could have produced a valid
                approval for the $820,000 transfer. That is the whole point: <strong>every irreversible
                action gets an owner, and the owner&rsquo;s approval can&rsquo;t be moved to a different action.</strong>
              </p>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 18 }}>
                <button onClick={downloadSignoff} style={secondaryBtn}>↓ Download this signoff</button>
                <a href="/verify" style={{ ...secondaryBtn, textDecoration: 'none' }}>Re-verify it on /verify →</a>
                <button onClick={reset} style={ghostBtn2}>Run it again</button>
              </div>
            </div>
          </div>
        )}

        {/* trust note */}
        <div style={{ marginTop: 36, paddingTop: 22, borderTop: `1px solid ${color.border}`, fontSize: 13, color: color.t3, lineHeight: 1.7 }}>
          <strong style={{ color: color.t2 }}>This is not a video.</strong> The approval is a real{' '}
          <a href="https://www.w3.org/TR/webauthn-2/" style={lnk}>WebAuthn</a> ceremony on your device, and the
          verification is the open-source <code style={{ fontFamily: font.mono, fontSize: 12 }}>@emilia-protocol/verify</code>{' '}
          package running in this tab. Open your network tab — nothing is uploaded. The simulated option uses an
          ephemeral key generated in your browser and discarded on reload; it exists only so the demo works where a
          platform authenticator isn&rsquo;t available.
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}

// ── small components ──────────────────────────────────────────────────────────
function Step({ n, label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
      <span style={{ width: 24, height: 24, borderRadius: 24, background: color.t1, color: '#fff', fontSize: 13, fontWeight: 700, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{n}</span>
      <span style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t2, fontWeight: 600 }}>{label}</span>
    </div>
  );
}

function ActionCard({ context }) {
  const rows = [
    ['Action', 'Wire transfer'],
    ['Amount', fmtUSD(context.amount)],
    ['Beneficiary', `${context.beneficiary} ····${context.beneficiary_account_last4}`],
    ['Memo', context.memo],
    ['Initiated by', context.initiated_by],
  ];
  return (
    <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden' }}>
      {rows.map(([k, v], i) => (
        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, padding: '11px 16px', borderTop: i ? `1px solid ${color.border}` : 'none', background: k === 'Amount' ? '#FFFBEB' : color.card }}>
          <span style={{ fontSize: 12, fontFamily: font.mono, color: color.t3, textTransform: 'uppercase', letterSpacing: 0.5 }}>{k}</span>
          <span style={{ fontSize: 14, color: color.t1, fontWeight: k === 'Amount' ? 700 : 500, textAlign: 'right' }}>{v}</span>
        </div>
      ))}
    </div>
  );
}

function VerifyPanel({ ok, checks, title, meaning, forged }) {
  const accent = ok ? color.green : color.red;
  const bg = ok ? '#F0FDF4' : '#FEF2F2';
  const rows = CHECK_ORDER.filter(([k]) => checks[k] !== null && checks[k] !== undefined);
  return (
    <div style={{ borderRadius: radius.base, border: `1px solid ${accent}`, overflow: 'hidden', marginBottom: 16 }}>
      <div style={{ background: bg, padding: '20px 22px', borderBottom: `1px solid ${ok ? '#BBF7D0' : '#FECACA'}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 24, lineHeight: 1 }}>{ok ? '✅' : '⛔️'}</span>
          <div>
            <div style={{ fontWeight: 700, fontSize: 18, color: ok ? '#15803D' : color.red, letterSpacing: -0.3 }}>
              {ok ? 'VERIFIED' : 'REJECTED — forgery detected'}
            </div>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1, textTransform: 'uppercase', color: color.t3, marginTop: 3 }}>{title}</div>
          </div>
        </div>
        {ok && meaning && <p style={{ margin: '12px 0 0', fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{meaning}</p>}
        {!ok && forged && <p style={{ margin: '12px 0 0', fontSize: 13, color: color.red, lineHeight: 1.6, fontFamily: font.mono }}>challenge_binding: false — the approval does not match this action</p>}
      </div>
      <div style={{ background: color.card }}>
        {rows.map(([key, label]) => (
          <div key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 22px', borderTop: `1px solid ${color.border}` }}>
            <span style={{ fontSize: 15, lineHeight: '20px', width: 18, flexShrink: 0, color: checks[key] === true ? color.green : color.red }}>
              {checks[key] === true ? '✓' : '✕'}
            </span>
            <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.45 }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ErrorNote({ text }) {
  return (
    <div style={{ marginTop: 14, padding: '11px 14px', borderRadius: radius.sm, background: '#FEF2F2', border: `1px solid ${color.red}`, color: color.red, fontSize: 13, lineHeight: 1.55 }}>
      {text}
    </div>
  );
}

// ── style atoms ───────────────────────────────────────────────────────────────
const card = { background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '24px 24px' };
const lbl = { display: 'block', fontSize: 12, fontWeight: 600, color: color.t2, marginBottom: 6, fontFamily: font.mono, letterSpacing: 0.5 };
const input = { width: '100%', padding: '12px 14px', borderRadius: radius.base, border: `1px solid ${color.inputBorder}`, background: color.card, color: color.t1, fontSize: 15, fontFamily: 'inherit', outline: 'none', marginBottom: 18, boxSizing: 'border-box' };
const primaryBtn = (busy) => ({ width: '100%', background: color.t1, color: '#fff', border: 'none', borderRadius: radius.sm, padding: '14px 24px', fontFamily: font.sans, fontWeight: 600, fontSize: 15, cursor: busy ? 'wait' : 'pointer', opacity: busy ? 0.6 : 1 });
const secondaryBtn = { background: 'transparent', color: color.t1, border: `1px solid ${color.borderHover}`, borderRadius: radius.sm, padding: '11px 18px', fontFamily: font.sans, fontWeight: 600, fontSize: 14, cursor: 'pointer' };
const ghostBtn = { display: 'block', width: '100%', background: 'none', border: 'none', color: color.t3, fontSize: 13, cursor: 'pointer', fontFamily: font.sans, marginTop: 12, textAlign: 'center', textDecoration: 'underline' };
const ghostBtn2 = { background: 'none', border: 'none', color: color.t3, fontSize: 14, cursor: 'pointer', fontFamily: font.sans, padding: '11px 8px' };
const lnk = { color: color.blue, textDecoration: 'none' };
