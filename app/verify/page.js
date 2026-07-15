'use client';

/**
 * /verify — Verify an authorization receipt in your own browser.
 * @license Apache-2.0
 *
 * The open, zero-trust answer to a proprietary "control plane": a receipt or a
 * Class-A device signoff is verified entirely client-side with @emilia-protocol/
 * verify (Web Crypto). Nothing is uploaded, no account, no EP server trusted —
 * just public-key math the visitor can audit (the same package ships on npm).
 *
 * Auto-detects receipt / signoff / commitment-proof / bundle from the pasted
 * JSON and runs the matching verifier. Ships with real, fully-signed examples
 * so a skeptic sees every check go green without needing their own artifact.
 */

import { useState, useCallback, useRef } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, font, radius } from '@/lib/tokens';
import {
  verifyReceipt,
  verifyWebAuthnSignoff,
  verifyCommitmentProof,
  verifyReceiptBundle,
  isSupported,
} from '@/lib/verify-web';
import { EXAMPLE_RECEIPT, EXAMPLE_SIGNOFF } from './examples';
import { strictJsonGate } from '@/lib/strict-json.js';

const MAX_VERIFY_INPUT_BYTES = 8 * 1024 * 1024;

// Look for an embedded public key under conventional field names. This enables
// a self-contained integrity check only; a key carried by an artifact cannot
// establish its own issuer or approver identity.
function findKey(doc, names) {
  for (const n of names) {
    if (typeof doc?.[n] === 'string') return doc[n];
    if (typeof doc?.context?.[n] === 'string') return doc.context[n];
    if (typeof doc?.signer?.[n] === 'string') return doc.signer[n];
  }
  return null;
}

const RECEIPT_LABELS = {
  version: 'Recognized receipt format (EP-RECEIPT-v1)',
  signature: 'Signature matches the presented key (Ed25519) — payload is intact',
  anchor: 'Included in the published Merkle anchor',
};
const SIGNOFF_LABELS = {
  challenge_binding: 'Approval is bound to this exact action — change one field and it breaks',
  client_data_type: 'A genuine authenticator assertion (not a re-used registration)',
  user_present: 'A human was physically present at the device',
  user_verified: 'Verified with biometric / PIN (Face ID · Touch ID · passkey)',
  rp_id_hash: 'Scoped to the expected relying party',
  signature: 'Signature matches the presented device key (ECDSA P-256)',
};

// Turn a verifier result into ordered display rows + a one-line meaning.
function present(kind, result) {
  if (kind === 'receipt') {
    const c = result.checks || {};
    const rows = [
      ['version', c.version],
      ['signature', c.signature],
    ];
    if (c.anchor !== null && c.anchor !== undefined) rows.push(['anchor', c.anchor]);
    return {
      title: 'Authorization Receipt',
      labels: RECEIPT_LABELS,
      rows,
      meaning: 'The bytes are intact under the presented key. This self-contained check does not establish who controls that key, issuer authority, or relying-party acceptance.',
    };
  }
  if (kind === 'signoff') {
    const c = result.checks || {};
    const rows = [
      ['challenge_binding', c.challenge_binding],
      ['user_verified', c.user_verified],
      ['user_present', c.user_present],
      ['signature', c.signature],
      ['client_data_type', c.client_data_type],
    ];
    if (c.rp_id_hash !== null && c.rp_id_hash !== undefined) rows.push(['rp_id_hash', c.rp_id_hash]);
    return {
      title: 'Class A Device Signoff',
      labels: SIGNOFF_LABELS,
      rows,
      meaning: 'A user-present, user-verified authenticator ceremony signed this exact context under the presented key. This integrity-only page does not independently pin the RP ID, origin, identity, authority, perception, or relying-party acceptance.',
    };
  }
  if (kind === 'proof') {
    return { title: 'Commitment Proof', labels: {}, rows: [], meaning: 'The pre-action commitment is authentic and unexpired.' };
  }
  return { title: 'Receipt Bundle', labels: {}, rows: [], meaning: `${result.verified}/${result.total} receipts verified.` };
}

async function verifyAny(doc) {
  // EP-BUNDLE-v1
  if (doc?.['@version'] === 'EP-BUNDLE-v1') {
    const key = findKey(doc, ['issuer_public_key', 'public_key', 'publicKey']);
    if (!key) return { kind: 'bundle', needKey: true };
    return { kind: 'bundle', result: await verifyReceiptBundle(doc, key) };
  }
  // EP-RECEIPT-v1
  if (doc?.['@version'] === 'EP-RECEIPT-v1') {
    const key = findKey(doc, ['issuer_public_key', 'public_key', 'publicKey']);
    if (!key) return { kind: 'receipt', needKey: true };
    return { kind: 'receipt', result: await verifyReceipt(doc, key) };
  }
  // EP-PROOF-v1
  if (doc?.['@version'] === 'EP-PROOF-v1') {
    const key = findKey(doc, ['public_key', 'publicKey', 'entity_public_key']);
    return { kind: 'proof', result: await verifyCommitmentProof(doc, key) };
  }
  // Device signoff (context + webauthn)
  if (doc?.context && doc?.webauthn) {
    const key = findKey(doc, ['approver_public_key', 'public_key', 'publicKey']);
    if (!key) return { kind: 'signoff', needKey: true };
    // This public page has no out-of-band relying-party trust profile. Do not
    // copy an RP ID or origin from the artifact and present it as an independent
    // pin; run the low-level integrity check and label that boundary plainly.
    return { kind: 'signoff', result: await verifyWebAuthnSignoff(doc, key) };
  }
  return { kind: null };
}

export default function VerifyPage() {
  const [input, setInput] = useState('');
  const [state, setState] = useState(null); // { kind, result } | { error }
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef(null);

  const supported = typeof window === 'undefined' ? true : isSupported();

  const run = useCallback(async (raw) => {
    setBusy(true);
    setState(null);
    try {
      let doc;
      try {
        if (new TextEncoder().encode(raw).length > MAX_VERIFY_INPUT_BYTES) throw new Error('input is too large');
        const strict = strictJsonGate(raw);
        if (!strict.ok) throw new Error(strict.reason);
        doc = JSON.parse(raw);
      } catch (error) {
        setState({ error: `That is not strict JSON: ${error.message}. Paste one unambiguous receipt or signoff document.` });
        setBusy(false);
        return;
      }
      const out = await verifyAny(doc);
      if (out.kind === null) { setState({ error: 'Unrecognized document. Expected an EP receipt, device signoff, bundle, or commitment proof.' }); }
      else if (out.needKey) { setState({ error: `This ${out.kind} has no embedded public key. Verify it with the full evidence packet (which includes the key), or via the CLI: npx @emilia-protocol/verify`, kind: out.kind }); }
      else { setState({ kind: out.kind, result: out.result }); }
    } catch (e) {
      setState({ error: `Verification error: ${e.message}` });
    }
    setBusy(false);
  }, []);

  const loadExample = (ex) => {
    const text = JSON.stringify(ex, null, 2);
    setInput(text);
    run(text);
  };

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { const t = String(reader.result || ''); setInput(t); run(t); };
    reader.readAsText(file);
  }, [run]);

  const pageStyle = { minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans };
  const wrap = { maxWidth: 820, margin: '0 auto', padding: '56px 24px 96px' };

  return (
    <div style={pageStyle}>
      <SiteNav />
      <main style={wrap}>
        <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 18 }}>
          Verify it yourself
        </div>
        <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(34px, 5vw, 52px)', letterSpacing: -1.5, lineHeight: 1.02, margin: '0 0 20px' }}>
          Check a receipt&rsquo;s cryptographic integrity in your own browser.
        </h1>
        <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.7, maxWidth: 640, margin: '0 0 36px' }}>
          Paste a receipt or device signoff below. Its signature and binding are checked <strong style={{ color: color.t1 }}>entirely on this page</strong> with
          {' '}pure public-key math — nothing is uploaded, no account, no EMILIA server is trusted. The exact code running here is the
          {' '}open-source <code style={{ fontFamily: font.mono, fontSize: 14 }}>@emilia-protocol/verify</code> package. Embedded keys support an integrity check; acceptance requires trust anchors supplied independently by the relying party.
        </p>

        {!supported && (
          <div style={{ padding: 16, borderRadius: radius.base, background: '#FEF2F2', border: `1px solid ${color.red}`, color: color.red, marginBottom: 24, fontSize: 14 }}>
            This browser does not expose the Web Crypto algorithms EP needs. Use a current browser, or verify from the terminal with <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/verify</code>.
          </div>
        )}

        {/* Example loaders */}
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 14 }}>
          <button onClick={() => loadExample(EXAMPLE_RECEIPT)} style={exampleBtn}>↳ Load example receipt ($82,000)</button>
          <button onClick={() => loadExample(EXAMPLE_SIGNOFF)} style={exampleBtn}>↳ Load example device signoff</button>
        </div>
        <p style={{ fontSize: 13, color: color.t3, margin: '0 0 18px' }}>
          Want to make your own? <a href="/try" style={{ color: color.blue, textDecoration: 'none' }}>Approve an action with Face&nbsp;ID on /try →</a> then download the signoff and verify it here.
        </p>

        {/* Input */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          style={{ border: `1.5px dashed ${dragging ? color.gold : color.inputBorder}`, borderRadius: radius.base, background: dragging ? '#FEFCE8' : color.card, transition: 'border-color .15s, background .15s' }}
        >
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='Paste receipt or signoff JSON here — or drop a .json file.'
            spellCheck={false}
            style={{ width: '100%', minHeight: 200, resize: 'vertical', border: 'none', outline: 'none', background: 'transparent', padding: 18, fontFamily: font.mono, fontSize: 13, lineHeight: 1.6, color: color.t1, borderRadius: radius.base }}
          />
        </div>

        <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 16, flexWrap: 'wrap' }}>
          <button
            onClick={() => run(input)}
            disabled={busy || !input.trim()}
            style={{ background: color.t1, color: '#fff', border: 'none', borderRadius: radius.sm, padding: '12px 28px', fontFamily: font.sans, fontWeight: 600, fontSize: 15, cursor: busy || !input.trim() ? 'default' : 'pointer', opacity: busy || !input.trim() ? 0.45 : 1 }}
          >
            {busy ? 'Verifying…' : 'Verify'}
          </button>
          {input && <button onClick={() => { setInput(''); setState(null); }} style={{ background: 'none', border: 'none', color: color.t3, fontSize: 14, cursor: 'pointer', fontFamily: font.sans }}>Clear</button>}
          <input ref={fileRef} type="file" accept="application/json,.json" style={{ display: 'none' }} onChange={(e) => { const f = e.target.files?.[0]; if (f) { const r = new FileReader(); r.onload = () => { const t = String(r.result || ''); setInput(t); run(t); }; r.readAsText(f); } }} />
          <button onClick={() => fileRef.current?.click()} style={{ background: 'none', border: `1px solid ${color.border}`, borderRadius: radius.sm, color: color.t2, fontSize: 14, cursor: 'pointer', fontFamily: font.sans, padding: '11px 18px' }}>Choose file…</button>
        </div>

        {/* Result */}
        {state && <Result state={state} />}

        {/* Trust note */}
        <div style={{ marginTop: 40, paddingTop: 24, borderTop: `1px solid ${color.border}`, fontSize: 13, color: color.t3, lineHeight: 1.7 }}>
          <strong style={{ color: color.t2 }}>Why you can trust this page over our word:</strong> open your browser&rsquo;s network tab and verify a receipt — you&rsquo;ll see no request leaves your machine. The verifier is{' '}
          <a href="https://www.npmjs.com/package/@emilia-protocol/verify" style={{ color: color.blue, textDecoration: 'none' }}>published on npm</a> and{' '}
          <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/packages/verify/web.js" style={{ color: color.blue, textDecoration: 'none' }}>auditable on GitHub</a>; run it yourself with <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/verify</code>. Receipts use Ed25519; device signoffs use ECDSA P-256 over a WebAuthn assertion.
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}

function Result({ state }) {
  if (state.error) {
    return (
      <div style={{ marginTop: 28, padding: 20, borderRadius: radius.base, background: '#FEF2F2', border: `1px solid ${color.red}` }}>
        <div style={{ fontWeight: 600, color: color.red, fontSize: 15 }}>Could not verify</div>
        <div style={{ color: color.t2, fontSize: 14, marginTop: 6, lineHeight: 1.6 }}>{state.error}</div>
      </div>
    );
  }

  const { kind, result } = state;
  const view = present(kind, result);
  const ok = result.valid;
  const accent = ok ? color.green : color.red;
  const bg = ok ? '#F0FDF4' : '#FEF2F2';

  return (
    <div style={{ marginTop: 28, borderRadius: radius.base, border: `1px solid ${accent}`, overflow: 'hidden' }}>
      <div style={{ background: bg, padding: '22px 24px', borderBottom: `1px solid ${ok ? '#BBF7D0' : '#FECACA'}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 26, lineHeight: 1 }}>{ok ? '✅' : '⛔️'}</span>
          <div>
            <div style={{ fontWeight: 700, fontSize: 19, color: ok ? '#15803D' : color.red, letterSpacing: -0.3 }}>
              {ok ? 'CRYPTOGRAPHICALLY VERIFIED' : 'NOT VERIFIED'}
            </div>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1, textTransform: 'uppercase', color: color.t3, marginTop: 3 }}>{view.title}</div>
          </div>
        </div>
        {ok && <p style={{ margin: '14px 0 0', fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{view.meaning}</p>}
        {!ok && result.error && <p style={{ margin: '14px 0 0', fontSize: 13, color: color.red, lineHeight: 1.6, fontFamily: font.mono }}>{result.error}</p>}
      </div>

      {view.rows.length > 0 && (
        <div style={{ background: color.card }}>
          {view.rows.map(([key, val]) => (
            <div key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '13px 24px', borderTop: `1px solid ${color.border}` }}>
              <span style={{ fontSize: 15, lineHeight: '20px', width: 18, flexShrink: 0, color: val === true ? color.green : color.red }}>
                {val === true ? '✓' : '✕'}
              </span>
              <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.45 }}>{view.labels[key] || key}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const exampleBtn = {
  background: color.cardHover,
  border: `1px solid ${color.border}`,
  borderRadius: radius.sm,
  color: color.t2,
  fontSize: 13,
  fontFamily: font.mono,
  padding: '8px 14px',
  cursor: 'pointer',
};
