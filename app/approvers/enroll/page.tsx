'use client';
// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — approver passkey enrollment (pilot surface).
//
// An org admin runs this with their EP API key (sent only to EP's own API,
// held in component state, never persisted). The admin's authenticated
// entity is recorded as the second-party attestation on the enrollment
// (draft §5.2). The approver completes the passkey ceremony on THEIR device.

import { useState } from 'react';

const mono ={ fontFamily: "'JetBrains Mono', ui-monospace, monospace" };
const field = {
  width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid #33302A',
  background: '#16140F', color: '#F5F2EC', fontSize: 14, marginBottom: 12,
};
const lbl = { display: 'block', fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#8A857C', marginBottom: 6 };

export default function EnrollApproverPage() {
  const [apiKey, setApiKey] = useState('');
  const [approverId, setApproverId] = useState('');
  const [approverName, setApproverName] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{approver_id?: string, credential_id?: string, attested_by?: string} | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function enroll() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      if (!apiKey.trim() || !approverId.trim()) throw new Error('EP API key and approver ID are required.');
      const headers = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey.trim()}`,
      };

      const optRes = await fetch('/api/v1/approvers/webauthn/register-options', {
        method: 'POST',
        headers,
        body: JSON.stringify({ approver_id: approverId.trim(), approver_name: approverName.trim() || undefined }),
      });
      const optData = await optRes.json();
      if (!optRes.ok) throw new Error(optData.detail || optData.title || 'Could not start enrollment');

      const { startRegistration } = await import('@simplewebauthn/browser');
      const attestation = await startRegistration({ optionsJSON: optData.options });

      const verRes = await fetch('/api/v1/approvers/webauthn/register-verify', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          approver_id: approverId.trim(),
          approver_name: approverName.trim() || undefined,
          attestation,
        }),
      });
      const verData = await verRes.json();
      if (!verRes.ok) throw new Error(verData.detail || verData.title || 'Enrollment verification failed');
      setResult(verData);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: '#0E0D0B', color: '#F5F2EC',
      fontFamily: "'Inter', -apple-system, system-ui, sans-serif",
      display: 'flex', justifyContent: 'center', padding: '48px 20px',
    }}>
      <div style={{ width: '100%', maxWidth: 480 }}>
        <div style={{ fontSize: 11, letterSpacing: '0.14em', textTransform: 'uppercase', color: '#C9A554', marginBottom: 6 }}>
          EMILIA Protocol · approver enrollment
        </div>
        <h1 style={{ fontSize: 24, margin: '0 0 8px', fontWeight: 650 }}>Enroll a signing passkey</h1>
        <p style={{ color: '#8A857C', fontSize: 13, lineHeight: 1.6, marginBottom: 24 }}>
          The approver&rsquo;s device generates and holds the key — EP never sees it
          and cannot sign for them. Run this on the approver&rsquo;s own device. The
          authenticated admin key below is recorded as the second-party
          attestation on this enrollment.
        </p>

        <label htmlFor="ep-key" style={lbl}>EP API key (org admin)</label>
        <input id="ep-key" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="ep_live_…" style={{ ...field, ...mono }} />

        <label htmlFor="ep-appr" style={lbl}>Approver ID</label>
        <input id="ep-appr" value={approverId} onChange={(e) => setApproverId(e.target.value)} placeholder="ep:approver:jchen-controller" style={{ ...field, ...mono }} />

        <label htmlFor="ep-name" style={lbl}>Approver name (for receipts)</label>
        <input id="ep-name" value={approverName} onChange={(e) => setApproverName(e.target.value)} placeholder="Jane Chen, Treasury Controller" style={field} />

        <button
          onClick={enroll}
          disabled={busy}
          style={{
            width: '100%', padding: '12px 16px', borderRadius: 8, border: 'none',
            cursor: busy ? 'wait' : 'pointer', background: '#C9A554', color: '#16140F',
            fontWeight: 700, fontSize: 14, marginTop: 4,
          }}
        >
          {busy ? 'Waiting for authenticator…' : 'Create passkey (Face ID / Touch ID / key)'}
        </button>

        {result && (
          <div style={{ marginTop: 16, padding: '12px 14px', borderRadius: 8, background: '#16271A', color: '#A9D8B0', fontSize: 13, lineHeight: 1.7 }}>
            ✅ Enrolled <strong>{result.approver_id}</strong> (key class A)<br />
            credential <span style={mono}>{(result.credential_id || '').slice(0, 20)}…</span><br />
            attested by <span style={mono}>{result.attested_by}</span>
          </div>
        )}
        {error && (
          <div style={{ marginTop: 16, padding: '12px 14px', borderRadius: 8, background: '#2A1714', color: '#E8A398', fontSize: 13 }}>
            {error}
          </div>
        )}
      </div>
    </div>
  );
}
