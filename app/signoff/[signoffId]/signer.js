'use client';
// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — client signer. Calls webauthn-options, runs the
// platform authenticator via @simplewebauthn/browser, posts the assertion.

import { useState } from 'react';

const mono = { fontFamily: "'JetBrains Mono', ui-monospace, monospace" };

export default function SignoffSigner({ signoffId, initialApproverId, status }) {
  const [approverId, setApproverId] = useState(initialApproverId || '');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = /** @type {[{decision?: string, receipt_id?: string, context_hash?: string} | null, (v: any) => void]} */ (useState(null));
  const [error, setError] = useState(null);

  if (status !== 'pending' && !result) {
    return (
      <div style={{ padding: '14px 16px', borderRadius: 10, background: '#16140F', fontSize: 14 }}>
        {status === 'approved' && '✅ This signoff has been approved.'}
        {status === 'rejected' && '⛔ This signoff was rejected.'}
        {status === 'expired' && '⌛ This signoff window has expired.'}
      </div>
    );
  }

  async function sign(decision) {
    setBusy(true);
    setError(null);
    try {
      if (!approverId.trim()) throw new Error('Enter your approver ID first.');

      const optRes = await fetch(`/api/v1/signoffs/${signoffId}/webauthn-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approver_id: approverId.trim(), decision }),
      });
      const optData = await optRes.json();
      if (!optRes.ok) throw new Error(optData.detail || optData.title || 'Could not start signing');
      const expectedSignedDecision = decision === 'approved' ? 'approved' : 'denied';
      if (optData.context?.decision !== expectedSignedDecision) {
        throw new Error('Signing context does not match the decision you selected. Nothing was signed.');
      }

      const { startAuthentication } = await import('@simplewebauthn/browser');
      const assertion = await startAuthentication({ optionsJSON: optData.options });

      const apprRes = await fetch(`/api/v1/signoffs/${signoffId}/approve-webauthn`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approver_id: approverId.trim(), decision, assertion }),
      });
      const apprData = await apprRes.json();
      if (!apprRes.ok) throw new Error(apprData.detail || apprData.title || 'Signoff failed');

      setResult(apprData);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <div style={{ padding: '16px', borderRadius: 10, background: '#16140F', fontSize: 14, lineHeight: 1.7 }}>
        <div style={{ fontWeight: 650 }}>
          {result.decision === 'approved' ? '✅ Signed and approved' : '⛔ Signed and rejected'} — key class A
        </div>
        <div style={{ color: '#8A857C', fontSize: 12, marginTop: 6 }}>
          receipt <span style={mono}>{result.receipt_id}</span><br />
          context hash <span style={mono}>{(result.context_hash || '').slice(0, 24)}…</span><br />
          Your device key signed this exact action. The receipt now verifies
          offline — no EP server required.
        </div>
      </div>
    );
  }

  return (
    <div>
      <label htmlFor="ep-approver-id" style={{ display: 'block', fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#8A857C', marginBottom: 6 }}>
        Approver ID
      </label>
      <input
        id="ep-approver-id"
        value={approverId}
        onChange={(e) => setApproverId(e.target.value)}
        placeholder="ep:approver:jchen-controller"
        style={{
          width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid #33302A',
          background: '#16140F', color: '#F5F2EC', fontSize: 14, marginBottom: 12, ...mono,
        }}
      />
      <div style={{ display: 'flex', gap: 10 }}>
        <button
          onClick={() => sign('approved')}
          disabled={busy}
          style={{
            flex: 1, padding: '12px 16px', borderRadius: 8, border: 'none', cursor: busy ? 'wait' : 'pointer',
            background: '#C9A554', color: '#16140F', fontWeight: 700, fontSize: 14,
          }}
        >
          {busy ? 'Waiting for authenticator…' : 'Approve & sign'}
        </button>
        <button
          onClick={() => sign('rejected')}
          disabled={busy}
          style={{
            padding: '12px 16px', borderRadius: 8, border: '1px solid #33302A', cursor: busy ? 'wait' : 'pointer',
            background: 'transparent', color: '#F5F2EC', fontWeight: 600, fontSize: 14,
          }}
        >
          Decline & sign
        </button>
      </div>
      {error && (
        <div style={{ marginTop: 12, padding: '10px 12px', borderRadius: 8, background: '#2A1714', color: '#E8A398', fontSize: 13 }}>
          {error}
        </div>
      )}
    </div>
  );
}
