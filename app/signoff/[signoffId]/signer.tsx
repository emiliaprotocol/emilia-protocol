'use client';
// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — client signer. Calls webauthn-options, runs the
// platform authenticator via @simplewebauthn/browser, posts the assertion.

import { useState } from 'react';

interface SignoffSignerProps {
  signoffId: string;
  intendedApproverId?: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  expectedActionHash: string;
  expectedDisplayHash: string;
  expectedRenderProfile: string;
}

interface SignoffResult {
  decision?: string;
  receipt_id?: string;
  context_hash?: string;
}

interface PreparedData {
  decision: string;
  optData: any;
}

const mono: React.CSSProperties = { fontFamily: "'JetBrains Mono', ui-monospace, monospace" };

export default function SignoffSigner({
  signoffId,
  intendedApproverId,
  status,
  expectedActionHash,
  expectedDisplayHash,
  expectedRenderProfile,
}: SignoffSignerProps) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SignoffResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [prepared, setPrepared] = useState<PreparedData | null>(null);

  if (status !== 'pending' && !result) {
    return (
      <div style={{ padding: '14px 16px', borderRadius: 10, background: '#16140F', fontSize: 14 }}>
        {status === 'approved' && '✅ This signoff has been approved.'}
        {status === 'rejected' && '⛔ This signoff was rejected.'}
        {status === 'expired' && '⌛ This signoff window has expired.'}
      </div>
    );
  }

  async function prepare(decision: string) {
    setBusy(true);
    setError(null);
    try {
      if (!intendedApproverId) throw new Error('This signoff request has no intended approver. Nothing was signed.');

      const optRes = await fetch(`/api/v1/signoffs/${signoffId}/webauthn-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approver_id: intendedApproverId, decision }),
      });
      const optData = await optRes.json();
      if (!optRes.ok) throw new Error(optData.detail || optData.title || 'Could not start signing');
      const expectedSignedDecision = decision === 'approved' ? 'approved' : 'denied';
      if (optData.context?.decision !== expectedSignedDecision) {
        throw new Error('Signing context does not match the decision you selected. Nothing was signed.');
      }
      if (optData.context?.action_hash !== expectedActionHash) {
        throw new Error('Signing context action hash does not match the action you reviewed. Nothing was signed.');
      }
      if (optData.context?.display_hash !== expectedDisplayHash) {
        throw new Error('Signing context display hash does not match the presentation you reviewed. Nothing was signed.');
      }
      if (optData.rendering?.render_profile !== expectedRenderProfile) {
        throw new Error('Signing render profile does not match the presentation you reviewed. Nothing was signed.');
      }
      if (optData.rendering?.action_hash?.replace(/^sha256:/, '') !== expectedActionHash
          || optData.rendering?.display_hash !== expectedDisplayHash) {
        throw new Error('Signing renderer returned material for a different action. Nothing was signed.');
      }
      setPrepared({ decision, optData });
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      if (!prepared) throw new Error('Prepare and review the signed challenge first.');
      const { decision, optData } = prepared;
      const { startAuthentication } = await import('@simplewebauthn/browser');
      const assertion = await startAuthentication({ optionsJSON: optData.options });

      const apprRes = await fetch(`/api/v1/signoffs/${signoffId}/approve-webauthn`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approver_id: intendedApproverId, decision, assertion }),
      });
      const apprData = await apprRes.json();
      if (!apprRes.ok) throw new Error(apprData.detail || apprData.title || 'Signoff failed');

      setResult(apprData);
      setPrepared(null);
    } catch (e) {
      setError((e as Error).message || String(e));
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
      <div style={{ padding: '10px 12px', borderRadius: 8, border: '1px solid #33302A', background: '#16140F', marginBottom: 12 }}>
        <div style={{ color: '#8A857C', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Intended approver</div>
        <div style={{ ...mono, marginTop: 4, fontSize: 13 }}>{intendedApproverId || 'Missing — signing disabled'}</div>
      </div>
      {prepared ? (
        <div style={{ border: '1px solid #4B432F', borderRadius: 10, padding: 14, background: '#16140F' }}>
          <div style={{ fontWeight: 650 }}>Review the signed challenge</div>
          <p style={{ color: '#8A857C', fontSize: 12, lineHeight: 1.6 }}>
            Decision: <span style={mono}>{prepared.optData.context.decision}</span><br />
            Action hash: <span style={mono}>{prepared.optData.context.action_hash}</span><br />
            Display hash: <span style={mono}>{prepared.optData.context.display_hash}</span><br />
            Expires: <span style={mono}>{prepared.optData.context.expires_at}</span>
          </p>
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              onClick={confirm}
              disabled={busy}
              style={{ flex: 1, padding: '12px 16px', borderRadius: 8, border: 'none', background: '#C9A554', color: '#16140F', fontWeight: 700 }}
            >
              {busy ? 'Waiting for authenticator…' : 'Confirm & use passkey'}
            </button>
            <button
              onClick={() => setPrepared(null)}
              disabled={busy}
              style={{ padding: '12px 16px', borderRadius: 8, border: '1px solid #33302A', background: 'transparent', color: '#F5F2EC' }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            onClick={() => prepare('approved')}
            disabled={busy || !intendedApproverId}
            style={{
              flex: 1, padding: '12px 16px', borderRadius: 8, border: 'none', cursor: busy ? 'wait' : 'pointer',
              background: '#C9A554', color: '#16140F', fontWeight: 700, fontSize: 14,
            }}
          >
            {busy ? 'Preparing challenge…' : 'Prepare approval'}
          </button>
          <button
            onClick={() => prepare('rejected')}
            disabled={busy || !intendedApproverId}
            style={{
              padding: '12px 16px', borderRadius: 8, border: '1px solid #33302A', cursor: busy ? 'wait' : 'pointer',
              background: 'transparent', color: '#F5F2EC', fontWeight: 600, fontSize: 14,
            }}
          >
            Prepare decline
          </button>
        </div>
      )}
      {error && (
        <div style={{ marginTop: 12, padding: '10px 12px', borderRadius: 8, background: '#2A1714', color: '#E8A398', fontSize: 13 }}>
          {error}
        </div>
      )}
    </div>
  );
}
