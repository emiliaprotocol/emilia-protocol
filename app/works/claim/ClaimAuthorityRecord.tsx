'use client';

// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';

import { cta, color, font, radius, styles } from '@/lib/tokens';
import css from '../works.module.css';

type OwnedRecord = {
  record_id: string;
  status: string;
  version: number;
  record_digest: string;
  projection: Record<string, unknown>;
};

async function jsonCall(url: string, init: RequestInit) {
  const response = await fetch(url, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init.headers || {}) },
    cache: 'no-store',
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || 'Request failed.');
  return body;
}

export default function ClaimAuthorityRecord() {
  const [invitationToken, setInvitationToken] = useState('');
  const [proofUrl, setProofUrl] = useState('');
  const [ownerToken, setOwnerToken] = useState('');
  const [ownerRecordId, setOwnerRecordId] = useState('');
  const [ownerCredentialIssued, setOwnerCredentialIssued] = useState(false);
  const [record, setRecord] = useState<OwnedRecord | null>(null);
  const [projectionJson, setProjectionJson] = useState('');
  const [status, setStatus] = useState('Use the private invitation and repository proof to claim this record.');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const fragment = window.location.hash.slice(1);
    if (/^ari1_[0-9a-f]{64}$/.test(fragment)) {
      window.history.replaceState(null, '', window.location.pathname);
      queueMicrotask(() => setInvitationToken(fragment));
    }
  }, []);

  function displayRecord(next: OwnedRecord) {
    setRecord(next);
    setProjectionJson(JSON.stringify(next.projection, null, 2));
  }

  const savedCredential = useMemo(() => ownerToken && record
    ? `Save this one-time owner credential now: ${ownerToken}` : '', [ownerToken, record]);

  async function claim() {
    setBusy(true);
    setStatus('Verifying the immutable repository proof…');
    try {
      const body = await jsonCall('/api/works/authority-records/claim', {
        method: 'POST', body: JSON.stringify({ invitation_token: invitationToken, proof_url: proofUrl }),
      });
      const claimed = body as OwnedRecord & { owner_token: string };
      setOwnerToken(claimed.owner_token);
      setOwnerRecordId(claimed.record_id);
      setOwnerCredentialIssued(true);
      displayRecord(claimed);
      sessionStorage.setItem(`emilia.authority-owner.${claimed.record_id}`, claimed.owner_token);
      setInvitationToken('');
      setStatus('Repository control verified. The record is still private until you approve its exact digest.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Claim failed.');
    } finally {
      setBusy(false);
    }
  }

  async function loadClaimedRecord() {
    if (!/^authority-record-[a-z0-9][a-z0-9-]{2,63}$/.test(ownerRecordId)
        || !/^aro1_[0-9a-f]{64}$/.test(ownerToken)) return;
    setBusy(true);
    try {
      const body = await jsonCall(`/api/works/authority-records/${ownerRecordId}`, {
        method: 'POST', headers: { authorization: `Bearer ${ownerToken}` },
      });
      displayRecord(body.record);
      setOwnerCredentialIssued(false);
      sessionStorage.setItem(`emilia.authority-owner.${ownerRecordId}`, ownerToken);
      setStatus('Claimed record loaded. The credential remains in this tab only.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Record could not be loaded.');
    } finally {
      setBusy(false);
    }
  }

  async function startMonitoring() {
    if (!record || !ownerToken) return;
    setBusy(true);
    try {
      const body = await jsonCall(`/api/works/authority-records/${record.record_id}/billing/checkout`, {
        method: 'POST', headers: { authorization: `Bearer ${ownerToken}` },
      });
      if (typeof body.url !== 'string' || !body.url.startsWith('https://')) throw new Error('Checkout is unavailable.');
      window.location.assign(body.url);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Checkout failed.');
      setBusy(false);
    }
  }

  async function reconcileMonitoring() {
    if (!record || !ownerToken) return;
    setBusy(true);
    try {
      const body = await jsonCall(`/api/works/authority-records/${record.record_id}/billing/reconcile`, {
        method: 'POST', headers: { authorization: `Bearer ${ownerToken}` },
      });
      setStatus(`Monitoring state reconciled: ${body.entitlement?.status || 'unknown'}.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Monitoring reconciliation failed.');
    } finally {
      setBusy(false);
    }
  }

  async function revise() {
    if (!record || !ownerToken) return;
    setBusy(true);
    try {
      const projection = JSON.parse(projectionJson);
      const body = await jsonCall(`/api/works/authority-records/${record.record_id}`, {
        method: 'PATCH',
        headers: { authorization: `Bearer ${ownerToken}` },
        body: JSON.stringify({ projection }),
      });
      displayRecord(body.record);
      setStatus('Correction saved as a new private version. Review the new digest before publishing.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Correction failed.');
    } finally {
      setBusy(false);
    }
  }

  async function approve() {
    if (!record || !ownerToken) return;
    setBusy(true);
    try {
      const body = await jsonCall(`/api/works/authority-records/${record.record_id}/approve`, {
        method: 'POST',
        headers: { authorization: `Bearer ${ownerToken}` },
        body: JSON.stringify({ record_digest: record.record_digest }),
      });
      displayRecord({ ...record, ...body.record });
      setStatus('Published. The public page contains only the exact bytes you approved.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Approval failed.');
    } finally {
      setBusy(false);
    }
  }

  async function withdraw() {
    if (!record || !ownerToken) return;
    setBusy(true);
    try {
      const body = await jsonCall(`/api/works/authority-records/${record.record_id}/withdraw`, {
        method: 'POST',
        headers: { authorization: `Bearer ${ownerToken}` },
        body: '{}',
      });
      displayRecord({ ...record, ...body.record });
      setStatus('Withdrawn. The public projection is no longer available.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Withdrawal failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ display: 'grid', gap: 24 }}>
      {!record ? (
        <>
          <div style={{ ...styles.card, display: 'grid', gap: 18 }}>
            <label className={css.field}>
              <span>Private invitation token</span>
              <input style={styles.input} value={invitationToken}
                onChange={(event) => setInvitationToken(event.target.value.trim())}
                autoComplete="off" spellCheck={false} />
            </label>
            <label className={css.field}>
              <span>Immutable proof URL</span>
              <input style={styles.input} value={proofUrl}
                onChange={(event) => setProofUrl(event.target.value.trim())}
                placeholder="https://raw.githubusercontent.com/owner/repo/COMMIT/.well-known/emilia-authority-record.json"
                autoComplete="off" spellCheck={false} />
              <span className={css.hint} style={{ color: color.t3 }}>
                The URL must pin a commit, not a branch. Put the exact claim document from your invitation at the stated path.
              </span>
            </label>
            <button type="button" style={cta.primary} disabled={busy || !invitationToken || !proofUrl}
              onClick={claim}>Verify repository and claim</button>
          </div>
          <div style={{ ...styles.card, display: 'grid', gap: 14 }}>
            <strong>Already claimed?</strong>
            <input style={styles.input} value={ownerRecordId}
              onChange={(event) => setOwnerRecordId(event.target.value.trim())}
              placeholder="authority-record-your-agent" autoComplete="off" spellCheck={false} />
            <input style={styles.input} value={ownerToken}
              onChange={(event) => setOwnerToken(event.target.value.trim())}
              placeholder="aro1_ owner credential" type="password" autoComplete="off" spellCheck={false} />
            <button type="button" style={cta.secondary} disabled={busy || !ownerRecordId || !ownerToken}
              onClick={loadClaimedRecord}>Load claimed record</button>
          </div>
        </>
      ) : (
        <>
          {ownerCredentialIssued ? <div style={{ ...styles.card, borderColor: color.gold }}>
            <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, marginBottom: 8 }}>
              OWNER CREDENTIAL · SHOWN ONCE
            </div>
            <code className={css.keyValue}>{savedCredential}</code>
            <p style={{ color: color.t3, fontSize: 13, marginBottom: 0 }}>
              It is held only in this tab&apos;s sessionStorage. EMILIA stores a digest, not this credential.
            </p>
          </div> : null}

          <div style={{ ...styles.card, display: 'grid', gap: 16 }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3 }}>CURRENT EXACT DIGEST</div>
              <code className={css.keyValue}>{record.record_digest}</code>
            </div>
            <label className={css.field}>
              <span>Correct before publishing</span>
              <textarea className={css.textarea} style={{ ...styles.input, minHeight: 420 }}
                value={projectionJson} onChange={(event) => setProjectionJson(event.target.value)}
                spellCheck={false} />
            </label>
            <div className={css.actions}>
              <button type="button" style={cta.secondary} disabled={busy} onClick={revise}>
                Save correction as new version
              </button>
              <button type="button" style={cta.primary} disabled={busy || record.status === 'PUBLISHED'} onClick={approve}>
                Approve exact record {record.record_digest.slice(0, 18)}…
              </button>
              <button type="button" style={{ ...cta.ghost, color: '#ef4444' }} disabled={busy} onClick={withdraw}>
                Withdraw public record
              </button>
            </div>
          </div>

          <div style={{ ...styles.card, display: 'grid', gap: 12 }}>
            <strong>$29/month monitoring and freshness</strong>
            <p style={{ color: color.t3, margin: 0 }}>
              Payment buys recurring watched-ref checks, deeper presentation, and freshness history,
              never a favorable result.
            </p>
            <div className={css.actions}>
              <button type="button" style={cta.primary}
                disabled={busy || record.status === 'WITHDRAWN'} onClick={startMonitoring}>
                Start monitoring
              </button>
              <button type="button" style={cta.secondary} disabled={busy} onClick={reconcileMonitoring}>
                Reconcile Stripe status
              </button>
            </div>
          </div>
        </>
      )}

      <div aria-live="polite" className={css.status} style={{
        padding: 16, border: `1px solid ${color.border}`, borderRadius: radius.base, color: color.t2,
      }}>{status}</div>
    </div>
  );
}
