// SPDX-License-Identifier: Apache-2.0
'use client';
import { useEffect, useRef, useState } from 'react';
import { createWorkspaceFence, sendWorkflowIntent, workspaceMessage, type WorkflowIntent, type CommandConfirmation } from '../workspace-client';
import styles from './workspace.module.css';

export default function CommandReview({ title, description, intent, onCancel, onConfirmed, onReload }: {
  title: string; description: string; intent: WorkflowIntent; onCancel: () => void;
  onConfirmed: (result: CommandConfirmation) => void;
  onReload: () => void;
}) {
  const [consent, setConsent] = useState(false); const [busy, setBusy] = useState(false);
  const [attempted, setAttempted] = useState(false); const [error, setError] = useState('');
  const heading = useRef<HTMLHeadingElement>(null); const fence = useRef(createWorkspaceFence());
  useEffect(() => { heading.current?.focus(); const requests = fence.current; return () => requests.cancel(); }, []);
  async function confirm() {
    if (!consent || busy || document.visibilityState === 'hidden') return;
    const request = fence.current.begin(); setBusy(true); setAttempted(true); setError('');
    try { const result = await sendWorkflowIntent(intent, request.signal); if (request.isCurrent()) onConfirmed(result); }
    catch (caught) { if (request.isCurrent()) setError(workspaceMessage(caught)); }
    finally { if (request.isCurrent()) setBusy(false); }
  }
  return <section className={styles.review} aria-labelledby="command-review-title">
    <p className={styles.eyebrow}>Review your decision</p>
    <h2 id="command-review-title" ref={heading} tabIndex={-1}>{title}</h2>
    <p className={styles.reviewText}>{description}</p>
    <p className={styles.note}>Record {intent.id}. Reviewing revision {intent.body.expected_revision}. A newer change will require another review.</p>
    <label className={styles.consent}><input type="checkbox" checked={consent} disabled={busy} onChange={event => setConsent(event.target.checked)} /><span>I have reviewed this decision and the exact details shown above.</span></label>
    <div className={styles.actions}><button type="button" className={styles.button} disabled={!consent || busy} onClick={confirm}>{busy ? 'Confirming…' : attempted ? 'Retry this exact request' : 'Confirm decision'}</button>
      {!attempted ? <button type="button" className={styles.secondary} onClick={onCancel}>Go back</button> : null}</div>
    {attempted ? <p className={styles.note}>If the response is interrupted, this request keeps the same details and retry ID. Do not create another request to repeat this decision.</p> : null}
    {error ? <p role="alert" className={`${styles.notice} ${styles.error}`}>{error}</p> : null}
    {error && !busy ? <><button type="button" className={styles.quiet} onClick={onReload}>Check the latest record</button><p className={styles.note}>This reads the current state. It does not repeat your decision.</p></> : null}
  </section>;
}
