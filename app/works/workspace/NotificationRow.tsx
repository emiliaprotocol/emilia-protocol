// SPDX-License-Identifier: Apache-2.0
'use client';
import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import type { WorksNotification } from '@/lib/works/workflow-model';
import { createWorkspaceFence, prepareNotificationRead, sendNotificationRead, workspaceMessage,
  type NotificationReadConfirmation, type NotificationReadIntent } from '../workspace-client';
import styles from './workspace.module.css';

const titles: Record<WorksNotification['kind'], string> = {
  proposal_received: 'New proposal received', proposal_declined: 'Proposal declined', proposal_selected: 'Assignment proposed',
  assignment_confirmed: 'Builder confirmed the assignment', assignment_declined: 'Builder declined the assignment',
  delivery_submitted: 'Work is ready to review', changes_requested: 'Changes requested',
  completion_accepted: 'Completed work accepted', assignment_cancelled: 'Assignment cancelled',
};

export default function NotificationRow({ notification, disabled = false, onConfirmed, onReload }: {
  notification: WorksNotification; disabled?: boolean;
  onConfirmed: (result: NotificationReadConfirmation) => void; onReload: () => void;
}) {
  const [busy, setBusy] = useState(false); const [attempted, setAttempted] = useState(false); const [error, setError] = useState('');
  const requestFence = useRef(createWorkspaceFence()); const inFlight = useRef(false);
  const intent = useRef<NotificationReadIntent | null>(null);
  useEffect(() => { const fence = requestFence.current; return () => fence.cancel(); }, []);

  async function markRead() {
    if (disabled || notification.read_at || inFlight.current || document.visibilityState === 'hidden') return;
    inFlight.current = true; const request = requestFence.current.begin(); setBusy(true); setError('');
    try {
      // Create once on the explicit click. Failed requests retain this exact body.
      if (!intent.current) intent.current = prepareNotificationRead(notification.notification_id,
        { expected_revision: notification.revision, idempotency_key: crypto.randomUUID() });
      setAttempted(true);
      const result = await sendNotificationRead(intent.current, request.signal);
      if (request.isCurrent()) onConfirmed(result);
    } catch (caught) { if (request.isCurrent()) setError(workspaceMessage(caught)); }
    finally { if (request.isCurrent()) { inFlight.current = false; setBusy(false); } }
  }

  return <article className={styles.row} aria-labelledby={`update-${notification.notification_id}`}>
    <div className={styles.rowHeader}><h3 id={`update-${notification.notification_id}`}>{titles[notification.kind]}</h3>
      <span className={styles.status}>{notification.read_at ? 'Read' : 'Unread'}</span></div>
    <p className={styles.meta}><time dateTime={notification.created_at}>{new Date(notification.created_at).toLocaleString()}</time></p>
    <div className={`${styles.actions} ${styles.notificationActions}`}>
      <Link href={notification.resource_type === 'assignment' ? `/works/assignments/${notification.resource_id}` : `/works/submissions/${notification.resource_id}`} className={styles.quiet}>Open {notification.resource_type}</Link>
      {!notification.read_at ? <button type="button" className={styles.secondary} aria-describedby={`update-${notification.notification_id}`} onClick={() => void markRead()} disabled={disabled || busy}>
        {busy ? 'Marking as read…' : attempted ? 'Retry marking as read' : 'Mark as read'}
      </button> : <p className={styles.note}>Marked as read <time dateTime={notification.read_at}>{new Date(notification.read_at).toLocaleString()}</time></p>}
    </div>
    {error ? <div role="alert" className={`${styles.notice} ${styles.error}`}><p>Read status was not confirmed. {error}</p>
      <p className={styles.note}>Retrying keeps the same notification, revision and request ID.</p>
      <button type="button" className={styles.quiet} disabled={busy} onClick={onReload}>Check current updates</button>
    </div> : null}
  </article>;
}
