// SPDX-License-Identifier: Apache-2.0
'use client';
import Link from 'next/link';
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import type { WorksAssignmentCommand, WorksAssignmentState } from '@/lib/works/workflow-model';
import { createWorkspaceFence, loadAssignment, prepareWorkflowIntent, workspaceMessage, type AssignmentView, type WorkflowIntent } from '../../workspace-client';
import CommandReview from '../../workspace/CommandReview';
import { Status } from '../../workspace/Workspace';
import styles from '../../workspace/workspace.module.css';

const subscribe = () => () => {}; const client = () => true; const server = () => false;
const commandNames: Record<WorksAssignmentCommand, string> = {
  builder_confirm: 'Confirm this assignment', builder_decline: 'Decline this assignment', submit_delivery: 'Submit work for review',
  request_changes: 'Request changes', accept_completion: 'Accept completed work', cancel: 'Cancel this assignment',
};
export function availableAssignmentCommands(role: 'buyer' | 'builder', state: WorksAssignmentState): WorksAssignmentCommand[] {
  if (state === 'completed' || state === 'cancelled' || state === 'declined') return [];
  if (role === 'builder') {
    if (state === 'proposed') return ['builder_confirm', 'builder_decline'];
    if (state === 'confirmed' || state === 'changes_requested') return ['submit_delivery', 'cancel'];
    return ['cancel'];
  }
  if (state === 'delivery_submitted') return ['accept_completion', 'request_changes', 'cancel'];
  return ['cancel'];
}

export default function Assignment({ assignmentId }: { assignmentId: string }) {
  const ready = useSyncExternalStore(subscribe, client, server);
  const [view, setView] = useState<AssignmentView | null>(null); const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(''); const [command, setCommand] = useState<WorksAssignmentCommand | null>(null);
  const [decision, setDecision] = useState<{ title: string; description: string; intent: WorkflowIntent } | null>(null);
  const fence = useRef(createWorkspaceFence()); const loading = useRef(false);
  useEffect(() => {
    const requests = fence.current;
    function leave() { requests.cancel(); loading.current = false; setView(null); setDecision(null); setCommand(null); setBusy(false); setNotice('Private details were cleared. Open the assignment again to check the latest state.'); }
    function hide() { if (document.visibilityState === 'hidden') leave(); }
    document.addEventListener('visibilitychange', hide); window.addEventListener('pagehide', leave);
    return () => { requests.cancel(); document.removeEventListener('visibilitychange', hide); window.removeEventListener('pagehide', leave); };
  }, [assignmentId]);
  async function refresh(message = '') {
    if (!ready || loading.current || document.visibilityState === 'hidden') return;
    const request = fence.current.begin(); loading.current = true; setBusy(true); setView(null); setDecision(null); setCommand(null); setNotice(message);
    try { const result = await loadAssignment(assignmentId, request.signal); if (request.isCurrent()) setView(result); }
    catch (caught) { if (request.isCurrent()) setNotice(`${message ? `${message} ` : ''}${workspaceMessage(caught)}`); }
    finally { if (request.isCurrent()) { loading.current = false; setBusy(false); } }
  }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!view || !command || decision) return;
    const data = new FormData(event.currentTarget); const summary = String(data.get('summary') || '').trim(); const reason = String(data.get('reason') || '').trim(); const deliveryUrl = String(data.get('deliveryUrl') || '').trim();
    const assignment = view.assignment;
    try {
      const intent = prepareWorkflowIntent('assignment', assignmentId, { command, expected_revision: assignment.revision, idempotency_key: crypto.randomUUID(),
        ...(command === 'submit_delivery' ? { delivery_url: deliveryUrl, summary } : {}),
        ...(command === 'request_changes' || (command === 'accept_completion' && summary) ? { summary } : {}), ...(command === 'cancel' ? { reason } : {}) });
      const submitted = command === 'submit_delivery' ? `\n\nDelivery link\n${deliveryUrl}\n\nDelivery summary\n${summary}` : command === 'cancel' ? `\n\nReason\n${reason}` : summary ? `\n\nReview note\n${summary}` : '';
      setDecision({ title: commandNames[command], intent,
        description: `Assignment: ${assignmentId}\n\nFrozen scope\n${assignment.scope}\n\nAcceptance criteria\n${assignment.acceptance_criteria.map((item, index) => `${index + 1}. ${item}`).join('\n')}\n\nTerms reference\n${assignment.terms}${submitted}\n\n${command === 'accept_completion' ? 'You are recording the job owner’s acceptance of this delivered work. This is not an independent quality rating or a payment.' : command === 'cancel' ? 'Cancellation records the end of this assignment. It does not revoke runtime credentials or undo work already performed.' : 'This decision records the assignment workflow. It does not grant runtime permissions or process payment.'}` });
      setCommand(null); setNotice('');
    } catch (caught) { setNotice(workspaceMessage(caught)); }
  }
  return <div>
    {!view ? <section className={styles.welcome}><h2>Open the assignment record</h2><p>The buyer and builder can review this record with their own signed-in accounts. The page address alone does not grant access.</p>
      <div className={styles.actions}><button className={styles.button} type="button" disabled={!ready || busy} onClick={() => void refresh()}>{busy ? 'Opening…' : 'Open assignment'}</button><Link href="/works/account" className={styles.secondary}>Sign in</Link></div></section> : <>
      <div className={styles.toolbar}><p>You are viewing as the {view.viewer_role} · Revision {view.assignment.revision}</p><button type="button" className={styles.quiet} disabled={Boolean(decision)} onClick={() => void refresh()}>Refresh record</button></div>
      <AssignmentRecord view={view} />
      {availableAssignmentCommands(view.viewer_role, view.assignment.state).length ? <section className={styles.review} aria-labelledby="assignment-next"><p className={styles.eyebrow}>Next decision</p><h2 id="assignment-next">{view.viewer_role === 'builder' ? 'Your work, your commitment.' : 'Review before you accept.'}</h2>
        <p>{view.assignment.state === 'proposed' ? 'The scope is frozen. The builder must confirm it before the assignment moves forward.' : 'Use the agreed acceptance criteria. A delivery link records what the builder submitted; it does not prove the work is correct.'}</p>
        <div className={styles.actions}>{availableAssignmentCommands(view.viewer_role, view.assignment.state).map((choice, index) => <button key={choice} type="button" disabled={Boolean(decision)} className={index === 0 ? styles.button : styles.secondary} onClick={() => { setCommand(choice); setNotice(''); }}>{commandNames[choice]}</button>)}</div>
      </section> : <p className={styles.notice}>This assignment is {view.assignment.state.replaceAll('_', ' ')}. Its record remains available; there is no new decision to submit.</p>}
      {command ? <form method="post" className={styles.review} onSubmit={prepare}><h2>{commandNames[command]}</h2><fieldset className={styles.fields}><legend className={styles.srOnly}>Decision details</legend>
        {command === 'submit_delivery' ? <label className={styles.field}>Delivery link<span className={styles.note}>Use an HTTPS link the job owner can access. Do not put credentials or private access tokens in the URL.</span><input name="deliveryUrl" type="url" required maxLength={600} placeholder="https://…" /></label> : null}
        {command === 'submit_delivery' || command === 'request_changes' || command === 'accept_completion' ? <label className={styles.field}>{command === 'submit_delivery' ? 'What did you deliver?' : command === 'request_changes' ? 'What needs to change?' : 'Acceptance note (optional)'}<textarea name="summary" required={command !== 'accept_completion'} maxLength={8000} rows={4} /></label> : null}
        {command === 'cancel' ? <label className={styles.field}>Why is this assignment ending?<textarea name="reason" required maxLength={2000} rows={3} /></label> : null}
        <div className={styles.actions}><button type="submit" className={styles.button}>Review decision</button><button type="button" className={styles.secondary} onClick={() => setCommand(null)}>Go back</button></div>
      </fieldset></form> : null}
      {decision ? <CommandReview {...decision} key={decision.intent.body.idempotency_key} onCancel={() => setDecision(null)} onConfirmed={() => void refresh('Your decision is recorded.')} onReload={() => void refresh('Checking the current record. This does not repeat the earlier decision.')} /> : null}
    </>}
    {notice ? <p role="status" className={styles.notice}>{notice}</p> : null}
    <p className={styles.boundary}>Assignments do not grant runtime authority. Configure credentials, limits and any Gate enforcement separately. No money is held or moved here, and the owner’s review is not a certification.</p>
  </div>;
}

export function AssignmentRecord({ view }: { view: AssignmentView }) {
  const assignment = view.assignment;
  return <article className={styles.row}>
    <div className={styles.rowHeader}><h3>{String(assignment.frozen.job.title)}</h3><Status value={assignment.state} /></div>
    <p className={styles.meta}>Assignment {assignment.assignment_id} · Builder {assignment.builder_id}</p>
    <dl className={styles.facts}><div><dt>Frozen scope</dt><dd>{assignment.scope}</dd></div>
      <div><dt>Acceptance criteria</dt><dd><ol>{assignment.acceptance_criteria.map((criterion, index) => <li key={index}>{criterion}</li>)}</ol></dd></div>
      <div><dt>Terms reference</dt><dd>{assignment.terms}</dd></div>
      <div><dt>Original job</dt><dd>{String(assignment.frozen.job.description)}</dd></div>
      <div><dt>Original proposal</dt><dd>{String(assignment.frozen.proposal.proposal)}</dd></div></dl>
    {assignment.delivery ? <section><h3>Latest submitted work</h3><p className={styles.reviewText}>{assignment.delivery.summary}</p><a className={styles.quiet} href={assignment.delivery.url} target="_blank" rel="noopener noreferrer">Open delivery link</a>
      <p className={styles.note}>Submitted <time dateTime={assignment.delivery.submitted_at}>{new Date(assignment.delivery.submitted_at).toLocaleString()}</time>. This is a builder-supplied link; EMILIA does not execute or independently verify the delivery.</p></section> : <p className={styles.note}>No delivery has been submitted.</p>}
    {assignment.outcome ? <section className={styles.notice}><h3>Accepted by the job owner</h3>{assignment.outcome.summary ? <p>{assignment.outcome.summary}</p> : null}<p className={styles.note}><time dateTime={assignment.outcome.accepted_at}>{new Date(assignment.outcome.accepted_at).toLocaleString()}</time>. This records the owner’s review, not an independent rating or payment.</p></section> : null}
    <section aria-labelledby="assignment-history"><h3 id="assignment-history">Work record</h3>
      <p className={styles.note}>Decisions, change requests and deliveries recorded for this assignment.</p>
      <ol className={styles.timeline}>{assignment.history.map(event => <li key={event.revision}>
        <h3>{event.command === 'proposal_selected' ? 'Assignment proposed' : commandNames[event.command]}</h3>
        <p className={styles.meta}>{event.actor_role} · Revision {event.revision} · <time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time></p>
        {event.summary ? <p>{event.summary}</p> : null}{event.reason ? <p>{event.reason}</p> : null}
        {event.delivery ? <><p>{event.delivery.summary}</p><a className={styles.quiet} href={event.delivery.url} target="_blank" rel="noopener noreferrer">Open this delivery</a></> : null}
      </li>)}</ol>
    </section>
  </article>;
}
