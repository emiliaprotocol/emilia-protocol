// SPDX-License-Identifier: Apache-2.0
'use client';
import Link from 'next/link';
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent, type ReactNode } from 'react';
import type { WorksWorkspaceCommand } from '@/lib/works/workflow-model';
import { applyNotificationRead, createWorkspaceFence, loadWorkspace, prepareWorkflowIntent, workspaceMessage,
  type WorkspaceData, type WorkflowIntent, type ReceivedProposal, type CommandConfirmation, type NotificationReadConfirmation } from '../workspace-client';
import CommandReview from './CommandReview';
import NotificationRow from './NotificationRow';
import styles from './workspace.module.css';

const subscribe = () => () => {}; const client = () => true; const server = () => false;
type Tab = 'jobs' | 'agents' | 'proposals' | 'assignments' | 'updates';
type Decision = { title: string; description: string; intent: WorkflowIntent };
const labels: Record<WorksWorkspaceCommand, string> = {
  pause_listing: 'Pause this listing', archive_listing: 'Archive this listing', reactivate_listing: 'Reactivate this listing',
  close_job: 'Close this job to new proposals', reopen_job: 'Reopen this job', decline_proposal: 'Decline this proposal',
};

export default function Workspace() {
  const ready = useSyncExternalStore(subscribe, client, server);
  const [data, setData] = useState<WorkspaceData | null>(null); const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(''); const [checkedAt, setCheckedAt] = useState('');
  const [tab, setTab] = useState<Tab>('jobs'); const [decision, setDecision] = useState<Decision | null>(null);
  const [selection, setSelection] = useState<ReceivedProposal | null>(null);
  const requests = useRef(createWorkspaceFence()); const loading = useRef(false);
  useEffect(() => {
    const fence = requests.current;
    function leave() { fence.cancel(); loading.current = false; setData(null); setDecision(null); setSelection(null); setBusy(false); setCheckedAt(''); setNotice('Your private view was cleared. Open it again to check the latest records. An interrupted decision may already have been recorded.'); }
    function hide() { if (document.visibilityState === 'hidden') leave(); }
    document.addEventListener('visibilitychange', hide); window.addEventListener('pagehide', leave);
    return () => { fence.cancel(); document.removeEventListener('visibilitychange', hide); window.removeEventListener('pagehide', leave); };
  }, []);
  async function refresh(confirmation?: string) {
    if (!ready || loading.current || document.visibilityState === 'hidden') return;
    loading.current = true; const request = requests.current.begin(); setBusy(true); setData(null); setDecision(null); setSelection(null);
    setNotice(confirmation || '');
    try {
      const result = await loadWorkspace(request.signal); if (!request.isCurrent()) return;
      setData(result); setCheckedAt(new Date().toISOString());
      if (!checkedAt && result.viewer.role === 'builder') setTab('agents');
    } catch (caught) { if (request.isCurrent()) setNotice(`${confirmation ? `${confirmation} ` : ''}${workspaceMessage(caught)}`); }
    finally { if (request.isCurrent()) { loading.current = false; setBusy(false); } }
  }
  function stage(command: WorksWorkspaceCommand, recordId: string, revision: number, description: string) {
    if (decision || busy) return;
    setSelection(null); setNotice('');
    setDecision({ title: labels[command], description,
      intent: prepareWorkflowIntent('workspace', recordId, { command, record_id: recordId, expected_revision: revision, idempotency_key: crypto.randomUUID() }) });
  }
  function confirmed(result: CommandConfirmation) {
    void refresh(result.assignment ? 'The assignment proposal is recorded. The builder must confirm the frozen scope before work starts.' : 'Your decision is recorded.');
  }
  function notificationConfirmed(result: NotificationReadConfirmation) {
    setData(current => current ? applyNotificationRead(current, result) : null);
  }
  const canManage = Boolean(data && !busy && !decision && !selection);
  return <div>
    {!data ? <section className={styles.welcome}>
      <h2>Pick up where you left off.</h2>
      <p>Your workspace shows only the profiles, jobs, proposals and assignments available to your signed-in account.</p>
      <div className={styles.actions}><button type="button" className={styles.button} disabled={!ready || busy} onClick={() => void refresh()}>{busy ? 'Opening workspace…' : 'Open workspace'}</button>
        <Link href="/works/account" className={styles.secondary}>Sign in or create an account</Link></div>
      <noscript><p>Enable JavaScript to open your private workspace.</p></noscript>
    </section> : <>
      <div className={styles.toolbar}><p>{data.viewer.display_name || 'Your account'} · Checked <time dateTime={checkedAt}>{new Date(checkedAt).toLocaleTimeString()}</time></p>
        <div className={styles.actions}><button className={styles.quiet} type="button" disabled={busy || Boolean(decision)} onClick={() => void refresh()}>Refresh records</button><Link href="/works/account" className={styles.quiet}>Account</Link></div></div>
      <nav className={styles.tabs} aria-label="Workspace sections">
        {([['jobs', 'My jobs', data.jobs.length], ['agents', 'Agents', data.listings.length], ['proposals', 'Proposals', data.received_proposals.length + data.submitted_proposals.length], ['assignments', 'Assignments', data.assignments.length], ['updates', 'Updates', data.notifications.filter(item => item.read_at === null).length]] as const).map(([id, label, count]) => <button key={id} className={styles.tab} type="button" aria-pressed={tab === id} onClick={() => setTab(id)}>{label}<span aria-label={id === 'updates' ? `${count} unread updates` : undefined}>{count}</span></button>)}
      </nav>
      {tab === 'jobs' ? <section aria-labelledby="workspace-jobs">
        <SectionHeader id="workspace-jobs" title="Jobs you own" description="Describe the result you need, review proposals and decide when a job is ready to close."><Link href="/works/opportunities/new" className={styles.secondary}>Post a job</Link></SectionHeader>
        {data.jobs.length ? <div className={styles.list}>{data.jobs.map(({ record, workflow }) => <article className={styles.row} key={record.opportunity_id}>
          <div className={styles.rowHeader}><h3><Link href={`/works/opportunities/${record.opportunity_id}`}>{record.title}</Link></h3><Status value={workflow.state} /></div>
          <p>{record.description}</p><p className={styles.meta}>Revision {workflow.revision} · {record.contact_route}</p>
          <div className={styles.actions}><Link href={`/works/opportunities/${record.opportunity_id}/inbox`} className={styles.quiet}>Open proposal inbox</Link>
            {workflow.state === 'open' ? <button type="button" disabled={!canManage} className={styles.secondary} onClick={() => stage('close_job', record.opportunity_id, workflow.revision, `Stop accepting new proposals for “${record.title}”. Existing proposals and work records remain available.`)}>Close job</button> : workflow.state === 'closed' ? <button type="button" disabled={!canManage} className={styles.secondary} onClick={() => stage('reopen_job', record.opportunity_id, workflow.revision, `Accept new proposals for “${record.title}” again. This does not change an existing assignment or grant access to your systems.`)}>Reopen job</button> : null}</div>
        </article>)}</div> : <Empty title="No jobs yet" description="Start with one task. A clear result and a few boundaries help builders propose useful work." href="/works/opportunities/new" action="Describe your job" />}
      </section> : null}
      {tab === 'agents' ? <section aria-labelledby="workspace-agents">
        <SectionHeader id="workspace-agents" title="Your agent listings" description="Keep availability accurate. Pausing or archiving a listing does not revoke a running agent’s credentials."><Link href="/works/join" className={styles.secondary}>List an agent</Link></SectionHeader>
        {data.listings.length ? <div className={styles.list}>{data.listings.map(({ record, workflow }) => <article className={styles.row} key={record.listing_id}>
          <div className={styles.rowHeader}><h3><Link href={`/works/listings/${record.listing_id}`}>{record.name}</Link></h3><Status value={workflow.state} /></div><p>{record.summary}</p>
          <p className={styles.meta}>{record.supported_tasks.join(' · ')} · Revision {workflow.revision}</p>
          <div className={styles.actions}>{workflow.state === 'active' ? <button type="button" disabled={!canManage} className={styles.secondary} onClick={() => stage('pause_listing', record.listing_id, workflow.revision, `Pause “${record.name}” in the active directory. Existing assignments are unchanged.`)}>Pause listing</button> : <button type="button" disabled={!canManage} className={styles.secondary} onClick={() => stage('reactivate_listing', record.listing_id, workflow.revision, `Make “${record.name}” active in the directory again. This is your availability statement, not a verification of its performance.`)}>Reactivate listing</button>}
            {workflow.state !== 'archived' ? <button type="button" disabled={!canManage} className={styles.quiet} onClick={() => stage('archive_listing', record.listing_id, workflow.revision, `Archive “${record.name}”. Its record remains, and existing assignments are not cancelled.`)}>Archive listing</button> : null}</div>
        </article>)}</div> : <Empty title="No agent listings yet" description="Give companies a clear picture of the work your agent can do, who supports it and where its limits are." href="/works/join" action="List your agent" />}
        {data.profiles.length ? <p className={styles.note}>Your builder profiles: {data.profiles.map((profile, index) => <span key={profile.builder_id}>{index ? ', ' : ''}<Link href={`/works/builders/${profile.builder_id}`}>{profile.name}</Link></span>)}</p> : null}
      </section> : null}
      {tab === 'proposals' ? <section aria-labelledby="workspace-proposals">
        <SectionHeader id="workspace-proposals" title="Proposals" description="Review the proposed approach before defining an assignment. A proposal alone does not start work." />
        <h3>Received for your jobs</h3>
        {data.received_proposals.length ? <div className={styles.list}>{data.received_proposals.map(proposal => {
          const { record, workflow, job } = proposal; const ownedJob = data.jobs.find(item => item.record.opportunity_id === job.opportunity_id);
          return <article className={styles.row} key={record.submission_id}><div className={styles.rowHeader}><h3>{job.title}</h3><Status value={workflow.state} /></div>
            <p className={styles.reviewText}>{record.proposal}</p><p className={styles.meta}>Builder <Link href={`/works/builders/${record.builder_id}`}>{record.builder_id}</Link> · Proposal {record.submission_id}</p>
            {workflow.state === 'submitted' ? <div className={styles.actions}><button className={styles.button} type="button" disabled={!canManage || ownedJob?.workflow.state !== 'open'} onClick={() => { setSelection(proposal); setNotice(''); }}>Define assignment</button>
              <button type="button" className={styles.quiet} disabled={!canManage} onClick={() => stage('decline_proposal', record.submission_id, workflow.revision, `Decline proposal ${record.submission_id} for “${job.title}”. The proposal stays in the record. No assignment is created.`)}>Decline proposal</button></div> : null}
          </article>;
        })}</div> : <Empty title="No received proposals" description="Share the link to your posted job with builders. Proposals will appear here when submitted." href="/works/opportunities" action="Browse jobs" />}
        <h3>Sent by you</h3>
        {data.submitted_proposals.length ? <div className={styles.list}>{data.submitted_proposals.map(({ record, workflow }) => <article className={styles.row} key={record.submission_id}>
          <div className={styles.rowHeader}><h3><Link href={`/works/opportunities/${record.opportunity_id}`}>Job {record.opportunity_id}</Link></h3><Status value={workflow.state} /></div>
          <p className={styles.reviewText}>{record.proposal}</p><Link href={`/works/submissions/${record.submission_id}`} className={styles.quiet}>Open recorded proposal</Link>
        </article>)}</div> : <Empty title="No sent proposals" description="Find a job that fits your agent and propose an approach." href="/works/opportunities" action="Find work" />}
      </section> : null}
      {tab === 'assignments' ? <section aria-labelledby="workspace-assignments"><SectionHeader id="workspace-assignments" title="Assignments" description="A frozen scope, a builder’s confirmation and a result the job owner can review." />
        {data.assignments.length ? <div className={styles.list}>{data.assignments.map(({ assignment, viewer_role }) => <article className={styles.row} key={assignment.assignment_id}>
          <div className={styles.rowHeader}><h3><Link href={`/works/assignments/${assignment.assignment_id}`}>{String(assignment.frozen.job.title)}</Link></h3><Status value={assignment.state} /></div>
          <p>{assignment.scope}</p><p className={styles.meta}>You are the {viewer_role} · Revision {assignment.revision}</p>
          <Link href={`/works/assignments/${assignment.assignment_id}`} className={styles.secondary}>Review assignment</Link>
        </article>)}</div> : <Empty title="No assignments yet" description="A job owner defines the scope from a proposal. The builder then confirms the exact assignment before work starts." href="/works/opportunities" action="Find a job" />}</section> : null}
      <section hidden={tab !== 'updates'} aria-labelledby="workspace-updates"><SectionHeader id="workspace-updates" title="Updates" description="Recorded changes for this account. Marking an update as read does not accept a proposal or approve work. Email delivery is separate." />
        {data.notifications.length ? <div className={styles.list}>{data.notifications.map(item => <NotificationRow key={item.notification_id} notification={item} disabled={!canManage}
          onConfirmed={notificationConfirmed} onReload={() => void refresh('Checking current updates without repeating the read request.')} />)}</div>
          : <Empty title="You’re up to date" description="New proposals and assignment decisions will appear here." />}</section>
      {selection ? <SelectionDraft proposal={selection} jobRevision={data.jobs.find(item => item.record.opportunity_id === selection.job.opportunity_id)?.workflow.revision ?? -1}
        onCancel={() => setSelection(null)} onReview={next => { setSelection(null); setDecision(next); }} /> : null}
      {decision ? <CommandReview key={decision.intent.body.idempotency_key} {...decision} onCancel={() => setDecision(null)} onConfirmed={confirmed} onReload={() => void refresh('Checking the current record. This does not repeat the earlier decision.')} /> : null}
    </>}
    {notice ? <p role="status" className={styles.notice}>{notice}</p> : null}
    <p className={styles.boundary}>An assignment records agreed work. It does not grant an agent access, configure EMILIA Gate, transfer money or certify the result. Runtime permissions and commercial payment remain separate.</p>
  </div>;
}

function SelectionDraft({ proposal, jobRevision, onCancel, onReview }: {
  proposal: ReceivedProposal; jobRevision: number; onCancel: () => void; onReview: (decision: Decision) => void;
}) {
  const [error, setError] = useState(''); const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const fields = new FormData(event.currentTarget);
    const scope = String(fields.get('scope') || '').trim(); const criteria = String(fields.get('criteria') || '').split('\n').map(line => line.trim()).filter(Boolean); const terms = String(fields.get('terms') || '').trim();
    try {
      const intent = prepareWorkflowIntent('select', proposal.record.submission_id, { proposal_id: proposal.record.submission_id,
        expected_revision: jobRevision, idempotency_key: crypto.randomUUID(), scope, acceptance_criteria: criteria, terms });
      onReview({ title: `Propose an assignment for “${proposal.job.title}”`,
        description: `Builder: ${proposal.record.builder_id}\nProposal: ${proposal.record.submission_id}\n\nScope\n${scope}\n\nAcceptance criteria\n${criteria.map((item, index) => `${index + 1}. ${item}`).join('\n')}\n\nTerms reference\n${terms}\n\nThe builder must confirm these frozen details. This does not grant runtime authority or make a payment.`, intent });
    } catch (caught) { setError(workspaceMessage(caught)); }
  }
  return <section className={styles.review}><p className={styles.eyebrow}>Define the assignment</p><h2 ref={heading} tabIndex={-1}>{proposal.job.title}</h2>
    <p>Turn the proposal into a scope both sides can review. These details are frozen when you confirm; the builder can then accept or decline.</p>
    <form method="post" onSubmit={prepare}><fieldset className={styles.fields}><legend className={styles.srOnly}>Assignment details</legend>
      <label className={styles.field}>Scope and exclusions<textarea name="scope" required maxLength={8000} rows={5} placeholder="What will be delivered? What is not included?" /></label>
      <label className={styles.field}>Acceptance criteria<span className={styles.note}>One specific, reviewable criterion per line. Up to 32 criteria, 1,000 characters each.</span><textarea name="criteria" required maxLength={32032} rows={5} placeholder="The report covers all agreed accounts.&#10;Every exception includes a source reference." /></label>
      <label className={styles.field}>Commercial terms reference<span className={styles.note}>Summarize or reference terms agreed outside EMILIA. This field does not process a payment.</span><textarea name="terms" required maxLength={8000} rows={3} /></label>
      <div className={styles.actions}><button className={styles.button} type="submit">Review assignment</button><button type="button" className={styles.secondary} onClick={onCancel}>Go back</button></div>
    </fieldset></form>{error ? <p className={styles.notice} role="alert">{error}</p> : null}</section>;
}
export function Status({ value }: { value: string }) { return <span className={styles.status}>{value.replaceAll('_', ' ')}</span>; }
export function SectionHeader({ id, title, description, children }: { id: string; title: string; description: string; children?: ReactNode }) {
  return <div className={styles.sectionHeading}><div><h2 id={id}>{title}</h2><p>{description}</p></div>{children ? <div className={styles.actions}>{children}</div> : null}</div>;
}
export function Empty({ title, description, href, action }: { title: string; description: string; href?: string; action?: string }) {
  return <div className={styles.empty}><h3>{title}</h3><p>{description}</p>{href && action ? <Link href={href} className={styles.secondary}>{action}</Link> : null}</div>;
}
