// SPDX-License-Identifier: Apache-2.0
'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import { validWorksId } from '@/lib/works/model';
import { createProposalRequestFence, type ProposalResult } from './proposal-client';
import styles from './proposal.module.css';

const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;

export function ProposalFinder() {
  const router = useRouter();
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [submissionId, setSubmissionId] = useState('');
  const [notice, setNotice] = useState('');
  function open(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    const id = submissionId.trim();
    if (!validWorksId(id)) { setNotice('Enter the proposal ID shown when you sent your response.'); return; }
    router.push(`/works/submissions/${id}`);
  }
  return <section className={styles.panel}>
    <p>Enter the proposal ID shown after you sent a response. You’ll enter your API key on the next page.</p>
    <form method="post" onSubmit={open} className={styles.form}>
      <fieldset disabled={!ready}>
        <label htmlFor="find-proposal-id">Proposal ID</label>
        <input id="find-proposal-id" value={submissionId} onChange={(event) => { setSubmissionId(event.target.value); setNotice(''); }}
          required minLength={3} maxLength={64} pattern="[a-z0-9](?:[a-z0-9]|-){2,63}" autoComplete="off"
          spellCheck={false} autoCapitalize="off" placeholder="submission-…" />
        <div className={styles.actions}><button type="submit" disabled={!ready || !submissionId.trim()}>Continue to proposal</button></div>
      </fieldset>
    </form>
    {notice ? <p role="alert" className={styles.notice}>{notice}</p> : null}
    <noscript><p>Enable JavaScript to find a proposal. Don’t put your API key into a page address.</p></noscript>
    <p className={styles.note}>Looking for responses to a job you posted? Open that job’s proposal inbox instead.</p>
    <Link href="/works/opportunities">Find your job</Link>
  </section>;
}

export default function ProposalLookup({ submissionId }: { submissionId: string }) {
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [apiKey, setApiKey] = useState('');
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState('');
  const [result, setResult] = useState<{ record: ProposalResult; checkedAt: string } | null>(null);
  const fence = useRef<ReturnType<typeof createProposalRequestFence> | null>(null);
  if (fence.current === null) fence.current = createProposalRequestFence();

  function clear() {
    fence.current!.cancel();
    setApiKey('');
    setPending(false);
    setNotice('');
    setResult(null);
  }

  useEffect(() => {
    const requests = fence.current!;
    function leave() { requests.cancel(); setApiKey(''); setPending(false); setResult(null); setNotice(''); }
    function hide() {
      if (document.visibilityState === 'hidden') {
        leave();
        setNotice('The private view was cleared when you left the tab. Enter your key to open it again.');
      }
    }
    document.addEventListener('visibilitychange', hide);
    window.addEventListener('pagehide', leave);
    return () => { document.removeEventListener('visibilitychange', hide); window.removeEventListener('pagehide', leave); requests.cancel(); };
  }, [submissionId]);

  async function load(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || document.visibilityState === 'hidden') return;
    const key = apiKey.trim();
    clear();
    const request = fence.current!.begin();
    setPending(true);
    try {
      const loaded = await request.load(submissionId, key);
      if (!request.isCurrent() || !loaded) return;
      setResult({ record: loaded, checkedAt: new Date().toISOString() });
    } catch (error) {
      if (!request.isCurrent()) return;
      const code = error instanceof Error ? error.message : '';
      setNotice(code === 'proposal_access_refused'
        ? 'This proposal is not available to that key. Check the proposal ID and use the key that sent it or owns the job. We haven’t confirmed whether the proposal exists.'
        : code === 'proposal_rate_limited' ? 'Too many requests. Wait a minute, then enter your key again.'
          : code === 'proposal_input_invalid' ? 'Enter a valid EMILIA API key. Nothing was sent.'
            : 'We couldn’t load the proposal. This does not mean it is missing. Enter your key to try again.');
    } finally {
      if (request.isCurrent()) setPending(false);
    }
  }

  return <section className={styles.panel}>
    <p className={styles.recordId}>Proposal ID <code>{submissionId}</code></p>
    <p>You can bookmark this page. The link contains only the proposal ID; it doesn’t grant access to a private response.</p>
    <p className={styles.note}>For a private response, the server checks that your key belongs to the proposal author, the job owner or an authorized administrator. A public proposal remains publicly available.</p>
    <noscript><p>This view needs JavaScript to keep your key out of page navigation. Enable it before entering a key.</p></noscript>
    <form method="post" onSubmit={load} className={styles.form}>
      <fieldset disabled={!ready}>
        <label htmlFor="proposal-lookup-key">EMILIA API key</label>
        <input id="proposal-lookup-key" type="password" autoComplete="off" spellCheck={false} autoCapitalize="off"
          value={apiKey} onChange={(event) => { clear(); setApiKey(event.target.value); }} required maxLength={512}
          data-1p-ignore data-lpignore="true" placeholder="Your author or job-owner key" aria-describedby="proposal-lookup-help" />
        <p id="proposal-lookup-help" className={styles.note}>Your key goes only to this site’s API in an authentication header. It is not saved and clears after each request. Editing the key, clearing this view or leaving the tab hides the proposal.</p>
        <div className={styles.actions}>
          <button type="submit" disabled={!ready || pending || !apiKey.trim()}>{pending ? 'Opening…' : 'Open proposal'}</button>
          <button type="button" onClick={clear} className={styles.secondary}>Clear private view</button>
        </div>
      </fieldset>
    </form>
    <div aria-live="polite">
      {notice ? <p role="status" className={styles.notice}>{notice}</p> : null}
      {result ? <ProposalResults {...result} /> : null}
    </div>
  </section>;
}

export function ProposalResults({ record, checkedAt }: { record: ProposalResult; checkedAt: string }) {
  return <article className={styles.results} aria-labelledby="recorded-proposal-title">
    <p className={styles.eyebrow}>{record.visibility === 'private' ? 'Private proposal' : 'Public proposal'}</p>
    <h2 id="recorded-proposal-title">Recorded proposal</h2>
    <p className={styles.note}>Loaded at <time dateTime={checkedAt}>{new Date(checkedAt).toLocaleString()}</time>. This confirms the record; it does not mean the job owner has read or accepted it.</p>
    <p className={styles.proposalText}>{record.proposal}</p>
    {record.team.length ? <p className={styles.note}>Team names supplied: {record.team.join(', ')}</p> : null}
    {record.created_at ? <p className={styles.note}>Posted <time dateTime={record.created_at}>{new Date(record.created_at).toLocaleString()}</time>.</p> : null}
    <nav className={styles.links} aria-label="Proposal context">
      <Link href={`/works/opportunities/${record.opportunity_id}`} prefetch={false}>View the job and contact its owner</Link>
      <Link href={`/works/builders/${record.builder_id}`} prefetch={false}>View builder profile</Link>
      {record.listing_id ? <Link href={`/works/listings/${record.listing_id}`} prefetch={false}>View proposed agent</Link> : null}
    </nav>
    <p className={styles.nextStep}>Agree on the work, limits and terms before starting. This proposal does not hire an agent, grant it access or make a payment.</p>
  </article>;
}
