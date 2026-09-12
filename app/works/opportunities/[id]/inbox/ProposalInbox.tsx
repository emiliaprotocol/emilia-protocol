// SPDX-License-Identifier: Apache-2.0
'use client';

import Link from 'next/link';
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import { createInboxRequestFence, loadOpportunityInbox, type InboxPageResult } from './inbox-client';
import styles from './inbox.module.css';
import WorksAccountAccess, { useWorksAccount } from '../../../WorksAccountAccess';

const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;

export default function ProposalInbox({ opportunityId }: { opportunityId: string }) {
  const access = useWorksAccount();
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [apiKey, setApiKey] = useState('');
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState('');
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState<(InboxPageResult & { checkedAt: string }) | null>(null);
  const fence = useRef<ReturnType<typeof createInboxRequestFence> | null>(null);
  if (fence.current === null) fence.current = createInboxRequestFence();

  function clear(resetPage = true) {
    fence.current!.cancel();
    setApiKey('');
    setPending(false);
    setNotice('');
    setResult(null);
    if (resetPage) setOffset(0);
  }

  useEffect(() => {
    function hide() {
      if (document.visibilityState === 'hidden') {
        fence.current!.cancel();
        setApiKey('');
        setPending(false);
        setResult(null);
        setNotice('The private view was cleared when you left the page. Enter your key to load it again.');
      }
    }
    function leave() { fence.current!.cancel(); setApiKey(''); setPending(false); setResult(null); }
    document.addEventListener('visibilitychange', hide);
    window.addEventListener('pagehide', leave);
    return () => { document.removeEventListener('visibilitychange', hide); window.removeEventListener('pagehide', leave); fence.current!.cancel(); };
  }, [opportunityId]);

  async function load(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    const key = access.account ? null : apiKey.trim();
    clear(false);
    const request = fence.current!.begin();
    setPending(true);
    try {
      const page = await loadOpportunityInbox(opportunityId, key, request.signal, offset);
      if (!request.isCurrent()) return;
      setResult({ ...page, checkedAt: new Date().toISOString() });
    } catch (error) {
      if (!request.isCurrent()) return;
      const code = error instanceof Error ? error.message : '';
      setNotice(code === 'inbox_access_refused'
        ? 'This inbox is not available to that key. Use the key that posted the opportunity, or check the opportunity link.'
        : code === 'inbox_rate_limited' ? 'Too many requests. Wait a minute, then enter your key again.'
          : code === 'inbox_input_invalid' ? 'Enter a valid EMILIA API key. Nothing was sent.'
            : 'Responses could not be loaded. This does not mean there are no proposals. Please try again.');
    } finally {
      if (request.isCurrent()) setPending(false);
    }
  }

  return <section className={styles.inbox}>
    <h2>Open your private proposal inbox.</h2>
    <p>See who has responded, read their approach and open the proposed agent’s listing. Use the account that posted this job.</p>
    <p className={styles.note}>The server checks that the key belongs to the opportunity owner or an authorized administrator before returning proposals. A proposal is not an agreed assignment or a payment.</p>
    <noscript><p>The private inbox needs JavaScript to keep credentials out of page navigation. Enable it before entering a key.</p></noscript>
    <WorksAccountAccess access={access} />
    <form method="post" onSubmit={load} className={styles.form}>
      <fieldset disabled={!ready}>
      {!access.account ? <><label htmlFor="proposal-inbox-key">Existing API key (or sign in above)</label>
      <input id="proposal-inbox-key" type="password" autoComplete="off" spellCheck={false} maxLength={512}
        value={apiKey} onChange={(event) => { clear(false); setApiKey(event.target.value); }}
        autoCapitalize="off" data-1p-ignore data-lpignore="true"
        placeholder="Your posting key" aria-describedby="proposal-key-help" /></> : null}
      <p id="proposal-key-help" className={styles.note}>Your key goes only to this site’s API, in an authentication header. It is not saved and clears after you request the inbox. Editing the key, clearing this view or leaving the tab hides the proposals.</p>
      {offset > 0 ? <p className={styles.note}>Page {offset / 50 + 1}. Enter your posting key again to load this page.</p> : null}
      <div className={styles.actions}>
        <button type="submit" disabled={!ready || pending || (!access.account && !apiKey.trim())}>{pending ? 'Loading…' : 'Load responses'}</button>
        <button type="button" onClick={() => clear()} className={styles.secondary}>Clear private view</button>
      </div>
      </fieldset>
    </form>
    <p className={styles.note}><Link href="/works/workspace">Open your workspace</Link> to select or decline a proposal and track agreed work.</p>
    <div aria-live="polite">
      {notice ? <p className={styles.notice} role="status">{notice}</p> : null}
      {result ? <><ProposalInboxResults {...result} />
        {(result.offset > 0 || result.has_more) ? <nav className={styles.actions} aria-label="Proposal pages">
          {result.offset > 0 ? <button type="button" className={styles.secondary} onClick={() => { clear(); setOffset(Math.max(0, result.offset - result.limit)); }}>Previous page</button> : null}
          {result.has_more && result.offset < 100_000 ? <button type="button" className={styles.secondary} onClick={() => { clear(); setOffset(result.offset + result.limit); }}>Next page</button> : null}
          <p className={styles.note}>Each page needs your key again. New responses may change the page order.</p>
        </nav> : null}</> : null}
    </div>
  </section>;
}

export function ProposalInboxResults({ records, checkedAt, access, offset, has_more }: InboxPageResult & { checkedAt: string }) {
  return <section className={styles.results} aria-labelledby="inbox-results-title">
    <p className={styles.eyebrow}>{access === 'owner' ? 'Opportunity owner access confirmed' : 'Authorized administrator access'}</p>
    <h2 id="inbox-results-title">{records.length ? `${records.length} ${records.length === 1 ? 'proposal' : 'proposals'} to review` : 'No proposals on this page yet.'}</h2>
    <p className={styles.note}>Page {offset / 50 + 1}, newest first. Loaded in this browser at <time dateTime={checkedAt}>{new Date(checkedAt).toLocaleString()}</time>. Enter your key again to refresh.</p>
    {!records.length ? <p>{offset === 0 ? 'Your inbox is open. Share the opportunity link with builders and check here for responses.' : 'There are no responses on this page. Return to an earlier page to continue.'}</p> : null}
    {has_more ? <p className={styles.note}>More proposals are available on the next page.</p> : null}
    {records.map((record) => <article key={record.submission_id} className={styles.proposal}>
      <p className={styles.meta}>{record.visibility === 'private' ? 'Private response' : 'Public response'} · {record.submission_id}</p>
      <h3>{record.builder_id}</h3>
      <p className={styles.proposalText}>{record.proposal}</p>
      {record.team.length ? <p className={styles.note}>Team names supplied: {record.team.join(', ')}</p> : null}
      {record.created_at ? <p className={styles.note}>Posted {record.created_at}</p> : null}
      <div className={styles.candidateLinks}><Link href={`/works/builders/${record.builder_id}`} prefetch={false}>View builder and contact details</Link>
        {record.listing_id ? <Link href={`/works/listings/${record.listing_id}`} prefetch={false}>Inspect proposed agent: {record.listing_id}</Link> : null}</div>
    </article>)}
    {records.length ? <p className={styles.nextStep}>Next, discuss the scope with the builder: name the owner, deliverable, limits and acceptance criteria. Opening a profile or reviewing a proposal does not hire an agent or grant it access.</p> : null}
  </section>;
}
