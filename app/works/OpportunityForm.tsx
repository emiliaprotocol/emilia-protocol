// SPDX-License-Identifier: Apache-2.0
'use client';

import Link from 'next/link';
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent, type ReactNode } from 'react';
import type { OpportunityRecord } from '@/lib/works/model';
import type { OpportunityFormInput, SponsorClaimInput } from './form-payloads';
import { prepareOpportunityDraft, publishOpportunityWithRecovery } from './opportunity-publication';
import formStyles from './opportunity-form.module.css';

const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;
const value = (data: FormData, name: string) => String(data.get(name) || '').trim();

function claimInput(data: FormData, prefix: string): SponsorClaimInput {
  return {
    statement: value(data, `${prefix}Statement`), status: value(data, `${prefix}Status`) as SponsorClaimInput['status'],
    scope: value(data, `${prefix}Scope`), limitations: value(data, `${prefix}Limitations`),
  };
}

export default function OpportunityForm() {
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [jobId, setJobId] = useState('');
  const [contactRoute, setContactRoute] = useState('');
  const [draft, setDraft] = useState<OpportunityRecord | null>(null);
  const [publicConsent, setPublicConsent] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [attempted, setAttempted] = useState(false);
  const [posted, setPosted] = useState<OpportunityRecord | null>(null);
  const generation = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);
  const inFlight = useRef(false);
  const previewHeading = useRef<HTMLHeadingElement | null>(null);

  useEffect(() => {
    function cancelRequests() {
      generation.current++; activeRequest.current?.abort(); inFlight.current = false;
    }
    function clearPrivateState() {
      cancelRequests();
      setApiKey(''); setBusy(false); setPublicConsent(false);
    }
    function hide() { if (document.visibilityState === 'hidden') clearPrivateState(); }
    document.addEventListener('visibilitychange', hide);
    window.addEventListener('pagehide', clearPrivateState);
    return () => { cancelRequests(); document.removeEventListener('visibilitychange', hide); window.removeEventListener('pagehide', clearPrivateState); };
  }, []);
  useEffect(() => { if (draft) previewHeading.current?.focus(); }, [draft, posted]);

  function clearKey() {
    generation.current++; activeRequest.current?.abort(); inFlight.current = false;
    setApiKey(''); setBusy(false); setPublicConsent(false);
  }

  function preparePreview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || busy) return;
    if (attempted) return;
    const data = new FormData(event.currentTarget);
    const eligibility = claimInput(data, 'eligibility');
    if (eligibility.statement && !eligibility.scope) { setError('Add a scope for the eligibility statement, or leave it blank.'); return; }
    const title = value(data, 'title');
    const id = jobId || `${title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 45) || 'job'}-${crypto.randomUUID().slice(0, 8)}`;
    const input: OpportunityFormInput = {
      opportunityId: id, kind: value(data, 'kind') as OpportunityFormInput['kind'],
      title, description: value(data, 'description'), postedBy: '', contactRoute: value(data, 'contactRoute'),
      funding: claimInput(data, 'funding'), authority: claimInput(data, 'authority'),
      eligibility: eligibility.statement ? eligibility : null,
    };
    try {
      const preview = prepareOpportunityDraft(input);
      setContactRoute(preview.contact_route);
      setJobId(id); setDraft(preview); setPublicConsent(false); setError('');
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Check the job details before previewing.'); }
  }

  async function handlePublish(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || inFlight.current) return;
    if (!draft || !publicConsent) { setError('Review the preview and agree to make these details public first.'); return; }
    if (!apiKey.trim()) { setError('Enter your EMILIA key to publish, or request access below.'); return; }
    const requestKey = apiKey.trim();
    setApiKey(''); setPublicConsent(false);
    inFlight.current = true; setBusy(true); setAttempted(true); setError('');
    const current = ++generation.current;
    const controller = new AbortController(); activeRequest.current = controller;
    const isCurrent = () => current === generation.current && !controller.signal.aborted;
    try {
      const record = await publishOpportunityWithRecovery(requestKey, draft, controller.signal);
      if (!isCurrent()) return;
      setPosted(record); setApiKey(''); setPublicConsent(false);
    } catch (caught) {
      if (isCurrent()) {
        setError(caught instanceof Error ? caught.message : 'Job publication could not be confirmed.');
      }
    } finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }

  if (posted) return <section className={formStyles.result} aria-labelledby="opportunity-posted">
    <p className={formStyles.eyebrow}>Published</p>
    <h2 id="opportunity-posted" ref={previewHeading} tabIndex={-1}>Your job is ready for proposals.</h2>
    <p><strong>{posted.title}</strong> is public under {posted.posted_by}. Share the job link with builders, then check your proposal inbox with the same account key.</p>
    <div className={formStyles.actions}>
      <Link href={`/works/opportunities/${posted.opportunity_id}/inbox`} className={formStyles.primary}>Open proposal inbox</Link>
      <Link href={`/works/opportunities/${posted.opportunity_id}`} className={formStyles.secondary}>View and share job</Link>
    </div>
    <p className={formStyles.note}>No one has been hired and no payment has been taken. Works does not send email notifications for proposals. Your key has been cleared from this page.</p>
  </section>;

  return <div className={formStyles.intake}>
    <noscript><p>JavaScript is required to prepare and publish a job securely. The form stays disabled until it is ready.</p></noscript>
    <form method="post" className={formStyles.form} onSubmit={preparePreview} hidden={Boolean(draft)}>
      <fieldset disabled={!ready || busy} className={formStyles.fields}>
        <legend className={formStyles.srOnly}>Describe your job</legend>
        <Field label="What needs doing?" hint="Give the job a clear, specific title.">
          <input name="title" required maxLength={200} placeholder="Review refund requests before our finance team pays them" />
        </Field>
        <Field label="What would a good result look like?" hint="Include the deliverable, what is out of scope and what a proposal should cover. Keep confidential details out.">
          <textarea name="description" required maxLength={8000} rows={7} placeholder={'We need a daily review queue for refund requests.\n\nFlag exceptions against our policy. Do not issue refunds or change customer records.\n\nTell us how your agent connects, what needs human review and what it would cost.'} />
        </Field>
        <Field label="How can builders reach you?" hint="This contact will be public. Use a work email as mailto:you@example.com or an https:// contact page.">
          <input name="contactRoute" required maxLength={600} placeholder="mailto:finance@example.com" value={contactRoute} onChange={event => setContactRoute(event.target.value)} />
        </Field>
        <p className={formStyles.note}>Your authenticated account name will be shown as the poster. Publishing does not grant an agent access to your systems or authority to act.</p>
        <details className={formStyles.advanced}>
          <summary>Budget, authority and other details</summary>
          <p className={formStyles.note}>Funding and sponsor authority start as UNKNOWN. Add only what you can stand behind. ASSERTED means it is your statement, not independently verified.</p>
          <div className={formStyles.gridTwo}>
            <Field label="Job type"><select name="kind" defaultValue="problem"><option value="problem">Problem to solve</option><option value="challenge">Challenge</option><option value="bounty">Bounty</option><option value="procurement_notice">Procurement notice</option><option value="collaboration">Collaboration</option></select></Field>
            <Field label="Job ID" hint="We generate your public URL when you preview. You can choose one instead: 3–64 lowercase letters, numbers or hyphens."><input name="opportunityId" value={jobId} onChange={event => setJobId(event.target.value)} minLength={3} maxLength={64} pattern="[a-z0-9](?:[a-z0-9]|-){2,63}" placeholder="Generated for you" autoComplete="off" /></Field>
          </div>
          <ClaimFields prefix="funding" title="Funding" initialStatement="Funding has not been established." />
          <ClaimFields prefix="authority" title="Sponsor authority" initialStatement="The sponsor's procurement authority has not been established." />
          <ClaimFields prefix="eligibility" title="Eligibility" optional />
          <p className={formStyles.note}>These statements do not create payment, escrow or procurement authority. This form cannot award VERIFIED status.</p>
        </details>
        <div className={formStyles.actions}><button type="submit" disabled={!ready || busy} className={formStyles.primary}>Preview my job</button><Link href="/works/opportunities" className={formStyles.textLink}>Back to jobs</Link></div>
        <p className={formStyles.note}>Nothing is sent or published when you preview. Your draft stays only in this open page and is lost if you reload or leave.</p>
      </fieldset>
    </form>

    {draft ? <section className={formStyles.preview} aria-labelledby="job-preview">
      <p className={formStyles.eyebrow}>Review before publishing</p>
      <h2 id="job-preview" ref={previewHeading} tabIndex={-1}>{draft.title}</h2>
      <p className={formStyles.description}>{draft.description}</p>
      <dl className={formStyles.details}><div><dt>Public contact</dt><dd>{draft.contact_route}</dd></div><div><dt>Posted by</dt><dd>Your authenticated account name, set when published</dd></div><div><dt>Job type</dt><dd>{draft.kind.replaceAll('_', ' ')}</dd></div><div><dt>Public job ID</dt><dd>{draft.opportunity_id}</dd></div></dl>
      <div className={formStyles.claims}>{draft.claims.map((claim, index) => <div key={index}>
        <p><span className={formStyles.claimStatus}>{claim.status}</span> {claim.statement}</p>
        <p className={formStyles.note}>Scope: {claim.scope}{claim.limitations ? ` Limitations: ${claim.limitations}` : ''}</p>
        {claim.source ? <p className={formStyles.note}>Source: {claim.source.reference}</p> : null}
        <p className={formStyles.note}>Recorded for this preview: {claim.observed_at}</p>
      </div>)}</div>
      <form method="post" onSubmit={handlePublish} className={formStyles.publishForm}>
        <fieldset disabled={!ready || busy} className={formStyles.fields}>
          <legend className={formStyles.srOnly}>Publish the reviewed job</legend>
          <Field label="EMILIA API key" hint="Used to publish under your account and check an interrupted request. Never put this key in the job description."><input name="apiKey" type="password" required maxLength={256} autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" value={apiKey} onChange={event => { clearKey(); setApiKey(event.target.value); }} /></Field>
          <p className={formStyles.note}>Publishing requires an existing EMILIA entity key. <a href="mailto:team@emiliaprotocol.ai?subject=EMILIA%20Marketplace%20job%20posting%20access">Request posting access</a> if you do not have one. No new account is created here.</p>
          <label className={formStyles.consent}><input name="publicConsent" type="checkbox" required checked={publicConsent} onChange={event => setPublicConsent(event.target.checked)} /><span>I have reviewed the job, statements and contact route above. I agree to publish them with my authenticated account name.</span></label>
          <div className={formStyles.actions}><button type="submit" disabled={!ready || busy} className={formStyles.primary}>{busy ? 'Confirming publication…' : attempted ? 'Check and retry this job' : 'Publish job'}</button>{!attempted ? <button type="button" className={formStyles.secondary} onClick={() => { clearKey(); setDraft(null); setError(''); }}>Edit preview</button> : null}</div>
        </fieldset>
      </form>
      {apiKey || busy ? <button type="button" className={formStyles.textLink} onClick={clearKey}>Clear key from this page</button> : null}
      {attempted ? <p className={formStyles.note}>An interrupted request may already have published this job. Editing is paused while publication is unresolved. Re-enter your key and retry the same preview to check ownership. Do not start another post for this job.</p> : null}
      <p className={formStyles.note}>The key stays only in this page and clears when you leave the tab. Posting is an invitation for proposals, not a hire or a payment.</p>
    </section> : null}
    {error ? <p className={formStyles.error} role="alert">{error}</p> : null}
  </div>;
}

function ClaimFields({ prefix, title, initialStatement = '', optional = false }: {
  prefix: 'funding' | 'authority' | 'eligibility'; title: string; initialStatement?: string; optional?: boolean;
}) {
  return <fieldset className={formStyles.claimFields}>
    <legend>{title}{optional ? ' (optional)' : ''}</legend>
    <Field label={`${title} statement`} hint={optional ? 'Leave blank if there is no eligibility statement.' : undefined}><textarea name={`${prefix}Statement`} required={!optional} maxLength={600} rows={2} defaultValue={initialStatement} /></Field>
    <div className={formStyles.gridTwo}>
      <Field label={`${title} status`}><select name={`${prefix}Status`} defaultValue="UNKNOWN"><option value="UNKNOWN">UNKNOWN: no supporting source</option><option value="ASSERTED">ASSERTED: my statement</option></select></Field>
      <Field label={`${title} scope`}><input name={`${prefix}Scope`} required={!optional} maxLength={600} defaultValue={optional ? '' : 'This job only.'} placeholder="What this statement covers" /></Field>
    </div>
    <Field label={`${title} limitations`} hint="Any conditions or unresolved facts."><input name={`${prefix}Limitations`} maxLength={1000} /></Field>
  </fieldset>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className={formStyles.field}><span>{label}</span>{children}{hint ? <span className={formStyles.note}>{hint}</span> : null}</label>;
}
