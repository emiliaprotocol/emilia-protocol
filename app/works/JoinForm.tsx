// SPDX-License-Identifier: Apache-2.0

'use client';

import Link from 'next/link';
import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore, type FormEvent, type ReactNode } from 'react';
import { buildJoinPayloads, type JoinFormInput, type JoinPayloads } from './form-payloads';
import { validWorksId, type BuilderRecord } from '@/lib/works/model';
import { publishRecordWithRecovery, readOwnedRecord } from './join/owned-record';
import formStyles from './join/join.module.css';
import WorksAccountAccess, { useWorksAccount } from './WorksAccountAccess';
import { createWorkspaceFence, loadWorkspace, workspaceMessage } from './workspace-client';
import { clearJoinCredentials, confirmOwnedJoinResume, selectOwnedJoinProfile } from './join-profile-selection';

type RegistrationResponse = { api_key?: string; owner_id?: string };
type JoinProgress = {
  apiKey: string | null; keyCreatedHere: boolean; ownerId: string; payloads: JoinPayloads;
  builderCreated: boolean; listingCreated: boolean;
  reuseBuilder: boolean;
  accessCheckRequired?: boolean;
  failureStage: 'builder' | 'listing' | null; failureMessage: string;
};
const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;

function value(data: FormData, name: string): string { return String(data.get(name) || '').trim(); }

async function responseError(response: Response, fallback: string): Promise<string> {
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  for (const key of ['detail', 'message', 'error', 'title']) {
    if (typeof body?.[key] === 'string' && body[key]) return body[key];
  }
  return fallback;
}

async function postWorksRecord(collection: 'builders' | 'listings', apiKey: string | null, record: unknown, signal: AbortSignal): Promise<void> {
  return publishRecordWithRecovery(collection, apiKey, record as JoinPayloads['builder'] | JoinPayloads['listing'], signal);
}

export default function JoinForm({ registrationEnabled = false }: { registrationEnabled?: boolean }) {
  const access = useWorksAccount();
  const refreshAccount = access.refresh;
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [draft, setDraft] = useState<JoinPayloads | null>(null);
  const [publicConsent, setPublicConsent] = useState(false);
  const [accessMode, setAccessMode] = useState<'existing' | 'new'>('existing');
  const [profileMode, setProfileMode] = useState<'new' | 'existing'>('new');
  const [ownedBuilder, setOwnedBuilder] = useState<{ record: BuilderRecord; apiKey: string | null } | null>(null);
  const [progress, setProgress] = useState<JoinProgress | null>(null);
  const [copyStatus, setCopyStatus] = useState('');
  const [accountContext, setAccountContext] = useState(access.account);
  const [profiles, setProfiles] = useState<BuilderRecord[] | null>(null);
  const [profilesLoading, setProfilesLoading] = useState(false);
  const [profilesError, setProfilesError] = useState('');
  const [profileReload, setProfileReload] = useState(0);
  const [selectedProfileId, setSelectedProfileId] = useState('');
  const profileRequests = useRef(createWorkspaceFence());
  const generation = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);
  const inFlight = useRef(false);
  const previewHeading = useRef<HTMLHeadingElement | null>(null);
  const intakeForm = useRef<HTMLFormElement | null>(null);
  const page = useRef<HTMLDivElement | null>(null);

  // A checked account object is a new access context, even if the names match.
  // Preserve the unsigned new-profile preview through its first email sign-in.
  if (!access.loading && accountContext !== access.account) {
    setAccountContext(access.account);
    setOwnedBuilder(null); setProgress(progress ? clearJoinCredentials(progress) : null); setCopyStatus(''); setBusy(false); setPublicConsent(false);
    setProfiles(null); setSelectedProfileId(''); setProfilesError(''); setProfilesLoading(Boolean(access.account));
    if (accountContext || progress || profileMode === 'existing') setDraft(null);
    setError(accountContext || progress ? 'Account access changed. Previous profile and key details were cleared. Check your workspace before restarting an interrupted publication.' : '');
  }

  useLayoutEffect(() => {
    generation.current++; activeRequest.current?.abort(); inFlight.current = false;
    profileRequests.current.cancel();
    page.current?.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach(input => { input.value = ''; });
  }, [access.account]);

  useEffect(() => {
    if (!access.account) return;
    const fence = profileRequests.current;
    const request = fence.begin();
    void loadWorkspace(request.signal).then(workspace => {
      if (!request.isCurrent()) return;
      setProfiles(workspace.profiles); setProfilesError(''); setProfilesLoading(false);
      if (workspace.profiles.length === 1) {
        const record = selectOwnedJoinProfile(workspace.profiles, workspace.profiles[0].builder_id);
        setSelectedProfileId(record.builder_id); setOwnedBuilder({ record, apiKey: null });
      }
    }).catch(caught => {
      if (!request.isCurrent()) return;
      setProfilesLoading(false); setProfilesError(workspaceMessage(caught));
    });
    return () => fence.cancel();
  }, [access.account, profileReload]);

  useEffect(() => {
    function clearPrivateAccess() {
      generation.current++; activeRequest.current?.abort(); inFlight.current = false;
      profileRequests.current.cancel();
      page.current?.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach(input => { input.value = ''; });
      setOwnedBuilder(null); setProgress(current => current ? clearJoinCredentials(current) : null); setProfiles(null); setSelectedProfileId(''); setCopyStatus(''); setBusy(false); setPublicConsent(false);
      setDraft(null);
      setError('Private access details were cleared when you left this tab. If publication was interrupted, check your workspace before posting again.');
    }
    function visibilityChanged() {
      if (document.visibilityState === 'hidden') clearPrivateAccess();
      else void refreshAccount();
    }
    document.addEventListener('visibilitychange', visibilityChanged);
    window.addEventListener('pagehide', clearPrivateAccess);
    return () => {
      document.removeEventListener('visibilitychange', visibilityChanged);
      window.removeEventListener('pagehide', clearPrivateAccess);
    };
  }, [refreshAccount]);

  useEffect(() => () => { generation.current++; activeRequest.current?.abort(); }, []);
  useEffect(() => { if (draft && !progress) previewHeading.current?.focus(); }, [draft, progress]);

  function beginRequest() {
    inFlight.current = true;
    generation.current++;
    activeRequest.current?.abort();
    const controller = new AbortController(); activeRequest.current = controller;
    const current = generation.current;
    return { signal: controller.signal, isCurrent: () => current === generation.current && !controller.signal.aborted };
  }

  function clearKey() {
    generation.current++; activeRequest.current?.abort(); inFlight.current = false;
    setProgress(current => current ? clearJoinCredentials(current) : null); setOwnedBuilder(null); setCopyStatus(''); setBusy(false); setPublicConsent(false);
    if (profileMode === 'existing') setDraft(null);
    setError('Key cleared from this page. This does not undo a published record. If a request was still running, check the profile and listing before starting again.');
  }

  function resetOwnedBuilder() {
    generation.current++; activeRequest.current?.abort(); inFlight.current = false;
    setOwnedBuilder(null); setPublicConsent(false); setBusy(false);
  }

  function chooseProfile(id: string) {
    resetOwnedBuilder(); setSelectedProfileId(id); setError('');
    if (!id) return;
    try {
      const record = selectOwnedJoinProfile(profiles, id);
      setOwnedBuilder({ record, apiKey: null }); setAccessMode('existing');
    } catch { setError('Choose a profile belonging to this signed-in account.'); }
  }

  function changeProfileMode(mode: 'new' | 'existing') {
    resetOwnedBuilder(); setProfileMode(mode); setError('');
    if (mode === 'existing') {
      setAccessMode('existing');
      if (access.account && profiles?.length === 1) chooseProfile(profiles[0].builder_id);
      else setSelectedProfileId('');
    }
  }

  function reloadProfiles() {
    resetOwnedBuilder(); setProfiles(null); setSelectedProfileId(''); setProfilesError(''); setProfilesLoading(true);
    setProfileReload(current => current + 1);
  }

  async function loadMyBuilder() {
    if (!ready || inFlight.current || !intakeForm.current) return;
    if (access.loading || access.account) return;
    const data = new FormData(intakeForm.current);
    const id = value(data, 'builderId'); const apiKey = access.account ? null : value(data, 'profileKey');
    if (!validWorksId(id) || apiKey === '') { setError('Enter your builder profile ID, then sign in or use its existing key.'); return; }
    const request = beginRequest(); setBusy(true); setError(''); setOwnedBuilder(null);
    const keyInput = intakeForm.current.elements.namedItem('profileKey');
    if (keyInput instanceof HTMLInputElement) keyInput.value = '';
    try {
      const record = await readOwnedRecord('builders', id, apiKey, request.signal) as BuilderRecord;
      if (!request.isCurrent()) return;
      setOwnedBuilder({ record, apiKey }); setAccessMode('existing'); setPublicConsent(false);
    } catch (caught) { if (request.isCurrent()) setError(caught instanceof Error ? caught.message : 'Builder ownership could not be checked.'); }
    finally { if (request.isCurrent()) { inFlight.current = false; setBusy(false); } }
  }

  async function publishWorks(start: JoinProgress, request: ReturnType<typeof beginRequest>) {
    if (!request.isCurrent()) return;
    let next: JoinProgress = { ...start, failureStage: null, failureMessage: '' };
    setProgress(next);
    if (!next.builderCreated) {
      try {
        await postWorksRecord('builders', next.apiKey, next.payloads.builder, request.signal);
        if (!request.isCurrent()) return;
        next = { ...next, builderCreated: true }; setProgress(next);
      } catch (caught) {
        if (request.isCurrent()) setProgress({ ...next, failureStage: 'builder', failureMessage: caught instanceof Error ? caught.message : 'The profile write could not be confirmed.' });
        return;
      }
    }
    if (!next.listingCreated) {
      try {
        await postWorksRecord('listings', next.apiKey, next.payloads.listing, request.signal);
        if (!request.isCurrent()) return;
        next = { ...next, listingCreated: true }; setProgress(next);
      } catch (caught) {
        if (request.isCurrent()) setProgress({ ...next, failureStage: 'listing', failureMessage: caught instanceof Error ? caught.message : 'The listing write could not be confirmed.' });
      }
    }
  }

  function preparePreview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || inFlight.current) return;
    const data = new FormData(event.currentTarget);
    const input = Object.fromEntries([
      'builderId', 'builderKind', 'builderName', 'builderSummary', 'contactRoute', 'affiliationName', 'affiliationRelation',
      'listingId', 'listingKind', 'listingName', 'listingSummary', 'repositoryUrl', 'serviceUrl', 'license',
      'supportedTasks', 'interfaces', 'operatingConstraints',
    ].map(name => [name, value(data, name)])) as JoinFormInput;
    if (profileMode === 'existing' && (!ownedBuilder || input.builderId !== ownedBuilder.record.builder_id)) {
      setError('Choose your owned builder profile before previewing this listing.'); return;
    }
    if (profileMode === 'existing' && access.account) {
      try { selectOwnedJoinProfile(profiles, input.builderId); }
      catch { setError('Reload your profiles, then choose one belonging to this account.'); return; }
    }
    if (profileMode === 'new' && Boolean(input.affiliationName) !== Boolean(input.affiliationRelation)) {
      setError('Enter both affiliation name and relationship, or leave both blank.'); return;
    }
    if (profileMode === 'new' && !/^(https:\/\/|mailto:)/i.test(input.contactRoute)) {
      setError('Use an https:// or mailto: contact route. This contact will be public.'); return;
    }
    if ([input.repositoryUrl, input.serviceUrl].some(url => url && !/^https:\/\//i.test(url))) {
      setError('Repository and service links must start with https://.'); return;
    }
    const payloads = buildJoinPayloads(input);
    if (profileMode === 'existing' && ownedBuilder) payloads.builder = ownedBuilder.record;
    setError(''); setPublicConsent(false); setDraft(payloads);
  }

  async function handlePublish(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    if (inFlight.current) return;
    if (access.loading || document.visibilityState === 'hidden') return;
    if (!draft || !publicConsent) { setError('Review the preview and explicitly agree to public publication first.'); return; }
    const reuseBuilder = profileMode === 'existing';
    if (reuseBuilder && (!ownedBuilder || ownedBuilder.record.builder_id !== draft.builder.builder_id)) {
      setError('Reload your owned builder profile before publishing.'); return;
    }
    const existingKey = reuseBuilder ? ownedBuilder!.apiKey : access.account ? null : value(new FormData(event.currentTarget), 'existingKey');
    if (accessMode === 'existing' && existingKey === '') { setError('Sign in with email, or enter your existing key, to publish.'); return; }
    if (accessMode === 'new' && !registrationEnabled) { setError('New registration is not available. Use an existing key or request builder access.'); return; }
    const request = beginRequest(); setBusy(true); setError(''); setCopyStatus('');
    event.currentTarget.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach(input => { input.value = ''; });
    const payloads = draft;
    try {
      if (accessMode === 'existing' || access.account) {
        await publishWorks({ apiKey: existingKey, keyCreatedHere: false, ownerId: '', payloads,
          builderCreated: reuseBuilder, reuseBuilder, listingCreated: false, failureStage: null, failureMessage: '' }, request);
        return;
      }
      const response = await fetch('/api/entities/register', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payloads.entity), signal: request.signal,
      });
      if (!response.ok) {
        const detail = await responseError(response, 'Entity registration could not be completed.');
        if (request.isCurrent()) setError(`${detail} No one-time API key was returned to this page.`);
        return;
      }
      const body = await response.json() as RegistrationResponse;
      if (!request.isCurrent()) return;
      if (!body.api_key) { setError('Registration returned without an API key. Publication could not continue. Do not assume registration failed.'); return; }
      const registered: JoinProgress = { apiKey: body.api_key, keyCreatedHere: true, ownerId: body.owner_id || '', payloads,
        builderCreated: false, reuseBuilder: false, listingCreated: false, failureStage: null, failureMessage: '' };
      setProgress(registered); await publishWorks(registered, request);
    } catch {
      if (request.isCurrent()) setError('We could not confirm registration, and no API key reached this page. The IDs may already exist. Request help before registering again.');
    } finally {
      if (request.isCurrent()) { inFlight.current = false; setBusy(false); }
    }
  }

  async function retryWorks() {
    if (!progress || progress.accessCheckRequired || inFlight.current || access.loading || document.visibilityState === 'hidden') return;
    const request = beginRequest(); setBusy(true); setError('');
    try { await publishWorks(progress, request); }
    finally { if (request.isCurrent()) { inFlight.current = false; setBusy(false); } }
  }

  async function restorePublicationAccess(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!progress || !publicConsent || inFlight.current || access.loading || document.visibilityState === 'hidden') return;
    const apiKey = access.account ? null : value(new FormData(event.currentTarget), 'retryKey');
    if (apiKey === '') { setError('Sign in or enter the developer key for this publication.'); return; }
    event.currentTarget.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach(input => { input.value = ''; });
    const request = beginRequest(); setBusy(true); setError('');
    try {
      await confirmOwnedJoinResume(progress, apiKey, request.signal);
      if (!request.isCurrent()) return;
      await publishWorks({ ...progress, apiKey, accessCheckRequired: false }, request);
    } catch (caught) {
      if (request.isCurrent()) setError(caught instanceof Error ? caught.message : 'This access could not be confirmed. The original publication details are unchanged.');
    } finally { if (request.isCurrent()) { inFlight.current = false; setBusy(false); } }
  }

  async function copyKey() {
    if (!progress?.keyCreatedHere || !progress.apiKey) return;
    const current = generation.current;
    try { await navigator.clipboard.writeText(progress.apiKey); if (current === generation.current) setCopyStatus('Copied. Store it in your secret manager now.'); }
    catch { if (current === generation.current) setCopyStatus('Copy failed. Select the key and copy it manually.'); }
  }

  if (progress) {
    const complete = progress.builderCreated && progress.listingCreated;
    return <div ref={page} className={formStyles.result}>
      <p className={formStyles.eyebrow}>{complete ? 'Published' : busy ? 'Publishing' : 'Needs attention'}</p>
      <h2>{complete ? 'Your agent has a place to be found.' : progress.builderCreated ? progress.reuseBuilder ? 'Existing profile ready. Listing not yet confirmed.' : 'Profile published. Listing not yet confirmed.' : 'Profile publication is not yet confirmed.'}</h2>
      <p>{complete ? progress.reuseBuilder ? 'Your new listing is live under your existing builder profile. The profile was not changed. No sale, payment or customer assignment has been created.' : 'Your profile and listing are live. Companies can use your public contact route to discuss the work. No sale, payment or customer assignment has been created.'
        : progress.keyCreatedHere ? 'Entity registration succeeded. Do not register again. Save the key, then retry only the unfinished Works step.'
          : progress.apiKey === null ? 'Your signed-in account is being used. Check the error, then retry the unfinished step with the same details.' : 'No new account or key was created. We used the key you supplied. Check the error, then retry the unfinished step.'}</p>
      {progress.failureMessage ? <p className={formStyles.error} role="alert">{progress.failureMessage}</p> : null}
      {!complete && !busy ? <p className={formStyles.note}>A lost response can leave a record published without confirmation here. A duplicate-ID error is not proof that you own that record; check it before choosing a different ID.</p> : null}
      {progress.accessCheckRequired ? <section className={formStyles.keyPanel}>
        <h3>{complete ? 'Access details cleared.' : 'Continue with the original publication.'}</h3>
        <p className={formStyles.note}>The key was removed from this page. Your original public details and publication IDs are unchanged. This does not undo a published record.</p>
        {!complete ? <>
          <WorksAccountAccess access={access} />
          <details className={formStyles.advanced}><summary>Review the original public details</summary><pre>{JSON.stringify({ builder: progress.payloads.builder, listing: progress.payloads.listing }, null, 2)}</pre></details>
          <form method="post" onSubmit={restorePublicationAccess}>
            {!access.account ? <Field label="Developer key for this publication"><input name="retryKey" type="password" disabled={busy} maxLength={512} autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" onChange={() => setPublicConsent(false)} /></Field> : null}
            <label className={formStyles.consent}><input type="checkbox" checked={publicConsent} required disabled={busy} onChange={event => setPublicConsent(event.target.checked)} /><span>Use this account access to check and retry the original publication. Keep all public details and IDs unchanged.</span></label>
            <button type="submit" className={formStyles.primary} disabled={busy || access.loading || !publicConsent}>{busy ? 'Checking publication…' : 'Check and retry original publication'}</button>
          </form>
        </> : null}
      </section> : progress.apiKey !== null ? <div className={formStyles.keyPanel}>
        <h3>{progress.keyCreatedHere ? 'One-time API key' : 'Your existing key stays private'}</h3>
        {progress.keyCreatedHere ? <><p className={formStyles.note}>This key is kept only in this open page. Save it before leaving or reloading; it cannot be retrieved here afterward.</p><code className={formStyles.keyValue}>{progress.apiKey}</code></>
          : <p className={formStyles.note}>Your existing key is held only in this page for retries. It is not displayed here or saved in browser storage.</p>}
        {progress.ownerId ? <p className={formStyles.note}>Owner ID <code className={formStyles.keyValue}>{progress.ownerId}</code></p> : null}
        <div className={formStyles.actions}>
          {progress.keyCreatedHere ? <button type="button" onClick={copyKey} className={formStyles.secondary}>Copy key</button> : null}
          <button type="button" onClick={clearKey} className={formStyles.textButton}>Clear key from this page</button>
          {!complete ? <button type="button" onClick={retryWorks} disabled={busy} className={formStyles.primary}>{busy ? 'Publishing…' : 'Retry Works setup'}</button> : null}
        </div>
        <p className={formStyles.note} aria-live="polite">{copyStatus}</p>
      </div> : <div className={formStyles.actions}>{!complete ? <button type="button" onClick={retryWorks} disabled={busy} className={formStyles.primary}>Check and retry publication</button> : null}<Link href="/works/workspace" className={formStyles.primary}>Open your workspace</Link></div>}
      <div className={formStyles.actions}>
        <Link href={`/works/builders/${progress.payloads.builder.builder_id}`} className={formStyles.secondary}>{complete ? 'View profile' : 'Check profile'}</Link>
        <Link href={`/works/listings/${progress.payloads.listing.listing_id}`} className={formStyles.secondary}>{complete ? 'View listing' : 'Check listing'}</Link>
        {complete ? <Link href="/works/opportunities" className={formStyles.textButton}>Browse posted work</Link> : null}
      </div>
      {error ? <p className={formStyles.error} role="alert">{error}</p> : null}
    </div>;
  }

  return <div ref={page} className={formStyles.intake}>
    <WorksAccountAccess access={access} />
    {!ready ? <p className={formStyles.note} role="status">This form needs JavaScript to handle your key privately. Wait for it to finish loading before entering any details.</p> : null}
    <form method="post" ref={intakeForm} onSubmit={preparePreview} hidden={Boolean(draft)} className={formStyles.form}>
      <fieldset disabled={!ready || busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      <legend className={formStyles.srOnly}>Prepare your listing</legend>
      <div className={formStyles.sectionHeading}><span>01</span><div><h2>Start with the work.</h2><p>Be specific enough for a company to know when to contact you.</p></div></div>
      <fieldset className={formStyles.fields}><legend className={formStyles.srOnly}>Agent listing details</legend>
        <Field label="Agent or product name"><input name="listingName" required maxLength={200} placeholder="e.g. Ledger assistant" /></Field>
        <Field label="What job does it do?" hint="Tell a company what it can help with and what it needs from them."><textarea name="listingSummary" required maxLength={2000} placeholder="Reviews refund requests against your policy and prepares exceptions for a finance reviewer." /></Field>
        <div className={formStyles.gridTwo}><Field label="Specialized tasks" hint="Separate tasks with commas."><input name="supportedTasks" required maxLength={2000} placeholder="Refund review, finance operations" /></Field><Field label="How does it connect?" hint="Interfaces you support, not unbuilt integrations."><input name="interfaces" required maxLength={2000} placeholder="MCP, HTTP" /></Field></div>
        <Field label="Limits and requirements" hint="What it cannot do, or what a customer must supply. One per line."><textarea name="operatingConstraints" required maxLength={4000} placeholder={'Requires access to approved order records\nDoes not move money without a configured approval path'} /></Field>
        <details className={formStyles.advanced}><summary>Links, license and listing type <span>Optional</span></summary><div className={formStyles.gridTwo}>
          <Field label="Repository URL"><input name="repositoryUrl" type="url" maxLength={600} placeholder="https://github.com/your-project" /></Field>
          <Field label="Service URL"><input name="serviceUrl" type="url" maxLength={600} placeholder="https://your-app.example" /></Field>
          <Field label="License"><input name="license" maxLength={80} placeholder="e.g. Apache-2.0 or proprietary" /></Field>
          <Field label="Listing type"><select name="listingKind" defaultValue="agent"><option value="agent">Agent</option><option value="app">App</option><option value="project">Project</option></select></Field>
        </div></details>
      </fieldset>
      <div className={formStyles.sectionHeading}><span>02</span><div><h2>Put a person behind it.</h2><p>Give customers a clear way to reach the accountable builder.</p></div></div>
      <fieldset className={formStyles.fields}><legend className={formStyles.srOnly}>Accountable builder details</legend>
        <fieldset className={formStyles.accessChoice} disabled={busy}><legend>Builder profile</legend><label><input type="radio" name="profileMode" value="new" checked={profileMode === 'new'} onChange={() => changeProfileMode('new')} /> Create a profile</label><label><input type="radio" name="profileMode" value="existing" checked={profileMode === 'existing'} onChange={() => changeProfileMode('existing')} /> Use my existing profile</label></fieldset>
        {profileMode === 'new' ? <div className={formStyles.gridTwo}><Field label="Accountable name"><input name="builderName" required maxLength={200} autoComplete="name" placeholder="Your name or legal entity" /></Field><Field label="Public contact route" hint="Use a mailto: or https:// address. Customers discuss price and terms here."><input name="contactRoute" required maxLength={600} placeholder="mailto:hello@example.com" autoComplete="url" /></Field></div> : null}
        <div className={formStyles.gridTwo}>
          {profileMode === 'existing' && access.account ? <Field label="Your builder profile" hint="Only profiles belonging to your signed-in account appear here.">
            <select name="builderId" required value={selectedProfileId} disabled={profilesLoading || !profiles?.length} onChange={event => chooseProfile(event.target.value)}>
              <option value="">{profilesLoading ? 'Loading your profiles…' : 'Choose your profile'}</option>
              {profiles?.map(profile => <option value={profile.builder_id} key={profile.builder_id}>{profile.name}</option>)}
            </select>
          </Field> : <Field label="Builder profile ID" hint="Your public URL. 3–64 lowercase letters, numbers or hyphens."><input name="builderId" required minLength={3} maxLength={64} pattern="[a-z0-9](?:[a-z0-9]|-){2,63}" placeholder="your-studio" autoComplete="off" onChange={resetOwnedBuilder} /></Field>}
          <Field label="Listing ID" hint="The agent’s public URL. Choose an unused ID."><input name="listingId" required minLength={3} maxLength={64} pattern="[a-z0-9](?:[a-z0-9]|-){2,63}" placeholder="ledger-assistant" autoComplete="off" /></Field>
        </div>
        {profileMode === 'existing' ? <div>
          {!access.account ? <Field label="Key for your existing profile" hint="Sign in above, or use the key that owns this profile."><input name="profileKey" type="password" required={!ownedBuilder} maxLength={256} autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" onChange={resetOwnedBuilder} /></Field> : null}
          {access.account ? <>
            {profilesError ? <p role="alert" className={formStyles.error}>{profilesError}</p> : profiles && !profiles.length ? <p className={formStyles.note}>This account does not have a builder profile yet. Choose “Create a profile” above to make one with this listing.</p> : null}
            <div className={formStyles.actions}><button type="button" className={formStyles.textButton} onClick={reloadProfiles} disabled={profilesLoading || busy}>Reload my profiles</button></div>
          </> : <div className={formStyles.actions}><button type="button" className={formStyles.secondary} onClick={loadMyBuilder} disabled={busy || access.loading}>{busy ? 'Checking ownership…' : 'Load my profile'}</button></div>}
          {ownedBuilder ? <p role="status" className={formStyles.note}><strong>{ownedBuilder.record.name}</strong> belongs to your account. Its public contact is {ownedBuilder.record.contact_route}. We will reuse this profile without changing it.</p> : <p className={formStyles.note}>Only the new listing will be published. Your existing profile, contact route and previous listings stay unchanged.</p>}
        </div> : null}
        {profileMode === 'new' ? <details className={formStyles.advanced}><summary>More about the builder <span>Optional</span></summary><div className={formStyles.gridTwo}>
          <Field label="Profile type"><select name="builderKind" defaultValue="person"><option value="person">Person</option><option value="legal_entity">Legal entity</option></select></Field>
          <Field label="Builder summary"><textarea name="builderSummary" maxLength={2000} placeholder="Who builds and supports the agent?" /></Field>
          <Field label="Affiliation" hint="If supplied, include the relationship too."><input name="affiliationName" maxLength={200} placeholder="Organization" /></Field><Field label="Relationship"><input name="affiliationRelation" maxLength={200} placeholder="Employee, sponsor, independent builder" /></Field>
        </div></details> : null}
      </fieldset>
      <div className={formStyles.actions}><button type="submit" className={formStyles.primary} disabled={busy || (profileMode === 'existing' && !ownedBuilder)}>Preview my listing</button><Link href="/works" className={formStyles.textButton}>Back to marketplace</Link></div>
      <p className={formStyles.note}>Nothing is sent or published when you preview. Loading an existing profile is a separate authenticated read. Private access and confirmation details clear when you leave this tab. Reloading the page also clears the draft.</p>
      </fieldset>
    </form>
    {draft ? <section className={formStyles.preview} aria-labelledby="listing-preview-title">
      <div className={formStyles.sectionHeading}><span>03</span><div><h2 id="listing-preview-title" ref={previewHeading} tabIndex={-1}>This is what you’ll publish.</h2><p>Review the public details before anything goes live.</p></div></div>
      <div className={formStyles.previewSheet}><p className={formStyles.eyebrow}>Listing preview · Builder-supplied information</p><h3>{draft.listing.name}</h3><p className={formStyles.previewByline}>By {draft.builder.name}</p><p>{draft.listing.summary}</p>
        <dl><div><dt>Specialized tasks</dt><dd>{draft.listing.supported_tasks.join(', ')}</dd></div><div><dt>Interfaces</dt><dd>{draft.listing.interfaces.join(', ')}</dd></div><div><dt>Limits & requirements</dt><dd>{draft.listing.operating_constraints.join('\n')}</dd></div><div><dt>Public contact</dt><dd>{draft.builder.contact_route}</dd></div></dl>
        {profileMode === 'existing' ? <p className={formStyles.note}>Existing builder profile, unchanged. You are publishing only the new listing below.</p> : null}
        <details className={formStyles.advanced}><summary>Review every public field</summary><pre>{JSON.stringify({ ...(accessMode === 'new' ? { entity: draft.entity } : {}), ...(profileMode === 'existing' ? { existing_builder_unchanged: draft.builder } : { builder: draft.builder }), listing: draft.listing }, null, 2)}</pre></details>
      </div>
      <p className={formStyles.note}>This is a builder-supplied listing, not a safety certification, verified capability or promise of paid work. It does not publish your private scan or create an Authority Record.</p>
      <form method="post" className={formStyles.accessForm} onSubmit={handlePublish}>
        <fieldset disabled={!ready || busy} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
        <legend className={formStyles.srOnly}>Authorize listing publication</legend>
        <h3>Publish with your builder access.</h3>
        {access.account ? <p className={formStyles.note}>Publish as {access.account.displayName}. Email verification confirms access to your account, not your agent’s capabilities.</p> : profileMode === 'existing' ? <p className={formStyles.note}>Using the key that loaded your owned profile. It remains only in this page and is not displayed here.</p> : !registrationEnabled ? <p className={formStyles.note}>Create a free account or sign in with email above. Existing developer accounts can use an API key below.</p>
          : <fieldset className={formStyles.accessChoice} disabled={busy}><legend>Choose access</legend><label><input type="radio" name="accessMode" value="existing" checked={accessMode === 'existing'} onChange={() => { setAccessMode('existing'); setPublicConsent(false); }} /> Use an existing key</label><label><input type="radio" name="accessMode" value="new" checked={accessMode === 'new'} onChange={() => { setAccessMode('new'); setPublicConsent(false); }} /> Register a new entity</label></fieldset>}
        {profileMode === 'existing' || access.account ? null : accessMode === 'existing' ? <details><summary>Use an existing API key instead</summary><Field label="Existing EMILIA API key" hint="Used only for these publication requests. Held in this page for retries, never saved in browser storage or the URL."><input name="existingKey" type="password" maxLength={256} autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" placeholder="Your existing EMILIA API key" onChange={() => setPublicConsent(false)} /></Field></details>
          : <p className={formStyles.note}>Registration will create the public entity shown in the preview and return a one-time key. Save that key before leaving this page.</p>}
        <label className={formStyles.consent}><input name="publicConsent" type="checkbox" checked={publicConsent} disabled={busy} onChange={event => setPublicConsent(event.target.checked)} required /><span>{profileMode === 'existing' ? 'I am authorized to publish this new listing under my existing builder profile. Keep that profile unchanged.' : <>I am authorized to publish these details. Make this builder profile, listing and contact route public{accessMode === 'new' ? ', and register the new entity shown above' : ''}.</>}</span></label>
        <div className={formStyles.actions}><button type="submit" disabled={busy || !publicConsent} className={formStyles.primary}>{busy ? 'Publishing…' : profileMode === 'existing' ? 'Publish new listing' : 'Publish profile and listing'}</button><button type="button" className={formStyles.textButton} disabled={busy} onClick={() => { setDraft(null); setPublicConsent(false); setError(''); }}>Edit details</button></div>
        <p className={formStyles.note}>No payment is taken here. You and the customer agree on the work and commercial terms directly.</p>
        </fieldset>
      </form>
    </section> : null}
    <div className={formStyles.error} role={error ? 'alert' : undefined} aria-live="polite">{error}</div>
  </div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className={formStyles.field}><span>{label}</span>{children}{hint ? <small>{hint}</small> : null}</label>;
}
