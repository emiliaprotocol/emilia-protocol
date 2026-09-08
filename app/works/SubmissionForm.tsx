// SPDX-License-Identifier: Apache-2.0

'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import Link from 'next/link';
import { color, cta, styles } from '@/lib/tokens';
import { validWorksId } from '@/lib/works/model';
import { buildSubmissionPayload, type SubmissionFormInput, type SubmissionPayload } from './form-payloads';
import formStyles from './works.module.css';
import WorksAccountAccess, { useWorksAccount } from './WorksAccountAccess';
import { worksRequestAuth } from './session-request';
import { createWorkspaceFence, loadWorkspace, workspaceMessage, type WorkspaceData } from './workspace-client';

// The server and first hydration render keep sensitive controls disabled.
const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;

type SubmissionFormProps = {
  opportunityId: string;
  sponsorName: string;
  sponsorContactRoute: string;
};

function value(data: FormData, name: string): string {
  return String(data.get(name) || '').trim();
}

function newSubmissionId(): string {
  return `submission-${window.crypto.randomUUID()}`;
}

export function matchesSubmissionAttempt(value: unknown, expected: SubmissionPayload): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    const record = value as Record<string, unknown>;
    return ['submission_id', 'opportunity_id', 'builder_id', 'proposal', 'visibility']
      .every((field) => record[field] === expected[field])
      && (record.listing_id ?? null) === (expected.listing_id ?? null)
      && JSON.stringify(record.team ?? []) === JSON.stringify(expected.team ?? []);
  } catch { return false; }
}

/** A response retry names the same intent. Credentials never enter this state. */
export function createSubmissionAttemptTracker() {
  let current: SubmissionPayload | null = null;
  return {
    prepare(input: SubmissionFormInput, generateId: () => string = newSubmissionId): SubmissionPayload {
      const candidate = buildSubmissionPayload(input, current?.submission_id ?? generateId());
      if (current) {
        if (!matchesSubmissionAttempt(candidate, current)) throw new Error('submission_attempt_changed');
        return current;
      }
      Object.freeze(candidate.team);
      current = Object.freeze(candidate);
      return current;
    },
    clear() { current = null; },
  };
}

export async function sendOrCheckSubmission(payload: SubmissionPayload, apiKey: string | null, checkOnly = false, signal?: AbortSignal) {
  if (!validWorksId(payload.submission_id) || (apiKey !== null && !/^[A-Za-z0-9_-]{8,512}$/.test(apiKey))) throw new Error('submission_key_required');
  const auth = worksRequestAuth(apiKey);
  const options: RequestInit = { headers: { ...auth.headers, 'content-type': 'application/json' },
    cache: 'no-store', credentials: auth.credentials, redirect: 'error', referrerPolicy: 'no-referrer', signal,
  };
  signal?.throwIfAborted();
  const read = () => fetch(`/api/works/submissions/${payload.submission_id}`, { ...options, method: 'GET' });
  let response = checkOnly ? await read() : await fetch('/api/works/submissions', { ...options, method: 'POST', body: JSON.stringify(payload) });
  signal?.throwIfAborted();
  if (!checkOnly && response.status === 409) response = await read();
  signal?.throwIfAborted();
  if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? 'submission_access_refused' : 'submission_confirmation_missing');
  const body = await response.json();
  signal?.throwIfAborted();
  if (body?.collection !== 'submissions' || !matchesSubmissionAttempt(body.record, payload)) throw new Error('submission_confirmation_missing');
}

/** Session choices come only from the authenticated workspace, never the public directory. */
export function eligibleSubmissionChoice(workspace: WorkspaceData, builderId: string, listingId: string): boolean {
  if (!workspace.profiles.some(profile => profile.builder_id === builderId)) return false;
  return !listingId || workspace.listings.some(item => item.record.listing_id === listingId
    && item.record.builder_id === builderId && item.workflow.state === 'active');
}

export default function SubmissionForm(props: SubmissionFormProps) {
  const access = useWorksAccount();
  const [accountContext, setAccountContext] = useState(access.account);
  const [contextRevision, setContextRevision] = useState(0);
  // Reset the private form before committing an account change to the screen.
  // Display names are not account identities; compare the checked account object.
  if (accountContext !== access.account) {
    setAccountContext(access.account); setContextRevision(contextRevision + 1);
  }
  return <SubmissionFormBody key={contextRevision} {...props} access={access} />;
}

function SubmissionFormBody({
  opportunityId,
  sponsorName,
  sponsorContactRoute,
  access,
}: SubmissionFormProps & { access: ReturnType<typeof useWorksAccount> }) {
  const router = useRouter();
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [busy, setBusy] = useState(false);
  const [publishPublicly, setPublishPublicly] = useState(false);
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);
  const [attempt, setAttempt] = useState<SubmissionPayload | null>(null);
  const [confirmedId, setConfirmedId] = useState('');
  const [choices, setChoices] = useState<WorkspaceData | null>(null);
  const [choicesBusy, setChoicesBusy] = useState(Boolean(access.account));
  const [choicesError, setChoicesError] = useState('');
  const [builderId, setBuilderId] = useState('');
  const [listingId, setListingId] = useState('');
  const formRef = useRef<HTMLFormElement>(null);
  const choiceRequests = useRef(createWorkspaceFence());
  const sendRequests = useRef(createWorkspaceFence());
  const tracker = useRef<ReturnType<typeof createSubmissionAttemptTracker> | null>(null);
  const inFlight = useRef(false);
  if (tracker.current === null) tracker.current = createSubmissionAttemptTracker();

  useEffect(() => {
    const chooser = choiceRequests.current; const sender = sendRequests.current;
    if (!access.account) return;
    const request = chooser.begin();
    void loadWorkspace(request.signal).then(result => {
      if (!request.isCurrent()) return;
      setChoices(result); setBuilderId(result.profiles.length === 1 ? result.profiles[0].builder_id : ''); setChoicesBusy(false);
    }).catch(caught => { if (request.isCurrent()) { setChoicesBusy(false); setChoicesError(workspaceMessage(caught)); } });
    return () => { chooser.cancel(); sender.cancel(); };
  }, [access.account]);

  const refreshAccount = access.refresh;
  useEffect(() => {
    const chooser = choiceRequests.current; const sender = sendRequests.current;
    function leave() {
      chooser.cancel(); sender.cancel(); inFlight.current = false; tracker.current?.clear();
      setChoices(null); setChoicesBusy(false); setBuilderId(''); setListingId(''); setAttempt(null); setConfirmedId('');
      setBusy(false); setPublishPublicly(false); setMessage('Private form details were cleared when you left the tab. An interrupted proposal may already be recorded; check your workspace before sending it again.');
      formRef.current?.reset();
    }
    function visibility() { if (document.visibilityState === 'hidden') leave(); else void refreshAccount(); }
    document.addEventListener('visibilitychange', visibility); window.addEventListener('pagehide', leave);
    return () => { chooser.cancel(); sender.cancel(); document.removeEventListener('visibilitychange', visibility); window.removeEventListener('pagehide', leave); };
  }, [refreshAccount]);

  function changeDeveloperKey() {
    choiceRequests.current.cancel(); sendRequests.current.cancel(); inFlight.current = false;
    // Re-entering a cleared key must not mint a new proposal after response loss.
    // Clear the selections, but retain the frozen attempt for explicit check/retry.
    setChoices(null); setBuilderId(''); setListingId(''); setConfirmedId(''); setBusy(false); setPublishPublicly(false);
    setMessage('');
    for (const name of ['proposal', 'team']) {
      const field = formRef.current?.elements.namedItem(name);
      if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) field.value = '';
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    if (inFlight.current) return;
    if (access.loading || document.visibilityState === 'hidden') return;
    const request = sendRequests.current.begin();
    inFlight.current = true;
    const form = event.currentTarget;
    const data = new FormData(form);
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    const checkOnly = submitter instanceof HTMLButtonElement && submitter.value === 'check';
    const retryOnly = submitter instanceof HTMLButtonElement && submitter.value === 'retry';
    const apiKey = access.account ? null : value(data, 'apiKey');
    const keyInput = form.elements.namedItem('apiKey');
    if (keyInput instanceof HTMLInputElement) keyInput.value = '';

    setBusy(true);
    setMessage('');
    setIsError(false);
    setConfirmedId('');

    try {
      const selectedBuilder = value(data, 'builderId'); const selectedListing = value(data, 'listingId');
      if (access.account && !checkOnly && !retryOnly && (!choices || !eligibleSubmissionChoice(choices, selectedBuilder, selectedListing))) {
        throw new Error('submission_profile_required');
      }
      const payload = (checkOnly || retryOnly) && attempt ? attempt : tracker.current!.prepare({
        opportunityId,
        builderId: value(data, 'builderId'),
        listingId: value(data, 'listingId'),
        proposal: value(data, 'proposal'),
        team: value(data, 'team'),
        visibility: publishPublicly ? 'public' : 'private',
      });
      setAttempt(payload);

      await sendOrCheckSubmission(payload, apiKey, checkOnly, request.signal);
      if (!request.isCurrent()) return;

      tracker.current!.clear();
      setAttempt(null);
      setConfirmedId(payload.submission_id);
      form.reset();
      setPublishPublicly(false);
      setMessage(payload.visibility === 'public'
        ? 'Your proposal was published on this opportunity page.'
        : 'Your private response was recorded. You, the opportunity owner and authorized administrators can read it.');
      router.refresh();
    } catch (caught) {
      if (!request.isCurrent()) return;
      setIsError(true);
      const code = caught instanceof Error ? caught.message : '';
      setMessage(code === 'submission_attempt_changed'
        ? 'An earlier response is still unresolved. Restore its original fields to retry, or check the recorded response before starting a separate one.'
        : code === 'submission_profile_required' ? 'Choose a builder profile from your account and an active listing belonging to that profile, or leave the listing blank.'
          : code === 'submission_key_required' ? 'Enter a valid EMILIA API key. Nothing was sent.'
          : code === 'submission_access_refused' ? 'This key was not accepted. Enter the key that owns your builder profile and try again.'
            : 'We could not confirm the response. It may already have been recorded. Enter your key and check it below, or retry with the same response ID.');
    } finally {
      if (request.isCurrent()) { inFlight.current = false; setBusy(false); }
    }
  }

  return (
    <div style={{ ...styles.card, marginBottom: 48 }}>
      <div className={formStyles.notice} style={{ marginBottom: 20 }}>
        <p style={{ ...styles.cardBody, margin: 0 }}>
          Private responses can be read by you, the opportunity owner and authorized administrators. Public publication is optional.
          Signed-in builders choose their own profiles and agents below. Developer keys are optional and are not saved.
          The owner can review and respond from their workspace.
        </p>
        <p style={{ ...styles.cardBody, margin: 0 }}>
          Prefer not to post publicly?{' '}
          <a href={sponsorContactRoute} style={{ color: color.t1, fontWeight: 600 }}>
            Contact the sponsor privately
          </a>{' '}
          through {sponsorName}&apos;s listed contact route.
        </p>
      </div>

      <noscript><p>This private form needs JavaScript. You can use the sponsor’s contact route instead. Do not send your API key to the sponsor.</p></noscript>
      <WorksAccountAccess access={access} />
      <form method="post" ref={formRef} className={formStyles.form} onSubmit={handleSubmit}>
        <fieldset disabled={!ready || busy} className={formStyles.fieldset} style={{ border: 0 }}>
        <div className={formStyles.gridTwo}>
          {!access.account ? <Field label="Existing API key (or sign in above)">
            <input className="ep-input" style={styles.input} name="apiKey" type="password"
              autoComplete="off" spellCheck={false} autoCapitalize="off" maxLength={512} data-1p-ignore data-lpignore="true" placeholder="ep_live_…" onChange={changeDeveloperKey} />
          </Field> : null}
          {access.account ? <>
            {attempt ? <><input type="hidden" name="builderId" value={attempt.builder_id} /><input type="hidden" name="listingId" value={attempt.listing_id ?? ''} /></> : null}
            <Field label="Your builder profile">
              <select className="ep-input" style={{ ...styles.input, fontSize: 18 }} name="builderId" required value={builderId} disabled={choicesBusy || !choices?.profiles.length || Boolean(attempt)} onChange={event => { setBuilderId(event.target.value); setListingId(''); }}>
                <option value="">{choicesBusy ? 'Loading your profiles…' : 'Choose your profile'}</option>
                {choices?.profiles.map(profile => <option key={profile.builder_id} value={profile.builder_id}>{profile.name}</option>)}
              </select>
            </Field>
            <Field label="Agent for this proposal" hint="Optional. Only active listings owned by your selected builder profile appear here.">
              <select className="ep-input" style={{ ...styles.input, fontSize: 18 }} name="listingId" value={listingId} disabled={!builderId || Boolean(attempt)} onChange={event => setListingId(event.target.value)}>
                <option value="">Propose without an agent listing</option>
                {choices?.listings.filter(item => item.record.builder_id === builderId && item.workflow.state === 'active').map(item => <option key={item.record.listing_id} value={item.record.listing_id}>{item.record.name}</option>)}
              </select>
            </Field>
            {choicesError ? <p role="alert" className={formStyles.full}>{choicesError} <button type="button" onClick={() => void access.refresh()}>Reload my profiles</button></p> : choices && !choices.profiles.length ? <p className={formStyles.full}>Your account does not have a builder profile yet. <Link href="/works/join" target="_blank" rel="noopener noreferrer">Create your builder profile in a new tab</Link>, then return to this job and reload your profiles. <button type="button" onClick={() => void access.refresh()}>Reload my profiles</button></p> : null}
          </> : <><Field label="Builder ID">
            <input className="ep-input" style={styles.input} name="builderId" required minLength={3} maxLength={64}
              pattern="[a-z0-9](?:[a-z0-9]|-){2,63}" placeholder="your-builder-id" autoComplete="off" value={builderId} onChange={event => setBuilderId(event.target.value)} />
          </Field>
          <Field label="Listing ID" hint="Optional. Include the listing you propose to use.">
            <input className="ep-input" style={styles.input} name="listingId" minLength={3} maxLength={64}
              pattern="[a-z0-9](?:[a-z0-9]|-){2,63}" placeholder="your-listing-id" autoComplete="off" value={listingId} onChange={event => setListingId(event.target.value)} />
          </Field></>}
          <Field label="Team names" hint="Optional; comma- or line-separated. Names follow the response visibility you choose below.">
            <input className="ep-input" style={styles.input} name="team" placeholder="Alex, Sam" />
          </Field>
          <div className={formStyles.full}>
            <Field label="Proposal">
              <textarea className={`ep-input ${formStyles.textarea}`} style={styles.input} name="proposal"
                required maxLength={8000} placeholder="State your approach, boundaries, deliverable, and inspectable evidence you plan to provide." />
            </Field>
          </div>
        </div>

        <div className={formStyles.checkboxRow}>
          <input id={`public-consent-${opportunityId}`} name="publicConsent" type="checkbox"
            checked={publishPublicly} onChange={(event) => setPublishPublicly(event.target.checked)} />
          <label htmlFor={`public-consent-${opportunityId}`} style={{ color: color.t2, fontSize: 14 }}>
            Publish my proposal and any team names publicly on this opportunity page.
          </label>
        </div>
        </fieldset>

        {attempt ? <div className={formStyles.notice} style={styles.card}>
          <p style={{ ...styles.body, margin: 0 }}>Response ID: <code style={{ overflowWrap: 'anywhere' }}>{attempt.submission_id}</code></p>
          <a href={`/works/submissions/${attempt.submission_id}`} style={{ color: color.t1, fontWeight: 600 }}>Check this proposal ID</a>
          <p style={{ ...styles.cardBody, margin: 0 }}>Bookmark that page before leaving if you need to check this attempt later. The link does not confirm that a proposal was recorded.</p>
          <p style={{ ...styles.cardBody, margin: 0 }}>This attempt keeps the same proposal and {attempt.visibility} visibility when retried. If the response was interrupted, it may already have been recorded.</p>
          <button type="submit" name="mode" value="check" formNoValidate disabled={busy} style={cta.secondary}>Check recorded response</button>
          <button type="submit" name="mode" value="retry" formNoValidate disabled={busy} style={cta.secondary}>Retry unchanged response</button>
          <p style={{ ...styles.cardBody, margin: 0 }}>Use your signed-in account, or enter the original key again above. Checking only reads the saved response. Retrying sends the same frozen response and ID, never a new proposal ID.</p>
          <p style={{ ...styles.cardBody, margin: 0 }}>Start a separate response only after checking. This may create another proposal; it does not withdraw the earlier one.</p>
          <button type="button" disabled={busy} style={cta.secondary} onClick={() => {
            if (inFlight.current) return;
            tracker.current!.clear(); setAttempt(null); setMessage('The next send will be a separate response. The earlier response may still exist.'); setIsError(false);
          }}>Start a separate response</button>
        </div> : null}

        <div className={formStyles.actions}>
          {!attempt ? <button type="submit" disabled={!ready || busy} style={!ready || busy ? cta.disabled : cta.primary} className={!ready || busy ? undefined : 'ep-cta'}>
            {busy ? 'Sending…' : publishPublicly ? 'Publish response' : 'Send private response'}
          </button> : null}
        </div>
        <p style={{ ...styles.cardBody, margin: 0 }}>Changing accounts or leaving this tab clears private form details. After an interrupted send, check your workspace before creating another proposal.</p>
        <div className={formStyles.status} style={{ color: isError ? color.red : color.green }}
          role={isError ? 'alert' : 'status'} aria-live="polite">
          {message}
        </div>
        {confirmedId ? <div className={formStyles.notice}>
          <p style={{ ...styles.body, margin: 0 }}>Recorded response: <code style={{ overflowWrap: 'anywhere' }}>{confirmedId}</code></p>
          <a href={`/works/submissions/${confirmedId}`} style={{ color: color.t1, fontWeight: 600 }}>Open your recorded proposal</a>
          <p style={{ ...styles.cardBody, margin: 0 }}>You can also find this proposal in your signed-in workspace. Existing developer accounts can use their original key.</p>
          <p style={{ ...styles.cardBody, margin: 0 }}>This confirms the record, not that the owner has read or accepted it. Agree on the job, limits and terms before work begins.</p>
          <a href={sponsorContactRoute} style={{ color: color.t1, fontWeight: 600 }}>Contact {sponsorName} about this proposal</a>
        </div> : null}
      </form>
    </div>
  );
}

function Field({ label, hint, children }: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className={formStyles.field}>
      <span style={{ ...styles.label, marginBottom: 0 }}>{label}</span>
      {children}
      {hint ? <span className={formStyles.hint} style={{ color: color.t3 }}>{hint}</span> : null}
    </label>
  );
}
