// SPDX-License-Identifier: Apache-2.0

'use client';

import { useRouter } from 'next/navigation';
import { useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import { color, cta, styles } from '@/lib/tokens';
import { validWorksId } from '@/lib/works/model';
import { buildSubmissionPayload, type SubmissionFormInput, type SubmissionPayload } from './form-payloads';
import formStyles from './works.module.css';

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

export async function sendOrCheckSubmission(payload: SubmissionPayload, apiKey: string, checkOnly = false) {
  if (!validWorksId(payload.submission_id) || !/^[A-Za-z0-9_-]{8,512}$/.test(apiKey)) throw new Error('submission_key_required');
  const options: RequestInit = { headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
  };
  const read = () => fetch(`/api/works/submissions/${payload.submission_id}`, { ...options, method: 'GET' });
  let response = checkOnly ? await read() : await fetch('/api/works/submissions', { ...options, method: 'POST', body: JSON.stringify(payload) });
  if (!checkOnly && response.status === 409) response = await read();
  if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? 'submission_access_refused' : 'submission_confirmation_missing');
  const body = await response.json();
  if (body?.collection !== 'submissions' || !matchesSubmissionAttempt(body.record, payload)) throw new Error('submission_confirmation_missing');
}

export default function SubmissionForm({
  opportunityId,
  sponsorName,
  sponsorContactRoute,
}: SubmissionFormProps) {
  const router = useRouter();
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [busy, setBusy] = useState(false);
  const [publishPublicly, setPublishPublicly] = useState(false);
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);
  const [attempt, setAttempt] = useState<SubmissionPayload | null>(null);
  const [confirmedId, setConfirmedId] = useState('');
  const tracker = useRef<ReturnType<typeof createSubmissionAttemptTracker> | null>(null);
  const inFlight = useRef(false);
  if (tracker.current === null) tracker.current = createSubmissionAttemptTracker();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    if (inFlight.current) return;
    inFlight.current = true;
    const form = event.currentTarget;
    const data = new FormData(form);
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    const checkOnly = submitter instanceof HTMLButtonElement && submitter.value === 'check';
    const apiKey = value(data, 'apiKey');
    const keyInput = form.elements.namedItem('apiKey');
    if (keyInput instanceof HTMLInputElement) keyInput.value = '';

    setBusy(true);
    setMessage('');
    setIsError(false);
    setConfirmedId('');

    try {
      const payload = checkOnly && attempt ? attempt : tracker.current!.prepare({
        opportunityId,
        builderId: value(data, 'builderId'),
        listingId: value(data, 'listingId'),
        proposal: value(data, 'proposal'),
        team: value(data, 'team'),
        visibility: publishPublicly ? 'public' : 'private',
      });
      setAttempt(payload);

      await sendOrCheckSubmission(payload, apiKey, checkOnly);

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
      setIsError(true);
      const code = caught instanceof Error ? caught.message : '';
      setMessage(code === 'submission_attempt_changed'
        ? 'An earlier response is still unresolved. Restore its original fields to retry, or check the recorded response before starting a separate one.'
        : code === 'submission_key_required' ? 'Enter a valid EMILIA API key. Nothing was sent.'
          : code === 'submission_access_refused' ? 'This key was not accepted. Enter the key that owns your builder profile and try again.'
            : 'We could not confirm the response. It may already have been recorded. Enter your key and check it below, or retry with the same response ID.');
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  return (
    <div style={{ ...styles.card, marginBottom: 48 }}>
      <div className={formStyles.notice} style={{ marginBottom: 20 }}>
        <p style={{ ...styles.cardBody, margin: 0 }}>
          Private responses can be read by you, the opportunity owner and authorized administrators. Public publication is optional.
          Your API key is used for this request only and is not saved in the browser.
          The owner checks responses in their private inbox; no email notification is sent automatically.
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
      <form method="post" className={formStyles.form} onSubmit={handleSubmit}>
        <fieldset disabled={!ready || busy} className={formStyles.fieldset} style={{ border: 0 }}>
        <div className={formStyles.gridTwo}>
          <Field label="EMILIA API key">
            <input className="ep-input" style={styles.input} name="apiKey" type="password" required
              autoComplete="off" spellCheck={false} autoCapitalize="off" maxLength={512} data-1p-ignore data-lpignore="true" placeholder="ep_live_…" />
          </Field>
          <Field label="Builder ID">
            <input className="ep-input" style={styles.input} name="builderId" required minLength={3} maxLength={64}
              pattern="[a-z0-9][a-z0-9-]{2,63}" placeholder="your-builder-id" autoComplete="off" />
          </Field>
          <Field label="Listing ID" hint="Optional. Include the listing you propose to use.">
            <input className="ep-input" style={styles.input} name="listingId" minLength={3} maxLength={64}
              pattern="[a-z0-9][a-z0-9-]{2,63}" placeholder="your-listing-id" autoComplete="off" />
          </Field>
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
          <p style={{ ...styles.cardBody, margin: 0 }}>Enter your key again above. This check only reads your saved response; it does not send a new proposal.</p>
          <p style={{ ...styles.cardBody, margin: 0 }}>Start a separate response only after checking. This may create another proposal; it does not withdraw the earlier one.</p>
          <button type="button" disabled={busy} style={cta.secondary} onClick={() => {
            if (inFlight.current) return;
            tracker.current!.clear(); setAttempt(null); setMessage('The next send will be a separate response. The earlier response may still exist.'); setIsError(false);
          }}>Start a separate response</button>
        </div> : null}

        <div className={formStyles.actions}>
          <button type="submit" disabled={!ready || busy} style={!ready || busy ? cta.disabled : cta.primary} className={!ready || busy ? undefined : 'ep-cta'}>
            {busy ? 'Sending…' : publishPublicly ? 'Publish response' : 'Send private response'}
          </button>
        </div>
        <div className={formStyles.status} style={{ color: isError ? color.red : color.green }}
          role={isError ? 'alert' : 'status'} aria-live="polite">
          {message}
        </div>
        {confirmedId ? <div className={formStyles.notice}>
          <p style={{ ...styles.body, margin: 0 }}>Recorded response: <code style={{ overflowWrap: 'anywhere' }}>{confirmedId}</code></p>
          <a href={`/works/submissions/${confirmedId}`} style={{ color: color.t1, fontWeight: 600 }}>Open your recorded proposal</a>
          <p style={{ ...styles.cardBody, margin: 0 }}>Bookmark that page to return later. You’ll need your API key to open a private response.</p>
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
