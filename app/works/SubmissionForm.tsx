// SPDX-License-Identifier: Apache-2.0

'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { color, cta, styles } from '@/lib/tokens';
import { buildSubmissionPayload } from './form-payloads';
import formStyles from './works.module.css';

type SubmissionFormProps = {
  opportunityId: string;
  sponsorName: string;
  sponsorContactRoute: string;
};

function value(data: FormData, name: string): string {
  return String(data.get(name) || '').trim();
}

async function responseError(response: Response): Promise<string> {
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  for (const key of ['detail', 'message', 'error', 'title']) {
    if (typeof body?.[key] === 'string' && body[key]) return body[key];
  }
  return 'The proposal could not be posted.';
}

function newSubmissionId(): string {
  return `submission-${Date.now().toString(36)}-${window.crypto.randomUUID().slice(0, 8)}`;
}

export default function SubmissionForm({
  opportunityId,
  sponsorName,
  sponsorContactRoute,
}: SubmissionFormProps) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [publishPublicly, setPublishPublicly] = useState(false);
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);

    setBusy(true);
    setMessage('');
    setIsError(false);

    try {
      const payload = buildSubmissionPayload({
        opportunityId,
        builderId: value(data, 'builderId'),
        listingId: value(data, 'listingId'),
        proposal: value(data, 'proposal'),
        team: value(data, 'team'),
        visibility: publishPublicly ? 'public' : 'private',
      }, newSubmissionId());

      const response = await fetch('/api/works/submissions', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${value(data, 'apiKey')}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        setIsError(true);
        setMessage(await responseError(response));
        return;
      }

      form.reset();
      setPublishPublicly(false);
      setMessage(payload.visibility === 'public'
        ? 'Your proposal was published on this opportunity page.'
        : 'Your private response was shared only with the opportunity owner.');
      router.refresh();
    } catch (caught) {
      setIsError(true);
      setMessage(caught instanceof Error ? caught.message : 'The proposal could not be posted.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ ...styles.card, marginBottom: 48 }}>
      <div className={formStyles.notice} style={{ marginBottom: 20 }}>
        <p style={{ ...styles.cardBody, margin: 0 }}>
          Responses are private by default and shared only with the opportunity owner. Public publication is optional.
          Your API key is used for this request only and is not saved in the browser.
        </p>
        <p style={{ ...styles.cardBody, margin: 0 }}>
          Prefer not to post publicly?{' '}
          <a href={sponsorContactRoute} style={{ color: color.t1, fontWeight: 600 }}>
            Contact the sponsor privately
          </a>{' '}
          through {sponsorName}&apos;s listed contact route.
        </p>
      </div>

      <form className={formStyles.form} onSubmit={handleSubmit}>
        <div className={formStyles.gridTwo}>
          <Field label="EMILIA API key">
            <input className="ep-input" style={styles.input} name="apiKey" type="password" required
              autoComplete="off" spellCheck={false} placeholder="ep_… or ept_…" />
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

        <div className={formStyles.actions}>
          <button type="submit" disabled={busy} style={busy ? cta.disabled : cta.primary} className={busy ? undefined : 'ep-cta'}>
            {busy ? 'Sending…' : publishPublicly ? 'Publish response' : 'Send private response'}
          </button>
        </div>
        <div className={formStyles.status} style={{ color: isError ? color.red : color.green }}
          role={isError ? 'alert' : 'status'} aria-live="polite">
          {message}
        </div>
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
