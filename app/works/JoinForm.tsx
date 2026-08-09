// SPDX-License-Identifier: Apache-2.0

'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import { color, cta, font, styles } from '@/lib/tokens';
import {
  buildJoinPayloads,
  type JoinFormInput,
  type JoinPayloads,
} from './form-payloads';
import formStyles from './works.module.css';

type RegistrationResponse = {
  api_key?: string;
  owner_id?: string;
  entity?: { entity_id?: string };
};

type JoinProgress = {
  apiKey: string;
  ownerId: string;
  payloads: JoinPayloads;
  builderCreated: boolean;
  listingCreated: boolean;
  failureStage: 'builder' | 'listing' | null;
  failureMessage: string;
};

class RequestFailure extends Error {}

function value(data: FormData, name: string): string {
  return String(data.get(name) || '').trim();
}

async function responseError(response: Response, fallback: string): Promise<string> {
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  for (const key of ['detail', 'message', 'error', 'title']) {
    if (typeof body?.[key] === 'string' && body[key]) return body[key];
  }
  return fallback;
}

async function postWorksRecord(
  collection: 'builders' | 'listings',
  apiKey: string,
  record: unknown,
): Promise<void> {
  const response = await fetch(`/api/works/${collection}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(record),
  });
  if (!response.ok) {
    throw new RequestFailure(await responseError(response, `Works ${collection} could not be created.`));
  }
}

export default function JoinForm() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState<JoinProgress | null>(null);
  const [copyStatus, setCopyStatus] = useState('');

  async function publishWorks(start: JoinProgress): Promise<void> {
    let next = { ...start, failureStage: null, failureMessage: '' } as JoinProgress;
    setProgress(next);

    if (!next.builderCreated) {
      try {
        await postWorksRecord('builders', next.apiKey, next.payloads.builder);
        next = { ...next, builderCreated: true };
        setProgress(next);
      } catch (caught) {
        setProgress({
          ...next,
          failureStage: 'builder',
          failureMessage: caught instanceof Error ? caught.message : 'The Works profile was not created.',
        });
        return;
      }
    }

    if (!next.listingCreated) {
      try {
        await postWorksRecord('listings', next.apiKey, next.payloads.listing);
        next = { ...next, listingCreated: true };
        setProgress(next);
      } catch (caught) {
        setProgress({
          ...next,
          failureStage: 'listing',
          failureMessage: caught instanceof Error ? caught.message : 'The first listing was not created.',
        });
      }
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setCopyStatus('');

    const data = new FormData(event.currentTarget);
    const input: JoinFormInput = {
      builderId: value(data, 'builderId'),
      builderKind: value(data, 'builderKind') as JoinFormInput['builderKind'],
      builderName: value(data, 'builderName'),
      builderSummary: value(data, 'builderSummary'),
      contactRoute: value(data, 'contactRoute'),
      affiliationName: value(data, 'affiliationName'),
      affiliationRelation: value(data, 'affiliationRelation'),
      listingId: value(data, 'listingId'),
      listingKind: value(data, 'listingKind') as JoinFormInput['listingKind'],
      listingName: value(data, 'listingName'),
      listingSummary: value(data, 'listingSummary'),
      repositoryUrl: value(data, 'repositoryUrl'),
      serviceUrl: value(data, 'serviceUrl'),
      license: value(data, 'license'),
      supportedTasks: value(data, 'supportedTasks'),
      interfaces: value(data, 'interfaces'),
      operatingConstraints: value(data, 'operatingConstraints'),
    };

    if (Boolean(input.affiliationName) !== Boolean(input.affiliationRelation)) {
      setError('Enter both affiliation name and relationship, or leave both blank.');
      setBusy(false);
      return;
    }

    const payloads = buildJoinPayloads(input);

    try {
      const response = await fetch('/api/entities/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payloads.entity),
      });
      if (!response.ok) {
        const detail = await responseError(response, 'Entity registration could not be completed.');
        setError(`${detail} No one-time API key was returned to this page.`);
        return;
      }

      const body = await response.json() as RegistrationResponse;
      if (!body.api_key) {
        setError('Registration returned without an API key, so Works setup could not continue.');
        return;
      }

      const registered: JoinProgress = {
        apiKey: body.api_key,
        ownerId: body.owner_id || '',
        payloads,
        builderCreated: false,
        listingCreated: false,
        failureStage: null,
        failureMessage: '',
      };
      setProgress(registered);
      await publishWorks(registered);
    } catch {
      setError(
        'We could not confirm whether registration completed, and no API key reached this page. '
        + 'Check the connection before retrying; the same IDs may already be registered.',
      );
    } finally {
      setBusy(false);
    }
  }

  async function retryWorks() {
    if (!progress) return;
    setBusy(true);
    setError('');
    try {
      await publishWorks(progress);
    } finally {
      setBusy(false);
    }
  }

  async function copyKey() {
    if (!progress) return;
    try {
      await navigator.clipboard.writeText(progress.apiKey);
      setCopyStatus('Copied. Store it in your secret manager now.');
    } catch {
      setCopyStatus('Copy failed. Select the key and copy it manually.');
    }
  }

  if (progress) {
    const complete = progress.builderCreated && progress.listingCreated;
    return (
      <div className={formStyles.form}>
        <section style={styles.card} className={formStyles.notice} aria-labelledby="works-join-result">
          <div style={styles.eyebrow}>{complete ? 'Published' : 'Action required'}</div>
          <h2 id="works-join-result" style={{ ...styles.h2, margin: 0 }}>
            {complete
              ? 'Your profile and first listing are live.'
              : progress.builderCreated
                ? 'Your profile is live; the listing is not.'
                : 'Registration succeeded; the Works profile is not live.'}
          </h2>
          {progress.failureMessage ? (
            <p style={{ ...styles.body, margin: 0, color: color.red }}>{progress.failureMessage}</p>
          ) : null}
          {!complete ? (
            <p style={{ ...styles.body, margin: 0 }}>
              Your EMILIA entity registration is already complete. Do not register it again. Save
              the key below, then retry only the unfinished Works step.
            </p>
          ) : null}
        </section>

        <section style={styles.card} className={formStyles.notice} aria-labelledby="works-api-key">
          <div>
            <div id="works-api-key" style={{ ...styles.label, marginBottom: 8 }}>One-time API key</div>
            <p style={{ ...styles.cardBody, margin: '0 0 12px' }}>
              This is the only copy returned to this page. It is kept only in this open page and
              cannot be retrieved after you leave or reload. Treat it as a secret.
            </p>
            <code className={formStyles.keyValue} style={{
              padding: '14px 16px',
              border: `1px solid ${color.border}`,
              borderRadius: 8,
              background: color.cardHover,
              color: color.t1,
              fontFamily: font.mono,
              fontSize: 13,
            }}>
              {progress.apiKey}
            </code>
          </div>
          {progress.ownerId ? (
            <div>
              <div style={{ ...styles.label, marginBottom: 6 }}>Owner ID</div>
              <code className={formStyles.keyValue} style={{ color: color.t2, fontFamily: font.mono, fontSize: 12 }}>
                {progress.ownerId}
              </code>
            </div>
          ) : null}
          <div className={formStyles.actions}>
            <button type="button" onClick={copyKey} style={cta.secondary} className="ep-cta-secondary">
              Copy key
            </button>
            {!complete ? (
              <button
                type="button"
                onClick={retryWorks}
                disabled={busy}
                style={busy ? cta.disabled : cta.primary}
                className={busy ? undefined : 'ep-cta'}
              >
                {busy ? 'Retrying…' : 'Retry Works setup'}
              </button>
            ) : (
              <>
                <Link href={`/works/builders/${progress.payloads.builder.builder_id}`} style={cta.secondary} className="ep-cta-secondary">
                  View profile
                </Link>
                <Link href={`/works/listings/${progress.payloads.listing.listing_id}`} style={cta.primary} className="ep-cta">
                  View listing
                </Link>
              </>
            )}
          </div>
          <div className={formStyles.status} style={{ color: color.t3 }} aria-live="polite">
            {copyStatus}
          </div>
        </section>
      </div>
    );
  }

  return (
    <form className={formStyles.form} onSubmit={handleSubmit}>
      <fieldset className={formStyles.fieldset} style={styles.card}>
        <legend className={formStyles.legend}>Accountable builder</legend>
        <div className={formStyles.gridTwo}>
          <Field label="Builder ID" hint="3–64 lowercase letters, numbers, and hyphens.">
            <input className="ep-input" style={styles.input} name="builderId" required minLength={3} maxLength={64}
              pattern="[a-z0-9][a-z0-9-]{2,63}" placeholder="northstar-labs" autoComplete="off" />
          </Field>
          <Field label="Profile type">
            <select className="ep-input" style={styles.input} name="builderKind" defaultValue="person">
              <option value="person">Person</option>
              <option value="legal_entity">Legal entity</option>
            </select>
          </Field>
          <Field label="Accountable name">
            <input className="ep-input" style={styles.input} name="builderName" required maxLength={200}
              placeholder="Person or legal entity name" autoComplete="name" />
          </Field>
          <Field label="Contact route" hint="Use a mailto: or https:// route that visitors can follow.">
            <input className="ep-input" style={styles.input} name="contactRoute" required maxLength={600}
              placeholder="mailto:you@example.com" autoComplete="url" />
          </Field>
          <div className={formStyles.full}>
            <Field label="Builder summary" hint="Optional. Describe who is accountable; do not imply verification.">
              <textarea className={`ep-input ${formStyles.textarea}`} style={styles.input} name="builderSummary"
                maxLength={2000} placeholder="Who is behind the work and what they are responsible for." />
            </Field>
          </div>
          <Field label="Affiliation" hint="Optional; complete both affiliation fields or neither.">
            <input className="ep-input" style={styles.input} name="affiliationName" maxLength={200}
              placeholder="Organization or sponsor" autoComplete="organization" />
          </Field>
          <Field label="Relationship">
            <input className="ep-input" style={styles.input} name="affiliationRelation" maxLength={200}
              placeholder="employee, sponsor, independent builder" />
          </Field>
        </div>
      </fieldset>

      <fieldset className={formStyles.fieldset} style={styles.card}>
        <legend className={formStyles.legend}>First listing</legend>
        <div className={formStyles.gridTwo}>
          <Field label="Listing ID" hint="3–64 lowercase letters, numbers, and hyphens.">
            <input className="ep-input" style={styles.input} name="listingId" required minLength={3} maxLength={64}
              pattern="[a-z0-9][a-z0-9-]{2,63}" placeholder="northstar-agent" autoComplete="off" />
          </Field>
          <Field label="Kind">
            <select className="ep-input" style={styles.input} name="listingKind" defaultValue="agent">
              <option value="agent">Agent</option>
              <option value="app">App</option>
              <option value="project">Project</option>
            </select>
          </Field>
          <Field label="Listing name">
            <input className="ep-input" style={styles.input} name="listingName" required maxLength={200}
              placeholder="Northstar Agent" />
          </Field>
          <Field label="License" hint="Optional; use the exact license identifier if known.">
            <input className="ep-input" style={styles.input} name="license" maxLength={80}
              placeholder="Apache-2.0" />
          </Field>
          <div className={formStyles.full}>
            <Field label="Listing summary">
              <textarea className={`ep-input ${formStyles.textarea}`} style={styles.input} name="listingSummary"
                required maxLength={2000} placeholder="What it does, for whom, and the boundary of the listed work." />
            </Field>
          </div>
          <Field label="Repository URL" hint="Optional HTTPS URL.">
            <input className="ep-input" style={styles.input} name="repositoryUrl" type="url"
              maxLength={600} placeholder="https://github.com/…" />
          </Field>
          <Field label="Service URL" hint="Optional HTTPS URL.">
            <input className="ep-input" style={styles.input} name="serviceUrl" type="url"
              maxLength={600} placeholder="https://app.example.com" />
          </Field>
          <Field label="Supported tasks" hint="Comma-separated; these describe scope, not verified capability.">
            <input className="ep-input" style={styles.input} name="supportedTasks" required
              placeholder="research, synthesis" />
          </Field>
          <Field label="Interfaces" hint="Comma- or line-separated.">
            <input className="ep-input" style={styles.input} name="interfaces" required
              placeholder="MCP, HTTP" />
          </Field>
          <div className={formStyles.full}>
            <Field label="Operating constraints" hint="One per line. State what the listing does not do or requires.">
              <textarea className={`ep-input ${formStyles.textarea}`} style={styles.input} name="operatingConstraints"
                required placeholder={'Requires sponsor approval\nNo payment execution'} />
            </Field>
          </div>
        </div>
      </fieldset>

      <div className={formStyles.actions}>
        <button type="submit" disabled={busy} style={busy ? cta.disabled : cta.primary} className={busy ? undefined : 'ep-cta'}>
          {busy ? 'Creating profile…' : 'Create profile and listing'}
        </button>
        <Link href="/works" style={cta.ghost} className="ep-cta-ghost">Cancel</Link>
      </div>
      <div className={formStyles.status} style={{ color: error ? color.red : color.t3 }} role={error ? 'alert' : undefined} aria-live="polite">
        {error}
      </div>
    </form>
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
