// SPDX-License-Identifier: Apache-2.0

'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import { color, cta, styles } from '@/lib/tokens';
import {
  buildOpportunityPayload,
  type OpportunityFormInput,
  type SponsorClaimInput,
} from './form-payloads';
import formStyles from './works.module.css';

function value(data: FormData, name: string): string {
  return String(data.get(name) || '').trim();
}

async function responseError(response: Response): Promise<string> {
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  for (const key of ['detail', 'message', 'error', 'title']) {
    if (typeof body?.[key] === 'string' && body[key]) return body[key];
  }
  return 'The opportunity could not be posted.';
}

function claimInput(data: FormData, prefix: string): SponsorClaimInput {
  return {
    statement: value(data, `${prefix}Statement`),
    status: value(data, `${prefix}Status`) as SponsorClaimInput['status'],
    scope: value(data, `${prefix}Scope`),
    limitations: value(data, `${prefix}Limitations`),
  };
}

export default function OpportunityForm() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [postedId, setPostedId] = useState('');

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');

    const data = new FormData(event.currentTarget);
    const apiKey = value(data, 'apiKey');
    const eligibility = claimInput(data, 'eligibility');
    if (eligibility.statement && !eligibility.scope) {
      setError('Add an exact scope for the eligibility statement, or leave the optional statement blank.');
      setBusy(false);
      return;
    }

    const input: OpportunityFormInput = {
      opportunityId: value(data, 'opportunityId'),
      kind: value(data, 'kind') as OpportunityFormInput['kind'],
      title: value(data, 'title'),
      description: value(data, 'description'),
      postedBy: value(data, 'postedBy'),
      contactRoute: value(data, 'contactRoute'),
      funding: claimInput(data, 'funding'),
      authority: claimInput(data, 'authority'),
      eligibility: eligibility.statement ? eligibility : null,
    };
    const payload = buildOpportunityPayload(input);

    try {
      const response = await fetch('/api/works/opportunities', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        setError(await responseError(response));
        return;
      }
      setPostedId(payload.opportunity_id);
    } catch {
      setError('The network response was interrupted, so posting could not be confirmed. Check the opportunity list before retrying.');
    } finally {
      setBusy(false);
    }
  }

  if (postedId) {
    return (
      <section style={styles.card} className={formStyles.notice} aria-labelledby="opportunity-posted">
        <div style={styles.eyebrow}>Posted</div>
        <h2 id="opportunity-posted" style={{ ...styles.h2, margin: 0 }}>The opportunity is public on Works.</h2>
        <p style={{ ...styles.body, margin: 0 }}>
          Its funding, authority, and any eligibility statements display the evidence status selected
          in this form. Works does not handle payment, custody, or escrow.
        </p>
        <div className={formStyles.actions}>
          <Link href={`/works/opportunities/${postedId}`} style={cta.primary} className="ep-cta">
            View opportunity
          </Link>
          <Link href="/works/opportunities" style={cta.secondary} className="ep-cta-secondary">
            Browse opportunities
          </Link>
        </div>
      </section>
    );
  }

  return (
    <form className={formStyles.form} onSubmit={handleSubmit}>
      <fieldset className={formStyles.fieldset} style={styles.card}>
        <legend className={formStyles.legend}>Sponsor and opportunity</legend>
        <div className={formStyles.gridTwo}>
          <Field label="EMILIA API key" hint="Used for this request only; it is not saved in the browser.">
            <input className="ep-input" style={styles.input} name="apiKey" type="password" required
              autoComplete="off" spellCheck={false} placeholder="ep_… or ept_…" />
          </Field>
          <Field label="Opportunity ID" hint="3–64 lowercase letters, numbers, and hyphens.">
            <input className="ep-input" style={styles.input} name="opportunityId" required minLength={3} maxLength={64}
              pattern="[a-z0-9][a-z0-9-]{2,63}" placeholder="bounded-research-challenge" autoComplete="off" />
          </Field>
          <Field label="Sponsor name" hint="The authenticated entity display name is authoritative and may replace this value.">
            <input className="ep-input" style={styles.input} name="postedBy" required maxLength={200}
              placeholder="Accountable sponsor or organization" />
          </Field>
          <Field label="Sponsor contact route" hint="Builders can use this mailto: or https:// route for a private response.">
            <input className="ep-input" style={styles.input} name="contactRoute" required maxLength={600}
              placeholder="mailto:sponsor@example.com" />
          </Field>
          <Field label="Opportunity kind">
            <select className="ep-input" style={styles.input} name="kind" defaultValue="problem">
              <option value="problem">Problem</option>
              <option value="challenge">Challenge</option>
              <option value="bounty">Bounty</option>
              <option value="procurement_notice">Procurement notice</option>
              <option value="collaboration">Collaboration</option>
            </select>
          </Field>
          <Field label="Title">
            <input className="ep-input" style={styles.input} name="title" required maxLength={200}
              placeholder="What needs to be done?" />
          </Field>
          <div className={formStyles.full}>
            <Field label="Description" hint="Name the deliverable, boundaries, and what a useful response should include.">
              <textarea className={`ep-input ${formStyles.textarea}`} style={styles.input} name="description"
                required maxLength={8000} placeholder="Describe the work without implying funding or authority that has not been established." />
            </Field>
          </div>
        </div>
      </fieldset>

      <fieldset className={formStyles.fieldset} style={styles.card}>
        <legend className={formStyles.legend}>Evidence-status statements</legend>
        <p style={{ ...styles.cardBody, margin: '0 0 20px' }}>
          ASSERTED means the sponsor is the source of the statement. UNKNOWN means no supporting
          source is recorded. This self-service form cannot create VERIFIED statements.
        </p>
        <div className={formStyles.form}>
          <ClaimFields
            prefix="funding"
            title="Funding"
            statementPlaceholder="State the amount, availability, or that funding has not been established."
          />
          <ClaimFields
            prefix="authority"
            title="Sponsor authority"
            statementPlaceholder="State the sponsor's authority to issue, select, or procure for this opportunity."
          />
          <ClaimFields
            prefix="eligibility"
            title="Eligibility (optional)"
            statementPlaceholder="State any eligibility condition that builders should evaluate."
            optional
          />
        </div>
        <p style={{ ...styles.cardBody, margin: '20px 0 0', color: color.t3 }}>
          These statements do not move funds or create payment, custody, escrow, or procurement authority.
        </p>
      </fieldset>

      <div className={formStyles.actions}>
        <button type="submit" disabled={busy} style={busy ? cta.disabled : cta.primary} className={busy ? undefined : 'ep-cta'}>
          {busy ? 'Posting…' : 'Post opportunity'}
        </button>
        <Link href="/works/opportunities" style={cta.ghost} className="ep-cta-ghost">Cancel</Link>
      </div>
      <div className={formStyles.status} style={{ color: error ? color.red : color.t3 }} role={error ? 'alert' : undefined} aria-live="polite">
        {error}
      </div>
    </form>
  );
}

function ClaimFields({ prefix, title, statementPlaceholder, optional = false }: {
  prefix: 'funding' | 'authority' | 'eligibility';
  title: string;
  statementPlaceholder: string;
  optional?: boolean;
}) {
  return (
    <fieldset className={formStyles.fieldset}>
      <legend style={{ ...styles.label, marginBottom: 12 }}>{title}</legend>
      <div className={formStyles.gridThree}>
        <div className={formStyles.full}>
          <Field label="Statement" hint={optional ? 'Leave blank to omit this statement.' : undefined}>
            <textarea className={`ep-input ${formStyles.textarea}`} style={styles.input}
              name={`${prefix}Statement`} required={!optional} maxLength={600} placeholder={statementPlaceholder} />
          </Field>
        </div>
        <Field label="Status">
          <select className="ep-input" style={styles.input} name={`${prefix}Status`} defaultValue="UNKNOWN">
            <option value="UNKNOWN">UNKNOWN — no source recorded</option>
            <option value="ASSERTED">ASSERTED — sponsor statement</option>
          </select>
        </Field>
        <div className={formStyles.spanTwo}>
          <Field label="Exact scope">
            <input className="ep-input" style={styles.input} name={`${prefix}Scope`} required={!optional}
              maxLength={600} placeholder="What this statement covers—and nothing beyond it." />
          </Field>
        </div>
        <div className={formStyles.full}>
          <Field label="Limitations" hint="Optional but recommended.">
            <input className="ep-input" style={styles.input} name={`${prefix}Limitations`}
              maxLength={1000} placeholder="Known conditions, exclusions, or unresolved facts." />
          </Field>
        </div>
      </div>
    </fieldset>
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
