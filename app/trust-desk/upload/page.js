'use client';

/**
 * AI Trust Desk intake form (/trust-desk/upload).
 *
 * Qualifier-driven: the "active deal blocked" answer determines routing.
 *   - "yes" → submit + redirect to Stripe for the chosen tier
 *   - "soon" or "no" → submit + show waitlist confirmation (no Stripe)
 *
 * File upload posts as multipart to the configured webhook. Production
 * deployments should swap this for a signed S3/R2 PUT URL so files go
 * directly to object storage.
 */

import { useState } from 'react';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

const ACCENT = color.blue;

// Fallback to a sales mailto when Stripe link envs are missing — a click
// on production never lands on a 404. Same pattern as app/trust-desk/page.js.
const SALES_MAILTO         = 'mailto:team@emiliaprotocol.ai?subject=Trust%20Desk%20order';
const STRIPE_PACKET_URL    = process.env.NEXT_PUBLIC_STRIPE_PACKET    || SALES_MAILTO;
const STRIPE_EMERGENCY_URL = process.env.NEXT_PUBLIC_STRIPE_EMERGENCY || SALES_MAILTO;
// Form webhook fallback also goes to mailto so a missing env doesn't post
// PII to a placeholder URL.
const FORM_WEBHOOK_URL     = process.env.NEXT_PUBLIC_INTAKE_WEBHOOK   || SALES_MAILTO;

const INITIAL = {
  company: '', website: '', contact_name: '', contact_email: '',
  product_description: '', selling_into: 'fintech',
  active_deal_blocked: 'yes', buyer_name: '',
  ai_uses_customer_data: 'no', cloud_provider: '', soc2_status: 'in_progress',
  deadline: '', tier_preference: 'packet', notes: '',
};

export default function UploadPage() {
  const [form, setForm] = useState(INITIAL);
  const [file, setFile] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  function update(k, v) { setForm((f) => ({ ...f, [k]: v })); }

  async function onSubmit(e) {
    e.preventDefault();
    setError(null);

    if (!form.company.trim() || !form.contact_email.trim()) {
      setError('Company and email are required.');
      return;
    }
    if (!form.contact_email.includes('@')) {
      setError('Enter a valid email.');
      return;
    }
    if (form.selling_into !== 'fintech' && form.selling_into !== 'financial_services') {
      setError(
        'We only serve AI vendors selling into financial services right now. ' +
        'Healthcare is planned; you can note your interest below.',
      );
      return;
    }

    setSubmitting(true);
    try {
      const payload = new FormData();
      for (const [k, v] of Object.entries(form)) payload.append(k, v);
      if (file) payload.append('questionnaire', file);
      payload.append('submitted_at', new Date().toISOString());

      fetch(FORM_WEBHOOK_URL, { method: 'POST', body: payload }).catch(() => {});
      setSubmitted(true);

      if (form.active_deal_blocked === 'yes') {
        const stripe = form.tier_preference === 'emergency' ? STRIPE_EMERGENCY_URL : STRIPE_PACKET_URL;
        setTimeout(() => {
          window.location.href = `${stripe}?prefilled_email=${encodeURIComponent(form.contact_email)}`;
        }, 800);
      }
    } catch (err) {
      setError(`Submission failed: ${err.message}. Email hello@aitrustdesk.com directly.`);
      setSubmitting(false);
    }
  }

  if (submitted) {
    const qualified = form.active_deal_blocked === 'yes';
    return (
      <div style={styles.page}>
        <SiteNav />
        <div style={{ ...styles.section, maxWidth: 640 }}>
          <h1 style={{ fontSize: 32, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            {qualified ? 'Thanks — redirecting to checkout' : 'We received your interest'}
          </h1>
          <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.65, marginTop: 16 }}>
            {qualified
              ? `You are being redirected to Stripe to complete payment. Once checkout is done we will email you within 2 hours to confirm the intake and assign your reviewer.`
              : `AI Trust Desk is currently prioritizing vendors with an active stuck deal. We have logged your interest and will reach out when we open capacity for proactive-trust packages (4–6 weeks).`}
          </p>
          {qualified ? (
            <p style={{ fontSize: 14, color: color.t3, marginTop: 24 }}>
              If the redirect doesn&apos;t happen in 5 seconds, open{' '}
              <a href={form.tier_preference === 'emergency' ? STRIPE_EMERGENCY_URL : STRIPE_PACKET_URL}
                 style={{ color: ACCENT, textDecoration: 'underline' }}>checkout</a> manually.
            </p>
          ) : (
            <>
              <p style={{ fontSize: 14, color: color.t3, marginTop: 24 }}>
                In the meantime, forward any enterprise security review you receive to{' '}
                <a href="mailto:hello@aitrustdesk.com" style={{ color: ACCENT, textDecoration: 'underline' }}>
                  hello@aitrustdesk.com
                </a> and we&apos;ll route it faster.
              </p>
              <Link href="/trust-desk" style={{ display: 'inline-block', color: color.t3, textDecoration: 'underline', marginTop: 32, fontSize: 14 }}>
                ← Back to Trust Desk
              </Link>
            </>
          )}
        </div>
        <SiteFooter />
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <SiteNav />
      <div style={{ ...styles.section, maxWidth: 640 }}>
        <Link href="/trust-desk" style={{ fontSize: 14, color: color.t3, textDecoration: 'underline' }}>
          ← Back
        </Link>

        <h1 style={{ fontSize: 32, fontWeight: 700, letterSpacing: '-0.01em', marginTop: 24, margin: 0 }}>
          Upload your AI security review
        </h1>
        <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.65, marginTop: 12 }}>
          Takes about 5 minutes. A reviewer will confirm receipt within 2 business hours;
          full delivery in 24–48 hours once Stripe payment completes.
        </p>

        <form onSubmit={onSubmit} style={{ marginTop: 40, display: 'flex', flexDirection: 'column', gap: 32 }} noValidate>
          <Fieldset legend="About your company">
            <Field label="Company name" required>
              <Input type="text" required value={form.company} onChange={(e) => update('company', e.target.value)} />
            </Field>
            <Field label="Website">
              <Input type="url" placeholder="https://" value={form.website} onChange={(e) => update('website', e.target.value)} />
            </Field>
            <Field label="Your name" required>
              <Input type="text" required value={form.contact_name} onChange={(e) => update('contact_name', e.target.value)} />
            </Field>
            <Field label="Your email" required>
              <Input type="email" required value={form.contact_email} onChange={(e) => update('contact_email', e.target.value)} />
            </Field>
            <Field label="One-sentence product description" required>
              <Textarea rows={2} required value={form.product_description}
                onChange={(e) => update('product_description', e.target.value)}
                placeholder="e.g., AI-native KYC platform for mid-market banks." />
            </Field>
          </Fieldset>

          <Fieldset legend="Qualifier (determines how fast we can help)">
            <Field label="Who do you sell into?" required>
              <Select value={form.selling_into} onChange={(e) => update('selling_into', e.target.value)}>
                <option value="fintech">Fintech / financial services</option>
                <option value="financial_services">Banks / insurers / funds</option>
                <option value="healthcare">Healthcare (waitlist)</option>
                <option value="other">Other (waitlist)</option>
              </Select>
            </Field>
            <Field label="Do you have an active enterprise deal blocked by security, risk, legal, or procurement review?" required>
              <Select value={form.active_deal_blocked} onChange={(e) => update('active_deal_blocked', e.target.value)}>
                <option value="yes">Yes — named account, clock is running</option>
                <option value="soon">Not yet, but expecting one in 1–4 weeks</option>
                <option value="no">No — preparing in advance</option>
              </Select>
            </Field>
            {form.active_deal_blocked === 'yes' && (
              <Field label="Buyer name (kept confidential)">
                <Input type="text" value={form.buyer_name} onChange={(e) => update('buyer_name', e.target.value)}
                  placeholder="e.g., Capital One, Goldman, BlackRock" />
              </Field>
            )}
          </Fieldset>

          <Fieldset legend="Product & infra basics">
            <Field label="Does your AI use customer data at inference, training, or both?" required>
              <Select value={form.ai_uses_customer_data} onChange={(e) => update('ai_uses_customer_data', e.target.value)}>
                <option value="no">No customer data at inference or training</option>
                <option value="inference">Customer data at inference only (not training)</option>
                <option value="training">Customer data at training only</option>
                <option value="both">Both</option>
                <option value="unsure">I&apos;m not sure</option>
              </Select>
            </Field>
            <Field label="Primary cloud provider">
              <Input type="text" value={form.cloud_provider} onChange={(e) => update('cloud_provider', e.target.value)}
                placeholder="e.g., AWS us-east-1 + GCP us-central1" />
            </Field>
            <Field label="SOC 2 status" required>
              <Select value={form.soc2_status} onChange={(e) => update('soc2_status', e.target.value)}>
                <option value="type2">Type 2 complete</option>
                <option value="type1">Type 1 complete, Type 2 in progress</option>
                <option value="in_progress">In progress (Vanta / Drata / other)</option>
                <option value="planned">Planned — not started</option>
                <option value="none">None</option>
              </Select>
            </Field>
            <Field label="Deadline">
              <Input type="text" value={form.deadline} onChange={(e) => update('deadline', e.target.value)}
                placeholder="e.g., 2026-05-10 (buyer's EOD)" />
            </Field>
          </Fieldset>

          <Fieldset legend="Which tier?">
            <Field label="Preference">
              <Select value={form.tier_preference} onChange={(e) => update('tier_preference', e.target.value)}>
                <option value="packet">AI Trust Packet — $24,500 (recommended)</option>
                <option value="emergency">Emergency Review — $3,500</option>
                <option value="full">Full Completion — $9,500</option>
                <option value="retainer">Retainer — $12,000/mo</option>
                <option value="unsure">Not sure — recommend me one</option>
              </Select>
            </Field>
          </Fieldset>

          <Fieldset legend="Attach the questionnaire or buyer request">
            <Field label="File (Excel, PDF, Word, up to 25 MB)">
              <input
                type="file"
                accept=".xlsx,.xls,.pdf,.docx,.doc,.csv,.txt,.md"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                style={inputStyle}
              />
              <p style={{ fontSize: 12, color: color.t3, marginTop: 8, lineHeight: 1.5 }}>
                If you cannot share the file now, paste a description below. File storage is via
                signed URL to an S3-compatible bucket — you can request deletion any time.
              </p>
            </Field>
            <Field label="Notes (optional)">
              <Textarea rows={3} value={form.notes} onChange={(e) => update('notes', e.target.value)}
                placeholder="Anything else: the buyer pushback, a past question you struggled with, timing." />
            </Field>
          </Fieldset>

          {error && (
            <div style={{
              border: `1px solid ${color.red}`, background: '#FEF2F2', color: color.red,
              padding: '12px 16px', borderRadius: radius.sm, fontSize: 14,
            }}>{error}</div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'flex-start' }}>
            <button type="submit" disabled={submitting} style={{
              background: ACCENT, color: '#FFFFFF', fontWeight: 600, fontSize: 16,
              padding: '14px 24px', borderRadius: radius.sm, border: 'none',
              fontFamily: font.sans, cursor: submitting ? 'not-allowed' : 'pointer',
              opacity: submitting ? 0.6 : 1,
            }}>
              {submitting ? 'Submitting…' : form.active_deal_blocked === 'yes' ? 'Submit & go to checkout' : 'Submit'}
            </button>
            <p style={{ fontSize: 12, color: color.t3, lineHeight: 1.5 }}>
              By submitting you agree the information you provide is accurate to the best of
              your knowledge. Our MSA lands by email before any deliverable is published.
            </p>
          </div>
        </form>
      </div>
      <SiteFooter />
    </div>
  );
}

const inputStyle = {
  width: '100%', padding: '10px 12px', borderRadius: radius.sm,
  border: `1px solid ${color.inputBorder}`, fontFamily: font.sans, fontSize: 14,
  color: color.t1, background: color.card,
};

function Fieldset({ legend, children }) {
  return (
    <fieldset style={{ border: 0, padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <legend style={{
        fontFamily: font.mono, fontSize: 11, color: color.t3,
        letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600,
        padding: 0, marginBottom: 4,
      }}>{legend}</legend>
      {children}
    </fieldset>
  );
}

function Field({ label, required, children }) {
  return (
    <label style={{ display: 'block' }}>
      <span style={{ display: 'block', fontSize: 14, fontWeight: 500, color: color.t1, marginBottom: 6 }}>
        {label}
        {required && <span style={{ color: ACCENT, marginLeft: 4 }}>*</span>}
      </span>
      {children}
    </label>
  );
}

function Input(props) { return <input {...props} style={inputStyle} />; }
function Textarea(props) { return <textarea {...props} style={inputStyle} />; }
function Select({ children, ...props }) { return <select {...props} style={inputStyle}>{children}</select>; }
