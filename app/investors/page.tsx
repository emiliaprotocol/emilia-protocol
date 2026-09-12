'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

// Public investor-contact surface. Claim boundaries remain visible; detailed
// financing assumptions and private operating material are shared directly.
export default function InvestorsPage() {
  const [form, setForm] = useState({ name: '', firm: '', title: '', email: '', website: '', whyEmilia: '', helpOffer: '', notes: '' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const update = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const res = await fetch('/api/inquiries', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'investor', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const field = (k, label, opts: Record<string, any> = {}) => (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 6, fontFamily: font.sans, fontSize: 13, color: '#57534E' }}>
      {label}{opts.required ? ' *' : ''}
      {opts.area ? (
        <textarea value={form[k]} onChange={(e) => update(k, e.target.value)} required={opts.required} rows={opts.rows || 3}
          style={{ fontFamily: font.sans, fontSize: 15, color: '#0C0A09', background: '#FFFFFF', border: `1px solid ${color.border || '#D6D3D1'}`, borderRadius: radius.base || 4, padding: '10px 12px', resize: 'vertical' }} />
      ) : (
        <input type={opts.type || 'text'} value={form[k]} onChange={(e) => update(k, e.target.value)} required={opts.required}
          style={{ fontFamily: font.sans, fontSize: 15, color: '#0C0A09', background: '#FFFFFF', border: `1px solid ${color.border || '#D6D3D1'}`, borderRadius: radius.base || 4, padding: '10px 12px' }} />
      )}
    </label>
  );

  return (
    <div style={styles.page}>
      <head><meta name="robots" content="noindex, nofollow" /></head>

      <SiteNav activePage="" />
      <main>

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56, maxWidth: 760 }}>
        <div className="ep-tag" style={{ color: color.gold, fontFamily: font.mono || font.sans, fontSize: 12, letterSpacing: '0.16em', textTransform: 'uppercase', marginBottom: 20 }}>Investor Inquiries</div>
        <h1 style={{ fontFamily: font.sans, fontSize: 44, fontWeight: 700, color: '#0C0A09', lineHeight: 1.06, marginBottom: 20, maxWidth: 700 }}>
          Your AI workforce needs management.
        </h1>
        <p style={{ fontFamily: font.sans, fontSize: 18, lineHeight: 1.55, color: '#44403C', maxWidth: 700, marginBottom: 12 }}>
          Give every agent a job, set its authority, and know what happened.
          EMILIA is building the operating workspace around Gate, with the open Protocol underneath.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#78716C', maxWidth: 700, marginBottom: 12 }}>
          The agents can change. The company&apos;s instructions, remaining authority and unfinished
          work need to stay accounted for. That is the infrastructure responsibility we are taking on.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 17, lineHeight: 1.5, fontWeight: 700, color: color.gold, maxWidth: 700, marginBottom: 12 }}>
          Authorization infrastructure for agentic AI.
        </p>
        <div style={{ display: 'grid', gap: 18, marginTop: 32, marginBottom: 24 }}>
          {[
            ['The product', 'A workspace for jobs, owners, agent assignments, authority and work review. Gate applies customer limits on connected execution paths. A person or institution remains accountable.'],
            ['The concrete example', 'A refunds job starts with $10,000 of authority. With $3,000 consumed and $400 unresolved, its replacement agent still has $6,600 available. The retired assignment cannot start new covered work. This is a synthetic local-alpha scenario, not customer money or settlement evidence.'],
            ['The first evaluation', 'One finance team, one refunds workflow, a named owner and agreed acceptance criteria. The external team and provider are not yet selected. Evaluation terms are not yet set.'],
            ['The business', 'The proposed business is recurring software and operating support for protected work, with scoped integration and deployment. Prices and willingness to pay need buyer validation.'],
            ['The path to infrastructure', 'Keep useful identity, approval and business systems in place. Make authority and unfinished work survive changes in agents on supported paths. Earn expansion one customer workflow at a time.'],
            ['The open foundation', 'EMILIA is the company. Gate is the commercial product. The Protocol provides public formats, verifiers and reference code that can be used without buying from EMILIA.'],
            ['The proof that matters next', 'A customer relying on the product for real work and accepting its results. Engineering tests, citations and same-team integrations are not substitutes for that evidence.'],
          ].map(([title, body]) => (
            <div key={title} style={{ borderLeft: `2px solid ${color.gold}`, paddingLeft: 16 }}>
              <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 15, color: '#0C0A09', marginBottom: 5 }}>{title}</div>
              <div style={{ fontFamily: font.sans, fontSize: 14, lineHeight: 1.55, color: '#57534E' }}>{body}</div>
            </div>
          ))}
        </div>
        <p style={{ fontFamily: font.sans, fontSize: 14, lineHeight: 1.55, color: '#78716C', maxWidth: 700, marginBottom: 12 }}>
          The engineering asset is public and falsifiable. The customer evidence is not yet: EMILIA
          currently claims no customer traction, recurring revenue, production deployment,
          certification, RFC status, or standards-body endorsement. The workforce workspace is a private
          local alpha. Production custody, recovery and coverage require a separate deployment review.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#78716C', maxWidth: 700 }}>
          The technical and narrative investor materials are shared directly. Tell us a little below,
          or reach us at <a href="mailto:team@emiliaprotocol.ai" style={{ color: color.gold, textDecoration: 'none' }}>team@emiliaprotocol.ai</a>.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 100, maxWidth: 760 }}>
        {submitted ? (
          <div style={{ fontFamily: font.sans, fontSize: 17, color: '#0C0A09', border: `1px solid ${color.border || '#D6D3D1'}`, borderTop: `2px solid ${color.gold}`, borderRadius: radius.base || 4, padding: 28, background: '#FAFAF9' }}>
            Thank you. We received your note and will follow up from team@emiliaprotocol.ai.
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {field('name', 'Name', { required: true })}
              {field('firm', 'Firm')}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {field('title', 'Title')}
              {field('email', 'Email', { required: true, type: 'email' })}
            </div>
            {field('website', 'Website')}
            {field('whyEmilia', 'Why EMILIA', { area: true, rows: 3 })}
            {field('helpOffer', 'How you could help beyond capital', { area: true, rows: 2 })}
            {field('notes', 'Anything else', { area: true, rows: 2 })}
            {error && <div style={{ fontFamily: font.sans, fontSize: 14, color: '#DC2626' }}>{error}. Please try again or email team@emiliaprotocol.ai.</div>}
            <button type="submit" disabled={submitting}
              style={{ fontFamily: font.sans, fontSize: 15, fontWeight: 600, color: '#FAFAF9', background: '#0C0A09', border: 'none', borderRadius: radius.base || 4, padding: '13px 22px', cursor: submitting ? 'default' : 'pointer', opacity: submitting ? 0.6 : 1, alignSelf: 'flex-start' }}>
              {submitting ? 'Sending…' : 'Send inquiry'}
            </button>
          </form>
        )}
      </section>

      </main>
      <SiteFooter />
    </div>
  );
}
