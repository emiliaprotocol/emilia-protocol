'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import {
  PROTECTED_WORKFLOW_PILOT as PILOT_OFFER,
  GATE_IMPLEMENTATION as IMPLEMENTATION_OFFER,
  PRODUCTION_GATE,
} from '@/lib/commercial-offer';
import { styles, color, font, radius } from '@/lib/tokens';

// Public investor-contact surface only. Business model, moat, revenue, and
// vertical-pricing material are intentionally NOT published here; they live in
// the private strategy vault and are shared directly under NDA on request.
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

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56, maxWidth: 640 }}>
        <div className="ep-tag" style={{ color: color.gold, fontFamily: font.mono || font.sans, fontSize: 12, letterSpacing: '0.16em', textTransform: 'uppercase', marginBottom: 20 }}>Investor Inquiries</div>
        <h1 style={{ fontFamily: font.sans, fontSize: 40, fontWeight: 700, color: '#0C0A09', lineHeight: 1.1, marginBottom: 20, maxWidth: 560 }}>
          AI workers need authority. Not constant supervision.
        </h1>
        <p style={{ fontFamily: font.sans, fontSize: 17, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 12 }}>
          EMILIA is the authority control plane for autonomous work. A human or institution defines
          a finite operating mandate once; agents work unattended inside it; Gate enforces each
          consequential unit of work where money, code, permissions, records, or infrastructure can change.
        </p>
        <div style={{ display: 'grid', gap: 18, marginTop: 32, marginBottom: 24 }}>
          {[
            ['The problem', 'Identity proves who or what is present. Policy describes what is generally allowed. Neither defines the finite job an autonomous worker may perform under current limits.'],
            ['The product', 'The customer defines mission, limits, evidence, expiry, delegation, and exception rules once. Gate verifies the exact unit of work, reserves bounded authority, and controls provider entry through a customer- or partner-controlled executor adapter. Local risk signals may tighten, review, suspend, or refuse—never expand the mandate.'],
            ['The adoption loop', 'The open local Authority Brain maps supported declared action surfaces and names blind spots. The owner selects one consequence boundary; paid Gate implementation makes that path preventive.'],
            ['The first paid wedge', `A ${PILOT_OFFER.durationLabel.toLowerCase()} ${PILOT_OFFER.priceLabel} pilot protects one payer adverse medical-necessity determination workflow. Agent and MCP vendors plus consultancies create distribution leverage. ${IMPLEMENTATION_OFFER.priceLabel} implementation and ${PRODUCTION_GATE.priceLabel} operated Gate follow only after the boundary is accepted.`],
            ['Why this can compound', 'The Protocol stays open and portable. Models and agent processes change; the customer\'s mandate, consumption, revocation, uncertainty, and work history survive. Every identity system, policy engine, approval method, agent rail, and evidence source can feed the same neutral boundary instead of being replaced by it.'],
            ['What the round proves', 'One paid protected-workflow pilot, one limited-production boundary, independent operation, and repeatable deployment evidence. Public tests and external reproduction are engineering evidence—not customer adoption.'],
          ].map(([title, body]) => (
            <div key={title} style={{ borderLeft: `2px solid ${color.gold}`, paddingLeft: 16 }}>
              <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 15, color: '#0C0A09', marginBottom: 5 }}>{title}</div>
              <div style={{ fontFamily: font.sans, fontSize: 14, lineHeight: 1.55, color: '#57534E' }}>{body}</div>
            </div>
          ))}
        </div>
        <p style={{ fontFamily: font.sans, fontSize: 14, lineHeight: 1.55, color: '#78716C', maxWidth: 560, marginBottom: 12 }}>
          The engineering asset is public and falsifiable. The customer evidence is not yet: EMILIA
          currently claims no customer traction, recurring revenue, live payer integration,
          certification, RFC status, or standards-body endorsement. The financing converts software
          proof into the first external reliance event and repeatable operated deployment.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#78716C', maxWidth: 560 }}>
          The technical and narrative investor materials are shared directly. Tell us a little below,
          or reach us at <a href="mailto:team@emiliaprotocol.ai" style={{ color: color.gold, textDecoration: 'none' }}>team@emiliaprotocol.ai</a>.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 100, maxWidth: 640 }}>
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

      <SiteFooter />
    </div>
  );
}
