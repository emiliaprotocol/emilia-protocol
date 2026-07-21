'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
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
          The durable-consequence layer for machines that can change the world.
        </h1>
        <p style={{ fontFamily: font.sans, fontSize: 17, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 12 }}>
          AgentROA governs calls. ORPRG proves policy permitted the effect. EMILIA proves exact
          authorization by an enrolled approver under the relying party&apos;s pinned directory,
          then safely controls consequential outcomes. Gate enforces that separation at the
          protected executor.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 12 }}>
          Gate turns that hierarchy into a product boundary. Action Escrow demonstrates the whole
          chain on one exact release: a signed document is not payment authority, both parties
          authorize the release, and Gate consumes that release authority once. CAID correlates
          native action descriptions under pinned profiles without granting authority. Bounded
          capabilities reserve before provider entry and keep uncertain outcomes indeterminate
          until authenticated evidence reconciles them.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 12 }}>
          The technical moat is open interoperability plus reproducible assurance: fail-closed
          native verifiers, shared conformance vectors, scoped formal models, and an Assurance Plane
          that re-performs evidence instead of trusting a dashboard.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 14, lineHeight: 1.55, color: '#78716C', maxWidth: 560, marginBottom: 12 }}>
          CAID -00, Bounded Capability Receipts -00, Authorization Receipts -07,
          EP-QUORUM -03, and EP-AEC -03 are active individual Internet-Drafts; none
          is an RFC or adopted standard. No physical hardware attestation in production
          or independently operated witness network is claimed today.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#78716C', maxWidth: 560 }}>
          The round materials, business model, and commercial detail are shared directly under NDA. Tell us a little below, or reach us at <a href="mailto:team@emiliaprotocol.ai" style={{ color: color.gold, textDecoration: 'none' }}>team@emiliaprotocol.ai</a>.
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
