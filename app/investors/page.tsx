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

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56, maxWidth: 760 }}>
        <div className="ep-tag" style={{ color: color.gold, fontFamily: font.mono || font.sans, fontSize: 12, letterSpacing: '0.16em', textTransform: 'uppercase', marginBottom: 20 }}>Investor Inquiries</div>
        <h1 style={{ fontFamily: font.sans, fontSize: 44, fontWeight: 700, color: '#0C0A09', lineHeight: 1.06, marginBottom: 20, maxWidth: 700 }}>
          AI gave software intelligence. EMILIA puts authority in force.
        </h1>
        <p style={{ fontFamily: font.sans, fontSize: 18, lineHeight: 1.55, color: '#44403C', maxWidth: 700, marginBottom: 12 }}>
          Autonomous work needs two independent systems. The intelligence system plans, delegates,
          loops, and learns. The authority system remains outside it and controls the crossing from
          intent into changes to money, code, permissions, records, or infrastructure.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#78716C', maxWidth: 700, marginBottom: 12 }}>
          Authority brain is the mental model. EMILIA Gate is the product. It verifies the exact
          action against a customer-owned mandate before the protected provider path can begin.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 17, lineHeight: 1.5, fontWeight: 700, color: color.gold, maxWidth: 700, marginBottom: 12 }}>
          Even if AI writes the binary, it cannot write its own authority.
        </p>
        <div style={{ display: 'grid', gap: 18, marginTop: 32, marginBottom: 24 }}>
          {[
            ['The investable separation', 'Models are becoming agents, agents are receiving credentials, and software is moving from recommendation to consequence. Intelligence can keep changing. Customer authority must remain independently enforceable.'],
            ['The product', 'The customer defines mission, limits, required evidence, expiry, delegation, and exception rules. Gate matches the exact action, reserves its authority before provider entry, and requires authenticated reconciliation instead of a blind retry when the result is unknown.'],
            ['The control that survives continuous loops', 'The agent may keep running while its authority stops. Inside a covered Gate control domain, Emergency Authority Freeze blocks new reservations and prevents older reservations from entering after the epoch changes. It does not stop computation, undo entered effects, or claim instant reach across disconnected leased domains.'],
            ['The entry wedge', 'GitHub makes the product legible with almost no procurement friction. The open Authority Map finds declared authority gaps; the exact-commit Merge Gate can protect a required merge check. This is a distribution experiment, not claimed traction.'],
            ['The expansion', 'The same boundary applies when agents change cloud infrastructure, production code, permissions, payer records, treasury state, or industrial commands. Gate composes with native evidence rather than asking enterprises to replace identity, OAuth, policy, or workflow systems.'],
            ['Why this can become infrastructure', 'The protocol stays open and portable while the paid control plane owns durable admission, integrations, mandate operations, evidence lifecycle, and service levels. Models and agent frameworks can change without moving the customer\'s authority boundary.'],
            ['The commercial motion', `The current offer is a ${PILOT_OFFER.durationLabel.toLowerCase()} ${PILOT_OFFER.priceLabel} protected-workflow pilot. ${IMPLEMENTATION_OFFER.priceLabel} implementation and ${PRODUCTION_GATE.priceLabel} operated Gate are management hypotheses until buyers validate them.`],
            ['What the round proves', 'One independent reproduction, one buyer-funded protected workflow, one limited-production boundary, and a repeatable deployment path. Public tests, informative citations, and same-team integrations are engineering evidence, not customer adoption.'],
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
          certification, RFC status, or standards-body endorsement. GitHub and the payer workflow are
          go-to-market hypotheses until an external organization relies on the boundary.
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

      <SiteFooter />
    </div>
  );
}
