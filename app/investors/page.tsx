'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { GATE_QUALIFICATION, PRODUCTION_GATE } from '@/lib/commercial-offer';
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
          The consequence firewall—and first operating kernel of a Distributed Trust Computer.
        </h1>
        <p style={{ fontFamily: font.sans, fontSize: 17, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 12 }}>
          AI systems are moving from recommendations to actions that change money, code,
          permissions, regulated records, infrastructure, and physical state. EMILIA Gate sits at
          the protected executor: without valid authority for the exact action, the protected
          effect does not run.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 12 }}>
          The open EMILIA Protocol supplies portable formats, verifiers, and conformance material.
          The company packages Gate, Approver, and the Assurance Plane for customer-specific
          implementations. CAID names the material
          action; AEB joins independently verified evidence under relying-party-pinned mappings and
          requirements. Neither authorizes. Gate applies local policy, reserves bounded authority,
          owns the effect call, and records executed or indeterminate outcome evidence. It refuses
          blind replay after uncertain provider entry, reconciles only authenticated same-operation
          evidence, and treats refunds, returns, reversals, or other remedies as separately
          authorized actions rather than rewriting history.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 10 }}>
          Gate Qualification v2 converts accepted evaluation evidence into a portable, time-bounded
          qualification for one exact measured candidate and assignment. The relying party can require
          that evidence beside AEB, AEC, and local policy without turning an evaluation result into
          permission. {GATE_QUALIFICATION.disclaimer}
        </p>
        <p style={{ fontFamily: font.mono || font.sans, fontSize: 13, lineHeight: 1.55, color: color.gold, maxWidth: 560, marginBottom: 12 }}>
          {GATE_QUALIFICATION.boundaryLine}
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 15, lineHeight: 1.55, color: '#57534E', maxWidth: 560, marginBottom: 12 }}>
          Complex authority can be staged or parallel. The public experimental Trust Program
          profile binds each stage to its predecessors and fences one downstream effect owner.
          Action Escrow, GRACE, and Program Integrity are inspectable reference surfaces—not claims
          of custody, live grid operation, state deployment, or customer funds.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 14, lineHeight: 1.55, color: '#78716C', maxWidth: 560, marginBottom: 12 }}>
          {PRODUCTION_GATE.name} is {PRODUCTION_GATE.availabilityLabel.toLowerCase()} and is quoted for
          a defined protected workflow and operating boundary.
        </p>
        <p style={{ fontFamily: font.sans, fontSize: 14, lineHeight: 1.55, color: '#78716C', maxWidth: 560, marginBottom: 12 }}>
          The repository tracks 22 active Datatracker records. Six new or revised individual
          Internet-Drafts were filed on August 3, 2026: AEB -03, AEC -05, Model-to-Matter -03,
          Reliance Agreement -00, Bounded Capability Receipts -01, and Bounded Execution Program
          -00. They are not RFCs, working-group items, adopted standards, or IETF endorsement. No
          production hardware-attestation fleet or independently operated witness network is
          claimed today.
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
