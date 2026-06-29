'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export default function GovernmentPackPage() {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', surface:'', problem:'', notes:'' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const res = await fetch('/api/inquiries', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'pilot-government-pack', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  // Honest feature list — only items backed by code in lib/, tests in
  // tests/, or documented in docs/. PIV/CAC, Login.gov, FISMA/FedRAMP
  // claims removed: zero implementation, zero mapping documents. Marked
  // as "roadmap" below where pilots have asked for them.
  const FEATURES = [
    { title: 'Payment destination controls', body: 'GovGuard adapters cover vendor payment destinations, benefit direct deposit, and payment-address changes. The receipt binds the exact new destination, program, amount, and named approver before the change can be treated as authorized.' },
    { title: 'Disbursement and grant release controls', body: 'Government disbursement and grant releases require Class-A accountable signoff before funds move; million-dollar releases escalate to dual authorization.' },
    { title: 'Provider and eligibility controls', body: 'Provider enrollment changes, eligibility overrides, and caseworker overrides produce named signoff records bound to exact case, provider, decision, and policy fields.' },
    { title: 'GG-1 evidence packet', body: 'The fire drill exports high-risk actions, policy hashes, action hashes, execution-binding hashes, offline verifier instructions, and GG-1 controls. Action-level traceability, not session-level logs.' },
  ];

  // Items pilots have asked for that are NOT yet implemented. Keep the
  // marketing surface honest by labeling them as roadmap, not shipped.
  const ROADMAP = [
    { title: 'Government identity integration (PIV / CAC / Login.gov)', body: 'Pilot-track work; not yet implemented. Pilots needing PIV/CAC integration today should contact us — we will scope the work as part of the pilot.' },
    { title: 'FISMA / FedRAMP mapping', body: 'Control-family mapping documents are not yet published. EP trust enforcement satisfies action-level accountability requirements that map onto multiple NIST 800-53 controls; the formal mapping document is on the roadmap.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Government Control Pack</div>
        <h1 style={styles.h1}>Government Control Pack</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Pre-configured GovGuard deployment for government fraud-control fire drills and observe-mode pilots.
        </p>
        <a href="/pilot/sandbox?v=gov" className="ep-cta" style={cta.primary}>Run GovGuard Fire Drill</a>
      </section>

      {/* Features */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Included controls</h2>
          <p style={styles.body}>
            The Government Control Pack includes pre-configured policies, GovGuard adapter endpoints, signoff workflows, and evidence formats designed for government fraud prevention. Start with a fire drill, then deploy against a single trust surface in weeks, not months.
          </p>
          <div style={grid.stack}>
            {FEATURES.map((f, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{f.title}</div>
                <div style={styles.cardBody}>{f.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Roadmap (not yet shipped — explicit so federal procurement teams
          do not mistake aspirational features for delivered ones) */}
      <section style={styles.section}>
        <div style={styles.eyebrowBlue}>Roadmap (pilot-track)</div>
        <h2 style={styles.h2}>On the way, not yet shipped.</h2>
        <p style={styles.body}>
          The following capabilities are pilot-track work that we will scope as
          part of an active engagement. They are listed here because pilots
          frequently ask about them — not because they are deliverable today.
        </p>
        <div style={grid.stack}>
          {ROADMAP.map((f, i) => (
            <div key={i} className="ep-card-hover" style={{ ...styles.card, opacity: 0.85 }}>
              <div style={styles.cardTitle}>{f.title}</div>
              <div style={styles.cardBody}>{f.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Best first workflow */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Best first workflow</h2>
        <p style={styles.body}>Start with the highest-impact trust surface. For most government deployments, that is one payment-destination or release workflow.</p>
        <div className="ep-card-accent" style={{ ...styles.card, border: `1px solid ${color.border}` }}>
          <div style={{ ...styles.cardTitle, color: color.green, fontSize: 18, marginBottom: 10 }}>GovGuard Fire Drill</div>
          <div style={styles.cardBody}>
            A vendor, benefits recipient, provider, or disbursement target changes a payment route or release state. GovGuard evaluates the action in observe mode, shows what would have required named signoff, and exports a procurement evidence packet before any enforcement decision.
          </div>
          <div style={{ marginTop: 16, display: 'grid', gap: 8 }}>
            {[
              'Adapters cover vendor destination, disbursement, grant, benefit routing, provider enrollment, eligibility override, and caseworker override workflows',
              'Class-A signoff required for high-risk government actions',
              'Receipts are one-time consumable and replay-resistant',
              'Evidence packet includes policy hash, action hash, execution-binding hash, and verifier command',
              'GG-1 conformance covers wrong org, wrong approver, self-approval, Class-C approval, replay, tamper, and execution mismatch',
            ].map((item, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span style={{ color: color.green, fontSize: 14, flexShrink: 0, marginTop: 1 }}>+</span>
                <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Request Government Pilot</h2>
          {submitted ? (
            <div style={{ ...styles.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
              <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={styles.card}>
              <div style={grid.cols2}>
                {[['name','Name'],['org','Agency / Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                  <div key={k}>
                    <label style={styles.label}>{label}</label>
                    <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={styles.label}>Trust surface of interest</label>
                  <input className="ep-input" style={styles.input} placeholder="e.g. benefits disbursement, payment routing, operator approvals" value={form.surface} onChange={e => update('surface', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={styles.label}>Problem description</label>
                  <textarea className="ep-input" style={{ ...styles.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={styles.label}>Notes</label>
                  <input className="ep-input" style={styles.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
                </div>
              </div>
              {error && <p style={{ color: color.red, fontSize: 13, marginTop: 12 }}>{error}</p>}
              <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...(!form.name || !form.email ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Request Government Pilot'}
              </button>
            </div>
          )}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
