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

  const FEATURES = [
    { title: 'Benefits payment redirect controls', body: 'Cryptographic handshake required before any payment destination change commits. The handshake binds the exact new destination, program, amount, and authorizing principal. No redirect executes without satisfied trust policy.' },
    { title: 'Operator override constraints', body: 'Every caseworker or system operator override produces a named signoff record. The signoff is bound to the exact action parameters, not a session-level approval. Override without accountability does not proceed.' },
    { title: 'IG/GAO-ready audit evidence', body: 'Every handshake, signoff, and execution event produces an immutable record. Evidence packages are pre-formatted for Inspector General and GAO examination. Action-level traceability, not session-level logs.' },
    { title: 'Government identity integration', body: 'Native support for PIV/CAC smart cards, Login.gov, and agency-specific identity providers. Principal identities in EP map directly to government-issued credentials.' },
    { title: 'FISMA/FedRAMP mapping', body: 'Pre-mapped controls for FISMA and FedRAMP authorization. EP trust enforcement satisfies action-level accountability requirements across multiple control families. Documentation packages available for ATO submissions.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Government Control Pack</div>
        <h1 style={styles.h1}>Government Control Pack</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Pre-configured EP deployment for government fraud prevention.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Government Pilot</a>
      </section>

      {/* Features */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Included controls</h2>
          <p style={styles.body}>
            The Government Control Pack includes pre-configured policies, signoff workflows, and evidence formats designed for government fraud prevention. Deploy against a single trust surface in weeks, not months.
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

      {/* Best first workflow */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Best first workflow</h2>
        <p style={styles.body}>Start with the highest-impact trust surface. For most government deployments, that is payment destination change.</p>
        <div className="ep-card-accent" style={{ ...styles.card, border: `1px solid ${color.border}` }}>
          <div style={{ ...styles.cardTitle, color: color.green, fontSize: 18, marginBottom: 10 }}>Payment destination change</div>
          <div style={styles.cardBody}>
            A benefits recipient, vendor, or disbursement target updates their bank account, routing number, or payment address. EP generates a cryptographic handshake binding the exact new destination, the requesting identity, the authorizing caseworker, and the applicable policy. If the handshake is not satisfied, the change does not execute. The signoff record is immutable and available to Inspector General auditors in real time.
          </div>
          <div style={{ marginTop: 16, display: 'grid', gap: 8 }}>
            {[
              'Handshake binds exact new destination, amount, and program',
              'Named caseworker signoff required before change commits',
              'Signoff is one-time consumable and replay-resistant',
              'Immutable event record available to IG and GAO auditors',
              'Policy defines which changes require signoff based on risk class',
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
