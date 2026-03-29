'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export default function FinancialPackPage() {
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
        body: JSON.stringify({ type: 'pilot-financial-pack', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const FEATURES = [
    { title: 'Beneficiary / remittance change controls', body: 'Cryptographic handshake required before any beneficiary or remittance destination change commits. The handshake binds the exact new destination, currency, and authorizing principal. No change executes without satisfied trust policy.' },
    { title: 'Treasury dual authorization', body: 'High-value treasury operations require two named principals to independently sign off on the exact action. Each signoff is cryptographically bound to the action parameters. Both must be satisfied before execution proceeds.' },
    { title: 'SOX-ready payment-action evidence', body: 'Every handshake, signoff, and execution event produces structured evidence records. Evidence packages satisfy SOX segregation-of-duties requirements and provide tamper-evident audit trails for financial controls.' },
    { title: 'Wire transfer protection', body: 'Wire instruction changes, new wire destinations, and wire amount modifications above policy thresholds require accountable signoff. The signoff binds the exact wire parameters to named authorizers.' },
    { title: 'Amount-based escalation', body: 'Policy-defined amount thresholds trigger escalating signoff requirements. Low-value actions may proceed with single signoff. High-value actions require dual authorization. Critical-value actions require dual authorization plus senior officer attestation.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Financial Control Pack</div>
        <h1 style={styles.h1}>Financial Control Pack</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Pre-configured EP deployment for financial transaction control.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Financial Pilot</a>
      </section>

      {/* Features */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Included controls</h2>
          <p style={styles.body}>
            The Financial Control Pack includes pre-configured policies, signoff workflows, and evidence formats designed for financial transaction control. Deploy against a single trust surface in weeks, not months.
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
        <p style={styles.body}>Start with the highest-impact trust surface. For most financial deployments, that is beneficiary change.</p>
        <div className="ep-card-accent" style={{ ...styles.card, border: `1px solid ${color.border}` }}>
          <div style={{ ...styles.cardTitle, color: color.green, fontSize: 18, marginBottom: 10 }}>Beneficiary change</div>
          <div style={styles.cardBody}>
            A payment beneficiary, wire destination, or remittance target is modified within an authorized workflow. EP generates a cryptographic handshake binding the exact new destination, currency, amount, the requesting identity, and the authorizing officer. If the handshake is not satisfied, the change does not execute. For amounts above the dual-authorization threshold, two named principals must independently sign off. The signoff records are immutable and satisfy SOX evidence requirements.
          </div>
          <div style={{ marginTop: 16, display: 'grid', gap: 8 }}>
            {[
              'Handshake binds exact new beneficiary, currency, and amount',
              'Named officer signoff required before change commits',
              'Dual authorization for amounts above policy threshold',
              'Signoff is one-time consumable and replay-resistant',
              'SOX-grade evidence chain for every beneficiary change',
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
          <h2 style={styles.h2}>Request Financial Pilot</h2>
          {submitted ? (
            <div style={{ ...styles.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
              <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={styles.card}>
              <div style={grid.cols2}>
                {[['name','Name'],['org','Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                  <div key={k}>
                    <label style={styles.label}>{label}</label>
                    <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={styles.label}>Trust surface of interest</label>
                  <input className="ep-input" style={styles.input} placeholder="e.g. wire transfers, beneficiary changes, treasury operations" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
                {submitting ? 'Submitting...' : 'Request Financial Pilot'}
              </button>
            </div>
          )}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
