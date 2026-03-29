'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

export default function EmiliaEyePage() {
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
        body: JSON.stringify({ type: 'pilot-eye', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const STACK = [
    { label: 'Eye', verb: 'warns', detail: 'Lightweight triage signal that flags when a high-risk action pattern appears. No enforcement, no blocking. Eye raises a flag so the right system can respond.' },
    { label: 'EP Handshake', verb: 'verifies', detail: 'Pre-action trust enforcement. Binds actor identity, authority chain, policy version, and exact action context into a replay-resistant verification envelope before execution.' },
    { label: 'Accountable Signoff', verb: 'owns', detail: 'When policy requires named human ownership, a specific principal must explicitly assume responsibility for the exact action. Cryptographically bound, one-time consumable.' },
  ];

  const COMPARISON = [
    { dimension: 'Public scores', eye: 'No. Eye signals are internal to the deploying organization.', reputation: 'Yes. Scores are visible to counterparties or the public.' },
    { dimension: 'Persistent labels', eye: 'No. Eye warnings are short-lived and action-scoped.', reputation: 'Yes. Labels persist and follow entities across contexts.' },
    { dimension: 'Crowd input', eye: 'No. Signals come from policy and system context, not votes.', reputation: 'Yes. Ratings, reviews, and community feedback shape scores.' },
    { dimension: 'Enforcement', eye: 'No. Eye warns. Enforcement belongs to EP.', reputation: 'Often. Scores directly gate access or transactions.' },
    { dimension: 'Explainability', eye: 'Yes. Every warning includes the reason and the signal class.', reputation: 'Rarely. Scores are typically opaque aggregates.' },
  ];

  const SIGNAL_CLASSES = [
    { domain: 'Government', icon: 'GOV', examples: 'Payment destination changes, benefit redirects, eligibility overrides, unusual operator escalations' },
    { domain: 'Financial', icon: 'FIN', examples: 'Beneficiary changes, payout destination updates, remittance modifications, unusual treasury approval paths' },
    { domain: 'Enterprise', icon: 'ENT', examples: 'Privilege escalation, configuration changes, access grants, administrative overrides outside normal patterns' },
    { domain: 'AI / Agent', icon: 'AI', examples: 'Destructive tool-use actions, delegated authority boundary violations, autonomous execution of irreversible operations' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Emilia Eye</div>
        <h1 style={styles.h1}>Start lighter with Emilia Eye</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          A warning protocol that flags when stricter EP trust controls should apply. Eye does not enforce. It does not block. It raises a signal so the right system can respond.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#pilot" className="ep-cta" style={cta.primary}>Pilot Emilia Eye</a>
          <a href="/docs" className="ep-cta-secondary" style={cta.secondaryBlue}>Read the Spec</a>
        </div>
      </section>

      {/* What Eye is */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>What Emilia Eye is</h2>
          <p style={styles.body}>
            Eye is a warning-first protocol. It observes action patterns and raises a triage signal when something looks like it should trigger stricter trust controls.
          </p>
          <div style={grid.stack}>
            {[
              { title: 'Warning-first', body: 'Eye does not block, deny, or enforce. It flags. The downstream system decides what to do with the signal.' },
              { title: 'Triage signal', body: 'Eye classifies the reason for the warning and routes it to the appropriate enforcement layer. It is a routing primitive, not a decision engine.' },
              { title: 'Short-lived', body: 'Eye warnings are scoped to the action that triggered them. They do not persist as labels, scores, or reputation markers.' },
              { title: 'Subordinate to EP', body: 'Eye is not a replacement for EP Handshake or Accountable Signoff. It is the lightweight entry point that tells you when those controls should apply.' },
            ].map((item, i) => (
              <div key={i} style={styles.card}>
                <div style={styles.cardTitle}>{item.title}</div>
                <div style={styles.cardBody}>{item.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* The stack */}
      <section style={styles.section}>
        <h2 style={styles.h2}>The stack</h2>
        <p style={styles.body}>Three layers. Each does one thing. Together they cover the full lifecycle from warning to enforcement to ownership.</p>
        <div style={grid.auto(220)}>
          {STACK.map((item, i) => (
            <div key={i} style={{ ...styles.card, borderTop: `2px solid ${i === 0 ? color.green : i === 1 ? color.blue : '#F59E0B'}` }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: i === 0 ? color.green : i === 1 ? color.blue : '#F59E0B', marginBottom: 8 }}>{item.label}</div>
              <div style={{ ...styles.cardTitle, fontSize: 18, marginBottom: 8 }}>{item.verb}</div>
              <div style={styles.cardBody}>{item.detail}</div>
            </div>
          ))}
        </div>
        <p style={{ fontFamily: font.mono, fontSize: 15, color: color.t1, marginTop: 24, textAlign: 'center', letterSpacing: 0.5 }}>
          Eye warns. EP verifies. Signoff owns.
        </p>
      </section>

      {/* How Eye differs */}
      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>How Eye differs from scores and reputation</h2>
          <p style={styles.body}>Eye is not a reputation system. It does not produce public scores, persistent labels, or crowd-sourced ratings.</p>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 16 }}>
              <thead>
                <tr>
                  <th style={styles.tableHead}>Dimension</th>
                  <th style={{ ...styles.tableHead, color: color.green }}>Emilia Eye</th>
                  <th style={styles.tableHead}>Reputation Systems</th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON.map((row, i) => (
                  <tr key={i}>
                    <td style={{ ...styles.tableCell, fontWeight: 600, color: color.t1 }}>{row.dimension}</td>
                    <td style={styles.tableCell}>{row.eye}</td>
                    <td style={styles.tableCell}>{row.reputation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Signal classes */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Signal classes</h2>
        <p style={styles.body}>Eye classifies warnings by domain. Each signal class maps to the action patterns most likely to require stricter trust controls in that vertical.</p>
        <div style={grid.auto(280)}>
          {SIGNAL_CLASSES.map((sc, i) => (
            <div key={i} style={styles.card}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span style={{ ...styles.mono, background: color.bg, padding: '4px 10px', borderRadius: radius.sm, fontSize: 11, letterSpacing: 1 }}>{sc.icon}</span>
                <span style={styles.cardTitle}>{sc.domain}</span>
              </div>
              <div style={styles.cardBody}>{sc.examples}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Example flows */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Example flows</h2>
          <p style={styles.body}>How Eye works in practice across two high-risk verticals.</p>
          <div style={{ display: 'grid', gap: 24 }}>
            {/* Government flow */}
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.blue, marginBottom: 12 }}>Government</div>
              <div style={styles.cardTitle}>Payment destination change</div>
              <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
                {[
                  { step: '01', text: 'Operator initiates a payment destination change for a benefits disbursement.' },
                  { step: '02', text: 'Eye detects the action pattern and raises a GOV signal: beneficiary redirect, destination mismatch with enrollment record.' },
                  { step: '03', text: 'The system routes the flagged action into EP Handshake for pre-action verification.' },
                  { step: '04', text: 'If policy requires it, Accountable Signoff binds a named supervisor to the exact change before execution.' },
                ].map((flow, i) => (
                  <div key={i} style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 700, color: color.green, flexShrink: 0, minWidth: 28 }}>{flow.step}</div>
                    <div style={styles.cardBody}>{flow.text}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Financial flow */}
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.blue, marginBottom: 12 }}>Financial</div>
              <div style={styles.cardTitle}>Beneficiary change on wire transfer</div>
              <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
                {[
                  { step: '01', text: 'An operator or automated system requests a beneficiary change on an outbound wire.' },
                  { step: '02', text: 'Eye raises a FIN signal: payout destination change, new beneficiary not in approved counterparty registry.' },
                  { step: '03', text: 'The flagged transaction is routed to EP Handshake, which binds the actor, authority chain, and exact transaction parameters.' },
                  { step: '04', text: 'Treasury policy triggers Accountable Signoff. A named treasury officer signs off on the exact beneficiary change before the wire executes.' },
                ].map((flow, i) => (
                  <div key={i} style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 700, color: color.green, flexShrink: 0, minWidth: 28 }}>{flow.step}</div>
                    <div style={styles.cardBody}>{flow.text}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* OSS + Cloud */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Packaging</h2>
        <p style={styles.body}>Eye ships as both open-source and managed cloud.</p>
        <div style={grid.auto(280)}>
          <div style={{ ...styles.card, borderTop: `2px solid ${color.green}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.green, marginBottom: 8 }}>Open Source</div>
            <div style={styles.cardTitle}>Self-hosted Eye</div>
            <div style={styles.cardBody}>Apache 2.0 licensed. Run Eye on your own infrastructure. Full control over signal routing, storage, and integration with your existing trust stack.</div>
          </div>
          <div style={{ ...styles.card, borderTop: `2px solid ${color.blue}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.blue, marginBottom: 8 }}>Managed</div>
            <div style={styles.cardTitle}>EP Cloud with Eye</div>
            <div style={styles.cardBody}>Hosted signal processing, pre-built signal class libraries, dashboard for warning triage, and direct escalation into EP Handshake and Accountable Signoff.</div>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Pilot Emilia Eye</h2>
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
                  <input className="ep-input" style={styles.input} placeholder="e.g. payment destination changes, beneficiary updates, agent actions" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
              <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...((!form.name || !form.email) ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Pilot Emilia Eye'}
              </button>
            </div>
          )}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
