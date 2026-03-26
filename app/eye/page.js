'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

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

  const s = {
    page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
    section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
    sectionWide: { maxWidth: 1080, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#0F172A', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#3B82F6', marginBottom: 16 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 24, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 },
    h3: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 18, fontWeight: 700, letterSpacing: -0.3, marginBottom: 10, color: '#F8FAFC' },
    body: { fontSize: 16, color: '#94A3B8', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, color: '#F8FAFC', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#94A3B8', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0F172A', color: '#F8FAFC', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#94A3B8', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 0.5 },
    mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, color: '#3B82F6' },
    tableCell: { padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)', fontSize: 14, color: '#94A3B8', lineHeight: 1.5 },
    tableHead: { padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.1)', fontSize: 12, fontWeight: 700, color: '#F8FAFC', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1, textTransform: 'uppercase', textAlign: 'left' },
  };

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
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Product / Emilia Eye</div>
        <h1 style={s.h1}>Start lighter with Emilia Eye</h1>
        <p style={{ ...s.body, maxWidth: 640 }}>
          A warning protocol that flags when stricter EP trust controls should apply. Eye does not enforce. It does not block. It raises a signal so the right system can respond.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#pilot" style={{ ...s.cta, background: '#22C55E', color: '#020617' }}>Pilot Emilia Eye</a>
          <a href="/docs" style={{ ...s.cta, background: 'transparent', color: '#3B82F6', border: '1px solid rgba(59,130,246,0.3)' }}>Read the Spec</a>
        </div>
      </section>

      {/* What Eye is */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What Emilia Eye is</h2>
          <p style={s.body}>
            Eye is a warning-first protocol. It observes action patterns and raises a triage signal when something looks like it should trigger stricter trust controls.
          </p>
          <div style={{ display: 'grid', gap: 16 }}>
            {[
              { title: 'Warning-first', body: 'Eye does not block, deny, or enforce. It flags. The downstream system decides what to do with the signal.' },
              { title: 'Triage signal', body: 'Eye classifies the reason for the warning and routes it to the appropriate enforcement layer. It is a routing primitive, not a decision engine.' },
              { title: 'Short-lived', body: 'Eye warnings are scoped to the action that triggered them. They do not persist as labels, scores, or reputation markers.' },
              { title: 'Subordinate to EP', body: 'Eye is not a replacement for EP Handshake or Accountable Signoff. It is the lightweight entry point that tells you when those controls should apply.' },
            ].map((item, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{item.title}</div>
                <div style={s.cardBody}>{item.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* The stack */}
      <section style={s.section}>
        <h2 style={s.h2}>The stack</h2>
        <p style={s.body}>Three layers. Each does one thing. Together they cover the full lifecycle from warning to enforcement to ownership.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
          {STACK.map((item, i) => (
            <div key={i} style={{ ...s.card, borderTop: `2px solid ${i === 0 ? '#22C55E' : i === 1 ? '#3B82F6' : '#F59E0B'}` }}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: i === 0 ? '#22C55E' : i === 1 ? '#3B82F6' : '#F59E0B', marginBottom: 8 }}>{item.label}</div>
              <div style={{ ...s.cardTitle, fontSize: 18, marginBottom: 8 }}>{item.verb}</div>
              <div style={s.cardBody}>{item.detail}</div>
            </div>
          ))}
        </div>
        <p style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 15, color: '#F8FAFC', marginTop: 24, textAlign: 'center', letterSpacing: 0.5 }}>
          Eye warns. EP verifies. Signoff owns.
        </p>
      </section>

      {/* How Eye differs */}
      <section style={s.sectionAlt}>
        <div style={s.sectionWide}>
          <h2 style={s.h2}>How Eye differs from scores and reputation</h2>
          <p style={s.body}>Eye is not a reputation system. It does not produce public scores, persistent labels, or crowd-sourced ratings.</p>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 16 }}>
              <thead>
                <tr>
                  <th style={s.tableHead}>Dimension</th>
                  <th style={{ ...s.tableHead, color: '#22C55E' }}>Emilia Eye</th>
                  <th style={s.tableHead}>Reputation Systems</th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON.map((row, i) => (
                  <tr key={i}>
                    <td style={{ ...s.tableCell, fontWeight: 600, color: '#F8FAFC' }}>{row.dimension}</td>
                    <td style={s.tableCell}>{row.eye}</td>
                    <td style={s.tableCell}>{row.reputation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Signal classes */}
      <section style={s.section}>
        <h2 style={s.h2}>Signal classes</h2>
        <p style={s.body}>Eye classifies warnings by domain. Each signal class maps to the action patterns most likely to require stricter trust controls in that vertical.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {SIGNAL_CLASSES.map((sc, i) => (
            <div key={i} style={s.card}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span style={{ ...s.mono, background: '#020617', padding: '4px 10px', borderRadius: 6, fontSize: 11, letterSpacing: 1 }}>{sc.icon}</span>
                <span style={s.cardTitle}>{sc.domain}</span>
              </div>
              <div style={s.cardBody}>{sc.examples}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Example flows */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Example flows</h2>
          <p style={s.body}>How Eye works in practice across two high-risk verticals.</p>
          <div style={{ display: 'grid', gap: 24 }}>
            {/* Government flow */}
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: '#3B82F6', marginBottom: 12 }}>Government</div>
              <div style={s.cardTitle}>Payment destination change</div>
              <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
                {[
                  { step: '01', text: 'Operator initiates a payment destination change for a benefits disbursement.' },
                  { step: '02', text: 'Eye detects the action pattern and raises a GOV signal: beneficiary redirect, destination mismatch with enrollment record.' },
                  { step: '03', text: 'The system routes the flagged action into EP Handshake for pre-action verification.' },
                  { step: '04', text: 'If policy requires it, Accountable Signoff binds a named supervisor to the exact change before execution.' },
                ].map((flow, i) => (
                  <div key={i} style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                    <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, color: '#22C55E', flexShrink: 0, minWidth: 28 }}>{flow.step}</div>
                    <div style={s.cardBody}>{flow.text}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Financial flow */}
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: '#3B82F6', marginBottom: 12 }}>Financial</div>
              <div style={s.cardTitle}>Beneficiary change on wire transfer</div>
              <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
                {[
                  { step: '01', text: 'An operator or automated system requests a beneficiary change on an outbound wire.' },
                  { step: '02', text: 'Eye raises a FIN signal: payout destination change, new beneficiary not in approved counterparty registry.' },
                  { step: '03', text: 'The flagged transaction is routed to EP Handshake, which binds the actor, authority chain, and exact transaction parameters.' },
                  { step: '04', text: 'Treasury policy triggers Accountable Signoff. A named treasury officer signs off on the exact beneficiary change before the wire executes.' },
                ].map((flow, i) => (
                  <div key={i} style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                    <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, color: '#22C55E', flexShrink: 0, minWidth: 28 }}>{flow.step}</div>
                    <div style={s.cardBody}>{flow.text}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* OSS + Cloud */}
      <section style={s.section}>
        <h2 style={s.h2}>Packaging</h2>
        <p style={s.body}>Eye ships as both open-source and managed cloud.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          <div style={{ ...s.card, borderTop: '2px solid #22C55E' }}>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: '#22C55E', marginBottom: 8 }}>Open Source</div>
            <div style={s.cardTitle}>Self-hosted Eye</div>
            <div style={s.cardBody}>Apache 2.0 licensed. Run Eye on your own infrastructure. Full control over signal routing, storage, and integration with your existing trust stack.</div>
          </div>
          <div style={{ ...s.card, borderTop: '2px solid #3B82F6' }}>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: '#3B82F6', marginBottom: 8 }}>Managed</div>
            <div style={s.cardTitle}>EP Cloud with Eye</div>
            <div style={s.cardBody}>Hosted signal processing, pre-built signal class libraries, dashboard for warning triage, and direct escalation into EP Handshake and Accountable Signoff.</div>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={{ ...s.sectionAlt }}>
        <div style={s.section}>
          <h2 style={s.h2}>Pilot Emilia Eye</h2>
          {submitted ? (
            <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#22C55E', marginBottom: 8 }}>Thank you</div>
              <p style={{ color: '#94A3B8', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={s.card}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                {[['name','Name'],['org','Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                  <div key={k}>
                    <label style={s.label}>{label}</label>
                    <input style={s.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Trust surface of interest</label>
                  <input style={s.input} placeholder="e.g. payment destination changes, beneficiary updates, agent actions" value={form.surface} onChange={e => update('surface', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Problem description</label>
                  <textarea style={{ ...s.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Notes</label>
                  <input style={s.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
                </div>
              </div>
              {error && <p style={{ color: '#f87171', fontSize: 13, marginTop: 12 }}>{error}</p>}
              <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#22C55E', color: !form.name || !form.email ? '#64748B' : '#020617', marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Pilot Emilia Eye'}
              </button>
            </div>
          )}
        </div>
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#64748B', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#64748B', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
