'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

export default function EmiliaEyePage() {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', surface:'', problem:'', notes:'' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

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
    { label: 'Eye', verb: 'Observes', accent: color.green, detail: 'Moves through OBSERVE → SHADOW → ENFORCE lifecycle. Flags when a high-risk action pattern appears and routes it to the appropriate enforcement layer. No enforcement in OBSERVE mode. Full enforcement in ENFORCE mode.' },
    { label: 'EP Handshake', verb: 'Verifies', accent: color.blue, detail: 'Pre-action trust enforcement. Binds actor identity, authority chain, policy version, and exact action context into a replay-resistant verification envelope before execution.' },
    { label: 'Accountable Signoff', verb: 'Owns', accent: '#F59E0B', detail: 'When policy requires named human ownership, a specific principal must explicitly assume responsibility for the exact action. Cryptographically bound, one-time consumable.' },
    { label: 'EP Commit', verb: 'Seals', accent: '#78716C', detail: 'Atomically closes the action. Immutable, hash-linked, blockchain-anchored. Once sealed, the record cannot be partially reversed through protocol means. No partial states.' },
  ];

  const WHAT_EYE_IS = [
    { title: 'Warning-first', body: 'Eye does not block, deny, or enforce. It flags. The downstream system decides what to do with the signal.' },
    { title: 'Triage signal', body: 'Eye classifies the reason for the warning and routes it to the appropriate enforcement layer. It is a routing primitive, not a decision engine.' },
    { title: 'Short-lived', body: 'Eye warnings are scoped to the action that triggered them. They do not persist as labels, scores, or reputation markers.' },
    { title: 'Subordinate to EP', body: 'Eye is not a replacement for EP Handshake or Accountable Signoff. It is the lightweight entry point that tells you when those controls should apply.' },
  ];

  const COMPARISON = [
    { dimension: 'Public scores', eye: 'No. Eye signals are internal to the deploying organization.', reputation: 'Yes. Scores are visible to counterparties or the public.' },
    { dimension: 'Persistent labels', eye: 'No. Eye warnings are short-lived and action-scoped.', reputation: 'Yes. Labels persist and follow entities across contexts.' },
    { dimension: 'Crowd input', eye: 'No. Signals come from policy and system context, not votes.', reputation: 'Yes. Ratings, reviews, and community feedback shape scores.' },
    { dimension: 'Enforcement', eye: 'No. Eye observes. Enforcement belongs to Handshake.', reputation: 'Often. Scores directly gate access or transactions.' },
    { dimension: 'Explainability', eye: 'Yes. Every warning includes the reason and the signal class.', reputation: 'Rarely. Scores are typically opaque aggregates.' },
  ];

  const SIGNAL_CLASSES = [
    { domain: 'Government', icon: 'GOV', accent: color.green, examples: 'Payment destination changes, benefit redirects, eligibility overrides, unusual operator escalations' },
    { domain: 'Financial', icon: 'FIN', accent: color.blue, examples: 'Beneficiary changes, payout destination updates, remittance modifications, unusual treasury approval paths' },
    { domain: 'Enterprise', icon: 'ENT', accent: color.gold, examples: 'Privilege escalation, configuration changes, access grants, administrative overrides outside normal patterns' },
    { domain: 'AI / Agent', icon: 'AI', accent: color.blue, examples: 'Destructive tool-use actions, delegated authority boundary violations, autonomous execution of irreversible operations' },
  ];

  const cardStyle = (accent) => ({
    border: `1px solid ${color.border}`,
    borderTop: `2px solid ${accent}`,
    borderRadius: radius.base,
    padding: '24px',
    background: '#FAFAF9',
  });

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 72 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.green }}>Product / Emilia Eye</div>
        <h1 className="ep-hero-text" style={styles.h1}>Start lighter with Emilia Eye</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          A warning protocol that flags when stricter EP trust controls should apply. Eye does not enforce. It does not block. It raises a signal so the right system can respond.
        </p>
        <div className="ep-hero-text" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#pilot" className="ep-cta" style={cta.primary}>Pilot Emilia Eye</a>
          <a href="/docs" className="ep-cta-secondary" style={cta.secondary}>Read the Spec</a>
        </div>
      </section>

      {/* What Eye is */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>What Emilia Eye is</h2>
            <p style={styles.body}>
              Eye is a warning-first protocol. It observes action patterns and raises a triage signal when something looks like it should trigger stricter trust controls.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {WHAT_EYE_IS.map((item, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.green)}>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{item.title}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{item.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* The stack */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <h2 style={styles.h2}>The stack</h2>
          <p style={styles.body}>Four layers. Each does one thing. Together they cover the full lifecycle from observation to enforcement to ownership to sealing.</p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 32 }}>
          {STACK.map((item, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(item.accent)}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: item.accent, marginBottom: 8 }}>{item.label}</div>
              <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{item.verb}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{item.detail}</div>
            </div>
          ))}
        </div>
        <div className="ep-reveal" style={{ textAlign: 'center', fontFamily: font.mono, fontSize: 14, color: color.t1, letterSpacing: 0.5, padding: '16px 0' }}>
          Eye observes. Handshake verifies. Signoff owns. Commit seals.
        </div>
      </section>

      {/* How Eye differs */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 32 }}>
            <h2 style={styles.h2}>How Eye differs from scores and reputation</h2>
            <p style={styles.body}>Eye is not a reputation system. It does not produce public scores, persistent labels, or crowd-sourced ratings.</p>
          </div>
          <div className="ep-reveal" style={{
            borderTop: `1px solid ${color.border}`,
            borderLeft: `1px solid ${color.border}`,
            overflowX: 'auto',
          }}>
            <div style={{
              display: 'grid', gridTemplateColumns: '160px 1fr 1fr',
              borderRight: `1px solid ${color.border}`,
              borderBottom: `1px solid ${color.border}`,
              padding: '12px 20px',
              background: '#F5F3F0',
            }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1.2, textTransform: 'uppercase' }}>Dimension</div>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.green, letterSpacing: 1.2, textTransform: 'uppercase' }}>Emilia Eye</div>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1.2, textTransform: 'uppercase' }}>Reputation Systems</div>
            </div>
            {COMPARISON.map((row, i) => (
              <div key={i} className="ep-row-hover" style={{
                display: 'grid', gridTemplateColumns: '160px 1fr 1fr', gap: 0,
                borderRight: `1px solid ${color.border}`,
                borderBottom: `1px solid ${color.border}`,
                padding: '14px 20px',
              }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: color.t1 }}>{row.dimension}</div>
                <div style={{ fontSize: 13, color: color.t2, lineHeight: 1.6, paddingRight: 16 }}>{row.eye}</div>
                <div style={{ fontSize: 13, color: color.t2, lineHeight: 1.6 }}>{row.reputation}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Signal classes */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <h2 style={styles.h2}>Signal classes</h2>
          <p style={styles.body}>Eye classifies warnings by domain. Each signal class maps to the action patterns most likely to require stricter trust controls in that vertical.</p>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
          {SIGNAL_CLASSES.map((sc, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(sc.accent)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, background: '#F0EDE8', padding: '3px 8px', borderRadius: 3, color: sc.accent }}>{sc.icon}</span>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1 }}>{sc.domain}</div>
              </div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{sc.examples}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Example flows */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>Example flows</h2>
            <p style={styles.body}>How Eye works in practice across two high-risk verticals.</p>
          </div>
          <div style={{ display: 'grid', gap: 12 }}>
            {[
              {
                label: 'Government',
                accent: color.green,
                title: 'Payment destination change',
                steps: [
                  'Operator initiates a payment destination change for a benefits disbursement.',
                  'Eye detects the action pattern and raises a GOV signal: beneficiary redirect, destination mismatch with enrollment record.',
                  'The system routes the flagged action into EP Handshake for pre-action verification.',
                  'If policy requires it, Accountable Signoff binds a named supervisor to the exact change before execution.',
                ],
              },
              {
                label: 'Financial',
                accent: color.blue,
                title: 'Beneficiary change on wire transfer',
                steps: [
                  'An operator or automated system requests a beneficiary change on an outbound wire.',
                  'Eye raises a FIN signal: payout destination change, new beneficiary not in approved counterparty registry.',
                  'The flagged transaction is routed to EP Handshake, which binds the actor, authority chain, and exact transaction parameters.',
                  'Treasury policy triggers Accountable Signoff. A named treasury officer signs off on the exact beneficiary change before the wire executes.',
                ],
              },
            ].map((flow, fi) => (
              <div key={fi} className={`ep-card-lift ep-reveal ep-stagger-${fi + 1}`} style={cardStyle(flow.accent)}>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: flow.accent, marginBottom: 8 }}>{flow.label}</div>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 16 }}>{flow.title}</div>
                <div style={{ display: 'grid', gap: 10 }}>
                  {flow.steps.map((step, si) => (
                    <div key={si} style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                      <div style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 700, color: flow.accent, flexShrink: 0, minWidth: 24 }}>{String(si + 1).padStart(2, '0')}</div>
                      <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{step}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Packaging */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <h2 style={styles.h2}>Packaging</h2>
          <p style={styles.body}>Eye ships as both open-source and managed cloud.</p>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
          <div className="ep-card-lift ep-reveal ep-stagger-1" style={cardStyle(color.green)}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.green, marginBottom: 8 }}>Open Source</div>
            <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>Self-hosted Eye</div>
            <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>Apache 2.0 licensed. Run Eye on your own infrastructure. Full control over signal routing, storage, and integration with your existing trust stack.</div>
          </div>
          <div className="ep-card-lift ep-reveal ep-stagger-2" style={cardStyle(color.blue)}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.blue, marginBottom: 8 }}>Managed</div>
            <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>EP Cloud with Eye</div>
            <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>Hosted signal processing, pre-built signal class libraries, dashboard for warning triage, and direct escalation into EP Handshake and Accountable Signoff.</div>
          </div>
        </div>
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.green, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Product / Emilia Eye</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Start with observation. Build toward enforcement.
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            Deploy Eye in OBSERVE mode first. Understand your high-risk action patterns before adding enforcement. No disruption to existing workflows.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="#pilot" className="ep-cta" style={cta.primary}>Pilot Emilia Eye</a>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 32 }}>
          <h2 style={styles.h2}>Pilot Emilia Eye</h2>
        </div>
        {submitted ? (
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.green}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
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
            {error && <p style={{ color: '#DC2626', fontSize: 13, marginTop: 12 }}>{error}</p>}
            <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...((!form.name || !form.email) ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting...' : 'Pilot Emilia Eye'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
