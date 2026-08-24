'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function EmiliaEyePage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const STACK = [
    { label: 'Eye', verb: 'Advises', accent: color.green, detail: 'Observes or evaluates in shadow mode and emits an action-scoped advisory. The advisory can tighten posture but never authorizes or enforces an action by itself.' },
    { label: 'Protocol', verb: 'Verifies', accent: color.blue, detail: 'Native artifacts verify under their own rules and relying-party-pinned trust anchors. Verification remains separate from authorization.' },
    { label: 'Approver', verb: 'Captures', accent: '#F59E0B', detail: 'When the buyer-pinned policy requires a fresh human decision, an enrolled credential can approve, decline, amend, or reject the exact action.' },
    { label: 'Gate', verb: 'Controls admission', accent: '#78716C', detail: 'At a completely mediated executor boundary, Gate reserves accepted authority before provider entry and preserves executed or indeterminate outcomes without blind replay.' },
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
      <main>

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 72 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.green }}>Product / Emilia Eye</div>
        <h1 className="ep-hero-text" style={styles.h1}>Start lighter with Emilia Eye</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          An experimental advisory profile that flags when stricter EMILIA controls may apply.
          Eye never authorizes, blocks, or executes an action by itself; a relying party decides how
          to use the signal under its own pinned policy.
        </p>
        <div className="ep-hero-text" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/pilot" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
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
          <p style={styles.body}>Four distinct layers keep advisory, verification, human decision evidence, and consequence admission from collapsing into one verdict.</p>
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
          Eye advises. Protocol verifies. Approver captures. Gate controls admission.
        </div>
        <div className="ep-reveal" style={{
          marginTop: 24,
          border: `1px solid ${color.border}`,
          borderLeft: `2px solid ${color.gold}`,
          borderRadius: radius.base,
          padding: '24px',
          background: '#FAFAF9',
        }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.gold, marginBottom: 10 }}>
            Experimental · continuous-eval loop
          </div>
          <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: 0 }}>
            Eye is an experimental, advisory-only profile. A relying party may use an action-scoped
            advisory as one input that tightens posture, but the advisory is <strong>never authority</strong>
            and never the sole action gate. The public draft and repository implementation are not a
            production deployment, certification, standards adoption, or IETF endorsement.
          </p>
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
            <p style={styles.body}>Two bounded solution profiles showing how a buyer could compose Eye with a separate Gate boundary.</p>
          </div>
          <div style={{ display: 'grid', gap: 12 }}>
            {[
              {
                label: 'Government',
                accent: color.green,
                title: 'Payment destination change',
                steps: [
                  'Operator initiates a payment destination change for a benefits disbursement.',
                  'A buyer-pinned profile evaluates the action pattern and may raise a GOV advisory.',
                  'The relying party may route the flagged action to separate native verification and evidence checks.',
                  'If policy requires it, an enrolled supervisor credential decides over the exact change before a completely mediated Gate admits provider entry.',
                ],
              },
              {
                label: 'Financial',
                accent: color.blue,
                title: 'Beneficiary change on wire transfer',
                steps: [
                  'An operator or automated system requests a beneficiary change on an outbound wire.',
                  'A buyer-pinned profile may raise a FIN advisory for a payout-destination change.',
                  'The relying party can route the flagged transaction to separate authority and evidence checks bound to the exact parameters.',
                  'If treasury policy requires it, an enrolled officer decides over the exact change before a completely mediated Gate admits one provider attempt.',
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
          <h2 style={styles.h2}>Evaluation posture</h2>
          <p style={styles.body}>Evaluate the open advisory profile without implying a live managed service or production enforcement.</p>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
          <div className="ep-card-lift ep-reveal ep-stagger-1" style={cardStyle(color.green)}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.green, marginBottom: 8 }}>Open profile</div>
            <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>Inspect and reproduce</div>
            <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>Review the public draft, code, and exact evidence boundary under Apache 2.0. A local evaluation is not deployment evidence.</div>
          </div>
          <div className="ep-card-lift ep-reveal ep-stagger-2" style={cardStyle(color.blue)}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.blue, marginBottom: 8 }}>Canonical offer</div>
            <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{PROTECTED_WORKFLOW_PILOT.name}</div>
            <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel} · synthetic, read-only, sandbox, or shadow validation only. First offered profile: {PROTECTED_WORKFLOW_PILOT.firstProfileLabel}. Eye remains an eligible solution profile for fit review. No production provider credentials or actuation.</div>
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
            Assess one buyer-selected workflow in synthetic, read-only, sandbox, or shadow mode.
            Production enforcement is outside the pilot and requires a separate Gate Implementation
            after the buyer accepts the proposed consequence boundary.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/pilot" className="ep-cta" style={cta.primary}>Scope the {PROTECTED_WORKFLOW_PILOT.shortPriceLabel}, {PROTECTED_WORKFLOW_PILOT.durationLabel} pilot</a>
          </div>
        </div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
