'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const ENDPOINTS = [
  { name: '/initiate', desc: 'Client requests a trust ceremony by describing the high-risk action, actor identity, and context.' },
  { name: '/evaluate', desc: 'EP engine evaluates the request against bound policy, authority chain, and environmental conditions.' },
  { name: '/signoff',  desc: 'When policy requires human accountability, a named responsible party explicitly assumes ownership.' },
  { name: '/execute',  desc: 'One-time ceremony token is consumed. The action proceeds with full cryptographic binding.' },
  { name: '/audit',    desc: 'Immutable event record links every authorization to its outcome in an append-only trail.' },
];

const STATES = [
  { state: 'INITIATED',       desc: 'Ceremony request received and validated.',               color: color.blue  },
  { state: 'EVALUATING',      desc: 'Policy engine processing bindings and constraints.',      color: color.gold  },
  { state: 'PENDING_SIGNOFF', desc: 'Awaiting human accountability signoff.',                  color: color.gold  },
  { state: 'APPROVED',        desc: 'All bindings satisfied. One-time token issued.',          color: color.green },
  { state: 'EXECUTED',        desc: 'Token consumed. Action completed.',                       color: color.green },
  { state: 'DENIED',          desc: 'Policy evaluation failed. Action blocked.',               color: '#DC2626'   },
  { state: 'EXPIRED',         desc: 'Ceremony token exceeded temporal bounds.',                color: color.t3    },
];

// Only PIPs with a corresponding file in PIPs/ are listed. PIP-006
// (Federation) is in design but no draft file exists yet — adding it
// here without the file produces a contradiction the first reviewer
// who runs `ls PIPs/` will catch. Add it back when PIPs/PIP-006-*.md
// lands.
const PIPS = [
  { pip: 'PIP-001', title: 'Core Freeze',           status: 'Accepted' },
  { pip: 'PIP-002', title: 'Handshake',             status: 'Accepted' },
  { pip: 'PIP-003', title: 'Accountable Signoff',   status: 'Accepted' },
  { pip: 'PIP-004', title: 'EP Commit',             status: 'Accepted' },
  { pip: 'PIP-005', title: 'Emilia Eye',            status: 'Accepted' },
];

// Compliance numbers must match the underlying mapping documents exactly.
// "38/38" with "all subcategories mapped" implied 100% framework coverage,
// but NIST AI RMF 1.0 has ~72+ subcategories and the mapping doc covers
// 38 selectively across all four functions. Federal procurement teams will
// cross-check against the published framework.
const COMPLIANCE = [
  { framework: 'NIST AI RMF', coverage: '38 mapped',    detail: 'Across GOVERN, MAP, MEASURE, MANAGE — see docs/compliance/NIST-AI-RMF-MAPPING.md', accent: color.green },
  { framework: 'EU AI Act',   coverage: 'Articles 9-15, 26', detail: 'High-risk AI systems (Title III, Chapter 2) — see docs/compliance/EU-AI-ACT-MAPPING.md', accent: color.blue },
  { framework: 'SOC 2 II',    coverage: 'Preparing',    detail: 'Auditor selection in progress', accent: color.gold },
];

export default function ProtocolPage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <div style={styles.page}>
      <SiteNav activePage="Protocol" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 72 }}>
        <div className="ep-tag ep-hero-badge">The Protocol</div>
        <h1 className="ep-hero-text" style={styles.h1}>Trust, enforced at the action level</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 600 }}>
          EMILIA Protocol (EP) is an open standard for binding actor identity, authority, policy,
          and exact action context into a single cryptographic ceremony — before any high-risk
          action is allowed to proceed.
        </p>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 600 }}>
          Most authorization systems verify who is acting. EP verifies whether this specific action
          should be allowed to proceed right now, given the full context of who is asking, what
          authority they hold, and what policy governs the decision.
        </p>
      </section>

      {/* 5-endpoint story */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <div style={styles.eyebrow}>The 5-Endpoint Story</div>
            <h2 style={styles.h2}>One ceremony, five steps</h2>
            <p style={styles.body}>Every EP ceremony follows the same disciplined flow.</p>
          </div>
          <div style={{
            borderTop: `1px solid ${color.border}`,
            borderLeft: `1px solid ${color.border}`,
          }}>
            {ENDPOINTS.map((ep, i) => (
              <div key={ep.name} className="ep-row-hover ep-reveal" style={{
                display: 'flex', gap: 24, alignItems: 'flex-start',
                padding: '20px 24px',
                borderRight: `1px solid ${color.border}`,
                borderBottom: `1px solid ${color.border}`,
              }}>
                <span style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 600, color: color.green, minWidth: 100, flexShrink: 0, paddingTop: 1 }}>{ep.name}</span>
                <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{ep.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* State machine */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <div style={styles.eyebrow}>State Machine</div>
          <h2 style={styles.h2}>Ceremony lifecycle</h2>
          <p style={styles.body}>Each ceremony transitions through a deterministic set of states. No ambiguity, no undefined behavior.</p>
        </div>
        <div style={{
          borderTop: `1px solid ${color.border}`,
          borderLeft: `1px solid ${color.border}`,
        }}>
          {STATES.map((st, i) => (
            <div key={st.state} className="ep-row-hover ep-reveal" style={{
              display: 'flex', gap: 24, alignItems: 'center',
              padding: '14px 24px',
              borderRight: `1px solid ${color.border}`,
              borderBottom: `1px solid ${color.border}`,
            }}>
              <span style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 600, color: st.color, minWidth: 140, flexShrink: 0, letterSpacing: 0.5 }}>{st.state}</span>
              <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{st.desc}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Seven binding guarantees */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <div style={styles.eyebrow}>Seven Binding Guarantees</div>
            <h2 style={styles.h2}>What EP binds, every ceremony</h2>
            <p style={styles.body}>
              Actor identity. Authority chain. Exact action context. Policy version and hash. Nonce and expiry.
              One-time consumption. Immutable event traceability. Every ceremony. No exceptions.
            </p>
          </div>
          <div className="ep-reveal" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the Full Spec</a>
            <a href="/partners" className="ep-cta-ghost" style={cta.ghost}>Request Pilot</a>
          </div>
        </div>
      </section>

      {/* Protocol governance */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <div style={styles.eyebrow}>Protocol Governance</div>
          <h2 style={styles.h2}>Immutable core, extensible edges</h2>
          <p style={styles.body}>
            EP Core v1.0 (Trust Receipt, Trust Profile, Trust Decision) is frozen. Changes require a Protocol Improvement Proposal, 90-day review, and major version bump with 24-month deprecation. Extensions are added without touching Core.
          </p>
        </div>
        <div className="ep-reveal" style={{
          borderTop: `1px solid ${color.border}`,
          borderLeft: `1px solid ${color.border}`,
        }}>
          {PIPS.map((p, i) => (
            <div key={i} className="ep-row-hover" style={{
              display: 'flex', gap: 24, alignItems: 'center',
              padding: '12px 24px',
              borderRight: `1px solid ${color.border}`,
              borderBottom: `1px solid ${color.border}`,
            }}>
              <span style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, color: color.blue, minWidth: 72, flexShrink: 0 }}>{p.pip}</span>
              <span style={{ fontSize: 14, color: color.t1, flex: 1 }}>{p.title}</span>
              <span style={{ fontFamily: font.mono, fontSize: 10, color: p.status === 'Accepted' ? color.green : color.gold, letterSpacing: 1.5, textTransform: 'uppercase' }}>{p.status}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Compliance */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <div style={styles.eyebrow}>Compliance & Standards</div>
            <h2 style={styles.h2}>Built for regulated adoption</h2>
            <p style={styles.body}>
              EP has formal compliance mappings for 38 NIST AI RMF subcategories across all four functions (GOVERN, MAP, MEASURE, MANAGE) and EU AI Act Articles 9–15 + 26. SOC 2 Type II preparation is underway. Every mapping cites specific EP primitives — not aspirational claims.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
            {COMPLIANCE.map((c, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={{
                border: `1px solid ${color.border}`,
                borderTop: `2px solid ${c.accent}`,
                borderRadius: radius.base,
                padding: '24px',
                background: '#FAFAF9',
              }}>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: c.accent, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 12 }}>{c.framework}</div>
                <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 26, color: color.t1, marginBottom: 8 }}>{c.coverage}</div>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.55 }}>{c.detail}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Open Protocol</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Read the spec. Run the reference implementation. Request a pilot.
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            EP is Apache 2.0 licensed. The spec, the formal verification, and the reference runtime are all public.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/spec" className="ep-cta" style={cta.primary}>Read the Full Spec</a>
            <a href="/partners" className="ep-cta-secondary" style={{ ...cta.secondary, borderColor: 'rgba(255,255,255,0.15)', color: 'rgba(250,250,249,0.7)' }}>Request Pilot →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
