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

// Every entry must correspond to a file under PIPs/. Engineering
// reviewers run `ls PIPs/` against this list — listing a PIP without
// its file creates a discoverable contradiction. PIP-006 was restored
// once PIPs/PIP-006-federation.md was authored.
const PIPS = [
  { pip: 'PIP-001', title: 'Core Freeze',           status: 'Accepted' },
  { pip: 'PIP-002', title: 'Handshake',             status: 'Accepted' },
  { pip: 'PIP-003', title: 'Accountable Signoff',   status: 'Accepted' },
  { pip: 'PIP-004', title: 'EP Commit',             status: 'Accepted' },
  { pip: 'PIP-005', title: 'Emilia Eye',            status: 'Accepted' },
  { pip: 'PIP-006', title: 'Federation',            status: 'Draft'    },
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

// ─── Eight binding properties (Core 01–07 + Signoff extension 08) ─────────
// Visual grid moved here from the homepage so the buyer-facing page stays
// 30-second readable and the technical depth lives one click away.
const BINDINGS = [
  { num: '01', title: 'Actor identity',                     body: 'Cryptographically verified identity of the entity requesting the action.',                  code: 'verify(entity.keyId)' },
  { num: '02', title: 'Authority chain',                    body: 'Complete delegation path from root authority to the acting principal.',                     code: '∀d ∈ D: d(root→actor)' },
  { num: '03', title: 'Exact action context',               body: 'The precise operation, target, parameters, and environmental conditions.',                  code: 'bind(action, params)' },
  { num: '04', title: 'Policy version and hash',            body: 'Immutable reference to the exact policy version that authorized this action.',              code: 'pin(policy.sha256)' },
  { num: '05', title: 'Nonce and expiry',                   body: 'One-time cryptographic nonce and strict temporal bounds on authorization.',                 code: 'N_{t} ≠ N_{t-1}' },
  { num: '06', title: 'One-time consumption',               body: 'Each ceremony token is consumed on use — no replay, no reuse, no ambiguity.',               code: 'consume(token_id, lock)' },
  { num: '07', title: 'Immutable event traceability',       body: 'Append-only audit trail linking every authorization to its outcome.',                       code: 'Append(Log, Hash(E))' },
  { num: '08', title: 'Accountable signoff (extension)',    body: 'Named human responsibility for the exact action, cryptographically bound to the ceremony.', code: 'attest(actor, action)' },
];

// Four-step phased rollout (OBSERVE → SHADOW → ENFORCE-with-handshake →
// SEAL). Same content the homepage used to render.
const ROLLOUT = [
  { step: '01', accent: color.green, label: 'Start with Eye',         body: 'Observe, shadow, then enforce. Eye runs alongside existing workflows — logging first, flagging without blocking, then enforcing full ceremony when ready.', filled: true  },
  { step: '02', accent: color.blue,  label: 'Enforce with Handshake', body: 'Policy-bound pre-action trust enforcement. Canonical binding, replay resistance, one-time consumption. Seven properties verified before execution proceeds.', filled: false },
  { step: '03', accent: color.gold,  label: 'Own with Signoff',       body: 'Named human ownership when policy requires it. Not MFA. Cryptographically bound, action-specific accountability before execution.',                          filled: false },
  { step: '04', accent: color.t2,    label: 'Seal with Commit',       body: 'Atomic write to the immutable audit chain. Handshake consumed, signoff consumed, event chain sealed. Execution released. Cannot be undone.',                  filled: false },
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

      {/* Seven binding guarantees + signoff extension — visual grid */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <div style={styles.eyebrow}>Seven Binding Guarantees</div>
            <h2 style={styles.h2}>What EP binds, every ceremony</h2>
            <p style={styles.body}>
              Actor identity. Authority chain. Exact action context. Policy version and hash. Nonce and expiry.
              One-time consumption. Immutable event traceability. Every ceremony. No exceptions. The
              eighth property — accountable signoff — applies whenever policy requires named human ownership.
            </p>
          </div>

          {/* Border-collapse grid — same pattern the homepage used to render */}
          <div className="ep-reveal ep-stagger-1" style={{
            display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
            borderTop: `1px solid ${color.border}`,
            borderLeft: `1px solid ${color.border}`,
            background: '#F5F4F0',
            marginBottom: 32,
          }}>
            {BINDINGS.map((b, i) => (
              <div key={i} className="ep-card-lift" style={{
                position: 'relative', overflow: 'hidden',
                background: color.card,
                borderRight: `1px solid ${color.border}`,
                borderBottom: `1px solid ${color.border}`,
                padding: '24px',
              }}>
                {/* Ghost number */}
                <div aria-hidden style={{
                  position: 'absolute', right: -8, top: -16,
                  fontFamily: font.mono, fontWeight: 700, fontSize: 80,
                  color: 'rgba(232,229,225,0.6)', pointerEvents: 'none',
                  lineHeight: 1, userSelect: 'none',
                }}>{b.num}</div>
                <div style={{ position: 'relative', zIndex: 1 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 14 }}>
                    Property_{b.num}
                  </div>
                  <h4 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 13, marginBottom: 6, color: color.t1 }}>{b.title}</h4>
                  <p style={{ fontSize: 12, color: color.t2, lineHeight: 1.55, marginBottom: 14 }}>{b.body}</p>
                  <div style={{
                    fontFamily: font.mono, fontSize: 9,
                    background: '#F5F4F0', border: `1px solid ${color.border}`,
                    padding: '6px 10px', textAlign: 'center', color: color.t3,
                  }}>{b.code}</div>
                </div>
              </div>
            ))}
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

      {/* Phased rollout — Eye → Handshake → Signoff → Commit */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <div style={styles.eyebrow}>Rollout Schematics</div>
            <h2 style={styles.h2}>Progressive phased deployment</h2>
            <p style={styles.body}>
              EP rolls out in four phases. Most pilots begin in <strong>OBSERVE</strong> for 2–4 weeks
              to generate the &ldquo;what would have been blocked&rdquo; report before flipping to enforce.
            </p>
          </div>
          <div style={{ position: 'relative' }}>
            {/* Connecting line */}
            <div aria-hidden style={{
              position: 'absolute', top: 20, left: 36, right: 36,
              height: 1, background: color.border, zIndex: 0,
            }} />
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, position: 'relative', zIndex: 1 }}>
              {ROLLOUT.map((item, i) => (
                <div key={i} className="ep-card-lift ep-reveal" style={{
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  padding: '28px',
                }}>
                  <div style={{
                    width: 40, height: 40, borderRadius: 2,
                    background: item.filled ? color.t1 : '#F5F4F0',
                    border: item.filled ? 'none' : `1px solid ${color.border}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginBottom: 20,
                    fontFamily: font.mono, fontSize: 12, fontWeight: 600,
                    color: item.filled ? color.gold : color.t2,
                  }}>{item.step}</div>
                  <div style={{
                    fontFamily: font.mono, fontSize: 10, fontWeight: 500,
                    color: item.accent, letterSpacing: 1.5,
                    textTransform: 'uppercase', marginBottom: 10,
                  }}>{item.label}</div>
                  <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.65 }}>{item.body}</p>
                </div>
              ))}
            </div>
          </div>
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
