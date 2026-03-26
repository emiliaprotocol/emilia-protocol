'use client';

import SiteNav from '@/components/SiteNav';

const ENDPOINTS = [
  { name: '/initiate', desc: 'Client requests a trust ceremony by describing the high-risk action, actor identity, and context.' },
  { name: '/evaluate', desc: 'EP engine evaluates the request against bound policy, authority chain, and environmental conditions.' },
  { name: '/signoff', desc: 'When policy requires human accountability, a named responsible party explicitly assumes ownership.' },
  { name: '/execute', desc: 'One-time ceremony token is consumed. The action proceeds with full cryptographic binding.' },
  { name: '/audit', desc: 'Immutable event record links every authorization to its outcome in an append-only trail.' },
];

const STATES = [
  { state: 'INITIATED', desc: 'Ceremony request received and validated.' },
  { state: 'EVALUATING', desc: 'Policy engine processing bindings and constraints.' },
  { state: 'PENDING_SIGNOFF', desc: 'Awaiting human accountability signoff.' },
  { state: 'APPROVED', desc: 'All bindings satisfied. One-time token issued.' },
  { state: 'EXECUTED', desc: 'Token consumed. Action completed.' },
  { state: 'DENIED', desc: 'Policy evaluation failed. Action blocked.' },
  { state: 'EXPIRED', desc: 'Ceremony token exceeded temporal bounds.' },
];

const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
  sectionAlt: { background: '#0F172A', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 16 },
  h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
  h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 24, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 },
  body: { fontSize: 16, color: '#94A3B8', lineHeight: 1.75, marginBottom: 24 },
  endpointRow: { display: 'flex', gap: 16, alignItems: 'baseline', padding: '16px 0', borderBottom: '1px solid rgba(255,255,255,0.06)' },
  endpointName: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 14, fontWeight: 500, color: '#22C55E', minWidth: 100, flexShrink: 0 },
  endpointDesc: { fontSize: 14, color: '#94A3B8', lineHeight: 1.6 },
  stateRow: { display: 'flex', gap: 16, alignItems: 'baseline', padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.06)' },
  stateName: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, fontWeight: 500, color: '#3B82F6', minWidth: 140, flexShrink: 0 },
  stateDesc: { fontSize: 14, color: '#94A3B8', lineHeight: 1.6 },
  cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', border: '1px solid rgba(212,175,55,0.25)', color: '#22C55E', background: 'transparent', transition: 'background 0.2s', marginRight: 12 },
  ctaGhost: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', border: '1px solid rgba(255,255,255,0.06)', color: '#94A3B8', background: 'transparent', transition: 'color 0.2s' },
  divider: { height: 1, background: 'linear-gradient(90deg, transparent, rgba(212,175,55,0.25), transparent)', maxWidth: 400, margin: '0 auto' },
};

export default function ProtocolPage() {
  return (
    <div style={s.page}>
      <SiteNav activePage="Protocol" />

      <div style={s.section}>
        <div style={s.eyebrow}>The Protocol</div>
        <h1 style={s.h1}>Trust, enforced at the action level</h1>
        <p style={s.body}>
          EMILIA Protocol (EP) is an open standard for binding actor identity, authority, policy,
          and exact action context into a single cryptographic ceremony -- before any high-risk
          action is allowed to proceed.
        </p>
        <p style={s.body}>
          Most authorization systems verify who is acting. EP verifies whether this specific action
          should be allowed to proceed right now, given the full context of who is asking, what
          authority they hold, and what policy governs the decision.
        </p>
      </div>

      <div style={s.divider} />

      <div style={{ ...s.sectionAlt }}>
        <div style={s.section}>
          <div style={s.eyebrow}>The 5-Endpoint Story</div>
          <h2 style={s.h2}>One ceremony, five steps</h2>
          <p style={s.body}>Every EP ceremony follows the same disciplined flow.</p>
          <div>
            {ENDPOINTS.map((ep, i) => (
              <div key={ep.name} style={s.endpointRow}>
                <span style={s.endpointName}>{ep.name}</span>
                <span style={s.endpointDesc}>{ep.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={s.divider} />

      <div style={s.section}>
        <div style={s.eyebrow}>State Machine</div>
        <h2 style={s.h2}>Ceremony lifecycle</h2>
        <p style={s.body}>Each ceremony transitions through a deterministic set of states. No ambiguity, no undefined behavior.</p>
        <div>
          {STATES.map(st => (
            <div key={st.state} style={s.stateRow}>
              <span style={s.stateName}>{st.state}</span>
              <span style={s.stateDesc}>{st.desc}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={s.divider} />

      <div style={s.section}>
        <div style={s.eyebrow}>Seven Binding Guarantees</div>
        <h2 style={s.h2}>What EP binds, every ceremony</h2>
        <p style={s.body}>
          Actor identity. Authority chain. Exact action context. Policy version and hash. Nonce and expiry.
          One-time consumption. Immutable event traceability. Every ceremony. No exceptions.
        </p>
        <div style={{ marginTop: 32, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/spec" style={s.cta}>Read the Full Spec</a>
          <a href="/partners" style={s.ctaGhost}>Request Pilot</a>
        </div>
      </div>
    </div>
  );
}
