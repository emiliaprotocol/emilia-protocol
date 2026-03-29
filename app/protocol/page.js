'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

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

export default function ProtocolPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Protocol" />

      <div style={styles.section}>
        <div style={styles.eyebrow}>The Protocol</div>
        <h1 style={styles.h1}>Trust, enforced at the action level</h1>
        <p style={styles.body}>
          EMILIA Protocol (EP) is an open standard for binding actor identity, authority, policy,
          and exact action context into a single cryptographic ceremony -- before any high-risk
          action is allowed to proceed.
        </p>
        <p style={styles.body}>
          Most authorization systems verify who is acting. EP verifies whether this specific action
          should be allowed to proceed right now, given the full context of who is asking, what
          authority they hold, and what policy governs the decision.
        </p>
      </div>

      <div style={styles.divider} />

      <div style={styles.sectionAlt}>
        <div style={styles.section}>
          <div style={styles.eyebrow}>The 5-Endpoint Story</div>
          <h2 style={styles.h2}>One ceremony, five steps</h2>
          <p style={styles.body}>Every EP ceremony follows the same disciplined flow.</p>
          <div>
            {ENDPOINTS.map((ep, i) => (
              <div key={ep.name} style={{ display: 'flex', gap: 16, alignItems: 'baseline', padding: '16px 0', borderBottom: `1px solid ${color.border}` }}>
                <span style={{ fontFamily: font.mono, fontSize: 14, fontWeight: 500, color: color.green, minWidth: 100, flexShrink: 0 }}>{ep.name}</span>
                <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{ep.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={styles.divider} />

      <div style={styles.section}>
        <div style={styles.eyebrow}>State Machine</div>
        <h2 style={styles.h2}>Ceremony lifecycle</h2>
        <p style={styles.body}>Each ceremony transitions through a deterministic set of states. No ambiguity, no undefined behavior.</p>
        <div>
          {STATES.map(st => (
            <div key={st.state} style={{ display: 'flex', gap: 16, alignItems: 'baseline', padding: '12px 0', borderBottom: `1px solid ${color.border}` }}>
              <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 500, color: color.blue, minWidth: 140, flexShrink: 0 }}>{st.state}</span>
              <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{st.desc}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={styles.divider} />

      <div style={styles.section}>
        <div style={styles.eyebrow}>Seven Binding Guarantees</div>
        <h2 style={styles.h2}>What EP binds, every ceremony</h2>
        <p style={styles.body}>
          Actor identity. Authority chain. Exact action context. Policy version and hash. Nonce and expiry.
          One-time consumption. Immutable event traceability. Every ceremony. No exceptions.
        </p>
        <div style={{ marginTop: 32, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the Full Spec</a>
          <a href="/partners" className="ep-cta-ghost" style={cta.ghost}>Request Pilot</a>
        </div>
      </div>

      <SiteFooter />
    </div>
  );
}
