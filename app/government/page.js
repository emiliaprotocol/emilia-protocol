import SiteNav from '@/components/SiteNav';

export const metadata = {
  title: 'Government Fraud Prevention | EMILIA Protocol',
  description: 'EP for government payment integrity, benefit redirect controls, operator overrides, and high-risk administrative actions.',
};

export default function GovernmentPage() {
  const s = {
    page: { minHeight: '100vh', background: '#020617', color: '#e8e6e3', fontFamily: "'IBM Plex Sans', sans-serif" },
    section: { maxWidth: 1080, margin: '0 auto', padding: '64px 24px' },
    sectionAlt: { background: 'rgba(255,255,255,0.02)', borderTop: '1px solid rgba(255,255,255,0.06)', borderBottom: '1px solid rgba(255,255,255,0.06)' },
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", color: '#3B82F6', fontSize: 12, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 18 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontWeight: 700, fontSize: 'clamp(42px, 7vw, 72px)', lineHeight: 0.95, letterSpacing: -2, margin: '0 0 16px' },
    h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontWeight: 700, fontSize: 30, letterSpacing: -1, margin: '0 0 16px' },
    body: { color: '#9aa3b2', fontSize: 17, lineHeight: 1.7, maxWidth: 760 },
    card: { background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 14, padding: 20 },
    cardTitle: { fontWeight: 700, fontSize: 18, marginBottom: 8 },
    cardBody: { color: '#9aa3b2', fontSize: 15, lineHeight: 1.6 },
    cta: { display: 'inline-flex', alignItems: 'center', gap: 8, textDecoration: 'none', borderRadius: 10, padding: '14px 22px', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, letterSpacing: 1, textTransform: 'uppercase', fontWeight: 700 },
    list: { color: '#9aa3b2', lineHeight: 1.8, fontSize: 16, paddingLeft: 18 }
  };

  const cards = [
    ['Payment destination changes', 'Bind the beneficiary, approval policy, and accountable signer before disbursement changes take effect.'],
    ['Benefit redirect fraud', 'Enforce exact action binding and replay-resistant authorization before sensitive enrollment or benefit-routing changes execute.'],
    ['Operator overrides', 'Require Accountable Signoff when exceptions, overrides, or urgent case interventions cross policy thresholds.'],
    ['Delegated case actions', 'Ensure delegated staff and systems can only act within authority and only on the exact bound action.'],
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="Government" />
      <section style={{ ...s.section, paddingTop: 96 }}>
        <div style={s.eyebrow}>Government</div>
        <h1 style={s.h1}>Trust controls for public-sector fraud and payment integrity</h1>
        <p style={s.body}>
          EMILIA Protocol creates the control layer between authentication and execution for high-risk public workflows. EP is built for payment integrity, benefit redirect prevention, operator overrides, delegated administrative actions, and AI-assisted execution in government systems.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="mailto:team@emiliaprotocol.ai?subject=Government%20pilot%20request" style={{ ...s.cta, background: '#3B82F6', color: '#020617' }}>Request Government Pilot</a>
          <a href="/spec" style={{ ...s.cta, border: '1px solid rgba(59,130,246,0.3)', color: '#3B82F6', background: 'transparent' }}>Read the Protocol</a>
        </div>
      </section>

      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Best first workflows</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
            {cards.map(([title, body]) => (
              <div key={title} style={s.card}>
                <div style={s.cardTitle}>{title}</div>
                <div style={s.cardBody}>{body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section style={s.section}>
        <h2 style={s.h2}>What EP proves before a government action executes</h2>
        <ul style={s.list}>
          <li>actor identity from authenticated context, never self-asserted request body claims</li>
          <li>authority from registry, delegation, and policy—not declarations</li>
          <li>exact action and target binding through canonical binding material</li>
          <li>policy version and policy hash pinned at decision time</li>
          <li>replay resistance through nonce, expiry, and one-time consumption</li>
          <li>immutable events for reconstruction, oversight, and evidence export</li>
          <li>Accountable Signoff when policy requires named human ownership</li>
        </ul>
      </section>

      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What evidence agencies get after each controlled action</h2>
          <ul style={s.list}>
            <li>Decision record -- who acted, what was requested, what policy governed</li>
            <li>Event chain -- complete sequence from request through enforcement to outcome</li>
            <li>Signoff trace if required -- named human responsibility bound to the exact action</li>
            <li>Policy snapshot -- immutable reference to the exact policy version at decision time</li>
            <li>Reconstruction-ready export -- full evidence package for audit, oversight, and legal review</li>
          </ul>
        </div>
      </section>
    </div>
  );
}
