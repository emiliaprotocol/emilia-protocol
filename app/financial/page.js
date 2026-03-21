import SiteNav from '@/components/SiteNav';

export const metadata = {
  title: 'Financial Infrastructure Controls | EMILIA Protocol',
  description: 'EP for beneficiary changes, payout controls, treasury approvals, and other high-risk financial workflows.',
};

export default function FinancialPage() {
  const s = {
    page: { minHeight: '100vh', background: '#05060a', color: '#e8e6e3', fontFamily: "'Space Grotesk', sans-serif" },
    section: { maxWidth: 1080, margin: '0 auto', padding: '64px 24px' },
    sectionAlt: { background: 'rgba(255,255,255,0.02)', borderTop: '1px solid rgba(255,255,255,0.06)', borderBottom: '1px solid rgba(255,255,255,0.06)' },
    eyebrow: { fontFamily: "'JetBrains Mono', monospace", color: '#00d4ff', fontSize: 12, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 18 },
    h1: { fontFamily: "'Outfit', sans-serif", fontWeight: 900, fontSize: 'clamp(42px, 7vw, 72px)', lineHeight: 0.95, letterSpacing: -2, margin: '0 0 16px' },
    h2: { fontFamily: "'Outfit', sans-serif", fontWeight: 800, fontSize: 30, letterSpacing: -1, margin: '0 0 16px' },
    body: { color: '#9aa3b2', fontSize: 17, lineHeight: 1.7, maxWidth: 760 },
    card: { background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 14, padding: 20 },
    cardTitle: { fontWeight: 700, fontSize: 18, marginBottom: 8 },
    cardBody: { color: '#9aa3b2', fontSize: 15, lineHeight: 1.6 },
    cta: { display: 'inline-flex', alignItems: 'center', gap: 8, textDecoration: 'none', borderRadius: 10, padding: '14px 22px', fontFamily: "'JetBrains Mono', monospace", fontSize: 12, letterSpacing: 1, textTransform: 'uppercase', fontWeight: 700 },
    list: { color: '#9aa3b2', lineHeight: 1.8, fontSize: 16, paddingLeft: 18 }
  };

  const cards = [
    ['Beneficiary changes', 'Bind the beneficiary record, requested change, approving authority, and policy before modification.'],
    ['Payout destination changes', 'Require exact transaction binding, replay resistance, and accountable human ownership for destination edits.'],
    ['Treasury approvals', 'Constrain high-risk disbursements and exception approvals with one-time authorization and full evidence traceability.'],
    ['Vendor remittance controls', 'Protect remittance updates against thread hijacking, social engineering, and approved-looking workflow abuse.'],
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="Financial" />
      <section style={{ ...s.section, paddingTop: 96 }}>
        <div style={s.eyebrow}>Financial Infrastructure</div>
        <h1 style={s.h1}>Control high-risk financial actions before execution</h1>
        <p style={s.body}>
          EMILIA Protocol is infrastructure for beneficiary changes, payout destination controls, treasury approvals, remittance updates, and other high-risk financial workflows that fail when authentication is treated as enough.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="mailto:team@emiliaprotocol.ai?subject=Financial%20pilot%20request" style={{ ...s.cta, background: '#00d4ff', color: '#05060a' }}>Request Financial Pilot</a>
          <a href="/spec" style={{ ...s.cta, border: '1px solid rgba(0,212,255,0.3)', color: '#00d4ff', background: 'transparent' }}>Read the Protocol</a>
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
        <h2 style={s.h2}>What EP proves before a financial action executes</h2>
        <ul style={s.list}>
          <li>who is acting and under what authority chain</li>
          <li>what exact action is being requested, on what exact target</li>
          <li>which policy version and policy hash govern the action</li>
          <li>that the authorization artifact cannot be replayed or reused</li>
          <li>that accountable human signoff occurred when thresholds require human ownership</li>
          <li>that the full decision path is reconstructable through immutable events</li>
        </ul>
      </section>
    </div>
  );
}
