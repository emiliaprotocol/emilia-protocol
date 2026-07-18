import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Financial Infrastructure Controls | EMILIA Protocol',
  description: 'EP for beneficiary changes, payout controls, treasury approvals, and other high-risk financial workflows.',
};

export default function FinancialPage() {
  const cards = [
    ['Beneficiary changes', 'Bind the beneficiary record, requested change, approving authority, and policy before modification.'],
    ['Payout destination changes', 'Require exact transaction binding, replay resistance, and accountable human ownership for destination edits.'],
    ['Treasury approvals', 'Constrain high-risk disbursements and exception approvals with one-time authorization and full evidence traceability.'],
    ['Vendor remittance controls', 'Protect remittance updates against thread hijacking, social engineering, and approved-looking workflow abuse.'],
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="Financial" />
      <section style={{ ...styles.sectionWide, paddingTop: 96 }}>
        <div style={styles.eyebrowBlue}>Financial Infrastructure</div>
        <h1 style={styles.h1Large}>Control high-risk financial actions before execution</h1>
        <p style={{ ...styles.body, maxWidth: 760 }}>
          EMILIA Protocol is infrastructure for beneficiary changes, payout destination controls, treasury approvals, remittance updates, and other high-risk financial workflows that fail when authentication is treated as enough.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="mailto:team@emiliaprotocol.ai?subject=Financial%20pilot%20request" className="ep-cta" style={cta.primaryBlue}>Request Financial Pilot</a>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondaryBlue}>Read the Protocol</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>Best first workflows</h2>
          <div style={grid.auto(240)}>
            {cards.map(([title, body]) => (
              <div key={title} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{title}</div>
                <div style={styles.cardBody}>{body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section style={styles.sectionWide}>
        <h2 style={styles.h2}>What Gate can establish before a protected financial action executes</h2>
        <ul style={styles.list}>
          <li>Actor identity -- cryptographically verified, never self-asserted</li>
          <li>Authority chain -- complete delegation path from root to acting principal</li>
          <li>Exact transaction binding -- precise operation, target, parameters, and conditions</li>
          <li>Policy version and hash -- content-addressed reference to the governing policy at decision time</li>
          <li>Replay resistance -- one-time nonce and strict temporal bounds</li>
          <li>One-time consumption -- each ceremony token consumed on use, no reuse</li>
          <li>Accountable signoff when required -- named human responsibility bound to the exact action</li>
        </ul>
      </section>

      <section style={styles.sectionWide}>
        <div style={{ ...styles.card, borderLeft: `3px solid ${color.green}`, padding: '28px 32px' }}>
          <h3 style={styles.h3}>Start with one consequence boundary</h3>
          <p style={styles.cardBody}>
            Begin in observe mode around one system-of-record action, such as a beneficiary change,
            payment release, or remittance update. Move that path to Gate enforcement after the
            policy, authority, and approval requirements are validated.
          </p>
          <a href="/gate" style={{ fontFamily: font.mono, fontSize: 12, color: color.green, textDecoration: 'none', marginTop: 12, display: 'inline-block', letterSpacing: 1 }}>See EMILIA Gate &#8594;</a>
          <a href="/eye" style={{ fontFamily: font.mono, fontSize: 12, color: color.green, textDecoration: 'none', marginTop: 12, display: 'inline-block', letterSpacing: 1 }}>See Emilia Eye &#8594;</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>Best first pilot</h2>
          <p style={styles.body}>Start with one high-risk workflow and expand from there.</p>
          <ul style={{ ...styles.list, marginTop: 16 }}>
            <li>Beneficiary change</li>
            <li>Payout destination change</li>
            <li>Remittance update</li>
            <li>Treasury release approval</li>
          </ul>
          <div style={{ marginTop: 24 }}>
            <a href="mailto:team@emiliaprotocol.ai?subject=Financial%20pilot%20request" className="ep-cta" style={cta.primaryBlue}>Request Financial Pilot</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
