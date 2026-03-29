import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Government Fraud Prevention | EMILIA Protocol',
  description: 'EP for government payment integrity, benefit redirect controls, operator overrides, and high-risk administrative actions.',
};

export default function GovernmentPage() {
  const cards = [
    ['Payment destination changes', 'Bind the beneficiary, approval policy, and accountable signer before disbursement changes take effect.'],
    ['Benefit redirect fraud', 'Enforce exact action binding and replay-resistant authorization before sensitive enrollment or benefit-routing changes execute.'],
    ['Operator overrides', 'Require Accountable Signoff when exceptions, overrides, or urgent case interventions cross policy thresholds.'],
    ['Delegated case actions', 'Ensure delegated staff and systems can only act within authority and only on the exact bound action.'],
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="Government" />
      <section style={{ ...styles.sectionWide, paddingTop: 96 }}>
        <div style={styles.eyebrowBlue}>Government</div>
        <h1 style={styles.h1Large}>Trust controls for public-sector fraud and payment integrity</h1>
        <p style={{ ...styles.body, maxWidth: 760 }}>
          EMILIA Protocol creates the control layer between authentication and execution for high-risk public workflows. EP is built for payment integrity, benefit redirect prevention, operator overrides, delegated administrative actions, and AI-assisted execution in government systems.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="mailto:team@emiliaprotocol.ai?subject=Government%20pilot%20request" className="ep-cta" style={cta.primaryBlue}>Request Government Pilot</a>
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
        <h2 style={styles.h2}>What EP proves before a government action executes</h2>
        <ul style={styles.list}>
          <li>actor identity from authenticated context, never self-asserted request body claims</li>
          <li>authority from registry, delegation, and policy—not declarations</li>
          <li>exact action and target binding through canonical binding material</li>
          <li>policy version and policy hash pinned at decision time</li>
          <li>replay resistance through nonce, expiry, and one-time consumption</li>
          <li>immutable events for reconstruction, oversight, and evidence export</li>
          <li>Accountable Signoff when policy requires named human ownership</li>
        </ul>
      </section>

      <section style={styles.sectionWide}>
        <div style={{ ...styles.card, borderLeft: `3px solid ${color.green}`, padding: '28px 32px' }}>
          <h3 style={styles.h3}>Start with Emilia Eye</h3>
          <p style={styles.cardBody}>
            If an agency is not ready to redesign the workflow immediately, Eye can flag payment destination changes, benefit redirects, and unusual overrides so those cases trigger EP enforcement first.
          </p>
          <a href="/eye" style={{ fontFamily: font.mono, fontSize: 12, color: color.green, textDecoration: 'none', marginTop: 12, display: 'inline-block', letterSpacing: 1 }}>See Emilia Eye &#8594;</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>What evidence agencies get after each controlled action</h2>
          <ul style={styles.list}>
            <li>Decision record -- who acted, what was requested, what policy governed</li>
            <li>Event chain -- complete sequence from request through enforcement to outcome</li>
            <li>Signoff trace if required -- named human responsibility bound to the exact action</li>
            <li>Policy snapshot -- immutable reference to the exact policy version at decision time</li>
            <li>Reconstruction-ready export -- full evidence package for audit, oversight, and legal review</li>
          </ul>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
