import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color, grid, font } from '@/lib/tokens';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Government Action-Control Profile | EMILIA Protocol',
  description: 'A bounded EMILIA solution profile for government payment, benefit-routing, and administrative action controls.',
};

export default function GovernmentPage() {
  const cards = [
    ['Payment destination changes', 'Bind the beneficiary, approval policy, and accountable signer before disbursement changes take effect.'],
    ['Benefit payment redirect', 'A completely mediated profile can require exact-action binding and replay-resistant authority before a sensitive routing change reaches its provider.'],
    ['Healthcare program integrity', 'Bind provider standing, verified authorization, named review, claim parameters, payment destination, and authenticated outcome evidence to one exact action.'],
    ['Operator overrides', 'Require Accountable Signoff when exceptions, overrides, or urgent case interventions cross policy thresholds.'],
    ['Delegated case actions', 'Ensure delegated staff and systems can only act within authority and only on the exact bound action.'],
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="Government" />
      <main>
      <section style={{ ...styles.sectionWide, paddingTop: 96 }}>
        <div style={styles.eyebrowBlue}>Government solution profile</div>
        <h1 style={styles.h1Large}>Exact-action controls for public-sector workflows</h1>
        <p style={{ ...styles.body, maxWidth: 760 }}>
          EMILIA can be configured between authentication and a covered system-of-record action
          to evaluate exact authority and required evidence before provider entry. Government
          payment, benefit-routing, operator-override, and delegated administrative workflows are
          candidate profiles, not claims of agency adoption, fraud absence, or legal compliance.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="/pilot?v=gov" className="ep-cta" style={cta.primaryBlue}>
            Scope the {PROTECTED_WORKFLOW_PILOT.shortPriceLabel}, {PROTECTED_WORKFLOW_PILOT.durationLabel} pilot
          </a>
          <a href="/health/program-integrity" className="ep-cta-secondary" style={cta.secondaryBlue}>Run the synthetic scenario</a>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondaryBlue}>Read the Protocol</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>Candidate protected workflows</h2>
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
        <h2 style={styles.h2}>What a completely mediated Gate can evaluate before provider entry</h2>
        <ul style={styles.list}>
          <li>actor identity from authenticated context, never self-asserted request body claims</li>
          <li>authority from pinned registry, delegation, and policy inputs</li>
          <li>exact action and target binding through canonical binding material</li>
          <li>policy version and policy hash pinned at decision time</li>
          <li>replay resistance through nonce, expiry, and shared one-time consumption state</li>
          <li>tamper-evident events for reconstruction, oversight, and evidence export</li>
          <li>Accountable Signoff when the buyer-pinned policy requires a fresh human decision</li>
        </ul>
      </section>

      <section style={styles.sectionWide}>
        <div style={{ ...styles.card, borderLeft: `3px solid ${color.green}`, padding: '28px 32px' }}>
          <h3 style={styles.h3}>Start with one assessed consequence boundary</h3>
          <p style={styles.cardBody}>
            Finance operations remains the initial offered profile; government workflows are an
            eligible solution profile for fit review. The protected-workflow pilot is nonproduction
            only: synthetic, read-only, sandbox,
            or shadow validation around one buyer-selected action. It never receives production
            provider credentials or actuates a production system. Production is considered only
            through a separate Gate Implementation after the buyer accepts the proposed boundary.
          </p>
          <a href="/gate" style={{ fontFamily: font.mono, fontSize: 12, color: color.green, textDecoration: 'none', marginTop: 12, display: 'inline-block', letterSpacing: 1 }}>See EMILIA Gate &#8594;</a>
          <a href="/health/program-integrity" style={{ fontFamily: font.mono, fontSize: 12, color: color.blue, textDecoration: 'none', marginTop: 12, marginLeft: 24, display: 'inline-block', letterSpacing: 1 }}>Run the synthetic healthcare scenario &#8594;</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>What a configured protected path can preserve</h2>
          <ul style={styles.list}>
            <li>Decision record -- who acted, what was requested, and which pinned policy governed</li>
            <li>Event chain -- observed request, admission, provider, and outcome states without collapsing uncertainty</li>
            <li>Signoff trace when required -- enrolled-key evidence bound to the exact action</li>
            <li>Policy snapshot -- content-addressed reference to the policy version evaluated at decision time</li>
            <li>Scoped evidence export for authorized oversight, audit-support, and legal-review procedures</li>
          </ul>
        </div>
      </section>
      </main>

      <SiteFooter />
    </div>
  );
}
