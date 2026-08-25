import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';
import type { Metadata } from 'next';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

export const metadata: Metadata = {
  title: 'Government Exact-Action Control',
  description: 'Customer-owned authority control for selected government payment, benefit-routing, operator-override, and high-risk administrative paths.',
  alternates: { canonical: '/government' },
};

export default function GovernmentPage() {
  const cards = [
    ['Payment destination changes', 'Bind the beneficiary, approval policy, and accountable signer before disbursement changes take effect.'],
    ['Benefit redirect risk', 'Bind accepted authority and the exact change before a completely mediated enrollment or benefit-routing path reaches its system of record.'],
    ['Healthcare program integrity', 'Bind provider standing, verified authorization, named review, claim parameters, payment destination, and authenticated outcome evidence to one exact action.'],
    ['Operator overrides', 'Require Accountable Signoff when exceptions, overrides, or urgent case interventions cross policy thresholds.'],
    ['Delegated case actions', 'Refuse a covered action that exceeds the accepted delegation or does not match the exact bound parameters.'],
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="Government" />
      <main>
      <section style={{ ...styles.sectionWide, paddingTop: 96 }}>
        <div style={styles.eyebrowBlue}>Government</div>
        <h1 style={styles.h1Large}>Trust controls for public-sector fraud and payment integrity</h1>
        <p style={{ ...styles.body, maxWidth: 760 }}>
          EMILIA Gate adds a customer-owned authority decision between authentication and selected public-sector actions. On a completely mediated covered path, no accepted exact-action authority and required evidence means no provider entry.
        </p>
        <p style={{ ...styles.body, maxWidth: 760 }}>
          {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel} · {PROTECTED_WORKFLOW_PILOT.workflowLabel}. {PROTECTED_WORKFLOW_PILOT.rolloutLabel}.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="/pilot?v=gov" className="ep-cta" style={cta.primaryBlue}>Scope the protected-workflow pilot</a>
          <a href="/health/program-integrity" className="ep-cta-secondary" style={cta.secondaryBlue}>Run Program Integrity Demo</a>
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
        <h2 style={styles.h2}>What Gate can establish before a protected government action executes</h2>
        <ul style={styles.list}>
          <li>the presenting credential and accepted role from authenticated context, never self-asserted request-body claims</li>
          <li>authority from pinned registries, delegation evidence, and policy, not declarations; credential evidence does not establish civil identity by itself</li>
          <li>exact action and target binding through canonical binding material</li>
          <li>policy version and policy hash pinned at decision time</li>
          <li>replay resistance through nonce, expiry, and one-time consumption</li>
          <li>tamper-evident events for reconstruction, oversight, and evidence export</li>
          <li>action-bound evidence from an accepted enrolled approver credential when policy requires fresh approval</li>
        </ul>
      </section>

      <section style={styles.sectionWide}>
        <div style={{ ...styles.card, borderLeft: `3px solid ${color.green}`, padding: '28px 32px' }}>
          <h3 style={styles.h3}>Start with one consequence boundary</h3>
          <p style={styles.cardBody}>
            Begin in observe mode around one system-of-record action, such as a payment destination
            change, benefit redirect, provider enrollment update, or accountable override. Move
            that path to enforcement after the policy and evidence requirements are validated.
          </p>
          <a href="/gate" style={{ fontFamily: font.mono, fontSize: 12, color: color.green, textDecoration: 'none', marginTop: 12, display: 'inline-block', letterSpacing: 1 }}>See EMILIA Gate &#8594;</a>
          <a href="/health/program-integrity" style={{ fontFamily: font.mono, fontSize: 12, color: color.blue, textDecoration: 'none', marginTop: 12, marginLeft: 24, display: 'inline-block', letterSpacing: 1 }}>Run the healthcare scenario &#8594;</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>What evidence agencies get after each controlled action</h2>
          <ul style={styles.list}>
            <li>Decision record -- who acted, what was requested, what policy governed</li>
            <li>Covered-path event chain -- request, Gate decision, admission, and reported outcome kept distinct</li>
            <li>Signoff trace if required -- the accepted enrolled approver credential bound to the exact action</li>
            <li>Policy snapshot -- content-addressed reference to the exact policy version at decision time</li>
            <li>Reconstruction-ready export -- full evidence package for audit, oversight, and legal review</li>
          </ul>
        </div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
