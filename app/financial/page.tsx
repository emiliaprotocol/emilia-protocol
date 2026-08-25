import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

export const metadata: Metadata = {
  title: 'Cross-Rail Authority for Agentic Commerce',
  description: 'Payment partners move money. EMILIA Gate checks accepted exact-action authority and required evidence before a covered transaction reaches a configured connector.',
  alternates: { canonical: '/financial' },
};

export default function FinancialPage() {
  const cards = [
    ['Exact transaction admission', 'Bind amount, currency, counterparty, instrument, operation, and partner request before the rail is entered.'],
    ['Human interruption when needed', 'Let an external policy or risk service select when standing authority is insufficient, then bind the human decision to the same action.'],
    ['Single-use rail entry', 'Mint one opaque, short-lived permit only after current authority and an atomic budget reservation have passed.'],
    ['Uncertain outcomes stay uncertain', 'A lost provider response is fenced for authenticated reconciliation—not converted into a blind retry.'],
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="Financial" />
      <main>
      <section style={{ ...styles.sectionWide, paddingTop: 96 }}>
        <div style={styles.eyebrowBlue}>Cross-Rail Authority</div>
        <h1 style={styles.h1Large}>Let agents transact without giving them the keys</h1>
        <p style={{ ...styles.body, maxWidth: 760 }}>
          Payment partners move the money. On a completely mediated covered path, EMILIA Gate checks whether the exact transaction has accepted authority and required evidence before provider entry. Human approval is one optional evidence source when the buyer&apos;s policy requires it.
        </p>
        <p style={{ ...styles.body, maxWidth: 760 }}>
          {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel} · {PROTECTED_WORKFLOW_PILOT.workflowLabel}. {PROTECTED_WORKFLOW_PILOT.rolloutLabel}.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <a href="/pilot?v=fin" className="ep-cta" style={cta.primaryBlue}>Scope the protected-workflow pilot</a>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondaryBlue}>Read the Protocol</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>One authority contract across configured payment partners</h2>
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
        <h2 style={styles.h2}>What Gate evaluates and records before a transaction reaches a partner</h2>
        <ul style={styles.list}>
          <li>Who or what is acting, under which bounded authority</li>
          <li>The exact amount, currency, counterparty, instrument, operation, and provider request</li>
          <li>Which current policy and allowance permitted the action</li>
          <li>Why a human was—or was not—interrupted</li>
          <li>A separately verified, action-bound human decision when required</li>
          <li>An atomic budget reservation and one-use connector permit</li>
          <li>A durable distinction between executed, refused, and indeterminate</li>
        </ul>
      </section>

      <section style={styles.sectionWide}>
        <div style={{ ...styles.card, borderLeft: `3px solid ${color.green}`, padding: '28px 32px' }}>
          <h3 style={styles.h3}>Authority, not custody</h3>
          <p style={styles.cardBody}>
            EMILIA is not a bank, escrow service, custodian, or settlement rail. Native payment
            partners remain authoritative for authentication, mandates, funds, KYC/AML, settlement,
            refunds, and disputes. Gate controls only whether one exact action may enter a configured connector.
          </p>
          <a href="/gate" style={{ fontFamily: font.mono, fontSize: 12, color: color.green, textDecoration: 'none', marginTop: 12, display: 'inline-block', letterSpacing: 1 }}>See EMILIA Gate &#8594;</a>
          <a href="/eye" style={{ fontFamily: font.mono, fontSize: 12, color: color.green, textDecoration: 'none', marginTop: 12, display: 'inline-block', letterSpacing: 1 }}>See Emilia Eye &#8594;</a>
        </div>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.sectionWide}>
          <h2 style={styles.h2}>Best first pilot</h2>
          <p style={styles.body}>Map and validate one customer-owned Gate around one typed partner action. The public pilot remains synthetic and read-only; production is separately scoped after buyer acceptance.</p>
          <ul style={{ ...styles.list, marginTop: 16 }}>
            <li>Define one bounded operating allowance</li>
            <li>Pin one external policy or risk decision source</li>
            <li>Require human interruption above an agreed threshold</li>
            <li>Measure refused, admitted, and indeterminate transactions without exposing payment details</li>
          </ul>
          <div style={{ marginTop: 24 }}>
            <a href="/pilot?v=fin" className="ep-cta" style={cta.primaryBlue}>Scope the protected-workflow pilot</a>
          </div>
        </div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
