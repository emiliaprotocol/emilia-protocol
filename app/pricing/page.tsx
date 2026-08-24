import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { GATE_IMPLEMENTATION, GATE_QUALIFICATION, PRODUCTION_GATE, PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'EMILIA Gate Pricing',
  description:
    'Use the open EMILIA Protocol for free, run one fixed 90-day protected-workflow pilot, and scope customer-specific Gate enforcement with optional qualification and reliance-risk controls.',
  alternates: { canonical: '/pricing' },
  openGraph: {
    title: 'EMILIA Gate Pricing',
    description: 'Open verification infrastructure, one $25K protected-workflow pilot, customer-specific Gate implementation, and deployment-scoped enforcement, reconciliation, and evidence operations.',
    url: 'https://www.emiliaprotocol.ai/pricing',
    type: 'website',
    images: ['/og-sequence.jpg'],
  },
};

const C = ({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }): React.ReactElement => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 clamp(20px, 6vw, 32px)', ...style }}>{children}</div>
);

const TIERS: Array<{
  name: string;
  price: string;
  priceNote: string;
  priceIsLabel?: boolean;
  tagline: string;
  accent: string;
  cta: { label: string; href: string };
  ctaStyle: 'primary' | 'secondary';
  highlight: boolean;
  available: boolean;
  features: string[];
}> = [
  {
    name: 'Open Protocol',
    price: '$0',
    priceNote: 'Apache 2.0 · self-operated',
    priceIsLabel: false,
    tagline: 'Build and verify under your own keys when your team wants to operate the trust boundary itself.',
    accent: color.green,
    cta: { label: 'Read the protocol docs', href: '/protocol' },
    ctaStyle: 'secondary' as const,
    highlight: false,
    available: true,
    features: [
      'Open authorization-evidence formats and Gate runtime',
      'TypeScript, Python, and Go verification packages',
      'Public conformance vectors and security case',
      `${GATE_QUALIFICATION.name} formats and verifier`,
      'MCP and SDK integration packages',
      'Self-hosted under your own trust policy',
      'Community support; your team operates policy and evidence',
    ],
  },
  {
    name: PROTECTED_WORKFLOW_PILOT.name,
    price: PROTECTED_WORKFLOW_PILOT.shortPriceLabel,
    priceNote: `fixed scope · ${PROTECTED_WORKFLOW_PILOT.durationLabel}`,
    priceIsLabel: false,
    tagline: 'Evaluate and design one buyer-selected consequence boundary in synthetic, read-only, sandbox, or shadow mode. Production activation is scoped separately.',
    accent: color.blue,
    cta: { label: 'Scope the pilot', href: '/pilot' },
    ctaStyle: 'primary' as const,
    highlight: true,
    available: true,
    features: [
      PROTECTED_WORKFLOW_PILOT.workflowLabel,
      `First profile: ${PROTECTED_WORKFLOW_PILOT.firstProfileLabel}`,
      PROTECTED_WORKFLOW_PILOT.safetyRuleLabel,
      PROTECTED_WORKFLOW_PILOT.eligibilityLabel,
      'Synthetic replay and governed read-only validation',
      'Production decision packet and draft Gate Implementation SOW',
      'No production actuation or provider credential custody in the pilot',
      'Action Control Manifest and acceptance test plan',
    ],
  },
  {
    name: GATE_IMPLEMENTATION.name,
    price: GATE_IMPLEMENTATION.priceLabel,
    priceNote: GATE_IMPLEMENTATION.scopeLabel,
    priceIsLabel: true,
    tagline: 'Turn the selected risk area into a fail-closed prospective control, with optional qualification and reliance-risk policy at the real executor boundary.',
    accent: color.blue,
    cta: { label: 'Design the Gate', href: '/pilot' },
    ctaStyle: 'secondary' as const,
    highlight: false,
    available: true,
    features: [
      'System-of-record action and route binding',
      'Receipt Required challenge and approval acquisition',
      'Exact-action verification and one-time consumption',
      `Optional qualification for ${GATE_QUALIFICATION.scopeLabel}`,
      'Customer-owned Reliance Program and separately signed loss-schedule policy',
      'Open-exposure ceilings, no-blind-replay handling, and independent reconciliation',
      'Technical-refusal, population-reconciliation, receipt-census, and loss-feed artifacts',
      'Customer acceptance vectors and production runbook',
    ],
  },
  {
    name: PRODUCTION_GATE.name,
    price: PRODUCTION_GATE.priceLabel,
    priceNote: PRODUCTION_GATE.scopeLabel,
    priceIsLabel: true,
    tagline: `Operate policy, approval, consumption, reconciliation, and evidence inside one contracted deployment. ${PRODUCTION_GATE.availabilityLabel}.`,
    accent: color.gold,
    cta: { label: 'Scope a deployment', href: '/partners' },
    ctaStyle: 'secondary' as const,
    highlight: false,
    available: false,
    features: [
      'Everything accepted in the Gate implementation',
      'Private cloud, VPC, or self-hosted deployment options',
      'SAML/OIDC identity and SCIM provisioning integration',
      'Durable consumption, open-exposure, reconciliation, dispute, and remedy operations',
      'Evidence retention, export, observability, and SIEM integration',
      'Negotiated support and service-level terms, subject to a separately approved contract',
    ],
  },
];

// Honest open-core line: what the free protocol gives you vs. what the paid plane adds.
const OPEN_CORE = [
  ['Verify receipts under your own pinned trust policy', true, true, true, true],
  ['Use public formats, packages, and conformance vectors', true, true, true, true],
  ['Carry accepted evaluation evidence as a time-bounded qualification', true, false, true, true],
  ['Retrospective workflow diagnosis and source-linked cases', false, true, true, true],
  ['Prospective executor-bound enforcement', false, false, true, true],
  ['Managed production evidence and service operations', false, false, false, true],
];

const PACKS = [
  { name: 'Government profile', body: 'Evidence requirements for configured public-sector determinations and caseworker approvals.', href: '/govguard' },
  { name: 'Financial profile', body: 'Policy and evidence adapters for configured money-movement and treasury actions.', href: '/finguard' },
  { name: 'Energy profile', body: 'GRACE composes authorization evidence with action and measurement records at energy-control boundaries.', href: '/grace' },
  { name: 'Multi-party profile', body: 'Distinct-human, initiator-excluded quorum evidence for actions that require more than one approval.', href: '/quorum' },
];

function Check({ on }: { on: boolean | unknown }): React.ReactElement {
  return (
    <span style={{ color: on ? color.t1 : color.t2, fontFamily: font.mono, fontSize: 10, fontWeight: on ? 700 : 500 }}>
      {on ? 'Included' : 'Not included'}
    </span>
  );
}

export default function PricingPage(): React.ReactElement {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="Pricing" />
      <main>

      {/* HERO */}
      <section style={{ paddingTop: 120, paddingBottom: 56 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.goldDark, marginBottom: 24 }}>
            Pricing
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(38px, 5vw, 64px)', letterSpacing: -2.2, lineHeight: 1.0, color: color.t1, margin: '0 0 24px', maxWidth: 780 }}>
            Diagnose the past. Protect the next effect. Operate the boundary.
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 620, lineHeight: 1.7, margin: 0 }}>
            The open protocol is free. The one public pilot is {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} for{' '}
            {PROTECTED_WORKFLOW_PILOT.durationLabel} and {PROTECTED_WORKFLOW_PILOT.workflowLabel}. Gate Qualification
            can carry accepted evaluation evidence into that decision when needed. It is not identity, certification,
            or authority. Implementation is scoped; Operated Gate is quoted only for a customer-specific deployment.
          </p>
          <p style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 600, color: color.goldDark, lineHeight: 1.65, margin: '18px 0 0' }}>
            {GATE_QUALIFICATION.boundaryLine}
          </p>
        </C>
      </section>

      {/* FOUR DOORS */}
      <section style={{ paddingBottom: 80 }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, alignItems: 'stretch' }}>
            {TIERS.map((t) => (
              <div key={t.name} style={{
                display: 'flex', flexDirection: 'column',
                background: t.highlight ? color.card : color.card,
                border: `1px solid ${t.highlight ? color.gold : color.border}`,
                borderTop: `3px solid ${t.accent}`,
                borderRadius: radius.base,
                padding: '32px 28px',
                boxShadow: t.highlight ? '0 8px 30px rgba(176,141,53,0.10)' : 'none',
              }}>
                <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 18, color: color.t1, marginBottom: 8 }}>{t.name}</div>
                {!t.available && (
                  <div style={{
                    alignSelf: 'flex-start',
                    marginBottom: 12,
                    padding: '5px 8px',
                    border: `1px solid ${color.gold}`,
                    borderRadius: radius.sm,
                    color: color.t2,
                    fontFamily: font.mono,
                    fontSize: 10,
                    fontWeight: 600,
                    letterSpacing: 0.7,
                    textTransform: 'uppercase',
                  }}>
                    Not generally available
                  </div>
                )}
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontFamily: font.sans, fontWeight: 700, fontSize: t.priceIsLabel ? 19 : 28, letterSpacing: t.priceIsLabel ? 0 : -1, color: t.priceIsLabel ? color.t2 : color.t1 }}>{t.price}</span>
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 0.5, textTransform: 'uppercase', color: color.t3, marginBottom: 16 }}>{t.priceNote}</div>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginBottom: 22 }}>{t.tagline}</p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 11, marginBottom: 28 }}>
                  {t.features.map((f) => (
                    <div key={f} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                      <span style={{ color: t.accent, fontSize: 13, marginTop: 1, flexShrink: 0 }}>&#10003;</span>
                      <span style={{ fontSize: 13, color: color.t2, lineHeight: 1.5 }}>{f}</span>
                    </div>
                  ))}
                </div>
                {/* CTA pinned to the card bottom so all three align regardless of tagline/feature length */}
                {t.cta.href.startsWith('http') ? (
                  <a
                    href={t.cta.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={t.ctaStyle === 'primary' ? 'ep-cta' : 'ep-cta-secondary'}
                    style={{ ...(t.ctaStyle === 'primary' ? cta.primary : cta.secondary), boxSizing: 'border-box', justifyContent: 'center', width: '100%', marginTop: 'auto' }}
                  >
                    {t.cta.label}
                  </a>
                ) : (
                  <Link
                    href={t.cta.href}
                    className={t.ctaStyle === 'primary' ? 'ep-cta' : 'ep-cta-secondary'}
                    style={{ ...(t.ctaStyle === 'primary' ? cta.primary : cta.secondary), boxSizing: 'border-box', justifyContent: 'center', width: '100%', marginTop: 'auto' }}
                  >
                    {t.cta.label}
                  </Link>
                )}
              </div>
            ))}
          </div>
          <p style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, letterSpacing: 0.3, marginTop: 20, lineHeight: 1.6 }}>
            No seat tax and no generic API-call bundle. Production pricing follows the number and risk of protected
            workflows, the deployment boundary, evidence retention, integrations, and service level.
            {' '}<Link href="/pilot/sandbox" style={{ color: color.goldDark }}>Run the free sandbox first &rarr;</Link>
          </p>
          <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, maxWidth: 760, marginTop: 18 }}>
            <strong style={{ color: color.t1 }}>{GATE_QUALIFICATION.name} is an open entry path, not a pricing or certification tier.</strong>{' '}
            It carries {GATE_QUALIFICATION.outcomeLabel} into a Gate implementation when the protected
            workflow requires evaluated-candidate evidence. {GATE_QUALIFICATION.disclaimer}
          </p>
          <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, maxWidth: 820, marginTop: 14 }}>
            <strong style={{ color: color.t1 }}>Reliance Risk Plane scope is also deployment-specific.</strong>{' '}
            EMILIA can verify customer-supplied loss terms, reserve declared open exposure, and emit
            bounded risk evidence. EMILIA does not insure, bear or allocate loss, adjudicate disputes
            or losses, prove coverage, causation, solvency, or population completeness, or move money.{' '}
            <Link href="/gate#reliance-risk-plane" style={{ color: color.goldDark }}>See the shipped boundary &rarr;</Link>
          </p>
        </C>
      </section>

      {/* START WITH THE CANONICAL PILOT — the commercial front door */}
      <section style={{ padding: '76px 0', background: '#1C1917', borderTop: `3px solid ${color.gold}` }}>
        <C>
          <div style={{ maxWidth: 720 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
              Start here &middot; one protected workflow
            </div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3.2vw, 42px)', letterSpacing: -1.4, lineHeight: 1.08, color: '#FAFAF9', marginBottom: 18 }}>
              Design one real consequence boundary in 90 days.
            </h2>
            <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.72)', lineHeight: 1.7, marginBottom: 30, maxWidth: 620 }}>
              The first profile is {PROTECTED_WORKFLOW_PILOT.firstProfileLabel.toLowerCase()}:{' '}
              {PROTECTED_WORKFLOW_PILOT.safetyRuleLabel.toLowerCase()}. Missing, stale, exhausted, invalid, or mismatched
              authority does not admit provider entry on a completely mediated covered path. Gate does not prove bank-detail
              correctness, payee identity, fraud absence, or provider success. Other consequential workflows remain eligible.
              The pilot stays synthetic, read-only, sandbox, or shadow only. It
              ends with a production decision packet and draft SOW; production
              activation is a separately scoped Gate Implementation.
            </p>
            <div style={{ display: 'flex', gap: 36, flexWrap: 'wrap', marginBottom: 32 }}>
              {[[PROTECTED_WORKFLOW_PILOT.shortPriceLabel, 'fixed, scoped engagement'], [PROTECTED_WORKFLOW_PILOT.durationLabel, 'nonproduction pilot only'], [PROTECTED_WORKFLOW_PILOT.workflowLabel, 'buyer-selected consequence boundary']].map(([n, l]) => (
                <div key={n}>
                  <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 26, letterSpacing: -1, color: '#FAFAF9' }}>{n}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 0.4, color: 'rgba(250,250,249,0.55)' }}>{l}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/pilot" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: '#1C1917' }}>Scope the protected-workflow pilot &rarr;</Link>
              <Link href="/arena" className="ep-cta-secondary" style={{ ...cta.secondary, color: 'rgba(250,250,249,0.8)', borderColor: 'rgba(255,255,255,0.15)' }}>Create a factual synthetic record</Link>
            </div>
          </div>
        </C>
      </section>

      {/* OPEN-CORE LINE */}
      <section style={{ padding: '80px 0', background: 'rgba(245,244,240,0.45)', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.goldDark, marginBottom: 16 }}>
            Open verification, paid operation
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 520, marginBottom: 36 }}>
            Protocol proves. Gate prevents.
          </h2>
          <div className="ep-pricing-table" style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, overflowX: 'auto' }}>
            <table style={{ width: '100%', minWidth: 650, borderCollapse: 'collapse' }}>
              <caption style={{ position: 'absolute', width: 1, height: 1, padding: 0, margin: -1, overflow: 'hidden', clip: 'rect(0, 0, 0, 0)', whiteSpace: 'nowrap', border: 0 }}>
                Capabilities included in the Open, Diagnose, Implement, and Operate stages
              </caption>
              <thead>
                <tr style={{ background: 'rgba(245,244,240,0.6)' }}>
                  <th scope="col" style={{ width: '45%', padding: '14px 24px', borderBottom: `1px solid ${color.borderHover}`, fontFamily: font.mono, fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: color.t1, fontWeight: 700, textAlign: 'left' }}>Capability</th>
                  {['Open', 'Diagnose', 'Implement', 'Operate'].map((heading) => (
                    <th key={heading} scope="col" style={{ width: '13.75%', padding: '14px 8px', borderBottom: `1px solid ${color.borderHover}`, fontFamily: font.mono, fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: color.t1, fontWeight: 700, textAlign: 'center' }}>{heading}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {OPEN_CORE.map((row, index) => (
                  <tr key={String(row[0])}>
                    <th scope="row" style={{ padding: '16px 24px', borderBottom: index < OPEN_CORE.length - 1 ? `1px solid ${color.border}` : 'none', fontSize: 14, color: color.t2, fontWeight: 400, textAlign: 'left' }}>{row[0]}</th>
                    {row.slice(1).map((included, cellIndex) => (
                      <td key={cellIndex} style={{ padding: '16px 8px', borderBottom: index < OPEN_CORE.length - 1 ? `1px solid ${color.border}` : 'none', textAlign: 'center' }}>
                        <Check on={included} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </C>
      </section>

      {/* ASSURANCE SERVICES */}
      <section style={{ padding: '80px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
            <div className="ep-pricing-assurance-grid" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.1fr) minmax(280px, 0.9fr)', gap: 48, alignItems: 'start' }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.goldDark, marginBottom: 16 }}>
                Assurance services
              </div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 620, marginBottom: 16 }}>
                Claim-to-Consequence Assurance is the family. Its Assurance Plane is the service layer.
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, maxWidth: 640, marginBottom: 28 }}>
                Verification remains open and reproducible. Paid engagements help teams operate repeatable
                re-performance, maintain conformance records and continuous evidence, and prepare bounded packages
                for auditors and underwriters. EMILIA does not issue audit opinions or accredited certifications.
              </p>
              <Link href="/assurance" className="ep-cta-secondary" style={cta.secondary}>Explore Claim-to-Consequence Assurance &rarr;</Link>
            </div>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '26px 28px' }}>
              {[
                'Managed evidence re-performance',
                'Conformance records tied to public vectors',
                'Continuous evidence and drift review',
                'Audit and underwriter package preparation',
              ].map((item) => (
                <div key={item} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '10px 0', borderBottom: `1px solid ${color.border}` }}>
                  <span style={{ color: color.green, fontWeight: 700 }}>&#10003;</span>
                  <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.55 }}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </C>
      </section>

      {/* SOLUTION PROFILES */}
      <section style={{ padding: '80px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.goldDark, marginBottom: 16 }}>
            Gate solution profiles
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 560, marginBottom: 16 }}>
            One product, adapted to different consequence boundaries.
          </h2>
          <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, maxWidth: 600, marginBottom: 36 }}>
            These profiles package action schemas, policy templates, and integration guidance around Gate. They are
            not separate products, and they do not by themselves establish legal compliance.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
            {PACKS.map((p) => (
              <Link key={p.name} href={p.href} className="ep-card-lift" style={{ display: 'block', background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '24px 26px', textDecoration: 'none' }}>
                <div style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, color: color.t1, marginBottom: 8 }}>{p.name}</div>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.6, margin: 0 }}>{p.body}</p>
              </Link>
            ))}
          </div>
        </C>
      </section>

      {/* CTA */}
      <section style={{ padding: '88px 0' }}>
        <C>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 32, flexWrap: 'wrap' }}>
            <div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 3vw, 38px)', letterSpacing: -1.2, lineHeight: 1.1, color: color.t1, marginBottom: 10 }}>
                Start with one consequential workflow.
              </h2>
              <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.6, maxWidth: 440, margin: 0 }}>
                Begin with the canonical 90-day pilot, or use the open MCP path to protect one configured tool yourself.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/mcp" className="ep-cta" style={cta.primary}>Protect an MCP tool &rarr;</Link>
              <Link href="/pilot" className="ep-cta-secondary" style={cta.secondary}>Scope a pilot</Link>
              <Link href="/assurance" className="ep-cta-secondary" style={cta.secondary}>Re-perform evidence</Link>
            </div>
          </div>
        </C>
      </section>

      </main>
      <SiteFooter />
    </div>
  );
}
