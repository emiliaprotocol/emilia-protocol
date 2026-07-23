import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { MANAGED_PILOT, PRODUCTION_GATE } from '@/lib/commercial-offer';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'EMILIA Gate Pricing',
  description:
    'Use the open EMILIA Protocol for free, prove one protected workflow in a fixed-scope pilot, then price production Gate operations around the boundary you protect.',
  alternates: { canonical: '/pricing' },
  openGraph: {
    title: 'EMILIA Gate Pricing',
    description: 'Open proof infrastructure, a fixed-scope managed pilot, and production Gate operations priced by protected workflow.',
    url: 'https://www.emiliaprotocol.ai/pricing',
    type: 'website',
  },
};

const C = ({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }): React.ReactElement => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
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
      'MCP and SDK integration packages',
      'Self-hosted under your own trust policy',
      'Community support; your team operates policy and evidence',
    ],
  },
  {
    name: MANAGED_PILOT.name,
    price: MANAGED_PILOT.shortPriceLabel,
    priceNote: `fixed scope · ${MANAGED_PILOT.durationLabel}`,
    priceIsLabel: false,
    tagline: 'Prove Gate on one consequential workflow before committing to a production rollout.',
    accent: color.blue,
    cta: { label: 'Scope the pilot', href: '/pilot' },
    ctaStyle: 'primary' as const,
    highlight: true,
    available: true,
    features: [
      MANAGED_PILOT.workflowLabel,
      'Observe-mode baseline and risk inventory',
      'Action, evidence, approval, and escalation policy',
      'Customer-approved enforcement rollout',
      'Failure, reconciliation, and remedy-control drill',
      'Auditor-ready evidence package and findings review',
      'Production architecture and commercial recommendation',
    ],
  },
  {
    name: PRODUCTION_GATE.name,
    price: PRODUCTION_GATE.priceLabel,
    priceNote: 'quoted by protected workflow and operating boundary',
    priceIsLabel: true,
    tagline: 'Managed policy, approval, consumption, and evidence operations for consequential workflows in production.',
    accent: color.gold,
    cta: { label: 'Talk to us', href: '/partners' },
    ctaStyle: 'secondary' as const,
    highlight: false,
    available: true,
    features: [
      'Everything proven in the managed pilot',
      'Private cloud, VPC, or self-hosted deployment options',
      'SAML/OIDC identity and SCIM provisioning integration',
      'Durable consumption, reconciliation, dispute, and remedy operations',
      'Evidence retention, export, observability, and SIEM integration',
      'Negotiated support, service level, and deployment warranty',
    ],
  },
];

// Honest open-core line: what the free protocol gives you vs. what the paid plane adds.
const OPEN_CORE = [
  ['Verify receipts under your own pinned trust policy', true, true, true],
  ['Use public formats, packages, and conformance vectors', true, true, true],
  ['Managed workflow mapping and evidence policy', false, true, true],
  ['Observe-first rollout with customer-approved enforcement', false, true, true],
  ['Ongoing approver routing and continuous evidence', false, false, true],
  ['Private deployment, identity integration, profiles, and SLA', false, false, true],
];

const PACKS = [
  { name: 'Government profile', body: 'Evidence requirements for configured public-sector determinations and caseworker approvals.', href: '/govguard' },
  { name: 'Financial profile', body: 'Policy and evidence adapters for configured money-movement and treasury actions.', href: '/finguard' },
  { name: 'Energy profile', body: 'GRACE composes authorization evidence with action and measurement records at energy-control boundaries.', href: '/grace' },
  { name: 'Multi-party profile', body: 'Distinct-human, initiator-excluded quorum evidence for actions that require more than one approval.', href: '/quorum' },
];

function Check({ on, accent }: { on: boolean | unknown; accent: string }): React.ReactElement {
  return on ? (
    <span style={{ color: accent, fontWeight: 700 }}>&#10003;</span>
  ) : (
    <span style={{ color: color.border }}>&mdash;</span>
  );
}

export default function PricingPage(): React.ReactElement {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="Pricing" />

      {/* HERO */}
      <section style={{ paddingTop: 120, paddingBottom: 56 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>
            Pricing
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(38px, 5vw, 64px)', letterSpacing: -2.2, lineHeight: 1.0, color: color.t1, margin: '0 0 24px', maxWidth: 780 }}>
            Start open. Prove one workflow. Scale the boundary.
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 620, lineHeight: 1.7, margin: 0 }}>
            The protocol and self-operated runtime are free. The paid product begins when EMILIA maps, operates,
            and stands behind a protected workflow at your real system boundary.
          </p>
        </C>
      </section>

      {/* THREE DOORS */}
      <section style={{ paddingBottom: 80 }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, alignItems: 'stretch' }}>
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
                    style={{ ...(t.ctaStyle === 'primary' ? cta.primary : cta.secondary), justifyContent: 'center', width: '100%', marginTop: 'auto' }}
                  >
                    {t.cta.label}
                  </a>
                ) : (
                  <Link
                    href={t.cta.href}
                    className={t.ctaStyle === 'primary' ? 'ep-cta' : 'ep-cta-secondary'}
                    style={{ ...(t.ctaStyle === 'primary' ? cta.primary : cta.secondary), justifyContent: 'center', width: '100%', marginTop: 'auto' }}
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
            {' '}<Link href="/pilot/sandbox" style={{ color: color.gold }}>Run the free sandbox first &rarr;</Link>
          </p>
        </C>
      </section>

      {/* START WITH A PILOT — the commercial front door */}
      <section style={{ padding: '76px 0', background: '#1C1917', borderTop: `3px solid ${color.gold}` }}>
        <C>
          <div style={{ maxWidth: 720 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
              Start here &middot; observe-mode pilot
            </div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3.2vw, 42px)', letterSpacing: -1.4, lineHeight: 1.08, color: '#FAFAF9', marginBottom: 18 }}>
              Most teams start with a pilot, not a plan.
            </h2>
            <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.72)', lineHeight: 1.7, marginBottom: 30, maxWidth: 620 }}>
              One high-risk workflow over {MANAGED_PILOT.durationLabel}. We begin in observe mode, configure the
              evidence and approval policy, and enable enforcement only after your team approves it. You finish with
              a working control, an evidence package, and a decision-ready production plan.
            </p>
            <div style={{ display: 'flex', gap: 36, flexWrap: 'wrap', marginBottom: 32 }}>
              {[[MANAGED_PILOT.shortPriceLabel, 'fixed, scoped engagement'], [MANAGED_PILOT.durationLabel, 'observe, configure, then enforce'], [MANAGED_PILOT.workflowLabel, 'you pick the riskiest one']].map(([n, l]) => (
                <div key={n}>
                  <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 26, letterSpacing: -1, color: '#FAFAF9' }}>{n}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 0.4, color: 'rgba(250,250,249,0.55)' }}>{l}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/pilot" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: '#1C1917' }}>Scope the managed pilot &rarr;</Link>
              <Link href="/pilot/sandbox" className="ep-cta-secondary" style={{ ...cta.secondary, color: 'rgba(250,250,249,0.8)', borderColor: 'rgba(255,255,255,0.15)' }}>Run the sandbox yourself</Link>
            </div>
          </div>
        </C>
      </section>

      {/* OPEN-CORE LINE */}
      <section style={{ padding: '80px 0', background: 'rgba(245,244,240,0.45)', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
            Open verification, paid operation
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 520, marginBottom: 36 }}>
            Protocol proves. Gate prevents.
          </h2>
          <div className="ep-pricing-table" style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, overflowX: 'auto' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px 120px 120px', alignItems: 'center', padding: '14px 24px', borderBottom: `1px solid ${color.borderHover}`, background: 'rgba(245,244,240,0.6)' }}>
              <span style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: color.t1, fontWeight: 700 }}>Capability</span>
              {['Open', 'Pilot', 'Production'].map((h) => (
                <span key={h} style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: color.t1, fontWeight: 700, textAlign: 'center' }}>{h}</span>
              ))}
            </div>
            {OPEN_CORE.map((row, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 120px 120px 120px', alignItems: 'center', padding: '16px 24px', borderBottom: i < OPEN_CORE.length - 1 ? `1px solid ${color.border}` : 'none' }}>
                <span style={{ fontSize: 14, color: color.t2 }}>{row[0]}</span>
                <span style={{ textAlign: 'center' }}><Check on={row[1]} accent={color.green} /></span>
                <span style={{ textAlign: 'center' }}><Check on={row[2]} accent={color.blue} /></span>
                <span style={{ textAlign: 'center' }}><Check on={row[3]} accent={color.gold} /></span>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* ASSURANCE SERVICES */}
      <section style={{ padding: '80px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
            <div className="ep-pricing-assurance-grid" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.1fr) minmax(280px, 0.9fr)', gap: 48, alignItems: 'start' }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                Assurance services
              </div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 620, marginBottom: 16 }}>
                Assurance is a service layer, not a proprietary verdict.
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, maxWidth: 640, marginBottom: 28 }}>
                Verification remains open and reproducible. Paid engagements help teams operate repeatable
                re-performance, maintain conformance records and continuous evidence, and prepare bounded packages
                for auditors and underwriters. EMILIA does not issue audit opinions or accredited certifications.
              </p>
              <Link href="/assurance" className="ep-cta-secondary" style={cta.secondary}>Explore the Assurance Plane &rarr;</Link>
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
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
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
                Start with one protected action.
              </h2>
              <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.6, maxWidth: 440, margin: 0 }}>
                Put Gate immediately before one mutating system, require the evidence that matters, and measure the result.
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

      <SiteFooter />
    </div>
  );
}
