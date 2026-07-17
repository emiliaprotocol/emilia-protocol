import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'EMILIA Gate Pricing',
  description:
    'Keep EMILIA Protocol open and reproducible. Add EMILIA Gate Cloud or Enterprise for managed enforcement, evidence operations, and private deployment.',
  alternates: { canonical: '/pricing' },
  openGraph: {
    title: 'EMILIA Gate Pricing',
    description: 'Open proof infrastructure, with paid Gate operations and Assurance services.',
    url: 'https://www.emiliaprotocol.ai/pricing',
    type: 'website',
  },
};

const C = ({ children, style }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

// EP Cloud "Subscribe" activates the moment a payment link is set in env
// (see docs/STRIPE_SETUP.md). Until then the CTA falls back to early-access.
const CLOUD_CHECKOUT = process.env.NEXT_PUBLIC_STRIPE_CLOUD_TEAM || '';

const TIERS = [
  {
    name: 'Open Protocol',
    price: 'Free',
    priceNote: 'Apache 2.0 · forever',
    tagline: 'Use the public receipt formats, verifiers, conformance vectors, and integration packages under your own keys.',
    accent: color.green,
    cta: { label: 'Read the protocol docs', href: '/protocol' },
    ctaStyle: 'secondary',
    highlight: false,
    available: true,
    features: [
      'Open authorization-evidence formats',
      'JavaScript, Python, Go, and external Rust verification evidence',
      'Public conformance vectors and security case',
      'MCP and SDK integration packages',
      'Self-hosted under your own trust policy',
      'Offline, issuer-independent verification where the profile permits',
    ],
  },
  {
    name: 'Gate Cloud',
    price: '$499',
    priceNote: 'per month · early access',
    tagline: 'Managed consequence-firewall operations for teams that want to protect configured actions without running the control plane.',
    accent: color.blue,
    cta: CLOUD_CHECKOUT
      ? { label: 'Subscribe', href: CLOUD_CHECKOUT }
      : { label: 'Get started', href: '/signup' },
    ctaStyle: 'primary',
    available: true,
    features: [
      'Everything in the open Protocol',
      'Managed Gate policy and enforcement service',
      'Approver routing and escalation workflows',
      'Evidence retention, export, and observability',
      'Webhooks and integration support',
      'Tenant-isolated hosted operation',
    ],
  },
  {
    name: 'Gate Enterprise',
    price: 'Custom',
    priceNote: 'annual · scoped deployment',
    tagline: 'Private deployment, identity integration, solution profiles, and operational support at the protected system boundary.',
    accent: color.gold,
    cta: { label: 'Talk to us', href: '/partners' },
    ctaStyle: 'secondary',
    available: true,
    features: [
      'Everything in Gate Cloud',
      'Private cloud, VPC, or self-hosted deployment options',
      'SAML/OIDC identity and SCIM provisioning integration',
      'Government, financial, energy, and multi-party profiles',
      'Procurement and security-review evidence support',
      'Priority integration support and negotiated service levels',
    ],
  },
];

// Honest open-core line: what the free protocol gives you vs. what the paid plane adds.
const OPEN_CORE = [
  ['Verify receipts under your own pinned trust policy', true, true, true],
  ['Use public formats, packages, and conformance vectors', true, true, true],
  ['Managed Gate policy and enforcement operations', false, true, true],
  ['Hosted approver routing and continuous evidence', false, true, true],
  ['Private deployment, identity integration, profiles, and SLA', false, false, true],
];

const PACKS = [
  { name: 'Government profile', body: 'Evidence requirements for configured public-sector determinations and caseworker approvals.', href: '/govguard' },
  { name: 'Financial profile', body: 'Policy and evidence adapters for configured money-movement and treasury actions.', href: '/finguard' },
  { name: 'Energy profile', body: 'GRACE composes authorization evidence with action and measurement records at energy-control boundaries.', href: '/grace' },
  { name: 'Multi-party profile', body: 'Distinct-human, initiator-excluded quorum evidence for actions that require more than one approval.', href: '/quorum' },
];

function Check({ on, accent }) {
  return on ? (
    <span style={{ color: accent, fontWeight: 700 }}>&#10003;</span>
  ) : (
    <span style={{ color: color.border }}>&mdash;</span>
  );
}

export default function PricingPage() {
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
            The Protocol is open. Gate is the product.
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 620, lineHeight: 1.7, margin: 0 }}>
            Anyone can run EMILIA verification under their own pinned inputs. Customers pay for Gate to mediate
            configured consequential actions, operate the approval workflow, and preserve decision evidence at the real system boundary.
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
            The Protocol is open today. Gate Cloud is in early access, and Gate Enterprise is scoped around the
            protected actions, deployment boundary, and operating requirements.
            {' '}<Link href="/signup" style={{ color: color.gold }}>Or grab a free sandbox key &rarr;</Link>
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
              One high-risk workflow, 60 days, nothing blocked. EMILIA runs in observe mode and hands you the
              evidence packet &mdash; the receipts that would have been required, and the actions that had no
              verifiable human behind them. It&rsquo;s the fastest way to put a real receipt in front of your own auditor.
            </p>
            <div style={{ display: 'flex', gap: 36, flexWrap: 'wrap', marginBottom: 32 }}>
              {[['$25K', 'scoped departmental pilot'], ['60 days', 'observe mode, zero blocking'], ['1 workflow', 'you pick the riskiest one']].map(([n, l]) => (
                <div key={n}>
                  <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 26, letterSpacing: -1, color: '#FAFAF9' }}>{n}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 0.4, color: 'rgba(250,250,249,0.55)' }}>{l}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/pilot" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: '#1C1917' }}>Scope a 60-day pilot &rarr;</Link>
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
              {['Protocol', 'Gate Cloud', 'Gate Enterprise'].map((h) => (
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
