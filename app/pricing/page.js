import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Pricing — EMILIA Protocol',
  description:
    'Open-core pricing. EP Core is free and Apache 2.0 forever. EP Cloud is the managed '
    + 'control plane. EP Enterprise adds on-prem/VPC/air-gapped deployment, SAML/OIDC SSO + SCIM, sector packs, audit support, and SLAs.',
  alternates: { canonical: '/pricing' },
  openGraph: {
    title: 'EMILIA Protocol — Pricing',
    description: 'The protocol is free forever. Pay for the hosted control plane and enterprise assurance.',
    url: 'https://www.emiliaprotocol.ai/pricing',
    type: 'website',
  },
  keywords: ['EMILIA Protocol pricing', 'AI agent authorization pricing', 'trust layer pricing', 'open core'],
};

const C = ({ children, style }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

// EP Cloud "Subscribe" activates the moment a payment link is set in env
// (see docs/STRIPE_SETUP.md). Until then the CTA falls back to early-access.
const CLOUD_CHECKOUT = process.env.NEXT_PUBLIC_STRIPE_CLOUD_TEAM || '';

const TIERS = [
  {
    name: 'EP Core',
    price: 'Free',
    priceNote: 'Apache 2.0 · forever',
    tagline: 'Self-host the open protocol. Everything you need to gate, sign, and verify.',
    accent: color.green,
    cta: { label: 'Start free', href: '/docs' },
    ctaStyle: 'secondary',
    available: true,
    features: [
      'Full trust ceremony — Eye, Handshake, Signoff, Commit',
      '@emilia-protocol/sdk + @emilia-protocol/verify (npm)',
      'Native MCP server — 36 tools',
      'Authorization receipts — signed, Merkle-anchored, verifiable offline',
      'Agent Guard middleware — framework-agnostic',
      '26 TLA+ theorems · 35 Alloy facts · 85 red-team cases',
      'Self-hosted; your keys, your infrastructure',
    ],
  },
  {
    name: 'EP Cloud',
    price: 'Early access',
    priceNote: 'billing opens with our first cohort',
    tagline: 'Hosted control plane — policy management, signoff orchestration, and audit without running infrastructure.',
    accent: color.blue,
    cta: CLOUD_CHECKOUT
      ? { label: 'Subscribe', href: CLOUD_CHECKOUT }
      : { label: 'Request early access', href: '/product/cloud#pilot' },
    ctaStyle: 'primary',
    highlight: true,
    available: false,
    features: [
      'Everything in Core, fully managed',
      'Managed policy registry — version, diff, simulate before deploy',
      'Hosted signoff orchestration + escalation routing',
      'Event explorer — every handshake, signoff, and commit',
      'Audit exports — auditor-grade evidence packages',
      'Webhooks + observability',
      'Multi-tenant isolation',
    ],
  },
  {
    name: 'EP Enterprise',
    price: 'Talk to us',
    priceNote: 'annual · sales-led',
    tagline: 'On-prem or private cloud, identity integration, and the assurance a bank or agency needs to clear you.',
    accent: color.gold,
    cta: { label: 'Talk to us', href: '/partners' },
    ctaStyle: 'secondary',
    available: true,
    features: [
      'Everything in Cloud',
      'Self-hosted, VPC, or air-gapped deployment (offline installer included)',
      'SSO (SAML 2.0 / OIDC) + SCIM 2.0 provisioning — live IdP connected at onboarding',
      'Sector packs — GovGuard, FinGuard, Agent Governance',
      'Security-review + procurement support (DPA, sub-processors)',
      'Compliance evidence mapping — NIST AI RMF, EU AI Act',
      'Priority support + SLA',
    ],
  },
];

// Honest open-core line: what the free protocol gives you vs. what the paid plane adds.
const OPEN_CORE = [
  ['Run the protocol + verify receipts', true, true, true],
  ['Agent Guard middleware + MCP server', true, true, true],
  ['Managed policy registry + simulation', false, true, true],
  ['Hosted signoff orchestration + audit exports', false, true, true],
  ['On-prem / VPC / air-gap, SSO + SCIM, sector packs, SLA', false, false, true],
];

const PACKS = [
  { name: 'Government Pack', body: 'Benefit-integrity controls — accountable determinations, due-process receipts, caseworker signoff.', href: '/product/government-pack' },
  { name: 'Financial Pack', body: 'Money-movement controls — wire release, beneficiary changes, treasury actions, BEC defense, AML screening.', href: '/product/financial-pack' },
  { name: 'Agent Governance Pack', body: 'Autonomous-agent controls — gate every irreversible tool call behind a verified ceremony.', href: '/product/agent-governance-pack' },
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
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(38px, 5vw, 64px)', letterSpacing: -2.2, lineHeight: 1.0, color: color.t1, margin: '0 0 24px', maxWidth: 760 }}>
            Trust infrastructure, priced like infrastructure.
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 600, lineHeight: 1.7, margin: 0 }}>
            Open core. The protocol is free and self-hostable forever &mdash; that&rsquo;s how a standard
            wins. You pay for the hosted control plane and the assurance enterprises require.
          </p>
        </C>
      </section>

      {/* THREE DOORS */}
      <section style={{ paddingBottom: 80 }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, alignItems: 'stretch' }}>
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
                  <span style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 28, letterSpacing: -1, color: color.t1 }}>{t.price}</span>
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 0.5, textTransform: 'uppercase', color: color.t3, marginBottom: 16 }}>{t.priceNote}</div>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginBottom: 22, minHeight: 64 }}>{t.tagline}</p>
                {t.cta.href.startsWith('http') ? (
                  <a
                    href={t.cta.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={t.ctaStyle === 'primary' ? 'ep-cta' : 'ep-cta-secondary'}
                    style={{ ...(t.ctaStyle === 'primary' ? cta.primary : cta.secondary), justifyContent: 'center', width: '100%', marginBottom: 24 }}
                  >
                    {t.cta.label}
                  </a>
                ) : (
                  <Link
                    href={t.cta.href}
                    className={t.ctaStyle === 'primary' ? 'ep-cta' : 'ep-cta-secondary'}
                    style={{ ...(t.ctaStyle === 'primary' ? cta.primary : cta.secondary), justifyContent: 'center', width: '100%', marginBottom: 24 }}
                  >
                    {t.cta.label}
                  </Link>
                )}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
                  {t.features.map((f) => (
                    <div key={f} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                      <span style={{ color: t.accent, fontSize: 13, marginTop: 1, flexShrink: 0 }}>&#10003;</span>
                      <span style={{ fontSize: 13, color: color.t2, lineHeight: 1.5 }}>{f}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <p style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, letterSpacing: 0.3, marginTop: 20, lineHeight: 1.6 }}>
            EP Core is live and free today. EP Cloud is in early access &mdash; metered billing opens with
            our first cohort; request access and we&rsquo;ll onboard you. Enterprise terms are annual and sales-led.
            {' '}<Link href="/signup" style={{ color: color.gold }}>Or grab a free sandbox key &rarr;</Link>
          </p>
        </C>
      </section>

      {/* OPEN-CORE LINE */}
      <section style={{ padding: '80px 0', background: 'rgba(245,244,240,0.45)', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
            What&rsquo;s free vs. paid
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 520, marginBottom: 36 }}>
            The line is drawn on purpose.
          </h2>
          <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px 120px 120px', alignItems: 'center', padding: '14px 24px', borderBottom: `1px solid ${color.borderHover}`, background: 'rgba(245,244,240,0.6)' }}>
              <span style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: color.t1, fontWeight: 700 }}>Capability</span>
              {['Core', 'Cloud', 'Enterprise'].map((h) => (
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

      {/* SECTOR PACKS */}
      <section style={{ padding: '80px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
            Sector packs
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 560, marginBottom: 16 }}>
            Whether it&rsquo;s money or someone&rsquo;s livelihood, the ceremony is the same.
          </h2>
          <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, maxWidth: 600, marginBottom: 36 }}>
            Pre-built policies, adapters, and compliance mappings for the two places a wrong agent
            action does the most damage. Available with Enterprise.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
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
                Start with the free protocol.
              </h2>
              <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.6, maxWidth: 440, margin: 0 }}>
                Gate your first irreversible action in an afternoon. Upgrade when you need the control plane.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/agent-guard" className="ep-cta" style={cta.primary}>Guard an agent &rarr;</Link>
              <Link href="/demo" className="ep-cta-secondary" style={cta.secondary}>See it live</Link>
            </div>
          </div>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
