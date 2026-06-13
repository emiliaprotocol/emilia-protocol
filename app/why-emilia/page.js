import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import EmailCapture from '@/components/EmailCapture';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Why EMILIA — vs. the controls you already have',
  description:
    'Identity, PAM, authorization governance, and 4-eyes workflows all check WHO is acting. '
    + 'EMILIA checks WHETHER THIS EXACT ACTION should happen — and binds an accountable human to '
    + 'it with cryptographic proof. How EMILIA complements Okta, CyberArk, Veza, and manual review.',
  alternates: { canonical: '/why-emilia' },
  openGraph: {
    title: 'Why EMILIA vs. legacy controls',
    description: 'Identity checks who. EMILIA checks whether this exact action should happen — and proves it.',
    url: 'https://www.emiliaprotocol.ai/why-emilia',
    type: 'website',
  },
  keywords: [
    'EMILIA vs Okta', 'EMILIA vs CyberArk', 'EMILIA vs Veza', 'pre-action authorization',
    'agent authorization vs IAM', 'human in the loop vs PAM',
  ],
};

const C = ({ children, style }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

const ROWS = [
  {
    cat: 'Identity & SSO',
    examples: 'Okta, Entra ID, Auth0',
    secures: 'Who is signed in. Authentication and session.',
    gap: 'A valid session says nothing about whether a specific action inside it should run. Fraud moves through authenticated users.',
  },
  {
    cat: 'Privileged Access (PAM)',
    examples: 'CyberArk, BeyondTrust',
    secures: 'Who holds elevated credentials, and vaulting/rotation.',
    gap: 'Grants standing access to systems. Once inside, the individual irreversible action is ungoverned.',
  },
  {
    cat: 'Authorization Governance',
    examples: 'Veza, Opal, SailPoint',
    secures: 'Who can access what, reviewed over time.',
    gap: 'Answers "is this permission appropriate?" — not "should this exact transfer happen right now, and who is accountable?"',
  },
  {
    cat: 'Agent Governance (emerging)',
    examples: 'HumanLayer, AgentAuth',
    secures: 'Human-in-the-loop approval for agent steps.',
    gap: 'Approval without a portable, formally verified, offline-verifiable proof leaves no durable evidence — and ties you to one vendor.',
  },
  {
    cat: 'Manual 4-eyes review',
    examples: 'Email, tickets, dual control',
    secures: 'A second human looks before high-risk actions.',
    gap: 'Not bound to the exact action hash, easy to socially engineer (BEC), slow, and unprovable after the fact.',
  },
];

const ADDS = [
  'Binds authorization to the exact action — actor, authority, policy, action context, nonce, expiry, one-time consumption.',
  'Requires a named, accountable human signoff where policy demands it — not a standing grant.',
  'Emits a signed, Merkle-anchored authorization receipt: portable, offline-verifiable evidence of who approved what.',
  'Vendor-neutral — it doesn’t matter whose model your agent runs on, or whose IdP you use.',
  'Formally verified — 26 TLA+ theorems and 35 Alloy facts machine-checked in CI on every change to the formal models.',
];

export default function WhyEmiliaPage() {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="" />

      {/* HERO */}
      <section style={{ paddingTop: 120, paddingBottom: 56 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>
            Why EMILIA
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(36px, 4.8vw, 60px)', letterSpacing: -2.2, lineHeight: 1.02, color: color.t1, margin: '0 0 24px', maxWidth: 820 }}>
            Your controls check <em style={{ fontStyle: 'normal', color: color.t3 }}>who</em>. EMILIA checks{' '}
            <em style={{ fontStyle: 'normal', color: color.gold }}>whether this exact action should happen.</em>
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 640, lineHeight: 1.7, margin: 0 }}>
            EMILIA isn&rsquo;t a replacement for your identity stack &mdash; it&rsquo;s the layer none of
            them cover: the pre-execution moment where an irreversible action either gets a signed,
            accountable yes, or it doesn&rsquo;t run.
          </p>
        </C>
      </section>

      {/* COMPARISON TABLE */}
      <section style={{ padding: '40px 0 80px' }}>
        <C>
          <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden' }}>
            {/* header */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.4fr 1.4fr', background: 'rgba(245,244,240,0.7)', borderBottom: `1px solid ${color.borderHover}` }}>
              {['Control category', 'What it secures', 'The gap for irreversible agent actions'].map((h) => (
                <div key={h} style={{ padding: '14px 20px', fontFamily: font.mono, fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', color: color.t1 }}>{h}</div>
              ))}
            </div>
            {ROWS.map((r, i) => (
              <div key={r.cat} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.4fr 1.4fr', borderBottom: i < ROWS.length - 1 ? `1px solid ${color.border}` : 'none' }}>
                <div style={{ padding: '20px', borderRight: `1px solid ${color.border}` }}>
                  <div style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, color: color.t1, marginBottom: 4 }}>{r.cat}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3 }}>{r.examples}</div>
                </div>
                <div style={{ padding: '20px', borderRight: `1px solid ${color.border}`, fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{r.secures}</div>
                <div style={{ padding: '20px', fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{r.gap}</div>
              </div>
            ))}
          </div>
          <p style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 16, lineHeight: 1.6 }}>
            Product names are trademarks of their owners, referenced for comparison only. EMILIA is designed to sit alongside these, not replace them.
          </p>
        </C>
      </section>

      {/* WHAT EMILIA ADDS */}
      <section style={{ padding: '80px 0', background: 'rgba(245,244,240,0.45)', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.2fr', gap: 56 }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                What EMILIA adds
              </div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: 0 }}>
                The accountable, provable yes &mdash; bound to the action.
              </h2>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {ADDS.map((a) => (
                <div key={a} style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                  <span style={{ color: color.gold, fontSize: 16, lineHeight: 1.5, flexShrink: 0 }}>&#10003;</span>
                  <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.6, margin: 0 }}>{a}</p>
                </div>
              ))}
            </div>
          </div>
        </C>
      </section>

      {/* CTA */}
      <section style={{ padding: '88px 0' }}>
        <C>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 32, flexWrap: 'wrap' }}>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 3vw, 38px)', letterSpacing: -1.2, lineHeight: 1.1, color: color.t1, maxWidth: 520, margin: 0 }}>
              See the gap close in 30 seconds.
            </h2>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/demo" className="ep-cta" style={cta.primary}>Watch an agent get stopped &rarr;</Link>
              <Link href="/agent-guard" className="ep-cta-secondary" style={cta.secondary}>How Agent Guard works</Link>
            </div>
          </div>
        </C>
      </section>

      <EmailCapture
        eyebrow="Stay close"
        heading="Get the story as it unfolds."
        sub="Where agent accountability is heading, and what we ship next — only when it’s worth your inbox."
      />

      <SiteFooter />
    </div>
  );
}
