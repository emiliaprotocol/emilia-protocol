'use client';

/**
 * AI Trust Desk — landing page (/trust-desk).
 *
 * One scrollable page, one CTA: "Upload your AI security review."
 * Powered-by-EP framing is explicit in the header pill and footer.
 *
 * Visual differentiation from core EP pages: blue accent (instead of
 * EP's gold) signals "product page, not protocol page" — so a buyer
 * landing here doesn't mistake this for the protocol itself.
 */

import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

const ACCENT = color.blue; // Trust Desk signature color

// Stripe Payment Links — set via NEXT_PUBLIC_STRIPE_* env vars at deploy
// time. When the env var is missing we fall back to mailto:team@... so a
// click on a "Buy" button on production never lands on a 404 — it opens
// an email to the sales team. The previous fallback was a literal
// REPLACE_EMERGENCY URL that produced a broken link if the env was unset,
// which a buyer testing the live site would discover instantly.
const SALES_MAILTO = 'mailto:team@emiliaprotocol.ai?subject=Trust%20Desk%20order';
const STRIPE_LINKS = {
  emergency: process.env.NEXT_PUBLIC_STRIPE_EMERGENCY || SALES_MAILTO,
  full:      process.env.NEXT_PUBLIC_STRIPE_FULL      || SALES_MAILTO,
  packet:    process.env.NEXT_PUBLIC_STRIPE_PACKET    || SALES_MAILTO,
  retainer:  process.env.NEXT_PUBLIC_STRIPE_RETAINER  || SALES_MAILTO,
};

export default function TrustDeskLanding() {
  return (
    <div style={styles.page}>
      <SiteNav />

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 96 }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 8,
            padding: '6px 12px', border: `1px solid ${color.border}`, borderRadius: 999,
            fontFamily: font.mono, fontSize: 11, color: color.t3,
            letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 32,
          }}>
            <span style={{ height: 6, width: 6, borderRadius: 999, background: ACCENT }} />
            AI Trust Desk · Powered by Emilia Protocol
          </div>

          <h1 style={{
            fontFamily: font.sans, fontSize: 56, fontWeight: 700, lineHeight: 1.1,
            letterSpacing: '-0.02em', maxWidth: 860, color: color.t1, margin: 0,
          }}>
            Enterprise buyer asking hard AI-risk questions?
          </h1>

          <p style={{
            fontFamily: font.sans, fontSize: 20, lineHeight: 1.55, color: color.t2,
            maxWidth: 720, marginTop: 24,
          }}>
            We answer them in 48 hours and publish a{' '}
            <strong style={{ color: color.t1 }}>live trust page your buyer can verify</strong>.
            Prompt injection, model training, RAG data flows, agent tool access, AI incident
            response — the questions your SOC 2 platform does not handle well.
          </p>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 20, alignItems: 'center', marginTop: 40 }}>
            <Link
              href="/trust-desk/upload"
              style={{
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                background: ACCENT, color: '#FFFFFF', fontWeight: 600,
                padding: '14px 24px', borderRadius: radius.sm, textDecoration: 'none',
                fontFamily: font.sans, fontSize: 16,
              }}
            >
              Upload your AI security review
            </Link>
            <span style={{ fontSize: 14, color: color.t3 }}>
              48-hour turnaround · $3,500–$24,500 · No retainer required
            </span>
          </div>

          <p style={{ fontSize: 14, color: color.t3, marginTop: 32 }}>
            For AI vendors selling into <strong style={{ color: color.t2 }}>financial services</strong>.
            Healthcare waitlist-only for now.
          </p>
        </div>
      </section>

      {/* ── Who this is for ──────────────────────────────────────────────── */}
      <section style={{ borderBottom: `1px solid ${color.border}`, background: color.cardHover }}>
        <div style={styles.sectionWide}>
          <h2 style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            This is for you if
          </h2>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 24, marginTop: 40,
          }}>
            {[
              { k: '01', t: 'Your AI product sells into banks, funds, insurers, or fintechs.',
                b: 'Those buyers have security, risk, and compliance teams. They are the ones asking the hard questions.' },
              { k: '02', t: 'You have an active deal stuck in security, legal, risk, or procurement review.',
                b: 'Not "eventually will." Active. Named account. Named blocker. Clock is running.' },
              { k: '03', t: 'Your SOC 2 report does not cover the AI-specific questions.',
                b: 'Model training, prompt injection, RAG subprocessors, agent permissions, AI incident response — SOC 2 does not. That is the gap.' },
            ].map((card) => (
              <div key={card.k} style={{
                background: color.card, border: `1px solid ${color.border}`,
                borderTop: `3px solid ${ACCENT}`, borderRadius: radius.base, padding: 24,
              }}>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: ACCENT, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 12 }}>
                  {card.k}
                </div>
                <div style={{ fontSize: 16, fontWeight: 600, color: color.t1, lineHeight: 1.4 }}>{card.t}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginTop: 10 }}>{card.b}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── What you get ─────────────────────────────────────────────────── */}
      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={styles.sectionWide}>
          <h2 style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            What you get
          </h2>
          <p style={{ fontSize: 16, color: color.t2, maxWidth: 720, marginTop: 12, lineHeight: 1.6 }}>
            Every AI Trust Packet includes the six deliverables below. Each is signed,
            timestamped, and published on a live URL your buyer can bookmark.
          </p>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: 24, marginTop: 40,
          }}>
            {[
              ['Completed AI-specific questionnaire', 'Your buyer\'s security, risk, and AI-governance questions, answered in their language, aligned with SOC 2 and emerging AI-risk frameworks.'],
              ['Five AI policy documents', 'Data Handling & Model Training Disclosure. Prompt Injection Defense Statement. AI Subprocessor & Data Flow Map. Agent Access Control Policy. AI Incident Response Runbook.'],
              ['Live AI Trust Page', 'A URL you share with your buyer. Every claim timestamped, signed, and refreshable. Supersedes PDFs the day you deploy.'],
              ['Signed claim hashes', 'Every policy and every answer has a SHA-256 hash bound to an audit trail. Signed by AI Trust Desk. Buyer-verifiable from day 21.'],
              ['30-day Q&A Slack channel', 'When your buyer\'s CISO sends a follow-up question, we handle it. Caps at 5 hours total; covers the deal to close.'],
              ['Optional risk-call support', 'If your buyer\'s security team wants a live call to walk through the answers, we join. (Retainer tier only.)'],
            ].map(([t, b]) => (
              <div key={t} style={{ display: 'flex', gap: 16 }}>
                <div style={{
                  height: 24, width: 24, flexShrink: 0, background: `${ACCENT}15`,
                  borderRadius: 999, textAlign: 'center', fontFamily: font.mono,
                  fontSize: 11, color: ACCENT, lineHeight: '24px', fontWeight: 700,
                }}>✓</div>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 600, color: color.t1 }}>{t}</div>
                  <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginTop: 6 }}>{b}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Why a live trust page ────────────────────────────────────────── */}
      <section style={{ borderBottom: `1px solid ${color.border}`, background: color.cardHover }}>
        <div style={styles.sectionWide}>
          <h2 style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            Why a live trust page beats a PDF
          </h2>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 24, marginTop: 40,
          }}>
            {[
              ['PDFs die the day they are delivered', 'Your buyer files it. Six months later their CISO asks "is this still accurate?" Nobody knows. You redo the whole questionnaire.'],
              ['A live page stays current', 'Claims have timestamps and expiry dates. Updates are signed and logged. Your buyer bookmarks the URL; you keep it current.'],
              ['One page, every future deal', 'The trust page you ship for one deal becomes the baseline for the next 10. Every buyer sees the same vetted answers.'],
            ].map(([t, b]) => (
              <div key={t} style={{
                background: color.card, border: `1px solid ${color.border}`,
                borderRadius: radius.base, padding: 24,
              }}>
                <div style={{ fontSize: 16, fontWeight: 600, color: color.t1 }}>{t}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginTop: 10 }}>{b}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Pricing ──────────────────────────────────────────────────────── */}
      <section style={{ borderBottom: `1px solid ${color.border}` }} id="pricing">
        <div style={styles.sectionWide}>
          <h2 style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            Pricing
          </h2>
          <p style={{ fontSize: 16, color: color.t2, maxWidth: 720, marginTop: 12, lineHeight: 1.6 }}>
            Each tier is a fixed-scope, fixed-price engagement. Payment is upfront via Stripe.
            No hidden fees. No auto-renew.
          </p>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
            gap: 16, marginTop: 40,
          }}>
            <PricingCard
              name="Emergency Review" price="$3,500" unit="per questionnaire" turnaround="24 hours"
              href={STRIPE_LINKS.emergency}
              bullets={['Review existing questionnaire', 'Fill missing answers', 'Highlight remaining gaps', 'No policy docs', 'No trust page']}
            />
            <PricingCard
              name="Full Completion" price="$9,500" unit="per questionnaire" turnaround="48 hours"
              href={STRIPE_LINKS.full}
              bullets={['Full questionnaire completion', 'Answer alignment with SOC 2', 'One policy summary doc', 'No trust page', 'No live hosting']}
            />
            <PricingCard
              name="AI Trust Packet" price="$24,500" unit="per engagement" turnaround="48 hours"
              href={STRIPE_LINKS.packet} highlighted
              bullets={['Full questionnaire', 'All 5 AI policy docs', 'Live AI Trust Page', 'Signed claim hashes', '30-day Q&A Slack']}
            />
            <PricingCard
              name="Retainer" price="$12,000" unit="per month · 3 mo min" turnaround="Ongoing"
              href={STRIPE_LINKS.retainer}
              bullets={['Unlimited questionnaires', 'Rolling policy updates', 'Dedicated Slack channel', 'Live risk-call support', 'Custom vanity domain']}
            />
          </div>
          <p style={{ fontSize: 14, color: color.t3, marginTop: 40 }}>
            <strong>Not sure which?</strong> Most vendors with a single stuck deal pick the
            AI Trust Packet. Vendors with two or more active reviews should start on Retainer.
          </p>
        </div>
      </section>

      {/* ── How it works ─────────────────────────────────────────────────── */}
      <section style={{ borderBottom: `1px solid ${color.border}`, background: color.cardHover }}>
        <div style={styles.sectionWide}>
          <h2 style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            How it works
          </h2>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 24, marginTop: 40,
          }}>
            {[
              ['01', 'Upload', 'Send your questionnaire (Excel, PDF, or Word) plus 8 intake questions. Takes 10 minutes.'],
              ['02', 'We answer', 'Your assigned reviewer (a named human, not an LLM) completes the questionnaire, drafts the policies, and builds your trust page. 24–48 hours.'],
              ['03', 'You forward', 'We deliver the trust page URL and all deliverables in Slack. You forward the URL to your buyer. Deal moves.'],
            ].map(([k, t, b]) => (
              <div key={k} style={{
                background: color.card, border: `1px solid ${color.border}`,
                borderRadius: radius.base, padding: 24,
              }}>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: ACCENT, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 12 }}>
                  STEP {k}
                </div>
                <div style={{ fontSize: 16, fontWeight: 600, color: color.t1 }}>{t}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginTop: 10 }}>{b}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── FAQ ──────────────────────────────────────────────────────────── */}
      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.section, maxWidth: 720 }}>
          <h2 style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            Questions you probably have
          </h2>
          <div style={{ marginTop: 32, display: 'flex', flexDirection: 'column', gap: 28 }}>
            {FAQ.map((item) => (
              <div key={item.q}>
                <div style={{ fontSize: 16, fontWeight: 600, color: color.t1 }}>{item.q}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginTop: 8 }}>{item.a}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Closing CTA ──────────────────────────────────────────────────── */}
      <section>
        <div style={{ ...styles.section, textAlign: 'center', maxWidth: 720 }}>
          <h2 style={{
            fontFamily: font.sans, fontSize: 32, fontWeight: 700,
            letterSpacing: '-0.01em', color: color.t1, margin: 0,
          }}>
            One upload. 48 hours. Deal moves.
          </h2>
          <Link
            href="/trust-desk/upload"
            style={{
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              background: ACCENT, color: '#FFFFFF', fontWeight: 600,
              padding: '14px 28px', borderRadius: radius.sm, textDecoration: 'none',
              fontFamily: font.sans, fontSize: 16, marginTop: 32,
            }}
          >
            Upload your AI security review
          </Link>
          <p style={{ fontSize: 14, color: color.t3, marginTop: 16 }}>
            Prefer a 15-minute call first? Mention it on the intake form.
          </p>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}

function PricingCard({ name, price, unit, turnaround, bullets, href, highlighted = false }) {
  return (
    <div style={{
      background: highlighted ? `${ACCENT}08` : color.card,
      border: `1px solid ${highlighted ? ACCENT : color.border}`,
      borderTop: `3px solid ${highlighted ? ACCENT : color.border}`,
      borderRadius: radius.base, padding: 24, display: 'flex', flexDirection: 'column',
    }}>
      {highlighted && (
        <div style={{
          display: 'inline-block', background: ACCENT, color: '#FFFFFF',
          fontFamily: font.mono, fontSize: 10, fontWeight: 700, letterSpacing: 1.5,
          textTransform: 'uppercase', padding: '4px 10px', borderRadius: 999,
          alignSelf: 'flex-start', marginBottom: 12,
        }}>Most vendors pick this</div>
      )}
      <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1.5, textTransform: 'uppercase' }}>
        {name}
      </div>
      <div style={{ fontSize: 32, fontWeight: 700, color: color.t1, marginTop: 12 }}>{price}</div>
      <div style={{ fontSize: 12, color: color.t3, marginTop: 2 }}>{unit}</div>
      <div style={{ fontSize: 12, color: color.t3, marginTop: 12, fontFamily: font.mono }}>
        TURNAROUND: <span style={{ color: color.t1 }}>{turnaround}</span>
      </div>
      <ul style={{ marginTop: 20, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 8 }}>
        {bullets.map((b) => (
          <li key={b} style={{ display: 'flex', gap: 8, fontSize: 14, color: color.t2 }}>
            <span style={{ marginTop: 7, height: 4, width: 4, flexShrink: 0, borderRadius: 999, background: color.t3 }} />
            <span>{b}</span>
          </li>
        ))}
      </ul>
      <a
        href={href}
        style={{
          display: 'block', textAlign: 'center', textDecoration: 'none',
          padding: '10px 16px', marginTop: 28, borderRadius: radius.sm,
          background: highlighted ? ACCENT : color.card, color: highlighted ? '#FFFFFF' : color.t1,
          border: `1px solid ${highlighted ? ACCENT : color.border}`,
          fontWeight: 600, fontSize: 14,
        }}
      >Buy {name}</a>
    </div>
  );
}

const FAQ = [
  { q: 'Who actually fills out the questionnaire?',
    a: 'A named reviewer with security / compliance background — not an LLM, not a freelancer pool. You will know their name before work starts. They sign the attestation on your trust page.' },
  { q: 'What if my questionnaire has questions you have not seen?',
    a: 'Most AI security questionnaires share 80% of their content once you have seen 10 of them. For genuinely novel questions, we research the specific standard (NIST AI RMF, OWASP LLM Top 10, etc.) and answer in that framework\'s language.' },
  { q: 'Will my buyer accept a "live trust page" instead of a PDF?',
    a: 'Yes. Enterprise security teams increasingly prefer trust centers (SafeBase, Vanta Trust Center, Drata Trust Center). Our page is the same pattern — with AI-specific policies those tools do not cover.' },
  { q: 'Can I verify the signed claims independently?',
    a: 'Signed and timestamped hashes ship day 1. Independent buyer-side verification (via a public verify endpoint) lands day 21. Retainer customers get this from day 1.' },
  { q: 'Liability?',
    a: 'You remain responsible for the accuracy of the underlying claims about your product. We are responsible for the accuracy of the analysis, the policy drafting, and the platform. Our MSA is straightforward and we will send it on intake.' },
  { q: 'Why fintech only?',
    a: 'Fintech buyers ask the hardest AI-risk questions (money is on the line) and their questionnaires share the most structure. We know this market. Healthcare is planned; not yet.' },
];
