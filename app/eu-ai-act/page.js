/**
 * EU AI Act landing page.
 * SEO + procurement-officer surface for EU AI Act high-risk readiness (Annex III deferred to Dec 2, 2027 by the Digital Omnibus).
 *
 * Maps EP's pre-execution receipt architecture directly to Articles 9–15
 * (the Annex III high-risk obligations, now due Dec 2, 2027). Includes a live
 * countdown — clientside so it ticks without server work.
 *
 * @license Apache-2.0
 */
'use client';

import { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const EASE = [0.23, 1, 0.32, 1];

// Annex III high-risk obligations: originally 2026-08-02 (Article 113), then
// provisionally deferred to 2027-12-02 by the Digital Omnibus agreement
// (Council/Parliament/Commission, 2026-05-07; formal adoption pending, plenary
// expected June 2026). We count down to the deferred date and say so — the
// obligations are unchanged, only the clock moved. ISO 8601 Z anchor so the
// countdown is identical for every visitor regardless of local time zone.
const DEADLINE = new Date('2027-12-02T00:00:00Z');

const reveal = (delay = 0) => ({
  initial: { opacity: 0, y: 18 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-40px' },
  transition: { duration: 0.58, delay, ease: EASE },
});

const ARTICLES = [
  {
    num: 'Art. 9',
    title: 'Risk management system',
    burden: 'Continuous risk identification, evaluation, and mitigation across the AI lifecycle.',
    ep: 'Every receipt carries the policy version that authorized it. Risk register and policy graph are queryable through the Trust Explorer.',
  },
  {
    num: 'Art. 10',
    title: 'Data governance and quality',
    burden: 'Training and operational data must be relevant, representative, and free of errors.',
    ep: 'Action context is bound to receipt at sign time; tampering invalidates the cryptographic chain.',
  },
  {
    num: 'Art. 11',
    title: 'Technical documentation',
    burden: 'Documentation kept current and available to authorities on request.',
    ep: 'TLA+ spec, Alloy facts, and 3,500 automated tests are public. Apache 2.0 — auditors read source, not vendor PDFs.',
  },
  {
    num: 'Art. 12',
    title: 'Automatic logging',
    burden: 'Logs must enable post-incident traceability for the full operational life of the system.',
    ep: 'Pre-execution receipt is the log. Cryptographically signed, replay-proof, queryable by actor/policy/time.',
    primary: true,
  },
  {
    num: 'Art. 13',
    title: 'Transparency to users',
    burden: 'Users must be able to understand and use system outputs.',
    ep: 'Every receipt is human-inspectable JSON with the policy clause that fired. No black-box decisions.',
  },
  {
    num: 'Art. 14',
    title: 'Human oversight',
    burden: 'Natural-person oversight to prevent or minimize risks during operation.',
    ep: 'The Signoff phase is mandatory for high-risk actions. Cryptographically bound to a real human identity at decision time.',
    primary: true,
  },
  {
    num: 'Art. 15',
    title: 'Accuracy, robustness, cybersecurity',
    burden: 'System must be resilient to errors, faults, and unauthorized third-party alteration.',
    ep: '26 TLA+ theorems and 35 Alloy facts prove the ceremony cannot be replayed, forged, or partially executed.',
  },
];

const HIGH_RISK_DOMAINS = [
  'Biometric identification',
  'Critical infrastructure',
  'Education access and assessment',
  'Employment and worker management',
  'Essential services — banking, insurance, credit',
  'Law enforcement',
  'Migration, asylum, border control',
  'Administration of justice and democracy',
];

const PARALLEL_FORCING_FUNCTIONS = [
  {
    region: 'United States',
    rule: 'Executive Order 14110',
    detail: 'Federal procurement requires NIST AI RMF alignment. EP maps 38 RMF subcategories.',
  },
  {
    region: 'California',
    rule: 'SB 1047 successor (2026 session)',
    detail: 'Audit logging requirements for frontier model deployments.',
  },
  {
    region: 'Colorado',
    rule: 'Colorado AI Act',
    detail: 'Effective Feb 2026. Impact assessments and consumer notification.',
  },
  {
    region: 'New York',
    rule: 'AI Accountability Act',
    detail: 'Algorithmic decision impact assessments for high-risk uses.',
  },
];

function useCountdown(target) {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const diff = Math.max(0, target.getTime() - now.getTime());
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
  const minutes = Math.floor((diff / (1000 * 60)) % 60);
  const seconds = Math.floor((diff / 1000) % 60);

  return { days, hours, minutes, seconds, passed: diff === 0 };
}

function CountdownBlock({ value, label }) {
  return (
    <div style={{ textAlign: 'center', minWidth: 76 }}>
      <div
        style={{
          fontFamily: font.mono,
          fontSize: 'clamp(32px, 5vw, 48px)',
          fontWeight: 700,
          color: color.gold,
          letterSpacing: -1,
          lineHeight: 1,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {String(value).padStart(2, '0')}
      </div>
      <div
        style={{
          fontFamily: font.mono,
          fontSize: 10,
          letterSpacing: 2,
          color: color.t3,
          marginTop: 6,
          textTransform: 'uppercase',
        }}
      >
        {label}
      </div>
    </div>
  );
}

export default function EuAiActPage() {
  const { days, hours, minutes, seconds, passed } = useCountdown(DEADLINE);

  return (
    <div style={styles.page}>
      <SiteNav activePage="EU AI Act" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 48 }}>
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: EASE }}
        >
          <div style={{ ...styles.eyebrow, color: color.gold }}>
            EU AI Act · Annex III high-risk · provisionally deferred to Dec 2, 2027 (Digital Omnibus, May 7, 2026)
          </div>
          <h1 style={styles.h1Large}>
            The deadline moved.<br />The obligations didn&apos;t.<br />High-risk AI still needs a receipt.
          </h1>
          <p style={{ ...styles.body, maxWidth: 580, fontSize: 18, color: color.t2 }}>
            The Digital Omnibus agreement (May 7, 2026, formal adoption pending) defers stand-alone
            Annex III high-risk obligations from August 2, 2026 to <strong>December 2, 2027</strong>.
            Everything the law requires is unchanged: logging, human oversight, transparency,
            traceability — with penalties up to <strong>€35M or 7% of global turnover</strong>.
            The extension is time to build the evidence layer properly instead of in a panic.
            EMILIA Protocol is the formally verified, open-standard way to do that.
          </p>
        </motion.div>

        {/* Live countdown */}
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.12, ease: EASE }}
          style={{
            marginTop: 40,
            padding: '28px 24px',
            border: `1px solid ${color.border}`,
            borderRadius: radius.base,
            background: color.card,
            display: 'flex',
            justifyContent: 'space-around',
            alignItems: 'center',
            gap: 12,
            flexWrap: 'wrap',
          }}
          aria-label={passed
            ? 'EU AI Act Article 113 enforcement has begun.'
            : `Countdown: ${days} days, ${hours} hours, ${minutes} minutes until EU AI Act Article 113 enforcement.`}
        >
          {passed ? (
            <div style={{ textAlign: 'center', width: '100%' }}>
              <div
                style={{
                  fontFamily: font.mono,
                  fontSize: 24,
                  fontWeight: 700,
                  color: color.gold,
                  letterSpacing: 1,
                }}
              >
                ENFORCEMENT ACTIVE
              </div>
              <div
                style={{
                  fontFamily: font.mono,
                  fontSize: 11,
                  color: color.t3,
                  marginTop: 8,
                  letterSpacing: 1,
                }}
              >
                Annex III high-risk obligations in force as of 2027-12-02 00:00 UTC
              </div>
            </div>
          ) : (
            <>
              <CountdownBlock value={days} label="Days" />
              <CountdownBlock value={hours} label="Hours" />
              <CountdownBlock value={minutes} label="Minutes" />
              <CountdownBlock value={seconds} label="Seconds" />
            </>
          )}
        </motion.div>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2, ease: EASE }}
          style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}
        >
          <a href="/contact" className="ep-cta" style={cta.primary}>
            Talk to a compliance engineer
          </a>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondary}>
            Read the spec
          </a>
        </motion.div>
      </section>

      {/* What "high-risk" means */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <motion.div {...reveal()}>
            <div style={styles.eyebrow}>Scope</div>
            <h2 style={styles.h2}>What &quot;high-risk&quot; covers</h2>
            <p style={styles.body}>
              The EU AI Act defines high-risk systems by domain. If your AI agent
              touches any of these, Article 113 obligations apply on day one of
              enforcement — regardless of whether the agent is autonomous or
              human-assisted.
            </p>
          </motion.div>

          <motion.ul
            {...reveal(0.08)}
            style={{
              listStyle: 'none',
              padding: 0,
              margin: '24px 0 0',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: 12,
            }}
          >
            {HIGH_RISK_DOMAINS.map((domain) => (
              <li
                key={domain}
                style={{
                  fontFamily: font.sans,
                  fontSize: 14,
                  color: color.t1,
                  padding: '14px 16px',
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderLeft: `2px solid ${color.gold}`,
                  borderRadius: radius.sm,
                }}
              >
                {domain}
              </li>
            ))}
          </motion.ul>
        </div>
      </section>

      {/* Article-by-article mapping */}
      <section style={styles.section}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>The mapping</div>
          <h2 style={styles.h2}>How EP satisfies Articles 9 through 15</h2>
          <p style={styles.body}>
            Each obligation maps to a specific phase of the EMILIA ceremony.
            The two articles most often cited in early enforcement guidance —
            Art. 12 (logging) and Art. 14 (human oversight) — are highlighted.
          </p>
        </motion.div>

        <div style={{ marginTop: 32, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {ARTICLES.map((art, i) => (
            <motion.div
              key={art.num}
              {...reveal(i * 0.04)}
              style={{
                border: `1px solid ${art.primary ? color.gold : color.border}`,
                borderRadius: radius.base,
                padding: '20px 24px',
                background: art.primary ? '#FFFBF0' : color.card,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'baseline',
                  gap: 16,
                  flexWrap: 'wrap',
                  marginBottom: 8,
                }}
              >
                <div
                  style={{
                    fontFamily: font.mono,
                    fontSize: 12,
                    fontWeight: 700,
                    color: art.primary ? color.gold : color.t1,
                    letterSpacing: 1,
                  }}
                >
                  {art.num}
                </div>
                <div
                  style={{
                    fontFamily: font.sans,
                    fontSize: 16,
                    fontWeight: 600,
                    color: color.t1,
                  }}
                >
                  {art.title}
                </div>
                {art.primary && (
                  <div
                    style={{
                      fontFamily: font.mono,
                      fontSize: 9,
                      letterSpacing: 2,
                      color: color.gold,
                      padding: '2px 8px',
                      border: `1px solid ${color.gold}`,
                      borderRadius: radius.sm,
                      textTransform: 'uppercase',
                    }}
                  >
                    Primary EP fit
                  </div>
                )}
              </div>
              <div
                style={{
                  fontFamily: font.sans,
                  fontSize: 14,
                  color: color.t2,
                  marginBottom: 8,
                  lineHeight: 1.55,
                }}
              >
                <strong style={{ color: color.t1 }}>The obligation: </strong>
                {art.burden}
              </div>
              <div
                style={{
                  fontFamily: font.sans,
                  fontSize: 14,
                  color: color.t2,
                  lineHeight: 1.55,
                }}
              >
                <strong style={{ color: color.t1 }}>How EP satisfies it: </strong>
                {art.ep}
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Your 30-day path — Article 14 human-oversight kit */}
      <section style={{ ...styles.section, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={{ ...styles.eyebrow, color: color.gold }}>Article 14 Human-Oversight Kit</div>
          <h2 style={{ ...styles.h1, fontSize: 'clamp(26px, 3.4vw, 38px)', marginBottom: 14 }}>Your 30-day path to human oversight.</h2>
          <p style={{ ...styles.body, maxWidth: 600 }}>
            Article 14 asks that a human can oversee, intervene, and stop a high-risk system. EMILIA is the
            technical implementation of that slice — and it&apos;s mostly packaging what you already have.
          </p>
          <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
            {[
              ['Week 1 — Inventory', 'List every irreversible action your system can take. Each becomes a canonical action.'],
              ['Week 2 — Observe', 'Wrap them in Emilia Eye mode — log "what would have been blocked" with zero enforcement. No risk.'],
              ['Week 3 — Enforce + sign-off', 'Turn on signoff for the high-risk classes; route approvals to your humans. Every approval mints a receipt.'],
              ['Week 4 — Evidence', 'Export the receipt bundle — an auditor verifies it offline, no need to trust EP or you.'],
            ].map(([t, d], i) => (
              <div key={t} style={{ display: 'grid', gridTemplateColumns: '40px 1fr', gap: 18, alignItems: 'start', background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '18px 20px' }}>
                <div style={{ fontFamily: font.mono, fontWeight: 700, fontSize: 16, color: color.gold }}>{`0${i + 1}`}</div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 15, color: color.t1 }}>{t}</div>
                  <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginTop: 3 }}>{d}</div>
                </div>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 13, color: color.t3, marginTop: 14 }}>
            Maps to Art 14 (human oversight), Art 12 (record-keeping), Art 9 (risk management). Not a complete
            compliance program; not legal advice. Full mapping in the <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/eu-ai-act-article-14-kit.md" target="_blank" rel="noopener noreferrer" style={{ color: color.gold }}>Article 14 kit</a>.
          </p>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 16 }}>
            {[
              ['/compliance/emilia-eu-ai-act-financial-services.pdf', 'Financial services mapping (PDF)'],
              ['/compliance/emilia-eu-ai-act-government.pdf', 'Government programs mapping (PDF)'],
              ['/compliance/emilia-eu-ai-act-healthcare.pdf', 'Healthcare mapping (PDF)'],
            ].map(([href, label]) => (
              <a key={href} href={href} style={{ fontFamily: font.mono, fontSize: 12.5, color: color.t1, textDecoration: 'none', border: `1px solid ${color.borderHover}`, borderRadius: radius.sm, padding: '9px 14px' }}>
                ↓ {label}
              </a>
            ))}
          </div>
        </motion.div>
      </section>

      {/* Penalty stakes */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <motion.div {...reveal()}>
            <div style={styles.eyebrow}>Penalties</div>
            <h2 style={styles.h2}>What non-compliance costs</h2>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: 16,
                marginTop: 24,
              }}
            >
              <div
                style={{
                  padding: 24,
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderLeft: `3px solid ${color.red}`,
                  borderRadius: radius.base,
                }}
              >
                <div
                  style={{
                    fontFamily: font.mono,
                    fontSize: 28,
                    fontWeight: 700,
                    color: color.t1,
                  }}
                >
                  €35M
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 8 }}>
                  Maximum fine — flat ceiling
                </div>
              </div>
              <div
                style={{
                  padding: 24,
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderLeft: `3px solid ${color.red}`,
                  borderRadius: radius.base,
                }}
              >
                <div
                  style={{
                    fontFamily: font.mono,
                    fontSize: 28,
                    fontWeight: 700,
                    color: color.t1,
                  }}
                >
                  7%
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 8 }}>
                  Of global annual turnover — whichever is higher
                </div>
              </div>
              <div
                style={{
                  padding: 24,
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderLeft: `3px solid ${color.red}`,
                  borderRadius: radius.base,
                }}
              >
                <div
                  style={{
                    fontFamily: font.mono,
                    fontSize: 28,
                    fontWeight: 700,
                    color: color.t1,
                  }}
                >
                  Day 1
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 8 }}>
                  No grace period for high-risk systems
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Parallel forcing functions (US + state) */}
      <section style={styles.section}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Beyond Brussels</div>
          <h2 style={styles.h2}>Parallel forcing functions</h2>
          <p style={styles.body}>
            Even if your AI never touches an EU user, the US Executive Order and
            three active state laws create the same pre-execution governance
            requirement on a similar timeline. EP&apos;s NIST AI RMF mapping
            covers the federal side directly.
          </p>
        </motion.div>

        <div
          style={{
            marginTop: 24,
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
            gap: 16,
          }}
        >
          {PARALLEL_FORCING_FUNCTIONS.map((law, i) => (
            <motion.div
              key={law.rule}
              {...reveal(i * 0.05)}
              style={{
                padding: 20,
                background: color.card,
                border: `1px solid ${color.border}`,
                borderRadius: radius.base,
              }}
            >
              <div
                style={{
                  fontFamily: font.mono,
                  fontSize: 10,
                  letterSpacing: 2,
                  color: color.t3,
                  textTransform: 'uppercase',
                  marginBottom: 8,
                }}
              >
                {law.region}
              </div>
              <div
                style={{
                  fontFamily: font.sans,
                  fontSize: 15,
                  fontWeight: 700,
                  color: color.t1,
                  marginBottom: 8,
                }}
              >
                {law.rule}
              </div>
              <div style={{ fontFamily: font.sans, fontSize: 13, color: color.t2, lineHeight: 1.55 }}>
                {law.detail}
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Closing CTA */}
      <section style={styles.sectionAlt}>
        <div style={{ ...styles.section, textAlign: 'center', paddingTop: 64, paddingBottom: 80 }}>
          <motion.div {...reveal()}>
            <div style={styles.eyebrow}>Next step</div>
            <h2 style={{ ...styles.h2, fontSize: 32, marginBottom: 16 }}>
              74 days is enough — if you start this week.
            </h2>
            <p style={{ ...styles.body, maxWidth: 540, margin: '0 auto 28px' }}>
              We integrate in under a day. Apache 2.0, no vendor lock-in.
              Reference deployments at federal and fintech pilots underway.
            </p>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
              <a href="/contact" className="ep-cta" style={cta.primary}>
                Schedule a compliance walkthrough
              </a>
              <a href="/quickstart" className="ep-cta-secondary" style={cta.secondary}>
                Try the SDK
              </a>
            </div>
          </motion.div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
