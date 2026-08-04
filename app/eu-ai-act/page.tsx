/**
 * EU AI Act landing page.
 * SEO + procurement-officer surface for the adopted EU AI Act high-risk timeline.
 *
 * Maps EP's pre-execution receipt architecture directly to Articles 9–15
 * (the Annex III high-risk obligations, now due Dec 2, 2027). Includes a live
 * countdown — clientside so it ticks without server work.
 *
 * @license Apache-2.0
 */
'use client';

import { useEffect, useState } from 'react';
import proofStats from '@/lib/proof-stats.json';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

/** @type {readonly [number, number, number, number]} */
const EASE = [0.23, 1, 0.32, 1] as const;

// Regulation (EU) 2026/1744 sets Dec 2, 2027 for Annex III high-risk systems
// and Aug 2, 2028 for Annex I product-integrated systems. This page counts down
// to the first date and states the second separately.
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
    ep: 'Gate records the policy and exact action used for a protected decision. That artifact can support, but does not replace, a lifecycle risk-management system.',
  },
  {
    num: 'Art. 10',
    title: 'Data governance and quality',
    burden: 'Training and operational data must be relevant, representative, and free of errors.',
    ep: 'EMILIA does not establish training-data quality or representativeness. It can bind identified operational inputs to one protected action.',
  },
  {
    num: 'Art. 11',
    title: 'Technical documentation',
    burden: 'Documentation kept current and available to authorities on request.',
    ep: `Public specifications, bounded models, conformance vectors, and ${proofStats.tests.total.toLocaleString('en-US')} automated tests can support technical documentation. They are not the deployer's complete regulated documentation.`,
  },
  {
    num: 'Art. 12',
    title: 'Automatic logging',
    burden: 'Logs must enable post-incident traceability for the full operational life of the system.',
    ep: 'An authorization receipt is one tamper-evident event artifact. It does not replace complete operational logging or prove that every action passed through Gate.',
    primary: true,
  },
  {
    num: 'Art. 13',
    title: 'Transparency to users',
    burden: 'Users must be able to understand and use system outputs.',
    ep: 'Receipts expose the action, evidence references, policy version, and decision in a portable form. Usable notices and explanations remain the deployer\'s responsibility.',
  },
  {
    num: 'Art. 14',
    title: 'Human oversight',
    burden: 'Natural-person oversight to prevent or minimize risks during operation.',
    ep: 'A relying party can require signed human-approval evidence for selected protected actions. The organization still decides who is qualified and whether that control meets Article 14.',
    primary: true,
  },
  {
    num: 'Art. 15',
    title: 'Accuracy, robustness, cybersecurity',
    burden: 'System must be resilient to errors, faults, and unauthorized third-party alteration.',
    ep: 'Bounded models and executable tests cover named replay, one-time admission, and uncertain-outcome properties. They do not prove overall system accuracy, cybersecurity, or legal conformity.',
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
    rule: 'NIST AI RMF + OMB M-25-21',
    detail: 'Federal AI use-case inventories flag high-impact uses; NIST AI RMF alignment shapes procurement. EP publishes its RMF mapping.',
  },
  {
    region: 'California',
    rule: 'EO N-5-26 + TL 24-03',
    detail: 'Trusted-AI procurement standards and GenAI risk assessments for state entities.',
  },
  {
    region: 'Colorado',
    rule: 'Colorado AI Act',
    detail: 'Effective June 30, 2026. Impact assessments and consumer notification.',
  },
  {
    region: 'Texas',
    rule: 'TRAIGA (HB 149)',
    detail: 'Effective Jan 1, 2026. Agency AI governance and disclosure obligations.',
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

export default function EuAiActPage(): React.JSX.Element {
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
            EU AI Act · Regulation (EU) 2026/1744 · adopted July 2026
          </div>
          <h1 style={styles.h1Large}>
            The timeline is set.<br />The evidence design is still yours.<br />Build it before deployment.
          </h1>
          <p style={{ ...styles.body, maxWidth: 580, fontSize: 18, color: color.t2 }}>
            Regulation (EU) 2026/1744 applies the relevant high-risk obligations from
            <strong> December 2, 2027</strong> for Annex III systems and
            <strong> August 2, 2028</strong> for product-integrated Annex I systems.
            EMILIA is one open technical mechanism for exact-action admission and portable
            evidence. It may support selected logging and oversight controls; it is not a
            complete compliance program and the law does not mandate an EMILIA receipt.
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
              Annex III identifies high-risk use areas, subject to the Regulation&apos;s
              definitions, exceptions, and classification rules. A system touching one of
              these areas is not automatically high-risk; counsel and the deployer must
              classify the actual intended use.
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
          <h2 style={styles.h2}>Where EMILIA may contribute to Articles 9 through 15</h2>
          <p style={styles.body}>
            This is a technical-control mapping, not a conformity assessment. Articles 12
            and 14 are highlighted because exact-action records and human-approval evidence
            are EMILIA&apos;s closest fit.
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
                <strong style={{ color: color.t1 }}>Potential EMILIA contribution: </strong>
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
            Article 14 requires effective human oversight. EMILIA can implement one narrow
            control: requiring action-bound approval evidence at a protected boundary.
          </p>
          <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
            {[
              ['Week 1 — Inventory', 'List every irreversible action your system can take. Each becomes a canonical action.'],
              ['Week 2 — Observe', 'Run a scoped shadow assessment. It does not enforce and does not prove that every path is covered.'],
              ['Week 3 — Enforce + sign-off', 'Route selected protected actions to qualified reviewers and issue action-bound approval evidence.'],
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
            <h2 style={styles.h2}>Penalties depend on the violation</h2>
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
                  Up to €15M
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 8 }}>
                  Other-obligation tier under Article 99
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
                  Up to 3%
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 8 }}>
                  Prior-year worldwide turnover for that tier
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
                  Dec 2, 2027
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 8 }}>
                  Annex III high-risk application date
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
            U.S. federal and state instruments create different governance,
            documentation, inventory, and procurement pressures. They do not all require
            the same control, and an EMILIA mapping is not compliance by itself.
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
              Eighteen months is enough — if you start this week.
            </h2>
            <p style={{ ...styles.body, maxWidth: 540, margin: '0 auto 28px' }}>
              We integrate in under a day. Apache 2.0, no vendor lock-in.
              Reference verifiers deployed publicly; first pilot slots open.
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
