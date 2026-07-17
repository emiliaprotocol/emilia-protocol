/**
 * EU AI Act landing page.
 * SEO + procurement-officer surface for EU AI Act high-risk readiness.
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

const EASE = [0.23, 1, 0.32, 1];

// The Commission's current implementation timeline, following the May 7, 2026
// political agreement on the AI omnibus, applies Annex III high-risk rules from
// 2027-12-02 and product-integrated high-risk rules from 2028-08-02. ISO 8601 Z
// anchor keeps the countdown identical across visitor time zones.
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
    ep: 'Supporting evidence: the Gate records which versioned action rule was evaluated and which failing predicate caused a refusal. It does not identify every AI-system risk or replace the deployer’s risk-management process.',
  },
  {
    num: 'Art. 10',
    title: 'Data governance and quality',
    burden: 'Training and operational data must be relevant, representative, and free of errors.',
    ep: 'Outside the receipt layer’s scope. EMILIA can bind a digest of a referenced dataset or assessment to an action, but it does not establish data quality, representativeness, or freedom from bias.',
  },
  {
    num: 'Art. 11',
    title: 'Technical documentation',
    burden: 'Documentation kept current and available to authorities on request.',
    ep: `Supporting evidence: the reference implementation, security claims, model-checking scope, and ${proofStats.tests.total.toLocaleString('en-US')} automated tests are public and versioned. A deployment still needs system-specific technical documentation.`,
  },
  {
    num: 'Art. 12',
    title: 'Automatic logging',
    burden: 'Logs must enable post-incident traceability for the full operational life of the system.',
    ep: 'Direct evidence fit: authorization and refusal events can be retained as signed, exact-action records, with a tamper-evident evidence log. Retention, completeness, and routing every relevant event through the Gate remain deployment responsibilities.',
    primary: true,
  },
  {
    num: 'Art. 13',
    title: 'Transparency to users',
    burden: 'Users must be able to understand and use system outputs.',
    ep: 'Mostly outside scope. A receipt can identify the action, policy digest, and decision evidence, but it does not make an AI system’s output understandable or satisfy user-instruction and disclosure duties.',
  },
  {
    num: 'Art. 14',
    title: 'Human oversight',
    burden: 'Natural-person oversight to prevent or minimize risks during operation.',
    ep: 'Direct evidence fit: a deployment can require a pinned, named approver’s user-verified signature over the exact action before execution, retain typed refusals, and enforce M-of-N approval where its own policy requires it. This evidences one oversight mechanism; it is not the whole Article 14 assessment.',
    primary: true,
  },
  {
    num: 'Art. 15',
    title: 'Accuracy, robustness, cybersecurity',
    burden: 'System must be resilient to errors, faults, and unauthorized third-party alteration.',
    ep: 'Supporting evidence: protocol invariants, adversarial vectors, and fault-schedule tests cover named authorization and replay properties under stated assumptions. They do not prove the AI system’s accuracy, overall robustness, or cybersecurity.',
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
  const [now, setNow] = useState(null);

  useEffect(() => {
    const tick = () => setNow(new Date());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  if (now === null) {
    return { days: '--', hours: '--', minutes: '--', seconds: '--', passed: false, ready: false };
  }

  const diff = Math.max(0, target.getTime() - now.getTime());
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
  const minutes = Math.floor((diff / (1000 * 60)) % 60);
  const seconds = Math.floor((diff / 1000) % 60);

  return { days, hours, minutes, seconds, passed: diff === 0, ready: true };
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
  const { days, hours, minutes, seconds, passed, ready } = useCountdown(DEADLINE);

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
            EU AI Act · Annex III high-risk rules · 2 December 2027
          </div>
          <h1 style={styles.h1Large}>
            The timetable moved.<br />Evidence engineering still takes time.<br />Make human oversight inspectable.
          </h1>
          <p style={{ ...styles.body, maxWidth: 580, fontSize: 18, color: color.t2 }}>
            The Commission&apos;s current implementation timeline lists the rules for Annex III
            high-risk systems from <strong>2 December 2027</strong>; product-integrated high-risk
            systems follow on 2 August 2028. Use that time to build inspectable evidence for logging
            and human oversight. EMILIA is open specification work and an Apache-2.0 reference
            implementation for the action-authorization slice — not a compliance determination.
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
            ? 'The current Commission timeline date for Annex III high-risk rules has been reached; verify the operative legal timeline.'
            : ready
              ? `Countdown: ${days} days, ${hours} hours, ${minutes} minutes until the Commission timeline for Annex III high-risk rules.`
              : 'Loading the countdown to the current Commission timeline for Annex III high-risk rules.'}
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
                TIMELINE DATE REACHED
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
                Verify the operative legal timeline before relying on this date
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
        <p style={{ ...styles.body, marginTop: 12, fontSize: 12.5, color: color.t3 }}>
          Timeline source:{' '}
          <a
            href="https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: color.gold }}
          >
            European Commission AI Act implementation page
          </a>
          . Confirm the operative law and your role with qualified counsel.
        </p>

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
              The EU AI Act defines high-risk systems by intended use and regulatory
              category, not merely by whether software &quot;touches&quot; a domain. The
              2 December 2027 date applies to Annex III systems; product-integrated
              high-risk systems have a 2 August 2028 timeline. Confirm classification
              and role-specific duties with qualified counsel.
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
          <h2 style={styles.h2}>Where EMILIA contributes — and where it does not</h2>
          <p style={styles.body}>
            The strongest technical fit is narrow: action-level evidence for logging
            and human oversight. Other duties need separate controls. Art. 12 and
            Art. 14 are highlighted because the receipt and Gate directly produce
            evidence relevant to those assessments.
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
                <strong style={{ color: color.t1 }}>EMILIA contribution: </strong>
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
          <h2 style={{ ...styles.h1, fontSize: 'clamp(26px, 3.4vw, 38px)', marginBottom: 14 }}>A 30-day path to an inspectable authorization control.</h2>
          <p style={{ ...styles.body, maxWidth: 600 }}>
            Article 14 asks that a human can oversee, intervene, and stop a high-risk system. EMILIA provides
            one enforceable evidence mechanism for that program; it does not determine whether the complete
            oversight design is appropriate or proportionate.
          </p>
          <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
            {[
              ['Week 1 — Inventory', 'List every irreversible action your system can take. Each becomes a canonical action.'],
              ['Week 2 — Observe', 'Run the Gate in observation mode and compare its proposed refusals with the deployment’s approved risk controls. Observation is not enforcement.'],
              ['Week 3 — Enforce + sign-off', 'Turn on receipt requirements for approved action classes; route exact actions to enrolled human approvers.'],
              ['Week 4 — Evidence', 'Export receipts and the evidence log so an assessor can verify integrity and authorization bindings independently.'],
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
              ['/briefs/emilia-declaration-to-proof.pdf', 'Declaration to proof (PDF)'],
              ['/briefs/emilia-jtc21-human-oversight-contribution.pdf', 'JTC21 technical input (PDF)'],
              ['/briefs/emilia-article14-evidence-checklist.pdf', 'Article 14 evidence checklist (PDF)'],
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
            <h2 style={styles.h2}>Why evidence quality matters</h2>
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
                  AI Act&apos;s highest fine tier — not the default for every infringement
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
                  Highest percentage tier; applicable fine depends on the infringement
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
                  Current application date for Annex III high-risk rules
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
            Outside the EU, federal procurement policy and state measures create
            related governance pressure, but they do not impose one identical
            pre-execution requirement. EP publishes a separate NIST AI RMF mapping
            so each deployment can assess the relevant framework on its own terms.
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
              Evidence readiness begins before the deadline.
            </h2>
            <p style={{ ...styles.body, maxWidth: 540, margin: '0 auto 28px' }}>
              Start with one consequential action and one evidence question.
              Apache 2.0, self-hostable, with public verification code.
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
