/**
 * Human-Control landing page — the verifiable "meaningful human control" surface.
 * Client component (matches the vertical-page pattern); metadata lives in layout.js.
 *
 * @license Apache-2.0
 */
'use client';

import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const EASE = [0.23, 1, 0.32, 1] as const;

const reveal = (delay = 0) => ({
  initial: { opacity: 0, y: 18 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-40px' },
  transition: { duration: 0.58, delay, ease: EASE },
});

// Control regimes — the authorization boundary, not per-cycle approval.
const MODES = [
  {
    tag: 'Fresh-decision profile',
    line: 'One decision over one exact action.',
    body: 'When the buyer-pinned policy requires fresh human authority, an enrolled credential '
      + 'approves, declines, amends, or rejects the exact action. On a completely mediated '
      + 'covered path, missing required evidence refuses provider entry.',
  },
  {
    tag: 'Bounded-mandate profile',
    line: 'One finite envelope for unattended work.',
    body: 'A human or institution defines a bounded operating mandate such as action class, '
      + 'target set, budget, and time window. Agents may work unattended inside it; missing, '
      + 'stale, exhausted, or wider authority fails closed or returns to the authority source.',
  },
];

// Mission requirement -> shipped EMILIA mechanism.
const MAP = [
  ['An accountable approval credential — not a shared console assertion', 'Device-bound signoff plus a buyer-pinned approver directory'],
  ['Two-person or separation-of-duties policy', 'Quorum over distinct enrolled credentials under pinned roles'],
  ['Authority bounded by rules of engagement', 'Monotonic delegation constraints + signed ROE / policy reference'],
  ['The order was current, not a stale standing authorization', 'Validity window + observed-evidence freshness (fail-closed)'],
  ['Revoke or halt an autonomous envelope', 'Revocation + continuous evaluation'],
  ['Disconnected verification requirements', 'Offline receipt verification under buyer-pinned trust; deployment remains separate'],
  ['Missing required human evidence', 'No provider entry on a completely mediated covered path'],
];

// Review contexts. These references do not mandate EMILIA or establish compliance.
const DOCTRINE = [
  {
    ref: 'DoD Directive 3000.09',
    burden: 'One policy context for reviewing how human judgment, traceability, and governance are evidenced.',
    ep: 'An EMILIA receipt can supply scoped credential and exact-action evidence for an authorized review. It does not prove meaningful judgment, lawful use, or directive compliance.',
  },
  {
    ref: 'EU AI Act · Article 14',
    burden: 'One legal oversight context that a buyer and its counsel may map to a system-specific control design.',
    ep: 'EMILIA can preserve action-bound decision evidence when required by the local profile. It does not identify a natural person by itself or establish legal compliance.',
  },
  {
    ref: 'NIST AI RMF',
    burden: 'A voluntary risk-management framework that can inform governance and evidence procedures.',
    ep: 'Scoped EMILIA evidence can support a buyer-selected procedure. NIST does not mandate EMILIA, and the receipt is not an assessment result.',
  },
  {
    ref: 'UN CCW · LAWS',
    burden: 'An international policy discussion in which human control and accountability remain contested concepts.',
    ep: 'EMILIA can make one narrow authorization artifact independently checkable. It does not resolve the broader policy or legal question.',
  },
];

export default function HumanControlPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Human Control" />
      <main>

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: EASE }}
        >
          <div style={{ ...styles.eyebrow, color: color.gold }}>
            Verifiable human-decision evidence · for autonomous action
          </div>
          <h1 style={styles.h1Large}>
            Make exact-action human<br />decision evidence<br />independently checkable.
          </h1>
          <p style={{ ...styles.body, maxWidth: 600, fontSize: 18, color: color.t2 }}>
            EMILIA Approver can capture an enrolled credential&apos;s decision over an exact action
            when a buyer-pinned mandate or policy requires fresh human authority. The resulting
            evidence can be verified under pinned trust without treating it as proof of civil
            identity, comprehension, legality, wisdom, or successful effect. Agents may otherwise
            work unattended inside a finite operating mandate.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.18, ease: EASE }}
          style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}
        >
          <a href="/pilot" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
          <a href="/demo" className="ep-cta" style={cta.secondary}>See the receipt verify offline</a>
        </motion.div>
      </section>

      {/* The evidence gap */}
      <section style={{ ...styles.section, paddingTop: 8, paddingBottom: 48 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>The evidence gap</div>
          <h2 style={styles.h2}>The hard problem isn&apos;t the policy. It&apos;s the proof.</h2>
          <p style={{ ...styles.body, maxWidth: 640, color: color.t2 }}>
            Some systems preserve only session or application logs, leaving a reviewer to infer
            which credential decided over which exact action and policy. EMILIA offers an
            action-bound artifact that can be checked under the relying party&apos;s pinned trust
            profile. Whether that artifact is sufficient remains a local authorization and review decision.
          </p>
        </motion.div>
      </section>

      {/* Control modes */}
      <section style={{ ...styles.section, ...styles.sectionAlt, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>At the authorization boundary</div>
          <h2 style={styles.h2}>Not every cycle. The moments that matter.</h2>
          <p style={{ ...styles.body, maxWidth: 620, color: color.t2, marginBottom: 32 }}>
            EMILIA does not require a human for every cycle. A finite operating mandate permits
            unattended work inside its bounds; fresh human decision evidence is one optional
            requirement for selected actions or exceptions.
          </p>
        </motion.div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {MODES.map((m, i) => (
            <motion.div key={m.tag} {...reveal(i * 0.08)}
              style={{ ...styles.card, padding: 26 }}>
              <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.gold }}>
                {m.tag}
              </div>
              <div style={{ fontSize: 20, fontWeight: 700, color: color.t1, margin: '10px 0 12px' }}>{m.line}</div>
              <p style={{ ...styles.body, color: color.t2, margin: 0 }}>{m.body}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Mission requirement -> EMILIA mechanism */}
      <section style={{ ...styles.section, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Buyer-pinned profile</div>
          <h2 style={styles.h2}>Available mechanisms, mapped without collapsing the claims.</h2>
        </motion.div>
        <div style={{ marginTop: 24, border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden' }}>
          {MAP.map(([req, mech], i) => (
            <motion.div key={req} {...reveal(i * 0.04)}
              style={{
                display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16,
                padding: '18px 22px',
                borderTop: i === 0 ? 'none' : `1px solid ${color.border}`,
                background: i % 2 ? color.bg : color.card,
              }}>
              <div style={{ ...styles.body, color: color.t2, margin: 0 }}>{req}</div>
              <div style={{ ...styles.body, color: color.t1, margin: 0, fontWeight: 600 }}>{mech}</div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Doctrine */}
      <section style={{ ...styles.section, ...styles.sectionAlt, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Review contexts</div>
          <h2 style={styles.h2}>Four contexts a buyer may evaluate with counsel and authorized reviewers.</h2>
        </motion.div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginTop: 24 }}>
          {DOCTRINE.map((d, i) => (
            <motion.div key={d.ref} {...reveal(i * 0.06)} style={{ ...styles.card, padding: 24 }}>
              <div style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 700, color: color.gold, letterSpacing: 0.5 }}>{d.ref}</div>
              <p style={{ ...styles.body, color: color.t2, fontStyle: 'italic', margin: '12px 0' }}>{d.burden}</p>
              <p style={{ ...styles.body, color: color.t1, margin: 0 }}>{d.ep}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* What the artifact establishes / does not */}
      <section style={{ ...styles.section, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Stated plainly</div>
          <h2 style={styles.h2}>It verifies a pinned signing ceremony. Not authorization by itself.</h2>
          <p style={{ ...styles.body, maxWidth: 620, color: color.t2, marginBottom: 28 }}>
            Serious programs will ask exactly where the line is. So we draw it.
          </p>
        </motion.div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          <motion.div {...reveal()} style={{ ...styles.card, padding: 26, borderTop: `2px solid ${color.green}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.green, marginBottom: 12 }}>Establishes under the pinned profile</div>
            <p style={{ ...styles.body, color: color.t2, margin: 0 }}>
              Under the relying party&apos;s pinned directory, key, ceremony, policy, and time profile,
              the enrolled credential produced this signed decision over these exact bytes. The
              verifier can detect action substitution and evaluate the profile offline where its
              trust inputs are available. Separate systems determine authority sufficiency and admission.
            </p>
          </motion.div>
          <motion.div {...reveal(0.08)} style={{ ...styles.card, padding: 26, borderTop: `2px solid ${color.t3}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.t3, marginBottom: 12 }}>Does not prove</div>
            <p style={{ ...styles.body, color: color.t2, margin: 0 }}>
              A natural person&apos;s civil identity, comprehension, freedom from coercion, legal
              authority, or that the action was lawful, wise, safe, successful, or physically
              carried out. A receipt is evidence under one pinned profile, not a universal conclusion.
            </p>
          </motion.div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ ...styles.section, ...styles.sectionAlt, paddingTop: 64, paddingBottom: 72, textAlign: 'center' }}>
        <motion.div {...reveal()}>
          <h2 style={{ ...styles.h2, maxWidth: 720, margin: '0 auto 16px' }}>
            Make exact-action human decision evidence checkable.
          </h2>
          <p style={{ ...styles.body, maxWidth: 560, margin: '0 auto 28px', color: color.t2 }}>
            {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} for {PROTECTED_WORKFLOW_PILOT.durationLabel} to assess one buyer-selected consequence
            boundary. Finance operations remains the initial offered profile; human-decision evidence
            is an eligible solution profile for fit review. Validation uses synthetic, read-only,
            sandbox, or shadow evidence only. The pilot uses no
            production provider credentials or actuation. Production requires a separate Gate
            Implementation after the buyer accepts the boundary. No compliance conclusion is included.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="/pilot" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
            <a href="/docs" className="ep-cta" style={cta.secondary}>Read PIP-013 &amp; the crosswalk</a>
          </div>
        </motion.div>
      </section>
      </main>

      <SiteFooter />
    </div>
  );
}
