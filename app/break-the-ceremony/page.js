'use client';

/**
 * /break-the-ceremony — public red-team challenge.
 * @license Apache-2.0
 *
 * Credibility play: publish the formal guarantees, dare the world to break them,
 * commit to publishing every confirmed break + fix. Guarantee names are the REAL
 * source invariants from formal/ep_handshake.cfg (verified). The live key-minting
 * form is intentionally a "coming soon" state until the isolated challenge
 * instance is provisioned — we do NOT point a key form at production.
 */

import Link from 'next/link';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import ProofBlock from '@/components/ProofBlock';
import { styles, color, font, radius, cta } from '@/lib/tokens';

const EASE = [0.23, 1, 0.32, 1];
const reveal = (d = 0) => ({
  initial: { opacity: 0, y: 18 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-40px' },
  transition: { duration: 0.55, delay: d, ease: EASE },
});

const GUARANTEES = [
  {
    claim: 'A signed authorization can be consumed exactly once. Replay it and it must be rejected.',
    invariant: 'ConsumeOnceSafety',
    breakIf: 'You consume the same authorization twice and both succeed.',
  },
  {
    claim: 'You cannot fabricate a committed decision outside the ceremony — no write bypasses the protocol.',
    invariant: 'WriteBypassSafety',
    breakIf: 'You produce a record the verifier accepts that was never issued by the ceremony.',
  },
  {
    claim: 'No actor can approve, consume, or contest its own action. Separation of duties holds.',
    invariant: 'SelfContestImpossible',
    breakIf: 'The same identity both initiates and approves a high-risk action and it commits.',
  },
  {
    claim: 'Once an action is committed or refused, that outcome is terminal — it cannot be silently flipped.',
    invariant: 'TerminalStateIrreversibility',
    breakIf: 'You move a committed or refused action back to a pending/allowed state.',
  },
];

export default function BreakTheCeremonyPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Challenge" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 96, paddingBottom: 32 }}>
        <div style={{ ...styles.eyebrow, color: color.gold, display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: color.green, display: 'inline-block' }} />
          Open challenge · 0 confirmed breaks
        </div>
        <h1 style={styles.h1Large}>Break the ceremony.</h1>
        <p style={{ ...styles.body, maxWidth: 620, fontSize: 18, color: color.t2 }}>
          We claim EMILIA’s authorization ceremony cannot be replayed, forged, self-approved, or
          reversed — and we proved it with a model checker. Don’t take our word for it. The protocol
          is open. The receipts are public. <strong style={{ color: color.t1 }}>Try to break it.</strong>
        </p>
        <p style={{ ...styles.body, maxWidth: 620, fontSize: 14, color: color.t3 }}>
          Safety infrastructure earns trust by surviving attack in the open. Every confirmed break —
          and its fix — gets published here, with credit.
        </p>
      </section>

      {/* Guarantees */}
      <section style={styles.section}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>The four guarantees</div>
          <h2 style={styles.h2}>What counts as a break</h2>
        </motion.div>
        <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
          {GUARANTEES.map((g, i) => (
            <motion.div
              key={g.invariant}
              {...reveal(i * 0.05)}
              style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, background: color.card, padding: 20 }}
            >
              <div style={{ fontFamily: font.sans, fontSize: 15, fontWeight: 600, color: color.t1, lineHeight: 1.5 }}>{g.claim}</div>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, marginTop: 10 }}>{g.invariant}</div>
              <div
                style={{
                  marginTop: 12,
                  paddingTop: 12,
                  borderTop: `1px solid ${color.border}`,
                  fontFamily: font.sans,
                  fontSize: 13,
                  color: color.t2,
                  lineHeight: 1.5,
                }}
              >
                <span style={{ color: color.red, fontFamily: font.mono, fontSize: 11 }}>BREAK IF: </span>
                {g.breakIf}
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Proof */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <ProofBlock />
        </div>
      </section>

      {/* Transparency contract */}
      <section style={styles.section}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Our commitment</div>
          <h2 style={styles.h2}>The transparency contract</h2>
          <ul style={{ marginTop: 16, paddingLeft: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              'Every confirmed break is published here within 7 days, with the attacker’s credit (or anonymous, your call).',
              'Every fix is published alongside it — the spec change, the code, and the new passing proof.',
              'The running tally above (confirmed breaks) is never silently reset.',
              'In scope: the authorization ceremony, the signed-receipt format, the consume gate, the verifier.',
              'Out of scope: DDoS, social engineering, third-party infra (Vercel/Supabase), and anything against production tenant data.',
            ].map((t, i) => (
              <li key={i} style={{ display: 'flex', gap: 10, fontFamily: font.sans, fontSize: 15, color: color.t2, lineHeight: 1.6 }}>
                <span style={{ color: color.gold, flexShrink: 0 }}>—</span>
                {t}
              </li>
            ))}
          </ul>
        </motion.div>
      </section>

      {/* Submit — coming soon (isolated instance pending) */}
      <section style={styles.sectionAlt}>
        <div style={{ ...styles.section, textAlign: 'center', paddingTop: 56, paddingBottom: 64 }}>
          <motion.div {...reveal()}>
            <div style={styles.eyebrow}>Get started</div>
            <h2 style={{ ...styles.h2, fontSize: 28 }}>Start swinging</h2>
            <p style={{ ...styles.body, maxWidth: 560, margin: '0 auto 24px' }}>
              The protocol, the SDK, and a public demo receipt are live now — attack those directly.
              Scoped challenge keys against an isolated instance open shortly; report anything you
              find to the address below in the meantime.
            </p>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
              <Link href="/r/example" className="ep-cta" style={cta.primary}>Inspect a live receipt →</Link>
              <Link href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the spec</Link>
            </div>
            <p style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginTop: 24 }}>
              Report a break: <a href="mailto:security@emiliaprotocol.ai" style={{ color: color.gold }}>security@emiliaprotocol.ai</a>
            </p>
          </motion.div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
