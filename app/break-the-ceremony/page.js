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

/** @type {[number, number, number, number]} */
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

const PROVES = [
  'A named human — or a quorum of distinct humans — signed THIS exact action (amount, payee, target), not a session and not a scope.',
  'Anyone can verify it offline, with no account and no trust in the operator or in EMILIA.',
  'Tamper with one byte of the authorized action and verification fails.',
  'The authorization is consumable exactly once — replays are rejected.',
  'Missing, invalid, expired, or wrong-approver → the action does not proceed. Fail-closed by default.',
];

const NOT_PROVES = [
  'That the decision was correct or wise. EP proves authorization, not judgment.',
  'Real-world identity beyond the enrollment layer. A receipt proves the enrolled key signed; identity proofing is a separate, stated layer.',
  'The negative of an absence you were never handed. One-time-use and revocation freshness are server-state — ask the operator for the consumption record and any signed revocation (itself offline-verifiable).',
];

// Each row: the attack, why it fails, and what backs the claim. These are the
// classes a serious reviewer will reach for first.
const ATTACK_MATRIX = [
  ['Replay a captured authorization', 'One-time consume enforced under a row lock; the second attempt is rejected.', 'TLA+ ConsumeOnceSafety · binding_already_consumed vectors'],
  ['Forge a receipt the verifier accepts', 'Asymmetric signature over the canonical action hash — no trusted issuer key, no acceptance.', 'tri-language negative conformance vectors'],
  ['Tamper with the approved action', 'The signature covers SHA-256(JCS(action)); any altered field breaks challenge_binding.', 'verifier conformance suite (JS/Py/Go)'],
  ['Attach your signoff to someone else’s receipt', 'Signoff requests are bound to the receipt creator — a leaked receipt_id is not an approval attachment point.', 'creator-bound signoff (see “what we caught”)'],
  ['Approve with the wrong human', 'Approvals bind to the intended approver; a quorum requires distinct, enrolled humans.', '481 security/adversarial tests'],
  ['Proceed with no receipt', 'The consume gate refuses any governed action without a valid bound approval. Fail-closed.', 'consume-gate tests'],
  ['Satisfy a quorum with the wrong set', 'Quorum re-verified at consume: distinct humans, roles, order, window, action-binding, signatures.', 'EP-QUORUM cross-language conformance'],
];

export default function BreakTheCeremonyPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Challenge" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 96, paddingBottom: 32 }}>
        <div style={{ ...styles.eyebrow, color: color.gold, display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: color.green, display: 'inline-block' }} />
          Open challenge · 0 confirmed external breaks
        </div>
        <h1 style={styles.h1Large}>Break the ceremony.</h1>
        <p style={{ ...styles.body, maxWidth: 660, fontSize: 15, color: color.t2 }}>
          EMILIA is the authorization-receipt layer for irreversible AI-agent actions: no valid
          human-signed receipt, no execution &mdash; and afterward, anyone can verify who approved
          exactly what, without trusting us. This page is where you try to prove that wrong.
        </p>
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

      {/* What it proves / does not prove */}
      <section style={styles.section}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Bounded claims</div>
          <h2 style={styles.h2}>What a receipt proves — and what it doesn’t</h2>
          <p style={{ ...styles.body, maxWidth: 640 }}>
            The honesty is the credential. Here is exactly where the guarantee starts and stops.
          </p>
        </motion.div>
        <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
          <motion.div {...reveal(0.05)} style={{ border: `1px solid ${color.border}`, borderTop: `3px solid ${color.green}`, borderRadius: radius.base, background: color.card, padding: 22 }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1.2, textTransform: 'uppercase', color: color.green, fontWeight: 700, marginBottom: 12 }}>What it proves</div>
            <ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {PROVES.map((t, i) => (
                <li key={i} style={{ display: 'flex', gap: 9, fontSize: 14, color: color.t2, lineHeight: 1.55 }}>
                  <span style={{ color: color.green, flexShrink: 0 }}>&#10003;</span>{t}
                </li>
              ))}
            </ul>
          </motion.div>
          <motion.div {...reveal(0.1)} style={{ border: `1px solid ${color.border}`, borderTop: `3px solid ${color.t3}`, borderRadius: radius.base, background: color.card, padding: 22 }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1.2, textTransform: 'uppercase', color: color.t3, fontWeight: 700, marginBottom: 12 }}>What it does not prove</div>
            <ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {NOT_PROVES.map((t, i) => (
                <li key={i} style={{ display: 'flex', gap: 9, fontSize: 14, color: color.t2, lineHeight: 1.55 }}>
                  <span style={{ color: color.t3, flexShrink: 0 }}>&mdash;</span>{t}
                </li>
              ))}
            </ul>
          </motion.div>
        </div>
      </section>

      {/* Attack matrix */}
      <section style={styles.section}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>The attack matrix</div>
          <h2 style={styles.h2}>Attacks we reject — and what backs each claim</h2>
        </motion.div>
        <motion.div {...reveal(0.05)} style={{ marginTop: 22, border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden' }}>
          {ATTACK_MATRIX.map(([attack, why, backed], i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.4fr 1fr', gap: 18, padding: '16px 20px', background: color.card, borderTop: i ? `1px solid ${color.border}` : 'none' }}>
              <div style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 600, color: color.t1, lineHeight: 1.45 }}>{attack}</div>
              <div style={{ fontSize: 13.5, color: color.t2, lineHeight: 1.55 }}>{why}</div>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, lineHeight: 1.5 }}>{backed}</div>
            </div>
          ))}
        </motion.div>
        <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 14 }}>
          Run the negative cases yourself: <span style={{ fontFamily: font.mono, color: color.t2 }}>npx @emilia-protocol/crash-test</span> issues a genuine receipt, verifies it offline, then shows the forged copy being rejected.
        </p>
      </section>

      {/* What we caught — the IDOR, found and fixed */}
      <section style={styles.section}>
        <motion.div {...reveal()} style={{ border: `1px solid ${color.gold}`, background: '#FFFBEB', borderRadius: radius.base, padding: '24px 26px' }}>
          <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1.2, textTransform: 'uppercase', color: color.gold, fontWeight: 700, marginBottom: 10 }}>What we caught — and closed</div>
          <h2 style={{ ...styles.h2, fontSize: 22, marginTop: 0 }}>A real authority-binding bug, found in red-team and fixed</h2>
          <p style={{ ...styles.body, maxWidth: 680, marginBottom: 10 }}>
            In an adversarial pass we found that a leaked <span style={{ fontFamily: font.mono, fontSize: 13 }}>receipt_id</span> could
            let another authenticated actor attach their own signoff flow to someone else’s receipt and
            self-approve it. <strong style={{ color: color.t1 }}>The cryptography was sound; the authority-binding glue was not.</strong>
          </p>
          <p style={{ ...styles.body, maxWidth: 680, margin: 0 }}>
            We closed it by binding signoff requests to the receipt creator and approvals to the
            intended approver — now row four of the matrix above. We publish this on purpose: the danger
            zone for systems like this is authority binding and deployment semantics, not the math, and
            finding it in the open is the point of this page.
          </p>
        </motion.div>
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
              Report a break: <a href="mailto:team@emiliaprotocol.ai" style={{ color: color.gold }}>team@emiliaprotocol.ai</a>
            </p>
          </motion.div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
