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
import { styles, cta, color, font, radius } from '@/lib/tokens';

const EASE = [0.23, 1, 0.32, 1];

const reveal = (delay = 0) => ({
  initial: { opacity: 0, y: 18 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-40px' },
  transition: { duration: 0.58, delay, ease: EASE },
});

// Control regimes — the authorization boundary, not per-cycle approval.
const MODES = [
  {
    tag: 'Human-in-the-loop',
    line: 'One receipt per action.',
    body: 'A human authorizes each consequential action before it executes. No valid '
      + 'receipt bound to the exact action — the system fails closed. For the highest-'
      + 'consequence decisions where machine tempo allows a human gate.',
  },
  {
    tag: 'Human-on-the-loop',
    line: 'One receipt per envelope.',
    body: 'A human authorizes a bounded engagement envelope — effect class, target set, '
      + 'geofence, time window — and retains a halt authority. Autonomy operates only '
      + 'inside the envelope, only while unrevoked and unexpired.',
  },
];

// Mission requirement -> shipped EMILIA mechanism.
const MAP = [
  ['A named, accountable human — not a shared console login', 'Device-bound signoff (WebAuthn + user verification)'],
  ['Two-person rule / launch authority', 'Quorum — m-of-n distinct humans, ordered chain'],
  ['Authority bounded by rules of engagement', 'Monotonic delegation constraints + signed ROE / policy reference'],
  ['The order was current, not a stale standing authorization', 'Validity window + observed-evidence freshness (fail-closed)'],
  ['Revoke or halt an autonomous envelope', 'Revocation + continuous evaluation'],
  ['Contested, disconnected, classified operations', 'Fully offline verification; air-gap deployment'],
  ['No verified human authorization → no effect', 'Fail-closed enforcement — "no receipt, no execution"'],
];

// Governing instruments that require human control but can't currently prove it.
const DOCTRINE = [
  {
    ref: 'DoD Directive 3000.09',
    burden: '"Appropriate levels of human judgment over the use of force" — plus auditable, traceable, governable AI.',
    ep: 'A receipt proves a named human — or two-person quorum — authorized the exact engagement, within a defined envelope, verifiable offline by an inspector general or coalition partner without trusting the operator. (The primary U.S. defense hook.)',
  },
  {
    ref: 'EU AI Act · Article 14',
    burden: 'Civilian high-risk AI must be "effectively overseen by natural persons" who can decide not to use it and intervene.',
    ep: 'The receipt proves a natural person authorized the action; fail-closed enforcement is the "decide not to use it"; revocation is the stop button. (Civilian tailwind — the Act excludes exclusively military/defense systems; there, DoD 3000.09 governs.)',
  },
  {
    ref: 'NIST AI RMF',
    burden: 'Documented, auditable human oversight across GOVERN / MAP / MEASURE / MANAGE.',
    ep: 'Receipts are the auditable record of who authorized what, under which policy — verifiable, not asserted.',
  },
  {
    ref: 'UN CCW · LAWS',
    burden: 'The entire debate turns on demonstrating "meaningful human control."',
    ep: 'EMILIA turns meaningful human control from doctrine into a cryptographic artifact a third party can check.',
  },
];

export default function HumanControlPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Human Control" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: EASE }}
        >
          <div style={{ ...styles.eyebrow, color: color.gold }}>
            Verifiable human-authorization evidence · for autonomous action
          </div>
          <h1 style={styles.h1Large}>
            Everyone requires a human<br />in the loop.<br />No one can prove it.
          </h1>
          <p style={{ ...styles.body, maxWidth: 600, fontSize: 18, color: color.t2 }}>
            Doctrine and law — DoD Directive 3000.09, EU AI Act Article 14, NIST AI RMF —
            all mandate meaningful human control over autonomous action. None of them
            provides an artifact that <strong>proves it</strong>. Today that proof is a log
            the operator controls: forgeable, backfillable, rubber-stampable. EMILIA Protocol
            produces an <strong>offline-verifiable receipt</strong> that a named human
            authorized the exact action — checkable by a third party without trusting the
            operator. EP turns human oversight from a policy promise into a cryptographic
            artifact — no irreversible autonomous action without a verifiable human receipt.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.18, ease: EASE }}
          style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}
        >
          <a href="/contact" className="ep-cta" style={cta.primary}>Request a lighthouse pilot</a>
          <a href="/demo" className="ep-cta" style={cta.secondary}>See the receipt verify offline</a>
        </motion.div>
      </section>

      {/* The evidence gap */}
      <section style={{ ...styles.section, paddingTop: 8, paddingBottom: 48 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>The evidence gap</div>
          <h2 style={styles.h2}>The hard problem isn&apos;t the policy. It&apos;s the proof.</h2>
          <p style={{ ...styles.body, maxWidth: 640, color: color.t2 }}>
            When an autonomous system acts, the record that a named, accountable human
            authorized <em>that exact</em> engagement — at the right scope, currently, under
            the right authority — is an operator-owned log. After an incident, no inspector
            general, court, coalition partner, or treaty-verification regime can confirm it
            without trusting the very operator under review. EMILIA closes exactly that gap.
          </p>
        </motion.div>
      </section>

      {/* Control modes */}
      <section style={{ ...styles.section, ...styles.sectionAlt, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>At the authorization boundary</div>
          <h2 style={styles.h2}>Not every cycle. The moments that matter.</h2>
          <p style={{ ...styles.body, maxWidth: 620, color: color.t2, marginBottom: 32 }}>
            Per-cycle human approval is incompatible with machine tempo. EMILIA issues
            receipts at the points where a human grants, scopes, or renews autonomous authority.
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
          <div style={styles.eyebrow}>It already does what the mission needs</div>
          <h2 style={styles.h2}>Shipped mechanisms, mapped to the requirement.</h2>
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
          <div style={styles.eyebrow}>The requirement is already written</div>
          <h2 style={styles.h2}>Four instruments mandate it. None can prove it.</h2>
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

      {/* What it proves / does not */}
      <section style={{ ...styles.section, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Stated plainly</div>
          <h2 style={styles.h2}>It proves authorization. Not wisdom.</h2>
          <p style={{ ...styles.body, maxWidth: 620, color: color.t2, marginBottom: 28 }}>
            Serious programs will ask exactly where the line is. So we draw it.
          </p>
        </motion.div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          <motion.div {...reveal()} style={{ ...styles.card, padding: 26, borderTop: `2px solid ${color.green}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.green, marginBottom: 12 }}>Proves</div>
            <p style={{ ...styles.body, color: color.t2, margin: 0 }}>
              A specific, pinned human — or quorum of distinct humans — authorized this exact
              action or bounded envelope, at a stated scope, within a validity window, under a
              referenced authority. Given signature soundness and uncompromised signing keys,
              the record cannot be forged, replayed, re-targeted, or repudiated, and anyone can
              verify it offline.
            </p>
          </motion.div>
          <motion.div {...reveal(0.08)} style={{ ...styles.card, padding: 26, borderTop: `2px solid ${color.t3}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.t3, marginBottom: 12 }}>Does not prove</div>
            <p style={{ ...styles.body, color: color.t2, margin: 0 }}>
              That the human <em>understood</em> the action (a display / WYSIWYS concern), that
              they were uncoerced, or that the action was lawful or wise. EMILIA is the evidence
              of authorization — a necessary, not sufficient, condition for meaningful human
              control. Over-claiming is how accountability tech loses trust.
            </p>
          </motion.div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ ...styles.section, ...styles.sectionAlt, paddingTop: 64, paddingBottom: 72, textAlign: 'center' }}>
        <motion.div {...reveal()}>
          <h2 style={{ ...styles.h2, maxWidth: 720, margin: '0 auto 16px' }}>
            Make meaningful human control checkable.
          </h2>
          <p style={{ ...styles.body, maxWidth: 560, margin: '0 auto 28px', color: color.t2 }}>
            A lighthouse pilot: deploy EMILIA in observe-mode on one human-control boundary,
            produce the verifiable evidence trail, and demonstrate the compliance artifact in a
            tabletop review. No production change. Offline and air-gap ready. Apache-2.0.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="/contact" className="ep-cta" style={cta.primary}>Start a pilot conversation</a>
            <a href="/docs" className="ep-cta" style={cta.secondary}>Read PIP-013 &amp; the crosswalk</a>
          </div>
        </motion.div>
      </section>

      <SiteFooter />
    </div>
  );
}
