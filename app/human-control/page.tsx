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
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

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
    tag: 'Human-in-the-loop',
    line: 'Fresh approval for the selected action.',
    body: 'When local policy requires a fresh decision, Gate checks an accepted enrolled '
      + 'approver credential bound to the exact action. On a completely mediated covered '
      + 'path, missing or invalid required evidence means no provider entry.',
  },
  {
    tag: 'Human-on-the-loop',
    line: 'Finite authority for unattended work.',
    body: 'An accepted authority source can define a bounded envelope — effect class, target '
      + 'set, geofence, time window, limits, and exception rules. Gate admits only matching '
      + 'actions while that authority remains current and unexhausted.',
  },
];

// Mission requirement -> shipped EMILIA mechanism.
const MAP = [
  ['An accountable approver credential, not a shared session', 'Device-bound signoff plus a relying-party-pinned approver directory and role policy'],
  ['Two-person rule / launch authority', 'Quorum over distinct enrolled approver credentials with ordered-chain support'],
  ['Authority bounded by rules of engagement', 'Monotonic delegation constraints + signed ROE / policy reference'],
  ['The order was current, not a stale standing authorization', 'Validity window + observed-evidence freshness (fail-closed)'],
  ['Revoke or halt an autonomous envelope', 'Revocation + continuous evaluation'],
  ['Contested, disconnected, classified operations', 'Offline verification and an air-gap-capable deployment pattern'],
  ['No accepted fresh approval when policy requires it', 'No provider entry on a completely mediated covered path'],
];

// Reference points for customer-authored mappings, not legal-compliance claims.
const REFERENCE_POINTS = [
  {
    ref: 'DoD Directive 3000.09',
    burden: 'Programs define their own human-judgment, authorization, review, and system-safety procedures under the controlling directive and implementation guidance.',
    ep: 'EMILIA can preserve exact-action or bounded-envelope approval evidence for a program-authored procedure. It does not determine whether that procedure satisfies the directive.',
  },
  {
    ref: 'EU AI Act · Article 14',
    burden: 'Organizations assessing Article 14 need to document how their complete high-risk AI system enables the applicable human-oversight measures.',
    ep: 'An action-bound approval or refusal can support that evidence file. A receipt alone does not establish natural-person identity, effective oversight, system classification, or legal compliance.',
  },
  {
    ref: 'NIST AI RMF',
    burden: 'The framework gives organizations a vocabulary for governing, mapping, measuring, and managing AI risk.',
    ep: 'EMILIA publishes a control-to-evidence mapping and can preserve action-level inputs for an organization\'s own assessment. The mapping is not certification or a compliance verdict.',
  },
  {
    ref: 'UN CCW · LAWS',
    burden: 'Discussions about autonomous weapons include contested questions about human judgment, responsibility, predictability, and control.',
    ep: 'A signed action or envelope record can answer one evidentiary question: what a pinned credential signed. It does not resolve the policy or legal debate.',
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
            Verifiable human-authorization evidence · for autonomous action
          </div>
          <h1 style={styles.h1Large}>
            Make the approval boundary<br />checkable after the fact.
          </h1>
          <p style={{ ...styles.body, maxWidth: 600, fontSize: 18, color: color.t2 }}>
            Oversight rules differ by system, jurisdiction, and consequence. EMILIA does not
            decide when a human must act. It gives the relying party a way to require an
            enrolled approver credential over the exact action or a finite operating mandate,
            then verify that artifact offline under pinned keys and rules. On a completely
            mediated covered path, Gate refuses provider entry when the required evidence is missing.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.18, ease: EASE }}
          style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}
        >
          <a href="/pilot?v=human-control" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
          <a href="/demo" className="ep-cta" style={cta.secondary}>See the receipt verify offline</a>
        </motion.div>
      </section>

      {/* The evidence gap */}
      <section style={{ ...styles.section, paddingTop: 8, paddingBottom: 48 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>The evidence gap</div>
          <h2 style={styles.h2}>The hard problem isn&apos;t the policy. It&apos;s the evidence.</h2>
          <p style={{ ...styles.body, maxWidth: 640, color: color.t2 }}>
            A session log can show who was logged in without preserving the exact action,
            accepted authority, approver credential, policy, and validity window as one
            portable record. EMILIA makes those stated inputs independently re-performable.
            The relying party still owns the approver directory, role assignment, policy,
            and conclusion drawn from that evidence.
          </p>
        </motion.div>
      </section>

      {/* Control modes */}
      <section style={{ ...styles.section, ...styles.sectionAlt, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>At the authorization boundary</div>
          <h2 style={styles.h2}>Not every cycle. The moments that matter.</h2>
          <p style={{ ...styles.body, maxWidth: 620, color: color.t2, marginBottom: 32 }}>
            A finite operating mandate can let an agent work unattended inside clear limits.
            Fresh approval is reserved for the actions or exceptions the buyer&apos;s policy selects.
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
          <div style={styles.eyebrow}>Evidence mechanisms</div>
          <h2 style={styles.h2}>Map each local requirement to a checkable artifact.</h2>
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
          <div style={styles.eyebrow}>Reference points</div>
          <h2 style={styles.h2}>Use the evidence in an authorized review, not as a shortcut.</h2>
        </motion.div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginTop: 24 }}>
          {REFERENCE_POINTS.map((d, i) => (
            <motion.div key={d.ref} {...reveal(i * 0.06)} style={{ ...styles.card, padding: 24 }}>
              <div style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 700, color: color.gold, letterSpacing: 0.5 }}>{d.ref}</div>
              <p style={{ ...styles.body, color: color.t2, fontStyle: 'italic', margin: '12px 0' }}>{d.burden}</p>
              <p style={{ ...styles.body, color: color.t1, margin: 0 }}>{d.ep}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* What it verifies / does not establish */}
      <section style={{ ...styles.section, paddingTop: 56, paddingBottom: 56 }}>
        <motion.div {...reveal()}>
          <div style={styles.eyebrow}>Stated plainly</div>
          <h2 style={styles.h2}>It verifies a signed authorization artifact. Not wisdom.</h2>
          <p style={{ ...styles.body, maxWidth: 620, color: color.t2, marginBottom: 28 }}>
            Serious programs will ask exactly where the line is. So we draw it.
          </p>
        </motion.div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          <motion.div {...reveal()} style={{ ...styles.card, padding: 26, borderTop: `2px solid ${color.green}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.green, marginBottom: 12 }}>Verifies</div>
            <p style={{ ...styles.body, color: color.t2, margin: 0 }}>
              A specific enrolled credential — or quorum of distinct enrolled credentials —
              signed this exact action or bounded envelope, at a stated scope and within a
              validity window. Under the verifier&apos;s assumptions and the relying party&apos;s
              pinned keys, the signature and action binding can be checked offline. The relying
              party separately decides whether that credential was accepted for the required role.
            </p>
          </motion.div>
          <motion.div {...reveal(0.08)} style={{ ...styles.card, padding: 26, borderTop: `2px solid ${color.t3}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.t3, marginBottom: 12 }}>Does not prove</div>
            <p style={{ ...styles.body, color: color.t2, margin: 0 }}>
              The artifact does not establish the approver&apos;s civil identity, understanding,
              freedom from coercion, legal authority, or the wisdom or lawfulness of the action.
              It is one verifiable input to the relying party&apos;s broader control and review procedure.
            </p>
          </motion.div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ ...styles.section, ...styles.sectionAlt, paddingTop: 64, paddingBottom: 72, textAlign: 'center' }}>
        <motion.div {...reveal()}>
          <h2 style={{ ...styles.h2, maxWidth: 720, margin: '0 auto 16px' }}>
            Make required approval evidence checkable.
          </h2>
          <p style={{ ...styles.body, maxWidth: 560, margin: '0 auto 28px', color: color.t2 }}>
            {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel} · {PROTECTED_WORKFLOW_PILOT.workflowLabel}. Map the authority source, produce synthetic and read-only evidence, and run a tabletop re-performance. Production is separately scoped after buyer acceptance.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="/pilot?v=human-control" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
            <a href="/docs" className="ep-cta" style={cta.secondary}>Read PIP-013 &amp; the crosswalk</a>
          </div>
        </motion.div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
