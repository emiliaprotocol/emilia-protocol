'use client';

import Link from 'next/link';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import ProofBlock from '@/components/ProofBlock';
import { GATE_QUALIFICATION, PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';

const TEST_CASES = Number(proofStats.tests.total).toLocaleString('en-US');
const TAMARIN_OBLIGATIONS = String(proofStats.tamarin.verifiedObligations);
const TAMARIN_ATTACK_TRACES = String(proofStats.tamarin.deliberatelyUnsafeCounterexamples);
const SECURITY_CLAIMS = String(proofStats.securityCase.claims);
const CONFORMANCE_VECTORS = String(proofStats.conformance.vectors);

const EASE: readonly [number, number, number, number] = [0.23, 1, 0.32, 1];
const reveal = (delay = 0): Record<string, unknown> => ({
  initial: { opacity: 1, y: 16 },
  whileInView: { y: 0 },
  viewport: { once: true, margin: '-40px' },
  transition: { duration: 0.56, delay, ease: EASE },
});
const heroIn = (delay = 0): Record<string, unknown> => ({
  initial: { opacity: 1, y: 12 },
  animate: { y: 0 },
  transition: { duration: 0.58, delay, ease: EASE },
});

const C = ({ children }: { children: React.ReactNode }): React.ReactElement => (
  <div className="ep-home-container" style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px' }}>
    {children}
  </div>
);

const eyebrow: React.CSSProperties = {
  fontFamily: font.mono,
  fontSize: 10,
  letterSpacing: 2,
  textTransform: 'uppercase',
  color: color.gold,
  marginBottom: 16,
};

const PRODUCTS = [
  {
    label: 'Discover + map',
    title: 'Authority Brain',
    body: 'Free, local discovery of supported declared action surfaces and blind spots. The scanner proposes; the owner reviews. A map is not protection.',
    href: '/authority-brain',
    accent: color.green,
  },
  {
    label: 'Protect',
    title: 'EMILIA Gate',
    body: 'The commercial consequence firewall. Gate sits on a completely mediated, credential-owning executor path and admits one exact action once—or refuses.',
    href: '/gate',
    accent: color.gold,
  },
  {
    label: 'Prove',
    title: 'Open Protocol + Approver',
    body: 'Portable formats, offline verification, and an exact-action human or quorum decision. Evidence remains attributable to its native source.',
    href: '/protocol',
    accent: color.blue,
  },
  {
    label: 'Operate',
    title: 'Assurance Plane',
    body: 'Re-performance, evidence operations, integrations, support, and service levels. EMILIA supports the procedure; it does not issue the audit opinion.',
    href: '/assurance',
    accent: color.t2,
  },
];

const LIFECYCLE = [
  ['01', 'Bind the action', 'Freeze the canonical amount, target, record, tool call, material fields, and validity window.'],
  ['02', 'Verify the evidence', 'Check each required identity, qualification, approval, status, and policy artifact under the owner’s pinned trust inputs.'],
  ['03', 'Authorize locally', 'The resource owner decides whether this exact action may proceed. Evidence is never silently promoted into permission.'],
  ['04', 'Consume before entry', 'Gate durably takes the one-time authority before the credentialed adapter can enter the provider.'],
  ['05', 'Preserve the result', 'Record provider and observer evidence separately. Unknown stays unknown; any remedy is a new authorized action.'],
];

const OUTCOMES = [
  ['REFUSED', 'The protected adapter did not enter the provider.'],
  ['ADMITTED', 'Required authority was accepted and consumed. This is not proof of success.'],
  ['OBSERVED', 'A pinned provider or observer supplied the stated evidence. Scope remains explicit.'],
  ['INDETERMINATE', 'Provider entry may have occurred, but the result is unresolved. Never retry blindly.'],
];

const EXPANSION = [
  ['Money', 'Payment releases, beneficiary changes, treasury operations'],
  ['Code', 'Production deploys, credential rotations, permission escalation'],
  ['Records', 'Payer determinations, benefit routing, accountable overrides'],
  ['Infrastructure', 'Bounded energy commands and other high-consequence actuators'],
];

export default function HomePage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section className="ep-home-calm-hero" aria-labelledby="home-trust-thesis">
          <C>
            <motion.div className="ep-home-calm-copy" {...heroIn()}>
              <div className="ep-home-calm-kicker">
                EMILIA Gate <span>· Consequence firewall for AI agents</span>
              </div>
              <h1 id="home-trust-thesis">Let agents act. Keep authority exact.</h1>
              <p className="ep-home-calm-lede ep-home-lede-desktop">
                EMILIA Gate sits before money, code, permissions, and regulated decisions.
                If the protected executor cannot verify the owner&apos;s required authority for the
                exact action, the mutation does not proceed.
              </p>
              <p className="ep-home-calm-lede ep-home-lede-mobile">
                Put Gate before the consequential action. No verified exact authority on the
                protected path, no mutation.
              </p>
              <p className="ep-home-calm-detail">
                Customer-controlled authority, credentials, trust roots, policy, and evidence.
                {' '}Protocol proves. Gate prevents.
              </p>
              <div className="ep-home-calm-actions">
                <Link href="/scan" className="ep-home-hero-primary">Run the local Authority Map</Link>
                <Link href="/pilot" className="ep-home-hero-secondary">Scope one protected workflow →</Link>
                <Link href="/gate/live" className="ep-home-hero-secondary">Open the Gate reference →</Link>
              </div>
            </motion.div>
          </C>
        </section>

        <section className="ep-home-technical-band" aria-label="Public engineering evidence">
          <C>
            <div className="ep-home-technical-line">
              <div className="ep-home-technical-title">
                <strong>Public evidence</strong>
                <span>Scoped and rerunnable</span>
              </div>
              <div className="ep-home-technical-facts">
                <span>{TEST_CASES} automated tests</span>
                <span>{CONFORMANCE_VECTORS} conformance vectors</span>
                <span>{SECURITY_CLAIMS} executable claims</span>
                <span>Tamarin: {TAMARIN_OBLIGATIONS} obligations</span>
                <span>{TAMARIN_ATTACK_TRACES} unsafe counterexamples</span>
              </div>
              <Link href="/proof" className="ep-home-technical-link">Inspect the proof →</Link>
            </div>
          </C>
        </section>

        <section style={{ padding: '104px 0 0' }}>
          <C>
            <motion.div {...reveal()} style={{ maxWidth: 820 }}>
              <div style={eyebrow}>The precedent</div>
              <h2 style={{ ...styles.h2, maxWidth: 780 }}>
                Payments separated authorization from movement. Agent actions still do not.
              </h2>
              <p style={{ ...styles.body, maxWidth: 700, marginTop: 18 }}>
                A card system does not confuse identity, authorization, movement, settlement, and
                dispute evidence. Most agent stacks collapse those facts into one tool call and one log.
              </p>
            </motion.div>
            <motion.div className="ep-home-grid-2" {...reveal(0.08)} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 38 }}>
              <div style={{ borderTop: `3px solid ${color.green}`, padding: '28px 26px', background: color.card, borderRadius: radius.base }}>
                <div style={{ ...eyebrow, color: color.green }}>$10,000 card charge</div>
                {['Authorization is distinct from movement.', 'Stable operation identity can prevent a duplicate.', 'The record binds who, what, and how much.', 'Settlement and disputes have separate evidence.'].map((line) => (
                  <p key={line} style={{ ...styles.body, fontSize: 15, margin: '12px 0' }}>{line}</p>
                ))}
              </div>
              <div style={{ borderTop: `3px solid ${color.gold}`, padding: '28px 26px', background: color.card, borderRadius: radius.base }}>
                <div style={eyebrow}>$10,000 agent action today</div>
                {['A broad credential and policy check may be treated as the yes.', 'The exact approved action may never be frozen.', 'A timeout may trigger a blind second attempt.', 'The log is written after the consequence.'].map((line) => (
                  <p key={line} style={{ ...styles.body, fontSize: 15, margin: '12px 0' }}>{line}</p>
                ))}
              </div>
            </motion.div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 16 }}>
              EMILIA is not a bank, settlement rail, or clearing network. The analogy is the separation
              between permission, provider entry, and evidence of effect.
            </p>
          </C>
        </section>

        <section className="ep-home-auth-bridge" style={{ padding: '104px 0 0' }}>
          <C>
            <motion.div {...reveal()} style={{ maxWidth: 780 }}>
              <div style={eyebrow}>Where existing controls stop</div>
              <h2 style={{ ...styles.h2, maxWidth: 760 }}>Auth opens the door. EMILIA controls what crosses it.</h2>
              <p style={{ ...styles.body, maxWidth: 700, marginTop: 18 }}>
                Identity, OAuth, policy engines, and monitoring remain essential. None alone proves
                that one exact consequential action may enter now, once, under current authority.
              </p>
            </motion.div>
            <motion.div className="ep-home-auth-map" {...reveal(0.08)}>
              <div className="ep-home-auth-column ep-home-auth-column-existing">
                <div className="ep-home-auth-label">Existing authorization stack</div>
                <div className="ep-home-auth-item"><span>01</span><strong>Identity verified</strong><em>Who or what is calling?</em></div>
                <div className="ep-home-auth-item"><span>02</span><strong>Credential issued</strong><em>What broad scope exists?</em></div>
                <div className="ep-home-auth-item"><span>03</span><strong>Policy permits</strong><em>Is this class of call allowed?</em></div>
                <div className="ep-home-auth-stop">The exact consequence is still unowned.</div>
              </div>
              <div className="ep-home-auth-handoff" aria-hidden="true">
                <span>executor boundary</span>
                <strong>→</strong>
              </div>
              <div className="ep-home-auth-column ep-home-auth-column-emilia">
                <div className="ep-home-auth-label">EMILIA Consequence Firewall</div>
                <div className="ep-home-auth-item"><span>04</span><strong>Exact action bound</strong><em>Target, fields, limits, expiry</em></div>
                <div className="ep-home-auth-item"><span>05</span><strong>Authority verified</strong><em>Owner-pinned evidence and policy</em></div>
                <div className="ep-home-auth-item"><span>06</span><strong>Authority consumed</strong><em>Once before credentialed provider entry</em></div>
                <div className="ep-home-auth-result">Required evidence verifies—or the mutation stays locked.</div>
              </div>
            </motion.div>
          </C>
        </section>

        <section style={{ padding: '104px 0 0' }}>
          <C>
            <motion.div {...reveal()} style={{ maxWidth: 780, marginBottom: 42 }}>
              <div style={eyebrow}>The EMILIA system</div>
              <h2 style={{ ...styles.h2, maxWidth: 720 }}>Open discovery creates the paid boundary.</h2>
              <p style={{ ...styles.body, maxWidth: 700, marginTop: 18 }}>
                The free map earns trust. Gate sells preventive control. The open Protocol keeps
                evidence portable. Assurance makes the deployed boundary operable.
              </p>
            </motion.div>
            <div style={{ borderTop: `1px solid ${color.border}` }}>
              {PRODUCTS.map((product, index) => (
                <motion.a
                  key={product.title}
                  href={product.href}
                  className="ep-home-stack-row"
                  {...reveal(index * 0.05)}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '120px minmax(180px, 0.6fr) minmax(280px, 1.4fr) 24px',
                    gap: 24,
                    alignItems: 'center',
                    padding: '26px 0',
                    borderBottom: `1px solid ${color.border}`,
                    textDecoration: 'none',
                  }}
                >
                  <span style={{ fontFamily: font.mono, fontSize: 10, color: product.accent, letterSpacing: 1.4, textTransform: 'uppercase' }}>{product.label}</span>
                  <strong style={{ fontFamily: font.sans, fontSize: 17, color: color.t1 }}>{product.title}</strong>
                  <span style={{ fontSize: 14.5, lineHeight: 1.65, color: color.t2 }}>{product.body}</span>
                  <span aria-hidden style={{ color: color.gold }}>→</span>
                </motion.a>
              ))}
            </div>
          </C>
        </section>

        <section style={{ padding: '88px 0 0' }}>
          <C>
            <motion.div {...reveal()} style={{ maxWidth: 820, borderTop: `2px solid ${color.gold}`, paddingTop: 28 }}>
              <div style={eyebrow}>{GATE_QUALIFICATION.name} · {GATE_QUALIFICATION.profileLabel}</div>
              <h2 style={{ ...styles.h2, maxWidth: 760 }}>Evidence can travel without becoming permission.</h2>
              <p style={{ ...styles.body, maxWidth: 720, marginTop: 18 }}>
                Accepted evaluation evidence may qualify one measured candidate and assignment. The
                resource owner still decides whether the exact protected action may proceed.
              </p>
              <p style={{ fontFamily: font.mono, fontSize: 14, fontWeight: 600, color: color.gold, lineHeight: 1.65, marginTop: 18 }}>
                {GATE_QUALIFICATION.boundaryLine}
              </p>
              <p style={{ ...styles.body, fontSize: 14, color: color.t3, maxWidth: 700, marginTop: 10 }}>
                {GATE_QUALIFICATION.disclaimer}
              </p>
            </motion.div>
          </C>
        </section>

        <section style={{ padding: '104px 0', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <motion.div {...reveal()} style={{ maxWidth: 780, marginBottom: 42 }}>
              <div style={eyebrow}>The execution contract</div>
              <h2 style={{ ...styles.h2, maxWidth: 740 }}>One exact action. One use of authority. No invented certainty.</h2>
            </motion.div>
            <div style={{ borderTop: `1px solid ${color.border}` }}>
              {LIFECYCLE.map(([step, title, body], index) => (
                <motion.div
                  key={step}
                  className="ep-home-grid-step"
                  {...reveal(index * 0.04)}
                  style={{ display: 'grid', gridTemplateColumns: '90px 230px 1fr', gap: 32, padding: '30px 0', borderBottom: `1px solid ${color.border}` }}
                >
                  <span style={{ fontFamily: font.mono, color: color.gold, fontSize: 11 }}>{step}</span>
                  <strong style={{ fontFamily: font.sans, fontSize: 16, color: color.t1 }}>{title}</strong>
                  <span style={{ fontSize: 14.5, lineHeight: 1.65, color: color.t2 }}>{body}</span>
                </motion.div>
              ))}
            </div>
            <motion.div {...reveal()} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginTop: 32 }}>
              {OUTCOMES.map(([state, body]) => (
                <div key={state} style={{ borderTop: `3px solid ${state === 'INDETERMINATE' ? color.gold : color.t2}`, padding: '20px 18px', background: color.card }}>
                  <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 700, color: color.t1, marginBottom: 8 }}>{state}</div>
                  <div style={{ fontSize: 13.5, lineHeight: 1.6, color: color.t2 }}>{body}</div>
                </div>
              ))}
            </motion.div>
          </C>
        </section>

        <section style={{ padding: '104px 0', background: '#1C1917', color: '#FAFAF9' }}>
          <C>
            <div className="ep-home-grid-2" style={{ display: 'grid', gridTemplateColumns: '1.05fr 0.95fr', gap: 72, alignItems: 'start' }}>
              <motion.div {...reveal()}>
                <div style={{ ...eyebrow, color: color.gold }}>First paid workflow</div>
                <h2 style={{ ...styles.h2, color: '#FAFAF9', maxWidth: 590 }}>
                  Start where a human decision already exists.
                </h2>
                <p style={{ fontSize: 17, color: 'rgba(250,250,249,0.72)', lineHeight: 1.72, maxWidth: 560, marginTop: 20 }}>
                  Payer adverse medical-necessity determinations contain recurring review and appeal
                  events, concrete action fields, and high consequence. EMILIA does not make the
                  medical judgment. It binds the buyer&apos;s required licensed-review evidence to the
                  exact adverse action at the protected boundary.
                </p>
                <p style={{ fontFamily: font.mono, fontSize: 13, color: color.gold, lineHeight: 1.7, marginTop: 22 }}>
                  {PROTECTED_WORKFLOW_PILOT.safetyRuleLabel}.
                </p>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 28 }}>
                  <Link href="/pilot" style={{ ...cta.primary, background: '#FAFAF9', color: '#1C1917' }}>Request the pilot</Link>
                  <Link href="/health/program-integrity" style={{ ...cta.secondary, color: '#FAFAF9', borderColor: 'rgba(250,250,249,0.28)' }}>Inspect the reference profile</Link>
                </div>
              </motion.div>
              <motion.div {...reveal(0.08)} style={{ borderTop: `3px solid ${color.gold}`, paddingTop: 26 }}>
                <div style={{ fontFamily: font.mono, color: color.gold, fontSize: 13, marginBottom: 8 }}>{PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel.toUpperCase()}</div>
                <h3 style={{ fontFamily: font.sans, fontSize: 24, color: '#FAFAF9', margin: '0 0 18px' }}>Protect one consequential workflow.</h3>
                {[
                  'Synthetic and read-only validation first',
                  'One buyer-selected consequence boundary',
                  'Exact action, authority rule, and evidence bar',
                  'Production only through a buyer-approved Gate path',
                ].map((line) => (
                  <div key={line} style={{ padding: '13px 0', borderBottom: '1px solid rgba(255,255,255,0.14)', fontSize: 14.5, color: 'rgba(250,250,249,0.72)' }}>{line}</div>
                ))}
                <p style={{ fontSize: 13.5, color: 'rgba(250,250,249,0.52)', lineHeight: 1.65, marginTop: 22 }}>
                  Agent and MCP vendors plus consultancies create distribution leverage. Payments,
                  privileged infrastructure, energy, and government are expansion paths—not claimed traction.
                </p>
              </motion.div>
            </div>
          </C>
        </section>

        <section style={{ padding: '104px 0 0' }}>
          <C>
            <motion.div {...reveal()} style={{ maxWidth: 760, marginBottom: 42 }}>
              <div style={eyebrow}>One machine, several consequence boundaries</div>
              <h2 style={{ ...styles.h2, maxWidth: 720 }}>Expand by protected workflow, not by vague platform promise.</h2>
            </motion.div>
            <div className="ep-home-grid-2" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
              {EXPANSION.map(([title, body], index) => (
                <motion.div key={title} {...reveal(index * 0.05)} style={{ borderLeft: `3px solid ${index === 0 ? color.green : color.gold}`, padding: '22px 24px', background: color.card }}>
                  <h3 style={{ fontFamily: font.sans, fontSize: 17, margin: '0 0 8px', color: color.t1 }}>{title}</h3>
                  <p style={{ ...styles.body, fontSize: 14, margin: 0 }}>{body}</p>
                </motion.div>
              ))}
            </div>
          </C>
        </section>

        <section className="ep-home-proof-section">
          <C>
            <ProofBlock />
          </C>
        </section>

        <section style={{ padding: '104px 0 88px', background: '#1C1917', borderTop: `3px solid ${color.gold}` }}>
          <C>
            <motion.div {...reveal()} style={{ maxWidth: 760 }}>
              <div style={{ ...eyebrow, color: color.gold }}>Start with one boundary</div>
              <h2 style={{ ...styles.h2, color: '#FAFAF9', fontSize: 'clamp(34px, 5vw, 62px)', letterSpacing: -2, lineHeight: 0.98 }}>
                More autonomy.<br />Finite authority.
              </h2>
              <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.62)', lineHeight: 1.7, maxWidth: 560, marginTop: 20 }}>
                Run the local map, choose the consequence that matters, and place Gate where the
                credentialed action actually enters the system of record.
              </p>
            </motion.div>
            <motion.div className="ep-home-grid-cta" {...reveal(0.08)} style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginTop: 42 }}>
              {[
                ['Free', 'Run the local Authority Map', 'See supported declared surfaces and explicit blind spots.', '/scan'],
                ['Pilot', 'Protect one workflow', `${PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · ${PROTECTED_WORKFLOW_PILOT.durationLabel}`, '/pilot'],
                ['Diligence', 'Inspect every claim', 'Open code, conformance, threat models, and bounded proof.', '/security'],
              ].map(([kind, title, body, href]) => (
                <div key={kind} style={{ display: 'flex', flexDirection: 'column', border: '1px solid rgba(255,255,255,0.13)', borderTop: `3px solid ${kind === 'Pilot' ? color.gold : color.green}`, borderRadius: radius.base, padding: '26px 24px' }}>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.4, textTransform: 'uppercase' }}>{kind}</div>
                  <h3 style={{ fontFamily: font.sans, fontSize: 18, color: '#FAFAF9', margin: '12px 0 8px' }}>{title}</h3>
                  <p style={{ fontSize: 14, color: 'rgba(250,250,249,0.6)', lineHeight: 1.6, flexGrow: 1 }}>{body}</p>
                  <Link href={href} style={{ ...cta.secondary, color: '#FAFAF9', borderColor: 'rgba(255,255,255,0.22)', justifyContent: 'center' }}>Open →</Link>
                </div>
              ))}
            </motion.div>
          </C>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
