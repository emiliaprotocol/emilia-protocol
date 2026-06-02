'use client';

/**
 * ProofBlock — the formal-verification trust anchor.
 * @license Apache-2.0
 *
 * The spear tip: almost nobody in AI governance can say "we machine-checked our
 * safety properties." EP can. Copy is ground-truthed against formal/ep_handshake.tla
 * + ep_relations.als (26 TLA+ invariants, 35 Alloy facts, 15 assertions, Alloy 6.0.0,
 * checked in CI). Invariant identifiers below are the REAL source names — do not
 * invent friendly labels.
 */

import Link from 'next/link';
import { motion } from 'motion/react';
import { color, font, radius } from '@/lib/tokens';

const EASE = [0.23, 1, 0.32, 1];

const STATS = [
  { n: '26', label: 'TLA+ invariants' },
  { n: '35', label: 'Alloy facts + 15 assertions' },
  { n: 'CI', label: 'machine-checked every commit' },
];

// Plain-English property + its real source invariant name.
const INVARIANTS = [
  ['An authorization can be consumed exactly once — never replayed.', 'ConsumeOnceSafety'],
  ['No path can write a committed state by bypassing the protocol.', 'WriteBypassSafety'],
  ['Once an action is committed or refused, that outcome is irreversible.', 'TerminalStateIrreversibility'],
  ['A signoff is bound to the exact action it approved — nothing else.', 'SignoffBindingMatch'],
  ['A delegated agent can never exceed the authority of its principal.', 'DelegateCannotExceedPrincipal'],
  ['No actor can approve or contest its own action.', 'SelfContestImpossible'],
];

export default function ProofBlock() {
  const reveal = {
    initial: { opacity: 0, y: 18 },
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true, margin: '-40px' },
    transition: { duration: 0.55, ease: EASE },
  };
  return (
    <motion.div {...reveal}>
      <div
        style={{
          fontFamily: font.mono,
          fontSize: 10,
          letterSpacing: 2,
          textTransform: 'uppercase',
          color: color.t3,
          marginBottom: 14,
          borderLeft: `3px solid ${color.gold}`,
          paddingLeft: 12,
        }}
      >
        The proof
      </div>
      <h2 style={{ fontFamily: font.sans, fontSize: 'clamp(26px,4vw,38px)', fontWeight: 700, letterSpacing: -0.5, margin: '0 0 12px', color: color.t1 }}>
        We didn’t just claim it’s safe. We proved it — with machine-checked math.
      </h2>
      <p style={{ fontFamily: font.sans, fontSize: 17, lineHeight: 1.6, color: color.t2, maxWidth: 640, marginBottom: 28 }}>
        Most “AI governance” is policy documents and good intentions. EMILIA’s core guarantees are
        written as formal specifications and verified by a model checker on every commit. The proofs
        are open — read them, or try to break them.
      </p>

      {/* Stat strip */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 32, marginBottom: 28 }}>
        {STATS.map((s) => (
          <div key={s.label}>
            <div style={{ fontFamily: font.mono, fontSize: 30, fontWeight: 700, color: color.gold }}>{s.n}</div>
            <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, letterSpacing: 0.5 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Invariants grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
        {INVARIANTS.map(([plain, name]) => (
          <div
            key={name}
            style={{
              border: `1px solid ${color.border}`,
              borderRadius: radius.base,
              background: color.card,
              padding: '14px 16px',
            }}
          >
            <div style={{ fontFamily: font.sans, fontSize: 14, color: color.t1, lineHeight: 1.5 }}>{plain}</div>
            <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, marginTop: 8 }}>{name}</div>
          </div>
        ))}
      </div>

      <p style={{ fontFamily: font.mono, fontSize: 11.5, color: color.t3, marginTop: 18, lineHeight: 1.6 }}>
        Bounded model-checking of the authorization state machine (TLA+ / Alloy 6.0.0) — not a proof
        of any AI model’s behavior. It proves the protocol cannot be replayed, forged, or partially
        executed.
      </p>

      <div style={{ display: 'flex', gap: 18, marginTop: 18, flexWrap: 'wrap' }}>
        <Link href="/spec" style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 600, color: color.t1 }}>
          Read the spec →
        </Link>
        <Link href="/blog/how-formal-verification-works-for-protocols" style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 600, color: color.t1 }}>
          How the verification works →
        </Link>
      </div>
    </motion.div>
  );
}
