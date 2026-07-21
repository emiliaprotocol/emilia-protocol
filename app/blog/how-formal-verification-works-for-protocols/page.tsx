'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export default function BlogFormalVerificationPage(): React.ReactElement {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const inline = (s) => (
    <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue, background: '#F5F5F4', padding: '1px 6px', borderRadius: 4 }}>{s}</code>
  );

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Blog · Formal Methods · June 2026</div>
        <h1 className="ep-hero-text" style={styles.h1}>We formally verified an AI-safety protocol — here&apos;s the proof</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          Most “AI safety” and “AI governance” is policy documents and good intentions. EMILIA’s core
          guarantee — that an AI agent cannot take an irreversible action without a signed human
          approval — is written as a formal specification and checked by a model checker on every
          commit. Tests prove a protocol works on the cases the author thought of; formal verification
          proves it across every case the model admits. For an authorization protocol standing between
          an autonomous agent and someone’s money, that gap is the whole point.
        </p>
      </section>

      {/* Safety framing — what the proofs guarantee for AI agents */}
      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What the proofs guarantee for an AI agent</h2>
        <p className="ep-reveal" style={styles.body}>
          EMILIA sits at the pre-execution moment: an agent is about to do something irreversible, and
          the protocol decides whether it may proceed. Four of the verified invariants are the
          load-bearing safety properties — they hold across every reachable state of the model, not
          just the tested ones:
        </p>
        <ul className="ep-reveal" style={{ ...styles.body, paddingLeft: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 720 }}>
          <li>{inline('ConsumeOnceSafety')} — a signed authorization is consumed exactly once; an agent cannot replay it.</li>
          <li>{inline('WriteBypassSafety')} — no path can fabricate a committed decision outside the ceremony.</li>
          <li>{inline('SelfContestImpossible')} — an agent cannot approve, consume, or contest its own action.</li>
          <li>{inline('TerminalStateIrreversibility')} — once an action is committed or refused, that outcome cannot be silently flipped.</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          What it does <em>not</em> prove: anything about a language model’s cognition. This is bounded
          model-checking of the authorization state machine — it proves the gate around the agent is
          sound, not that the agent is. That distinction is deliberate, and it is exactly why the gate
          exists. See it stop a real attack on the{' '}
          <Link href="/demo" style={{ color: color.gold }}>live crash test</Link>, or try to break the
          guarantees yourself on the{' '}
          <Link href="/break-the-ceremony" style={{ color: color.gold }}>open challenge</Link>.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What "formally verified" actually means</h2>
        <p className="ep-reveal" style={styles.body}>
          A formal model is a mathematical description of the protocol — its states, its transitions, the conditions under which a transition is allowed. A formal verification tool explores that model and either confirms a property holds across every reachable state, or returns a counterexample: a specific sequence of transitions that breaks the property.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The thing being verified is the model, not the implementation. The implementation can still have bugs. What you have ruled out is design-level ambiguity: races, missing invariants, ambiguous orderings, properties that turn out to be subtly false. Those are the bugs that survive code review and unit tests because nobody ever wrote down precisely enough what was supposed to be true.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>TLA+ — temporal properties across runs</h2>
        <p className="ep-reveal" style={styles.body}>
          TLA+ is built around the idea that a protocol is a sequence of states over time. You write actions ("here's how a state transitions to the next") and properties that must hold either everywhere ("safety": no bad state is ever reachable) or eventually ("liveness": every request eventually completes).
        </p>
        <p className="ep-reveal" style={styles.body}>
          The TLC model checker explores the reachable state space and either certifies the property or gives you a trace. EMILIA's spec encodes 26 such theorems — examples include: every issued handshake is bound to a specific action and cannot be reused for a different action; every signoff binds to the exact handshake context and cannot be replayed; every receipt is verifiable from its own contents without reference to issuer state.
        </p>
        <p className="ep-reveal" style={styles.body}>
          When a TLA+ theorem fails, the counterexample is a literal step-by-step run of the protocol that violates the property. You read it like a stack trace. The fix is usually either tightening a precondition (the action shouldn't have been allowed in that state) or adding a binding (the missing field that lets you distinguish two superficially similar actions).
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Alloy — structural invariants in bounded scope</h2>
        <p className="ep-reveal" style={styles.body}>
          Alloy is the complement. Where TLA+ explores time, Alloy explores structure. You write facts ("this property is always true of any well-formed instance of the protocol's state") and assertions ("this stronger property follows from the facts"). The Alloy Analyzer searches for a counterexample within a bounded scope — usually small numbers of actors, handshakes, signoffs.
        </p>
        <p className="ep-reveal" style={styles.body}>
          Bounded scope sounds like a weakness; it is also a feature. The "small scope hypothesis" — that most invariant violations show up in small instances — has held remarkably well in practice. EMILIA&apos;s CI runs four Alloy models with 35 facts and 32 assertions in total, including {inline('OneBindingPerHandshake')}, {inline('ConsumedRequiresVerifiedEvent')}, {inline('SignoffChallengeBindingMatchesHandshake')}, quorum distinctness, and capability-delegation acyclicity. Three assertions in the original relations model failed during initial development and surfaced real protocol gaps; fixing them added the facts that now keep the assertions true. Current counts come from the generated proof manifest, not this prose.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Why use both</h2>
        <p className="ep-reveal" style={styles.body}>
          The two tools answer different questions. TLA+ is best at "across every possible run of the protocol, is this property always true?" Alloy is best at "across every possible structural configuration, is this invariant always true?" Most authorization protocols have properties of both shapes.
        </p>
        <p className="ep-reveal" style={styles.body}>
          A worked example: handshake-binding integrity. The TLA+ theorem says "no execution path produces a state where a signoff exists for one handshake and a different handshake is consumed." The Alloy fact says "every consumed handshake has exactly one signoff that binds to its own challenge — never a sibling's." Both are about the same property; they catch different ways the protocol can go wrong.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Verification in CI</h2>
        <p className="ep-reveal" style={styles.body}>
          The interesting engineering claim isn't "we ran TLC once." It's "TLC and the Alloy Analyzer run on every push." When the model and the implementation can drift, verification becomes a snapshot. When they ship together — the spec changes, CI fails, the spec is fixed before the implementation lands — verification stays load-bearing.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EMILIA's CI runs the full theorem suite in under five minutes for the standard scope, longer scopes on a nightly job. Counterexamples surface as PR comments. The model is part of the codebase, not a paper attached to it.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Read the spec</h2>
        <p style={styles.body}>
          The full TLA+ module, the Alloy facts, and the assertion list are in the public repo. The protocol page links to a guided walk-through.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <Link href="/spec" className="ep-cta" style={cta.primary}>Read the spec</Link>
          <Link href="/protocol" className="ep-cta-secondary" style={cta.secondary}>Protocol overview</Link>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
