'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export default function BlogFormalVerificationPage() {
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
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Blog · Formal Methods · April 2026</div>
        <h1 className="ep-hero-text" style={styles.h1}>How formal verification works for protocols</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Tests prove a protocol works on the cases the author thought of. Formal verification proves it works on every case the model admits — including the ones the author didn't think of. For an authorization protocol, that gap matters.
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
          Bounded scope sounds like a weakness; it is also a feature. The "small scope hypothesis" — that most invariant violations show up in small instances — has held remarkably well in practice. EMILIA's Alloy model has 35 facts (e.g., {inline('OneBindingPerHandshake')}, {inline('ConsumedRequiresVerifiedEvent')}, {inline('SignoffChallengeBindingMatchesHandshake')}) and 15 assertions. Three of those assertions failed during initial development and surfaced real protocol gaps; fixing them added the facts that now keep the assertions true.
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
          <a href="/spec" className="ep-cta" style={cta.primary}>Read the spec</a>
          <a href="/protocol" className="ep-cta-secondary" style={cta.secondary}>Protocol overview</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
