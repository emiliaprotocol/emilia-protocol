'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color } from '@/lib/tokens';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

export default function BlogVoiceFraudPage(): React.ReactElement {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.red }}>Blog · Financial · April 2026</div>
        <h1 className="ep-hero-text" style={styles.h1}>AI voice cloning fraud — defense by action binding</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          A convincing synthetic voice can make a familiar caller sound trustworthy. The stronger control is to move transaction authority off the voice channel and bind it to the exact action.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Why voice authentication broke</h2>
        <p className="ep-reveal" style={styles.body}>
          A voice can be useful context, but it is not durable evidence that a specific transaction was authorized. Synthetic audio, replay, social engineering, and ordinary account compromise all make a channel-level signal a poor substitute for an exact-action decision.
        </p>
        <p className="ep-reveal" style={styles.body}>
          A common attack pattern is simple: a treasury operator receives an urgent request to change vendor bank details or release a wire. The caller sounds familiar and the surrounding messages look plausible. If the workflow treats that channel as sufficient authority, the payment can enter the rail before anyone checks the exact destination and amount on an independent approval surface.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>The wrong fix: better voice models</h2>
        <p className="ep-reveal" style={styles.body}>
          Deepfake detection can remain a useful risk signal, but it should not carry transaction authority. A detection model can be unavailable, uncertain, or wrong. The payment control still needs a separate answer to a simpler question: did an accepted authority approve this exact destination, amount, and operation?
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>The right fix: bind authorization to the action</h2>
        <p className="ep-reveal" style={styles.body}>
          The structural fix is to stop treating the caller as the transaction. On a configured financial path, EMILIA Gate evaluates accepted authority and required evidence for the exact wire — destination, amount, beneficiary, operation, and the other material fields selected by the relying party. Fresh approver evidence is required only when that party&apos;s policy calls for it.
        </p>
        <p className="ep-reveal" style={styles.body}>
          When fresh approval is required, an enrolled approver reviews the exact action on a separate surface and signs or refuses it. On a completely mediated covered path, no accepted exact-action authority and required evidence means no provider entry. The signed credential is evidence under the buyer&apos;s pinned directory and role rules; it does not, by itself, prove civil identity, judgment, lawfulness, or absence of fraud.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What the operator workflow looks like</h2>
        <ol className="ep-reveal" style={styles.list}>
          <li>A human, agent, or back-office system requests a covered financial action.</li>
          <li>Gate binds the typed material fields selected by the relying party, such as destination account, amount, beneficiary, operation identifier, policy, and validity window.</li>
          <li>If policy requires fresh approval, an enrolled approver credential receives the complete bound action on a separate review surface.</li>
          <li>The approver signs or refuses. The signature covers the exact action rather than the surrounding voice, email, or login session.</li>
          <li>Gate reserves accepted authority before provider entry and returns action-bound evidence. Provider success or an indeterminate outcome is recorded separately from authorization.</li>
        </ol>
        <p className="ep-reveal" style={styles.body}>
          A voice request can prompt step (1). It is not sufficient evidence for steps (3) or (4). The authority decision has moved off the channel the attacker is trying to imitate.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What this displaces</h2>
        <p className="ep-reveal" style={styles.body}>
          Action binding does not replace your fraud-detection stack — it complements it. Detection still does useful work on Tier-0 and Tier-1 transactions, login risk, and forensics. What action binding replaces is the assumption that any voice, email, or session signal is sufficient evidence of intent for an irreversible Tier-2 transaction. That assumption is what AI-voice fraud is exploiting.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>For wire desks and treasury teams</h2>
        <p style={styles.body}>
          FinGuard packages the Gate runtime, optional approver workflow, and action-bound evidence for treasury operations. The public pilot is {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} for {PROTECTED_WORKFLOW_PILOT.durationLabel} and {PROTECTED_WORKFLOW_PILOT.workflowLabel}; {PROTECTED_WORKFLOW_PILOT.rolloutLabel.toLowerCase()}.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/finguard" className="ep-cta" style={cta.primary}>FinGuard</a>
          <a href="/use-cases/financial" className="ep-cta-secondary" style={cta.secondary}>Financial use case</a>
        </div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
