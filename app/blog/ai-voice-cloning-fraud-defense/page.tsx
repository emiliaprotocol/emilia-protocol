'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color } from '@/lib/tokens';

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
        <h1 className="ep-hero-text" style={styles.h1}>AI voice-cloning risk — change the control question</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Synthetic voice makes the caller&apos;s sound a weaker basis for a consequential payment
          decision. Action binding moves the authorization check to the exact payment instruction
          and a buyer-pinned evidence policy. It does not prove the caller is genuine or that fraud
          is absent.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Why voice authentication broke</h2>
        <p className="ep-reveal" style={styles.body}>
          Voice and callback procedures are signals, not exact-action authority. As synthetic-audio
          tools improve, a familiar-sounding caller or a successful callback should not by itself
          authorize a new bank destination or payment release.
        </p>
        <p className="ep-reveal" style={styles.body}>
          Consider a bounded risk scenario: a treasury operator receives an urgent request to change
          vendor bank details or release a wire. The voice and callback appear familiar, but the
          exact destination, amount, authority, and required approvals still need independent evaluation.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Detection alone does not establish authority</h2>
        <p className="ep-reveal" style={styles.body}>
          Deepfake detection can remain useful for triage and investigation. Its output should not
          silently become authorization for an irreversible action. A detector score, email thread,
          session, or callback result answers a different question from whether this exact payment is
          authorized under the relying party&apos;s current policy.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>A stronger pattern: bind evidence to the exact action</h2>
        <p className="ep-reveal" style={styles.body}>
          A configured EMILIA profile binds the material payment instruction to the authority and
          evidence the relying party requires. A fresh human decision is one possible requirement,
          not a universal rule. On a completely mediated covered path, missing, stale, exhausted,
          invalid, or mismatched authority refuses provider entry.
        </p>
        <p className="ep-reveal" style={styles.body}>
          In one candidate workflow, a wire-desk operator reviews the complete action context on a
          separately enrolled approval surface. Gate then evaluates that evidence beside the buyer&apos;s
          authority and policy inputs. This separates the request channel from the admission decision;
          it does not prove payee identity, bank-detail correctness, fraud absence, or provider success.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What the operator workflow looks like</h2>
        <ol className="ep-reveal" style={styles.list}>
          <li>An action is initiated — either by a human, an authenticated agent, or a back-office automation.</li>
          <li>The relying party constructs the exact material action and registers an evidence challenge naming the current policy and missing evidence.</li>
          <li>If the policy requires a fresh human decision, the enrolled approver receives the complete bound action context, including the actual destination and amount.</li>
          <li>The enrolled credential approves, declines, amends, or rejects the exact action. The signature proves control of that credential under the pinned ceremony, not civil identity or comprehension by itself.</li>
          <li>On a completely mediated path, Gate admits one provider attempt only after the configured checks pass. Authorization, provider admission, and observed outcome remain separate records.</li>
        </ol>
        <p className="ep-reveal" style={styles.body}>
          A voice request can prompt step (1). It is not sufficient evidence for the later
          authorization and admission steps under this candidate profile.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What this displaces</h2>
        <p className="ep-reveal" style={styles.body}>
          Action binding does not replace fraud detection, identity verification, transaction
          monitoring, sanctions screening, or provider controls. It adds an exact-action authority
          boundary where the executor path is completely mediated. Unmediated paths remain outside
          the prevention claim.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>For wire desks and treasury teams</h2>
        <p style={styles.body}>
          The initial offered commercial profile assesses one vendor bank-detail change or payment
          release for {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} over {PROTECTED_WORKFLOW_PILOT.durationLabel}. The protected-workflow pilot is
          nonproduction only: synthetic, read-only, sandbox, or shadow validation, with no production
          provider credentials or production actuation. Production is a separate Gate Implementation after
          the buyer accepts the boundary.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/pilot?v=fin" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
          <a href="/use-cases/financial" className="ep-cta-secondary" style={cta.secondary}>Financial use case</a>
        </div>
      </section>
      </main>

      <SiteFooter />
    </div>
  );
}
