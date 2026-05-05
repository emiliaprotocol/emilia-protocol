'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color } from '@/lib/tokens';

export default function BlogVoiceFraudPage() {
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

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.red }}>Blog · Financial · April 2026</div>
        <h1 className="ep-hero-text" style={styles.h1}>AI voice cloning fraud — defense by action binding</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Three seconds of recorded audio is enough to clone a caller's voice well enough to pass most callback procedures. The right defense isn't a better voice model. It's moving the trust check off the voice channel entirely.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Why voice authentication broke</h2>
        <p className="ep-reveal" style={styles.body}>
          Voice authentication was always a weak signal — it worked because the cost of cloning a voice was high. That cost has collapsed. Open-source models clone speaker timbre from a few seconds of public audio. Commercial APIs do it in real time over a phone call, with prosody good enough to fool relatives, much less wire-desk callback procedures designed in a different decade.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The fraud pattern this enables is well-documented and rising: a treasury operator gets a call from "the CFO" requesting an urgent vendor-bank-change or wire release, the voice matches, the callback to the cloned number works, the wire goes out. Internal controls were followed. Detection systems show no anomaly. The funds are gone.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>The wrong fix: better voice models</h2>
        <p className="ep-reveal" style={styles.body}>
          The intuitive response is to layer a deepfake-detection model on the voice channel. This is a treadmill. Detection accuracy on the latest cloning systems is markedly worse than on year-old systems, and the underlying capability gets cheaper, not more expensive. Building defense around the voice channel is building a Maginot line on the channel the attacker is gleeful to operate inside.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>The right fix: bind authorization to the action</h2>
        <p className="ep-reveal" style={styles.body}>
          The structural fix is to stop trying to authenticate the caller and start authorizing the action. EMILIA Protocol issues a one-time cryptographic handshake bound to the exact wire — destination, amount, beneficiary, every parameter that matters — and refuses to clear without a named human signoff against that handshake.
        </p>
        <p className="ep-reveal" style={styles.body}>
          A wire-desk operator who receives a voice request opens the trust desk, sees the action context, and signs off (or refuses) on a separate channel from the request. The voice call is no longer a control surface. The action either has a valid signoff bound to its parameters, or it does not execute. A cloned voice with the right callback number cannot generate that signoff. Neither can a compromised email thread, a phished operator account, or an AI agent that has been prompt-injected.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What the operator workflow looks like</h2>
        <ol className="ep-reveal" style={styles.list}>
          <li>An action is initiated — either by a human, an authenticated agent, or a back-office automation.</li>
          <li>EMILIA generates a handshake bound to the action context: destination account, amount, beneficiary, originating identity, timestamp, policy hash.</li>
          <li>The named approver (a treasury officer, a wire-desk lead — whoever the policy designates for this Tier-2 action) receives a signoff request in the trust desk. The request shows the bound action context. Not a summary. The actual destination and amount.</li>
          <li>The approver signs off (or refuses). The signoff is a digital signature over the action context, not a session token.</li>
          <li>The action executes. A self-verifying receipt records what was authorized. The receipt verifies offline.</li>
        </ol>
        <p className="ep-reveal" style={styles.body}>
          A voice request can prompt step (1). It cannot complete steps (3) or (4). The control plane has moved off the channel the attacker controls.
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
          FinGuard packages the EP runtime, signoff workflow, and trust desk for community banks, credit unions, and fintech treasury operations. Pilot deployments take days, not quarters.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/finguard" className="ep-cta" style={cta.primary}>FinGuard</a>
          <a href="/use-cases/financial" className="ep-cta-secondary" style={cta.secondary}>Financial use case</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
