'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function CompareFraudPage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const ROWS = [
    { dim: 'Where the check runs', det: 'Before, during, or after a transaction, depending on the detection and payment stack', ep: 'Before provider entry on a configured, completely mediated protected path' },
    { dim: 'Signal source', det: 'Behavioral patterns, statistical models', ep: 'Cryptographic handshake + finite customer authority and policy evidence' },
    { dim: 'False-positive cost', det: 'Legitimate transactions blocked or delayed', ep: 'Adds a gate on configured Tier-2 actions; human signoff only when policy requires it' },
    { dim: 'False-negative cost', det: 'Varies by action, detection timing, and recovery path', ep: 'Covered provider entry is refused when required authority evidence is missing or invalid' },
    { dim: 'AI-voice / deepfake role', det: 'May detect channel, identity, behavior, or transaction anomalies', ep: 'Does not detect the attack; evaluates authority bound to the proposed action' },
    { dim: 'Insider-misuse role', det: 'May identify anomalous insider behavior or policy violations', ep: 'Checks the presented finite authority and evidence at the protected boundary' },
    { dim: 'Audit evidence', det: 'Alerts, scores, decisions, and investigation records', ep: 'Action-bound receipt recording the authority evidence admitted at the gate' },
    { dim: 'Composes with', det: 'EP, MFA, audit logs', ep: 'Detection (defense in depth)' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.red }}>Comparison / Fraud Detection</div>
        <h1 className="ep-hero-text" style={styles.h1}>Exact-action authority and fraud detection</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Fraud controls may score, hold, or reject activity before, during, or after a transaction. On a completely mediated protected path,
          pre-action authorization can refuse an action before provider entry when required authority
          evidence is missing. EMILIA is not a fraud detector and does not replace transaction monitoring;
          it adds a separate exact-action authority condition where the executor can enforce it.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The shape of detection</h2>
        <p className="ep-reveal" style={styles.body}>
          Modern fraud stacks combine pre-transaction rules, real-time scoring, payment holds,
          transaction monitoring, behavioral analytics, and post-event investigation. Their signals
          can include destination, timing, amount, device, identity, and network context. Exact timing
          and intervention power depend on the institution and payment rail.
        </p>
        <p className="ep-reveal" style={styles.body}>
          Even strong detection does not answer the separate authority question: what finite mandate
          and evidence authorized this exact destination, amount, and operation at the executor? That
          distinction matters most when recovery is difficult or the instruction arrives through a
          legitimate authenticated channel.
        </p>
        <h2 className="ep-reveal" style={{ ...styles.h2, marginTop: 32 }}>Where detection breaks for AI-era fraud</h2>
        <p className="ep-reveal" style={styles.body}>
          Deepfakes, business-email compromise, insiders, and prompt-injected agents may reuse
          legitimate sessions or persuasive identity signals. Detection can still help, but a normal-looking
          channel or transaction is not proof that the exact action carries finite customer authority.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EP changes the question. The system does not ask only &ldquo;does this transaction look
          anomalous?&rdquo; It asks whether this exact destination and amount carry admissible finite
          customer authority and policy evidence. When policy requires a fresh human decision, that
          evidence includes the named signoff. The gate evaluates the evidence independently of the
          channel the instruction arrived on.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={/** @type {React.CSSProperties} */ (styles.tableHead)}>Dimension</th>
                <th style={/** @type {React.CSSProperties} */ (styles.tableHead)}>Post-action fraud detection</th>
                <th style={/** @type {React.CSSProperties} */ (styles.tableHead)}>EP pre-action authorization</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map(r => (
                <tr key={r.dim}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{r.dim}</td>
                  <td style={styles.tableCell}>{r.det}</td>
                  <td style={styles.tableCell}>{r.ep}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Defense in depth, not replacement</h2>
        <p className="ep-reveal" style={styles.body}>
          EP and detection compose. Detection is still the right control for Tier-0 reads, login risk scoring, fraud pattern discovery across the long tail, and downstream forensics. EP is the right control for the irreversible Tier-2 actions where post-hoc detection doesn't return your money.
        </p>
        <p className="ep-reveal" style={styles.body}>
          A community bank running EP on wire releases keeps its existing transaction-monitoring stack. Most transactions never see EP — they're below the action-binding threshold. The wire-out-to-new-beneficiary action does. The handshake refuses to clear until a named officer signs off on the exact destination and amount.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Where this matters most</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/use-cases/financial" className="ep-cta" style={cta.primary}>Financial use case</a>
          <a href="/finguard" className="ep-cta-secondary" style={cta.secondary}>FinGuard</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
