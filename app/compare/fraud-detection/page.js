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
    { dim: 'Where the check runs', det: 'After the action executes', ep: 'Before the action executes — gates execution' },
    { dim: 'Signal source', det: 'Behavioral patterns, statistical models', ep: 'Cryptographic handshake + named human signoff' },
    { dim: 'False-positive cost', det: 'Legitimate transactions blocked or delayed', ep: 'Adds a signoff step on Tier-2 actions only' },
    { dim: 'False-negative cost', det: 'Funds gone; recovery rare', ep: 'Action does not execute without valid handshake' },
    { dim: 'Effectiveness on AI-voice / deepfake', det: 'Degrades — model-driven attacks evade behavior baselines', ep: 'Independent of attack channel — binds the action, not the actor channel' },
    { dim: 'Effectiveness on insider misuse', det: 'Limited — insider patterns look normal', ep: 'Handshake binds authority chain at request time' },
    { dim: 'Audit evidence', det: 'Alert + post-hoc investigation', ep: 'Self-verifying trust receipt issued at the gate' },
    { dim: 'Composes with', det: 'EP, MFA, audit logs', ep: 'Detection (defense in depth)' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.red }}>Comparison / Fraud Detection</div>
        <h1 className="ep-hero-text" style={styles.h1}>Pre-action authorization vs post-action fraud detection</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Detection finds bad actions after they execute. Pre-action authorization stops them before they execute. For irreversible actions — wire transfers, benefit redirects, AI-voice-cloned approvals — detection alone is the wrong primitive.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The shape of detection</h2>
        <p className="ep-reveal" style={styles.body}>
          Modern fraud detection — behavioral analytics, statistical anomaly models, BEC scoring, transaction monitoring — runs <em>after</em> the action submits. The signals are real: unusual destination, unusual time, unusual amount, atypical user agent. The downside is structural: by the time the alert fires, the wire has cleared.
        </p>
        <p className="ep-reveal" style={styles.body}>
          That tradeoff worked when most fraud cleared slowly and recovery was possible. It does not work when the action is an instant ACH or a same-day wire to a beneficiary that goes silent within minutes.
        </p>
        <h2 className="ep-reveal" style={{ ...styles.h2, marginTop: 32 }}>Where detection breaks for AI-era fraud</h2>
        <p className="ep-reveal" style={styles.body}>
          Behavioral models assume the legitimate user is a stable signal — same IP ranges, same device, same approval cadence. AI-voice-cloned phone calls reproduce the legitimate user's signal exactly. Prompt-injected agent runtimes operate from the same authenticated session, the same scope, the same device. The "anomaly" the detection model is looking for is no longer there.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EP changes the question. The system doesn't ask "does this transaction look anomalous?" — it asks "did a named human authorize this exact destination, this exact amount, with a valid handshake?" The answer is binary, cryptographic, and resistant to the channel the attack arrived on.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>Post-action fraud detection</th>
                <th style={styles.tableHead}>EP pre-action authorization</th>
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
