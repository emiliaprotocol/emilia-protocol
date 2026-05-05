'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function CompareAuditLogsPage() {
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
    { dim: 'When evidence is created', logs: 'After the action', ep: 'Before — gates execution' },
    { dim: 'Tamper resistance', logs: 'Depends on log store integrity', ep: 'Cryptographic; verifiable offline' },
    { dim: 'Who approved', logs: 'Inferred from session ID', ep: 'Named principal, signature-bound' },
    { dim: 'What was approved', logs: 'API call shape', ep: 'Exact action parameters, policy version, authority chain' },
    { dim: 'Replay protection', logs: 'None inherent', ep: 'One-time consumable per action' },
    { dim: 'Verifies without DB access', logs: 'No', ep: 'Yes — receipt is self-contained' },
    { dim: 'Use', logs: 'Forensics + detection', ep: 'Prevention + forensics' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.green }}>Comparison / Audit Logs</div>
        <h1 className="ep-hero-text" style={styles.h1}>Audit logs aren't enough for AI agent actions</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Audit logs tell you what happened. EP trust receipts prove what was <em>authorized</em> — before the action executed. For consequential, irreversible actions, post-hoc logs are a forensics tool, not a control.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The detection gap</h2>
        <p className="ep-reveal" style={styles.body}>
          A wire transfer fired by a compromised AI agent shows up in your audit log seconds after it executes. By then the funds have left, the API call has succeeded, and the only remaining job is investigation. Logs are necessary — they are not sufficient when the cost of an unauthorized action is unrecoverable.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EP shifts the boundary: every high-risk action requires a valid handshake and named human signoff <em>before</em> execution. The trust receipt that emerges is itself the audit record — but issued at the gate, not after the breach.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>What's in a trust receipt</h2>
        <ul style={styles.list}>
          <li>The exact action context (parameters, target, amount — whatever was about to execute).</li>
          <li>The actor identity and authority chain that requested the action.</li>
          <li>The policy hash pinned at request time (so future policy changes don't retroactively legitimize a past action).</li>
          <li>The named principal who signed off, and their Ed25519 signature over the bound action context.</li>
          <li>A Merkle anchor for batch verification across many receipts.</li>
        </ul>
        <p style={styles.body}>
          Receipts verify offline against a published key set. An IG, GAO, or external auditor can confirm an action was authorized without contacting the issuing system — useful when the issuing system is itself under investigation.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>Audit logs</th>
                <th style={styles.tableHead}>EP trust receipts</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map(r => (
                <tr key={r.dim}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{r.dim}</td>
                  <td style={styles.tableCell}>{r.logs}</td>
                  <td style={styles.tableCell}>{r.ep}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>See receipts in the explorer</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/explorer" className="ep-cta" style={cta.primary}>Open the explorer</a>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the receipt spec</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
