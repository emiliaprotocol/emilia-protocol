'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function CompareHumanInTheLoopPage() {
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
    { dim: 'What gets approved', them: 'An action, often coarse — approve once, broad scope', ep: 'The exact action — bound to actor, authority, policy, and parameters' },
    { dim: 'Replay resistance', them: 'Usually none — an approval can be reused', ep: 'One-time consumable handshake' },
    { dim: 'Evidence', them: 'A log line in your own system — trust us', ep: 'Trust Receipt — Ed25519 + Merkle, verifiable offline' },
    { dim: 'Approver identity', them: 'Whoever clicked the button', ep: 'A named principal bound into the signoff' },
    { dim: 'Assurance', them: 'Your own glue code', ep: 'Formally verified policy engine — 26 TLA+ theorems + 35 Alloy facts' },
    { dim: 'What you maintain', them: 'Channels, state, retries, audit storage', ep: 'A drop-in gate (MCP / SDK); receipts included' },
    { dim: 'Compliance', them: 'Ad hoc', ep: 'Maps to NIST AI RMF + EU AI Act human-oversight and traceability' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Comparison / Human-in-the-Loop</div>
        <h1 className="ep-hero-text" style={styles.h1}>EMILIA Protocol vs DIY human-in-the-loop</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          Adding a Slack or email approval to your agent is the right instinct. EMILIA makes that approval <em>accountable</em> — bound to the exact action, replay-resistant, and provable offline — without you maintaining the trust plumbing.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>The pattern you are reaching for</h2>
        <p className="ep-reveal" style={styles.body}>
          When an agent hits a risky action, post to Slack or email, wait for a click, then proceed. Homegrown wrappers and approval libraries do exactly this, and the instinct is correct: a human should stand between an agent and an irreversible action. It works — until you need to prove who approved what, stop a captured approval from being reused, or hand an auditor evidence that does not require trusting your own logs.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>What a click in Slack is missing</h2>
        <p className="ep-reveal" style={styles.body}>
          A button press approves &ldquo;an action.&rdquo; It is usually not cryptographically bound to the exact parameters — the amount, the destination, the beneficiary — so the same approval can authorize a different action than the one the human saw. It can often be replayed. And the evidence it leaves is a row in a database you control, which is precisely what a regulator or an insurer will not take at face value.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EMILIA binds the signoff to the exact action, makes it one-time consumable, and mints a Trust Receipt anyone can verify offline (Ed25519 + Merkle, no account, no call home). The policy engine underneath is formally verified, not glue code you have to trust.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>DIY human-in-the-loop</th>
                <th style={styles.tableHead}>EMILIA Protocol</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map(r => (
                <tr key={r.dim}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{r.dim}</td>
                  <td style={styles.tableCell}>{r.them}</td>
                  <td style={styles.tableCell}>{r.ep}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Keep your Slack approval — change what it means</h2>
        <p className="ep-reveal" style={styles.body}>
          EMILIA is not a different approval UX. Keep approving in Slack or email if your team likes it. The difference is what the approval <em>is</em>: instead of a click and a log line, it becomes a bound, replay-resistant, offline-provable artifact — the thing you can hand to an auditor, an insurer, or a counterparty without asking them to trust your systems.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>See it in practice</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/quickstart" className="ep-cta" style={cta.primary}>Add it to your agent</a>
          <a href="/playground" className="ep-cta-secondary" style={cta.secondary}>Try the live demo</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
