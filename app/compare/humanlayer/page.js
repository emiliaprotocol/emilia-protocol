'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function CompareHumanLayerPage() {
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
    { dim: 'Core question', them: '“Did a human click approve?”', ep: '“Can anyone prove this exact action was authorized by an accountable human?”' },
    { dim: 'Where approval lives', them: 'Your application layer — your code decides to honor it', ep: 'Bound into the protocol — action hash, nonce, separation of duty' },
    { dim: 'Binding to the action', them: 'Approves a request; not cryptographically bound to the exact parameters', ep: 'Signoff bound to the exact action hash — amount, destination, beneficiary' },
    { dim: 'Replay', them: 'Reusable unless you prevent it', ep: 'One-time consumable (nonce)' },
    { dim: 'Evidence', them: 'A record in your own system — trust us', ep: 'Trust Receipt — Ed25519 + Merkle, verifiable offline, no account, no call home' },
    { dim: 'Assurance', them: 'A well-built product; trust the implementation', ep: 'Formally verified policy engine — 26 TLA+ theorems + 35 Alloy facts, run the checker yourself' },
    { dim: 'Best for', them: 'Fast, friendly approval UX — developer velocity', ep: 'Provable authorization for auditors, regulators, fraud & treasury controls' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Comparison / HumanLayer</div>
        <h1 className="ep-hero-text" style={styles.h1}>EMILIA Protocol vs HumanLayer</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 660 }}>
          Same shelf, different layer. HumanLayer is excellent approval <em>plumbing</em> &mdash; it pauses a sensitive tool call and routes it to Slack or email. EMILIA is an enforcement-and-evidence layer: it binds the approval to the exact action and turns it into an artifact anyone can verify offline, years later.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Where HumanLayer is the right call</h2>
        <p className="ep-reveal" style={styles.body}>
          If you&rsquo;re a developer wiring a human into your agent and you want a clean approval experience &mdash; Slack/email routing, escalations, timeouts &mdash; in an afternoon, HumanLayer is a strong, well-made choice, and we won&rsquo;t pretend otherwise. For developer velocity and a friendly approval UX, it wins. If &ldquo;a human clicked approve&rdquo; is the whole question you need to answer, you don&rsquo;t need EMILIA.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The different question EMILIA answers</h2>
        <p className="ep-reveal" style={styles.body}>
          Approval plumbing answers &ldquo;did a human click approve?&rdquo; The approval lives in your application layer, and your code decides whether to honor it. EMILIA answers the harder question auditors, regulators, and fraud teams actually ask: <em>can anyone prove, later, that this exact irreversible action was authorized by an accountable, named human?</em>
        </p>
        <p className="ep-reveal" style={styles.body}>
          It does that by binding the signoff to the exact action hash, consuming it once via nonce, enforcing separation of duty in the protocol, and minting a Trust Receipt that verifies offline with pure math (Ed25519 + Merkle) &mdash; no account, no call home. The policy engine underneath is formally verified, and you can run the model checker yourself.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>Approval plumbing (e.g. HumanLayer)</th>
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
        <p className="ep-reveal" style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 12 }}>
          Based on HumanLayer&rsquo;s public design as approval-routing middleware. If we&rsquo;ve mischaracterized anything, tell us and we&rsquo;ll correct it.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The honest part &mdash; what neither of us does in-process</h2>
        <p className="ep-reveal" style={styles.body}>
          A guard that runs inside a process the agent&rsquo;s operator controls is skippable &mdash; that is true of HumanLayer and it is true of EMILIA. So EMILIA&rsquo;s edge is <em>not</em> &ldquo;we can&rsquo;t be bypassed.&rdquo; It is two things: the <strong style={{ color: color.t1 }}>offline-verifiable receipt</strong> &mdash; evidence that survives outside the agent&rsquo;s runtime and proves what was authorized &mdash; and the path to <strong style={{ color: color.t1 }}>end-to-end enforcement</strong>, which is airtight only when the system of record (the bank API, the benefits system) verifies the receipt before it executes. We say this plainly on our <a href="/security" style={{ color: color.blue, textDecoration: 'none' }}>security page</a>, because pretending otherwise is exactly the claim this category should distrust.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Which do you need?</h2>
        <p style={styles.body}>
          Need a fast human-in-the-loop UX, answerable to your own team? Use approval plumbing. Need to prove authorization to an auditor, an insurer, a regulator, or after a fraud loss &mdash; treasury, payments, benefits integrity, SOX-scoped controls? That is the line where you need a bound, replay-resistant, offline-provable receipt.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 8 }}>
          <a href="/quickstart" className="ep-cta" style={cta.primary}>Add it to your agent</a>
          <a href="/playground" className="ep-cta-secondary" style={cta.secondary}>Try the live demo</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
