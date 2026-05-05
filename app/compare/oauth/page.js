'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function CompareOAuthPage() {
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
    { dim: 'Authorization granularity', oauth: 'Session + scope', ep: 'Exact action parameters' },
    { dim: 'Replay resistance', oauth: 'Refresh tokens, expiry', ep: 'One-time consumable per action' },
    { dim: 'Action parameter binding', oauth: 'No', ep: 'Cryptographic — actor, authority, policy, action context' },
    { dim: 'Named human signoff', oauth: 'Out of scope', ep: 'Required for high-risk actions; bound to action context' },
    { dim: 'Audit evidence', oauth: 'Token issuance / scope claims', ep: 'Self-verifying trust receipt (offline verifiable)' },
    { dim: 'Compliance mapping', oauth: 'OAuth 2.1, OIDC', ep: 'NIST AI RMF, EU AI Act high-risk system controls' },
    { dim: 'AI agent fit', oauth: 'Authorizes the agent runtime', ep: 'Authorizes each consequential agent action' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Comparison / OAuth</div>
        <h1 className="ep-hero-text" style={styles.h1}>EMILIA Protocol vs OAuth</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          OAuth authorizes sessions and scopes. EP authorizes a specific action with bound parameters. Both can coexist — and for any consequential workflow involving AI agents or high-value transactions, both are necessary.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The problem OAuth doesn't solve</h2>
        <p className="ep-reveal" style={styles.body}>
          A correctly issued OAuth access token with the <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>payments:write</code> scope authorizes <em>any</em> payment within scope until the token expires. The token has no opinion about the destination account, the amount, or whether the action that just executed matches what a human authorized.
        </p>
        <p className="ep-reveal" style={styles.body}>
          For an AI agent that earned that token through a legitimate consent flow, a prompt-injected instruction to "wire $50,000 to a new beneficiary" is technically in-scope. The token authorizes it. The downstream system has no way to distinguish authorized action from compromised action.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EMILIA Protocol generates a one-time cryptographic handshake bound to the exact actor, the authority chain, the policy version, and the exact action context — destination, amount, beneficiary, every parameter — before the action proceeds. A captured handshake cannot be replayed against a different action. A compromised agent runtime cannot generate a valid signoff for an action that no named human approved.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>OAuth 2.1 / OIDC</th>
                <th style={styles.tableHead}>EMILIA Protocol</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map(r => (
                <tr key={r.dim}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{r.dim}</td>
                  <td style={styles.tableCell}>{r.oauth}</td>
                  <td style={styles.tableCell}>{r.ep}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>When you need EP on top of OAuth</h2>
        <ul className="ep-reveal" style={styles.list}>
          <li>An AI agent executes consequential actions on behalf of a human (payments, infrastructure changes, data exports, account modifications).</li>
          <li>The action is irreversible or high-cost to undo (wire transfers, benefit disbursements, production deploys, permission escalations).</li>
          <li>You need cryptographic evidence — beyond an audit log entry — that a named human approved this exact action with these exact parameters.</li>
          <li>Compliance frameworks (NIST AI RMF, EU AI Act, SOX) require pre-execution authorization controls, not post-hoc detection.</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          EP is not a replacement for OAuth. It is the layer that makes OAuth-issued sessions safe for the actions OAuth was never designed to authorize.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>See it in practice</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/protocol" className="ep-cta" style={cta.primary}>Read the protocol</a>
          <a href="/playground" className="ep-cta-secondary" style={cta.secondary}>Try the live demo</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
