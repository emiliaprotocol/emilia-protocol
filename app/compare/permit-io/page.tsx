'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function ComparePermitPage(): React.JSX.Element {
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
    { dim: 'Primary job', them: 'Real-time fine-grained authorization — is this agent allowed to do X?', ep: 'Action-bound admission — is this exact action within finite customer authority?' },
    { dim: 'Authorization models', them: 'RBAC, ABAC, ReBAC; policy-as-code — broad and mature', ep: 'Action risk classes + finite mandates and evidence profiles, focused on the gate' },
    { dim: 'Human in the loop', them: 'Consent collection, just-in-time access requests', ep: 'Named signoff bound to the exact action when the mandate or local policy requires it' },
    { dim: 'Evidence', them: 'Audit logs and decision traces, inside the platform', ep: 'Authorization receipt — Ed25519 + Merkle, verifiable offline against independently pinned key material' },
    { dim: 'Assurance', them: 'Open-source policy engine (OPA / OPAL)', ep: 'Formally analyzed models — 26 TLA+ invariants checked by TLC + 35 Alloy facts in CI' },
    { dim: 'Replay resistance', them: 'Per-request policy decisions', ep: 'One-time consumable handshake bound to the exact action' },
    { dim: 'MCP', them: 'MCP Gateway — authenticate humans, identify agents, gate tokens, collect consent', ep: 'MCP server that gates the action and mints the receipt' },
    { dim: 'Deployment', them: 'SaaS + self-hosted', ep: 'Apache-2.0 protocol and reference runtime; any managed or private production implementation is separately scoped' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Comparison / Permit.io</div>
        <h1 className="ep-hero-text" style={styles.h1}>EMILIA Protocol vs Permit.io</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          Permit.io decides what an AI agent is allowed to do. EMILIA binds the specific action to
          finite customer authority and produces portable evidence. When the mandate or local policy
          requires a fresh human decision, that evidence includes the named signoff. They solve
          different problems, and they can be used together.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>What Permit.io is built for</h2>
        <p className="ep-reveal" style={styles.body}>
          Permit.io is a real-time authorization platform, and it does fine-grained access control well — RBAC, ABAC, and ReBAC, policy-as-code on an open-source core (OPA/OPAL), agent identity, an MCP gateway, and audit logs. If your question is &ldquo;is this agent allowed to touch this resource, under what policy?&rdquo;, Permit.io is purpose-built to answer it, and EMILIA does not try to replace it.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The problem authorization alone does not solve</h2>
        <p className="ep-reveal" style={styles.body}>
          Authorization answers &ldquo;is this allowed?&rdquo; It does not necessarily bind that decision to
          <em> this exact</em> action, a finite mandate, and portable evidence a third party can verify
          later. If the mandate requires fresh human approval, the same evidence must bind that named decision.
        </p>
        <p className="ep-reveal" style={styles.body}>
          A broad policy can legitimately allow an agent to release payments. A prompt-injected agent
          acting within that policy may still be authorized. For actions that are expensive or impossible
          to undo, EMILIA can require admissible authority and policy evidence bound to the exact parameters
          (amount, destination, beneficiary). A named signoff is one evidence profile, used when the customer
          mandate or local policy requires it.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={/** @type {React.CSSProperties} */ (styles.tableHead)}>Dimension</th>
                <th style={/** @type {React.CSSProperties} */ (styles.tableHead)}>Permit.io</th>
                <th style={/** @type {React.CSSProperties} */ (styles.tableHead)}>EMILIA Protocol</th>
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
        <h2 className="ep-reveal" style={styles.h2}>Use them together</h2>
        <p className="ep-reveal" style={styles.body}>
          The clean division of labor: let Permit.io decide whether an agent may attempt an action, and
          use EMILIA on configured protected paths to require finite customer authority bound to the exact
          parameters. EMILIA returns an authorization receipt (formerly Trust Receipt) that can be verified
          offline against independently pinned issuer or operator key material. When the mandate or local policy requires a fresh human decision, the receipt also binds
          that named signoff. Fine-grained authorization and action-bound evidence are complementary controls.
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Authorize the agent and the resource with Permit.io (RBAC/ABAC/ReBAC, policy-as-code).</li>
          <li>Gate the configured protected action with EMILIA using finite customer authority and policy evidence bound to the exact parameters.</li>
          <li>Keep the authorization receipt as offline-verifiable evidence of the authority admitted for that action; include a named signoff when policy requires one.</li>
        </ul>
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
