'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function ComparePermitPage() {
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
    { dim: 'Primary job', them: 'Real-time fine-grained authorization — is this agent allowed to do X?', ep: 'Accountable human signoff before an irreversible action — did a named human approve THIS action?' },
    { dim: 'Authorization models', them: 'RBAC, ABAC, ReBAC; policy-as-code — broad and mature', ep: 'Action risk classes + signoff thresholds, focused on the gate' },
    { dim: 'Human in the loop', them: 'Consent collection, just-in-time access requests', ep: 'Named signoff bound to the exact action parameters, one-time consumable' },
    { dim: 'Evidence', them: 'Audit logs and decision traces, inside the platform', ep: 'Trust Receipt — Ed25519 + Merkle, verifiable offline with no account or network' },
    { dim: 'Assurance', them: 'Open-source policy engine (OPA / OPAL)', ep: 'Formally verified policy engine — 26 TLA+ theorems + 35 Alloy facts in CI' },
    { dim: 'Replay resistance', them: 'Per-request policy decisions', ep: 'One-time consumable handshake bound to the exact action' },
    { dim: 'MCP', them: 'MCP Gateway — authenticate humans, identify agents, gate tokens, collect consent', ep: 'MCP server that gates the action and mints the receipt' },
    { dim: 'Deployment', them: 'SaaS + self-hosted', ep: 'Open protocol (Apache-2.0), self-host or cloud' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Comparison / Permit.io</div>
        <h1 className="ep-hero-text" style={styles.h1}>EMILIA Protocol vs Permit.io</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          Permit.io decides what an AI agent is allowed to do. EMILIA proves a named human approved the specific irreversible action — and mints a receipt anyone can verify offline. They solve different problems, and they are strongest together.
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
          Authorization answers &ldquo;is this allowed?&rdquo; It does not answer &ldquo;did a specific, named human approve <em>this exact</em> irreversible action — and can a third party prove it later without trusting either system?&rdquo;
        </p>
        <p className="ep-reveal" style={styles.body}>
          A policy can legitimately allow an agent to release payments. A prompt-injected agent acting within that policy is still authorized — the wire it just sent was permitted. For actions that are expensive or impossible to undo, you need a signoff bound to the exact parameters (amount, destination, beneficiary) and an evidence artifact that verifies on its own, without trusting the platform that produced it. That is the layer EMILIA adds.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>Permit.io</th>
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
        <h2 className="ep-reveal" style={styles.h2}>Use them together</h2>
        <p className="ep-reveal" style={styles.body}>
          The clean division of labor: let Permit.io decide whether an agent may attempt an action, and let EMILIA secure the irreversible ones. Permit evaluates the policy; EMILIA captures a named human&rsquo;s signoff bound to the exact parameters and returns a Trust Receipt your auditor, your insurer, or a counterparty can verify offline. Fine-grained authorization and accountable signoff are complementary controls, not substitutes.
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Authorize the agent and the resource with Permit.io (RBAC/ABAC/ReBAC, policy-as-code).</li>
          <li>Gate the irreversible action with EMILIA — named signoff bound to the exact parameters, one-time consumable.</li>
          <li>Keep the Trust Receipt as offline-verifiable evidence that this exact action was approved by this named human under this policy.</li>
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
