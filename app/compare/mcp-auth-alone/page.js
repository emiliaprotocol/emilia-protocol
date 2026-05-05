'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function CompareMcpPage() {
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
    { dim: 'Authorizes', mcp: 'Which tools the client can call', ep: 'Whether THIS specific call was approved' },
    { dim: 'Granularity', mcp: 'Tool-level scopes', ep: 'Per-invocation parameter binding' },
    { dim: 'Replay protection', mcp: 'Token expiry', ep: 'One-time consumable per action' },
    { dim: 'Human accountability', mcp: 'Out of scope', ep: 'Named principal signoff bound to action' },
    { dim: 'Output evidence', mcp: 'Server logs', ep: 'Self-verifying trust receipt' },
    { dim: 'Composes with OAuth', mcp: 'Yes (recommended)', ep: 'Yes — sits above MCP + OAuth' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Comparison / MCP Authorization</div>
        <h1 className="ep-hero-text" style={styles.h1}>MCP authorization is necessary but not sufficient</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Model Context Protocol authorization decides which tools an agent client can reach. EMILIA Protocol decides whether the specific tool invocation about to execute was authorized by a named human. Both layers are required for any MCP tool that touches money, infrastructure, or user data.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>What MCP authorization gives you</h2>
        <p className="ep-reveal" style={styles.body}>
          MCP servers expose tools. The MCP authorization spec — built on OAuth 2.1 — answers <em>which</em> tools a client is allowed to call. Once a client holds a valid token with the right scopes, every call to a permitted tool succeeds. This is the right layer for distinguishing trusted clients from untrusted ones.
        </p>
        <h2 className="ep-reveal" style={{ ...styles.h2, marginTop: 32 }}>What MCP authorization doesn't give you</h2>
        <p className="ep-reveal" style={styles.body}>
          MCP authorization makes no statement about whether the <em>arguments</em> to a permitted call were authorized. A client with the <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>send_wire</code> scope can invoke <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>send_wire(account, amount, beneficiary)</code> with any well-formed arguments. The MCP server has no signal that distinguishes a human-approved invocation from a prompt-injected one.
        </p>
        <p className="ep-reveal" style={styles.body}>
          For tools that move money, change infrastructure, escalate permissions, export data, or trigger irreversible state changes, scope-level authorization is the floor — not the ceiling.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>MCP authorization (alone)</th>
                <th style={styles.tableHead}>EP on top of MCP</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map(r => (
                <tr key={r.dim}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{r.dim}</td>
                  <td style={styles.tableCell}>{r.mcp}</td>
                  <td style={styles.tableCell}>{r.ep}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>How the two compose</h2>
        <p className="ep-reveal" style={styles.body}>
          A high-risk MCP tool wraps its handler with the EP SDK. When the agent invokes the tool, the MCP server first verifies the client's OAuth token (MCP authorization), then asks EP whether a valid handshake exists for these exact arguments. If the handshake is missing or doesn't match, the tool refuses to execute — and the client surfaces a request for human signoff before retrying.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The EP MCP server itself ships 34 tools for protocol operations and reference workflows; the SDK pattern is a 3-line wrap of any other tool you want to gate.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>See the integration</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/use-cases/ai-agent" className="ep-cta" style={cta.primary}>AI agent use case</a>
          <a href="/protocol" className="ep-cta-secondary" style={cta.secondary}>Read the protocol</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
