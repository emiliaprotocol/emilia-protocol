'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export default function BlogMcpPostPage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const code = (s) => (
    <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue, background: '#F5F5F4', padding: '1px 6px', borderRadius: 4 }}>{s}</code>
  );

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Blog · MCP · April 2026</div>
        <h1 className="ep-hero-text" style={styles.h1}>MCP authorization best practices in 2026</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          The Model Context Protocol authorization spec is excellent at deciding which tools an agent can reach. It is silent on whether the specific invocation about to execute was approved by a human. For tools that touch money, infrastructure, or user data, that gap matters.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>The two questions every MCP server has to answer</h2>
        <p className="ep-reveal" style={styles.body}>
          When an agent invokes a tool on your MCP server, the server has to answer:
        </p>
        <ol className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>Is this client allowed to call this tool at all?</strong> — answered by MCP authorization (OAuth 2.1 + scopes).</li>
          <li><strong style={{ color: color.t1 }}>Was this specific invocation, with these specific arguments, approved by a named human?</strong> — answered (or not) by whatever you wire on top.</li>
        </ol>
        <p className="ep-reveal" style={styles.body}>
          For most tools — read-only data lookups, search, summarization — the answer to (1) is sufficient. The cost of a bad invocation is small. For a meaningful subset — payments, infrastructure changes, data exports, account modifications, anything irreversible — you need (2).
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Tier your tools by blast radius</h2>
        <p className="ep-reveal" style={styles.body}>
          Before you write authorization code, classify every tool. A simple three-tier model goes a long way:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>Tier 0 — read-only.</strong> Search, retrieval, summarization, status checks. Scope-level MCP authorization is enough. Don't add friction.</li>
          <li><strong style={{ color: color.t1 }}>Tier 1 — bounded write.</strong> Creating drafts, posting comments, adding rows to a sandbox table. Scope-level auth + rate limits. Maybe per-tenant quotas. Still don't gate on a human signoff.</li>
          <li><strong style={{ color: color.t1 }}>Tier 2 — consequential.</strong> Money movement, infrastructure changes, permission changes, data exports, anything irreversible or hard to undo. Scope-level auth is necessary; per-invocation pre-action authorization is non-negotiable.</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          The mistake is treating every tool as Tier 0. The other mistake is treating every tool as Tier 2 — that's how you make agent integrations unusable.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Anatomy of a Tier 2 invocation</h2>
        <p className="ep-reveal" style={styles.body}>
          A Tier 2 tool needs to refuse to execute unless three things hold:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>The client's OAuth token is valid and carries the right scope (MCP authorization layer).</li>
          <li>A pre-action handshake exists for this exact tool, this exact actor, these exact arguments — and was issued recently enough to still be valid.</li>
          <li>A named human signed off on that handshake. The signoff binds to the action context, not to the session.</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          With EMILIA Protocol the wrap is short: import the SDK, declare the tool as gated, and the SDK enforces all three checks before your handler runs. A failed check returns a structured error that the client surfaces as a request for human signoff.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What good looks like in 2026</h2>
        <ul className="ep-reveal" style={styles.list}>
          <li>Every tool is tagged with a tier in the manifest — discoverable by the agent runtime so it can prompt for signoff <em>before</em> it tries to invoke.</li>
          <li>Scope claims are tight enough that a single token can't authorize cross-tenant action across Tier 1 tools.</li>
          <li>Tier 2 invocations emit a self-verifying receipt — useful for audit, useful for replaying authorization to a different system.</li>
          <li>Receipts verify offline. Auditors don't need to call back into the issuing server.</li>
        </ul>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What to avoid</h2>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>Letting "the agent has the {code('payments:write')} scope" mean anything more than "the agent's runtime is trusted."</strong> It says nothing about whether the prompt that just instructed the agent was authentic.</li>
          <li><strong style={{ color: color.t1 }}>Treating the OAuth refresh token as evidence of human intent.</strong> A refresh token is evidence the user once consented to the integration. It is not evidence the user authorized today's wire transfer.</li>
          <li><strong style={{ color: color.t1 }}>Burying the human-in-the-loop check inside your application layer.</strong> The check belongs at the MCP server boundary so every client honoring the protocol gets the same enforcement.</li>
        </ul>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Try the integration</h2>
        <p style={styles.body}>
          The EP MCP server is open source (Apache 2.0) and ships with 34 reference tools. The SDK pattern wraps any other MCP tool you operate.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/use-cases/ai-agent" className="ep-cta" style={cta.primary}>AI agent integration</a>
          <a href="/compare/mcp-auth-alone" className="ep-cta-secondary" style={cta.secondary}>Compare MCP auth alone</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
