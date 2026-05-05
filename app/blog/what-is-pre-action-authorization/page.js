'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color } from '@/lib/tokens';

export default function BlogPreActionPage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Blog · Concepts · April 2026</div>
        <h1 className="ep-hero-text" style={styles.h1}>What is pre-action authorization?</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          The short version: sessions and scopes authorize the <em>actor</em>. Pre-action authorization authorizes the <em>action</em> — the exact destination, the exact amount, the exact parameters — before execution.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>The shape of the problem</h2>
        <p className="ep-reveal" style={styles.body}>
          Most authorization systems answer one question: <em>is this caller allowed to do things in this category?</em> A user with a valid session and the right role can transfer funds. An AI agent with a valid OAuth token and the right scope can call the wire-transfer tool. The system says yes.
        </p>
        <p className="ep-reveal" style={styles.body}>
          That answer was good enough when the gap between "decided to act" and "acted" was a human pressing a button. It is not good enough when the actor is an autonomous program that can be steered — by a prompt-injected document, by a compromised data source, by a malformed model response — into actions the human never authorized. The session was real. The scope was real. The action was not.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What pre-action authorization adds</h2>
        <p className="ep-reveal" style={styles.body}>
          Pre-action authorization asks a sharper question: <em>was this exact action — these arguments, this destination, this amount — approved by a named human, and is the approval still valid?</em>
        </p>
        <p className="ep-reveal" style={styles.body}>
          That requires four things the older systems don't typically produce together:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>Action binding.</strong> The authorization names the exact parameters of the action. A captured authorization for "wire $1,000 to Acme" cannot authorize "wire $50,000 to Acme" or "wire $1,000 to a different account."</li>
          <li><strong style={{ color: color.t1 }}>Authority chain.</strong> The authorization records who held the authority, where it came from, and which policy it was issued under — pinned at request time so later policy changes don't retroactively legitimize past actions.</li>
          <li><strong style={{ color: color.t1 }}>Named signoff.</strong> A human principal signs off explicitly. Not "the user is logged in." A signature, by name, over the bound action context.</li>
          <li><strong style={{ color: color.t1 }}>Verifiable evidence.</strong> What emerges is a self-verifying receipt — checkable offline, by an auditor with no access to the issuing system.</li>
        </ul>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Where it matters</h2>
        <p className="ep-reveal" style={styles.body}>
          The places where pre-action authorization earns its weight are the places where the cost of an unauthorized action is unrecoverable — not just unwanted:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Wire transfers, ACH releases, treasury operations.</li>
          <li>Beneficiary changes, vendor bank-account updates, payment-destination rewrites.</li>
          <li>Production deployments, infrastructure changes, IAM permission changes.</li>
          <li>Bulk data exports, cross-tenant reads, anything that touches PII.</li>
          <li>Government benefit disbursements, caseworker overrides, claim approvals.</li>
          <li>Any AI-agent-issued action where prompt injection has a meaningful blast radius.</li>
        </ul>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>What it does <em>not</em> replace</h2>
        <p className="ep-reveal" style={styles.body}>
          Pre-action authorization is a layer, not a replacement. It assumes you already have:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Authentication (so you know who is asking).</li>
          <li>Session and scope authorization (OAuth 2.1, OIDC, MCP authorization, IAM roles).</li>
          <li>Audit logs (for forensics and detection).</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          What it adds is the missing question between authorization and execution: not <em>can</em> you do it, but <em>did a named human authorize</em> the specific thing you are about to do?
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>See it work</h2>
        <p style={styles.body}>
          EMILIA Protocol is the open standard implementation of pre-action authorization. The protocol is formally verified — 26 TLA+ theorems, 35 Alloy facts — and the reference runtime is Apache 2.0.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/protocol" className="ep-cta" style={cta.primary}>Read the protocol</a>
          <a href="/playground" className="ep-cta-secondary" style={cta.secondary}>Try the live demo</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
