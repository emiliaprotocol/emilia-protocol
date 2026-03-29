'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function InvestorsPage() {
  const [form, setForm] = useState({ name:'', firm:'', title:'', email:'', website:'', whyEmilia:'', helpOffer:'', notes:'' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const res = await fetch('/api/inquiries', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'investor', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const s = {
    page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
    section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#0F172A', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 16 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 24, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 },
    body: { fontSize: 16, color: '#94A3B8', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, color: '#F8FAFC', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#94A3B8', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0F172A', color: '#F8FAFC', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#94A3B8', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 0.5 },
    highlight: { color: '#F8FAFC', fontWeight: 600 },
  };

  const FEATURES = [
    { title: 'Protocol-grade trust substrate', body: 'Infrastructure for high-risk action enforcement between authentication and execution.' },
    { title: 'Policy-based evaluation', body: 'Trust decisions should depend on context and policy, not a single universal score.' },
    { title: 'Handshake and action control', body: 'Pre-action trust enforcement that binds actor, authority, policy, and exact action context.' },
    { title: 'Accountable signoff and evidence', body: 'High-risk actions can require named human ownership, policy snapshots, and reconstruction-ready event trails.' },
    { title: 'Replay-resistant authorization', body: 'One-time consumption, policy binding, and immutable events for high-risk workflows.' },
    { title: 'Commercial products', body: 'Reference implementations, enterprise trust console, hosted services, integrations, and workflow tooling.' },
  ];

  const REVENUE = ['Enterprise trust console', 'Managed hosting', 'Policy packs and integrations', 'Premium registries and workflow tooling', 'Compliance and audit workflows', 'Onboarding and implementation services', 'Ecosystem-specific trust products built on top of EMILIA'];

  return (
    <div style={s.page}>
      {/* noindex meta */}
      <head><meta name="robots" content="noindex, nofollow" /></head>

      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Trust Infrastructure</div>
        <h1 style={s.h1}>Trust before high-risk action.</h1>
        <p style={{ ...s.body, maxWidth: 600 }}>
          EMILIA is a protocol-grade trust substrate for high-risk action enforcement. It creates the control layer between authentication and execution.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#inquiry" style={{ ...s.cta, background: '#22C55E', color: '#020617' }}>Request Investor Materials</a>
          <a href="mailto:team@emiliaprotocol.ai" style={{ ...s.cta, background: 'transparent', color: '#22C55E', border: '1px solid rgba(34,197,94,0.3)' }}>Start a Conversation</a>
        </div>
        <p style={{ fontSize: 13, color: '#64748B', marginTop: 16, maxWidth: 520 }}>
          We are selectively speaking with aligned investors, strategic partners, and operators who can help EMILIA become both credible infrastructure and a durable company.
        </p>
      </section>

      {/* The thesis */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>The thesis</h2>
          <p style={s.body}>
            High-risk actions increasingly happen inside authenticated, approved-looking workflows. The hard problem is no longer just who is acting. It is whether this exact action should be allowed to proceed under this exact authority chain and this exact policy.
          </p>
          <p style={s.body}>
            Connection standards help. Metadata helps. Signatures help. Registries help. But they do not fully answer a harder question:
          </p>
          <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 20, fontWeight: 700, color: '#F8FAFC', lineHeight: 1.5, marginBottom: 24, borderLeft: '3px solid #22C55E', paddingLeft: 20 }}>
            Should this exact high-risk action be allowed, under what authority, under what policy, and with what protection against replay or reuse?
          </p>
          <p style={s.body}>EMILIA is designed to fill that gap.</p>
        </div>
      </section>

      {/* Why now */}
      <section style={s.section}>
        <h2 style={s.h2}>Why now</h2>
        <p style={s.body}>
          As governments, enterprises, financial systems, and AI-assisted workflows automate more execution, they need a trust-control layer between authentication and action. That is the category EMILIA now occupies.
        </p>
        <p style={s.body}>
          The winning trust protocol is more likely to emerge while these ecosystems are still forming than after habits are already locked in. This is the moment to define action-level trust control for governments, financial infrastructure, enterprise privileged actions, and agent execution before weak habits become permanent.
        </p>
      </section>

      {/* What EMILIA is building */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What EMILIA is building</h2>
          <p style={s.body}>EMILIA is building protocol-grade trust infrastructure with a commercial layer on top.</p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
            {FEATURES.map((f, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{f.title}</div>
                <div style={s.cardBody}>{f.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why different */}
      <section style={s.section}>
        <h2 style={s.h2}>Why EMILIA is different</h2>
        <p style={s.body}>EMILIA is not trying to be another black-box scoring product. It is designed around a different set of principles:</p>
        {['Trust should be action-bound', 'Trust should be policy-bound', 'Trust should be replay-resistant', 'Trust should be one-time consumable when used for authorization', 'Trust infrastructure should produce immutable event traceability'].map((p, i) => (
          <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 8, alignItems: 'center' }}>
            <span style={{ color: '#22C55E', fontSize: 14, flexShrink: 0 }}>+</span>
            <span style={{ fontSize: 15, color: '#94A3B8' }}>{p}</span>
          </div>
        ))}
      </section>

      {/* Why this is now a product */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Why this is now a product, not just a protocol</h2>
          <p style={s.body}>
            Open protocols invite forks. EMILIA is built so the product layer is structurally difficult to replicate without the protocol underneath.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 24 }}>
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>Technical Moat</div>
              <div style={s.cardTitle}>Canonical binding</div>
              <div style={s.cardBody}>
                Every trust decision binds actor identity, authority chain, policy version, and exact action context into a single cryptographic envelope. Forks can copy the spec — they cannot replicate the binding depth without reimplementing the full protocol stack.
              </div>
            </div>
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>Replay Resistance</div>
              <div style={s.cardTitle}>One-time consumption</div>
              <div style={s.cardBody}>
                Trust handshakes are consumed on use. They cannot be replayed, reused, or forged after the fact. This is not a feature toggle — it is a structural property of the protocol that competing products cannot bolt on.
              </div>
            </div>
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>Compliance Layer</div>
              <div style={s.cardTitle}>Policy-bound decisions</div>
              <div style={s.cardBody}>
                Policies are not just rules — they are versioned, hashed, and auditable artifacts. Every action decision references an immutable policy snapshot. Regulators and auditors get a verifiable chain, not a dashboard screenshot.
              </div>
            </div>
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>Accountability</div>
              <div style={s.cardTitle}>Accountable signoff</div>
              <div style={s.cardBody}>
                Every high-risk action traces back to a named human principal with a recorded authority chain. This is the ownership layer that turns trust from a signal into a liability instrument. Buyers pay because someone is accountable.
              </div>
            </div>
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>Revenue Engine</div>
              <div style={s.cardTitle}>Cloud control plane</div>
              <div style={s.cardBody}>
                The managed service runs policy evaluation, receipt storage, dispute resolution, and audit export as a hosted control plane. This is recurring infrastructure revenue — not consulting, not one-time license fees.
              </div>
            </div>
            <div style={s.card}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>Vertical Pricing</div>
              <div style={s.cardTitle}>Regulated vertical packs</div>
              <div style={s.cardBody}>
                Government, financial services, and enterprise compliance teams pay for pre-built policy packs, audit-ready receipt formats, and sector-specific conformance profiles. Vertical pricing captures the compliance premium that horizontal SaaS leaves on the table.
              </div>
            </div>
          </div>
          <p style={{ fontSize: 15, color: '#94A3B8', lineHeight: 1.7 }}>
            <span style={{ color: '#F8FAFC', fontWeight: 600 }}>The moat is above open source.</span> Competitors can read the spec. They cannot replicate the canonical binding, the consumption model, the policy-versioning chain, or the accountability layer without rebuilding EMILIA from scratch. <span style={{ color: '#F8FAFC', fontWeight: 600 }}>Buyers pay because compliance and liability reduction are existential</span> — not optional. This is not standards work with a business model bolted on. It is a product that requires the protocol to function.
          </p>
        </div>
      </section>

      {/* Commercial model */}
      <section style={{ background: '#020617' }}>
        <div style={s.section}>
          <h2 style={s.h2}>Commercial model</h2>
          <p style={s.body}>The protocol can remain open while the company builds products and services around it.</p>
          <div style={s.card}>
            {REVENUE.map((r, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, marginBottom: i < REVENUE.length - 1 ? 10 : 0, alignItems: 'center' }}>
                <span style={{ color: '#22C55E', fontSize: 12, flexShrink: 0 }}>+</span>
                <span style={{ fontSize: 14, color: '#94A3B8' }}>{r}</span>
              </div>
            ))}
          </div>
          <p style={{ ...s.body, marginTop: 24, fontStyle: 'italic', color: '#64748B' }}>
            We believe the protocol should be broad enough to matter and the commercial layer focused enough to win.
          </p>
        </div>
      </section>

      {/* Governance position */}
      <section style={s.section}>
        <h2 style={s.h2}>Open protocol, aligned company</h2>
        <p style={s.body}>
          We believe trust infrastructure becomes stronger when the protocol layer is open and the commercial layer is clearly separated. The company can build the reference experience, hosted services, enterprise tooling, and implementation support. Over time, broader participation in governance, conformance expectations, and ecosystem input should strengthen legitimacy and adoption.
        </p>
        <p style={s.body}>
          EMILIA is not being built as a closed scoring product masquerading as infrastructure. It is being built as an open protocol for high-risk action enforcement with a commercial layer above the repo: cloud control plane, enterprise deployment, and regulated vertical packs.
        </p>
      </section>

      {/* What we're looking for */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What we are looking for in capital partners</h2>
          <p style={s.body}>We are looking for aligned capital and strategic help.</p>
          {['Investors who understand infrastructure and standards', 'People who can open pilot opportunities', 'Operators who understand developer ecosystems, AI, trust, or enterprise security', 'Partners who respect the difference between open protocol governance and commercial execution'].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <span style={{ color: '#22C55E', fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: '#94A3B8', lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* What we're NOT */}
      <section style={s.section}>
        <h2 style={s.h2}>What we are not optimizing for</h2>
        {['Capital that wants to close the protocol too early', 'Pressure to reduce EMILIA to a generic SaaS dashboard', 'Short-term growth tactics that weaken neutrality or credibility', 'Passive money with no ecosystem value'].map((item, i) => (
          <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
            <span style={{ color: '#f87171', fontSize: 14, flexShrink: 0, marginTop: 2 }}>—</span>
            <span style={{ fontSize: 15, color: '#94A3B8', lineHeight: 1.6 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* What makes EP defensible */}
      <section style={s.section}>
        <div style={s.eyebrow}>Defensibility</div>
        <h2 style={s.h2}>Why EP is a moat, not a feature</h2>
        <p style={s.body}>
          EP{"'"}s defensibility comes from protocol-grade properties that cannot be replicated by adding a feature to an existing product.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          <div style={{ ...s.card, borderColor: 'rgba(34,197,94,0.2)' }}>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>Canonical Binding</div>
            <div style={s.cardTitle}>Cryptographic action binding</div>
            <div style={s.cardBody}>
              Every authorization binds 12 fields into a single SHA-256 hash: actor, authority, policy version, exact action context, nonce, and expiry. Forks cannot replicate the binding discipline — it is enforced by runtime guards, CI gates, and formal verification.
            </div>
          </div>
          <div style={{ ...s.card, borderColor: 'rgba(34,197,94,0.2)' }}>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#22C55E', marginBottom: 8, textTransform: 'uppercase' }}>One-Time Consumption</div>
            <div style={s.cardTitle}>Replay-resistant by construction</div>
            <div style={s.cardBody}>
              Every authorization can be consumed exactly once. Database triggers prevent reversal. Unique constraints enforce atomic insert-or-fail. 100-way concurrent race tests prove zero double-consumption under adversarial conditions.
            </div>
          </div>
          <div style={{ ...s.card, borderColor: 'rgba(34,197,94,0.2)' }}>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#3B82F6', marginBottom: 8, textTransform: 'uppercase' }}>Accountable Signoff</div>
            <div style={s.cardTitle}>Named human ownership before execution</div>
            <div style={s.cardBody}>
              When policy requires it, a named responsible human must explicitly assume ownership of the exact action before it executes. Not MFA. Not approval theater. Cryptographically bound, policy-driven accountability with recorded authority chain.
            </div>
          </div>
          <div style={{ ...s.card, borderColor: 'rgba(34,197,94,0.2)' }}>
            <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, color: '#3B82F6', marginBottom: 8, textTransform: 'uppercase' }}>Cloud Control Plane</div>
            <div style={s.cardTitle}>Revenue engine above the open protocol</div>
            <div style={s.cardBody}>
              Managed policy registry, signoff orchestration, event explorer, audit exports, tenant management, alerting, and webhooks. The protocol is open. The control plane is the recurring revenue product. Vertical packs for government, financial, and agent governance add sector pricing.
            </div>
          </div>
        </div>
      </section>

      {/* What is proven now */}
      <section style={s.section}>
        <div style={s.eyebrow}>Proof Status</div>
        <h2 style={s.h2}>What is no longer theoretical</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
          <div style={{ ...s.card, borderColor: 'rgba(34,197,94,0.2)' }}>
            <div style={s.cardTitle}>Accepted mutual flow</div>
            <div style={s.cardBody}>
              Full 7-step Accountable Signoff chain proven end-to-end under load: create, present (dual-key), verify (accepted), challenge, attest, consume. Zero errors at 50 concurrent users.
            </div>
          </div>
          <div style={{ ...s.card, borderColor: 'rgba(34,197,94,0.2)' }}>
            <div style={s.cardTitle}>Measured operating envelope</div>
            <div style={s.cardBody}>
              Supported band with per-endpoint latency targets. Overload band with explicit 503 backpressure instead of timeout collapse. No correctness violations under stress.
            </div>
          </div>
          <div style={{ ...s.card, borderColor: 'rgba(34,197,94,0.2)' }}>
            <div style={s.cardTitle}>Protocol + product coherence</div>
            <div style={s.cardBody}>
              Open protocol, open runtime, managed cloud, enterprise packs, vertical pricing. GitHub release v1.0.0 published. 1,500+ tests, 19 TLA+ theorems, 85 red team cases.
            </div>
          </div>
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ ...s.sectionAlt, textAlign: 'center' }}>
        <div style={{ ...s.section, maxWidth: 540 }}>
          <h2 style={{ ...s.h2, fontSize: 28 }}>Interested in backing the trust-control layer between authentication and execution?</h2>
          <p style={s.body}>
            We are selectively speaking with aligned investors, strategic partners, and operators who can help EMILIA become both credible infrastructure and a durable company.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="#inquiry" style={{ ...s.cta, background: '#22C55E', color: '#020617' }}>Request Investor Materials</a>
            <a href="mailto:team@emiliaprotocol.ai" style={{ ...s.cta, background: 'transparent', color: '#22C55E', border: '1px solid rgba(34,197,94,0.3)' }}>Start a Conversation</a>
          </div>
        </div>
      </section>

      {/* Inquiry form */}
      <section id="inquiry" style={s.section}>
        <h2 style={s.h2}>Request investor materials</h2>
        {submitted ? (
          <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: '#22C55E', marginBottom: 8 }}>Thank you</div>
            <p style={{ color: '#94A3B8', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <div style={s.card}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {[['name','Name'],['firm','Firm / Organization'],['title','Title'],['email','Email'],['website','Website']].map(([k,label]) => (
                <div key={k} style={k === 'website' ? { gridColumn: '1 / -1' } : {}}>
                  <label style={s.label}>{label}</label>
                  <input style={s.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                </div>
              ))}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={s.label}>Why EMILIA?</label>
                <textarea style={{ ...s.input, minHeight: 80, resize: 'vertical' }} value={form.whyEmilia} onChange={e => update('whyEmilia', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={s.label}>What can you help with?</label>
                <textarea style={{ ...s.input, minHeight: 60, resize: 'vertical' }} value={form.helpOffer} onChange={e => update('helpOffer', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={s.label}>Notes</label>
                <input style={s.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
              </div>
            </div>
            {error && <p style={{ color: '#f87171', fontSize: 13, marginTop: 12 }}>{error}</p>}
            <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#22C55E', color: !form.name || !form.email ? '#64748B' : '#020617', marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting…' : 'Request Investor Materials'}
            </button>
          </div>
        )}
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#64748B', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#64748B', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
