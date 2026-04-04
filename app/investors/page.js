'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

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
    <div style={styles.page}>
      {/* noindex meta */}
      <head><meta name="robots" content="noindex, nofollow" /></head>

      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrow}>Trust Infrastructure</div>
        <h1 style={styles.h1}>Trust before high-risk action.</h1>
        <p style={{ ...styles.body, maxWidth: 600 }}>
          EMILIA is a protocol-grade trust substrate for high-risk action enforcement. It creates the control layer between authentication and execution.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#inquiry" className="ep-cta" style={cta.primary}>Request Investor Materials</a>
          <a href="mailto:team@emiliaprotocol.ai" className="ep-cta-secondary" style={cta.secondary}>Start a Conversation</a>
        </div>
        <p style={{ fontSize: 13, color: color.t3, marginTop: 16, maxWidth: 520 }}>
          We are selectively speaking with aligned investors, strategic partners, and operators who can help EMILIA become both credible infrastructure and a durable company.
        </p>
      </section>

      {/* The thesis */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>The thesis</h2>
          <p style={styles.body}>
            High-risk actions increasingly happen inside authenticated, approved-looking workflows. The hard problem is no longer just who is acting. It is whether this exact action should be allowed to proceed under this exact authority chain and this exact policy.
          </p>
          <p style={styles.body}>
            Connection standards help. Metadata helps. Signatures help. Registries help. But they do not fully answer a harder question:
          </p>
          <p className="ep-blockquote" style={{ fontFamily: font.sans, fontSize: 20, fontWeight: 700, color: color.t1, lineHeight: 1.5, marginBottom: 24, borderLeft: `3px solid ${color.green}`, paddingLeft: 20 }}>
            Should this exact high-risk action be allowed, under what authority, under what policy, and with what protection against replay or reuse?
          </p>
          <p style={styles.body}>EMILIA is designed to fill that gap.</p>
        </div>
      </section>

      {/* Why now */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Why now</h2>
        <p style={styles.body}>
          As governments, enterprises, financial systems, and AI-assisted workflows automate more execution, they need a trust-control layer between authentication and action. That is the category EMILIA now occupies.
        </p>
        <p style={styles.body}>
          The winning trust protocol is more likely to emerge while these ecosystems are still forming than after habits are already locked in. This is the moment to define action-level trust control for governments, financial infrastructure, enterprise privileged actions, and agent execution before weak habits become permanent.
        </p>
      </section>

      {/* What EMILIA is building */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>What EMILIA is building</h2>
          <p style={styles.body}>EMILIA is building protocol-grade trust infrastructure with a commercial layer on top.</p>
          <div style={grid.auto(220)}>
            {FEATURES.map((f, i) => (
              <div key={i} style={styles.card}>
                <div style={styles.cardTitle}>{f.title}</div>
                <div style={styles.cardBody}>{f.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why different */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Why EMILIA is different</h2>
        <p style={styles.body}>EMILIA is not trying to be another black-box scoring product. It is designed around a different set of principles:</p>
        {['Trust should be action-bound', 'Trust should be policy-bound', 'Trust should be replay-resistant', 'Trust should be one-time consumable when used for authorization', 'Trust infrastructure should produce immutable event traceability'].map((p, i) => (
          <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 8, alignItems: 'center' }}>
            <span style={{ color: color.green, fontSize: 14, flexShrink: 0 }}>+</span>
            <span style={{ fontSize: 15, color: color.t2 }}>{p}</span>
          </div>
        ))}
      </section>

      {/* Why this is now a product */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Why this is now a product, not just a protocol</h2>
          <p style={styles.body}>
            Open protocols invite forks. EMILIA is built so the product layer is structurally difficult to replicate without the protocol underneath.
          </p>
          <div style={{ ...grid.auto(280), marginBottom: 24 }}>
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>Technical Moat</div>
              <div style={styles.cardTitle}>Canonical binding</div>
              <div style={styles.cardBody}>
                Every trust decision binds actor identity, authority chain, policy version, and exact action context into a single cryptographic envelope. Forks can copy the spec — they cannot replicate the binding depth without reimplementing the full protocol stack.
              </div>
            </div>
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>Replay Resistance</div>
              <div style={styles.cardTitle}>One-time consumption</div>
              <div style={styles.cardBody}>
                Trust handshakes are consumed on use. They cannot be replayed, reused, or forged after the fact. This is not a feature toggle — it is a structural property of the protocol that competing products cannot bolt on.
              </div>
            </div>
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>Compliance Layer</div>
              <div style={styles.cardTitle}>Policy-bound decisions</div>
              <div style={styles.cardBody}>
                Policies are not just rules — they are versioned, hashed, and auditable artifacts. Every action decision references an immutable policy snapshot. Regulators and auditors get a verifiable chain, not a dashboard screenshot.
              </div>
            </div>
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>Accountability</div>
              <div style={styles.cardTitle}>Accountable signoff</div>
              <div style={styles.cardBody}>
                Every high-risk action traces back to a named human principal with a recorded authority chain. This is the ownership layer that turns trust from a signal into a liability instrument. Buyers pay because someone is accountable.
              </div>
            </div>
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>Revenue Engine</div>
              <div style={styles.cardTitle}>Cloud control plane</div>
              <div style={styles.cardBody}>
                The managed service runs policy evaluation, receipt storage, dispute resolution, and audit export as a hosted control plane. This is recurring infrastructure revenue — not consulting, not one-time license fees.
              </div>
            </div>
            <div style={styles.card}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>Vertical Pricing</div>
              <div style={styles.cardTitle}>Regulated vertical packs</div>
              <div style={styles.cardBody}>
                Government, financial services, and enterprise compliance teams pay for pre-built policy packs, audit-ready receipt formats, and sector-specific conformance profiles. Vertical pricing captures the compliance premium that horizontal SaaS leaves on the table.
              </div>
            </div>
          </div>
          <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7 }}>
            <span style={{ color: color.t1, fontWeight: 600 }}>The moat is above open source.</span> Competitors can read the spec. They cannot replicate the canonical binding, the consumption model, the policy-versioning chain, or the accountability layer without rebuilding EMILIA from scratch. <span style={{ color: color.t1, fontWeight: 600 }}>Buyers pay because compliance and liability reduction are existential</span> — not optional. This is not standards work with a business model bolted on. It is a product that requires the protocol to function.
          </p>
        </div>
      </section>

      {/* Commercial model */}
      <section style={{ background: color.bg }}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Commercial model</h2>
          <p style={styles.body}>The protocol can remain open while the company builds products and services around it.</p>
          <div style={styles.card}>
            {REVENUE.map((r, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, marginBottom: i < REVENUE.length - 1 ? 10 : 0, alignItems: 'center' }}>
                <span style={{ color: color.green, fontSize: 12, flexShrink: 0 }}>+</span>
                <span style={{ fontSize: 14, color: color.t2 }}>{r}</span>
              </div>
            ))}
          </div>
          <p style={{ ...styles.body, marginTop: 24, fontStyle: 'italic', color: color.t3 }}>
            We believe the protocol should be broad enough to matter and the commercial layer focused enough to win.
          </p>
        </div>
      </section>

      {/* Governance position */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Open protocol, aligned company</h2>
        <p style={styles.body}>
          We believe trust infrastructure becomes stronger when the protocol layer is open and the commercial layer is clearly separated. The company can build the reference experience, hosted services, enterprise tooling, and implementation support. Over time, broader participation in governance, conformance expectations, and ecosystem input should strengthen legitimacy and adoption.
        </p>
        <p style={styles.body}>
          EMILIA is not being built as a closed scoring product masquerading as infrastructure. It is being built as an open protocol for high-risk action enforcement with a commercial layer above the repo: cloud control plane, enterprise deployment, and regulated vertical packs.
        </p>
      </section>

      {/* What we're looking for */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>What we are looking for in capital partners</h2>
          <p style={styles.body}>We are looking for aligned capital and strategic help.</p>
          {['Investors who understand infrastructure and standards', 'People who can open pilot opportunities', 'Operators who understand developer ecosystems, AI, trust, or enterprise security', 'Partners who respect the difference between open protocol governance and commercial execution'].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <span style={{ color: color.green, fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* What we're NOT */}
      <section style={styles.section}>
        <h2 style={styles.h2}>What we are not optimizing for</h2>
        {['Capital that wants to close the protocol too early', 'Pressure to reduce EMILIA to a generic SaaS dashboard', 'Short-term growth tactics that weaken neutrality or credibility', 'Passive money with no ecosystem value'].map((item, i) => (
          <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
            <span style={{ color: color.red, fontSize: 14, flexShrink: 0, marginTop: 2 }}>—</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.6 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* What makes EP defensible */}
      <section style={styles.section}>
        <div style={styles.eyebrow}>Defensibility</div>
        <h2 style={styles.h2}>Why EP is a moat, not a feature</h2>
        <p style={styles.body}>
          EP{"'"}s defensibility comes from protocol-grade properties that cannot be replicated by adding a feature to an existing product.
        </p>
        <div style={grid.auto(280)}>
          <div style={styles.card}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>Canonical Binding</div>
            <div style={styles.cardTitle}>Cryptographic action binding</div>
            <div style={styles.cardBody}>
              Every authorization binds 12 fields into a single SHA-256 hash: actor, authority, policy version, exact action context, nonce, and expiry. Forks cannot replicate the binding discipline — it is enforced by runtime guards, CI gates, and formal verification.
            </div>
          </div>
          <div style={styles.card}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.green, marginBottom: 8, textTransform: 'uppercase' }}>One-Time Consumption</div>
            <div style={styles.cardTitle}>Replay-resistant by construction</div>
            <div style={styles.cardBody}>
              Every authorization can be consumed exactly once. Database triggers prevent reversal. Unique constraints enforce atomic insert-or-fail. 100-way concurrent race tests prove zero double-consumption under adversarial conditions.
            </div>
          </div>
          <div style={styles.card}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.blue, marginBottom: 8, textTransform: 'uppercase' }}>Accountable Signoff</div>
            <div style={styles.cardTitle}>Named human ownership before execution</div>
            <div style={styles.cardBody}>
              When policy requires it, a named responsible human must explicitly assume ownership of the exact action before it executes. Not MFA. Not approval theater. Cryptographically bound, policy-driven accountability with recorded authority chain.
            </div>
          </div>
          <div style={styles.card}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, color: color.blue, marginBottom: 8, textTransform: 'uppercase' }}>Cloud Control Plane</div>
            <div style={styles.cardTitle}>Revenue engine above the open protocol</div>
            <div style={styles.cardBody}>
              Managed policy registry, signoff orchestration, event explorer, audit exports, tenant management, alerting, and webhooks. The protocol is open. The control plane is the recurring revenue product. Vertical packs for government, financial, and agent governance add sector pricing.
            </div>
          </div>
        </div>
      </section>

      {/* What is proven now */}
      <section style={styles.section}>
        <div style={styles.eyebrow}>Proof Status</div>
        <h2 style={styles.h2}>What is no longer theoretical</h2>
        <div style={grid.auto(260)}>
          <div style={styles.card}>
            <div style={styles.cardTitle}>Accepted mutual flow</div>
            <div style={styles.cardBody}>
              Full 7-step Accountable Signoff chain proven end-to-end under load: create, present (dual-key), verify (accepted), challenge, attest, consume. Zero errors at 50 concurrent users.
            </div>
          </div>
          <div style={styles.card}>
            <div style={styles.cardTitle}>Measured operating envelope</div>
            <div style={styles.cardBody}>
              Supported band with per-endpoint latency targets. Overload band with explicit 503 backpressure instead of timeout collapse. No correctness violations under stress.
            </div>
          </div>
          <div style={styles.card}>
            <div style={styles.cardTitle}>Protocol + product coherence</div>
            <div style={styles.cardBody}>
              Open protocol, open runtime, managed cloud, enterprise packs, vertical pricing. GitHub release v1.0.0 published. 3,277 automated tests across 125 files, 20 TLA+ theorems machine-verified (TLC 2.19, 0 errors), 116 red team cases documented and remediated.
            </div>
          </div>
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ ...styles.sectionAlt, textAlign: 'center' }}>
        <div style={{ ...styles.section, maxWidth: 540 }}>
          <h2 style={{ ...styles.h2, fontSize: 28 }}>Interested in backing the trust-control layer between authentication and execution?</h2>
          <p style={styles.body}>
            We are selectively speaking with aligned investors, strategic partners, and operators who can help EMILIA become both credible infrastructure and a durable company.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="#inquiry" className="ep-cta" style={cta.primary}>Request Investor Materials</a>
            <a href="mailto:team@emiliaprotocol.ai" className="ep-cta-secondary" style={cta.secondary}>Start a Conversation</a>
          </div>
        </div>
      </section>

      {/* Inquiry form */}
      <section id="inquiry" style={styles.section}>
        <h2 style={styles.h2}>Request investor materials</h2>
        {submitted ? (
          <div style={{ ...styles.card, textAlign: 'center', padding: 40 }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <div style={styles.card}>
            <div style={grid.cols2}>
              {[['name','Name'],['firm','Firm / Organization'],['title','Title'],['email','Email'],['website','Website']].map(([k,label]) => (
                <div key={k} style={k === 'website' ? { gridColumn: '1 / -1' } : {}}>
                  <label style={styles.label}>{label}</label>
                  <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                </div>
              ))}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>Why EMILIA?</label>
                <textarea className="ep-input" style={{ ...styles.input, minHeight: 80, resize: 'vertical' }} value={form.whyEmilia} onChange={e => update('whyEmilia', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>What can you help with?</label>
                <textarea className="ep-input" style={{ ...styles.input, minHeight: 60, resize: 'vertical' }} value={form.helpOffer} onChange={e => update('helpOffer', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>Notes</label>
                <input className="ep-input" style={styles.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
              </div>
            </div>
            {error && <p style={{ color: color.red, fontSize: 13, marginTop: 12 }}>{error}</p>}
            <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...((!form.name || !form.email) ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting...' : 'Request Investor Materials'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
