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
    page: { minHeight: '100vh', background: '#05060a', color: '#e8eaf0', fontFamily: "'Space Grotesk', -apple-system, sans-serif" },
    section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#0a0c18', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    eyebrow: { fontFamily: "'JetBrains Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#ffd700', marginBottom: 16 },
    h1: { fontFamily: "'Outfit', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 900, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'Outfit', sans-serif", fontSize: 24, fontWeight: 800, letterSpacing: -0.5, marginBottom: 16 },
    body: { fontSize: 16, color: '#7a809a', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#0e1120', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'Outfit', sans-serif", fontSize: 16, fontWeight: 700, color: '#e8eaf0', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#7a809a', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0a0c18', color: '#e8eaf0', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#7a809a', marginBottom: 6, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 },
    highlight: { color: '#e8eaf0', fontWeight: 600 },
  };

  const FEATURES = [
    { title: 'Open trust protocol', body: 'A portable trust model for machine counterparties and software.' },
    { title: 'Policy-based evaluation', body: 'Trust decisions should depend on context and policy, not a single universal score.' },
    { title: 'Trust profiles and preflight', body: 'Structured trust surfaces that can be evaluated before connection, installation, or delegation.' },
    { title: 'Receipts, disputes, and appeals', body: 'Trust should be evidence-based and contestable.' },
    { title: 'Identity and continuity', body: 'Software and machine counterparties need clearer continuity and lineage over time.' },
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
        <div style={s.eyebrow}>Investor Overview</div>
        <h1 style={s.h1}>Invest in the next layer of trust infrastructure</h1>
        <p style={{ ...s.body, maxWidth: 600 }}>
          EMILIA is an open trust protocol for machine counterparties and software. We believe the future needs a portable trust layer that helps organizations know what to trust before connection, installation, or delegation.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#inquiry" style={{ ...s.cta, background: '#ffd700', color: '#05060a' }}>Request Investor Materials</a>
          <a href="mailto:team@emiliaprotocol.ai" style={{ ...s.cta, background: 'transparent', color: '#ffd700', border: '1px solid rgba(255,215,0,0.3)' }}>Start a Conversation</a>
        </div>
        <p style={{ fontSize: 13, color: '#4a4f6a', marginTop: 16, maxWidth: 520 }}>
          We are selectively speaking with aligned investors, strategic partners, and operators who can help EMILIA become both credible infrastructure and a durable company.
        </p>
      </section>

      {/* The thesis */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>The thesis</h2>
          <p style={s.body}>
            Software ecosystems are becoming more open, more dynamic, and more machine-mediated. Agents connect to tools. Developers install packages, extensions, plugins, and GitHub apps. Platforms increasingly expose users to third-party counterparties that can affect data, workflows, execution, and trust.
          </p>
          <p style={s.body}>
            Connection standards help. Metadata helps. Signatures help. Registries help. But they do not fully answer a harder question:
          </p>
          <p style={{ fontFamily: "'Outfit', sans-serif", fontSize: 20, fontWeight: 700, color: '#e8eaf0', lineHeight: 1.5, marginBottom: 24, borderLeft: '3px solid #ffd700', paddingLeft: 20 }}>
            Should this thing be trusted, under what policy, with what evidence, and with what path for dispute or appeal?
          </p>
          <p style={s.body}>EMILIA is designed to fill that gap.</p>
        </div>
      </section>

      {/* Why now */}
      <section style={s.section}>
        <h2 style={s.h2}>Why now</h2>
        <p style={s.body}>
          The shift toward AI agents, machine-to-machine workflows, plugin ecosystems, and delegated software actions creates a new trust problem. The internet has standards for connection, discovery, and identity. It does not yet have a broadly portable trust layer for machine counterparties and software.
        </p>
        <p style={s.body}>
          The winning trust layer is more likely to emerge while these ecosystems are still forming than after habits are already locked in. This is the moment to define trust preflight, policy-aware evaluation, continuity, receipts, disputes, and appeals for modern software ecosystems.
        </p>
      </section>

      {/* What EMILIA is building */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What EMILIA is building</h2>
          <p style={s.body}>EMILIA is building open trust infrastructure with a commercial layer on top.</p>
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
        {['Trust should be portable', 'Trust should be evidence-based', 'Trust should be policy-aware', 'Trust should be appealable', 'Trust infrastructure should have a path toward broader governance'].map((p, i) => (
          <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 8, alignItems: 'center' }}>
            <span style={{ color: '#ffd700', fontSize: 14, flexShrink: 0 }}>+</span>
            <span style={{ fontSize: 15, color: '#7a809a' }}>{p}</span>
          </div>
        ))}
      </section>

      {/* Commercial model */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Commercial model</h2>
          <p style={s.body}>The protocol can remain open while the company builds products and services around it.</p>
          <div style={s.card}>
            {REVENUE.map((r, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, marginBottom: i < REVENUE.length - 1 ? 10 : 0, alignItems: 'center' }}>
                <span style={{ color: '#ffd700', fontSize: 12, flexShrink: 0 }}>+</span>
                <span style={{ fontSize: 14, color: '#7a809a' }}>{r}</span>
              </div>
            ))}
          </div>
          <p style={{ ...s.body, marginTop: 24, fontStyle: 'italic', color: '#4a4f6a' }}>
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
          EMILIA is not being built as a closed scoring product masquerading as infrastructure. It is being built as a trust layer with real implementation discipline and a credible path toward broader legitimacy.
        </p>
      </section>

      {/* What we're looking for */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What we are looking for in capital partners</h2>
          <p style={s.body}>We are looking for aligned capital and strategic help.</p>
          {['Investors who understand infrastructure and standards', 'People who can open pilot opportunities', 'Operators who understand developer ecosystems, AI, trust, or enterprise security', 'Partners who respect the difference between open protocol governance and commercial execution'].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <span style={{ color: '#ffd700', fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: '#7a809a', lineHeight: 1.6 }}>{item}</span>
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
            <span style={{ fontSize: 15, color: '#7a809a', lineHeight: 1.6 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* CTA strip */}
      <section style={{ ...s.sectionAlt, textAlign: 'center' }}>
        <div style={{ ...s.section, maxWidth: 540 }}>
          <h2 style={{ ...s.h2, fontSize: 28 }}>Interested in backing the trust layer before it becomes obvious?</h2>
          <p style={s.body}>
            We are selectively speaking with aligned investors, strategic partners, and operators who can help EMILIA become both credible infrastructure and a durable company.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="#inquiry" style={{ ...s.cta, background: '#ffd700', color: '#05060a' }}>Request Investor Materials</a>
            <a href="mailto:team@emiliaprotocol.ai" style={{ ...s.cta, background: 'transparent', color: '#ffd700', border: '1px solid rgba(255,215,0,0.3)' }}>Start a Conversation</a>
          </div>
        </div>
      </section>

      {/* Inquiry form */}
      <section id="inquiry" style={s.section}>
        <h2 style={s.h2}>Request investor materials</h2>
        {submitted ? (
          <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: '#ffd700', marginBottom: 8 }}>Thank you</div>
            <p style={{ color: '#7a809a', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
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
            <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#ffd700', color: !form.name || !form.email ? '#4a4f6a' : '#05060a', marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting…' : 'Request Investor Materials'}
            </button>
          </div>
        )}
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#4a4f6a', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#4a4f6a', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
