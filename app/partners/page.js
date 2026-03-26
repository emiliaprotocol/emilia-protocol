'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function PartnersPage() {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', website:'', partnerType:'', trustSurface:'', problem:'', timeline:'', notes:'' });
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
        body: JSON.stringify({ type: 'partner', ...form }),
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
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#3B82F6', marginBottom: 16 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 24, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 },
    body: { fontSize: 16, color: '#94A3B8', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, color: '#F8FAFC', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#94A3B8', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0F172A', color: '#F8FAFC', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#94A3B8', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 0.5 },
    li: { fontSize: 15, color: '#94A3B8', lineHeight: 1.7, marginBottom: 6 },
  };

  const AUDIENCE = [
    { title: 'Pilot deployments', body: 'Test EMILIA in a real workflow — payment approvals, agent execution, operator overrides, or delegated authority. Prove control value in 60 to 90 days with one action class.' },
    { title: 'Regulated workflow design partners', body: 'Government agencies, banks, and enterprises that need policy-bound, auditable control over high-risk actions before they execute. Shape the compliance patterns that become defaults.' },
    { title: 'Control architecture partnerships', body: 'Integrate the EMILIA Protocol into existing infrastructure — identity providers, CI/CD pipelines, SIEM platforms, or agent orchestration layers. Make EP the enforcement point inside what you already run.' },
  ];

  const PILOT_STEPS = [
    'Select one trust surface such as MCP servers, browser extensions, GitHub apps, npm packages, or agent tools',
    'Define one or two policies relevant to your workflow',
    'Register counterparties and generate trust profiles',
    'Run policy evaluation and install preflight',
    'Capture trust receipts and workflow decisions',
    'Test dispute and appeal paths where relevant',
    'Produce a final trust review with lessons, metrics, and implementation recommendations',
  ];

  const BENEFITS = [
    'Priority onboarding support',
    'Access to implementation guidance',
    'Policy design collaboration',
    'Early visibility into protocol evolution',
    'Optional case study collaboration',
    'Opportunity to shape ecosystem norms',
  ];

  const FAQS = [
    { q: 'Is EMILIA open source?', a: 'EMILIA is being developed as open trust infrastructure with a focus on portability, inspectability, and implementability.' },
    { q: 'Do pilot partners need to commit long term?', a: 'No. Early pilots are designed to be narrow, practical, and time-bounded.' },
    { q: 'Is this only for AI agents?', a: 'No. AI is one entry point. The broader category is high-risk action enforcement across government, payments, enterprise approvals, and agent workflows.' },
    { q: 'Are you looking for technical contributors too?', a: 'Yes. We are open to technical reviewers, maintainers, and governance participants who can strengthen correctness and adoption.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="Partners" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Partners</div>
        <h1 style={s.h1}>Pilot EMILIA in a real high-risk workflow</h1>
        <p style={{ ...s.body, maxWidth: 620 }}>
          Start with one action class — payment changes, delegated approvals, operator overrides, or agent execution — and prove the control value fast.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#inquiry" style={{ ...s.cta, background: '#3B82F6', color: '#020617' }}>Apply for a Pilot</a>
          <a href="mailto:team@emiliaprotocol.ai" style={{ ...s.cta, background: 'transparent', color: '#3B82F6', border: '1px solid rgba(212,175,55,0.3)' }}>Talk to the Team</a>
        </div>
        <p style={{ fontSize: 13, color: '#64748B', marginTop: 16 }}>
          We are looking for pilot deployment partners, regulated workflow design partners, and control architecture integrators.
        </p>
      </section>

      {/* Why partner now */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Why partner now</h2>
          <p style={s.body}>
            High-risk actions are already executing inside authenticated, approved-looking workflows. Agents approve payments. Operators override limits. Delegated authority chains span multiple systems. The question is no longer who is acting — it is whether this exact action should proceed under this exact authority and this exact policy.
          </p>
          <p style={s.body}>
            EMILIA gives you the enforcement point. Partners deploy it inside a real workflow and prove the control value before competitors define the category.
          </p>
        </div>
      </section>

      {/* Partnership categories */}
      <section style={s.section}>
        <h2 style={s.h2}>How to partner</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
          {AUDIENCE.map((c, i) => (
            <div key={i} style={s.card}>
              <div style={s.cardTitle}>{c.title}</div>
              <div style={s.cardBody}>{c.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* What a pilot looks like */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What a pilot looks like</h2>
          <p style={s.body}>A typical EMILIA pilot runs for 60 to 90 days and focuses on a narrow, high-value trust surface.</p>
          <div style={{ ...s.card, marginBottom: 24 }}>
            {PILOT_STEPS.map((step, i) => (
              <div key={i} style={{ display: 'flex', gap: 12, marginBottom: i < PILOT_STEPS.length - 1 ? 12 : 0, alignItems: 'flex-start' }}>
                <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, color: '#3B82F6', minWidth: 20, flexShrink: 0 }}>{String(i + 1).padStart(2, '0')}</span>
                <span style={s.li}>{step}</span>
              </div>
            ))}
          </div>
          <a href="#inquiry" style={{ ...s.cta, background: '#3B82F6', color: '#020617' }}>Apply for a Pilot</a>
        </div>
      </section>

      {/* What partners get */}
      <section style={s.section}>
        <h2 style={s.h2}>What partners get</h2>
        <p style={s.body}>
          Partners receive direct access to the EMILIA team, implementation support, working sessions on policy design, early influence on trust surfaces and conformance expectations, and a structured pilot review at the end of the engagement.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {BENEFITS.map((b, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <span style={{ color: '#3B82F6', fontSize: 14, flexShrink: 0 }}>+</span>
              <span style={{ fontSize: 14, color: '#94A3B8' }}>{b}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Governance */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Open protocol. Thoughtful governance.</h2>
          <p style={s.body}>
            EMILIA is being developed as open trust infrastructure. The goal is not a black-box scoring product. The goal is a trust protocol that can become portable, inspectable, and broadly implementable across software ecosystems.
          </p>
          <p style={s.body}>
            The commercial team can build reference implementations, hosted services, enterprise tooling, and support. Governance should become broader over time through outside participation, conformance processes, and structured ecosystem input.
          </p>
        </div>
      </section>

      {/* Strong first-fit */}
      <section style={s.section}>
        <h2 style={s.h2}>Strong first-fit partners</h2>
        <p style={s.body}>
          The best early partners are organizations that already face real liability around payment changes, delegated approvals, operator overrides, or agent execution — and need auditable, policy-bound control before action proceeds.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {['Government agencies with delegated authority', 'Banks and payment processors', 'Enterprise compliance teams', 'Agent orchestration platforms', 'CI/CD and DevSecOps pipelines', 'Identity and access management vendors', 'Regulated industry SaaS'].map(tag => (
            <span key={tag} style={{ padding: '6px 14px', borderRadius: 100, border: '1px solid rgba(212,175,55,0.15)', background: 'rgba(212,175,55,0.04)', fontSize: 13, color: '#3B82F6' }}>{tag}</span>
          ))}
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ ...s.sectionAlt, textAlign: 'center' }}>
        <div style={{ ...s.section, maxWidth: 540 }}>
          <h2 style={{ ...s.h2, fontSize: 28 }}>Ready to deploy control before action in a real workflow?</h2>
          <p style={s.body}>
            We are looking for a small number of deployment partners who want to prove policy-bound, auditable action control in production — not in theory.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="#inquiry" style={{ ...s.cta, background: '#3B82F6', color: '#020617' }}>Apply for a Pilot</a>
            <a href="mailto:team@emiliaprotocol.ai" style={{ ...s.cta, background: 'transparent', color: '#3B82F6', border: '1px solid rgba(212,175,55,0.3)' }}>Request a Conversation</a>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section style={s.section}>
        <h2 style={s.h2}>Frequently asked questions</h2>
        {FAQS.map((faq, i) => (
          <div key={i} style={{ marginBottom: 24, paddingBottom: 24, borderBottom: i < FAQS.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#F8FAFC', marginBottom: 6 }}>{faq.q}</div>
            <div style={{ fontSize: 15, color: '#94A3B8', lineHeight: 1.7 }}>{faq.a}</div>
          </div>
        ))}
      </section>

      {/* Inquiry form */}
      <section id="inquiry" style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Partner inquiry</h2>
          {submitted ? (
            <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#3B82F6', marginBottom: 8 }}>Thank you</div>
              <p style={{ color: '#94A3B8', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={s.card}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                {[['name','Name'],['org','Company / Organization'],['title','Title'],['email','Work email'],['website','Website']].map(([k,label]) => (
                  <div key={k} style={k === 'website' ? { gridColumn: '1 / -1' } : {}}>
                    <label style={s.label}>{label}</label>
                    <input style={s.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div>
                  <label style={s.label}>Partner type</label>
                  <select style={{ ...s.input, cursor: 'pointer' }} value={form.partnerType} onChange={e => update('partnerType', e.target.value)}>
                    <option value="">Select…</option>
                    {['Pilot deployment partner','Regulated workflow design partner','Control architecture integration partner','Technical reviewer','Other'].map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
                <div>
                  <label style={s.label}>Trust surface</label>
                  <select style={{ ...s.input, cursor: 'pointer' }} value={form.trustSurface} onChange={e => update('trustSurface', e.target.value)}>
                    <option value="">Select…</option>
                    {['MCP servers','Browser extensions','GitHub apps / actions','npm packages','Agent tools','Marketplace plugins','Other'].map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>What are you trying to solve?</label>
                  <textarea style={{ ...s.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
                </div>
                <div>
                  <label style={s.label}>Timeline</label>
                  <input style={s.input} value={form.timeline} onChange={e => update('timeline', e.target.value)} placeholder="e.g. Q2 2026" />
                </div>
                <div>
                  <label style={s.label}>Optional notes</label>
                  <input style={s.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
                </div>
              </div>
              {error && <p style={{ color: '#f87171', fontSize: 13, marginTop: 12 }}>{error}</p>}
              <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#3B82F6', color: !form.name || !form.email ? '#64748B' : '#020617', marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting…' : 'Submit Partner Inquiry'}
              </button>
            </div>
          )}
        </div>
      </section>

      <SiteNav activePage="Partners" showFooter={false} />
      {/* Footer */}
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
