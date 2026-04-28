'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

export default function PartnersPage() {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', website:'', partnerType:'', trustSurface:'', problem:'', timeline:'', notes:'' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

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

  const AUDIENCE = [
    { title: 'Pilot deployments', body: 'Test EMILIA in a real workflow — payment approvals, agent execution, operator overrides, or delegated authority. Prove control value in 60 to 90 days with one action class.' },
    { title: 'Regulated workflow design partners', body: 'Government agencies, banks, and enterprises that need policy-bound, auditable control over high-risk actions before they execute. Shape the compliance patterns that become defaults.' },
    { title: 'Control architecture partnerships', body: 'Integrate the EMILIA Protocol into existing infrastructure — identity providers, CI/CD pipelines, SIEM platforms, or agent orchestration layers. Make EP the enforcement point inside what you already run.' },
  ];

  const PILOT_STEPS = [
    'Select one high-risk workflow such as a beneficiary change, payment destination change, operator override, privileged production action, or destructive agent tool use',
    'Define one or two policies relevant to your workflow',
    'Register counterparties and generate trust profiles',
    'Run policy evaluation, Handshake, and—if needed—Accountable Signoff',
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

  const cardStyle = (accent) => ({
    border: `1px solid ${color.border}`,
    borderTop: `2px solid ${accent}`,
    borderRadius: radius.base,
    padding: '24px',
    background: '#FAFAF9',
  });

  return (
    <div style={styles.page}>
      <SiteNav activePage="Partners" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 72 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Partners</div>
        <h1 className="ep-hero-text" style={styles.h1}>Pilot EMILIA in a real high-risk workflow</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Start with one action class — payment changes, delegated approvals, operator overrides, or agent execution — and prove the control value fast.
        </p>
        <div className="ep-hero-text" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="#inquiry" className="ep-cta" style={cta.primary}>Apply for a Pilot</a>
          <a href="mailto:team@emiliaprotocol.ai" className="ep-cta-secondary" style={cta.secondary}>Talk to the Team</a>
        </div>
        <p className="ep-hero-text" style={{ fontSize: 13, color: color.t3 }}>
          We are looking for pilot deployment partners, regulated workflow design partners, and control architecture integrators.
        </p>
      </section>

      {/* Why partner now */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 24 }}>
            <h2 style={styles.h2}>Why partner now</h2>
            <p style={styles.body}>
              High-risk actions are already executing inside authenticated, approved-looking workflows. Agents approve payments. Operators override limits. Delegated authority chains span multiple systems. The question is no longer who is acting — it is whether this exact action should proceed under this exact authority and this exact policy.
            </p>
            <p style={styles.body}>
              EMILIA gives you the enforcement point. Partners deploy it inside a real workflow and prove the control value before competitors define the category.
            </p>
          </div>
        </div>
      </section>

      {/* How to partner */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <h2 style={styles.h2}>How to partner</h2>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {AUDIENCE.map((c, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>PARTNERSHIP {String(i + 1).padStart(2, '0')}</div>
              <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{c.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{c.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* What a pilot looks like */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>What a pilot looks like</h2>
            <p style={styles.body}>A typical EMILIA pilot runs for 60 to 90 days and focuses on a narrow, high-value trust surface.</p>
          </div>
          <div className="ep-reveal" style={{
            borderTop: `1px solid ${color.border}`,
            borderLeft: `1px solid ${color.border}`,
            marginBottom: 32,
          }}>
            {PILOT_STEPS.map((step, i) => (
              <div key={i} className="ep-row-hover" style={{
                display: 'flex', gap: 24, alignItems: 'flex-start',
                padding: '16px 24px',
                borderRight: `1px solid ${color.border}`,
                borderBottom: `1px solid ${color.border}`,
              }}>
                <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 600, color: color.blue, minWidth: 28, flexShrink: 0, paddingTop: 1 }}>{String(i + 1).padStart(2, '0')}</span>
                <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{step}</span>
              </div>
            ))}
          </div>
          <a href="#inquiry" className="ep-cta" style={cta.primary}>Apply for a Pilot</a>
        </div>
      </section>

      {/* What partners get */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 32 }}>
          <h2 style={styles.h2}>What partners get</h2>
          <p style={styles.body}>
            Partners receive direct access to the EMILIA team, implementation support, working sessions on policy design, early influence on trust surfaces and conformance expectations, and a structured pilot review at the end of the engagement.
          </p>
        </div>
        {BENEFITS.map((b, i) => (
          <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
            <span className="ep-list-bullet">+</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{b}</span>
          </div>
        ))}
      </section>

      {/* Governance */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 24 }}>
            <h2 style={styles.h2}>Open protocol. Thoughtful governance.</h2>
            <p style={styles.body}>
              EMILIA is being developed as open trust infrastructure. The goal is not a black-box scoring product. The goal is a trust protocol that can become portable, inspectable, and broadly implementable across software ecosystems.
            </p>
            <p style={styles.body}>
              The commercial team can build reference implementations, hosted services, enterprise tooling, and support. Governance should become broader over time through outside participation, conformance processes, and structured ecosystem input.
            </p>
          </div>
        </div>
      </section>

      {/* Strong first-fit */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 32 }}>
          <h2 style={styles.h2}>Strong first-fit partners</h2>
          <p style={styles.body}>
            The best early partners are organizations that already face real liability around payment changes, delegated approvals, operator overrides, or agent execution — and need auditable, policy-bound control before action proceeds.
          </p>
        </div>
        <div className="ep-reveal" style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {['Government agencies with delegated authority', 'Banks and payment processors', 'Enterprise compliance teams', 'Agent orchestration platforms', 'CI/CD and DevSecOps pipelines', 'Identity and access management vendors', 'Regulated industry SaaS'].map(tag => (
            <span key={tag} style={{ padding: '6px 14px', borderRadius: 100, border: `1px solid ${color.border}`, background: 'rgba(59,130,246,0.04)', fontSize: 13, color: color.blue }}>{tag}</span>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>Frequently asked questions</h2>
          </div>
          <div className="ep-reveal" style={{
            borderTop: `1px solid ${color.border}`,
            borderLeft: `1px solid ${color.border}`,
          }}>
            {FAQS.map((faq, i) => (
              <div key={i} className="ep-row-hover" style={{
                padding: '20px 24px',
                borderRight: `1px solid ${color.border}`,
                borderBottom: `1px solid ${color.border}`,
              }}>
                <div style={{ fontSize: 15, fontWeight: 700, color: color.t1, marginBottom: 6 }}>{faq.q}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.7 }}>{faq.a}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Partner Program</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Deploy control before action in a real workflow
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            We are looking for a small number of deployment partners who want to prove policy-bound, auditable action control in production — not in theory.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="#inquiry" className="ep-cta" style={cta.primary}>Apply for a Pilot</a>
            <a href="mailto:team@emiliaprotocol.ai" className="ep-cta-secondary" style={{ ...cta.secondary, borderColor: 'rgba(255,255,255,0.15)', color: 'rgba(250,250,249,0.7)' }}>Request a Conversation →</a>
          </div>
        </div>
      </section>

      {/* Inquiry form */}
      <section id="inquiry" style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 32 }}>
          <h2 style={styles.h2}>Partner inquiry</h2>
        </div>
        {submitted ? (
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.blue}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.blue, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <div style={styles.card}>
            <div style={grid.cols2}>
              {[['name','Name'],['org','Company / Organization'],['title','Title'],['email','Work email'],['website','Website']].map(([k,label]) => (
                <div key={k} style={k === 'website' ? { gridColumn: '1 / -1' } : {}}>
                  <label style={styles.label}>{label}</label>
                  <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                </div>
              ))}
              <div>
                <label style={styles.label}>Partner type</label>
                <select className="ep-input" style={{ ...styles.input, cursor: 'pointer' }} value={form.partnerType} onChange={e => update('partnerType', e.target.value)}>
                  <option value="">Select...</option>
                  {['Pilot deployment partner','Regulated workflow design partner','Control architecture integration partner','Technical reviewer','Other'].map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
              <div>
                <label style={styles.label}>Workflow to control</label>
                <select className="ep-input" style={{ ...styles.input, cursor: 'pointer' }} value={form.trustSurface} onChange={e => update('trustSurface', e.target.value)}>
                  <option value="">Select...</option>
                  {[
                    'Vendor bank-account change',
                    'Benefit redirect / benefit-routing change',
                    'Large payment release',
                    'Operator override / caseworker override',
                    'Beneficiary creation',
                    'Privileged production action',
                    'AI-agent-initiated payment action',
                    'Other',
                  ].map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>What are you trying to solve?</label>
                <textarea className="ep-input" style={{ ...styles.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
              </div>
              <div>
                <label style={styles.label}>Timeline</label>
                <input className="ep-input" style={styles.input} value={form.timeline} onChange={e => update('timeline', e.target.value)} placeholder="e.g. Q2 2026" />
              </div>
              <div>
                <label style={styles.label}>Optional notes</label>
                <input className="ep-input" style={styles.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
              </div>
            </div>
            {error && <p style={{ color: '#DC2626', fontSize: 13, marginTop: 12 }}>{error}</p>}
            <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...((!form.name || !form.email) ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting...' : 'Submit Partner Inquiry'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
