'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export default function EnterprisePage() {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', surface:'', problem:'', notes:'' });
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
        body: JSON.stringify({ type: 'pilot-enterprise', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  // Honest enterprise feature list. SAML / SCIM / OIDC removed —
  // not implemented in lib/cloud/auth.js or anywhere else. K8s / VMware /
  // OpenShift deployments removed from list and from "Deployment models"
  // section: no Helm charts, no manifests, no operators in repo. These
  // are pilot-track items; see the explicit roadmap below.
  const FEATURES = [
    { title: 'VPC / private deployment', body: 'EP runs entirely within your infrastructure boundary. No trust data, policy configurations, or signoff records leave your network. Reference AWS CloudFormation template ships in infrastructure/aws/.' },
    { title: 'Data residency', body: 'All trust data, event records, and policy configurations reside in your chosen jurisdiction. Meet data sovereignty requirements without architectural compromise.' },
    { title: 'Evidence retention & legal hold', body: 'Configurable retention policies for all trust events. Legal hold capability preserves evidence across retention boundaries for litigation, investigation, or regulatory response.' },
    { title: 'Regulator artifact exports', body: 'Generate structured evidence packages for regulatory examination, mapped to control families used in SOX and sector-specific frameworks (full FISMA / PCI-DSS mapping is roadmap).' },
    { title: 'Investigation tooling', body: 'Query and reconstruct action sequences across time, principals, and trust surfaces. Investigation mode provides forensic-grade evidence chains for incident response and internal audit.' },
    { title: 'Delegated administration', body: 'Hierarchical administration with scoped permissions. Delegate policy management, signoff configuration, and evidence access to business units without granting global control.' },
  ];

  const ROADMAP = [
    { title: 'SSO / SCIM (SAML 2.0, OIDC, automated provisioning)', body: 'Pilot-track work. EP currently authenticates via API keys + EP-IX identity bindings. SAML / OIDC / SCIM integration is scoped per pilot when an enterprise IdP is in play.' },
    { title: 'On-prem Kubernetes / VMware / OpenShift packaging', body: 'Container images and AWS CFN templates ship today. Helm charts, OpenShift operators, and VMware OVF templates are roadmap — pilots needing them get them as part of the engagement.' },
    { title: 'Air-gap installer', body: 'Air-gapped deployment is a pilot-track engagement, not a downloadable installer. The runtime supports offline operation; the packaging is bespoke for now.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Enterprise</div>
        <h1 style={styles.h1}>EP Enterprise</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Hardened deployment for regulated environments that require private infrastructure, data residency, and compliance-grade evidence.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Enterprise Pilot</a>
      </section>

      {/* Features */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Enterprise capabilities</h2>
          <p style={styles.body}>
            EP Enterprise provides the full trust-control plane deployed within your infrastructure. Every feature available in EP Cloud, plus the controls required by regulated environments.
          </p>
          <div style={grid.auto(280)}>
            {FEATURES.map((f, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{f.title}</div>
                <div style={styles.cardBody}>{f.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Roadmap (pilot-track) — explicit so enterprise procurement teams
          do not mistake aspirational integrations for delivered features. */}
      <section style={styles.section}>
        <div style={styles.eyebrowBlue}>Roadmap (pilot-track)</div>
        <h2 style={styles.h2}>Asked-for, not yet shipped.</h2>
        <p style={styles.body}>
          Items below come up in nearly every enterprise pilot conversation.
          They are scoped per engagement rather than shipped off-the-shelf.
        </p>
        <div style={grid.auto(280)}>
          {ROADMAP.map((f, i) => (
            <div key={i} className="ep-card-hover" style={{ ...styles.card, opacity: 0.85 }}>
              <div style={styles.cardTitle}>{f.title}</div>
              <div style={styles.cardBody}>{f.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Deployment models */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Deployment models</h2>
        <p style={styles.body}>EP Enterprise supports multiple deployment topologies based on your security requirements and infrastructure constraints.</p>
        <div style={grid.stack}>
          {[
            { title: 'Customer VPC (AWS today)', body: 'EP control plane deployed in your cloud account. You control the network boundary, encryption keys, and data lifecycle. We provide the container images, the AWS CloudFormation template (infrastructure/aws/template.yaml), configuration, and operational runbooks.' },
            { title: 'Private cloud / on-prem (pilot-track)', body: 'On-premises deployment for environments that require physical infrastructure control. Container images run anywhere Linux runs; Helm charts, OpenShift operators, and VMware OVF templates are scoped per pilot rather than shipped as off-the-shelf artifacts.' },
            { title: 'Hybrid', body: 'Policy management and event explorer in EP Cloud. Signoff orchestration and evidence storage in your infrastructure. Minimizes operational burden while maintaining data residency for sensitive records.' },
          ].map((d, i) => (
            <div key={i} className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>{d.title}</div>
              <div style={styles.cardBody}>{d.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Request Enterprise Pilot</h2>
          {submitted ? (
            <div style={{ ...styles.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
              <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={styles.card}>
              <div style={grid.cols2}>
                {[['name','Name'],['org','Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                  <div key={k}>
                    <label style={styles.label}>{label}</label>
                    <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={styles.label}>Trust surface of interest</label>
                  <input className="ep-input" style={styles.input} placeholder="e.g. payment controls, privilege escalation, agent governance" value={form.surface} onChange={e => update('surface', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={styles.label}>Problem description</label>
                  <textarea className="ep-input" style={{ ...styles.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={styles.label}>Notes</label>
                  <input className="ep-input" style={styles.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
                </div>
              </div>
              {error && <p style={{ color: color.red, fontSize: 13, marginTop: 12 }}>{error}</p>}
              <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...(!form.name || !form.email ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Request Enterprise Pilot'}
              </button>
            </div>
          )}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
