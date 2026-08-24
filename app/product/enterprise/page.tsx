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
        body: JSON.stringify({
          type: 'partner',
          partnerType: 'Gate Implementation inquiry',
          trustSurface: form.surface,
          ...form,
        }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  // Artifact inventory, not a claim that an integrated enterprise service is
  // generally available. SAML 2.0 SP + OIDC RP live at
  // app/api/sso/* (lib/sso/, docs/SSO.md); SCIM 2.0 at app/api/scim/v2/*
  // (lib/scim/, docs/SCIM.md); air-gap installer at deploy/airgap/ with a CI
  // audit job. K8s / VMware / OpenShift packaging remains genuinely roadmap:
  // no Helm charts, no operators, no OVF templates in repo.
  const FEATURES = [
    { title: 'VPC / private deployment', body: 'A reference AWS CloudFormation template ships in infrastructure/aws/. Customer isolation, no-egress posture, key ownership, and lifecycle controls must be established and accepted in a separate Gate Implementation; no customer deployment is implied.' },
    { title: 'SSO — SAML 2.0 + OIDC', body: 'Reference SAML Service Provider and OIDC Relying Party paths are implemented with library-backed signature validation. A live customer IdP tenant, identity mapping, key custody, and operating procedure are deployment-specific and not part of the nonproduction pilot.' },
    { title: 'SCIM 2.0 provisioning', body: 'Reference RFC 7643/7644-shaped Users, Groups, deactivation, and filtering paths are implemented. Production directory integration, offboarding latency, credential revocation, and operating evidence require deployment testing.' },
    { title: 'Air-gapped deployment', body: 'A self-contained offline bundle and static no-egress checks exist. A full run on the buyer\'s isolated hardware, network controls, update path, and operational acceptance remain separate implementation work.' },
    { title: 'Data residency', body: 'Customer-controlled regional placement is a deployment target, not a generally available hosted-service claim. Jurisdiction, subprocessors, backups, support access, and key ownership must be contracted and verified per implementation.' },
    { title: 'Evidence retention & legal hold', body: 'Receipts can be verified offline. Formal retention policies, legal hold, population completeness, and customer export are separately scoped; a signed receipt alone does not establish an immutable or complete audit trail.' },
    { title: 'Regulator artifact exports', body: 'Implemented report artifacts can support an examination procedure. Framework mappings, evidence sufficiency, and any compliance conclusion remain with the customer and its independent assessor.' },
    { title: 'Investigation tooling', body: 'Reference event and report surfaces support bounded reconstruction from supplied records. A production forensic workflow, completeness anchor, and retention operation remain engagement-scoped.' },
    { title: 'Delegated administration', body: 'Scoped administration is an implementation target. Role mapping, separation of duties, break-glass handling, and revocation must be validated under the customer\'s policy before production use.' },
  ];

  const ROADMAP = [
    { title: 'On-prem Kubernetes / VMware / OpenShift packaging', body: 'Container images, AWS CFN templates, and the air-gap compose bundle exist. Helm charts, OpenShift operators, and VMware OVF templates are roadmap and carry no delivery commitment; they may be evaluated in a separate Gate Implementation scope.' },
    { title: 'PIV / CAC / Login.gov integration', body: 'Government identity rails beyond SAML/OIDC, including smart-card authentication and Login.gov private_key_jwt, are roadmap and are not included in the public pilot.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />
      <main>

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Enterprise</div>
        <h1 style={styles.h1}>Enterprise Gate implementation pathways</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Reference components exist for private and disconnected environments. An integrated customer deployment is not generally available and is not included in the public nonproduction pilot.
        </p>
        <a href="#implementation" className="ep-cta" style={cta.primary}>Discuss Gate Implementation</a>
      </section>

      {/* Features */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Implemented artifacts and deployment work</h2>
          <p style={styles.body}>
            These are reference components and scoped implementation targets, not proof of a live
            managed service, customer deployment, certification, or operating effectiveness. A
            buyer first completes the nonproduction protected-workflow pilot. Production activation,
            if accepted, requires a separately contracted Gate Implementation.
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
          These requested integrations are scoped per implementation rather than shipped
          or promised as part of the public pilot.
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
        <h2 style={styles.h2}>Deployment targets</h2>
        <p style={styles.body}>These topologies describe separate Gate Implementation paths. They are not generally available managed-service offerings.</p>
        <div style={grid.stack}>
          {[
            { title: 'Customer VPC (AWS reference)', body: 'Container and CloudFormation artifacts provide a starting point. Network isolation, keys, data lifecycle, configuration, runbooks, and operational acceptance are buyer-specific implementation work.' },
            { title: 'Private cloud / on-prem (target)', body: 'Container-based private deployment is a design path. Helm charts, OpenShift operators, and VMware OVF templates are not shipped off-the-shelf.' },
            { title: 'Air-gapped (reference bundle)', body: 'The repository includes an offline bundle and static self-containment checks. The buyer must separately validate the full no-egress runtime, transfer, update, recovery, and hardware-specific controls.' },
            { title: 'Hybrid (designed)', body: 'A split control/data-plane topology is designed but no generally available Gate Cloud service is operating. Data flow, support access, custody, and failure semantics require a separate implementation and security review.' },
          ].map((d, i) => (
            <div key={i} className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>{d.title}</div>
              <div style={styles.cardBody}>{d.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Gate Implementation inquiry. This is not a second public pilot. */}
      <section id="implementation" style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Discuss a separate Gate Implementation</h2>
          <p style={styles.body}>The fixed $25K, 90-day protected-workflow pilot is nonproduction. This inquiry is for buyers who want to scope the distinct production implementation stage after accepting a boundary design.</p>
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
                    <label htmlFor={`implementation-${k}`} style={styles.label}>{label}</label>
                    <input id={`implementation-${k}`} type={k === 'email' ? 'email' : 'text'} className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label htmlFor="implementation-surface" style={styles.label}>Trust surface of interest</label>
                  <input id="implementation-surface" className="ep-input" style={styles.input} placeholder="e.g. payment controls, privilege escalation, agent governance" value={form.surface} onChange={e => update('surface', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label htmlFor="implementation-problem" style={styles.label}>Problem description</label>
                  <textarea id="implementation-problem" className="ep-input" style={{ ...styles.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label htmlFor="implementation-notes" style={styles.label}>Notes</label>
                  <input id="implementation-notes" className="ep-input" style={styles.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
                </div>
              </div>
              {error && <p style={{ color: color.red, fontSize: 13, marginTop: 12 }}>{error}</p>}
              <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...(!form.name || !form.email ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Discuss Gate Implementation'}
              </button>
            </div>
          )}
        </div>
      </section>

      </main>
      <SiteFooter />
    </div>
  );
}
