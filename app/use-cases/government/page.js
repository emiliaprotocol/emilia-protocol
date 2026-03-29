'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export default function GovernmentUseCasePage() {
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
        body: JSON.stringify({ type: 'pilot-government', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const PROBLEMS = [
    { title: 'Benefits redirect inside authorized sessions', body: 'Threat actors change payment destinations within legitimate authenticated workflows. The session looks valid. The action is not.' },
    { title: 'Operator overrides without action-level accountability', body: 'Caseworkers and system operators can modify records, approve exceptions, and redirect funds. Current audit trails capture who logged in, not who authorized the exact action.' },
    { title: 'Payment destination changes in approved workflows', body: 'Wire destinations, direct deposit targets, and disbursement accounts change inside sessions that pass every existing authentication check.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Handshake binds exact action', body: 'Every high-risk action generates a cryptographic handshake that binds the actor, the authority chain, the policy, and the exact action parameters before execution proceeds.' },
    { title: 'Signoff ensures named human accountability', body: 'No high-risk action executes without a named principal signing off. The signoff is bound to the exact action context, not a blanket session approval.' },
    { title: 'Immutable audit trail for IG and GAO', body: 'Every handshake, signoff, and execution produces an immutable event record. Inspector General and GAO auditors get action-level traceability, not session-level logs.' },
    { title: 'Replay-resistant authorization', body: 'Each authorization is one-time consumable. A captured handshake cannot be replayed to authorize a different payment, a different amount, or a different destination.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Use Case / Government</div>
        <h1 style={styles.h1}>Fraud prevention inside authorized government workflows</h1>
        <p style={{ ...styles.body, maxWidth: 620 }}>
          The hardest fraud to stop is the fraud that happens inside legitimate sessions. Benefits redirects, payment destination changes, and operator overrides all occur within workflows that pass every existing authentication check. EMILIA enforces trust before the high-risk action, not after the breach.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Pilot</a>
      </section>

      {/* Numbers */}
      <section style={styles.sectionAlt}>
        <div style={{ ...styles.section, paddingTop: 60, paddingBottom: 60 }}>
          <div style={grid.auto(200)}>
            <div style={{ textAlign: 'center', padding: '24px 16px' }}>
              <div style={{ fontFamily: font.sans, fontSize: 36, fontWeight: 700, color: color.green, marginBottom: 4 }}>$236B</div>
              <div style={{ fontSize: 13, color: color.t2, lineHeight: 1.5 }}>GAO-reported improper payments across federal programs annually</div>
            </div>
            <div style={{ textAlign: 'center', padding: '24px 16px' }}>
              <div style={{ fontFamily: font.sans, fontSize: 36, fontWeight: 700, color: color.green, marginBottom: 4 }}>$125K</div>
              <div style={{ fontSize: 13, color: color.t2, lineHeight: 1.5 }}>Average loss per business email compromise incident (FBI IC3)</div>
            </div>
            <div style={{ textAlign: 'center', padding: '24px 16px' }}>
              <div style={{ fontFamily: font.sans, fontSize: 36, fontWeight: 700, color: color.green, marginBottom: 4 }}>0</div>
              <div style={{ fontSize: 13, color: color.t2, lineHeight: 1.5 }}>Action-level trust enforcement layers in most government workflows today</div>
            </div>
          </div>
        </div>
      </section>

      {/* The problem */}
      <section style={styles.section}>
        <h2 style={styles.h2}>The problem</h2>
        <p style={styles.body}>
          Government systems authenticate users. They authorize sessions. They log activity after the fact. What they do not do is enforce trust at the exact moment a high-risk action is about to execute.
        </p>
        <div style={grid.stack}>
          {PROBLEMS.map((p, i) => (
            <div key={i} className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>{p.title}</div>
              <div style={styles.cardBody}>{p.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* How EP helps */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>How EMILIA helps</h2>
          <p style={styles.body}>
            EMILIA inserts a control layer between authentication and action execution. It does not replace identity management or session controls. It adds action-level trust enforcement where none exists today.
          </p>
          <div style={grid.auto(280)}>
            {HOW_EP_HELPS.map((h, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{h.title}</div>
                <div style={styles.cardBody}>{h.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* What changes */}
      <section style={styles.section}>
        <h2 style={styles.h2}>What changes with EMILIA</h2>
        <p style={styles.body}>Before EMILIA, a benefits redirect inside an authenticated session is invisible until post-incident review. After EMILIA:</p>
        {[
          'Every payment destination change requires a cryptographic handshake binding the exact new destination, amount, and authorizing principal',
          'Every operator override produces a named signoff record tied to the specific action, not a session log entry',
          'Every high-risk action is replay-resistant and one-time consumable',
          'Inspector General and GAO auditors receive action-level evidence chains, not session-level access logs',
        ].map((item, i) => (
          <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
            <span style={{ color: color.green, fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.6 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* Best first workflow */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Best first workflow</h2>
          <p style={styles.body}>Pick one high-risk action surface and deploy EMILIA in enforcement mode. These are the three most common starting points in government environments.</p>
          <div style={grid.stack}>
            {[
              { title: 'Payment destination change', body: 'A benefits recipient or vendor updates their bank account or routing number. EMILIA generates a cryptographic handshake binding the exact new destination, the requesting identity, and the authorizing caseworker before the change commits. If the handshake is not satisfied, the change does not execute.' },
              { title: 'Benefit redirect', body: 'A disbursement target changes inside an authenticated session. EMILIA requires a named signoff bound to the exact new target, amount, and program. The signoff record is immutable and available to Inspector General auditors in real time.' },
              { title: 'Operator override', body: 'A caseworker or system operator modifies a record, approves an exception, or escalates privileges. EMILIA enforces action-level accountability: the override does not proceed without a handshake that binds the exact action parameters to the exact operator identity and authority chain.' },
            ].map((w, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{w.title}</div>
                <div style={styles.cardBody}>{w.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...styles.section, maxWidth: 600, paddingTop: 60, paddingBottom: 60 }}>
          <h2 style={{ ...styles.h2, fontSize: 28 }}>Trust before high-risk action in government workflows</h2>
          <p style={styles.body}>
            EMILIA is selectively working with government agencies, system integrators, and public-sector technology teams to pilot action-level trust enforcement.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center' }}>
            <a href="/partners?type=government-pilot" className="ep-cta" style={{ ...cta.primary, width: '100%', maxWidth: 380, textAlign: 'center' }}>Request Fraud-Control Pilot</a>
            <a href="/docs" className="ep-cta-secondary" style={{ ...cta.secondaryBlue, width: '100%', maxWidth: 380, textAlign: 'center' }}>See Government Architecture</a>
            <a href="/docs" className="ep-cta-ghost" style={{ ...cta.ghost, width: '100%', maxWidth: 380, textAlign: 'center' }}>Download Audit Evidence Model</a>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.section}>
        <h2 style={styles.h2}>Request a pilot</h2>
        {submitted ? (
          <div style={{ ...styles.card, textAlign: 'center', padding: 40 }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <div style={styles.card}>
            <div style={grid.cols2}>
              {[['name','Name'],['org','Agency / Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                <div key={k}>
                  <label style={styles.label}>{label}</label>
                  <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                </div>
              ))}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>Trust surface of interest</label>
                <input className="ep-input" style={styles.input} placeholder="e.g. benefits disbursement, payment routing, operator approvals" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
              {submitting ? 'Submitting...' : 'Request Pilot'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
