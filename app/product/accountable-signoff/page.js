'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export default function AccountableSignoffPage() {
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
        body: JSON.stringify({ type: 'pilot-accountable-signoff', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const METHODS = [
    { title: 'iOS reference app', body: 'A buildable SwiftUI client renders the exact-action presentation, CAID Action Lock, material changes, quorum, and consequence state; it uses a passkey and binds Apple App Attest evidence to the same ceremony. Public distribution remains release-gated.' },
    { title: 'Android reference app', body: 'A buildable Kotlin client renders the same Action Lock and lifecycle, then uses Credential Manager, a non-exportable Android Keystore key, and Google Play Integrity under server-pinned app identity. Public distribution remains release-gated.' },
    { title: 'Passkey ceremony', body: 'The Class-A signoff uses WebAuthn/passkeys with user presence and user verification. The mobile layer composes with this established primitive instead of inventing new cryptography.' },
    { title: 'Embeddable SDKs', body: 'Swift and Kotlin libraries let an organization embed the same ceremony into its own branded, self-hosted application while keeping its own trust roots and execution boundary.' },
    { title: 'Distinct-human quorum', body: 'A profile can require multiple enrolled approvers, initiator exclusion, ordering, and separate device-bound ceremonies over the same exact action before Gate permits execution.' },
  ];

  const WHEN_REQUIRED = [
    { title: 'Payment changes above threshold', body: 'Any modification to payment destination, routing, or amount that exceeds a policy-defined threshold requires a named human to sign off on the exact change before it commits.' },
    { title: 'Government benefit redirects', body: 'Disbursement target changes within benefits programs. The signoff binds the exact new destination, program, and amount to a named authorizing principal.' },
    { title: 'Agent destructive actions', body: 'AI agent actions classified as destructive or irreversible. The agent cannot proceed without a named human explicitly assuming responsibility for the specific action.' },
    { title: 'Privileged enterprise operations', body: 'Privilege escalation, access grants, configuration changes, and administrative overrides in enterprise environments. Each operation requires named accountability.' },
  ];

  const WHY_IT_MATTERS = [
    { context: 'Government', icon: 'IG', detail: 'Action-level evidence can show which enrolled approver completed the ceremony, over which exact action, under which pinned profile. The agency and its auditor decide what conclusion that record supports.' },
    { context: 'Treasury', icon: 'SOX', detail: 'Named, action-bound signoff and distinct-human quorum can support segregation-of-duties control testing without claiming that a cryptographic record alone establishes compliance.' },
    { context: 'Enterprise', icon: 'PAM', detail: 'At a fully mediated privileged-operation boundary, Gate can require an enrolled human decision before a configured administrative action executes.' },
    { context: 'Agent Execution', icon: 'AI', detail: 'When an agent requests a protected operation, the app gives the accountable human a separate exact-action decision surface before Gate permits the integrated executor to proceed.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>EMILIA Approver Apps</div>
        <h1 style={styles.h1}>The human decision edge of EMILIA Gate</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Gate creates the exact-action challenge. The app shows the material fields and a
          stable CAID fingerprint on a separate device, captures an approve or deny
          decision, and follows that decision through quorum, consumption, uncertainty,
          and authenticated outcome reconciliation.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Pilot the Approver apps</a>
      </section>

      {/* Not MFA */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Identity starts the ceremony. It does not authorize the action.</h2>
          <p style={styles.body}>
            Authentication establishes control of an enrolled credential. The Approver ceremony
            adds the exact action, the relying party&rsquo;s challenge and profile, a fresh decision,
            and evidence that Gate can verify before execution.
          </p>
          <div style={grid.stack}>
            <div className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>MFA</div>
              <div style={styles.cardBody}>Proves you are who you claim to be. Does not prove you authorized <span style={styles.mono}>this specific action</span> with <span style={styles.mono}>these specific parameters</span>. A session authenticated with MFA can still execute unauthorized actions.</div>
            </div>
            <div className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>Human-in-the-loop</div>
              <div style={styles.cardBody}>Confirms a human clicked a button. Does not bind a <span style={styles.mono}>named principal</span> to the <span style={styles.mono}>exact action context</span>. The audit trail shows a confirmation happened, not who is accountable for what.</div>
            </div>
            <div className="ep-card-accent" style={{ ...styles.card, border: `1px solid ${color.border}` }}>
              <div style={{ ...styles.cardTitle, color: color.green }}>Accountable Signoff</div>
              <div style={styles.cardBody}>An enrolled approver receives a relying-party-created presentation and makes a fresh decision. The response binds the <span style={styles.mono}>action</span>, the <span style={styles.mono}>credential</span>, the <span style={styles.mono}>profile</span>, and the <span style={styles.mono}>challenge</span>. Gate consumes an accepted ceremony once at the protected executor.</div>
            </div>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section style={styles.section}>
        <h2 style={styles.h2}>How it works</h2>
        <p style={styles.body}>Four steps across the app and the enforcement boundary.</p>
        <div style={{ display: 'grid', gap: 20 }}>
          {[
            { step: '01', label: 'Lock', detail: 'Gate resolves the action and presentation from the protected system, computes its CAID and authoritative digest, and signs the action reference, CAID, digest, policy, approver, and expiry into one challenge.' },
            { step: '02', label: 'Decide', detail: 'The app verifies the Action Lock, renders every material field and any revision changes, then binds the approver’s decision, passkey assertion, and supported app or device integrity evidence to the same request.' },
            { step: '03', label: 'Consume', detail: 'After the required quorum, Gate atomically consumes the accepted authority and freezes the intended executor key before any integrated system mutates state. An approval can be withdrawn before consumption, never after.' },
            { step: '04', label: 'Reconcile', detail: 'If the provider times out after invocation, the action becomes indeterminate and cannot be blindly retried. Only retained, authenticated provider evidence bound to the same operation, executor key, and Action Lock can resolve the outcome.' },
          ].map((s2, i) => (
            <div key={i} style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
              <div style={{ fontFamily: font.mono, fontSize: 28, fontWeight: 700, color: color.green, flexShrink: 0, lineHeight: 1, minWidth: 44 }}>{s2.step}</div>
              <div>
                <div style={{ ...styles.cardTitle, fontSize: 17, marginBottom: 4 }}>{s2.label}</div>
                <div style={styles.cardBody}>{s2.detail}</div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Continuity */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>The approval does not disappear after the tap</h2>
          <p style={styles.body}>
            The reference apps keep the exact decision and the downstream consequence
            connected without pretending that authorization proves execution.
          </p>
          <div style={grid.auto(280)}>
            {[
              { title: 'Action Lock', body: 'A short fingerprint comes from the CAID of the complete authoritative action. The signed context also carries the action reference and digest, so a changed action is a new decision.' },
              { title: 'Revision-aware review', body: 'When material fields change, the prior approval is superseded. The app shows what was added, changed, or removed and requires a fresh ceremony for the new CAID.' },
              { title: 'Quorum and lifecycle', body: 'See approvals still required and distinguish authorized, consumed, indeterminate, executed, refused, withdrawn, expired, and cancelled states.' },
              { title: 'Decision passport', body: 'Export a bounded record of action identity, decision, quorum, and effect state. It carries evidence digests, not raw passkey or provider evidence.' },
            ].map((item) => (
              <div key={item.title} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{item.title}</div>
                <div style={styles.cardBody}>{item.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Methods */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Signoff methods</h2>
        <p style={styles.body}>Open reference clients and SDKs capture the decision. The relying party still chooses the acceptable apps, keys, integrity services, and assurance floor.</p>
        <p style={styles.body}>
          The ceremony establishes that a pinned enrolled key completed a verified response over
          exact bytes. It does not prove perception, comprehension, legal sufficiency, or that a
          compromised device displayed honest pixels.
        </p>
        <div style={grid.stack}>
          {METHODS.map((m, i) => (
            <div key={i} className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>{m.title}</div>
              <div style={styles.cardBody}>{m.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* When required */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>When signoff is required</h2>
          <p style={styles.body}>Policy defines when accountable signoff is required. These are the most common trigger surfaces.</p>
          <div style={grid.auto(280)}>
            {WHEN_REQUIRED.map((w, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{w.title}</div>
                <div style={styles.cardBody}>{w.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why it matters */}
      <section style={styles.section}>
          <h2 style={styles.h2}>Why it matters</h2>
          <p style={styles.body}>Different environments need accountable signoff for different reasons. The mechanism is the same; each organization decides what control or legal conclusion the evidence supports.</p>
          <div style={grid.auto(280)}>
            {WHY_IT_MATTERS.map((w, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ ...styles.mono, background: color.card, padding: '4px 10px', borderRadius: radius.sm, fontSize: 11, letterSpacing: 1 }}>{w.icon}</span>
                  <span style={styles.cardTitle}>{w.context}</span>
                </div>
                <div style={styles.cardBody}>{w.detail}</div>
              </div>
            ))}
          </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.section}>
        <h2 style={styles.h2}>Pilot the Approver apps</h2>
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
                <input className="ep-input" style={styles.input} placeholder="e.g. payment authorization, agent governance, privilege escalation" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
              {submitting ? 'Submitting...' : 'Request an Approver pilot'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
