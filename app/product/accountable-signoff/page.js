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
    { title: 'Passkey', body: 'FIDO2/WebAuthn credential bound to device hardware. Phishing-resistant, biometric-gated. The strongest available consumer-grade signoff method.' },
    { title: 'Secure App', body: 'Dedicated mobile application that displays the exact action context and requires explicit confirmation. Action details are rendered on the device, not in the requesting session.' },
    { title: 'Platform Authenticator', body: 'OS-level biometric or PIN challenge (Touch ID, Windows Hello, Android biometric). Uses the platform\'s trusted execution environment for key operations.' },
    { title: 'Out-of-band', body: 'Signoff delivered through a separate channel from the requesting session. SMS, email, or push notification with action-bound one-time code. Weakest method, used only where stronger methods are unavailable.' },
    { title: 'Dual Signoff', body: 'Two named principals must independently attest to the same action before execution proceeds. Each signoff is cryptographically bound to the exact action parameters. Used for the highest-risk operations.' },
  ];

  const WHEN_REQUIRED = [
    { title: 'Payment changes above threshold', body: 'Any modification to payment destination, routing, or amount that exceeds a policy-defined threshold requires a named human to sign off on the exact change before it commits.' },
    { title: 'Government benefit redirects', body: 'Disbursement target changes within benefits programs. The signoff binds the exact new destination, program, and amount to a named authorizing principal.' },
    { title: 'Agent destructive actions', body: 'AI agent actions classified as destructive or irreversible. The agent cannot proceed without a named human explicitly assuming responsibility for the specific action.' },
    { title: 'Privileged enterprise operations', body: 'Privilege escalation, access grants, configuration changes, and administrative overrides in enterprise environments. Each operation requires named accountability.' },
  ];

  const WHY_IT_MATTERS = [
    { context: 'Government', icon: 'IG', detail: 'Inspector General and GAO auditors receive action-level evidence chains with named human accountability. Every signoff produces an immutable record binding the authorizer to the exact action.' },
    { context: 'Treasury', icon: 'SOX', detail: 'SOX-grade evidence for payment authorization. Named signoff records satisfy segregation-of-duties requirements and provide tamper-evident audit trails for financial controls.' },
    { context: 'Enterprise', icon: 'PAM', detail: 'Privilege escalation prevention. No administrative action executes without a named human signing off on the exact operation. Eliminates blanket session-based approvals.' },
    { context: 'Agent Execution', icon: 'AI', detail: 'Human responsibility chain for AI agent actions. When an agent requests a high-risk operation, a named human must explicitly accept responsibility before the agent can proceed.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Accountable Signoff</div>
        <h1 style={styles.h1}>Accountable Signoff</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          When policy requires human ownership, EP requires a named responsible human to explicitly assume responsibility for the exact action before execution.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Pilot</a>
      </section>

      {/* Not MFA */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Not MFA. Not human-in-the-loop. Named human accountability.</h2>
          <p style={styles.body}>
            Multi-factor authentication proves identity. Human-in-the-loop confirms a step happened. Neither binds a named human to a specific action with cryptographic evidence.
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
              <div style={styles.cardBody}>A named human reviews the exact action parameters and explicitly assumes responsibility. The signoff is cryptographically bound to the <span style={styles.mono}>action</span>, the <span style={styles.mono}>principal</span>, the <span style={styles.mono}>policy</span>, and the <span style={styles.mono}>timestamp</span>. It is one-time consumable and replay-resistant.</div>
            </div>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section style={styles.section}>
        <h2 style={styles.h2}>How it works</h2>
        <p style={styles.body}>Three steps. No ambiguity about who authorized what.</p>
        <div style={{ display: 'grid', gap: 20 }}>
          {[
            { step: '01', label: 'Challenge', detail: 'The system presents the exact action context to the named principal: what will happen, to what, with what parameters. The challenge is cryptographically bound to the action.' },
            { step: '02', label: 'Attest', detail: 'The named principal reviews the action context and explicitly attests. The attestation binds their identity to the exact action parameters using their chosen signoff method (passkey, secure app, platform authenticator).' },
            { step: '03', label: 'Consume', detail: 'The attestation is consumed exactly once. The action executes. The signoff record is immutable. The attestation cannot be replayed for a different action, a different amount, or a different target.' },
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

      {/* Methods */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Signoff methods</h2>
          <p style={styles.body}>EP supports multiple attestation methods. Policy determines which methods are acceptable for each action risk class.</p>
          <div style={grid.stack}>
            {METHODS.map((m, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{m.title}</div>
                <div style={styles.cardBody}>{m.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* When required */}
      <section style={styles.section}>
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
      </section>

      {/* Why it matters */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Why it matters</h2>
          <p style={styles.body}>Different environments need accountable signoff for different reasons. The mechanism is the same. The evidence it produces satisfies each context.</p>
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
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.section}>
        <h2 style={styles.h2}>Request Pilot</h2>
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
              {submitting ? 'Submitting...' : 'Request Pilot'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
