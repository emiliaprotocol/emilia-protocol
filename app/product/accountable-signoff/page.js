'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

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

  const s = {
    page: { minHeight: '100vh', background: '#0a0f1e', color: '#f0f2f5', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
    section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#111827', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#4a90d9', marginBottom: 16 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 24, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 },
    h3: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 18, fontWeight: 700, letterSpacing: -0.3, marginBottom: 10, color: '#f0f2f5' },
    body: { fontSize: 16, color: '#8b95a5', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, color: '#f0f2f5', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#8b95a5', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#111827', color: '#f0f2f5', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#8b95a5', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 0.5 },
    mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, color: '#4a90d9' },
  };

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
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Product / Accountable Signoff</div>
        <h1 style={s.h1}>Accountable Signoff</h1>
        <p style={{ ...s.body, maxWidth: 640 }}>
          When policy requires human ownership, EP requires a named responsible human to explicitly assume responsibility for the exact action before execution.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Pilot</a>
      </section>

      {/* Not MFA */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Not MFA. Not human-in-the-loop. Named human accountability.</h2>
          <p style={s.body}>
            Multi-factor authentication proves identity. Human-in-the-loop confirms a step happened. Neither binds a named human to a specific action with cryptographic evidence.
          </p>
          <div style={{ display: 'grid', gap: 16 }}>
            <div style={s.card}>
              <div style={s.cardTitle}>MFA</div>
              <div style={s.cardBody}>Proves you are who you claim to be. Does not prove you authorized <span style={s.mono}>this specific action</span> with <span style={s.mono}>these specific parameters</span>. A session authenticated with MFA can still execute unauthorized actions.</div>
            </div>
            <div style={s.card}>
              <div style={s.cardTitle}>Human-in-the-loop</div>
              <div style={s.cardBody}>Confirms a human clicked a button. Does not bind a <span style={s.mono}>named principal</span> to the <span style={s.mono}>exact action context</span>. The audit trail shows a confirmation happened, not who is accountable for what.</div>
            </div>
            <div style={{ ...s.card, border: '1px solid rgba(212,175,55,0.2)' }}>
              <div style={{ ...s.cardTitle, color: '#d4af55' }}>Accountable Signoff</div>
              <div style={s.cardBody}>A named human reviews the exact action parameters and explicitly assumes responsibility. The signoff is cryptographically bound to the <span style={s.mono}>action</span>, the <span style={s.mono}>principal</span>, the <span style={s.mono}>policy</span>, and the <span style={s.mono}>timestamp</span>. It is one-time consumable and replay-resistant.</div>
            </div>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section style={s.section}>
        <h2 style={s.h2}>How it works</h2>
        <p style={s.body}>Three steps. No ambiguity about who authorized what.</p>
        <div style={{ display: 'grid', gap: 20 }}>
          {[
            { step: '01', label: 'Challenge', detail: 'The system presents the exact action context to the named principal: what will happen, to what, with what parameters. The challenge is cryptographically bound to the action.' },
            { step: '02', label: 'Attest', detail: 'The named principal reviews the action context and explicitly attests. The attestation binds their identity to the exact action parameters using their chosen signoff method (passkey, secure app, platform authenticator).' },
            { step: '03', label: 'Consume', detail: 'The attestation is consumed exactly once. The action executes. The signoff record is immutable. The attestation cannot be replayed for a different action, a different amount, or a different target.' },
          ].map((s2, i) => (
            <div key={i} style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 28, fontWeight: 700, color: '#d4af55', flexShrink: 0, lineHeight: 1, minWidth: 44 }}>{s2.step}</div>
              <div>
                <div style={{ ...s.cardTitle, fontSize: 17, marginBottom: 4 }}>{s2.label}</div>
                <div style={s.cardBody}>{s2.detail}</div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Methods */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Signoff methods</h2>
          <p style={s.body}>EP supports multiple attestation methods. Policy determines which methods are acceptable for each action risk class.</p>
          <div style={{ display: 'grid', gap: 16 }}>
            {METHODS.map((m, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{m.title}</div>
                <div style={s.cardBody}>{m.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* When required */}
      <section style={s.section}>
        <h2 style={s.h2}>When signoff is required</h2>
        <p style={s.body}>Policy defines when accountable signoff is required. These are the most common trigger surfaces.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {WHEN_REQUIRED.map((w, i) => (
            <div key={i} style={s.card}>
              <div style={s.cardTitle}>{w.title}</div>
              <div style={s.cardBody}>{w.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Why it matters */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Why it matters</h2>
          <p style={s.body}>Different environments need accountable signoff for different reasons. The mechanism is the same. The evidence it produces satisfies each context.</p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {WHY_IT_MATTERS.map((w, i) => (
              <div key={i} style={s.card}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ ...s.mono, background: '#111827', padding: '4px 10px', borderRadius: 6, fontSize: 11, letterSpacing: 1 }}>{w.icon}</span>
                  <span style={s.cardTitle}>{w.context}</span>
                </div>
                <div style={s.cardBody}>{w.detail}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={s.section}>
        <h2 style={s.h2}>Request Pilot</h2>
        {submitted ? (
          <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: '#d4af55', marginBottom: 8 }}>Thank you</div>
            <p style={{ color: '#8b95a5', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <div style={s.card}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {[['name','Name'],['org','Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                <div key={k}>
                  <label style={s.label}>{label}</label>
                  <input style={s.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                </div>
              ))}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={s.label}>Trust surface of interest</label>
                <input style={s.input} placeholder="e.g. payment authorization, agent governance, privilege escalation" value={form.surface} onChange={e => update('surface', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={s.label}>Problem description</label>
                <textarea style={{ ...s.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={s.label}>Notes</label>
                <input style={s.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
              </div>
            </div>
            {error && <p style={{ color: '#f87171', fontSize: 13, marginTop: 12 }}>{error}</p>}
            <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#d4af55', color: !form.name || !form.email ? '#5a6577' : '#0a0f1e', marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting...' : 'Request Pilot'}
            </button>
          </div>
        )}
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#5a6577', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#5a6577', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
