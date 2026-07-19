'use client';

/**
 * /pilot — pilot request form.
 * @license Apache-2.0
 *
 * Replaces the mailto: CTA (a dead button on machines with no mail handler —
 * i.e. most government workstations). Four fields, honeypot spam guard,
 * graceful fallback to the team@ address if the API is unreachable.
 * ?v=gov|fin|health preselects the workflow.
 */

import { useEffect, useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, font, radius, styles } from '@/lib/tokens';

const WORKFLOWS = [
  ['wire_release', 'Wire / payment release'],
  ['beneficiary_change', 'Vendor / beneficiary bank-detail change'],
  ['benefit_account_change', 'Benefit payment-destination change'],
  ['caseworker_override', 'Caseworker / examiner override'],
  ['clinical_action', 'Clinical / administrative healthcare action'],
  ['other', 'Another irreversible agent action'],
];

const PRESELECT = { gov: 'benefit_account_change', fin: 'wire_release', health: 'clinical_action' };

const TERMS = [
  ['4 weeks', 'time-boxed, calendar honest'],
  ['Free', 'no contract, no card'],
  ['Observe-mode first', 'nothing blocked until you decide'],
  ['One workflow', 'the scariest action you have'],
  ['Exit anytime', 'one email; keep the report'],
];

export default function PilotPage() {
  const [form, setForm] = useState({ name: '', org: '', email: '', workflow: 'wire_release', message: '', website: '' });
  const [state, setState] = useState('idle'); // idle | busy | done | error
  const [error, setError] = useState('');

  useEffect(() => {
    // Microtask defer — same pattern as EuAiActBanner — so the update isn't
    // synchronous in the effect body (react-hooks/set-state-in-effect).
    let cancelled = false;
    Promise.resolve().then(() => {
      if (cancelled) return;
      const v = new URLSearchParams(window.location.search).get('v');
      if (v && PRESELECT[v]) setForm((f) => ({ ...f, workflow: PRESELECT[v] }));
    });
    return () => { cancelled = true; };
  }, []);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  async function submit(e) {
    e.preventDefault();
    setState('busy');
    setError('');
    try {
      const res = await fetch('/api/pilot/request', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.detail || data.title || 'Something went wrong.');
        setState('error');
        return;
      }
      setState('done');
    } catch {
      setError('Network error.');
      setState('error');
    }
  }

  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ maxWidth: 660, margin: '0 auto', padding: '56px 24px 96px' }}>
        <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 18 }}>
          Pilot request
        </div>
        <h1 style={{ ...styles.h1, maxWidth: 600 }}>One workflow. Four weeks. Free.</h1>
        <p style={{ ...styles.body, maxWidth: 580 }}>
          Pick the scariest irreversible action your systems (or agents) take. Week one runs in
          observe-mode — zero blocking, zero risk — and you get the &ldquo;what would have required
          approval&rdquo; report. If it&rsquo;s boring, we shake hands and you keep it. If it isn&rsquo;t,
          we turn on enforcement for that one action.
        </p>

        {/* terms strip */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '0 0 36px' }}>
          {TERMS.map(([t, d]) => (
            <span key={t} title={d} style={{ fontFamily: font.mono, fontSize: 12, color: color.t2, border: `1px solid ${color.border}`, borderRadius: radius.sm, padding: '6px 10px', background: color.card }}>
              {t}
            </span>
          ))}
        </div>

        {state === 'done' ? (
          <div style={{ background: '#F0FDF4', border: `1px solid ${color.green}`, borderRadius: radius.base, padding: '24px 26px' }}>
            <div style={{ fontWeight: 700, fontSize: 18, color: '#15803D', marginBottom: 8 }}>Got it — check your email.</div>
            <p style={{ fontSize: 14.5, color: color.t2, lineHeight: 1.65, margin: 0 }}>
              A confirmation with next steps is on its way to your inbox, and I reply personally within
              one business day. Meanwhile: <a href="/try" style={lnk}>be the approver yourself in 20 seconds</a>.
            </p>
          </div>
        ) : (
          <form onSubmit={submit}>
            <label style={lbl} htmlFor="p-name">Your name</label>
            <input id="p-name" required value={form.name} onChange={set('name')} style={input} placeholder="Jordan Chen" />

            <label style={lbl} htmlFor="p-org">Organization</label>
            <input id="p-org" required value={form.org} onChange={set('org')} style={input} placeholder="First Example Bank / State Agency / Startup" />

            <label style={lbl} htmlFor="p-email">Work email</label>
            <input id="p-email" required type="email" value={form.email} onChange={set('email')} style={input} placeholder="you@organization.gov" />

            <label style={lbl} htmlFor="p-workflow">The workflow to pilot</label>
            <select id="p-workflow" value={form.workflow} onChange={set('workflow')} style={{ ...input, appearance: 'auto' }}>
              {WORKFLOWS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
            </select>

            <label style={lbl} htmlFor="p-msg">Anything else (optional)</label>
            <textarea id="p-msg" value={form.message} onChange={set('message')} style={{ ...input, minHeight: 96, resize: 'vertical' }} placeholder="Stack, timeline, constraints…" />

            {/* honeypot — humans never see or fill this */}
            <input type="text" name="website" value={form.website} onChange={set('website')} autoComplete="off" tabIndex={-1} aria-hidden="true" style={{ position: 'absolute', left: -9999, width: 1, height: 1, opacity: 0 }} />

            <button type="submit" disabled={state === 'busy'} style={{ width: '100%', background: color.t1, color: '#fff', border: 'none', borderRadius: radius.sm, padding: '14px 24px', fontFamily: font.sans, fontWeight: 600, fontSize: 15, cursor: state === 'busy' ? 'wait' : 'pointer', opacity: state === 'busy' ? 0.6 : 1, marginTop: 6 }}>
              {state === 'busy' ? 'Sending…' : 'Request the pilot →'}
            </button>

            {state === 'error' && (
              <div style={{ marginTop: 14, padding: '11px 14px', borderRadius: radius.sm, background: '#FEF2F2', border: `1px solid ${color.red}`, color: color.red, fontSize: 13.5, lineHeight: 1.55 }}>
                {error} You can always email <a href="mailto:team@emiliaprotocol.ai?subject=Pilot%20request" style={{ color: color.red, fontWeight: 600 }}>team@emiliaprotocol.ai</a> directly.
              </div>
            )}
          </form>
        )}

        <p style={{ fontSize: 13, color: color.t3, lineHeight: 1.7, marginTop: 28 }}>
          Prefer plain email? <a href="mailto:team@emiliaprotocol.ai?subject=Pilot%20request" style={lnk}>team@emiliaprotocol.ai</a>.
          Want to evaluate first? <a href="/try" style={lnk}>/try</a> (be the approver), <a href="/verify" style={lnk}>/verify</a> (check a receipt offline),
          {' '}<a href="/auditors" style={lnk}>/auditors</a> (for your assurance team).
        </p>
      </main>
      <SiteFooter />
    </div>
  );
}

const lnk = { color: color.blue, textDecoration: 'none' };
const lbl = { display: 'block', fontSize: 12, fontWeight: 600, color: color.t2, margin: '16px 0 6px', fontFamily: font.mono, letterSpacing: 0.5 };
/** @type {React.CSSProperties} */
const input = { width: '100%', padding: '12px 14px', borderRadius: radius.base, border: `1px solid ${color.inputBorder}`, background: color.card, color: color.t1, fontSize: 15, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box' };
