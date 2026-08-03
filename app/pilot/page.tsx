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
import { AGENT_ADOPTION_DESIGN_PARTNER, MANAGED_PILOT } from '@/lib/commercial-offer';
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

export default function PilotPage(): React.ReactElement {
  const [form, setForm] = useState({
    name: '', org: '', email: '', workflow: 'wire_release', message: '', website: '', offer_id: '',
  });
  const [state, setState] = useState('idle'); // idle | busy | done | error
  const [error, setError] = useState('');

  useEffect(() => {
    // Microtask defer — same pattern as EuAiActBanner — so the update isn't
    // synchronous in the effect body (react-hooks/set-state-in-effect).
    let cancelled = false;
    Promise.resolve().then(() => {
      if (cancelled) return;
      const params = new URLSearchParams(window.location.search);
      const v = params.get('v');
      if (params.get('offer') === 'agent-adoption') {
        setForm((f) => ({
          ...f,
          offer_id: AGENT_ADOPTION_DESIGN_PARTNER.id,
          workflow: 'other',
        }));
      } else if (v && PRESELECT[v]) {
        setForm((f) => ({ ...f, workflow: PRESELECT[v] }));
      }
    });
    return () => { cancelled = true; };
  }, []);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const isAgentAdoption = form.offer_id === AGENT_ADOPTION_DESIGN_PARTNER.id;
  const selectedOffer = isAgentAdoption ? AGENT_ADOPTION_DESIGN_PARTNER : MANAGED_PILOT;
  const terms = isAgentAdoption
    ? [
        [selectedOffer.durationLabel, 'time-boxed engagement'],
        [selectedOffer.shortPriceLabel, 'fixed scope and price'],
        [selectedOffer.workflowLabel, 'one buyer-selected agent workflow'],
        ['Synthetic first', 'no production access during validation'],
        ['Buyer-approved boundary', 'production scope requires explicit acceptance'],
      ]
    : [
        [selectedOffer.durationLabel, 'time-boxed engagement'],
        [selectedOffer.shortPriceLabel, 'fixed scope and price'],
        ['Read-only first', 'no production path changes in the diagnostic'],
        [selectedOffer.workflowLabel, 'the consequential action you choose'],
        ['Decision package', 'findings, manifest template, and implementation scope'],
      ];

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
        <h1 style={{ ...styles.h1, maxWidth: 600 }}>
          {isAgentAdoption ? 'Protect one agent workflow.' : 'Find the workflow to protect.'}{' '}
          {selectedOffer.durationLabel}. {selectedOffer.shortPriceLabel}.
        </h1>
        <p style={{ ...styles.body, maxWidth: 580 }}>
          {isAgentAdoption
            ? 'Move one candidate from the public no-egress challenge into a separately scoped, buyer-controlled pilot. We validate the workflow synthetically first, define the exact consequence boundary, and connect production only after the buyer approves the Gate design. The public Operating Bond is context for the conversation—not production evidence.'
            : 'Pick one consequential workflow and begin with synthetic replay plus a governed read-only export. EMILIA Signal reconstructs the approval-to-effect chain, surfaces source-linked integrity cases, and produces the material-field map and Action Control Manifest template. You leave with evidence, a Gate implementation scope, and a clear decision about whether prospective enforcement is worth it.'}
        </p>

        {/* terms strip */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '0 0 36px' }}>
          {terms.map(([t, d]) => (
            <span key={t} title={d} style={{ fontFamily: font.mono, fontSize: 12, color: color.t2, border: `1px solid ${color.border}`, borderRadius: radius.sm, padding: '6px 10px', background: color.card }}>
              {t}
            </span>
          ))}
        </div>

        {state === 'done' ? (
          <div style={{ background: '#F0FDF4', border: `1px solid ${color.green}`, borderRadius: radius.base, padding: '24px 26px' }}>
            <div style={{ fontWeight: 700, fontSize: 18, color: '#15803D', marginBottom: 8 }}>Request recorded.</div>
            <p style={{ fontSize: 14.5, color: color.t2, lineHeight: 1.65, margin: 0 }}>
              I reply personally within one business day. Meanwhile:{' '}
              <a href={isAgentAdoption ? '/adopt' : '/try'} style={lnk}>
                {isAgentAdoption ? 'run the public candidate challenge' : 'be the approver yourself in 20 seconds'}
              </a>.
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
              {state === 'busy' ? 'Sending…' : isAgentAdoption ? 'Request the Agent Adoption pilot →' : 'Request a pilot scope →'}
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
const input: React.CSSProperties = { width: '100%', padding: '12px 14px', borderRadius: radius.base, border: `1px solid ${color.inputBorder}`, background: color.card, color: color.t1, fontSize: 15, fontFamily: 'inherit', boxSizing: 'border-box' };
