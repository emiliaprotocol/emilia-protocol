'use client';

/**
 * /pilot — pilot request form.
 * @license Apache-2.0
 *
 * Replaces the mailto: CTA (a dead button on machines with no mail handler —
 * i.e. most government workstations). Four fields, honeypot spam guard,
 * graceful fallback to the team@ address if the API is unreachable.
 * ?v=gov|fin|health|host preselects the workflow. A closed source parameter carries
 * first-party campaign attribution into the durable intake record.
 */

import { useEffect, useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { color, font, radius, styles } from '@/lib/tokens';

const WORKFLOWS = [
  ['beneficiary_change', 'Vendor / beneficiary bank-detail change · first finance profile'],
  ['wire_release', 'Wire / payment release · first finance profile'],
  ['payer_adverse_determination', 'Payer adverse medical-necessity determination'],
  ['benefit_account_change', 'Benefit payment-destination change'],
  ['caseworker_override', 'Caseworker / examiner override'],
  ['clinical_action', 'Clinical / administrative healthcare action'],
  ['other', 'Another irreversible agent action'],
];

const PRESELECT = {
  gov: 'benefit_account_change',
  fin: 'beneficiary_change',
  health: 'payer_adverse_determination',
  host: 'other',
} as const;

function publicRecordReturn(artifactId: string): { href: string; label: string } {
  const encoded = encodeURIComponent(artifactId);
  if (artifactId.startsWith('agent_record_')) {
    return { href: `/agent-record/r/${encoded}`, label: 'return to the Agent Record' };
  }
  if (artifactId.startsWith('agent_share_')) {
    return { href: `/adopt/r/${encoded}`, label: 'return to the Operating Bond' };
  }
  if (artifactId.startsWith('arena_share_')) {
    return { href: `/arena/r/${encoded}`, label: 'return to the Arena refusal record' };
  }
  return { href: '/try', label: 'be the approver yourself in 20 seconds' };
}

export default function PilotPage(): React.ReactElement {
  const [form, setForm] = useState({
    name: '', org: '', email: '', workflow: 'beneficiary_change', message: '', website: '',
    offer_id: PROTECTED_WORKFLOW_PILOT.id, artifact_id: '', source: 'direct',
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
      const preselectedWorkflow = v && Object.hasOwn(PRESELECT, v)
        ? PRESELECT[v as keyof typeof PRESELECT]
        : null;
      const source = params.get('source') === 'private_equity' ? 'private_equity' : 'direct';
      const artifactId = params.get('artifact_id')?.trim().slice(0, 80) ?? '';
      setForm((f) => ({
        ...f,
        ...(preselectedWorkflow ? { workflow: preselectedWorkflow } : {}),
        ...(artifactId ? { artifact_id: artifactId } : {}),
        source,
      }));
    });
    return () => { cancelled = true; };
  }, []);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const selectedOffer = PROTECTED_WORKFLOW_PILOT;
  const returnLink = publicRecordReturn(form.artifact_id);
  const terms = [
    [selectedOffer.durationLabel, 'time-boxed engagement'],
    [selectedOffer.shortPriceLabel, 'fixed scope and price'],
    [selectedOffer.workflowLabel, 'one buyer-selected consequence boundary'],
    ['Synthetic + read-only', 'production implementation is separately scoped'],
    ['Server-validated records only', 'public record IDs are resolved before intake'],
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
          Protect one consequential workflow.{' '}
          {selectedOffer.durationLabel}. {selectedOffer.shortPriceLabel}.
        </h1>
        <p style={{ ...styles.body, maxWidth: 580 }}>
          Start with {selectedOffer.firstProfileLabel.toLowerCase()}. The safety rule is simple:{' '}
          {selectedOffer.safetyRuleLabel.toLowerCase()}. On a completely mediated covered path, missing,
          stale, exhausted, invalid, or mismatched authority does not admit provider entry. Other
          consequential workflows remain eligible under the same
          fixed offer. EMILIA does not prove bank-detail correctness, payee identity, fraud absence,
          provider success, legality, or business wisdom, and it does not take custody or move money.
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
              <a href={returnLink.href} style={lnk}>
                {returnLink.label}
              </a>.
            </p>
          </div>
        ) : (
          <form onSubmit={submit}>
            <label style={lbl} htmlFor="p-name">Your name</label>
            <input id="p-name" required value={form.name} onChange={set('name')} style={input} placeholder="Jordan Chen" />

            <label style={lbl} htmlFor="p-org">Organization</label>
            <input id="p-org" required value={form.org} onChange={set('org')} style={input} placeholder="Portfolio company / Finance team / Enterprise" />

            <label style={lbl} htmlFor="p-email">Work email</label>
            <input id="p-email" required type="email" value={form.email} onChange={set('email')} style={input} placeholder="you@company.com" />

            <label style={lbl} htmlFor="p-workflow">The workflow to pilot</label>
            <select id="p-workflow" value={form.workflow} onChange={set('workflow')} style={{ ...input, appearance: 'auto' }}>
              {WORKFLOWS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
            </select>

            <label style={lbl} htmlFor="p-artifact">Public record ID (optional)</label>
            <input id="p-artifact" value={form.artifact_id} onChange={set('artifact_id')} style={input}
              maxLength={80} pattern="(?:arena_share|agent_share|agent_record)_[0-9a-f]{40}"
              placeholder="arena_share_…, agent_share_…, or agent_record_…" aria-describedby="p-artifact-note" />
            <small id="p-artifact-note" style={{ display: 'block', color: color.t3, lineHeight: 1.55 }}>
              Only an active public Arena refusal, Agent Adoption Operating Bond, or Agent Record ID is accepted.
              The server resolves it before recording the request; pasted claims, receipt text, and arbitrary URLs are not evidence.
            </small>

            <label style={lbl} htmlFor="p-msg">Buyer context (optional, unverified)</label>
            <textarea id="p-msg" value={form.message} onChange={set('message')} style={{ ...input, minHeight: 96, resize: 'vertical' }} placeholder="Stack, timeline, constraints…" />

            {/* honeypot — humans never see or fill this */}
            <input type="text" name="website" value={form.website} onChange={set('website')} autoComplete="off" tabIndex={-1} aria-hidden="true" style={{ position: 'absolute', left: -9999, width: 1, height: 1, opacity: 0 }} />

            <button type="submit" disabled={state === 'busy'} style={{ width: '100%', background: color.t1, color: '#fff', border: 'none', borderRadius: radius.sm, padding: '14px 24px', fontFamily: font.sans, fontWeight: 600, fontSize: 15, cursor: state === 'busy' ? 'wait' : 'pointer', opacity: state === 'busy' ? 0.6 : 1, marginTop: 6 }}>
              {state === 'busy' ? 'Sending…' : 'Request the protected-workflow pilot →'}
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
