'use client';

/**
 * /pilot/sandbox — self-serve GovGuard/FinGuard fire drill, end to end.
 * @license Apache-2.0
 *
 * Provision a scoped key → send real-shaped high-risk actions through the gate
 * in OBSERVE mode → pull the automated "what would have been blocked" evidence
 * packet. No sales call, nothing blocked, nothing uploaded beyond the action
 * metadata the caller chooses to send. This is the GovGuard fire drill.
 */

import { useState, useCallback } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, font, radius, styles } from '@/lib/tokens';

const VERTICALS = [
  ['gov', 'Government — fraud-control fire drill'],
  ['fin', 'Financial — $82K payment release'],
  ['health', 'Healthcare — caseworker/clinical override'],
];

// Browser-runnable sample actions per vertical (observe mode). amount drives
// the FinGuard tier; the gov/health ones trip money-destination / override.
function samplesFor(vertical, orgId) {
  if (vertical === 'fin') {
    return [
      ['$82,000 payment release', '/api/v1/adapters/fin/payment-release/precheck',
        { organization_id: orgId, enforcement_mode: 'observe', payment_instruction_id: 'pi_001', amount: 82000, currency: 'USD', before_state: { status: 'pending' }, after_state: { status: 'released' } }],
      ['$1.4M payment release (dual-auth tier)', '/api/v1/adapters/fin/payment-release/precheck',
        { organization_id: orgId, enforcement_mode: 'observe', payment_instruction_id: 'pi_002', amount: 1400000, currency: 'USD', before_state: { status: 'pending' }, after_state: { status: 'released' } }],
      ['$300 refund (allowed)', '/api/v1/adapters/fin/payment-release/precheck',
        { organization_id: orgId, enforcement_mode: 'observe', payment_instruction_id: 'pi_003', amount: 300, currency: 'USD', before_state: { status: 'pending' }, after_state: { status: 'released' } }],
    ];
  }
  if (vertical === 'health') {
    return [
      ['Caseworker override of an auto-deny', '/api/v1/adapters/gov/caseworker-override/precheck',
        { organization_id: orgId, enforcement_mode: 'observe', case_id: 'case_h1', before_state: { determination: 'auto_deny' }, after_state: { determination: 'manual_approve' } }],
    ];
  }
  return [
    ['Vendor payment destination change', '/api/v1/adapters/gov/vendor-payment-destination-change/precheck',
      { organization_id: orgId, enforcement_mode: 'observe', vendor_id: 'vendor_g1', target_changed_fields: ['bank_account'], before_state: { bank_account: '****1111' }, after_state: { bank_account: '****4021' } }],
    ['Disbursement release', '/api/v1/adapters/gov/disbursement-release/precheck',
      { organization_id: orgId, enforcement_mode: 'observe', payment_instruction_id: 'pay_g1', amount: 250000, currency: 'USD', before_state: { status: 'queued' }, after_state: { status: 'released' } }],
    ['Benefit bank-account change', '/api/v1/adapters/gov/benefit-bank-change/precheck',
      { organization_id: orgId, enforcement_mode: 'observe', recipient_id: 'case_g1', target_changed_fields: ['bank_account'], before_state: { bank_account: '****1111' }, after_state: { bank_account: '****4021' } }],
    ['Benefit mailing-address change', '/api/v1/adapters/gov/benefit-address-change/precheck',
      { organization_id: orgId, enforcement_mode: 'observe', recipient_id: 'case_g4', target_changed_fields: ['mailing_address'], before_state: { mailing_address_hash: 'old' }, after_state: { mailing_address_hash: 'new' } }],
    ['Caseworker override', '/api/v1/adapters/gov/caseworker-override/precheck',
      { organization_id: orgId, enforcement_mode: 'observe', case_id: 'case_g2', before_state: { determination: 'auto_deny' }, after_state: { determination: 'manual_approve' } }],
    ['Eligibility override', '/api/v1/adapters/gov/eligibility-override/precheck',
      { organization_id: orgId, enforcement_mode: 'observe', case_id: 'case_g5', eligibility_status: 'approved', before_state: { eligibility_status: 'denied' }, after_state: { eligibility_status: 'approved' } }],
    ['Routine address note (allowed)', '/api/v1/adapters/gov/benefit-bank-change/precheck',
      { organization_id: orgId, enforcement_mode: 'observe', recipient_id: 'case_g3', target_changed_fields: ['note'], before_state: { note: 'a' }, after_state: { note: 'b' } }],
  ];
}

export default function SandboxPage() {
  const [vertical, setVertical] = useState('gov');
  const [creds, setCreds] = useState(null); // { api_key, organization_id, ... }
  const [busy, setBusy] = useState('');
  const [ran, setRan] = useState([]); // [{ label, decision }]
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');

  const provision = useCallback(async () => {
    setBusy('provision'); setError(''); setReport(null); setRan([]);
    try {
      const res = await fetch('/api/pilot/sandbox/provision', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vertical }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.detail || 'Could not provision.'); }
      else setCreds(data);
    } catch { setError('Network error.'); }
    setBusy('');
  }, [vertical]);

  const runSample = useCallback(async (label, path, body) => {
    setBusy(label); setError('');
    try {
      const res = await fetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json', Authorization: `Bearer ${creds.api_key}` },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      const decision = data.observed_decision || data.decision || (res.ok ? 'allow' : 'error');
      setRan((r) => [...r, { label, decision, tier: data.signoff_tier }]);
    } catch { setError('Network error running the action.'); }
    setBusy('');
  }, [creds]);

  const pullReport = useCallback(async () => {
    setBusy('report'); setError('');
    try {
      const res = await fetch('/api/pilot/sandbox/report', { headers: { Authorization: `Bearer ${creds.api_key}` } });
      const data = await res.json();
      if (!res.ok) setError(data.detail || 'Could not load report.');
      else setReport(data);
    } catch { setError('Network error.'); }
    setBusy('');
  }, [creds]);

  const samples = creds ? samplesFor(vertical, creds.organization_id) : [];

  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ maxWidth: 760, margin: '0 auto', padding: '52px 24px 96px' }}>
        <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 18 }}>
          GovGuard fire drill
        </div>
        <h1 style={{ ...styles.h1, maxWidth: 660 }}>Run a government fraud-control fire drill. Nothing gets blocked.</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Provision a scoped key, send your high-risk actions through the gate in <strong>observe mode</strong>,
          and get the automated evidence packet of <strong>what would have required a named human&rsquo;s approval</strong> —
          the exact &ldquo;what would have been blocked before money moved&rdquo; artifact a controller, IG, or procurement
          team asks for. No sales call, no enforcement, no risk. The same engine that runs <a href="/try" style={lnk}>/try</a>.
        </p>

        {/* Step 1 — provision */}
        <section style={card}>
          <Step n="1" label="Provision your sandbox" />
          {!creds ? (
            <>
              <label style={lbl} htmlFor="v">Vertical (selects the example actions)</label>
              <select id="v" value={vertical} onChange={(e) => setVertical(e.target.value)} style={{ ...input, appearance: 'auto' }}>
                {VERTICALS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
              </select>
              <button onClick={provision} disabled={busy === 'provision'} style={primary(busy === 'provision')}>
                {busy === 'provision' ? 'Provisioning…' : 'Provision sandbox key →'}
              </button>
            </>
          ) : (
            <div style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.7 }}>
              <div><span style={muted}>organization_id</span> {creds.organization_id}</div>
              <div style={{ wordBreak: 'break-all' }}><span style={muted}>api_key</span> {creds.api_key}</div>
              <div style={{ marginTop: 8, color: color.t3, fontFamily: font.sans, fontSize: 13 }}>
                Observe-mode only — this key can never block a real system. Shown once; also runnable from your terminal (curl in the JSON response).
              </div>
            </div>
          )}
        </section>

        {/* Step 2 — run actions */}
        {creds && (
          <section style={card}>
            <Step n="2" label="Send actions through the gate (observe mode)" />
            <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, margin: '0 0 14px' }}>
              Click to send sample high-risk actions. In a real pilot these are your own. Nothing is blocked — the gate just records what it <em>would</em> do.
            </p>
            <div style={{ display: 'grid', gap: 8 }}>
              {samples.map(([label, path, body]) => (
                <button key={label} onClick={() => runSample(label, path, body)} disabled={busy === label} style={sampleBtn}>
                  <span>{busy === label ? 'Sending…' : `Send: ${label}`}</span>
                  <span style={{ color: color.gold }}>→</span>
                </button>
              ))}
            </div>
            {ran.length > 0 && (
              <div style={{ marginTop: 14, borderTop: `1px solid ${color.border}`, paddingTop: 12 }}>
                {ran.map((r, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, padding: '4px 0', fontFamily: font.mono }}>
                    <span style={{ color: color.t2 }}>{r.label}</span>
                    <span style={{ color: r.decision === 'deny' ? color.red : r.decision === 'allow_with_signoff' ? color.gold : color.green, fontWeight: 600 }}>
                      would {r.decision === 'allow_with_signoff' ? `require signoff${r.tier ? ` (${r.tier})` : ''}` : r.decision}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* Step 3 — report */}
        {creds && (
          <section style={card}>
            <Step n="3" label="Pull the automated report" />
            <button onClick={pullReport} disabled={busy === 'report'} style={primary(busy === 'report')}>
              {busy === 'report' ? 'Generating…' : 'Generate the “what would have been blocked” report →'}
            </button>
            {report && (
              <div style={{ marginTop: 16 }}>
                <div style={{ background: '#FFFBEB', border: `1px solid ${color.gold}`, borderRadius: radius.base, padding: '16px 18px', fontSize: 15, color: color.t1, lineHeight: 1.55, fontWeight: 600 }}>
                  {report.headline}
                </div>
                <div style={{ display: 'flex', gap: 10, marginTop: 14, flexWrap: 'wrap' }}>
                  <Stat n={report.summary.total_actions} label="observed" />
                  <Stat n={report.summary.would_require_signoff} label="would require signoff" accent={color.gold} />
                  <Stat n={report.summary.would_deny} label="would be denied" accent={color.red} />
                  <Stat n={report.summary.would_allow} label="would allow" accent={color.green} />
                </div>
                {report.samples?.length > 0 && (
                  <div style={{ marginTop: 16, border: `1px solid ${color.border}`, borderRadius: radius.base, overflow: 'hidden' }}>
                    {report.samples.map((s, i) => (
                      <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '11px 16px', borderTop: i ? `1px solid ${color.border}` : 'none', fontSize: 13 }}>
                        <span style={{ fontFamily: font.mono, color: color.t2 }}>{s.action_type}{s.amount ? ` · $${s.amount.toLocaleString()}` : ''}</span>
                        <span style={{ color: s.would_have === 'deny' ? color.red : color.gold, fontWeight: 600 }}>
                          would {s.would_have === 'allow_with_signoff' ? `require signoff${s.signoff_tier ? ` (${s.signoff_tier})` : ''}` : s.would_have}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                {report.evidence_packet && (
                  <div style={{ marginTop: 16, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: 16, background: color.card }}>
                    <div style={{ fontFamily: font.mono, fontSize: 12, color: color.green, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>
                      {report.evidence_packet.gg1.badge}
                    </div>
                    <div style={{ fontSize: 13.5, color: color.t2, lineHeight: 1.6, marginTop: 8 }}>
                      Procurement evidence packet: high-risk actions, policy hashes, action hashes,
                      execution-binding hashes, verifier command, and limitations.
                    </div>
                    <div style={{ fontFamily: font.mono, fontSize: 12.5, color: color.t1, marginTop: 10 }}>
                      {report.evidence_packet.verification.offline_command}
                    </div>
                  </div>
                )}
                <p style={{ fontSize: 13.5, color: color.t2, lineHeight: 1.6, marginTop: 14 }}>{report.next_step}</p>
              </div>
            )}
          </section>
        )}

        {error && <ErrorNote text={error} />}

        <div style={{ marginTop: 36, paddingTop: 22, borderTop: `1px solid ${color.border}`, fontSize: 13, color: color.t3, lineHeight: 1.7 }}>
          Ready for a guided pilot with enforcement and signed receipts? <a href="/pilot" style={lnk}>Request a pilot →</a>{' '}
          For your assurance team: <a href="/auditors" style={lnk}>/auditors</a> · <a href="/rfp" style={lnk}>RFP language</a>.
          This sandbox is observe-only and provisions a scoped, throwaway key.
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}

function Step({ n, label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
      <span style={{ width: 24, height: 24, borderRadius: 24, background: color.t1, color: '#fff', fontSize: 13, fontWeight: 700, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{n}</span>
      <span style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t2, fontWeight: 600 }}>{label}</span>
    </div>
  );
}
function Stat({ n, label, accent = color.t1 }) {
  return (
    <div style={{ flex: '1 1 120px', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '12px 14px', background: color.card }}>
      <div style={{ fontFamily: font.mono, fontSize: 24, fontWeight: 700, color: accent, lineHeight: 1 }}>{n}</div>
      <div style={{ fontSize: 11.5, color: color.t3, marginTop: 5, fontFamily: font.mono, letterSpacing: 0.3 }}>{label}</div>
    </div>
  );
}
function ErrorNote({ text }) {
  return <div style={{ marginTop: 16, padding: '11px 14px', borderRadius: radius.sm, background: '#FEF2F2', border: `1px solid ${color.red}`, color: color.red, fontSize: 13.5 }}>{text}</div>;
}

const card = { background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px', marginBottom: 16 };
const lbl = { display: 'block', fontSize: 12, fontWeight: 600, color: color.t2, margin: '0 0 6px', fontFamily: font.mono, letterSpacing: 0.5 };
const input = { width: '100%', padding: '12px 14px', borderRadius: radius.base, border: `1px solid ${color.inputBorder}`, background: color.card, color: color.t1, fontSize: 15, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box', marginBottom: 16 };
const primary = (b) => ({ width: '100%', background: color.t1, color: '#fff', border: 'none', borderRadius: radius.sm, padding: '14px 24px', fontFamily: font.sans, fontWeight: 600, fontSize: 15, cursor: b ? 'wait' : 'pointer', opacity: b ? 0.6 : 1 });
const sampleBtn = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', background: color.cardHover, border: `1px solid ${color.border}`, borderRadius: radius.sm, padding: '11px 16px', fontFamily: font.mono, fontSize: 13, color: color.t1, cursor: 'pointer', textAlign: 'left' };
const muted = { color: color.t3, marginRight: 8, display: 'inline-block', width: 110 };
const lnk = { color: color.blue, textDecoration: 'none' };
