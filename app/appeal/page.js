'use client';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

import { useState } from 'react';

export default function AppealPage() {
  const [mode, setMode] = useState('lookup'); // lookup | report | status | appeal
  const [entityId, setEntityId] = useState('');
  const [disputeId, setDisputeId] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Report form state
  const [reportType, setReportType] = useState('wrongly_downgraded');
  const [description, setDescription] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);

  // Appeal form state
  const [appealDisputeId, setAppealDisputeId] = useState('');
  const [appealReason, setAppealReason] = useState('');
  const [appealSubmitted, setAppealSubmitted] = useState(false);

  const lookupProfile = async () => {
    if (!entityId.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`/api/trust/profile/${encodeURIComponent(entityId)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Not found');
      setResult({ type: 'profile', data });
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const checkDispute = async () => {
    if (!disputeId.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`/api/disputes/${encodeURIComponent(disputeId)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Not found');
      setResult({ type: 'dispute', data });
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const submitReport = async () => {
    if (!entityId.trim() || !description.trim()) return;
    setLoading(true); setError(null);
    try {
      const res = await fetch('/api/disputes/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entity_id: entityId,
          report_type: reportType,
          description,
          contact_email: contactEmail || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to submit');
      setSubmitted(true);
      setResult({ type: 'report', data });
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const submitAppeal = async () => {
    if (!appealDisputeId.trim() || !appealReason.trim()) return;
    if (appealReason.trim().length < 10) { setError('Appeal reason must be at least 10 characters.'); return; }
    setLoading(true); setError(null);
    try {
      const res = await fetch('/api/disputes/appeal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dispute_id: appealDisputeId,
          reason: appealReason,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to file appeal');
      setAppealSubmitted(true);
      setResult({ type: 'appeal', data });
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const withdrawDispute = async (id) => {
    if (!confirm('Withdraw this dispute? This cannot be undone.')) return;
    setLoading(true); setError(null);
    try {
      const res = await fetch('/api/disputes/withdraw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dispute_id: id }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to withdraw');
      setResult({ type: 'dispute', data: { ...result.data, status: 'withdrawn' } });
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const tabStyle = (active) => ({
    padding: '10px 20px', borderRadius: radius.base, border: 'none', cursor: 'pointer',
    background: active ? 'rgba(34,197,94,0.15)' : 'rgba(255,255,255,0.05)',
    color: active ? color.blue : color.t3, fontSize: 13, fontWeight: 600,
  });

  const rowStyle = { display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: `1px solid ${color.border}` };
  const labelStyle = { fontSize: 11, color: color.t3, fontFamily: font.mono, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 8, display: 'block' };
  const errorStyle = { background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: radius.base, padding: 16, color: color.red, marginTop: 16 };
  const successStyle = { background: 'rgba(59,155,110,0.1)', border: '1px solid rgba(59,155,110,0.3)', borderRadius: radius.base, padding: 16, color: color.green, marginTop: 16 };
  const warningStyle = { background: 'rgba(34,197,94,0.1)', border: `1px solid rgba(34,197,94,0.3)`, borderRadius: radius.base, padding: 16, color: color.green, marginTop: 16 };
  const btnDangerStyle = { padding: '10px 20px', borderRadius: radius.base, border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer', background: 'rgba(239,68,68,0.1)', color: '#ef4444', fontSize: 13, fontWeight: 600 };
  const btnAppealStyle = { padding: '10px 20px', borderRadius: radius.base, border: '1px solid rgba(34,197,94,0.3)', cursor: 'pointer', background: 'rgba(34,197,94,0.1)', color: color.green, fontSize: 13, fontWeight: 600 };

  const statusColor = (status) => {
    const map = {
      open: color.green, under_review: color.blue, upheld: color.t3, reversed: color.green,
      dismissed: color.t3, appealed: color.green, appeal_upheld: color.t3,
      appeal_reversed: color.green, appeal_dismissed: color.t3, withdrawn: color.t3,
    };
    return map[status] || color.t3;
  };

  const canAppeal = (status) => ['upheld', 'reversed', 'dismissed'].includes(status);
  const canWithdraw = (status) => status === 'open';

  return (
    <>
    <SiteNav activePage="Appeal" />
    <div style={{ ...styles.page, padding: '24px 24px 60px' }}>
      <div style={{ maxWidth: 640, margin: '0 auto' }}>
        <div style={{ fontSize: 13, color: color.blue, fontFamily: font.mono, letterSpacing: 1, marginBottom: 24 }}>EP MUST NEVER MAKE TRUST MORE POWERFUL THAN APPEAL</div>
        <h1 style={{ fontSize: 32, fontWeight: 700, marginBottom: 8 }}>Trust & Appeal</h1>
        <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.6, marginBottom: 40 }}>
          Look up any entity's trust profile, report a trust issue, check a dispute, or appeal a resolution.
          No account required for lookups and reports. Appeals require entity authentication.
        </p>

        <div style={{ display: 'flex', gap: 8, marginBottom: 32, flexWrap: 'wrap' }}>
          <button style={tabStyle(mode === 'lookup')} onClick={() => { setMode('lookup'); setResult(null); setError(null); }}>Look Up Trust</button>
          <button style={tabStyle(mode === 'report')} onClick={() => { setMode('report'); setResult(null); setError(null); setSubmitted(false); }}>Report an Issue</button>
          <button style={tabStyle(mode === 'status')} onClick={() => { setMode('status'); setResult(null); setError(null); }}>Dispute Status</button>
          <button style={tabStyle(mode === 'appeal')} onClick={() => { setMode('appeal'); setResult(null); setError(null); setAppealSubmitted(false); }}>Appeal a Resolution</button>
        </div>

        {/* === LOOKUP TAB === */}
        {mode === 'lookup' && (
          <div>
            <input className="ep-input" style={styles.input} placeholder="Entity ID (e.g. merchant-xyz)" value={entityId} onChange={e => setEntityId(e.target.value)} onKeyDown={e => e.key === 'Enter' && lookupProfile()} />
            <button className="ep-cta" style={{ ...cta.primaryBlue, marginTop: 4 }} onClick={lookupProfile} disabled={loading}>{loading ? 'Looking up...' : 'Look Up Trust Profile'}</button>

            {result?.type === 'profile' && (
              <div style={{ ...styles.card, borderRadius: radius.base, marginTop: 24 }}>
                <div style={labelStyle}>Trust Profile</div>
                <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 16 }}>{result.data.display_name}</div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Confidence</span><span style={{ color: result.data.current_confidence === 'confident' ? color.green : color.green }}>{result.data.current_confidence}</span></div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Established</span><span>{result.data.historical_establishment ? 'Yes' : 'No'}</span></div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Compatibility Score</span><span>{result.data.compat_score}/100</span></div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Effective Evidence</span><span>{result.data.effective_evidence_current}</span></div>
                {result.data.quality_gated_evidence_current != null && (
                  <div style={rowStyle}><span style={{ color: color.t3 }}>Quality-Gated Evidence</span><span>{result.data.quality_gated_evidence_current}</span></div>
                )}
                <div style={rowStyle}><span style={{ color: color.t3 }}>Receipts</span><span>{result.data.receipt_count}</span></div>

                {result.data.trust_profile?.behavioral && (
                  <div style={{ marginTop: 16 }}>
                    <div style={labelStyle}>Behavioral Rates</div>
                    <div style={rowStyle}><span style={{ color: color.t3 }}>Completion</span><span style={{ color: color.green }}>{result.data.trust_profile.behavioral.completion_rate}%</span></div>
                    <div style={rowStyle}><span style={{ color: color.t3 }}>Dispute</span><span style={{ color: result.data.trust_profile.behavioral.dispute_rate > 5 ? color.red : color.t3 }}>{result.data.trust_profile.behavioral.dispute_rate}%</span></div>
                  </div>
                )}

                {result.data.disputes && (
                  <div style={{ marginTop: 16 }}>
                    <div style={labelStyle}>Disputes</div>
                    <div style={rowStyle}><span style={{ color: color.t3 }}>Total</span><span>{result.data.disputes.total}</span></div>
                    <div style={rowStyle}><span style={{ color: color.t3 }}>Active</span><span style={{ color: result.data.disputes.active > 0 ? '#ff9f1c' : color.t3 }}>{result.data.disputes.active}</span></div>
                    <div style={rowStyle}><span style={{ color: color.t3 }}>Reversed</span><span>{result.data.disputes.reversed}</span></div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* === REPORT TAB === */}
        {mode === 'report' && !submitted && (
          <div>
            <input className="ep-input" style={{ ...styles.input, marginBottom: 12 }} placeholder="Entity ID this report is about" value={entityId} onChange={e => setEntityId(e.target.value)} />
            <select className="ep-input" style={{ ...styles.input, marginBottom: 12 }} value={reportType} onChange={e => setReportType(e.target.value)}>
              <option value="wrongly_downgraded">I was wrongly downgraded</option>
              <option value="harmed_by_trusted_entity">I was harmed by a trusted entity</option>
              <option value="fraudulent_entity">This entity is fraudulent</option>
              <option value="inaccurate_profile">This trust profile is inaccurate</option>
              <option value="other">Other</option>
            </select>
            <textarea className="ep-input" style={{ ...styles.input, marginBottom: 12, minHeight: 120, resize: 'vertical', fontFamily: 'inherit' }} placeholder="Describe what happened. Be specific — what was wrong, when it happened, what evidence you have." value={description} onChange={e => setDescription(e.target.value)} />
            <input className="ep-input" style={{ ...styles.input, marginBottom: 12 }} placeholder="Your email (optional — for follow-up)" value={contactEmail} onChange={e => setContactEmail(e.target.value)} />
            <button className="ep-cta" style={cta.primaryBlue} onClick={submitReport} disabled={loading}>{loading ? 'Submitting...' : 'Submit Report'}</button>
          </div>
        )}

        {mode === 'report' && submitted && result?.type === 'report' && (
          <div style={successStyle}>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>Report received.</div>
            <div>Report ID: {result.data.report_id}</div>
            <div style={{ marginTop: 8, fontSize: 13, color: color.t3 }}>Your report will be reviewed. If you provided an email, we'll follow up.</div>
          </div>
        )}

        {/* === DISPUTE STATUS TAB === */}
        {mode === 'status' && (
          <div>
            <input className="ep-input" style={{ ...styles.input, marginBottom: 12 }} placeholder="Dispute ID (ep_disp_...) or Report ID (ep_rpt_...)" value={disputeId} onChange={e => setDisputeId(e.target.value)} onKeyDown={e => e.key === 'Enter' && checkDispute()} />
            <button className="ep-cta" style={cta.primaryBlue} onClick={checkDispute} disabled={loading}>{loading ? 'Checking...' : 'Check Status'}</button>

            {result?.type === 'dispute' && (
              <div style={{ ...styles.card, borderRadius: radius.base, marginTop: 24 }}>
                <div style={labelStyle}>Dispute Status</div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Status</span><span style={{ color: statusColor(result.data.status), fontWeight: 700 }}>{result.data.status.replace(/_/g, ' ').toUpperCase()}</span></div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Reason</span><span>{result.data.reason}</span></div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Entity</span><span>{result.data.entity?.display_name}</span></div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Filed by</span><span>{result.data.filed_by?.display_name} ({result.data.filed_by_type})</span></div>
                <div style={rowStyle}><span style={{ color: color.t3 }}>Response deadline</span><span>{new Date(result.data.response_deadline).toLocaleDateString()}</span></div>
                {result.data.has_response && <div style={rowStyle}><span style={{ color: color.t3 }}>Response</span><span style={{ color: color.blue }}>Received</span></div>}
                {result.data.resolution && <div style={rowStyle}><span style={{ color: color.t3 }}>Resolution</span><span style={{ fontWeight: 700 }}>{result.data.resolution}</span></div>}
                {result.data.resolution_rationale && <div style={{ marginTop: 12, fontSize: 13, color: color.t3, lineHeight: 1.6 }}><strong style={{ color: color.t1 }}>Rationale:</strong> {result.data.resolution_rationale}</div>}

                {/* Appeal details if dispute was appealed */}
                {result.data.appealed_at && (
                  <div style={{ marginTop: 16, borderTop: '1px solid rgba(34,197,94,0.2)', paddingTop: 16 }}>
                    <div style={{ ...labelStyle, color: color.green }}>Appeal</div>
                    <div style={rowStyle}><span style={{ color: color.t3 }}>Appealed at</span><span>{new Date(result.data.appealed_at).toLocaleDateString()}</span></div>
                    {result.data.appeal_reason && <div style={{ marginTop: 8, fontSize: 13, color: color.t3, lineHeight: 1.6 }}><strong style={{ color: color.green }}>Appeal reason:</strong> {result.data.appeal_reason}</div>}
                    {result.data.appeal_resolution && <div style={rowStyle}><span style={{ color: color.t3 }}>Appeal outcome</span><span style={{ fontWeight: 700, color: statusColor(result.data.appeal_resolution) }}>{result.data.appeal_resolution.replace(/_/g, ' ').toUpperCase()}</span></div>}
                    {result.data.appeal_rationale && <div style={{ marginTop: 8, fontSize: 13, color: color.t3, lineHeight: 1.6 }}><strong style={{ color: color.t1 }}>Appeal rationale:</strong> {result.data.appeal_rationale}</div>}
                  </div>
                )}

                {/* Action buttons */}
                <div style={{ marginTop: 20, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  {canWithdraw(result.data.status) && (
                    <button style={btnDangerStyle} onClick={() => withdrawDispute(result.data.dispute_id)} disabled={loading}>
                      Withdraw Dispute
                    </button>
                  )}
                  {canAppeal(result.data.status) && (
                    <button style={btnAppealStyle} onClick={() => { setMode('appeal'); setAppealDisputeId(result.data.dispute_id); setError(null); setResult(null); }}>
                      Appeal This Resolution
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* === APPEAL TAB === */}
        {mode === 'appeal' && !appealSubmitted && (
          <div>
            <div style={{ fontSize: 13, color: color.t3, lineHeight: 1.7, marginBottom: 20, padding: 16, background: 'rgba(34,197,94,0.05)', borderRadius: radius.base, border: '1px solid rgba(34,197,94,0.15)' }}>
              <strong style={{ color: color.green }}>When to appeal:</strong> If a dispute was resolved as upheld, reversed, or dismissed and you believe the resolution was wrong, you can appeal. Appeals are reviewed by a senior operator. The appeal decision is final.
            </div>
            <input className="ep-input" style={{ ...styles.input, marginBottom: 12 }} placeholder="Dispute ID to appeal (ep_disp_...)" value={appealDisputeId} onChange={e => setAppealDisputeId(e.target.value)} />
            <textarea className="ep-input" style={{ ...styles.input, marginBottom: 12, minHeight: 120, resize: 'vertical', fontFamily: 'inherit' }} placeholder="Explain why the resolution was wrong. Be specific — what was overlooked, what evidence was misinterpreted, what new information exists. Minimum 10 characters." value={appealReason} onChange={e => setAppealReason(e.target.value)} />
            <button className="ep-cta" style={cta.primaryBlue} onClick={submitAppeal} disabled={loading}>{loading ? 'Filing appeal...' : 'File Appeal'}</button>
            <div style={{ marginTop: 12, fontSize: 12, color: color.t3 }}>
              Appeals require entity authentication (API key). If you don't have one, use the Report tab — reports don't require authentication.
            </div>
          </div>
        )}

        {mode === 'appeal' && appealSubmitted && result?.type === 'appeal' && (
          <div style={warningStyle}>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>Appeal filed.</div>
            <div>Dispute: {result.data.dispute_id}</div>
            <div>Status: {result.data.status}</div>
            <div style={{ marginTop: 8, fontSize: 13, color: color.t3 }}>An appeal reviewer will evaluate the original resolution. You can check the status in the Dispute Status tab.</div>
          </div>
        )}

        {error && <div style={errorStyle}>{error}</div>}

        {/* === HOW DISPUTES WORK === */}
        <div style={{ marginTop: 48, padding: 24, background: 'rgba(255,255,255,0.02)', borderRadius: radius.base, border: `1px solid ${color.border}` }}>
          <div style={{ fontSize: 11, color: color.t3, fontFamily: font.mono, letterSpacing: 1, marginBottom: 8 }}>HOW DISPUTES AND APPEALS WORK</div>
          <div style={{ fontSize: 13, color: color.t3, lineHeight: 1.8 }}>
            1. Anyone can <strong style={{ color: color.t1 }}>report</strong> a trust issue — no account needed.<br/>
            2. EP entity holders can <strong style={{ color: color.t1 }}>file a formal dispute</strong> against a specific receipt.<br/>
            3. The receipt submitter has <strong style={{ color: color.t1 }}>7 days to respond</strong> with counter-evidence.<br/>
            4. Operators review and resolve: <strong style={{ color: color.green }}>upheld</strong>, <strong style={{ color: color.red }}>reversed</strong>, or <strong style={{ color: color.t3 }}>dismissed</strong>.<br/>
            5. Reversed receipts are <strong style={{ color: color.t1 }}>neutralized</strong> (weight → 0), never deleted. The ledger is append-only.<br/>
            6. The entity's trust profile <strong style={{ color: color.t1 }}>immediately recomputes</strong> to reflect the reversal.<br/>
            <span style={{ display: 'inline-block', marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(34,197,94,0.15)' }}>
              7. If the resolution was wrong, either party can <strong style={{ color: color.green }}>appeal</strong>. Appeals go to a senior reviewer.<br/>
              8. Appeal outcomes are <strong style={{ color: color.t1 }}>final</strong>: appeal upheld (original stands), appeal reversed (original overturned + trust recomputed), or appeal dismissed.<br/>
            </span>
            <span style={{ display: 'inline-block', marginTop: 8, paddingTop: 8, borderTop: `1px solid ${color.border}` }}>

              At any point before review begins, the filer can <strong style={{ color: color.t1 }}>withdraw</strong> a dispute.
            </span>
          </div>
        </div>

        <div style={{ marginTop: 24, textAlign: 'center', fontSize: 11, color: color.t3, fontFamily: font.mono, letterSpacing: 1 }}>
          <Link href="/" style={{ color: color.t3, textDecoration: 'none' }}>EMILIA PROTOCOL</Link> — TRUST MUST NEVER BE MORE POWERFUL THAN APPEAL
        </div>
      </div>
    </div>
    <SiteFooter />
    </>
  );
}
