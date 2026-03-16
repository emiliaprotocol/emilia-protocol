'use client';

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

  const s = {
    page: { minHeight: '100vh', background: '#0a0b14', color: '#e8e6e3', fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif', padding: '60px 24px' },
    container: { maxWidth: 640, margin: '0 auto' },
    h1: { fontSize: 32, fontWeight: 700, marginBottom: 8 },
    sub: { fontSize: 14, color: '#8b8fa3', lineHeight: 1.6, marginBottom: 40 },
    principle: { fontSize: 13, color: '#00d4ff', fontFamily: 'monospace', letterSpacing: 1, marginBottom: 24 },
    tabs: { display: 'flex', gap: 8, marginBottom: 32, flexWrap: 'wrap' },
    tab: (active) => ({
      padding: '10px 20px', borderRadius: 8, border: 'none', cursor: 'pointer',
      background: active ? 'rgba(0,212,255,0.15)' : 'rgba(255,255,255,0.05)',
      color: active ? '#00d4ff' : '#8b8fa3', fontSize: 13, fontWeight: 600,
    }),
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)', color: '#e8e6e3', fontSize: 14, marginBottom: 12, outline: 'none', boxSizing: 'border-box' },
    select: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)', color: '#e8e6e3', fontSize: 14, marginBottom: 12, outline: 'none', boxSizing: 'border-box' },
    textarea: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)', color: '#e8e6e3', fontSize: 14, marginBottom: 12, outline: 'none', minHeight: 120, resize: 'vertical', boxSizing: 'border-box', fontFamily: 'inherit' },
    btn: { padding: '12px 24px', borderRadius: 8, border: 'none', cursor: 'pointer', background: '#00d4ff', color: '#0a0b14', fontSize: 14, fontWeight: 600 },
    btnDanger: { padding: '10px 20px', borderRadius: 8, border: '1px solid rgba(255,45,120,0.3)', cursor: 'pointer', background: 'rgba(255,45,120,0.1)', color: '#ff2d78', fontSize: 13, fontWeight: 600 },
    btnAppeal: { padding: '10px 20px', borderRadius: 8, border: '1px solid rgba(255,215,0,0.3)', cursor: 'pointer', background: 'rgba(255,215,0,0.1)', color: '#ffd700', fontSize: 13, fontWeight: 600 },
    card: { background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24, marginTop: 24 },
    label: { fontSize: 11, color: '#8b8fa3', fontFamily: 'monospace', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 8, display: 'block' },
    row: { display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    error: { background: 'rgba(255,45,120,0.1)', border: '1px solid rgba(255,45,120,0.3)', borderRadius: 8, padding: 16, color: '#ff2d78', marginTop: 16 },
    success: { background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.3)', borderRadius: 8, padding: 16, color: '#00ff88', marginTop: 16 },
    warning: { background: 'rgba(255,215,0,0.1)', border: '1px solid rgba(255,215,0,0.3)', borderRadius: 8, padding: 16, color: '#ffd700', marginTop: 16 },
  };

  const statusColor = (status) => {
    const map = {
      open: '#ffd700', under_review: '#00d4ff', upheld: '#8b8fa3', reversed: '#00ff88',
      dismissed: '#8b8fa3', appealed: '#ffd700', appeal_upheld: '#8b8fa3',
      appeal_reversed: '#00ff88', appeal_dismissed: '#8b8fa3', withdrawn: '#8b8fa3',
    };
    return map[status] || '#8b8fa3';
  };

  const canAppeal = (status) => ['upheld', 'reversed', 'dismissed'].includes(status);
  const canWithdraw = (status) => status === 'open';

  return (
    <nav style={{
          position: 'sticky', top: 0, zIndex: 100,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 40px', height: 60,
          background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(12px)',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          fontFamily: 'monospace', fontSize: 11, letterSpacing: 1, textTransform: 'uppercase',
        }}>
          <a href="/" style={{ fontWeight: 700, fontSize: 14, letterSpacing: 3, color: '#e8e6e3', textDecoration: 'none' }}>EMILIA</a>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <a href="/" style={{ color: '#4a4f6a', textDecoration: 'none' }}>Home</a>
            <a href="/quickstart.html" style={{ color: '#4a4f6a', textDecoration: 'none' }}>Quickstart</a>
            <a href="/demo.html" style={{ color: '#4a4f6a', textDecoration: 'none' }}>Demo</a>
            <a href="/spec" style={{ color: '#4a4f6a', textDecoration: 'none' }}>Spec</a>
            <a href="/operators.html" style={{ color: '#4a4f6a', textDecoration: 'none' }}>Operators</a>
            <a href="/appeal" style={{ color: '#00d4ff', textDecoration: 'none' }}>Appeal</a>
            <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank" style={{ color: '#4a4f6a', textDecoration: 'none' }}>GitHub</a>
          </div>
        </nav>
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.principle}>EP MUST NEVER MAKE TRUST MORE POWERFUL THAN APPEAL</div>
        <h1 style={s.h1}>Trust & Appeal</h1>
        <p style={s.sub}>
          Look up any entity's trust profile, report a trust issue, check a dispute, or appeal a resolution.
          No account required for lookups and reports. Appeals require entity authentication.
        </p>

        <div style={s.tabs}>
          <button style={s.tab(mode === 'lookup')} onClick={() => { setMode('lookup'); setResult(null); setError(null); }}>Look Up Trust</button>
          <button style={s.tab(mode === 'report')} onClick={() => { setMode('report'); setResult(null); setError(null); setSubmitted(false); }}>Report an Issue</button>
          <button style={s.tab(mode === 'status')} onClick={() => { setMode('status'); setResult(null); setError(null); }}>Dispute Status</button>
          <button style={s.tab(mode === 'appeal')} onClick={() => { setMode('appeal'); setResult(null); setError(null); setAppealSubmitted(false); }}>Appeal a Resolution</button>
        </div>

        {/* === LOOKUP TAB === */}
        {mode === 'lookup' && (
          <div>
            <input style={s.input} placeholder="Entity ID (e.g. merchant-xyz)" value={entityId} onChange={e => setEntityId(e.target.value)} onKeyDown={e => e.key === 'Enter' && lookupProfile()} />
            <button style={s.btn} onClick={lookupProfile} disabled={loading}>{loading ? 'Looking up...' : 'Look Up Trust Profile'}</button>

            {result?.type === 'profile' && (
              <div style={s.card}>
                <div style={s.label}>Trust Profile</div>
                <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 16 }}>{result.data.display_name}</div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Confidence</span><span style={{ color: result.data.current_confidence === 'confident' ? '#00ff88' : '#ffd700' }}>{result.data.current_confidence}</span></div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Established</span><span>{result.data.historical_establishment ? 'Yes' : 'No'}</span></div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Compatibility Score</span><span>{result.data.compat_score}/100</span></div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Effective Evidence</span><span>{result.data.effective_evidence_current}</span></div>
                {result.data.quality_gated_evidence_current != null && (
                  <div style={s.row}><span style={{ color: '#8b8fa3' }}>Quality-Gated Evidence</span><span>{result.data.quality_gated_evidence_current}</span></div>
                )}
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Receipts</span><span>{result.data.receipt_count}</span></div>

                {result.data.trust_profile?.behavioral && (
                  <div style={{ marginTop: 16 }}>
                    <div style={s.label}>Behavioral Rates</div>
                    <div style={s.row}><span style={{ color: '#8b8fa3' }}>Completion</span><span style={{ color: '#00ff88' }}>{result.data.trust_profile.behavioral.completion_rate}%</span></div>
                    <div style={s.row}><span style={{ color: '#8b8fa3' }}>Dispute</span><span style={{ color: result.data.trust_profile.behavioral.dispute_rate > 5 ? '#ff2d78' : '#8b8fa3' }}>{result.data.trust_profile.behavioral.dispute_rate}%</span></div>
                  </div>
                )}

                {result.data.disputes && (
                  <div style={{ marginTop: 16 }}>
                    <div style={s.label}>Disputes</div>
                    <div style={s.row}><span style={{ color: '#8b8fa3' }}>Total</span><span>{result.data.disputes.total}</span></div>
                    <div style={s.row}><span style={{ color: '#8b8fa3' }}>Active</span><span style={{ color: result.data.disputes.active > 0 ? '#ff9f1c' : '#8b8fa3' }}>{result.data.disputes.active}</span></div>
                    <div style={s.row}><span style={{ color: '#8b8fa3' }}>Reversed</span><span>{result.data.disputes.reversed}</span></div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* === REPORT TAB === */}
        {mode === 'report' && !submitted && (
          <div>
            <input style={s.input} placeholder="Entity ID this report is about" value={entityId} onChange={e => setEntityId(e.target.value)} />
            <select style={s.select} value={reportType} onChange={e => setReportType(e.target.value)}>
              <option value="wrongly_downgraded">I was wrongly downgraded</option>
              <option value="harmed_by_trusted_entity">I was harmed by a trusted entity</option>
              <option value="fraudulent_entity">This entity is fraudulent</option>
              <option value="fake_receipts">Fake receipts / trust farming</option>
              <option value="unsafe_software">Unsafe software</option>
              <option value="misleading_identity">Misleading identity</option>
              <option value="inaccurate_profile">This trust profile is inaccurate</option>
              <option value="terms_violation">Terms violation</option>
              <option value="other">Other</option>
            </select>
            <textarea style={s.textarea} placeholder="Describe what happened. Be specific — what was wrong, when it happened, what evidence you have." value={description} onChange={e => setDescription(e.target.value)} />
            <input style={s.input} placeholder="Your email (optional — for follow-up)" value={contactEmail} onChange={e => setContactEmail(e.target.value)} />
            <button style={s.btn} onClick={submitReport} disabled={loading}>{loading ? 'Submitting...' : 'Submit Report'}</button>
          </div>
        )}

        {mode === 'report' && submitted && result?.type === 'report' && (
          <div style={s.success}>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>Report received.</div>
            <div>Report ID: {result.data.report_id}</div>
            <div style={{ marginTop: 8, fontSize: 13, color: '#8b8fa3' }}>Your report will be reviewed. If you provided an email, we'll follow up.</div>
          </div>
        )}

        {/* === DISPUTE STATUS TAB === */}
        {mode === 'status' && (
          <div>
            <input style={s.input} placeholder="Dispute ID (ep_disp_...) or Report ID (ep_rpt_...)" value={disputeId} onChange={e => setDisputeId(e.target.value)} onKeyDown={e => e.key === 'Enter' && checkDispute()} />
            <button style={s.btn} onClick={checkDispute} disabled={loading}>{loading ? 'Checking...' : 'Check Status'}</button>

            {result?.type === 'dispute' && (
              <div style={s.card}>
                <div style={s.label}>Dispute Status</div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Status</span><span style={{ color: statusColor(result.data.status), fontWeight: 700 }}>{result.data.status.replace(/_/g, ' ').toUpperCase()}</span></div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Reason</span><span>{result.data.reason}</span></div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Entity</span><span>{result.data.entity?.display_name}</span></div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Filed by</span><span>{result.data.filed_by?.display_name} ({result.data.filed_by_type})</span></div>
                <div style={s.row}><span style={{ color: '#8b8fa3' }}>Response deadline</span><span>{new Date(result.data.response_deadline).toLocaleDateString()}</span></div>
                {result.data.has_response && <div style={s.row}><span style={{ color: '#8b8fa3' }}>Response</span><span style={{ color: '#00d4ff' }}>Received</span></div>}
                {result.data.resolution && <div style={s.row}><span style={{ color: '#8b8fa3' }}>Resolution</span><span style={{ fontWeight: 700 }}>{result.data.resolution}</span></div>}
                {result.data.resolution_rationale && <div style={{ marginTop: 12, fontSize: 13, color: '#8b8fa3', lineHeight: 1.6 }}><strong style={{ color: '#e8e6e3' }}>Rationale:</strong> {result.data.resolution_rationale}</div>}

                {/* Appeal details if dispute was appealed */}
                {result.data.appealed_at && (
                  <div style={{ marginTop: 16, borderTop: '1px solid rgba(255,215,0,0.2)', paddingTop: 16 }}>
                    <div style={{ ...s.label, color: '#ffd700' }}>Appeal</div>
                    <div style={s.row}><span style={{ color: '#8b8fa3' }}>Appealed at</span><span>{new Date(result.data.appealed_at).toLocaleDateString()}</span></div>
                    {result.data.appeal_reason && <div style={{ marginTop: 8, fontSize: 13, color: '#8b8fa3', lineHeight: 1.6 }}><strong style={{ color: '#ffd700' }}>Appeal reason:</strong> {result.data.appeal_reason}</div>}
                    {result.data.appeal_resolution && <div style={s.row}><span style={{ color: '#8b8fa3' }}>Appeal outcome</span><span style={{ fontWeight: 700, color: statusColor(result.data.appeal_resolution) }}>{result.data.appeal_resolution.replace(/_/g, ' ').toUpperCase()}</span></div>}
                    {result.data.appeal_rationale && <div style={{ marginTop: 8, fontSize: 13, color: '#8b8fa3', lineHeight: 1.6 }}><strong style={{ color: '#e8e6e3' }}>Appeal rationale:</strong> {result.data.appeal_rationale}</div>}
                  </div>
                )}

                {/* Action buttons */}
                <div style={{ marginTop: 20, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  {canWithdraw(result.data.status) && (
                    <button style={s.btnDanger} onClick={() => withdrawDispute(result.data.dispute_id)} disabled={loading}>
                      Withdraw Dispute
                    </button>
                  )}
                  {canAppeal(result.data.status) && (
                    <button style={s.btnAppeal} onClick={() => { setMode('appeal'); setAppealDisputeId(result.data.dispute_id); setError(null); setResult(null); }}>
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
            <div style={{ fontSize: 13, color: '#8b8fa3', lineHeight: 1.7, marginBottom: 20, padding: 16, background: 'rgba(255,215,0,0.05)', borderRadius: 8, border: '1px solid rgba(255,215,0,0.15)' }}>
              <strong style={{ color: '#ffd700' }}>When to appeal:</strong> If a dispute was resolved as upheld, reversed, or dismissed and you believe the resolution was wrong, you can appeal. Appeals are reviewed by a senior operator. The appeal decision is final.
            </div>
            <input style={s.input} placeholder="Dispute ID to appeal (ep_disp_...)" value={appealDisputeId} onChange={e => setAppealDisputeId(e.target.value)} />
            <textarea style={s.textarea} placeholder="Explain why the resolution was wrong. Be specific — what was overlooked, what evidence was misinterpreted, what new information exists. Minimum 10 characters." value={appealReason} onChange={e => setAppealReason(e.target.value)} />
            <button style={s.btn} onClick={submitAppeal} disabled={loading}>{loading ? 'Filing appeal...' : 'File Appeal'}</button>
            <div style={{ marginTop: 12, fontSize: 12, color: '#8b8fa3' }}>
              Appeals require entity authentication (API key). If you don't have one, use the Report tab — reports don't require authentication.
            </div>
          </div>
        )}

        {mode === 'appeal' && appealSubmitted && result?.type === 'appeal' && (
          <div style={s.warning}>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>Appeal filed.</div>
            <div>Dispute: {result.data.dispute_id}</div>
            <div>Status: {result.data.status}</div>
            <div style={{ marginTop: 8, fontSize: 13, color: '#8b8fa3' }}>An appeal reviewer will evaluate the original resolution. You can check the status in the Dispute Status tab.</div>
          </div>
        )}

        {error && <div style={s.error}>{error}</div>}

        {/* === HOW DISPUTES WORK === */}
        <div style={{ marginTop: 48, padding: 24, background: 'rgba(255,255,255,0.02)', borderRadius: 12, border: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ fontSize: 11, color: '#8b8fa3', fontFamily: 'monospace', letterSpacing: 1, marginBottom: 8 }}>HOW DISPUTES AND APPEALS WORK</div>
          <div style={{ fontSize: 13, color: '#8b8fa3', lineHeight: 1.8 }}>
            1. Anyone can <strong style={{ color: '#e8e6e3' }}>report</strong> a trust issue — no account needed.<br/>
            2. EP entity holders can <strong style={{ color: '#e8e6e3' }}>file a formal dispute</strong> against a specific receipt.<br/>
            3. The receipt submitter has <strong style={{ color: '#e8e6e3' }}>7 days to respond</strong> with counter-evidence.<br/>
            4. Operators review and resolve: <strong style={{ color: '#00ff88' }}>upheld</strong>, <strong style={{ color: '#ff2d78' }}>reversed</strong>, or <strong style={{ color: '#8b8fa3' }}>dismissed</strong>.<br/>
            5. Reversed receipts are <strong style={{ color: '#e8e6e3' }}>neutralized</strong> (weight → 0), never deleted. The ledger is append-only.<br/>
            6. The entity's trust profile <strong style={{ color: '#e8e6e3' }}>immediately recomputes</strong> to reflect the reversal.<br/>
            <span style={{ display: 'inline-block', marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,215,0,0.15)' }}>
              7. If the resolution was wrong, either party can <strong style={{ color: '#ffd700' }}>appeal</strong>. Appeals go to a senior reviewer.<br/>
              8. Appeal outcomes are <strong style={{ color: '#e8e6e3' }}>final</strong>: appeal upheld (original stands), appeal reversed (original overturned + trust recomputed), or appeal dismissed.<br/>
            </span>
            <span style={{ display: 'inline-block', marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
              At any point before review begins, the filer can <strong style={{ color: '#e8e6e3' }}>withdraw</strong> a dispute.
            </span>
          </div>
        </div>

        <div style={{ marginTop: 24, textAlign: 'center', fontSize: 11, color: '#4a4f6a', fontFamily: 'monospace', letterSpacing: 1 }}>
          <a href="/" style={{ color: '#4a4f6a', textDecoration: 'none' }}>EMILIA PROTOCOL</a> — TRUST MUST NEVER BE MORE POWERFUL THAN APPEAL
        </div>
      </div>
    </div>
    </>
  );
}
