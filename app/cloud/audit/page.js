'use client';

import { useState } from 'react';

const REPORT_TYPES = ['Evidence Package', 'IG/GAO Report', 'SOX Evidence', 'AI Act Trail'];
const SCOPE_OPTIONS = ['All', 'Specific Handshake IDs', 'Specific Policy'];

const MOCK_REPORTS = [
  { id: 'rpt_01HXK9', type: 'Evidence Package', scope: 'All', generated: '2026-03-19T14:22:00Z', status: 'complete', size: '4.2 MB', integrity: 'verified' },
  { id: 'rpt_01HXK8', type: 'SOX Evidence', scope: 'policy:sox-404', generated: '2026-03-18T09:15:00Z', status: 'complete', size: '12.8 MB', integrity: 'verified' },
  { id: 'rpt_01HXK7', type: 'AI Act Trail', scope: 'hs_7f3a9b2c', generated: '2026-03-17T16:40:00Z', status: 'complete', size: '1.1 MB', integrity: 'verified' },
  { id: 'rpt_01HXK6', type: 'IG/GAO Report', scope: 'All', generated: '2026-03-15T11:05:00Z', status: 'complete', size: '8.6 MB', integrity: 'mismatch' },
  { id: 'rpt_01HXK5', type: 'Evidence Package', scope: 'policy:aml-kyc', generated: '2026-03-14T08:30:00Z', status: 'generating', size: '—', integrity: 'pending' },
];

export default function AuditExportPage() {
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [reportType, setReportType] = useState(REPORT_TYPES[0]);
  const [scope, setScope] = useState(SCOPE_OPTIONS[0]);
  const [scopeValue, setScopeValue] = useState('');
  const [generating, setGenerating] = useState(false);
  const [reports, setReports] = useState(MOCK_REPORTS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleGenerate = async () => {
    if (!dateFrom || !dateTo) { setError('Date range is required.'); return; }
    setGenerating(true); setError(null);
    await new Promise(r => setTimeout(r, 1500));
    const newReport = {
      id: 'rpt_' + Math.random().toString(36).slice(2, 8),
      type: reportType,
      scope: scope === 'All' ? 'All' : scopeValue || scope,
      generated: new Date().toISOString(),
      status: 'generating',
      size: '—',
      integrity: 'pending',
    };
    setReports(prev => [newReport, ...prev]);
    setGenerating(false);
  };

  const s = {
    page: { minHeight: '100vh', background: '#0a0f1e', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
    container: { maxWidth: 1080, margin: '0 auto', padding: '40px 24px' },
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#d4af55', marginBottom: 8 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8 },
    subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
    card: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 24, marginBottom: 24 },
    label: { display: 'block', fontSize: 12, fontWeight: 600, color: '#7a809a', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 0.5 },
    input: { width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#111827', color: '#e8eaf0', fontSize: 14, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box' },
    select: { width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#111827', color: '#e8eaf0', fontSize: 14, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box', appearance: 'none' },
    btn: { padding: '10px 24px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: 'none', cursor: 'pointer' },
    mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
    th: { padding: '10px 14px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1, textTransform: 'uppercase', borderBottom: '1px solid rgba(255,255,255,0.06)' },
    td: { padding: '10px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)' },
  };

  const integrityBadge = (status) => {
    const colors = { verified: '#3b9b6e', mismatch: '#f87171', pending: '#d4af55' };
    return (
      <span style={{ ...s.mono, color: colors[status] || '#7a809a', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: colors[status] || '#7a809a', display: 'inline-block' }} />
        {status}
      </span>
    );
  };

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Audit</div>
        <h1 style={s.h1}>Audit Export</h1>
        <p style={s.subtitle}>Generate compliance evidence packages, regulatory reports, and audit trails.</p>

        <div style={s.card}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <label style={s.label}>Date From</label>
              <input type="date" style={s.input} value={dateFrom} onChange={e => setDateFrom(e.target.value)} />
            </div>
            <div>
              <label style={s.label}>Date To</label>
              <input type="date" style={s.input} value={dateTo} onChange={e => setDateTo(e.target.value)} />
            </div>
            <div>
              <label style={s.label}>Report Type</label>
              <select style={s.select} value={reportType} onChange={e => setReportType(e.target.value)}>
                {REPORT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label style={s.label}>Scope</label>
              <select style={s.select} value={scope} onChange={e => setScope(e.target.value)}>
                {SCOPE_OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            </div>
            {scope !== 'All' && (
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={s.label}>{scope === 'Specific Handshake IDs' ? 'Handshake IDs (comma-separated)' : 'Policy Identifier'}</label>
                <input style={s.input} placeholder={scope === 'Specific Handshake IDs' ? 'hs_7f3a9b2c, hs_2e8d1f4a' : 'policy:sox-404'} value={scopeValue} onChange={e => setScopeValue(e.target.value)} />
              </div>
            )}
          </div>
          {error && <p style={{ color: '#f87171', fontSize: 13, marginTop: 12 }}>{error}</p>}
          <button onClick={handleGenerate} disabled={generating} style={{ ...s.btn, background: generating ? '#1a1e30' : '#d4af55', color: generating ? '#4a4f6a' : '#0a0f1e', marginTop: 20 }}>
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>

        <div style={s.card}>
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Recent Reports</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={s.th}>Report ID</th>
                  <th style={s.th}>Type</th>
                  <th style={s.th}>Scope</th>
                  <th style={s.th}>Generated</th>
                  <th style={s.th}>Size</th>
                  <th style={s.th}>Integrity</th>
                  <th style={s.th}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.id}>
                    <td style={{ ...s.td, ...s.mono, color: '#4a90d9' }}>{r.id}</td>
                    <td style={s.td}>{r.type}</td>
                    <td style={{ ...s.td, ...s.mono, color: '#7a809a' }}>{r.scope}</td>
                    <td style={{ ...s.td, ...s.mono, color: '#7a809a', fontSize: 12 }}>{new Date(r.generated).toLocaleString()}</td>
                    <td style={{ ...s.td, ...s.mono }}>{r.size}</td>
                    <td style={s.td}>{integrityBadge(r.integrity)}</td>
                    <td style={s.td}>
                      {r.status === 'complete' ? (
                        <button style={{ ...s.btn, padding: '4px 12px', background: 'transparent', color: '#4a90d9', border: '1px solid rgba(212,175,85,0.3)', fontSize: 11 }}>Download</button>
                      ) : (
                        <span style={{ ...s.mono, color: '#d4af55' }}>Processing...</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
