'use client';

import { useState, useEffect } from 'react';

const s = {
  page: { minHeight: '100vh', background: '#0a0f1e', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 1120, margin: '0 auto', padding: '40px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#d4af55', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8, color: '#e8eaf0' },
  subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 32 },
  statCard: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: '20px 24px' },
  statLabel: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: '#7a809a', marginBottom: 8 },
  statValue: { fontSize: 28, fontWeight: 700, letterSpacing: -1 },
  card: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: 24, marginBottom: 24 },
  cardTitle: { fontSize: 15, fontWeight: 600, marginBottom: 16 },
  tabs: { display: 'flex', gap: 0, marginBottom: 24, borderBottom: '1px solid rgba(255,255,255,0.06)' },
  tab: (active) => ({ padding: '10px 20px', fontSize: 13, fontWeight: 500, color: active ? '#e8eaf0' : '#4a4f6a', background: 'none', border: 'none', borderBottom: active ? '2px solid #d4af55' : '2px solid transparent', cursor: 'pointer', fontFamily: "'IBM Plex Sans', sans-serif" }),
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  th: { padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1.5, textTransform: 'uppercase', borderBottom: '1px solid rgba(255,255,255,0.06)' },
  td: { padding: '12px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)' },
  dot: (color) => ({ width: 7, height: 7, borderRadius: '50%', background: color, display: 'inline-block', marginRight: 8 }),
  loading: { textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 },
  error: { background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 },
};

const MOCK_SUMMARY = { pending: 18, completed: 1243, expired: 34 };

const MOCK_SIGNOFFS = [
  { id: 'sig_a9f2c1', handshake: 'hs_9f2a1b3c', policy: 'aml-kyc-v3', signer: 'compliance-officer@acme.com', status: 'pending', created: '2026-03-22T14:30:00Z', expires: '2026-03-23T14:30:00Z' },
  { id: 'sig_b3e7d4', handshake: 'hs_7e4d2a8f', policy: 'sox-404-controls', signer: 'auditor@globex.com', status: 'pending', created: '2026-03-22T12:15:00Z', expires: '2026-03-23T12:15:00Z' },
  { id: 'sig_c5a1f8', handshake: 'hs_3c1b9e7d', policy: 'gdpr-consent-v2', signer: 'dpo@initech.eu', status: 'completed', created: '2026-03-21T09:00:00Z', expires: '2026-03-22T09:00:00Z' },
  { id: 'sig_d8c4b2', handshake: 'hs_5a8f3c2e', policy: 'ai-act-trail', signer: 'legal@acme.com', status: 'completed', created: '2026-03-20T16:45:00Z', expires: '2026-03-21T16:45:00Z' },
  { id: 'sig_e2f9a6', handshake: 'hs_1d6e4b9a', policy: 'sanctions-screen', signer: 'ops@globex.com', status: 'expired', created: '2026-03-18T10:00:00Z', expires: '2026-03-19T10:00:00Z' },
];

const statusColor = { pending: '#d4af55', completed: '#3b9b6e', expired: '#f87171' };

export default function SignoffsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const [signoffs, setSignoffs] = useState([]);
  const [activeTab, setActiveTab] = useState('all');

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        await new Promise(r => setTimeout(r, 500));
        setSummary(MOCK_SUMMARY);
        setSignoffs(MOCK_SIGNOFFS);
      } catch (err) {
        setError('Failed to load signoff data.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const filtered = activeTab === 'all' ? signoffs : signoffs.filter(x => x.status === activeTab);

  if (loading) return <div style={s.page}><div style={s.loading}>Loading signoffs...</div></div>;

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Signoffs</div>
        <h1 style={s.h1}>Signoff Queue</h1>
        <p style={s.subtitle}>Manage attestation challenges and signoff approvals across policies.</p>

        {error && <div style={s.error}>{error}</div>}

        {summary && (
          <div style={s.grid}>
            <div style={s.statCard}>
              <div style={s.statLabel}>Pending</div>
              <div style={{ ...s.statValue, color: '#d4af55' }}>{summary.pending}</div>
            </div>
            <div style={s.statCard}>
              <div style={s.statLabel}>Completed</div>
              <div style={{ ...s.statValue, color: '#3b9b6e' }}>{summary.completed}</div>
            </div>
            <div style={s.statCard}>
              <div style={s.statLabel}>Expired</div>
              <div style={{ ...s.statValue, color: '#f87171' }}>{summary.expired}</div>
            </div>
          </div>
        )}

        <div style={s.tabs}>
          {['all', 'pending', 'completed', 'expired'].map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} style={s.tab(activeTab === tab)}>
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        <div style={s.card}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={s.th}>Signoff ID</th>
                <th style={s.th}>Handshake</th>
                <th style={s.th}>Policy</th>
                <th style={s.th}>Signer</th>
                <th style={s.th}>Status</th>
                <th style={s.th}>Created</th>
                <th style={s.th}>Expires</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(sig => (
                <tr key={sig.id}>
                  <td style={{ ...s.td, ...s.mono, color: '#4a90d9' }}>{sig.id}</td>
                  <td style={{ ...s.td, ...s.mono, color: '#7a809a' }}>{sig.handshake}</td>
                  <td style={{ ...s.td, ...s.mono }}>{sig.policy}</td>
                  <td style={{ ...s.td, fontSize: 12 }}>{sig.signer}</td>
                  <td style={s.td}>
                    <span style={{ ...s.mono, color: statusColor[sig.status], display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <span style={s.dot(statusColor[sig.status])} />
                      {sig.status}
                    </span>
                  </td>
                  <td style={{ ...s.td, ...s.mono, color: '#4a4f6a', fontSize: 11 }}>{new Date(sig.created).toLocaleString()}</td>
                  <td style={{ ...s.td, ...s.mono, color: '#4a4f6a', fontSize: 11 }}>{new Date(sig.expires).toLocaleString()}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={7} style={{ ...s.td, textAlign: 'center', color: '#4a4f6a', padding: 40 }}>No signoffs in this category.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
