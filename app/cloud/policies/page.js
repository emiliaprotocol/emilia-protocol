'use client';

import { useState, useEffect } from 'react';

const s = {
  page: { minHeight: '100vh', background: '#0a0f1e', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 1120, margin: '0 auto', padding: '40px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#d4af55', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8, color: '#e8eaf0' },
  subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
  card: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: 24, marginBottom: 24 },
  topBar: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24, gap: 12 },
  searchInput: { flex: 1, maxWidth: 360, padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0a0f1e', color: '#e8eaf0', fontSize: 13, fontFamily: "'IBM Plex Sans', sans-serif", outline: 'none' },
  btn: { padding: '10px 20px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: 'none', cursor: 'pointer', background: '#d4af55', color: '#0a0f1e' },
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  th: { padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1.5, textTransform: 'uppercase', borderBottom: '1px solid rgba(255,255,255,0.06)' },
  td: { padding: '12px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)' },
  badge: (bg, fg) => ({ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 0.5, padding: '3px 8px', borderRadius: 4, background: bg, color: fg, display: 'inline-block' }),
  loading: { textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 },
  error: { background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 },
};

const MOCK_POLICIES = [
  { id: 'pol_aml_kyc_v3', name: 'AML/KYC Verification', version: 'v3.2.1', status: 'active', enforcement: 'strict', handshakes: 4821, lastUpdated: '2026-03-20T10:30:00Z' },
  { id: 'pol_sox_404', name: 'SOX 404 Controls', version: 'v2.1.0', status: 'active', enforcement: 'strict', handshakes: 2104, lastUpdated: '2026-03-18T14:15:00Z' },
  { id: 'pol_gdpr_consent', name: 'GDPR Consent Management', version: 'v4.0.0', status: 'active', enforcement: 'advisory', handshakes: 3567, lastUpdated: '2026-03-19T09:45:00Z' },
  { id: 'pol_ai_act', name: 'AI Act Compliance Trail', version: 'v1.3.0', status: 'active', enforcement: 'strict', handshakes: 1289, lastUpdated: '2026-03-17T16:20:00Z' },
  { id: 'pol_sanctions', name: 'Sanctions Screening', version: 'v2.0.0', status: 'active', enforcement: 'strict', handshakes: 890, lastUpdated: '2026-03-16T11:00:00Z' },
  { id: 'pol_data_residency', name: 'Data Residency Rules', version: 'v1.1.0', status: 'draft', enforcement: 'strict', handshakes: 0, lastUpdated: '2026-03-21T08:00:00Z' },
  { id: 'pol_vendor_risk', name: 'Vendor Risk Assessment', version: 'v1.0.0', status: 'inactive', enforcement: 'advisory', handshakes: 412, lastUpdated: '2026-03-10T13:30:00Z' },
];

const statusBadge = (status) => {
  const map = { active: ['rgba(0,255,136,0.1)', '#00ff88'], draft: ['rgba(212,175,85,0.1)', '#d4af55'], inactive: ['rgba(122,128,154,0.1)', '#7a809a'] };
  const [bg, fg] = map[status] || map.inactive;
  return <span style={s.badge(bg, fg)}>{status}</span>;
};

const enforcementBadge = (mode) => {
  const map = { strict: ['rgba(74,144,217,0.1)', '#4a90d9'], advisory: ['rgba(212,175,85,0.1)', '#d4af55'] };
  const [bg, fg] = map[mode] || ['rgba(122,128,154,0.1)', '#7a809a'];
  return <span style={s.badge(bg, fg)}>{mode}</span>;
};

export default function PoliciesPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [search, setSearch] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        await new Promise(r => setTimeout(r, 500));
        setPolicies(MOCK_POLICIES);
      } catch (err) {
        setError('Failed to load policies.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const filtered = policies.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.id.toLowerCase().includes(search.toLowerCase())
  );

  if (loading) return <div style={s.page}><div style={s.loading}>Loading policies...</div></div>;

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Policies</div>
        <h1 style={s.h1}>Policy Management</h1>
        <p style={s.subtitle}>Configure and manage compliance policies enforced across handshakes.</p>

        {error && <div style={s.error}>{error}</div>}

        <div style={s.topBar}>
          <input
            style={s.searchInput}
            placeholder="Search policies..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <button style={s.btn}>+ New Policy</button>
        </div>

        <div style={s.card}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={s.th}>Policy ID</th>
                <th style={s.th}>Name</th>
                <th style={s.th}>Version</th>
                <th style={s.th}>Status</th>
                <th style={s.th}>Enforcement</th>
                <th style={s.th}>Handshakes</th>
                <th style={s.th}>Last Updated</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(p => (
                <tr key={p.id}>
                  <td style={{ ...s.td, ...s.mono, color: '#4a90d9' }}>{p.id}</td>
                  <td style={{ ...s.td, fontWeight: 500 }}>{p.name}</td>
                  <td style={{ ...s.td, ...s.mono, color: '#7a809a' }}>{p.version}</td>
                  <td style={s.td}>{statusBadge(p.status)}</td>
                  <td style={s.td}>{enforcementBadge(p.enforcement)}</td>
                  <td style={{ ...s.td, ...s.mono }}>{p.handshakes.toLocaleString()}</td>
                  <td style={{ ...s.td, ...s.mono, color: '#4a4f6a', fontSize: 11 }}>{new Date(p.lastUpdated).toLocaleDateString()}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={7} style={{ ...s.td, textAlign: 'center', color: '#4a4f6a', padding: 40 }}>No policies match your search.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
